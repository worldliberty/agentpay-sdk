//! Wallet lifecycle: `BootstrapWallet` (wallet key, agent key, and limits in
//! one atomic step), the wallet listing in [`list`], and the encrypted backups
//! in [`backup`].
//!
//! Bootstrapping validates everything it can before changing anything (the
//! limits, the backup and its passphrase, which wallet and agent to use), then
//! applies the change under the signing and state guards and persists it once.
//! A failure after the signer backend made a new key deletes that key again
//! and restores the state snapshot; replaced keys are deleted from the backend
//! only after the new state is on disk.

mod backup;
mod list;

use std::collections::BTreeSet;

use agentpay_api::rpc::limits::SpendingLimit;
use agentpay_api::rpc::wallet::{
    WalletBootstrap, WalletBootstrapMode, WalletBootstrapOutcome, MAX_WALLET_NAME_CHARS,
};
use agentpay_domain::{
    AdminAuth, AgentCredentials, AgentKey, PolicyAttachment, SpendingPolicy, VaultKey,
};
use agentpay_signer::{KeyCreateRequest, VaultSignerBackend};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::auth::{generate_agent_auth_token, hash_agent_auth_token};
use super::limits::{build_policies, validate_limits};
use crate::{DaemonError, InMemoryDaemon, RequestContext};

/// A wallet name as stored: trimmed, 1 to [`MAX_WALLET_NAME_CHARS`]
/// characters, no control characters; `None` stays `None`.
pub(super) fn wallet_name(name: Option<String>) -> Result<Option<String>, DaemonError> {
    let Some(name) = name else {
        return Ok(None);
    };
    let trimmed = name.trim();
    let length = trimmed.chars().count();
    if length == 0 || length > MAX_WALLET_NAME_CHARS || trimmed.chars().any(char::is_control) {
        return Err(DaemonError::InvalidWalletRequest(format!(
            "the wallet name must be 1 to {MAX_WALLET_NAME_CHARS} characters without control characters"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

/// Where the wallet key comes from, after validation.
enum WalletSource {
    /// Generate a new key, replacing `replaced` (possibly none).
    Generate { replaced: Vec<Uuid> },
    /// Import a decrypted backup key, replacing `replaced` (possibly none).
    Import {
        private_key_hex: Zeroizing<String>,
        replaced: Vec<Uuid>,
    },
    /// Keep `vault_key`; refresh `agent_key_id` or create an agent key.
    Reuse {
        vault_key: VaultKey,
        agent_key_id: Option<Uuid>,
    },
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn bootstrap_wallet_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        mode: WalletBootstrapMode,
        limits: Vec<SpendingLimit>,
    ) -> Result<WalletBootstrap, DaemonError> {
        let mut mode = mode;
        let result = self
            .bootstrap_wallet_inner(ctx, auth, &mut mode, limits)
            .await;
        mode.zeroize_secrets();
        result
    }

    async fn bootstrap_wallet_inner(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        mode: &mut WalletBootstrapMode,
        limits: Vec<SpendingLimit>,
    ) -> Result<WalletBootstrap, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let limits = validate_limits(limits)?;
        let policies = build_policies(&limits)?;
        let requested_name = match mode {
            WalletBootstrapMode::Create { name, .. }
            | WalletBootstrapMode::RestoreFromBackup { name, .. } => wallet_name(name.take())?,
            WalletBootstrapMode::Reuse { .. } => None,
        };
        // The slow part (scrypt) runs before any guard is taken.
        let restored = match mode {
            WalletBootstrapMode::RestoreFromBackup {
                backup_json,
                passphrase,
                ..
            } => Some(
                self.decrypt_backup(
                    std::mem::take(backup_json),
                    Zeroizing::new(std::mem::take(&mut **passphrase)),
                )
                .await?,
            ),
            _ => None,
        };

        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let now = OffsetDateTime::now_utc();
        let mut name = requested_name;
        let (source, outcome) = match (&*mode, restored) {
            (
                WalletBootstrapMode::Create {
                    replace_existing, ..
                },
                _,
            ) => (
                WalletSource::Generate {
                    replaced: self.replaceable_wallets(*replace_existing)?,
                },
                WalletBootstrapOutcome::Created,
            ),
            (
                WalletBootstrapMode::RestoreFromBackup {
                    replace_existing, ..
                },
                Some(contents),
            ) => {
                if self.vault_key_holding(&contents.public_key_hex)?.is_some() {
                    return Err(DaemonError::InvalidWalletRequest(
                        "the daemon already holds this wallet; bootstrap with reuse instead"
                            .to_string(),
                    ));
                }
                if name.is_none() {
                    name = backup::backup_name(contents.name);
                }
                (
                    WalletSource::Import {
                        private_key_hex: contents.private_key_hex,
                        replaced: self.replaceable_wallets(*replace_existing)?,
                    },
                    WalletBootstrapOutcome::Restored,
                )
            }
            (WalletBootstrapMode::RestoreFromBackup { .. }, None) => {
                return Err(DaemonError::InvalidWalletRequest(
                    "the backup was not decrypted".to_string(),
                ));
            }
            (
                WalletBootstrapMode::Reuse {
                    vault_key_id,
                    agent_key_id,
                },
                _,
            ) => {
                let vault_key = self.resolve_wallet(*vault_key_id)?;
                let agent_key_id = self.reusable_agent_key(&vault_key, *agent_key_id)?;
                (
                    WalletSource::Reuse {
                        vault_key,
                        agent_key_id,
                    },
                    WalletBootstrapOutcome::Reused,
                )
            }
        };

        let backup = self.backup_state_if_persistent()?;
        let (vault_key, created_key, replaced) = match source {
            WalletSource::Generate { replaced } => {
                let mut key = self
                    .signer_backend
                    .create_vault_key(KeyCreateRequest::Generate)
                    .await?;
                key.name = name;
                (key.clone(), Some(key.id), replaced)
            }
            WalletSource::Import {
                private_key_hex,
                replaced,
            } => {
                let mut key = self
                    .signer_backend
                    .create_vault_key(KeyCreateRequest::Import { private_key_hex })
                    .await?;
                key.name = name;
                (key.clone(), Some(key.id), replaced)
            }
            WalletSource::Reuse {
                vault_key,
                agent_key_id,
            } => {
                let applied = self.apply_reuse(agent_key_id, &vault_key, policies, now);
                let credentials = self.commit(applied, backup, None)?;
                return self.bootstrap_result(outcome, vault_key, credentials, Vec::new(), now);
            }
        };
        let applied = self.apply_new_wallet(&vault_key, &replaced, policies, now);
        let credentials = self.commit(applied, backup, created_key)?;
        for id in &replaced {
            // The new state no longer references these keys; a failed delete
            // only leaves unreachable material in the backend.
            let _ = self.signer_backend.delete_vault_key_if_present(*id);
        }
        self.bootstrap_result(outcome, vault_key, credentials, replaced, now)
    }

    /// The vault keys a new wallet would replace: refuses unless
    /// `replace_existing` when there are any.
    fn replaceable_wallets(&self, replace_existing: bool) -> Result<Vec<Uuid>, DaemonError> {
        let mut existing: Vec<Uuid> = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .keys()
            .copied()
            .collect();
        existing.sort_unstable();
        if !existing.is_empty() && !replace_existing {
            return Err(DaemonError::WalletAlreadyExists {
                vault_key_ids: existing,
            });
        }
        Ok(existing)
    }

    /// The agent key `reuse` refreshes: `requested`, or the wallet's only one
    /// (`None` when it has none, so one is created).
    fn reusable_agent_key(
        &self,
        vault_key: &VaultKey,
        requested: Option<Uuid>,
    ) -> Result<Option<Uuid>, DaemonError> {
        let agent_keys = self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        if let Some(id) = requested {
            let agent = agent_keys
                .get(&id)
                .ok_or(DaemonError::UnknownAgentKey(id))?;
            if agent.vault_key_id != vault_key.id {
                return Err(DaemonError::InvalidWalletRequest(format!(
                    "agent key {id} belongs to another vault key"
                )));
            }
            return Ok(Some(id));
        }
        let mut owned: Vec<Uuid> = agent_keys
            .values()
            .filter(|agent| agent.vault_key_id == vault_key.id)
            .map(|agent| agent.id)
            .collect();
        owned.sort_unstable();
        match owned.as_slice() {
            [] => Ok(None),
            [only] => Ok(Some(*only)),
            _ => Err(DaemonError::InvalidWalletRequest(format!(
                "vault key {} has {} agent keys; pass agent_key_id",
                vault_key.id,
                owned.len()
            ))),
        }
    }

    /// `reuse`: replaces the agent's limits and rotates its token, or creates
    /// an agent key when the wallet has none.
    fn apply_reuse(
        &self,
        agent_key_id: Option<Uuid>,
        vault_key: &VaultKey,
        policies: Vec<SpendingPolicy>,
        now: OffsetDateTime,
    ) -> Result<AgentCredentials, DaemonError> {
        let Some(agent_key_id) = agent_key_id else {
            let ids = self.insert_new_policies(policies)?;
            return self.insert_agent_key(vault_key.id, ids, now);
        };
        self.replace_agent_limit_policies(agent_key_id, policies)?;
        let agent_key = self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .cloned()
            .ok_or(DaemonError::UnknownAgentKey(agent_key_id))?;
        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key_id, hash_agent_auth_token(&auth_token));
        Ok(AgentCredentials {
            agent_key,
            auth_token: auth_token.into(),
        })
    }

    /// `create` / `restore_from_backup`: removes the replaced wallets with
    /// everything tied to them, registers the new key, and creates its agent key.
    fn apply_new_wallet(
        &self,
        vault_key: &VaultKey,
        replaced: &[Uuid],
        policies: Vec<SpendingPolicy>,
        now: OffsetDateTime,
    ) -> Result<AgentCredentials, DaemonError> {
        let mut orphaned = BTreeSet::new();
        for vault_key_id in replaced {
            let agents: Vec<AgentKey> = self
                .agent_keys
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .values()
                .filter(|agent| agent.vault_key_id == *vault_key_id)
                .cloned()
                .collect();
            for agent in agents {
                orphaned.extend(self.governing_policy_ids(&agent)?.0);
                self.purge_agent_key(agent.id, now)?;
            }
            self.vault_keys
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?
                .remove(vault_key_id);
            self.nonce_heads
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?
                .remove(vault_key_id);
            self.reusable_nonce_gaps
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?
                .remove(vault_key_id);
        }
        self.retire_unused_policies(&orphaned)?;
        self.vault_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(vault_key.id, vault_key.clone());
        let ids = self.insert_new_policies(policies)?;
        self.insert_agent_key(vault_key.id, ids, now)
    }

    /// Creates an agent key attached to exactly `policy_ids`, with a new token.
    fn insert_agent_key(
        &self,
        vault_key_id: Uuid,
        policy_ids: BTreeSet<Uuid>,
        now: OffsetDateTime,
    ) -> Result<AgentCredentials, DaemonError> {
        let agent_key = AgentKey {
            id: Uuid::new_v4(),
            vault_key_id,
            policies: PolicyAttachment::policy_set(policy_ids)
                .map_err(|err| DaemonError::InvalidPolicyAttachment(err.to_string()))?,
            created_at: now,
        };
        self.agent_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key.id, agent_key.clone());
        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key.id, hash_agent_auth_token(&auth_token));
        Ok(AgentCredentials {
            agent_key,
            auth_token: auth_token.into(),
        })
    }

    /// Persists an applied change, or undoes it: restores the snapshot and
    /// deletes a key the backend created for it.
    fn commit(
        &self,
        applied: Result<AgentCredentials, DaemonError>,
        backup: Option<crate::persistence::PersistedDaemonState>,
        created_key: Option<Uuid>,
    ) -> Result<AgentCredentials, DaemonError> {
        let outcome = match applied {
            Ok(credentials) => self.persist_state_if_enabled().map(|()| credentials),
            Err(err) => Err(err),
        };
        let Err(err) = outcome else {
            return outcome;
        };
        if let Some(snapshot) = backup {
            self.restore_state(snapshot)?;
        }
        if let Some(id) = created_key {
            self.vault_keys
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?
                .remove(&id);
            self.signer_backend
                .delete_vault_key_if_present(id)
                .map_err(DaemonError::Signer)?;
        }
        Err(err)
    }

    fn bootstrap_result(
        &self,
        outcome: WalletBootstrapOutcome,
        vault_key: VaultKey,
        agent_credentials: AgentCredentials,
        replaced_vault_key_ids: Vec<Uuid>,
        now: OffsetDateTime,
    ) -> Result<WalletBootstrap, DaemonError> {
        let (evm_address, solana_address) = self.wallet_addresses(&vault_key)?;
        let spending_limits = self.spending_limits_report(agent_credentials.agent_key.id, now)?;
        Ok(WalletBootstrap {
            outcome,
            vault_key,
            evm_address,
            solana_address,
            agent_credentials,
            spending_limits,
            replaced_vault_key_ids,
        })
    }
}
