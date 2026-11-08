//! Vault key and agent key lifecycle: creation, policy attachment refresh,
//! auth-token rotation, and revocation.

use agentpay_domain::{AdminAuth, AgentCredentials, AgentKey, PolicyAttachment, VaultKey};
use agentpay_signer::{KeyCreateRequest, SignerError, VaultSignerBackend};
use time::OffsetDateTime;
use uuid::Uuid;

use super::auth::{generate_agent_auth_token, hash_agent_auth_token};
use crate::{DaemonError, InMemoryDaemon, RequestContext};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn create_vault_key_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        // Authorize before snapshotting so unauthorized callers never trigger a
        // key-material export.
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        let vault_key = self.signer_backend.create_vault_key(request).await?;
        if let Err(err) = self
            .vault_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)
            .map(|mut vault_keys| {
                vault_keys.insert(vault_key.id, vault_key.clone());
            })
        {
            if let Err(cleanup_err) = self
                .signer_backend
                .delete_vault_key_if_present(vault_key.id)
            {
                return Err(DaemonError::Signer(SignerError::Internal(format!(
                    "create_vault_key cleanup failed after error `{err}`: {cleanup_err}"
                ))));
            }
            return Err(err);
        }
        if let Err(err) = self.persist_or_revert(backup) {
            if let Err(cleanup_err) = self
                .signer_backend
                .delete_vault_key_if_present(vault_key.id)
            {
                return Err(DaemonError::Signer(SignerError::Internal(format!(
                    "create_vault_key cleanup failed after error `{err}`: {cleanup_err}"
                ))));
            }
            return Err(err);
        }
        Ok(vault_key)
    }

    pub(crate) async fn solana_public_key_hex_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;

        if !self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .contains_key(&vault_key_id)
        {
            return Err(DaemonError::UnknownVaultKey(vault_key_id));
        }

        self.signer_backend
            .solana_public_key_hex(vault_key_id)
            .map_err(DaemonError::Signer)
    }

    pub(crate) async fn create_agent_key_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        let now = OffsetDateTime::now_utc();
        self.authorize_admin(ctx, auth, now)?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        if !self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .contains_key(&vault_key_id)
        {
            return Err(DaemonError::UnknownVaultKey(vault_key_id));
        }

        validate_agent_key_attachment(self, &attachment)?;

        let agent_key = AgentKey {
            id: Uuid::new_v4(),
            vault_key_id,
            policies: attachment,
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

        self.persist_or_revert(backup)?;
        Ok(AgentCredentials {
            agent_key,
            auth_token: auth_token.into(),
        })
    }

    pub(crate) async fn refresh_agent_key_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        validate_agent_key_attachment(self, &attachment)?;

        let agent_key = {
            let mut agent_keys = self
                .agent_keys
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let agent_key = agent_keys
                .get_mut(&agent_key_id)
                .ok_or(DaemonError::UnknownAgentKey(agent_key_id))?;
            if agent_key.vault_key_id != vault_key_id {
                return Err(DaemonError::InvalidPolicyAttachment(format!(
                    "agent key {agent_key_id} belongs to vault key {} instead of requested vault key {vault_key_id}",
                    agent_key.vault_key_id
                )));
            }
            agent_key.policies = attachment;
            agent_key.clone()
        };

        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key_id, hash_agent_auth_token(&auth_token));
        self.persist_or_revert(backup)?;
        Ok(AgentCredentials {
            agent_key,
            auth_token: auth_token.into(),
        })
    }

    pub(crate) async fn rotate_agent_auth_token_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        if !self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .contains_key(&agent_key_id)
        {
            return Err(DaemonError::UnknownAgentKey(agent_key_id));
        }

        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key_id, hash_agent_auth_token(&auth_token));
        self.persist_or_revert(backup)?;
        Ok(auth_token)
    }

    pub(crate) async fn revoke_agent_key_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let now = OffsetDateTime::now_utc();
        if !self.purge_agent_key(agent_key_id, now)? {
            return Err(DaemonError::UnknownAgentKey(agent_key_id));
        }
        self.persist_or_revert(backup)?;
        Ok(())
    }

    /// Removes an agent key and everything tied to it: its token, spend
    /// history, nonce reservations, manual approval requests, recoverable
    /// results, Tempo channels, and releasable signed transactions. Returns
    /// whether the agent key existed. The caller holds the signing and state
    /// guards and persists.
    pub(super) fn purge_agent_key(
        &self,
        agent_key_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DaemonError> {
        let _ = self.manual_approval_retention_cutoffs(now)?;

        let removed = self
            .agent_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .remove(&agent_key_id)
            .is_some();
        if !removed {
            return Ok(false);
        }

        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .remove(&agent_key_id);
        self.spend_log
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|event| event.agent_key_id != agent_key_id);
        let removed_reservations = {
            let mut reservations = self
                .nonce_reservations
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let removed = reservations
                .values()
                .filter(|reservation| reservation.agent_key_id == agent_key_id)
                .cloned()
                .collect::<Vec<_>>();
            reservations.retain(|_, reservation| reservation.agent_key_id != agent_key_id);
            removed
        };
        self.reclaim_unused_nonce_heads(&removed_reservations)?;
        self.manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, request| request.agent_key_id != agent_key_id);
        self.prune_manual_approval_requests(now)?;
        self.recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, result| result.agent_key_id != agent_key_id);
        self.tempo_channels
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, record| record.agent_key_id != agent_key_id);
        self.forget_signed_broadcasts_of_agent(agent_key_id)?;
        self.prune_manual_approval_requests(now)?;
        Ok(true)
    }
}

fn validate_agent_key_attachment<B: VaultSignerBackend>(
    daemon: &InMemoryDaemon<B>,
    attachment: &PolicyAttachment,
) -> Result<(), DaemonError> {
    if let PolicyAttachment::PolicySet(ids) = attachment {
        if ids.is_empty() {
            return Err(DaemonError::InvalidPolicyAttachment(
                "policy set cannot be empty".to_string(),
            ));
        }
        let policies = daemon
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        for id in ids {
            let policy = policies.get(id).ok_or(DaemonError::UnknownPolicy(*id))?;
            if !policy.enabled {
                return Err(DaemonError::InvalidPolicyAttachment(format!(
                    "policy {id} is disabled and would not be enforced; enable it before attaching it to an agent key",
                )));
            }
        }
    }

    Ok(())
}
