//! `ListWallets` and `RenameWallet`: the vault keys on this machine with
//! their names, addresses, and agent keys. Public metadata only; nothing
//! secret leaves the daemon.

use std::collections::BTreeMap;

use agentpay_api::rpc::wallet::WalletInfo;
use agentpay_domain::{AdminAuth, VaultKey};
use agentpay_signer::VaultSignerBackend;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DaemonError, InMemoryDaemon, RequestContext};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Every vault key, oldest first (then by id), with its agent keys ascending.
    pub(crate) fn list_wallets_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
    ) -> Result<Vec<WalletInfo>, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let mut vault_keys = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        vault_keys.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then(left.id.cmp(&right.id))
        });
        let mut agents_by_wallet: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        for agent in self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
        {
            agents_by_wallet
                .entry(agent.vault_key_id)
                .or_default()
                .push(agent.id);
        }
        vault_keys
            .into_iter()
            .map(|vault_key| {
                let agent_key_ids = agents_by_wallet.remove(&vault_key.id).unwrap_or_default();
                self.wallet_info(vault_key, agent_key_ids)
            })
            .collect()
    }

    /// Sets (or with `None` clears) a wallet's name and persists it.
    pub(crate) async fn rename_wallet_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        name: Option<String>,
    ) -> Result<WalletInfo, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let name = super::wallet_name(name)?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let vault_key = {
            let mut vault_keys = self
                .vault_keys
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let vault_key = vault_keys
                .get_mut(&vault_key_id)
                .ok_or(DaemonError::UnknownVaultKey(vault_key_id))?;
            vault_key.name = name;
            vault_key.clone()
        };
        self.persist_or_revert(backup)?;
        let agent_key_ids = self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .filter(|agent| agent.vault_key_id == vault_key_id)
            .map(|agent| agent.id)
            .collect();
        self.wallet_info(vault_key, agent_key_ids)
    }

    /// The listing entry of `vault_key`, with `agent_key_ids` sorted.
    fn wallet_info(
        &self,
        vault_key: VaultKey,
        mut agent_key_ids: Vec<Uuid>,
    ) -> Result<WalletInfo, DaemonError> {
        let (evm_address, solana_address) = self.wallet_addresses(&vault_key)?;
        agent_key_ids.sort_unstable();
        Ok(WalletInfo {
            vault_key_id: vault_key.id,
            algorithm: vault_key.algorithm,
            evm_address,
            solana_address,
            created_at: vault_key.created_at,
            source: vault_key.source,
            name: vault_key.name,
            agent_key_ids,
        })
    }
}
