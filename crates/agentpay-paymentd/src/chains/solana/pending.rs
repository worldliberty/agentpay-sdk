//! [`PendingStore`]: Solana signing actions waiting for a manual approval,
//! persisted so the same call can resume them.
//!
//! The signer daemon matches a resent request to its approval by the exact
//! payload bytes. A Solana transfer rebuilt later would differ (a new
//! priority fee estimate, a new blockhash), so when signing stops at
//! `ManualApprovalPending` the flow stores the exact action under a key
//! derived from the agent and the call's intent ([`intent_key`]). When the
//! same agent sends the same call again, the stored action is resent. Only
//! durable nonce actions can be approved, and their blockhash (the nonce
//! value) stays valid until the nonce account is advanced; the flow discards
//! a stored action whose nonce has moved on.
//!
//! Each entry also records the agent, method, network, and options, so that
//! `ResumeApproved` can find it by approval request id ([`PendingStore::find`])
//! and finish the call as it was asked.
//!
//! The file is `<state dir>/solana-pending.json` (mode `0600`, checked like
//! `config.json`). Entries expire with the signer daemon's approval requests,
//! after 24 hours.

use std::collections::BTreeMap;
use std::path::PathBuf;

use agentpay_api::payments::SolanaTransferOptions;
use agentpay_domain::AgentAction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::{read_trusted, write_atomically};
use crate::error::PaymentsError;

/// File name inside the state directory.
pub const PENDING_FILE_NAME: &str = "solana-pending.json";
/// How long a stored action is kept (the signer daemon's approval lifetime).
const PENDING_TTL: time::Duration = time::Duration::hours(24);
/// Most stored actions kept; the oldest are dropped first.
const MAX_PENDING: usize = 256;

/// A stored action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAction {
    /// The agent that made the call; only it can resume the action.
    pub agent_key_id: Uuid,
    /// `TransferSol` or `TransferSpl`.
    pub method: String,
    /// The chain key the call named.
    pub network: String,
    /// The call's options (broadcast, confirmation, nonce mode, ...).
    pub options: SolanaTransferOptions,
    /// The exact action that was sent to the signer daemon.
    pub action: AgentAction,
    /// The signer daemon's approval request for it.
    pub approval_request_id: Uuid,
    /// When it was stored (Unix seconds); set by [`PendingStore::put`].
    pub stored_at: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredFile {
    schema: u32,
    entries: BTreeMap<String, PendingAction>,
}

/// Pending Solana actions by intent key.
#[derive(Debug)]
pub struct PendingStore {
    path: Option<PathBuf>,
    entries: Mutex<BTreeMap<String, PendingAction>>,
}

impl PendingStore {
    /// Loads `path`, starting empty when it does not exist. An unreadable or
    /// untrusted file is ignored with a warning: losing a pending action only
    /// means the next call creates a new approval request.
    #[must_use]
    pub fn open(path: PathBuf) -> Self {
        let entries = match read_trusted(&path) {
            Ok(Some(bytes)) => match serde_json::from_slice::<StoredFile>(&bytes) {
                Ok(file) => file.entries,
                Err(_) => {
                    tracing::warn!(
                        file = PENDING_FILE_NAME,
                        "ignoring an unreadable pending file"
                    );
                    BTreeMap::new()
                }
            },
            Ok(None) => BTreeMap::new(),
            Err(_) => {
                tracing::warn!(
                    file = PENDING_FILE_NAME,
                    "ignoring an untrusted pending file"
                );
                BTreeMap::new()
            }
        };
        Self {
            path: Some(path),
            entries: Mutex::new(entries),
        }
    }

    /// A store that is never written to disk (tests).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            path: None,
            entries: Mutex::new(BTreeMap::new()),
        }
    }

    /// The unexpired action stored under `key`.
    pub async fn get(&self, key: &str) -> Option<PendingAction> {
        let entries = self.entries.lock().await;
        entries
            .get(key)
            .filter(|entry| !expired(entry, now()))
            .cloned()
    }

    /// The unexpired entry of `agent_key_id` for `approval_request_id`,
    /// with its key.
    pub async fn find(
        &self,
        agent_key_id: Uuid,
        approval_request_id: Uuid,
    ) -> Option<(String, PendingAction)> {
        let entries = self.entries.lock().await;
        let now = now();
        entries
            .iter()
            .find(|(_, entry)| {
                entry.agent_key_id == agent_key_id
                    && entry.approval_request_id == approval_request_id
                    && !expired(entry, now)
            })
            .map(|(key, entry)| (key.clone(), entry.clone()))
    }

    /// Stores `entry` under `key`, replacing any earlier one.
    pub async fn put(&self, key: &str, mut entry: PendingAction) -> Result<(), PaymentsError> {
        let mut entries = self.entries.lock().await;
        let now = now();
        entries.retain(|_, entry| !expired(entry, now));
        entry.stored_at = now;
        entries.insert(key.to_string(), entry);
        while entries.len() > MAX_PENDING {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.stored_at)
                .map(|(key, _)| key.clone());
            match oldest {
                Some(oldest) => entries.remove(&oldest),
                None => break,
            };
        }
        self.persist(&entries)
    }

    /// Forgets `key`; does nothing when it is not stored.
    pub async fn remove(&self, key: &str) -> Result<(), PaymentsError> {
        let mut entries = self.entries.lock().await;
        if entries.remove(key).is_none() {
            return Ok(());
        }
        self.persist(&entries)
    }

    fn persist(&self, entries: &BTreeMap<String, PendingAction>) -> Result<(), PaymentsError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let file = StoredFile {
            schema: 1,
            entries: entries.clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(|err| {
            PaymentsError::Internal(format!("failed to encode pending actions: {err}"))
        })?;
        write_atomically(path, &bytes).map_err(|_| {
            PaymentsError::Persistence("failed to write the pending Solana actions".into())
        })
    }
}

/// The store key of one call: SHA-256 over the agent key id, the method, and
/// the call's intent (everything that determines the action except values
/// read from the chain), as lower-case hex.
pub fn intent_key(agent_key_id: Uuid, method: &str, intent: &impl Serialize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_key_id.as_bytes());
    hasher.update(method.as_bytes());
    hasher.update([0]);
    // Serializing plain data cannot fail; an empty intent would only make
    // the key coarser, never wrong for another agent.
    hasher.update(serde_json::to_vec(intent).unwrap_or_default());
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn expired(entry: &PendingAction, now: i64) -> bool {
    now.saturating_sub(entry.stored_at) > PENDING_TTL.whole_seconds()
}

#[cfg(test)]
mod tests {
    use agentpay_domain::{SolanaAddress, SolanaNonceAccountCreate};

    use super::*;
    use crate::test_support::TempDir;

    fn entry(seed: &str, approval_request_id: Uuid) -> PendingAction {
        PendingAction {
            agent_key_id: Uuid::nil(),
            method: "TransferSol".into(),
            network: "solana-devnet".into(),
            options: SolanaTransferOptions::default(),
            action: action(seed),
            approval_request_id,
            stored_at: 0,
        }
    }

    fn action(seed: &str) -> AgentAction {
        let wallet: SolanaAddress = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
            .parse()
            .expect("address");
        AgentAction::SolanaNonceAccountCreate {
            create: SolanaNonceAccountCreate {
                chain_id: agentpay_domain::SOLANA_DEVNET_CHAIN_ID,
                recent_blockhash: "11111111111111111111111111111111".into(),
                fee_payer: wallet.clone(),
                nonce_account: wallet,
                seed: seed.into(),
                rent_lamports: 1,
            },
        }
    }

    #[tokio::test]
    async fn actions_survive_a_restart_and_can_be_removed() {
        let dir = TempDir::new("pending");
        let path = dir.path().join(PENDING_FILE_NAME);
        let id = Uuid::new_v4();
        let store = PendingStore::open(path.clone());
        assert!(store.get("k").await.is_none());
        store.put("k", entry("a", id)).await.expect("put");
        assert_eq!(
            store.find(Uuid::nil(), id).await.map(|(key, _)| key),
            Some("k".into())
        );
        assert!(
            store.find(Uuid::new_v4(), id).await.is_none(),
            "other agents"
        );

        let reopened = PendingStore::open(path.clone());
        let entry = reopened.get("k").await.expect("persisted");
        assert_eq!(entry.action, action("a"));
        assert_eq!(entry.approval_request_id, id);
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("file").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        reopened.remove("k").await.expect("remove");
        assert!(PendingStore::open(path).get("k").await.is_none());
    }

    #[tokio::test]
    async fn expired_and_untrusted_entries_are_ignored() {
        let dir = TempDir::new("pending");
        let path = dir.path().join(PENDING_FILE_NAME);
        let store = PendingStore::open(path.clone());
        store
            .put("old", entry("a", Uuid::new_v4()))
            .await
            .expect("put");
        store
            .entries
            .lock()
            .await
            .get_mut("old")
            .expect("entry")
            .stored_at -= PENDING_TTL.whole_seconds() + 1;
        assert!(store.get("old").await.is_none());

        crate::test_support::set_mode(&path, 0o644);
        assert!(PendingStore::open(path).get("old").await.is_none());
    }

    #[test]
    fn intent_keys_separate_agents_methods_and_intents() {
        let agent = Uuid::new_v4();
        let key = intent_key(agent, "TransferSol", &("to", 1));
        assert_eq!(key.len(), 64);
        assert_eq!(key, intent_key(agent, "TransferSol", &("to", 1)));
        assert_ne!(key, intent_key(Uuid::new_v4(), "TransferSol", &("to", 1)));
        assert_ne!(key, intent_key(agent, "TransferSpl", &("to", 1)));
        assert_ne!(key, intent_key(agent, "TransferSol", &("to", 2)));
    }
}
