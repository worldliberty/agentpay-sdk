//! Persisted MPP session channels: `<state dir>/mpp-sessions.json`.
//!
//! One file holds every persisted channel, keyed by agent key id and
//! `session_key`. It is written to a fresh `0600` temporary file that is
//! synced and renamed into place, and read only when it is a private
//! regular file of the service account (like `config.json`). Records hold no
//! secrets: channel terms, the deposit, and the highest cumulative amount the
//! agent has signed.
//!
//! [`SessionLocks`] serializes calls that use the same channel, and every
//! read-modify-write of the file.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use agentpay_api::payments::mpp::MAX_SESSION_KEY_BYTES;
use agentpay_domain::{u128_as_decimal_string, EvmAddress};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{read_trusted, write_atomically};
use crate::error::PaymentsError;

/// File name in the state directory.
pub(crate) const SESSIONS_FILE_NAME: &str = "mpp-sessions.json";
/// Format version of the file.
const SESSIONS_SCHEMA: u32 = 1;
/// Most persisted channels; the oldest are dropped from the file beyond it.
const MAX_SESSIONS: usize = 256;

/// One persisted TIP-1034 channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionRecord {
    /// The agent that opened it.
    pub(crate) agent_key_id: Uuid,
    /// The caller's name for it.
    pub(crate) session_key: String,
    /// Origin (`scheme://host:port`) of the URL that opened it.
    pub(crate) origin: String,
    /// Tempo chain id.
    pub(crate) chain_id: u64,
    /// TIP-20 token.
    pub(crate) token: EvmAddress,
    /// Payee.
    pub(crate) recipient: EvmAddress,
    /// Operator (zero address when unused).
    pub(crate) operator: EvmAddress,
    /// Payer and authorized signer: the agent's wallet.
    pub(crate) payer: EvmAddress,
    /// Channel salt, `0x` + 64 hex.
    pub(crate) salt_hex: String,
    /// Descriptor `expiringNonceHash`, `0x` + 64 hex.
    pub(crate) expiring_nonce_hash_hex: String,
    /// Channel id, `0x` + 64 hex.
    pub(crate) channel_id_hex: String,
    /// Total deposit (base units).
    #[serde(with = "u128_as_decimal_string")]
    pub(crate) deposit: u128,
    /// Highest cumulative amount signed (base units).
    #[serde(with = "u128_as_decimal_string")]
    pub(crate) cumulative: u128,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SessionsFile {
    schema: u32,
    sessions: Vec<SessionRecord>,
}

/// One async lock per `(agent, session_key)`.
type ChannelLocks = HashMap<(Uuid, String), Arc<tokio::sync::Mutex<()>>>;

/// Serializes use of one channel and access to the file.
#[derive(Default)]
pub struct SessionLocks {
    channels: Mutex<ChannelLocks>,
    file: Mutex<()>,
}

impl SessionLocks {
    /// The lock for `(agent, session_key)`; hold it for a whole call.
    pub(crate) fn channel(&self, agent: Uuid, session_key: &str) -> Arc<tokio::sync::Mutex<()>> {
        match self.channels.lock() {
            Ok(mut channels) => channels
                .entry((agent, session_key.to_string()))
                .or_default()
                .clone(),
            // A poisoned map still yields a usable (unshared) lock.
            Err(_) => Arc::default(),
        }
    }
}

/// Checks a `session_key`: 1 to 64 characters from `A-Z a-z 0-9 . _ : -`.
pub(crate) fn check_session_key(key: &str) -> Result<(), PaymentsError> {
    let valid = !key.is_empty()
        && key.len() <= MAX_SESSION_KEY_BYTES
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'));
    if valid {
        Ok(())
    } else {
        Err(PaymentsError::InvalidRequest(format!(
            "session_key must be 1 to {MAX_SESSION_KEY_BYTES} characters from A-Z a-z 0-9 . _ : -"
        )))
    }
}

/// The persisted channels of one state directory.
pub(crate) struct SessionStore<'a> {
    path: PathBuf,
    locks: &'a SessionLocks,
}

impl<'a> SessionStore<'a> {
    /// The store in `state_dir`.
    pub(crate) fn new(state_dir: &Path, locks: &'a SessionLocks) -> Self {
        Self {
            path: state_dir.join(SESSIONS_FILE_NAME),
            locks,
        }
    }

    /// The channel persisted for `(agent, session_key)`.
    pub(crate) fn load(
        &self,
        agent: Uuid,
        session_key: &str,
    ) -> Result<Option<SessionRecord>, PaymentsError> {
        let _guard = self.file_guard()?;
        Ok(self
            .read()?
            .sessions
            .into_iter()
            .find(|record| record.agent_key_id == agent && record.session_key == session_key))
    }

    /// Inserts or replaces `record`.
    pub(crate) fn save(&self, record: &SessionRecord) -> Result<(), PaymentsError> {
        let _guard = self.file_guard()?;
        let mut file = self.read()?;
        file.sessions.retain(|existing| !same_key(existing, record));
        file.sessions.push(record.clone());
        if file.sessions.len() > MAX_SESSIONS {
            let excess = file.sessions.len() - MAX_SESSIONS;
            file.sessions.drain(..excess);
        }
        self.write(&file)
    }

    /// Forgets the channel persisted for `(agent, session_key)`.
    pub(crate) fn remove(&self, agent: Uuid, session_key: &str) -> Result<(), PaymentsError> {
        let _guard = self.file_guard()?;
        let mut file = self.read()?;
        let before = file.sessions.len();
        file.sessions
            .retain(|record| !(record.agent_key_id == agent && record.session_key == session_key));
        if file.sessions.len() == before {
            return Ok(());
        }
        self.write(&file)
    }

    fn file_guard(&self) -> Result<std::sync::MutexGuard<'a, ()>, PaymentsError> {
        self.locks
            .file
            .lock()
            .map_err(|_| PaymentsError::Internal("the session store lock is poisoned".into()))
    }

    fn read(&self) -> Result<SessionsFile, PaymentsError> {
        let Some(bytes) = read_trusted(&self.path).map_err(PaymentsError::Persistence)? else {
            return Ok(SessionsFile {
                schema: SESSIONS_SCHEMA,
                sessions: Vec::new(),
            });
        };
        let file: SessionsFile = serde_json::from_slice(&bytes).map_err(|_| {
            PaymentsError::Persistence(format!("{SESSIONS_FILE_NAME} is not a valid session file"))
        })?;
        if file.schema != SESSIONS_SCHEMA {
            return Err(PaymentsError::Persistence(format!(
                "{SESSIONS_FILE_NAME} has unsupported schema {}",
                file.schema
            )));
        }
        Ok(file)
    }

    fn write(&self, file: &SessionsFile) -> Result<(), PaymentsError> {
        let bytes = serde_json::to_vec_pretty(file)
            .map_err(|_| PaymentsError::Internal("failed to encode the session file".into()))?;
        write_atomically(&self.path, &bytes).map_err(|_| {
            PaymentsError::Persistence(format!("failed to write {SESSIONS_FILE_NAME}"))
        })
    }
}

fn same_key(left: &SessionRecord, right: &SessionRecord) -> bool {
    left.agent_key_id == right.agent_key_id && left.session_key == right.session_key
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::str::FromStr;

    use super::*;
    use crate::test_support::{set_mode, TempDir};

    fn record(agent: Uuid, key: &str, cumulative: u128) -> SessionRecord {
        let address =
            EvmAddress::from_str("0x2c7536e3605d9c16a7a3d7b1898e529396a65c23").expect("address");
        SessionRecord {
            agent_key_id: agent,
            session_key: key.into(),
            origin: "https://llm.example.com".into(),
            chain_id: 42431,
            token: address.clone(),
            recipient: address.clone(),
            operator: address.clone(),
            payer: address,
            salt_hex: format!("0x{}", "11".repeat(32)),
            expiring_nonce_hash_hex: format!("0x{}", "22".repeat(32)),
            channel_id_hex: format!("0x{}", "33".repeat(32)),
            deposit: 1_000_000,
            cumulative,
        }
    }

    #[test]
    fn records_round_trip_per_agent_and_key_in_a_private_file() {
        let dir = TempDir::new("mpp-store");
        let locks = SessionLocks::default();
        let store = SessionStore::new(dir.path(), &locks);
        let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(store.load(alice, "llm").expect("load"), None);

        store.save(&record(alice, "llm", 10)).expect("save");
        store.save(&record(bob, "llm", 20)).expect("save");
        store.save(&record(alice, "llm", 30)).expect("replace");
        assert_eq!(
            store
                .load(alice, "llm")
                .expect("load")
                .map(|r| r.cumulative),
            Some(30)
        );
        assert_eq!(
            store.load(bob, "llm").expect("load").map(|r| r.cumulative),
            Some(20)
        );
        let mode = std::fs::metadata(dir.path().join(SESSIONS_FILE_NAME))
            .expect("file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        store.remove(alice, "llm").expect("remove");
        assert_eq!(store.load(alice, "llm").expect("load"), None);
        assert!(store.load(bob, "llm").expect("load").is_some());
    }

    #[test]
    fn a_readable_or_corrupt_file_is_refused() {
        let dir = TempDir::new("mpp-store");
        let locks = SessionLocks::default();
        let store = SessionStore::new(dir.path(), &locks);
        store.save(&record(Uuid::new_v4(), "k", 1)).expect("save");
        let path = dir.path().join(SESSIONS_FILE_NAME);
        set_mode(&path, 0o644);
        assert!(matches!(
            store.load(Uuid::new_v4(), "k"),
            Err(PaymentsError::Persistence(_))
        ));
        set_mode(&path, 0o600);
        std::fs::write(&path, b"{not json").expect("corrupt");
        assert!(matches!(
            store.load(Uuid::new_v4(), "k"),
            Err(PaymentsError::Persistence(_))
        ));
    }

    #[test]
    fn session_keys_are_restricted() {
        for good in ["llm", "proxy:api.example.com:443", "a.b_c-d"] {
            assert!(check_session_key(good).is_ok(), "{good}");
        }
        for bad in ["", "has space", "slash/", &"x".repeat(65)] {
            assert!(check_session_key(bad).is_err(), "{bad}");
        }
    }
}
