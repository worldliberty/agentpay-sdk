//! Encrypted on-disk daemon state: store configuration, the persisted state
//! schema, and the [`EncryptedStateStore`] that loads, migrates, and saves it.

use std::collections::HashMap;
use std::path::PathBuf;

use agentpay_domain::serde_helpers::retired;
use agentpay_domain::{
    AdminCredential, AgentKey, ManualApprovalRequest, NonceReservation, SpendEvent, SpendingPolicy,
    VaultKey,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::envelope::legacy::{open_legacy_state, KdfLimits};
use self::envelope::{
    envelope_version, open_state, seal_state, StateKey, ENVELOPE_VERSION,
    LEGACY_PASSWORD_ENVELOPE_VERSION, NONCE_LEN,
};
pub use self::secret::{LegacyStatePassword, StateSecret, STATE_SECRET_LEN};
use self::secure_fs::{atomic_write_secure, ensure_secure_path, read_file_secure};
use crate::daemon::{
    prepare_loaded_state, validate_loaded_state, RecoverableAgentResult, ReusableNonceGaps,
    SignedBroadcastRecord, TempoChannelRecord,
};

mod envelope;
mod secret;
mod secure_fs;
#[cfg(test)]
mod tests;

/// Configuration for encrypted, persistent daemon state storage.
#[derive(Debug, Clone)]
pub struct PersistentStoreConfig {
    /// Filesystem path to the encrypted state file.
    pub path: PathBuf,
    legacy_password: Option<LegacyStatePassword>,
    allow_current_uid_in_tests: bool,
}

impl PersistentStoreConfig {
    /// Creates a new persistent-store config for `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            legacy_password: None,
            allow_current_uid_in_tests: false,
        }
    }

    /// Requests a one-time migration of a legacy v1 (vault password) state file.
    ///
    /// When the file at `path` is a v1 envelope, it is decrypted with `password`
    /// and atomically rewritten as a v2 envelope keyed by the state secret. A
    /// file that is already v2 opens normally, so the migration is idempotent.
    /// A missing file is an error: there is nothing to migrate.
    #[must_use]
    pub fn with_legacy_password_migration(mut self, password: LegacyStatePassword) -> Self {
        self.legacy_password = Some(password);
        self
    }

    #[cfg(test)]
    pub(crate) fn new_test(path: PathBuf) -> Self {
        Self {
            allow_current_uid_in_tests: true,
            ..Self::new(path)
        }
    }
}

/// Newest persisted-state schema this daemon build understands.
///
/// Files written by a newer daemon carry a higher version and are rejected at
/// load time instead of being silently reinterpreted.
const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Schema version tag stored inside the encrypted state payload.
///
/// Legacy files without the field deserialize as version 1.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub(crate) struct SchemaVersion(pub u32);

impl Default for SchemaVersion {
    fn default() -> Self {
        Self(CURRENT_SCHEMA_VERSION)
    }
}

/// Decrypted daemon state.
///
/// Older files may still carry fields and entries for retired features
/// (Railgun keys, policies and recipients, legacy Tempo sessions v1 and
/// Permit2 approvals, relay configuration and its X25519 private key). Unknown
/// top-level fields are ignored and the `retired::*` deserializers drop the
/// retired entries, so such files keep loading; the next save rewrites them
/// without the retired data.
#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct PersistedDaemonState {
    pub schema_version: SchemaVersion,
    /// Enrolled admin credentials (Secure Enclave public keys). Older state
    /// files predate admin credentials and load with an empty map. Admin leases
    /// are deliberately not persisted: they die with the daemon process.
    pub admin_credentials: HashMap<Uuid, AdminCredential>,
    #[serde(deserialize_with = "retired::policy_map")]
    pub policies: HashMap<Uuid, SpendingPolicy>,
    #[serde(deserialize_with = "retired::vault_key_map")]
    pub vault_keys: HashMap<Uuid, VaultKey>,
    #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string_map")]
    pub software_signer_private_keys: HashMap<Uuid, Zeroizing<String>>,
    pub agent_keys: HashMap<Uuid, AgentKey>,
    pub agent_auth_tokens: HashMap<Uuid, [u8; 32]>,
    pub replay_ids: HashMap<Uuid, OffsetDateTime>,
    pub nonce_heads: HashMap<Uuid, HashMap<u64, u64>>,
    pub reusable_nonce_gaps: ReusableNonceGaps,
    pub nonce_reservations: HashMap<Uuid, NonceReservation>,
    pub recoverable_agent_results: HashMap<Uuid, RecoverableAgentResult>,
    #[serde(deserialize_with = "retired::spend_log")]
    pub spend_log: Vec<SpendEvent>,
    #[serde(deserialize_with = "retired::manual_approval_map")]
    pub manual_approval_requests: HashMap<Uuid, ManualApprovalRequest>,
    /// Tempo session channels opened through this daemon, keyed by channel id.
    /// Older state files predate the registry and load with an empty map.
    pub tempo_channels: HashMap<String, TempoChannelRecord>,
    /// Recently signed `BroadcastTx` transactions whose nonce may still be
    /// released (`ReleaseSignedNonce`), keyed by lowercase `0x` hash. Older
    /// state files load with an empty map.
    pub signed_broadcasts: HashMap<String, SignedBroadcastRecord>,
}

impl std::fmt::Debug for PersistedDaemonState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistedDaemonState")
            .field("schema_version", &self.schema_version)
            .field("admin_credentials", &self.admin_credentials)
            .field("policies", &self.policies)
            .field("vault_keys", &self.vault_keys)
            .field("software_signer_private_keys", &"<redacted>")
            .field("agent_keys", &self.agent_keys)
            .field("agent_auth_tokens", &"<redacted>")
            .field("replay_ids", &self.replay_ids)
            .field("nonce_heads", &self.nonce_heads)
            .field("nonce_reservations", &self.nonce_reservations)
            .field("spend_log", &self.spend_log)
            .field("manual_approval_requests", &self.manual_approval_requests)
            .field("tempo_channels", &self.tempo_channels)
            .field("signed_broadcasts", &self.signed_broadcasts)
            .finish()
    }
}

pub(crate) struct EncryptedStateStore {
    path: PathBuf,
    key: StateKey,
    allow_current_uid_in_tests: bool,
}

impl EncryptedStateStore {
    /// Opens the state file at `store.path`, creating an empty state when it does
    /// not exist yet and migrating a legacy v1 file when a legacy password is set.
    pub(crate) fn open_or_initialize(
        secret: &StateSecret,
        config: &crate::DaemonConfig,
        store: PersistentStoreConfig,
    ) -> Result<(Self, PersistedDaemonState), String> {
        let PersistentStoreConfig {
            path,
            legacy_password,
            allow_current_uid_in_tests,
        } = store;
        ensure_secure_path(&path, allow_current_uid_in_tests)?;
        if !path.exists() {
            if legacy_password.is_some() {
                return Err(format!(
                    "cannot migrate state file '{}': it does not exist",
                    path.display()
                ));
            }
            let state = prepare_loaded_state(PersistedDaemonState::default())
                .map_err(|err| format!("default state failed integrity validation: {err}"))?;
            let store = Self {
                path,
                key: StateKey::generate(secret)?,
                allow_current_uid_in_tests,
            };
            return Ok((store, state));
        }

        let bytes = read_file_secure(&path, allow_current_uid_in_tests)?;
        match envelope_version(&bytes)? {
            ENVELOPE_VERSION => {
                let (state, key) = open_state(&bytes, secret)?;
                let store = Self {
                    path,
                    key,
                    allow_current_uid_in_tests,
                };
                Ok((store, state))
            }
            LEGACY_PASSWORD_ENVELOPE_VERSION => {
                let Some(password) = legacy_password else {
                    return Err(format!(
                        "state file '{}' uses the legacy vault-password envelope (v1) and must be \
                         migrated once by supplying the legacy vault password \
                         (agentpay-daemon --migrate-from-password-stdin)",
                        path.display()
                    ));
                };
                let state =
                    open_legacy_state(&bytes, password.expose(), &KdfLimits::from_config(config))?;
                let store = Self {
                    path,
                    key: StateKey::generate(secret)?,
                    allow_current_uid_in_tests,
                };
                store
                    .save(&state)
                    .map_err(|err| format!("failed to write migrated state: {err}"))?;
                Ok((store, state))
            }
            version => Err(format!(
                "unsupported state file version {version}; expected {ENVELOPE_VERSION}"
            )),
        }
    }

    /// Validates, seals under a fresh nonce, and atomically replaces the state file.
    pub(crate) fn save(&self, state: &PersistedDaemonState) -> Result<(), String> {
        validate_loaded_state(state)
            .map_err(|err| format!("refusing to persist invalid state: {err}"))?;
        ensure_secure_path(&self.path, self.allow_current_uid_in_tests)?;
        let bytes = Zeroizing::new(seal_state(
            state,
            &self.key,
            rand::random::<[u8; NONCE_LEN]>(),
        )?);
        atomic_write_secure(&self.path, &bytes)
    }
}
