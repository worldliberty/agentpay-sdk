use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use argon2::{Argon2, ParamsBuilder};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use vault_domain::{
    AgentKey, Lease, ManualApprovalRequest, NonceReservation, RelayConfig, SpendEvent,
    SpendingPolicy, VaultKey,
};
use zeroize::{Zeroize, Zeroizing};

use super::RecoverableAgentResult;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Configuration for encrypted, persistent daemon state storage.
#[derive(Debug, Clone)]
pub struct PersistentStoreConfig {
    /// Filesystem path to the encrypted state file.
    pub path: PathBuf,
    allow_current_uid_in_tests: bool,
}

impl PersistentStoreConfig {
    /// Creates a new persistent-store config for `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            allow_current_uid_in_tests: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_test(path: PathBuf) -> Self {
        Self {
            path,
            allow_current_uid_in_tests: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct PersistedDaemonState {
    pub leases: HashMap<Uuid, Lease>,
    pub policies: HashMap<Uuid, SpendingPolicy>,
    pub vault_keys: HashMap<Uuid, VaultKey>,
    #[serde(with = "vault_domain::serde_helpers::zeroizing_string_map")]
    pub software_signer_private_keys: HashMap<Uuid, Zeroizing<String>>,
    pub agent_keys: HashMap<Uuid, AgentKey>,
    pub agent_auth_tokens: HashMap<Uuid, [u8; 32]>,
    pub replay_ids: HashMap<Uuid, OffsetDateTime>,
    pub nonce_heads: HashMap<Uuid, HashMap<u64, u64>>,
    pub reusable_nonce_gaps: crate::ReusableNonceGaps,
    pub nonce_reservations: HashMap<Uuid, NonceReservation>,
    pub recoverable_agent_results: HashMap<Uuid, RecoverableAgentResult>,
    pub spend_log: Vec<SpendEvent>,
    pub manual_approval_requests: HashMap<Uuid, ManualApprovalRequest>,
    pub relay_config: RelayConfig,
    #[serde(with = "vault_domain::serde_helpers::zeroizing_string")]
    pub relay_private_key_hex: Zeroizing<String>,
}

impl std::fmt::Debug for PersistedDaemonState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PersistedDaemonState")
            .field("leases", &self.leases)
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
            .field("relay_config", &self.relay_config)
            .field("relay_private_key_hex", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KdfParams {
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EncryptedStateEnvelope {
    version: u8,
    kdf: KdfParams,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

const ENVELOPE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

pub(crate) struct EncryptedStateStore {
    path: PathBuf,
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    allow_current_uid_in_tests: bool,
}

impl Drop for EncryptedStateStore {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl EncryptedStateStore {
    pub(crate) fn open_or_initialize(
        password: &str,
        config: &crate::DaemonConfig,
        store: PersistentStoreConfig,
    ) -> Result<(Self, PersistedDaemonState), String> {
        let PersistentStoreConfig {
            path,
            allow_current_uid_in_tests,
        } = store;
        ensure_secure_path(&path, allow_current_uid_in_tests)?;
        if path.exists() {
            let bytes = read_file_secure(&path, allow_current_uid_in_tests)?;
            let (state, key, salt, kdf) = load_state_from_envelope_bytes(&bytes, password)?;
            Ok((
                Self {
                    path,
                    key,
                    salt,
                    kdf,
                    allow_current_uid_in_tests,
                },
                state,
            ))
        } else {
            let kdf = KdfParams {
                memory_kib: config.argon2_memory_kib,
                time_cost: config.argon2_time_cost,
                parallelism: config.argon2_parallelism,
            };
            let salt = rand::random::<[u8; SALT_LEN]>();
            let key = derive_key(password, &salt, &kdf)?;
            let state = crate::prepare_loaded_state(PersistedDaemonState::default())
                .map_err(|err| format!("default state failed integrity validation: {err}"))?;
            Ok((
                Self {
                    path,
                    key,
                    salt,
                    kdf,
                    allow_current_uid_in_tests,
                },
                state,
            ))
        }
    }

    pub(crate) fn save(&self, state: &PersistedDaemonState) -> Result<(), String> {
        crate::validate_loaded_state(state)
            .map_err(|err| format!("refusing to persist invalid state: {err}"))?;
        ensure_secure_path(&self.path, self.allow_current_uid_in_tests)?;
        let nonce = rand::random::<[u8; NONCE_LEN]>();
        let envelope =
            build_encrypted_state_envelope(state, &self.key, &self.salt, &self.kdf, nonce)?;
        let bytes = serialize_state_envelope(&envelope)?;
        atomic_write_secure(&self.path, &bytes)
    }
}

fn load_state_from_envelope_bytes(
    bytes: &[u8],
    password: &str,
) -> Result<
    (
        PersistedDaemonState,
        [u8; KEY_LEN],
        [u8; SALT_LEN],
        KdfParams,
    ),
    String,
> {
    let envelope: EncryptedStateEnvelope = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse state envelope: {err}"))?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(format!(
            "unsupported state file version {}; expected {}",
            envelope.version, ENVELOPE_VERSION
        ));
    }
    let kdf = envelope.kdf;
    let salt_bytes = hex::decode(&envelope.salt_hex)
        .map_err(|err| format!("invalid state salt encoding: {err}"))?;
    if salt_bytes.len() != SALT_LEN {
        return Err("invalid state salt length".to_string());
    }
    let nonce_bytes = hex::decode(&envelope.nonce_hex)
        .map_err(|err| format!("invalid state nonce encoding: {err}"))?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err("invalid state nonce length".to_string());
    }
    let ciphertext = hex::decode(&envelope.ciphertext_hex)
        .map_err(|err| format!("invalid state ciphertext encoding: {err}"))?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&salt_bytes);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce_bytes);
    let key = derive_key(password, &salt, &kdf)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt((&nonce).into(), ciphertext.as_ref())
            .map_err(|_| "failed to decrypt state (wrong password or tampered file)".to_string())?,
    );
    let state: PersistedDaemonState = serde_json::from_slice(&plaintext)
        .map_err(|err| format!("failed to deserialize state payload: {err}"))?;
    let state = crate::prepare_loaded_state(state)
        .map_err(|err| format!("loaded state failed integrity validation: {err}"))?;
    Ok((state, key, salt, kdf))
}

fn build_encrypted_state_envelope(
    state: &PersistedDaemonState,
    key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
    nonce: [u8; NONCE_LEN],
) -> Result<EncryptedStateEnvelope, String> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(state)
            .map_err(|err| format!("failed to serialize daemon state: {err}"))?,
    );
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext.as_ref())
        .map_err(|err| format!("failed to encrypt daemon state: {err}"))?;
    Ok(EncryptedStateEnvelope {
        version: ENVELOPE_VERSION,
        kdf: kdf.clone(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn serialize_state_envelope(envelope: &EncryptedStateEnvelope) -> Result<Vec<u8>, String> {
    serde_json::to_vec(envelope).map_err(|err| format!("failed to serialize state envelope: {err}"))
}

fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
) -> Result<[u8; KEY_LEN], String> {
    let params = ParamsBuilder::new()
        .m_cost(kdf.memory_kib)
        .t_cost(kdf.time_cost)
        .p_cost(kdf.parallelism)
        .build()
        .map_err(|err| format!("invalid state kdf params: {err}"))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| format!("failed to derive state key: {err}"))?;
    Ok(key)
}

fn ensure_secure_path(path: &Path, allow_current_uid_in_tests: bool) -> Result<(), String> {
    if is_symlink(path)? {
        return Err(format!(
            "state path '{}' must not be a symlink",
            path.display()
        ));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create state directory '{}': {err}",
                    parent.display()
                )
            })?;
            if is_symlink(parent)? {
                return Err(format!(
                    "state directory '{}' must not be a symlink",
                    parent.display()
                ));
            }
            ensure_secure_directory(parent, allow_current_uid_in_tests)?;
        }
    }

    if path.exists() {
        let metadata = std::fs::metadata(path)
            .map_err(|err| format!("failed to inspect state file '{}': {err}", path.display()))?;
        validate_private_state_file(path, &metadata, allow_current_uid_in_tests)?;
    }

    Ok(())
}

#[cfg(unix)]
fn ensure_secure_directory(path: &Path, allow_current_uid_in_tests: bool) -> Result<(), String> {
    const STICKY_BIT_MODE: u32 = 0o1000;

    fn validate_directory(
        path: &Path,
        metadata: &std::fs::Metadata,
        allow_sticky_group_other_write: bool,
        allow_current_uid_in_tests: bool,
    ) -> Result<(), String> {
        if !metadata.is_dir() {
            return Err(format!(
                "state directory '{}' is not a directory",
                path.display()
            ));
        }

        validate_root_owned(
            path,
            metadata,
            "state directory",
            allow_current_uid_in_tests,
        )?;
        validate_directory_mode(
            path,
            metadata.mode() & 0o7777,
            STICKY_BIT_MODE,
            allow_sticky_group_other_write,
        )
    }

    let metadata = std::fs::metadata(path).map_err(|err| {
        format!(
            "failed to inspect state directory '{}': {err}",
            path.display()
        )
    })?;
    validate_directory(path, &metadata, false, allow_current_uid_in_tests)?;

    let canonical = std::fs::canonicalize(path).map_err(|err| {
        format!(
            "failed to canonicalize state directory '{}': {err}",
            path.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).map_err(|err| {
            format!(
                "failed to inspect ancestor state directory '{}': {err}",
                ancestor.display()
            )
        })?;
        validate_directory(ancestor, &metadata, true, allow_current_uid_in_tests)?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn ensure_secure_directory(_path: &Path, _allow_current_uid_in_tests: bool) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_root_owned(
    path: &Path,
    metadata: &std::fs::Metadata,
    label: &str,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    validate_root_owned_uid(path, metadata.uid(), label, allow_current_uid_in_tests)
}

#[cfg(not(unix))]
fn validate_root_owned(
    _path: &Path,
    _metadata: &std::fs::Metadata,
    _label: &str,
    _allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    Ok(())
}

fn validate_private_state_file(
    path: &Path,
    metadata: &std::fs::Metadata,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "state file '{}' must be a regular file",
            path.display()
        ));
    }

    validate_root_owned(path, metadata, "state file", allow_current_uid_in_tests)?;

    #[cfg(unix)]
    {
        validate_private_state_file_mode(path, metadata.mode() & 0o777)?;
    }

    Ok(())
}

#[cfg(all(unix, any(test, coverage)))]
fn validate_root_owned_uid(
    path: &Path,
    uid: u32,
    label: &str,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    let current_uid = nix::unistd::Uid::effective().as_raw();
    #[cfg(coverage)]
    let allow_current_uid = true;
    #[cfg(not(coverage))]
    let allow_current_uid = allow_current_uid_in_tests;

    if uid == 0 || (allow_current_uid && uid == current_uid) {
        return Ok(());
    }

    Err(format!(
        "{label} '{}' must be owned by root; found uid {uid}",
        path.display()
    ))
}

#[cfg(all(unix, not(any(test, coverage))))]
fn validate_root_owned_uid(
    path: &Path,
    uid: u32,
    label: &str,
    _allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    if uid == 0 {
        return Ok(());
    }

    Err(format!(
        "{label} '{}' must be owned by root; found uid {uid}",
        path.display()
    ))
}

#[cfg(unix)]
fn validate_directory_mode(
    path: &Path,
    mode: u32,
    sticky_bit_mode: u32,
    allow_sticky_group_other_write: bool,
) -> Result<(), String> {
    if mode & 0o022 != 0 && !(allow_sticky_group_other_write && mode & sticky_bit_mode != 0) {
        return Err(format!(
            "state directory '{}' must not be writable by group/other",
            path.display()
        ));
    }

    Ok(())
}

#[cfg(unix)]
fn validate_private_state_file_mode(path: &Path, mode: u32) -> Result<(), String> {
    if mode & 0o077 != 0 {
        return Err(format!(
            "state file '{}' must not grant group/other permissions",
            path.display()
        ));
    }

    Ok(())
}

fn is_symlink(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "failed to inspect metadata for '{}': {err}",
            path.display()
        )),
    }
}

fn read_file_secure(path: &Path, allow_current_uid_in_tests: bool) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("failed to open state file '{}': {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect state file '{}': {err}", path.display()))?;
    validate_private_state_file(path, &metadata, allow_current_uid_in_tests)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read state file '{}': {err}", path.display()))?;
    Ok(bytes)
}

fn atomic_write_secure(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("agentpay-state");
    let temp_name = if file_name.starts_with('.') {
        format!("{file_name}.tmp.{}", Uuid::new_v4().simple())
    } else {
        format!(".{file_name}.tmp.{}", Uuid::new_v4().simple())
    };
    let temp_path = path.with_file_name(temp_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = options.open(&temp_path).map_err(|err| {
        format!(
            "failed to create temp state file '{}': {err}",
            temp_path.display()
        )
    })?;
    file.write_all(bytes).map_err(|err| {
        format!(
            "failed to write temp state file '{}': {err}",
            temp_path.display()
        )
    })?;
    file.sync_all().map_err(|err| {
        format!(
            "failed to sync temp state file '{}': {err}",
            temp_path.display()
        )
    })?;
    drop(file);

    #[cfg(unix)]
    {
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |err| {
                format!(
                    "failed to set state file permissions '{}': {err}",
                    temp_path.display()
                )
            },
        )?;
    }

    std::fs::rename(&temp_path, path).map_err(|err| {
        format!(
            "failed to atomically replace state file '{}' from '{}': {err}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}-{}-{}", std::process::id(), nanos))
    }

    fn relative_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        PathBuf::from(format!(".{name}-{}-{nanos}.state", std::process::id()))
    }

    fn cwd_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_temp_current_dir<T>(label: &str, action: impl FnOnce() -> T) -> T {
        let _guard = cwd_lock().lock().expect("lock current dir");
        let original_dir = std::env::current_dir().expect("current dir");
        let temp_dir = temp_path(label);
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");
        std::env::set_current_dir(&temp_dir).expect("enter temp dir");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));

        std::env::set_current_dir(&original_dir).expect("restore current dir");
        std::fs::remove_dir_all(&temp_dir).expect("remove temp dir");

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn sample_state() -> PersistedDaemonState {
        let relay_private_key_hex = "11".repeat(32);
        let secret = x25519_dalek::StaticSecret::from([0x11; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        PersistedDaemonState {
            relay_config: RelayConfig {
                relay_url: Some("https://relay.example".to_string()),
                frontend_url: Some("https://frontend.example".to_string()),
                daemon_id_hex: "aa".repeat(32),
                daemon_public_key_hex: hex::encode(public.as_bytes()),
            },
            relay_private_key_hex: relay_private_key_hex.into(),
            ..PersistedDaemonState::default()
        }
    }

    fn assert_runtime_ready_state(state: &PersistedDaemonState) {
        crate::validate_loaded_state(state).expect("state should pass loaded-state validation");
        assert_eq!(
            state.relay_config.relay_url.as_deref(),
            Some(crate::DEFAULT_RELAY_URL)
        );
        assert!(state.relay_config.frontend_url.is_none());
        assert_eq!(state.relay_config.daemon_id_hex.len(), 64);
        assert_eq!(state.relay_config.daemon_public_key_hex.len(), 64);
        assert_eq!(state.relay_private_key_hex.len(), 64);
    }

    #[test]
    fn derive_key_rejects_invalid_kdf_params() {
        let err = derive_key(
            "vault-password",
            &[7u8; SALT_LEN],
            &KdfParams {
                memory_kib: 0,
                time_cost: 0,
                parallelism: 0,
            },
        )
        .expect_err("invalid params");
        assert!(err.contains("invalid state kdf params"));
    }

    #[test]
    fn encrypted_state_envelope_round_trips_without_filesystem() {
        let state = sample_state();
        let salt = [5u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let kdf = KdfParams {
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
        };
        let key = derive_key("vault-password", &salt, &kdf).expect("derive key");
        let envelope =
            build_encrypted_state_envelope(&state, &key, &salt, &kdf, nonce).expect("envelope");
        let bytes = serialize_state_envelope(&envelope).expect("serialize");

        let (loaded, loaded_key, loaded_salt, loaded_kdf) =
            load_state_from_envelope_bytes(&bytes, "vault-password").expect("load state");

        assert_eq!(loaded, state);
        assert_eq!(loaded_key, key);
        assert_eq!(loaded_salt, salt);
        assert_eq!(loaded_kdf.memory_kib, kdf.memory_kib);
        assert_eq!(loaded_kdf.time_cost, kdf.time_cost);
        assert_eq!(loaded_kdf.parallelism, kdf.parallelism);
    }

    #[test]
    fn load_state_from_envelope_bytes_rejects_invalid_metadata_and_wrong_password() {
        let kdf = KdfParams {
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
        };
        let valid = EncryptedStateEnvelope {
            version: ENVELOPE_VERSION,
            kdf: kdf.clone(),
            salt_hex: hex::encode([1u8; SALT_LEN]),
            nonce_hex: hex::encode([2u8; NONCE_LEN]),
            ciphertext_hex: "00".to_string(),
        };

        let mut wrong_version = valid.clone();
        wrong_version.version = 9;
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&wrong_version).expect("serialize"),
            "vault-password",
        )
        .expect_err("wrong version");
        assert!(err.contains("unsupported state file version"));

        let mut bad_salt = valid.clone();
        bad_salt.salt_hex = "zz".to_string();
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&bad_salt).expect("serialize"),
            "vault-password",
        )
        .expect_err("bad salt");
        assert!(err.contains("invalid state salt encoding"));

        let mut short_nonce = valid.clone();
        short_nonce.nonce_hex = "aa".repeat(NONCE_LEN - 1);
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&short_nonce).expect("serialize"),
            "vault-password",
        )
        .expect_err("short nonce");
        assert!(err.contains("invalid state nonce length"));

        let state = sample_state();
        let salt = [3u8; SALT_LEN];
        let nonce = [4u8; NONCE_LEN];
        let key = derive_key("vault-password", &salt, &kdf).expect("key");
        let envelope =
            build_encrypted_state_envelope(&state, &key, &salt, &kdf, nonce).expect("envelope");
        let bytes = serialize_state_envelope(&envelope).expect("serialize");
        let err =
            load_state_from_envelope_bytes(&bytes, "wrong-password").expect_err("wrong password");
        assert!(err.contains("failed to decrypt state"));
    }

    #[test]
    fn load_state_from_envelope_bytes_rejects_remaining_invalid_hex_and_payload_cases() {
        let kdf = KdfParams {
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
        };
        let valid = EncryptedStateEnvelope {
            version: ENVELOPE_VERSION,
            kdf: kdf.clone(),
            salt_hex: hex::encode([1u8; SALT_LEN]),
            nonce_hex: hex::encode([2u8; NONCE_LEN]),
            ciphertext_hex: "00".to_string(),
        };

        let mut short_salt = valid.clone();
        short_salt.salt_hex = "aa".repeat(SALT_LEN - 1);
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&short_salt).expect("serialize"),
            "vault-password",
        )
        .expect_err("short salt");
        assert!(err.contains("invalid state salt length"));

        let mut bad_nonce = valid.clone();
        bad_nonce.nonce_hex = "zz".to_string();
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&bad_nonce).expect("serialize"),
            "vault-password",
        )
        .expect_err("bad nonce");
        assert!(err.contains("invalid state nonce encoding"));

        let mut bad_ciphertext = valid.clone();
        bad_ciphertext.ciphertext_hex = "zz".to_string();
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&bad_ciphertext).expect("serialize"),
            "vault-password",
        )
        .expect_err("bad ciphertext");
        assert!(err.contains("invalid state ciphertext encoding"));

        let salt = [6u8; SALT_LEN];
        let nonce = [7u8; NONCE_LEN];
        let key = derive_key("vault-password", &salt, &kdf).expect("key");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt((&nonce).into(), b"not-json".as_slice())
            .expect("encrypt");
        let invalid_payload = EncryptedStateEnvelope {
            version: ENVELOPE_VERSION,
            kdf,
            salt_hex: hex::encode(salt),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(ciphertext),
        };
        let err = load_state_from_envelope_bytes(
            &serde_json::to_vec(&invalid_payload).expect("serialize"),
            "vault-password",
        )
        .expect_err("invalid payload");
        assert!(err.contains("failed to deserialize state payload"));
    }

    #[test]
    fn load_state_from_envelope_bytes_rejects_inconsistent_state_entries() {
        let mut state = sample_state();
        let signing_key =
            k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("test signing key");
        let vault_key = VaultKey {
            id: Uuid::new_v4(),
            source: vault_domain::KeySource::Generated,
            algorithm: vault_domain::KeyAlgorithm::Secp256k1,
            public_key_hex: hex::encode(
                signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            created_at: OffsetDateTime::now_utc(),
        };
        state.vault_keys.insert(vault_key.id, vault_key.clone());
        let agent_key = AgentKey {
            id: Uuid::new_v4(),
            vault_key_id: vault_key.id,
            policies: vault_domain::PolicyAttachment::AllPolicies,
            created_at: OffsetDateTime::now_utc(),
        };
        state.agent_keys.insert(Uuid::new_v4(), agent_key);

        let salt = [8u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let kdf = KdfParams {
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
        };
        let key = derive_key("vault-password", &salt, &kdf).expect("key");
        let envelope =
            build_encrypted_state_envelope(&state, &key, &salt, &kdf, nonce).expect("envelope");
        let bytes = serialize_state_envelope(&envelope).expect("serialize");

        let err = load_state_from_envelope_bytes(&bytes, "vault-password")
            .expect_err("mismatched agent key entry should fail");
        assert!(err.contains("loaded state failed integrity validation"));
        assert!(err.contains("agent key entry keyed by"));
    }

    #[test]
    fn save_rejects_inconsistent_state_entries() {
        let path = relative_path("agentpay-persistence-invalid-save");
        let (store, _) = EncryptedStateStore::open_or_initialize(
            "vault-password",
            &crate::DaemonConfig::default(),
            PersistentStoreConfig::new(path.clone()),
        )
        .expect("initialize store");

        let mut state = sample_state();
        let lease = Lease {
            lease_id: Uuid::new_v4(),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(1),
        };
        state.leases.insert(Uuid::new_v4(), lease);

        let err = store
            .save(&state)
            .expect_err("invalid state should be rejected before persistence");
        assert!(err.contains("refusing to persist invalid state"));
        assert!(err.contains("lease entry keyed by"));
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_permission_validators_cover_root_and_mode_rules() {
        let path = Path::new("/tmp/daemon-state.enc");

        validate_root_owned_uid(path, 0, "state file", false).expect("root-owned path");
        #[cfg(not(coverage))]
        let err =
            validate_root_owned_uid(path, 501, "state file", false).expect_err("non-root owner");
        #[cfg(coverage)]
        let err = {
            let current_uid = nix::unistd::Uid::effective().as_raw();
            validate_root_owned_uid(path, current_uid, "state file", false)
                .expect("coverage build accepts current uid");
            let rejected_uid = if current_uid == 0 {
                1
            } else {
                current_uid.saturating_add(1)
            };
            validate_root_owned_uid(path, rejected_uid, "state file", false).expect_err("other uid")
        };
        assert!(err.contains("must be owned by root"));

        validate_directory_mode(path, 0o700, 0o1000, false).expect("private dir");
        validate_directory_mode(path, 0o1777, 0o1000, true).expect("sticky dir allowed");
        let err =
            validate_directory_mode(path, 0o770, 0o1000, false).expect_err("group writable dir");
        assert!(err.contains("must not be writable by group/other"));

        validate_private_state_file_mode(path, 0o600).expect("private state file");
        let err = validate_private_state_file_mode(path, 0o640).expect_err("group readable file");
        assert!(err.contains("must not grant group/other permissions"));
    }

    #[test]
    fn atomic_write_secure_persists_bytes() {
        let path = temp_path("agentpay-persistence-write");
        atomic_write_secure(&path, b"hello world").expect("write state file");
        let contents = std::fs::read(&path).expect("read state file");
        assert_eq!(contents, b"hello world");
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn atomic_write_secure_replaces_existing_contents() {
        let path = temp_path("agentpay-persistence-rewrite");
        atomic_write_secure(&path, b"first").expect("initial write");
        atomic_write_secure(&path, b"second").expect("replacement write");
        let contents = std::fs::read(&path).expect("read state file");
        assert_eq!(contents, b"second");
        std::fs::remove_file(path).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn is_symlink_detects_symlink_and_missing_paths() {
        let root = temp_path("agentpay-persistence-symlink");
        std::fs::create_dir_all(&root).expect("create root");
        let target = root.join("target");
        let link = root.join("link");
        std::fs::write(&target, b"target").expect("write target");
        symlink(&target, &link).expect("create symlink");

        assert!(is_symlink(&link).expect("inspect symlink"));
        assert!(!is_symlink(&root.join("missing")).expect("inspect missing path"));

        std::fs::remove_file(link).expect("remove symlink");
        std::fs::remove_file(target).expect("remove target");
        std::fs::remove_dir_all(root).expect("remove root");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_secure_path_rejects_symlink_path_and_symlink_parent() {
        let root = temp_path("agentpay-persistence-secure-path-symlink");
        std::fs::create_dir_all(&root).expect("create root");

        let target = root.join("target.state");
        std::fs::write(&target, b"payload").expect("write target");
        let link = root.join("link.state");
        symlink(&target, &link).expect("symlink file");
        let err = ensure_secure_path(&link, false).expect_err("symlink path");
        assert!(err.contains("must not be a symlink"));

        let real_dir = root.join("real-dir");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
        let symlink_dir = root.join("dir-link");
        symlink(&real_dir, &symlink_dir).expect("symlink dir");
        let err =
            ensure_secure_path(&symlink_dir.join("daemon.state"), false).expect_err("symlink dir");
        assert!(err.contains("state directory"));
        assert!(err.contains("must not be a symlink"));

        std::fs::remove_file(link).expect("remove file symlink");
        std::fs::remove_file(target).expect("remove target");
        std::fs::remove_file(symlink_dir).expect("remove dir symlink");
        std::fs::remove_dir_all(real_dir).expect("remove real dir");
        std::fs::remove_dir_all(root).expect("remove root");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_secure_directory_and_private_state_file_reject_invalid_file_types() {
        let file_path = temp_path("agentpay-persistence-not-dir");
        std::fs::write(&file_path, b"payload").expect("write file");
        let err = ensure_secure_directory(&file_path, false).expect_err("non-directory");
        assert!(err.contains("is not a directory"));

        let dir_path = temp_path("agentpay-persistence-dir-state");
        std::fs::create_dir_all(&dir_path).expect("create dir");
        let metadata = std::fs::metadata(&dir_path).expect("metadata");
        let err =
            validate_private_state_file(&dir_path, &metadata, false).expect_err("directory state");
        assert!(err.contains("must be a regular file"));

        std::fs::remove_file(file_path).expect("remove file");
        std::fs::remove_dir_all(dir_path).expect("remove dir");
    }

    #[cfg(all(unix, not(coverage)))]
    #[test]
    fn read_file_secure_and_ensure_secure_path_reject_non_root_owned_files() {
        let missing = temp_path("agentpay-persistence-missing");
        let err = read_file_secure(&missing, false).expect_err("missing file");
        assert!(err.contains("failed to open state file"));

        let path = temp_path("agentpay-persistence-user-file");
        std::fs::write(&path, b"secret").expect("write state file");

        let err = ensure_secure_path(&path, false).expect_err("non-root owned file");
        assert!(err.contains("must be owned by root"));

        let err = read_file_secure(&path, false).expect_err("non-root owned read");
        assert!(err.contains("must be owned by root"));

        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn open_or_initialize_uses_config_kdf_for_new_relative_store() {
        with_temp_current_dir("agentpay-persistence-init-cwd", || {
            let path = relative_path("agentpay-persistence-init");
            let config = crate::DaemonConfig {
                argon2_memory_kib: 8_192,
                argon2_time_cost: 3,
                argon2_parallelism: 2,
                ..crate::DaemonConfig::default()
            };

            let (store, state) = EncryptedStateStore::open_or_initialize(
                "vault-password",
                &config,
                PersistentStoreConfig::new(path.clone()),
            )
            .expect("initialize store");

            assert_eq!(store.path, path);
            assert_eq!(
                store.kdf,
                KdfParams {
                    memory_kib: 8_192,
                    time_cost: 3,
                    parallelism: 2,
                }
            );
            assert_runtime_ready_state(&state);
            assert!(!store.path.exists());
        });
    }

    #[cfg(not(coverage))]
    #[test]
    fn save_writes_encrypted_relative_store_and_reopen_rejects_user_owned_file() {
        with_temp_current_dir("agentpay-persistence-save-cwd", || {
            let path = relative_path("agentpay-persistence-save");
            let (store, _) = EncryptedStateStore::open_or_initialize(
                "vault-password",
                &crate::DaemonConfig::default(),
                PersistentStoreConfig::new(path.clone()),
            )
            .expect("initialize store");

            let state = sample_state();
            store.save(&state).expect("save state");

            let bytes = std::fs::read(&path).expect("read state file");
            let envelope: EncryptedStateEnvelope =
                serde_json::from_slice(&bytes).expect("serialized envelope");
            assert_eq!(envelope.version, ENVELOPE_VERSION);
            assert_ne!(
                envelope.ciphertext_hex,
                hex::encode(serde_json::to_vec(&state).expect("plaintext"))
            );

            let err = match EncryptedStateStore::open_or_initialize(
                "vault-password",
                &crate::DaemonConfig::default(),
                PersistentStoreConfig::new(path.clone()),
            ) {
                Ok(_) => panic!("reopen non-root file should fail"),
                Err(err) => err,
            };
            assert!(err.contains("must be owned by root"));

            std::fs::remove_file(path).expect("cleanup");
        });
    }

    #[cfg(all(unix, coverage))]
    #[test]
    fn coverage_build_accepts_current_user_owned_paths_for_successful_reopen_and_read() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("agentpay-persistence-coverage-success");
        let nested = root.join("state").join("daemon.state");
        std::fs::create_dir_all(root.join("state")).expect("create state dir");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("secure root dir");
        std::fs::set_permissions(root.join("state"), std::fs::Permissions::from_mode(0o700))
            .expect("secure nested dir");

        let (store, initial_state) = EncryptedStateStore::open_or_initialize(
            "vault-password",
            &crate::DaemonConfig::default(),
            PersistentStoreConfig::new(nested.clone()),
        )
        .expect("initialize current-user-owned store in coverage build");
        assert_runtime_ready_state(&initial_state);

        let state = sample_state();
        store.save(&state).expect("save state");

        let raw = read_file_secure(&nested, false).expect("read secure state file");
        assert!(!raw.is_empty());

        let (reopened, loaded_state) = EncryptedStateStore::open_or_initialize(
            "vault-password",
            &crate::DaemonConfig::default(),
            PersistentStoreConfig::new(nested.clone()),
        )
        .expect("reopen saved state");
        assert_eq!(reopened.path, nested);
        assert_eq!(loaded_state, state);

        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
