//! Envelope v2 (HKDF state secret), legacy v1 (Argon2 password), and migration tests.

use super::super::envelope::legacy::{
    open_legacy_state, seal_legacy_plaintext, KdfLimits, KdfParams, LegacyStateEnvelope,
};
use super::super::envelope::{
    envelope_version, open_state, seal_plaintext, seal_state, EncryptedStateEnvelope, StateKey,
    ENVELOPE_VERSION, LEGACY_PASSWORD_ENVELOPE_VERSION, NONCE_LEN, SALT_LEN,
};
use super::{sample_state, temp_path, test_secret};
use crate::persistence::{
    EncryptedStateStore, LegacyStatePassword, PersistedDaemonState, PersistentStoreConfig,
    StateSecret,
};
use crate::DaemonConfig;

const LEGACY_PASSWORD: &str = "legacy vault password";

fn test_kdf() -> KdfParams {
    KdfParams {
        memory_kib: 8_192,
        time_cost: 1,
        parallelism: 1,
    }
}

fn test_kdf_limits() -> KdfLimits {
    KdfLimits::from_config(&DaemonConfig::default())
}

fn legacy_password() -> LegacyStatePassword {
    LegacyStatePassword::new(LEGACY_PASSWORD.to_string().into()).expect("legacy password")
}

fn legacy_envelope(state: &PersistedDaemonState) -> LegacyStateEnvelope {
    seal_legacy_plaintext(
        &serde_json::to_vec(state).expect("state json"),
        LEGACY_PASSWORD,
        [1u8; SALT_LEN],
        [2u8; NONCE_LEN],
        test_kdf(),
    )
}

fn sample_state_with_policy() -> PersistedDaemonState {
    let mut state = sample_state();
    let policy = agentpay_domain::SpendingPolicy::new(
        1,
        agentpay_domain::PolicyType::PerTxMaxSpending,
        100,
        agentpay_domain::EntityScope::All,
        agentpay_domain::EntityScope::All,
        agentpay_domain::EntityScope::All,
    )
    .expect("policy");
    state.policies.insert(policy.id, policy);
    state
}

/// Creates a private directory for a state file and returns the file path.
fn state_file_path(label: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_path(label);
    std::fs::create_dir_all(&dir).expect("create state dir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    dir.join("daemon-state.enc")
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).expect("write state file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn open_store(
    path: &std::path::Path,
    secret: &StateSecret,
    password: Option<LegacyStatePassword>,
) -> Result<(EncryptedStateStore, PersistedDaemonState), String> {
    let mut config = PersistentStoreConfig::new_test(path.to_path_buf());
    if let Some(password) = password {
        config = config.with_legacy_password_migration(password);
    }
    EncryptedStateStore::open_or_initialize(secret, &DaemonConfig::default(), config)
}

#[test]
fn state_secret_parses_hex_and_rejects_bad_input() {
    let secret = StateSecret::from_hex(&format!("  {}\n", "ab".repeat(32))).expect("hex secret");
    assert_eq!(secret.expose(), &[0xab; 32]);
    assert_eq!(format!("{secret:?}"), "StateSecret(<redacted>)");
    for bad in [
        "",
        "ab",
        &"zz".repeat(32),
        &"ab".repeat(33),
        &"00".repeat(32),
    ] {
        assert!(
            StateSecret::from_hex(bad).is_err(),
            "{bad:?} must be rejected"
        );
    }
    assert!(LegacyStatePassword::new(" \n".to_string().into()).is_err());
    assert!(LegacyStatePassword::new("a".repeat(16 * 1024 + 1).into()).is_err());
}

#[test]
fn v2_envelope_round_trips_and_binds_the_secret_and_header() {
    let state = sample_state_with_policy();
    let key = StateKey::derive(&test_secret(), [5u8; SALT_LEN]).expect("key");
    let bytes = seal_state(&state, &key, [9u8; NONCE_LEN]).expect("seal");
    assert_eq!(envelope_version(&bytes).expect("version"), ENVELOPE_VERSION);

    let (loaded, loaded_key) = open_state(&bytes, &test_secret()).expect("open");
    assert_eq!(loaded, state);
    assert_eq!(loaded_key.key_bytes(), key.key_bytes());
    assert_eq!(loaded_key.salt(), [5u8; SALT_LEN]);

    let other = StateSecret::from_bytes([8u8; 32]).expect("other secret");
    let err = open_state(&bytes, &other).err().expect("wrong secret");
    assert!(err.contains("wrong state secret or tampered file"));

    // The salt is authenticated: swapping it changes both the key and the AAD.
    let mut envelope: EncryptedStateEnvelope = serde_json::from_slice(&bytes).expect("json");
    envelope.salt_hex = hex::encode([6u8; SALT_LEN]);
    let tampered = serde_json::to_vec(&envelope).expect("json");
    assert!(open_state(&tampered, &test_secret()).is_err());
}

#[test]
fn v2_key_derivation_is_domain_separated_and_salted() {
    let secret = test_secret();
    let first = StateKey::derive(&secret, [1u8; SALT_LEN]).expect("key");
    let again = StateKey::derive(&secret, [1u8; SALT_LEN]).expect("key");
    let other_salt = StateKey::derive(&secret, [2u8; SALT_LEN]).expect("key");
    assert_eq!(first.key_bytes(), again.key_bytes());
    assert_ne!(first.key_bytes(), other_salt.key_bytes());
    assert_ne!(
        first.key_bytes(),
        secret.expose(),
        "the secret is never used directly"
    );
}

#[test]
fn v2_envelope_rejects_malformed_headers_and_payloads() {
    let valid = EncryptedStateEnvelope {
        version: ENVELOPE_VERSION,
        salt_hex: hex::encode([1u8; SALT_LEN]),
        nonce_hex: hex::encode([2u8; NONCE_LEN]),
        ciphertext_hex: "00".to_string(),
    };
    type Mutation = fn(&mut EncryptedStateEnvelope);
    let cases: Vec<(Mutation, &str)> = vec![
        (|e| e.version = 9, "unsupported state file version"),
        (|e| e.salt_hex = "zz".into(), "invalid state salt encoding"),
        (
            |e| e.salt_hex = "aa".repeat(SALT_LEN - 1),
            "invalid state salt length",
        ),
        (
            |e| e.nonce_hex = "zz".into(),
            "invalid state nonce encoding",
        ),
        (
            |e| e.nonce_hex = "aa".repeat(NONCE_LEN - 1),
            "invalid state nonce length",
        ),
        (
            |e| e.ciphertext_hex = "zz".into(),
            "invalid state ciphertext encoding",
        ),
    ];
    for (mutate, expected) in cases {
        let mut envelope = valid.clone();
        mutate(&mut envelope);
        let bytes = serde_json::to_vec(&envelope).expect("json");
        let err = open_state(&bytes, &test_secret()).err().expect("must fail");
        assert!(err.contains(expected), "{err} should contain {expected}");
    }
    assert!(envelope_version(b"not json")
        .expect_err("garbage")
        .contains("failed to parse state envelope"));

    let key = StateKey::derive(&test_secret(), [3u8; SALT_LEN]).expect("key");
    let bytes = seal_plaintext(b"not-json", &key, [4u8; NONCE_LEN]).expect("seal");
    let err = open_state(&bytes, &test_secret()).err().expect("payload");
    assert!(err.contains("failed to deserialize state payload"));
}

#[test]
fn v2_envelope_rejects_inconsistent_state_entries() {
    let mut state = sample_state();
    let vault_key = agentpay_domain::VaultKey {
        id: uuid::Uuid::new_v4(),
        source: agentpay_domain::KeySource::Generated,
        algorithm: agentpay_domain::KeyAlgorithm::Secp256k1,
        public_key_hex: "11".repeat(33),
        created_at: time::OffsetDateTime::now_utc(),
        name: None,
    };
    state.vault_keys.insert(uuid::Uuid::new_v4(), vault_key);
    let key = StateKey::derive(&test_secret(), [8u8; SALT_LEN]).expect("key");
    let bytes = seal_state(&state, &key, [9u8; NONCE_LEN]).expect("seal");
    let err = open_state(&bytes, &test_secret())
        .err()
        .expect("inconsistent");
    assert!(err.contains("loaded state failed integrity validation"));
}

#[test]
fn legacy_envelope_opens_with_the_password_only() {
    let state = sample_state_with_policy();
    let bytes = serde_json::to_vec(&legacy_envelope(&state)).expect("json");
    assert_eq!(
        envelope_version(&bytes).expect("version"),
        LEGACY_PASSWORD_ENVELOPE_VERSION
    );
    let loaded = open_legacy_state(&bytes, LEGACY_PASSWORD, &test_kdf_limits()).expect("open");
    assert_eq!(loaded, state);

    let err = open_legacy_state(&bytes, "wrong password", &test_kdf_limits()).expect_err("wrong");
    assert!(err.contains("wrong vault password or tampered file"));
    let err = open_state(&bytes, &test_secret())
        .err()
        .expect("v2 opener rejects v1");
    assert!(err.contains("unsupported state file version 1"));
}

#[test]
fn legacy_envelope_rejects_kdf_params_above_configured_maxima() {
    let envelope = legacy_envelope(&sample_state());
    let tampered = |mutate: fn(&mut KdfParams)| {
        let mut envelope = envelope.clone();
        mutate(&mut envelope.kdf);
        serde_json::to_vec(&envelope).expect("json")
    };
    for (bytes, field) in [
        (tampered(|kdf| kdf.memory_kib = u32::MAX), "kdf memory_kib"),
        (tampered(|kdf| kdf.time_cost = u32::MAX), "kdf time_cost"),
        (
            tampered(|kdf| kdf.parallelism = u32::MAX),
            "kdf parallelism",
        ),
    ] {
        let err = open_legacy_state(&bytes, LEGACY_PASSWORD, &test_kdf_limits())
            .expect_err("tampered kdf params must be rejected before key derivation");
        assert!(err.contains(field) && err.contains("exceeds configured maximum"));
    }
}

#[test]
fn legacy_state_file_is_refused_without_a_migration_password() {
    let path = state_file_path("agentpay-legacy-refused");
    let legacy_bytes = serde_json::to_vec(&legacy_envelope(&sample_state())).expect("json");
    write_private_file(&path, &legacy_bytes);

    let err = open_store(&path, &test_secret(), None)
        .err()
        .expect("legacy file must be refused");
    assert!(err.contains("legacy vault-password envelope (v1)"));
    assert!(err.contains("--migrate-from-password-stdin"));
    assert_eq!(
        std::fs::read(&path).expect("read"),
        legacy_bytes,
        "file untouched"
    );

    std::fs::remove_dir_all(path.parent().expect("dir")).expect("cleanup");
}

#[test]
fn legacy_state_file_migrates_atomically_to_the_state_secret() {
    let path = state_file_path("agentpay-legacy-migrate");
    let state = sample_state_with_policy();
    write_private_file(
        &path,
        &serde_json::to_vec(&legacy_envelope(&state)).expect("json"),
    );

    let (_, migrated) =
        open_store(&path, &test_secret(), Some(legacy_password())).expect("migrate");
    assert_eq!(migrated, state);

    let bytes = std::fs::read(&path).expect("read migrated file");
    assert_eq!(envelope_version(&bytes).expect("version"), ENVELOPE_VERSION);
    let (reopened, _) = open_state(&bytes, &test_secret()).expect("open migrated envelope");
    assert_eq!(reopened, state);

    // After migration the secret alone opens the file, and repeating the
    // migration is a no-op.
    let (_, loaded) = open_store(&path, &test_secret(), None).expect("reopen with secret");
    assert_eq!(loaded, state);
    let (_, loaded) =
        open_store(&path, &test_secret(), Some(legacy_password())).expect("idempotent");
    assert_eq!(loaded, state);
    assert!(open_store(&path, &StateSecret::generate(), None).is_err());

    std::fs::remove_dir_all(path.parent().expect("dir")).expect("cleanup");
}

#[test]
fn failed_migration_leaves_the_legacy_file_untouched() {
    let path = state_file_path("agentpay-legacy-wrong-password");
    let legacy_bytes = serde_json::to_vec(&legacy_envelope(&sample_state())).expect("json");
    write_private_file(&path, &legacy_bytes);

    let wrong = LegacyStatePassword::new("not the password".to_string().into()).expect("pw");
    let err = open_store(&path, &test_secret(), Some(wrong))
        .err()
        .expect("wrong legacy password");
    assert!(err.contains("wrong vault password"));
    assert_eq!(std::fs::read(&path).expect("read"), legacy_bytes);

    std::fs::remove_dir_all(path.parent().expect("dir")).expect("cleanup");
}

#[test]
fn migration_requires_an_existing_state_file() {
    let path = state_file_path("agentpay-legacy-missing");
    let err = open_store(&path, &test_secret(), Some(legacy_password()))
        .err()
        .expect("nothing to migrate");
    assert!(err.contains("does not exist"));
    assert!(!path.exists());

    write_private_file(&path, br#"{"version":7}"#);
    let err = open_store(&path, &test_secret(), None)
        .err()
        .expect("unknown version");
    assert!(err.contains("unsupported state file version 7"));

    std::fs::remove_dir_all(path.parent().expect("dir")).expect("cleanup");
}
