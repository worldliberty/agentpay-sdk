//! Unit tests for the encrypted state store and filesystem checks.
//!
//! Envelope formats and legacy migration are covered in [`envelope`].

mod envelope;

use super::envelope::{
    open_state, seal_plaintext, EncryptedStateEnvelope, StateKey, ENVELOPE_VERSION, NONCE_LEN,
    SALT_LEN,
};
use super::secure_fs::{
    atomic_write_secure, ensure_secure_directory, ensure_secure_path, is_symlink, read_file_secure,
    validate_directory_mode, validate_private_state_file, validate_private_state_file_mode,
    validate_root_owned_uid,
};
use super::*;
use crate::daemon::validate_loaded_state;
use crate::PersistentStoreConfig;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh private (`0700`) directory under the system temp directory. Files must not sit
/// directly in the temp directory: on Linux that is the shared `/tmp` (mode `1777`), which the
/// daemons rightly refuse as a state or socket directory.
fn private_temp_dir() -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ap-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .subsec_nanos()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("create private temp dir");
    dir
}

fn temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    private_temp_dir().join(format!("{name}-{nanos}"))
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

fn test_secret() -> StateSecret {
    StateSecret::from_bytes([7u8; 32]).expect("test secret")
}

fn sample_state() -> PersistedDaemonState {
    PersistedDaemonState::default()
}

fn assert_runtime_ready_state(state: &PersistedDaemonState) {
    validate_loaded_state(state).expect("state should pass loaded-state validation");
}

#[test]
fn save_rejects_inconsistent_state_entries() {
    let path = relative_path("agentpay-persistence-invalid-save");
    let (store, _) = EncryptedStateStore::open_or_initialize(
        &test_secret(),
        &crate::DaemonConfig::default(),
        PersistentStoreConfig::new(path.clone()),
    )
    .expect("initialize store");

    let mut state = sample_state();
    let credential = AdminCredential {
        id: Uuid::new_v4(),
        public_key_sec1_hex: "02".repeat(33),
        label: "Mac".to_string(),
        created_at: OffsetDateTime::now_utc(),
    };
    state.admin_credentials.insert(Uuid::new_v4(), credential);

    let err = store
        .save(&state)
        .expect_err("invalid state should be rejected before persistence");
    assert!(err.contains("refusing to persist invalid state"));
    assert!(err.contains("admin credential entry keyed by"));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn unix_permission_validators_cover_root_and_mode_rules() {
    let path = Path::new("/tmp/daemon-state.enc");

    validate_root_owned_uid(path, 0, "state file", false).expect("root-owned path");
    #[cfg(not(coverage))]
    let err = validate_root_owned_uid(path, 501, "state file", false).expect_err("non-root owner");
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
    let err = validate_directory_mode(path, 0o770, 0o1000, false).expect_err("group writable dir");
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
fn open_or_initialize_derives_a_fresh_key_for_new_relative_store() {
    with_temp_current_dir("agentpay-persistence-init-cwd", || {
        let path = relative_path("agentpay-persistence-init");
        let (store, state) = EncryptedStateStore::open_or_initialize(
            &test_secret(),
            &crate::DaemonConfig::default(),
            PersistentStoreConfig::new(path.clone()),
        )
        .expect("initialize store");
        let (other, _) = EncryptedStateStore::open_or_initialize(
            &test_secret(),
            &crate::DaemonConfig::default(),
            PersistentStoreConfig::new(path.clone()),
        )
        .expect("initialize second store");

        assert_eq!(store.path, path);
        assert_ne!(
            store.key.salt(),
            other.key.salt(),
            "each new store draws a fresh random salt"
        );
        assert_ne!(store.key.key_bytes(), other.key.key_bytes());
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
            &test_secret(),
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
        let (loaded, _) = open_state(&bytes, &test_secret()).expect("open saved envelope");
        assert_eq!(loaded, state);
        assert_ne!(
            envelope.ciphertext_hex,
            hex::encode(serde_json::to_vec(&state).expect("plaintext"))
        );

        let err = match EncryptedStateStore::open_or_initialize(
            &test_secret(),
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
        &test_secret(),
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
        &test_secret(),
        &crate::DaemonConfig::default(),
        PersistentStoreConfig::new(nested.clone()),
    )
    .expect("reopen saved state");
    assert_eq!(reopened.path, nested);
    assert_eq!(loaded_state, state);

    std::fs::remove_dir_all(root).expect("cleanup");
}

fn encrypt_plaintext_state(plaintext: &[u8]) -> Vec<u8> {
    let key = StateKey::derive(&test_secret(), [4u8; SALT_LEN]).expect("key");
    seal_plaintext(plaintext, &key, [3u8; NONCE_LEN]).expect("seal")
}

/// State files written before Railgun, legacy Tempo sessions v1, Permit2
/// permits, and the relay were retired must keep loading. The retired
/// entries are dropped and everything else survives unchanged.
#[test]
fn legacy_state_with_retired_features_loads_without_retired_entries() {
    use agentpay_domain::{
        AgentAction, AssetId, EntityScope, EvmAddress, KeyAlgorithm, KeySource,
        ManualApprovalStatus, PolicyAttachment, PolicyType, RecipientId,
    };
    use std::collections::BTreeSet;

    let now = OffsetDateTime::now_utc();
    let signing_key = k256::ecdsa::SigningKey::from_slice(&[7u8; 32]).expect("test signing key");
    let vault_key = VaultKey {
        id: Uuid::new_v4(),
        source: KeySource::Generated,
        algorithm: KeyAlgorithm::Secp256k1,
        public_key_hex: hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        ),
        created_at: now,
        name: None,
    };
    let agent_key = AgentKey {
        id: Uuid::new_v4(),
        vault_key_id: vault_key.id,
        policies: PolicyAttachment::AllPolicies,
        created_at: now,
    };
    let recipient: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("recipient");
    let token: EvmAddress = "0x2222222222222222222222222222222222222222"
        .parse()
        .expect("token");
    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::Set(BTreeSet::from([recipient.clone()])),
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let transfer = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 10,
    };
    let approval = ManualApprovalRequest {
        id: Uuid::new_v4(),
        agent_key_id: agent_key.id,
        vault_key_id: vault_key.id,
        request_payload_hash_hex: "ab".repeat(32),
        chain_id: 1,
        asset: AssetId::Erc20(token),
        recipient: RecipientId::Evm(recipient.clone()),
        amount_wei: 10,
        action: transfer,
        created_at: now,
        updated_at: now,
        status: ManualApprovalStatus::Pending,
        triggered_by_policy_ids: vec![],
        reasons: Vec::new(),
        completed_at: None,
        rejection_reason: None,
    };
    let spend = SpendEvent {
        agent_key_id: agent_key.id,
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: RecipientId::Evm(recipient),
        amount_wei: 5,
        at: now,
        approval_request_id: None,
    };

    let mut current = sample_state();
    current.vault_keys.insert(vault_key.id, vault_key);
    current.agent_keys.insert(agent_key.id, agent_key.clone());
    current.policies.insert(policy.id, policy.clone());
    current
        .manual_approval_requests
        .insert(approval.id, approval.clone());
    current.spend_log.push(spend);

    let railgun_recipient = serde_json::json!({
        "kind": "railgun",
        "value": "0zk1qyk9nn28x0u3rwn5pknglda68wrn7gw6anjw8gg94mcj6eq5u48tlrv7j6fe3z53lama02nutwtcqc979wnce0qwly4y7w4rls5cq040g7z8eagshxrw5ajy990",
    });
    let mut legacy = serde_json::to_value(&current).expect("state json");
    // Relay configuration and its private key are no longer persisted.
    legacy["relay_config"] = serde_json::json!({
        "relay_url": "https://relay.example",
        "frontend_url": null,
        "daemon_id_hex": "aa".repeat(32),
        "daemon_public_key_hex": "bb".repeat(32),
    });
    legacy["relay_private_key_hex"] = serde_json::json!("11".repeat(32));
    // A Railgun recipient inside a live policy scope and a retired shield policy.
    let policy_key = policy.id.to_string();
    legacy["policies"][&policy_key]["recipients"]["values"]
        .as_array_mut()
        .expect("recipient set")
        .push(railgun_recipient.clone());
    let mut shield_policy = legacy["policies"][&policy_key].clone();
    let shield_policy_id = Uuid::new_v4();
    shield_policy["id"] = serde_json::json!(shield_policy_id);
    shield_policy["policy_type"] = serde_json::json!("PerTxMaxShieldAmount");
    legacy["policies"][shield_policy_id.to_string()] = shield_policy;
    // A Railgun viewing key.
    let railgun_key_id = Uuid::new_v4();
    legacy["vault_keys"][railgun_key_id.to_string()] = serde_json::json!({
        "id": railgun_key_id,
        "source": "Generated",
        "algorithm": "railgun_viewing",
        "public_key_hex": "cc".repeat(32),
        "created_at": legacy["vault_keys"].as_object().expect("vault keys").values().next()
            .expect("vault key")["created_at"].clone(),
    });
    // Spend events carried an `action_kind`, and Railgun spends had a Railgun recipient.
    let spend_log = legacy["spend_log"].as_array_mut().expect("spend log");
    spend_log[0]["action_kind"] = serde_json::json!("transfer");
    let mut railgun_spend = spend_log[0].clone();
    railgun_spend["recipient"] = railgun_recipient;
    railgun_spend["action_kind"] = serde_json::json!("shield");
    spend_log.push(railgun_spend);
    // Manual approvals for retired v1 Tempo and Permit2 actions.
    for retired_kind in ["TempoSessionVoucher", "Permit2Permit", "Shield"] {
        let mut retired = legacy["manual_approval_requests"][approval.id.to_string()].clone();
        let retired_id = Uuid::new_v4();
        retired["id"] = serde_json::json!(retired_id);
        retired["action"] = serde_json::json!({ "kind": retired_kind, "authorization": {} });
        legacy["manual_approval_requests"][retired_id.to_string()] = retired;
    }

    let bytes = encrypt_plaintext_state(&serde_json::to_vec(&legacy).expect("legacy json"));
    let (loaded, _) = open_state(&bytes, &test_secret()).expect("legacy state must keep loading");

    assert_eq!(loaded, current);
    let reserialized = serde_json::to_value(&loaded).expect("reserialize");
    assert!(reserialized.get("relay_config").is_none());
    assert!(reserialized.get("relay_private_key_hex").is_none());
}

#[test]
fn retired_entry_filters_do_not_mask_malformed_live_entries() {
    let mut legacy = serde_json::to_value(sample_state()).expect("state json");
    let policy_id = Uuid::new_v4();
    legacy["policies"][policy_id.to_string()] =
        serde_json::json!({ "id": policy_id, "policy_type": "NotARealPolicyType" });
    let bytes = encrypt_plaintext_state(&serde_json::to_vec(&legacy).expect("legacy json"));
    let err = match open_state(&bytes, &test_secret()) {
        Ok(_) => panic!("unknown policy types must still fail"),
        Err(err) => err,
    };
    assert!(err.contains("failed to deserialize state payload"));
}

#[test]
fn schema_version_defaults_to_current_and_newer_files_are_rejected() {
    assert_eq!(
        SchemaVersion::default(),
        SchemaVersion(CURRENT_SCHEMA_VERSION)
    );
    assert_eq!(
        PersistedDaemonState::default().schema_version,
        SchemaVersion(CURRENT_SCHEMA_VERSION)
    );

    // Legacy payloads without the field deserialize as version 1.
    let legacy: PersistedDaemonState =
        serde_json::from_str("{}").expect("legacy payload without schema_version");
    assert_eq!(legacy.schema_version, SchemaVersion(1));

    let mut future_state = serde_json::to_value(sample_state()).expect("state json");
    future_state["schema_version"] = serde_json::json!(CURRENT_SCHEMA_VERSION + 1);
    let bytes =
        encrypt_plaintext_state(&serde_json::to_vec(&future_state).expect("serialize future"));
    let err = match open_state(&bytes, &test_secret()) {
        Ok(_) => panic!("newer schema version must be rejected"),
        Err(err) => err,
    };
    assert!(err.contains("unsupported state schema version 2"));
    assert!(err.contains("supports up to 1"));
}
