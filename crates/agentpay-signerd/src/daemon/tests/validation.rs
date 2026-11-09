//! Validation helpers: config, passwords, tokens, policies, and loaded state.

use std::collections::BTreeSet;

use agentpay_domain::{
    AdminAuth, EntityScope, ManualApprovalStatus, PolicyAttachment, SpendingPolicy,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use alloy_primitives::keccak256;
use uuid::Uuid;

use super::support::{
    policy_all_per_tx, sample_agent_credentials, sample_manual_approval_request,
    sample_nonce_reservation,
};
use crate::config::validate_config;
use crate::daemon::auth::{constant_time_eq, generate_agent_auth_token, hash_agent_auth_token};
use crate::daemon::policies::validate_policy;
use crate::daemon::signing::{
    ethereum_address_from_public_key_hex, map_domain_to_signer_error, parse_verifying_key,
    payload_hash_hex,
};
use crate::daemon::state::validate_loaded_state;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[test]
fn payload_hash_hex_is_stable_and_input_sensitive() {
    let first = payload_hash_hex(b"hello world");
    let second = payload_hash_hex(b"hello world");
    let different = payload_hash_hex(b"hello world!");

    assert_eq!(first, second);
    assert_ne!(first, different);
    assert_eq!(first.len(), 64);
}

#[tokio::test]
async fn ethereum_address_helper_derives_address_from_vault_public_key() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;

    let second = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("second key");

    let expected_address = {
        let public_bytes =
            hex::decode(second.public_key_hex.trim_start_matches("0x")).expect("decode public key");
        let digest = keccak256(&public_bytes[1..]);
        format!("0x{}", hex::encode(&digest.0[12..]))
    };

    assert_eq!(
        ethereum_address_from_public_key_hex(&second.public_key_hex).expect("address"),
        expected_address
    );
    assert!(
        matches!(
            ethereum_address_from_public_key_hex("zz"),
            Err(DaemonError::Signer(_))
        ),
        "invalid hex should be rejected"
    );
}

#[test]
fn api_validation_helpers_cover_config_and_token_paths() {
    validate_config(&DaemonConfig::default()).expect("valid config");
    assert!(matches!(
        validate_config(&DaemonConfig {
            lease_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("lease_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_active_leases: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_active_leases")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_sign_payload_bytes: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_sign_payload_bytes")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_request_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_request_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_request_clock_skew: time::Duration::seconds(-1),
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_request_clock_skew")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_tracked_replay_ids: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_tracked_replay_ids")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            nonce_reservation_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("nonce_reservation_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_active_nonce_reservations: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_active_nonce_reservations")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            manual_approval_active_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("manual_approval_active_ttl")
    ));
    validate_config(&DaemonConfig {
        manual_approval_terminal_retention: time::Duration::ZERO,
        ..DaemonConfig::default()
    })
    .expect("zero manual approval retention must be allowed");
    assert!(matches!(
        validate_config(&DaemonConfig {
            manual_approval_terminal_retention: time::Duration::seconds(-1),
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("manual_approval_terminal_retention")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_tracked_nonce_chains_per_vault: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_tracked_nonce_chains_per_vault")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_failed_admin_auth_attempts: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_failed_admin_auth_attempts")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            admin_auth_lockout: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("admin_auth_lockout")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            admin_challenge_ttl: time::Duration::ZERO,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("admin_challenge_ttl")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_pending_admin_challenges: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_pending_admin_challenges")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_admin_credentials: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message)) if message.contains("max_admin_credentials")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_pending_manual_approval_requests_per_agent: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_pending_manual_approval_requests_per_agent")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_recoverable_agent_results: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_recoverable_agent_results")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_persisted_argon2_memory_kib: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_persisted_argon2_*")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_persisted_argon2_time_cost: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_persisted_argon2_*")
    ));
    assert!(matches!(
        validate_config(&DaemonConfig {
            max_persisted_argon2_parallelism: 0,
            ..DaemonConfig::default()
        }),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("max_persisted_argon2_*")
    ));

    let token = generate_agent_auth_token();
    assert!(token.contains('.'));
    let left = hash_agent_auth_token(&token);
    let same = hash_agent_auth_token(&token);
    let right = hash_agent_auth_token("different-token");
    assert!(constant_time_eq(&left, &same));
    assert!(!constant_time_eq(&left, &right));
    assert!(!constant_time_eq(&left, &[1u8; 31]));
}

#[tokio::test]
async fn parsing_policy_and_loaded_state_helpers_cover_remaining_error_paths() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let parsed_key = parse_verifying_key(&key.public_key_hex).expect("valid public key");
    assert_eq!(
        parsed_key.to_encoded_point(false).as_bytes(),
        &hex::decode(&key.public_key_hex).expect("hex")
    );
    assert!(matches!(
        parse_verifying_key("zz"),
        Err(DaemonError::Signer(_))
    ));
    assert!(matches!(
        parse_verifying_key(&hex::encode([0u8; 33])),
        Err(DaemonError::Signer(_))
    ));
    assert!(matches!(
        map_domain_to_signer_error(agentpay_domain::DomainError::UnsupportedTransactionType(
            0x03
        )),
        DaemonError::Signer(_)
    ));

    validate_policy(&policy_all_per_tx(1)).expect("valid policy");
    validate_policy(
        &SpendingPolicy::new_calldata_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid calldata policy"),
    )
    .expect("calldata policy");
    validate_policy(
        &SpendingPolicy::new_tx_count_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid tx-count policy"),
    )
    .expect("tx-count policy");
    validate_policy(
        &SpendingPolicy::new_fee_per_gas_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid max-fee policy"),
    )
    .expect("max-fee policy");
    validate_policy(
        &SpendingPolicy::new_priority_fee_per_gas_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid priority-fee policy"),
    )
    .expect("priority-fee policy");
    validate_policy(
        &SpendingPolicy::new_gas_spend_limit(
            0,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("valid gas-spend policy"),
    )
    .expect("gas-spend policy");
    let mut zero_policy = policy_all_per_tx(1);
    zero_policy.max_amount_wei = 0;
    assert!(matches!(
        validate_policy(&zero_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_amount_wei")
    ));
    let mut zero_calldata_policy = SpendingPolicy::new_calldata_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid calldata policy");
    zero_calldata_policy.max_calldata_bytes = None;
    zero_calldata_policy.max_amount_wei = 0;
    assert!(matches!(
        validate_policy(&zero_calldata_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_calldata_bytes")
    ));
    let mut zero_tx_count_policy = SpendingPolicy::new_tx_count_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid tx-count policy");
    zero_tx_count_policy.max_tx_count = None;
    assert!(matches!(
        validate_policy(&zero_tx_count_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_tx_count")
    ));
    let mut zero_max_fee_policy = SpendingPolicy::new_fee_per_gas_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid max-fee policy");
    zero_max_fee_policy.max_fee_per_gas_wei = None;
    assert!(matches!(
        validate_policy(&zero_max_fee_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_fee_per_gas_wei")
    ));
    let mut zero_priority_fee_policy = SpendingPolicy::new_priority_fee_per_gas_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid priority-fee policy");
    zero_priority_fee_policy.max_priority_fee_per_gas_wei = None;
    assert!(matches!(
        validate_policy(&zero_priority_fee_policy),
        Err(DaemonError::InvalidPolicy(message))
            if message.contains("max_priority_fee_per_gas_wei")
    ));
    let mut zero_gas_spend_policy = SpendingPolicy::new_gas_spend_limit(
        0,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("valid gas-spend policy");
    zero_gas_spend_policy.max_gas_spend_wei = None;
    assert!(matches!(
        validate_policy(&zero_gas_spend_policy),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("max_gas_spend_wei")
    ));
    let mut bad_networks = policy_all_per_tx(1);
    bad_networks.networks = EntityScope::Set(BTreeSet::from([0]));
    assert!(matches!(
        validate_policy(&bad_networks),
        Err(DaemonError::InvalidPolicy(message)) if message.contains("network set scope")
    ));

    let valid_state = daemon.snapshot_state().expect("snapshot");
    validate_loaded_state(&valid_state).expect("valid loaded state");

    let mut state = valid_state.clone();
    let credential = agentpay_domain::AdminCredential {
        id: Uuid::new_v4(),
        public_key_sec1_hex: "04".to_string() + &"11".repeat(64),
        label: "Mac".to_string(),
        created_at: time::OffsetDateTime::now_utc(),
    };
    state
        .admin_credentials
        .insert(Uuid::new_v4(), credential.clone());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("admin credential entry keyed by")
    ));
    let mut state = valid_state.clone();
    state.admin_credentials.insert(credential.id, credential);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("not a valid P-256 point")
    ));

    let mut state = valid_state.clone();
    let mut policy = policy_all_per_tx(1);
    let mismatched_policy_key = Uuid::new_v4();
    policy.id = Uuid::new_v4();
    state.policies.insert(mismatched_policy_key, policy);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("policy entry keyed by")
    ));

    let mut state = valid_state.clone();
    state
        .software_signer_private_keys
        .insert(Uuid::new_v4(), "11".repeat(32).into());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("signer key material")
    ));

    let mut state = valid_state.clone();
    let agent_key = sample_agent_credentials().agent_key;
    state.agent_keys.insert(agent_key.id, agent_key.clone());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references unknown vault key")
    ));

    let mut state = valid_state.clone();
    let mut attached_agent = sample_agent_credentials().agent_key;
    attached_agent.vault_key_id = key.id;
    attached_agent.policies = PolicyAttachment::PolicySet(BTreeSet::new());
    state.agent_keys.insert(attached_agent.id, attached_agent);
    validate_loaded_state(&state).expect("empty policy set should be loadable");

    let mut state = valid_state.clone();
    let mut disabled_policy = policy_all_per_tx(100);
    disabled_policy.enabled = false;
    let disabled_policy_id = disabled_policy.id;
    state.policies.insert(disabled_policy.id, disabled_policy);
    let mut attached_agent = sample_agent_credentials().agent_key;
    attached_agent.vault_key_id = key.id;
    attached_agent.policies = PolicyAttachment::PolicySet(BTreeSet::from([disabled_policy_id]));
    state.agent_keys.insert(attached_agent.id, attached_agent);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("disabled policy")
    ));

    let mut state = valid_state.clone();
    state.agent_auth_tokens.insert(Uuid::new_v4(), [7u8; 32]);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("auth token for unknown agent")
    ));

    let mut state = valid_state.clone();
    state
        .nonce_heads
        .insert(Uuid::new_v4(), std::collections::HashMap::new());
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("nonce head for unknown vault key")
    ));

    let mut state = valid_state.clone();
    state.nonce_heads.entry(key.id).or_default().insert(0, 7);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid chain_id 0")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut reservation = sample_nonce_reservation();
    reservation.agent_key_id = valid_agent.id;
    reservation.vault_key_id = key.id;
    reservation.chain_id = 0;
    state
        .nonce_reservations
        .insert(reservation.reservation_id, reservation);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid chain_id 0")
    ));

    let mut state = valid_state.clone();
    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    let manual_policy_id = manual_policy.id;
    state.policies.insert(manual_policy.id, manual_policy);
    let mut request = sample_manual_approval_request();
    request.agent_key_id = Uuid::new_v4();
    request.triggered_by_policy_ids = vec![manual_policy_id];
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references unknown agent")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = Uuid::new_v4();
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("vault key mismatch")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.chain_id = 0;
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid chain_id 0")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.request_payload_hash_hex = "   ".to_string();
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("empty payload hash")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.updated_at = request.created_at - time::Duration::seconds(1);
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("invalid timestamps")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.status = ManualApprovalStatus::Completed;
    request.completed_at = None;
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("completed without completed_at")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.triggered_by_policy_ids = vec![Uuid::new_v4()];
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references unknown policy")
    ));

    let mut state = valid_state.clone();
    let mut valid_agent = sample_agent_credentials().agent_key;
    valid_agent.vault_key_id = key.id;
    state.agent_keys.insert(valid_agent.id, valid_agent.clone());
    let mut non_manual_policy = policy_all_per_tx(1);
    non_manual_policy.id = Uuid::new_v4();
    let non_manual_policy_id = non_manual_policy.id;
    state
        .policies
        .insert(non_manual_policy.id, non_manual_policy);
    let mut request = sample_manual_approval_request();
    request.agent_key_id = valid_agent.id;
    request.vault_key_id = key.id;
    request.triggered_by_policy_ids = vec![non_manual_policy_id];
    state.manual_approval_requests.insert(request.id, request);
    assert!(matches!(
        validate_loaded_state(&state),
        Err(DaemonError::Persistence(message)) if message.contains("references non-manual policy")
    ));
}

#[test]
fn daemon_new_rejects_invalid_runtime_limits() {
    let config = DaemonConfig {
        max_active_leases: 0,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "zero lease capacity must be rejected"
    );

    let config = DaemonConfig {
        max_sign_payload_bytes: 0,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "zero payload cap must be rejected"
    );

    let config = DaemonConfig {
        max_request_ttl: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive request ttl must be rejected"
    );

    let config = DaemonConfig {
        nonce_reservation_ttl: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive nonce reservation ttl must be rejected"
    );

    let config = DaemonConfig {
        manual_approval_terminal_retention: time::Duration::MAX,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(message)) if message.contains("manual_approval_terminal_retention")),
        "overflowing manual approval retention must be rejected"
    );

    let config = DaemonConfig {
        max_failed_admin_auth_attempts: 0,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "zero admin auth attempt budget must be rejected"
    );

    let config = DaemonConfig {
        admin_auth_lockout: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive admin auth lockout must be rejected"
    );

    let config = DaemonConfig {
        lease_ttl: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new(SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive lease ttl must be rejected"
    );
}

#[test]
fn validate_config_accepts_default_legacy_kdf_maxima() {
    let config = DaemonConfig {
        max_persisted_argon2_memory_kib: 1,
        max_persisted_argon2_time_cost: 1,
        max_persisted_argon2_parallelism: 1,
        ..DaemonConfig::default()
    };
    validate_config(&config).expect("small but non-zero legacy KDF maxima are valid");
}
