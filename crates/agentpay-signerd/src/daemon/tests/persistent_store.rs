//! Daemon state persistence and startup scrubbing.

use std::time::{SystemTime, UNIX_EPOCH};

use agentpay_domain::{
    AdminAuth, AgentAction, AssetId, EntityScope, ManualApprovalStatus, NonceReleaseRequest,
    NonceReservationRequest, PolicyAttachment, SpendingPolicy,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    policy_all_per_tx, reserve_nonce_for_agent, sample_manual_approval_request,
    sample_nonce_reservation, sign_request, test_state_secret, unique_state_path,
};
use crate::persistence::EncryptedStateStore;
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
    StateSecret,
};

#[tokio::test]
async fn snapshot_restore_and_non_persistent_helpers_cover_state_management_paths() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(77))
        .await
        .expect("add policy");
    let vault_key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let agent_credentials = daemon
        .create_agent_key(&session, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent credentials");
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 5).await;
    let snapshot = daemon.snapshot_state().expect("snapshot");

    daemon.policies.write().expect("policies").clear();
    daemon.vault_keys.write().expect("vault keys").clear();
    daemon.agent_keys.write().expect("agent keys").clear();
    daemon
        .agent_auth_tokens
        .write()
        .expect("auth tokens")
        .clear();
    daemon
        .reusable_nonce_gaps
        .write()
        .expect("reusable nonce gaps")
        .clear();
    daemon
        .nonce_reservations
        .write()
        .expect("reservations")
        .clear();
    daemon
        .restore_state(snapshot.clone())
        .expect("restore snapshot");

    assert_eq!(
        daemon.snapshot_state().expect("restored snapshot").policies,
        snapshot.policies
    );
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("restored snapshot")
            .vault_keys,
        snapshot.vault_keys
    );
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("restored snapshot")
            .agent_auth_tokens,
        snapshot.agent_auth_tokens
    );
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("restored snapshot")
            .nonce_reservations,
        snapshot.nonce_reservations
    );

    assert!(daemon
        .backup_state_if_persistent()
        .expect("backup")
        .is_none());
    daemon.persist_state_if_enabled().expect("persist noop");
    daemon
        .persist_or_revert(None)
        .expect("persist or revert noop");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_restores_policies_and_agent_auth_state() {
    let state_path = unique_state_path("restore");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let policy = policy_all_per_tx(1_000);
    daemon
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1500000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2500000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };
    let request = sign_request(&agent_credentials, action);
    daemon
        .evaluate_for_agent(request.clone())
        .await
        .expect("evaluate before restart");
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    let session = AdminAuth::PeerCredentials;
    let listed = restarted
        .list_policies(&session)
        .await
        .expect("list policies");
    assert!(
        listed.iter().any(|item| item.id == policy.id),
        "policy should persist across restart"
    );
    restarted
        .evaluate_for_agent(request)
        .await
        .expect("evaluate after restart");
    restarted
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1500000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2500000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("sign after restart");

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_restores_reclaimed_nonce_gaps_before_head() {
    let state_path = unique_state_path("nonce-gap-restore");
    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let now = time::OffsetDateTime::now_utc();
    let first = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve first");
    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve second");
    let third = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve third");
    assert_eq!((first.nonce, second.nonce, third.nonce), (0, 1, 2));

    for reservation_id in [first.reservation_id, third.reservation_id] {
        daemon
            .release_nonce(NonceReleaseRequest {
                request_id: Uuid::new_v4(),
                agent_key_id: agent_credentials.agent_key.id,
                agent_auth_token: agent_credentials.auth_token.clone(),
                reservation_id,
                requested_at: now,
                expires_at: now + time::Duration::minutes(2),
            })
            .await
            .expect("release reclaimed gap");
    }

    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");

    let reclaimed_gap = restarted
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve reclaimed gap after restart");
    assert_eq!(reclaimed_gap.nonce, 0);

    let next_from_head = restarted
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve head after restart");
    assert_eq!(next_from_head.nonce, 2);

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_scrubs_expired_ephemeral_state_on_startup() {
    let state_path = unique_state_path("startup-scrub");
    let config = DaemonConfig {
        manual_approval_active_ttl: time::Duration::minutes(1),
        manual_approval_terminal_retention: time::Duration::minutes(1),
        ..DaemonConfig::default()
    };

    let daemon =
        InMemoryDaemon::new(SoftwareSignerBackend::default(), config.clone()).expect("daemon");
    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut stale_state = daemon.snapshot_state().expect("snapshot");
    stale_state.replay_ids.clear();
    stale_state.nonce_heads.clear();
    stale_state.nonce_reservations.clear();
    stale_state.spend_log.clear();
    stale_state.manual_approval_requests.clear();

    let now = time::OffsetDateTime::now_utc();
    let stale_replay_id = Uuid::new_v4();
    stale_state
        .replay_ids
        .insert(stale_replay_id, now - time::Duration::seconds(1));

    let mut stale_reservation = sample_nonce_reservation();
    stale_reservation.reservation_id = Uuid::new_v4();
    stale_reservation.agent_key_id = agent_credentials.agent_key.id;
    stale_reservation.vault_key_id = key.id;
    stale_reservation.chain_id = 1;
    stale_reservation.nonce = 0;
    stale_reservation.issued_at = now - time::Duration::minutes(5);
    stale_reservation.expires_at = now - time::Duration::minutes(4);
    let stale_reservation_id = stale_reservation.reservation_id;
    stale_state.nonce_heads.insert(
        key.id,
        std::collections::HashMap::from([(stale_reservation.chain_id, 1)]),
    );
    stale_state
        .nonce_reservations
        .insert(stale_reservation_id, stale_reservation);

    stale_state.spend_log.push(agentpay_domain::SpendEvent {
        agent_key_id: agent_credentials.agent_key.id,
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 7,
        at: now - time::Duration::days(9),
        approval_request_id: None,
    });

    let mut stale_request = sample_manual_approval_request();
    stale_request.id = Uuid::new_v4();
    stale_request.agent_key_id = agent_credentials.agent_key.id;
    stale_request.vault_key_id = key.id;
    stale_request.created_at = now - time::Duration::minutes(5);
    stale_request.updated_at = now - time::Duration::minutes(5);
    stale_request.status = ManualApprovalStatus::Pending;
    stale_request.triggered_by_policy_ids = vec![manual_policy.id];
    let stale_request_id = stale_request.id;
    stale_state
        .manual_approval_requests
        .insert(stale_request_id, stale_request);

    let (store, _) = EncryptedStateStore::open_or_initialize(
        &test_state_secret(),
        &config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("store");
    store.save(&stale_state).expect("write stale state");

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    assert!(
        !restarted
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "startup scrub must remove expired replay ids"
    );
    assert!(
        !restarted
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "startup scrub must remove expired nonce reservations"
    );
    assert!(
        restarted
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "startup scrub must reclaim nonce heads tied only to expired reservations"
    );
    assert!(
        restarted.spend_log.read().expect("spend log").is_empty(),
        "startup scrub must remove expired spend history"
    );
    assert!(
        !restarted
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "startup scrub must remove expired manual approvals"
    );
    drop(restarted);

    let reloaded = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("reloaded daemon");
    assert!(
        !reloaded
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "startup scrub must persist cleaned replay ids"
    );
    assert!(
        !reloaded
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "startup scrub must persist cleaned reservations"
    );
    assert!(
        reloaded
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "startup scrub must persist reclaimed nonce heads"
    );
    assert!(
        reloaded.spend_log.read().expect("spend log").is_empty(),
        "startup scrub must persist cleaned spend history"
    );
    assert!(
        !reloaded
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "startup scrub must persist cleaned manual approvals"
    );
    drop(reloaded);

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn unrelated_persistence_paths_scrub_expired_ephemeral_state_before_save() {
    let state_path = unique_state_path("persist-scrub");
    let config = DaemonConfig {
        manual_approval_active_ttl: time::Duration::minutes(1),
        manual_approval_terminal_retention: time::Duration::minutes(1),
        ..DaemonConfig::default()
    };

    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let now = time::OffsetDateTime::now_utc();
    let stale_replay_id = Uuid::new_v4();
    daemon
        .replay_ids
        .write()
        .expect("replay ids")
        .insert(stale_replay_id, now - time::Duration::seconds(1));

    let mut stale_reservation = sample_nonce_reservation();
    stale_reservation.reservation_id = Uuid::new_v4();
    stale_reservation.agent_key_id = agent_credentials.agent_key.id;
    stale_reservation.vault_key_id = key.id;
    stale_reservation.chain_id = 1;
    stale_reservation.nonce = 0;
    stale_reservation.issued_at = now - time::Duration::minutes(5);
    stale_reservation.expires_at = now - time::Duration::minutes(4);
    let stale_reservation_id = stale_reservation.reservation_id;
    daemon.nonce_heads.write().expect("nonce heads").insert(
        key.id,
        std::collections::HashMap::from([(stale_reservation.chain_id, 1)]),
    );
    daemon
        .nonce_reservations
        .write()
        .expect("nonce reservations")
        .insert(stale_reservation_id, stale_reservation);

    daemon
        .spend_log
        .write()
        .expect("spend log")
        .push(agentpay_domain::SpendEvent {
            agent_key_id: agent_credentials.agent_key.id,
            chain_id: 1,
            asset: AssetId::NativeEth,
            recipient: "0x7200000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 8,
            at: now - time::Duration::days(9),
            approval_request_id: None,
        });

    let mut stale_request = sample_manual_approval_request();
    stale_request.id = Uuid::new_v4();
    stale_request.agent_key_id = agent_credentials.agent_key.id;
    stale_request.vault_key_id = key.id;
    stale_request.created_at = now - time::Duration::minutes(5);
    stale_request.updated_at = now - time::Duration::minutes(5);
    stale_request.status = ManualApprovalStatus::Pending;
    stale_request.triggered_by_policy_ids = vec![manual_policy.id];
    let stale_request_id = stale_request.id;
    daemon
        .manual_approval_requests
        .write()
        .expect("manual approvals")
        .insert(stale_request_id, stale_request);

    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("unrelated admin write");

    assert!(
        !daemon
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "unrelated persistence must prune expired replay ids"
    );
    assert!(
        !daemon
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "unrelated persistence must prune expired nonce reservations"
    );
    assert!(
        daemon
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "unrelated persistence must reclaim nonce heads tied only to expired reservations"
    );
    assert!(
        daemon.spend_log.read().expect("spend log").is_empty(),
        "unrelated persistence must prune expired spend history"
    );
    assert!(
        !daemon
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "unrelated persistence must prune expired manual approvals"
    );
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    assert!(
        !restarted
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "cleaned persistence must stay free of expired replay ids after restart"
    );
    assert!(
        !restarted
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "cleaned persistence must stay free of expired nonce reservations after restart"
    );
    assert!(
        restarted
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "cleaned persistence must keep reclaimed nonce heads removed after restart"
    );
    assert!(
        restarted.spend_log.read().expect("spend log").is_empty(),
        "cleaned persistence must stay free of expired spend history after restart"
    );
    assert!(
        !restarted
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "cleaned persistence must stay free of expired manual approvals after restart"
    );
    drop(restarted);

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_rejects_wrong_state_secret() {
    let state_path = unique_state_path("wrong-password");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(10))
        .await
        .expect("add policy");
    drop(daemon);

    let wrong_secret = StateSecret::from_bytes([9u8; 32]).expect("secret");
    let err = match InMemoryDaemon::new_with_persistent_store(
        &wrong_secret,
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    ) {
        Ok(_) => panic!("wrong state secret must fail state load"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::Persistence(message) if message.contains("wrong state secret"))
    );

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_rejects_group_writable_ancestor_directory() {
    use std::os::unix::fs::PermissionsExt;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "agentpay-daemon-persistence-parent-{}-{}",
        std::process::id(),
        unique
    ));
    let insecure = root.join("insecure");
    let leaf = insecure.join("leaf");
    std::fs::create_dir_all(&leaf).expect("create test directories");
    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o770))
        .expect("set insecure ancestor permissions");

    let err = match InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(leaf.join("daemon-state.enc")),
    ) {
        Ok(_) => panic!("group-writable ancestor must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::Persistence(message) if message.contains("state directory") && message.contains("must not be writable by group/other"))
    );

    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o700))
        .expect("restore ancestor permissions for cleanup");
    std::fs::remove_dir_all(&root).expect("cleanup directories");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_rejects_group_readable_state_file() {
    use std::os::unix::fs::PermissionsExt;

    let state_path = unique_state_path("group-readable");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(10))
        .await
        .expect("add policy");
    drop(daemon);

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640))
        .expect("set insecure state file permissions");

    let err = match InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    ) {
        Ok(_) => panic!("group-readable state file must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::Persistence(message) if message.contains("state file") && message.contains("must not grant group/other permissions"))
    );

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore state file permissions for cleanup");
    std::fs::remove_file(&state_path).expect("cleanup state file");
}
