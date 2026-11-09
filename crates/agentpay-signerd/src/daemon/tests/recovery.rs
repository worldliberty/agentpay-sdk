//! Recovery of signatures and nonce results after persistence failures.

use std::time::{SystemTime, UNIX_EPOCH};

use agentpay_domain::{
    AdminAuth, AgentAction, EntityScope, EvmAddress, NonceReleaseRequest, NonceReservationRequest,
    PolicyAttachment, PolicyType, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    daemon_with_agent, nonce_request, policy_all_per_tx, recoverable_release, sign_request,
    test_state_secret, unique_state_path,
};
use crate::persistence::PersistedDaemonState;
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
};

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn sign_success_survives_post_sign_persist_failure_and_flushes_later() {
    use std::os::unix::fs::PermissionsExt;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "agentpay-daemon-sign-persist-recovery-{}-{}",
        std::process::id(),
        unique
    ));
    std::fs::create_dir_all(&root).expect("create persistence root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("secure persistence root");
    let state_path = root.join("daemon-state.enc");

    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                0,
                PolicyType::DailyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily policy"),
        )
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

    let token = "0x7100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let first = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 40,
        },
    );

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770))
        .expect("make persistence root insecure");

    let signature = daemon
        .sign_for_agent(first.clone())
        .await
        .expect("signature must still be returned when post-sign persistence fails");
    assert!(!signature.bytes.is_empty());

    let recovered = daemon
        .sign_for_agent(first.clone())
        .await
        .expect("same request id must recover the stored signature");
    assert_eq!(recovered, signature);

    let spend_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: recipient.clone(),
                amount_wei: 70,
            },
        ))
        .await
        .expect_err("spend log must remain live in memory");
    assert!(matches!(
        spend_err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 40,
            requested_amount_wei: 70,
            ..
        })
    ));

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("restore persistence root permissions");
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("later mutation should flush pending signed state");
    drop(daemon);

    let reloaded = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("reload daemon");

    let recovered = reloaded
        .sign_for_agent(first)
        .await
        .expect("persisted recovery cache should return the original signature");
    assert_eq!(recovered, signature);

    let spend_err = reloaded
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 70,
            },
        ))
        .await
        .expect_err("persisted spend log must survive restart");
    assert!(matches!(
        spend_err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 40,
            requested_amount_wei: 70,
            ..
        })
    ));

    drop(reloaded);
    std::fs::remove_dir_all(&root).expect("cleanup persistence root");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn sign_for_agent_recovers_signature_after_post_sign_persist_failure() {
    use std::os::unix::fs::PermissionsExt;

    let state_path = unique_state_path("recover-signature-after-persist-failure");
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

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x1600000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2600000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640))
        .expect("make state file unwritable for secure save");

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("signature should still be returned");
    assert!(!signature.bytes.is_empty());
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("snapshot after sign")
            .spend_log
            .len(),
        1
    );

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore state file permissions");

    let recovered = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("retry should recover the original signature");
    assert_eq!(recovered, signature);
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("snapshot after recovery")
            .spend_log
            .len(),
        1
    );

    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restart daemon");
    let recovered = restarted
        .sign_for_agent(request)
        .await
        .expect("restarted daemon should recover the original signature");
    assert_eq!(recovered, signature);

    std::fs::remove_file(&state_path).expect("cleanup state file");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn nonce_recovery_results_survive_restart() {
    let state_path = unique_state_path("recover-nonce-results-after-restart");
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
    let reserve_request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };
    let reservation = daemon
        .reserve_nonce(reserve_request.clone())
        .await
        .expect("reserve");
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restart daemon");
    let recovered_reservation = restarted
        .reserve_nonce(reserve_request.clone())
        .await
        .expect("restart should recover original reservation");
    assert_eq!(recovered_reservation, reservation);

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: reservation.reservation_id,
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };
    restarted
        .release_nonce(release_request.clone())
        .await
        .expect("release");
    drop(restarted);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restart daemon after release");
    restarted
        .release_nonce(release_request)
        .await
        .expect("restart should recover release success");
    assert!(restarted
        .snapshot_state()
        .expect("snapshot after recovered release")
        .nonce_reservations
        .is_empty());

    drop(restarted);
    std::fs::remove_file(&state_path).expect("cleanup state file");
}

#[test]
fn record_recoverable_agent_result_evicts_oldest_entries_beyond_cap() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_recoverable_agent_results: 3,
            ..DaemonConfig::default()
        },
    )
    .expect("daemon");
    let now = time::OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let request_ids = (0..5).map(|_| Uuid::new_v4()).collect::<Vec<_>>();

    for (index, request_id) in request_ids.iter().enumerate() {
        let recover_until = now + time::Duration::days(8) + time::Duration::seconds(index as i64);
        daemon
            .record_recoverable_agent_result(
                *request_id,
                recoverable_release(agent_key_id, recover_until),
                now,
            )
            .expect("record result");
        assert!(
            daemon
                .recoverable_agent_results
                .read()
                .expect("results")
                .len()
                <= 3,
            "table must never exceed the configured cap"
        );
    }

    let results = daemon.recoverable_agent_results.read().expect("results");
    assert_eq!(results.len(), 3);
    assert!(
        !results.contains_key(&request_ids[0]),
        "oldest entry evicted"
    );
    assert!(
        !results.contains_key(&request_ids[1]),
        "second oldest entry evicted"
    );
    for request_id in &request_ids[2..] {
        assert!(results.contains_key(request_id), "newest entries retained");
    }
}

#[tokio::test]
async fn recoverable_result_cap_evicts_oldest_reservation_recovery() {
    let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig {
        max_recoverable_agent_results: 2,
        ..DaemonConfig::default()
    })
    .await;

    let mut requests = Vec::new();
    for _ in 0..3 {
        let request = nonce_request(&credentials, Uuid::new_v4(), 0, false);
        daemon
            .reserve_nonce(request.clone())
            .await
            .expect("reservation");
        requests.push(request);
        // Recoverable results are ordered by their expiry, which derives from the
        // wall clock; keep consecutive reservations strictly ordered.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    assert_eq!(
        daemon
            .recoverable_agent_results
            .read()
            .expect("results")
            .len(),
        2
    );

    // The oldest recovery entry is gone, so the retry is treated as a replay.
    let err = daemon
        .reserve_nonce(requests[0].clone())
        .await
        .expect_err("evicted recovery must not re-issue a nonce");
    assert!(matches!(err, DaemonError::RequestReplayDetected));

    // Newer entries still recover idempotently.
    let recovered = daemon
        .reserve_nonce(requests[2].clone())
        .await
        .expect("recent request recovers");
    assert_eq!(recovered.nonce, 2);
    assert_eq!(
        daemon
            .nonce_reservations
            .read()
            .expect("reservations")
            .len(),
        3,
        "recovery must not allocate additional reservations"
    );
}

#[test]
fn scrub_persisted_ephemeral_state_trims_recoverable_results_to_cap() {
    let config = DaemonConfig {
        max_recoverable_agent_results: 2,
        ..DaemonConfig::default()
    };
    let now = time::OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let mut state = PersistedDaemonState::default();
    let request_ids = (0..4).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    for (index, request_id) in request_ids.iter().enumerate() {
        state.recoverable_agent_results.insert(
            *request_id,
            recoverable_release(
                agent_key_id,
                now + time::Duration::days(1) + time::Duration::seconds(index as i64),
            ),
        );
    }
    let expired_id = Uuid::new_v4();
    state.recoverable_agent_results.insert(
        expired_id,
        recoverable_release(agent_key_id, now - time::Duration::seconds(1)),
    );

    InMemoryDaemon::<SoftwareSignerBackend>::scrub_persisted_ephemeral_state(
        &config, &mut state, now,
    )
    .expect("scrub");

    assert_eq!(state.recoverable_agent_results.len(), 2);
    assert!(!state.recoverable_agent_results.contains_key(&expired_id));
    assert!(!state
        .recoverable_agent_results
        .contains_key(&request_ids[0]));
    assert!(!state
        .recoverable_agent_results
        .contains_key(&request_ids[1]));
    assert!(state
        .recoverable_agent_results
        .contains_key(&request_ids[2]));
    assert!(state
        .recoverable_agent_results
        .contains_key(&request_ids[3]));
}
