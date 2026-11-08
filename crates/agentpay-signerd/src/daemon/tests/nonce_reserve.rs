//! Nonce reservation and reservation replay.

use agentpay_domain::{
    AdminAuth, AgentAction, BroadcastTx, NonceReleaseRequest, NonceReservation,
    NonceReservationRequest, PolicyAttachment,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    policy_all_per_tx, policy_per_chain_gas, reserve_nonce_for_agent, sign_request,
};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn reserve_nonce_is_monotonic_for_same_agent_and_chain() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
            chain_id: 1,
            min_nonce: 7,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reservation");
    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 7,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("second reservation");
    assert_eq!(first.nonce, 7);
    assert_eq!(second.nonce, 8);
}

#[tokio::test]
async fn reserve_nonce_replay_recovers_original_reservation() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        chain_id: 1,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    let first = daemon
        .reserve_nonce(request.clone())
        .await
        .expect("first reserve");

    let second = daemon
        .reserve_nonce(request)
        .await
        .expect("identical reserve replay should recover the original reservation");
    assert_eq!(second, first);
}

#[tokio::test]
async fn reserve_nonce_replay_is_rejected_after_release() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release");

    let err = daemon
        .reserve_nonce(reserve_request)
        .await
        .expect_err("released reservation must not be replay-recovered");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn reserve_nonce_replay_is_rejected_after_signed_request_consumes_reservation() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

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
    daemon
        .reserve_nonce(reserve_request.clone())
        .await
        .expect("reserve");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x9300000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 1_000_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect("consume reservation by signing");

    let err = daemon
        .reserve_nonce(reserve_request)
        .await
        .expect_err("consumed reservation must not be replay-recovered");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn reserve_nonce_replay_is_rejected_after_reservation_expiry() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            nonce_reservation_ttl: time::Duration::milliseconds(5),
            ..DaemonConfig::default()
        },
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
    let request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        chain_id: 56,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };
    daemon
        .reserve_nonce(request.clone())
        .await
        .expect("reserve");

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let err = daemon
        .reserve_nonce(request)
        .await
        .expect_err("expired reservation must not be replay-recovered");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn reserve_nonce_reuse_with_different_scope_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .reserve_nonce(request.clone())
        .await
        .expect("first reserve");

    let replay = NonceReservationRequest {
        request_id: request.request_id,
        agent_key_id: request.agent_key_id,
        agent_auth_token: agent_credentials.auth_token,
        chain_id: 10,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    let err = daemon
        .reserve_nonce(replay)
        .await
        .expect_err("mismatched reserve replay must fail");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn exact_nonce_reserve_consumes_reclaimed_gap() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let _second = daemon
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

    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve exact reclaimed gap");
    assert_eq!(exact.nonce, 0);

    let next = daemon
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
        .expect("reserve after exact reclaimed gap");
    assert_eq!(next.nonce, 2);
}

#[tokio::test]
async fn exact_nonce_above_head_preserves_skipped_lower_nonces() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    // Track a head first; an untracked chain is seeded at the requested nonce
    // without gaps, so skipped nonces only exist relative to a tracked head.
    let tracked = daemon
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
        .expect("reserve initial head");
    assert_eq!(tracked.nonce, 0);

    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 5,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve exact above head");
    assert_eq!(exact.nonce, 5);

    let first_lower = daemon
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
        .expect("reserve first skipped lower nonce");
    assert_eq!(first_lower.nonce, 1);

    let second_lower = daemon
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
        .expect("reserve second skipped lower nonce");
    assert_eq!(second_lower.nonce, 2);
}

#[tokio::test]
async fn exact_nonce_can_reuse_chain_nonce_after_signed_request_advances_head() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;
    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x9300000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 1_000_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect("consume first reservation");

    let now = time::OffsetDateTime::now_utc();
    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("exact reserve");
    assert_eq!(exact.nonce, 0);

    let next = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("next reserve");
    assert_eq!(next.nonce, 1);
}

#[tokio::test]
async fn future_issued_nonce_reservation_is_reclaimed_before_exact_reserve() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let future_reservation = NonceReservation {
        reservation_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        vault_key_id: key.id,
        chain_id: 1,
        nonce: 0,
        issued_at: now + time::Duration::hours(1),
        expires_at: now + time::Duration::hours(2),
    };
    daemon
        .nonce_reservations
        .write()
        .expect("reservations write")
        .insert(
            future_reservation.reservation_id,
            future_reservation.clone(),
        );

    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("exact reserve must ignore future reservation");

    assert_eq!(exact.nonce, 0);
    let reservations = daemon.nonce_reservations.read().expect("reservations read");
    assert!(!reservations.contains_key(&future_reservation.reservation_id));
    assert!(reservations.contains_key(&exact.reservation_id));
}

#[tokio::test]
async fn reserve_nonce_rejects_zero_chain_id() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 0,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect_err("chain_id zero must fail");

    assert!(matches!(
        err,
        DaemonError::InvalidNonceReservation(message)
            if message.contains("chain_id must be greater than zero")
    ));
}
