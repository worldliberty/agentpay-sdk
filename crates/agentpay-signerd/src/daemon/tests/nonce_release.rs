//! Nonce release and reclamation of unused nonces.

use agentpay_domain::{AdminAuth, NonceReleaseRequest, NonceReservationRequest, PolicyAttachment};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::policy_all_per_tx;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn release_nonce_reclaims_latest_unused_nonce() {
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
    let reservation = daemon
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
        .expect("reserve");
    assert_eq!(reservation.nonce, 0);

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release");

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
        .expect("reserve after release");
    assert_eq!(next.nonce, 0);
}

#[tokio::test]
async fn reserve_nonce_with_higher_min_preserves_lower_reclaimed_and_skipped_nonces() {
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
    assert_eq!((first.nonce, third.nonce), (0, 2));

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

    let raised_min = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 5,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve with raised minimum");
    assert_eq!(raised_min.nonce, 5);

    let reclaimed_lower = daemon
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
        .expect("reserve reclaimed lower nonce");
    assert_eq!(reclaimed_lower.nonce, 0);

    let skipped_lower = daemon
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
        .expect("reserve skipped lower nonce");
    assert_eq!(skipped_lower.nonce, 2);
}

#[tokio::test]
async fn release_nonce_reclaims_out_of_order_gaps_before_head() {
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

    let recycled_gap = daemon
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
        .expect("reserve reclaimed gap");
    assert_eq!(recycled_gap.nonce, 0);

    let next_from_head = daemon
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
        .expect("reserve head after reclaimed gap");
    assert_eq!(next_from_head.nonce, 2);
}

#[tokio::test]
async fn expired_nonce_reservation_is_reclaimed_before_next_reserve() {
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
        .expect("first reserve");
    assert_eq!(first.nonce, 0);

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("second reserve");
    assert_eq!(second.nonce, 0);
}

#[tokio::test]
async fn expired_nonce_reservations_reclaim_out_of_order_gaps_before_head() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            nonce_reservation_ttl: time::Duration::seconds(1),
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
    let soon = now + time::Duration::milliseconds(5);
    let later = now + time::Duration::seconds(1);
    let first = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: soon,
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
            expires_at: later,
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
            expires_at: soon,
        })
        .await
        .expect("reserve third");
    assert_eq!((first.nonce, second.nonce, third.nonce), (0, 1, 2));

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let refresh_now = time::OffsetDateTime::now_utc();
    let recycled_gap = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: refresh_now,
            expires_at: refresh_now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve reclaimed expired gap");
    assert_eq!(recycled_gap.nonce, 0);

    let next_from_head = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: refresh_now,
            expires_at: refresh_now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve head after reclaimed expired gap");
    assert_eq!(next_from_head.nonce, 2);
}

#[tokio::test]
async fn release_nonce_replay_returns_success() {
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
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .release_nonce(release_request.clone())
        .await
        .expect("first release");

    daemon
        .release_nonce(release_request)
        .await
        .expect("identical release replay should be idempotent");
}

#[tokio::test]
async fn release_nonce_reuse_with_different_reservation_is_rejected() {
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
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");
    let other_reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: reservation.nonce + 1,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve other");

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        reservation_id: reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .release_nonce(release_request.clone())
        .await
        .expect("first release");

    let replay = NonceReleaseRequest {
        request_id: release_request.request_id,
        agent_key_id: release_request.agent_key_id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: other_reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    let err = daemon
        .release_nonce(replay)
        .await
        .expect_err("mismatched release replay must fail");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn release_nonce_rejects_non_owner_agent() {
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

    let owner_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("owner");
    let attacker_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("attacker");

    let now = time::OffsetDateTime::now_utc();
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: owner_credentials.agent_key.id,
            agent_auth_token: owner_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");

    let err = daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: attacker_credentials.agent_key.id,
            agent_auth_token: attacker_credentials.auth_token,
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect_err("non-owner should not release reservation");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: owner_credentials.agent_key.id,
            agent_auth_token: owner_credentials.auth_token,
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("owner must still be able to release");
}

#[tokio::test]
async fn release_nonce_removes_reservation_from_snapshot() {
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
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .release_nonce(release_request)
        .await
        .expect("release");

    let snapshot = daemon.snapshot_state().expect("snapshot");
    assert!(
        !snapshot
            .nonce_reservations
            .contains_key(&reservation.reservation_id),
        "released reservation must be removed from persisted state snapshot"
    );
}
