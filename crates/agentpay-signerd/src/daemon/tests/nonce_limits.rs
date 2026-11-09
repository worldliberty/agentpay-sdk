//! Nonce skip bounds and nonce tracking capacity limits.

use agentpay_domain::{AdminAuth, NonceReleaseRequest, NonceReservationRequest, PolicyAttachment};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    daemon_with_agent, nonce_request, policy_all_per_tx, tracked_nonce_gap_count,
    tracked_nonce_head,
};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, MAX_NONCE_SKIP};

#[tokio::test]
async fn nonce_head_tracking_limit_blocks_new_chains_until_old_heads_are_reclaimed() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_tracked_nonce_chains_per_vault: 1,
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
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reserve");

    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 2,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect_err("second chain should exceed tracking limit");
    assert!(matches!(
        err,
        DaemonError::InvalidNonceReservation(message)
            if message.contains("maximum 1 nonce head chains")
    ));

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: first.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release first reservation");

    assert!(
        daemon
            .nonce_heads
            .read()
            .expect("nonce heads read")
            .get(&key.id)
            .is_none(),
        "releasing the only tracked head should reclaim the chain entry"
    );

    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 2,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reclaimed head capacity should allow a new chain");
    assert_eq!(second.nonce, 0);
}

#[tokio::test]
async fn active_nonce_reservation_limit_blocks_new_reservations_until_slots_are_freed() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_active_nonce_reservations: 1,
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
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reserve");

    let full_now = time::OffsetDateTime::now_utc();
    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: full_now,
            expires_at: full_now + time::Duration::minutes(2),
        })
        .await
        .expect_err("second active reservation should exceed cap");
    assert!(matches!(
        err,
        DaemonError::TooManyActiveNonceReservations { max_active: 1 }
    ));

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: first.reservation_id,
            requested_at: full_now,
            expires_at: full_now + time::Duration::minutes(2),
        })
        .await
        .expect("release first reservation");

    let recovery_now = time::OffsetDateTime::now_utc();
    let recovered = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: recovery_now,
            expires_at: recovery_now + time::Duration::minutes(2),
        })
        .await
        .expect("released reservation should free capacity");
    assert_eq!(recovered.nonce, 0);
}

#[tokio::test]
async fn reserve_nonce_rejects_skips_beyond_max_nonce_skip_without_state_change() {
    let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig::default()).await;

    // Track a head first: the skip bound only applies relative to a tracked head.
    let first = daemon
        .reserve_nonce(nonce_request(&credentials, Uuid::new_v4(), 0, false))
        .await
        .expect("first reservation");
    assert_eq!(first.nonce, 0);
    assert_eq!(tracked_nonce_head(&daemon, &credentials), Some(1));

    for (min_nonce, exact_nonce) in [
        (u64::MAX, false),
        (u64::MAX, true),
        (50_000_000, false),
        (50_000_000, true),
        (MAX_NONCE_SKIP + 2, false),
        (MAX_NONCE_SKIP + 2, true),
    ] {
        let request_id = Uuid::new_v4();
        let started = std::time::Instant::now();
        let err = daemon
            .reserve_nonce(nonce_request(
                &credentials,
                request_id,
                min_nonce,
                exact_nonce,
            ))
            .await
            .expect_err("oversized nonce skip must be rejected");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "rejection must be immediate rather than materializing {min_nonce} gaps"
        );
        assert!(
            matches!(
                err,
                DaemonError::NonceSkipTooLarge {
                    requested_skip,
                    max_skip,
                } if requested_skip == min_nonce - 1 && max_skip == MAX_NONCE_SKIP
            ),
            "unexpected error for min_nonce {min_nonce}: {err:?}"
        );

        assert_eq!(
            tracked_nonce_head(&daemon, &credentials),
            Some(1),
            "rejected reservation must not move the nonce head"
        );
        assert_eq!(
            tracked_nonce_gap_count(&daemon, &credentials),
            0,
            "rejected reservation must not materialize reusable gaps"
        );
        assert_eq!(
            daemon
                .nonce_reservations
                .read()
                .expect("reservations")
                .len(),
            1,
            "rejected reservation must not be stored"
        );
        assert!(
            !daemon
                .replay_ids
                .read()
                .expect("replay ids")
                .contains_key(&request_id),
            "rejected reservation must not consume the replay id"
        );
        assert!(
            !daemon
                .recoverable_agent_results
                .read()
                .expect("recoverable results")
                .contains_key(&request_id),
            "rejected reservation must not record a recoverable result"
        );
    }
}

#[tokio::test]
async fn reserve_nonce_on_untracked_chain_seeds_head_at_min_nonce_without_gaps() {
    for exact_nonce in [false, true] {
        let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig::default()).await;
        assert_eq!(tracked_nonce_head(&daemon, &credentials), None);

        let started = std::time::Instant::now();
        let reservation = daemon
            .reserve_nonce(nonce_request(
                &credentials,
                Uuid::new_v4(),
                5_000_000,
                exact_nonce,
            ))
            .await
            .expect("first reservation on an untracked chain uses the live nonce");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(reservation.nonce, 5_000_000);
        assert_eq!(tracked_nonce_head(&daemon, &credentials), Some(5_000_001));
        assert_eq!(
            tracked_nonce_gap_count(&daemon, &credentials),
            0,
            "seeding an untracked head must not materialize gaps (exact={exact_nonce})"
        );

        // Once tracked, the bound applies relative to the head again.
        let err = daemon
            .reserve_nonce(nonce_request(
                &credentials,
                Uuid::new_v4(),
                5_000_001 + MAX_NONCE_SKIP + 1,
                exact_nonce,
            ))
            .await
            .expect_err("skip past a tracked head must fail");
        assert!(matches!(
            err,
            DaemonError::NonceSkipTooLarge {
                requested_skip,
                max_skip,
            } if requested_skip == MAX_NONCE_SKIP + 1 && max_skip == MAX_NONCE_SKIP
        ));
        assert_eq!(tracked_nonce_head(&daemon, &credentials), Some(5_000_001));
    }
}

#[tokio::test]
async fn reserve_nonce_on_untracked_chain_rejects_u64_max_without_state_change() {
    let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig::default()).await;
    for exact_nonce in [false, true] {
        let err = daemon
            .reserve_nonce(nonce_request(
                &credentials,
                Uuid::new_v4(),
                u64::MAX,
                exact_nonce,
            ))
            .await
            .expect_err("u64::MAX can never be followed by another nonce");
        assert!(matches!(err, DaemonError::InvalidNonceReservation(_)));
        assert!(daemon.nonce_heads.read().expect("nonce heads").is_empty());
        assert!(daemon
            .reusable_nonce_gaps
            .read()
            .expect("nonce gaps")
            .is_empty());
    }
}

#[tokio::test]
async fn reserve_nonce_after_head_reclaim_accepts_large_live_nonce() {
    let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig::default()).await;

    let reservation = daemon
        .reserve_nonce(nonce_request(&credentials, Uuid::new_v4(), 0, false))
        .await
        .expect("first reservation");
    assert_eq!(tracked_nonce_head(&daemon, &credentials), Some(1));

    let now = time::OffsetDateTime::now_utc();
    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release");
    assert_eq!(
        tracked_nonce_head(&daemon, &credentials),
        None,
        "releasing the only reservation reclaims and prunes the head"
    );

    let large = daemon
        .reserve_nonce(nonce_request(
            &credentials,
            Uuid::new_v4(),
            5_000_000,
            false,
        ))
        .await
        .expect("large live nonce after head prune must succeed");
    assert_eq!(large.nonce, 5_000_000);
    assert_eq!(tracked_nonce_head(&daemon, &credentials), Some(5_000_001));
    assert_eq!(tracked_nonce_gap_count(&daemon, &credentials), 0);
}

#[tokio::test]
async fn reserve_nonce_allows_skips_up_to_max_nonce_skip_relative_to_head() {
    let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig::default()).await;

    // A fresh head is seeded at the requested nonce without creating gaps.
    let reservation = daemon
        .reserve_nonce(nonce_request(&credentials, Uuid::new_v4(), 10, false))
        .await
        .expect("first reservation seeds the head");
    assert_eq!(reservation.nonce, 10);
    let head = tracked_nonce_head(&daemon, &credentials).expect("head tracked");
    assert_eq!(head, 11);
    assert_eq!(tracked_nonce_gap_count(&daemon, &credentials), 0);

    // A skip of exactly MAX_NONCE_SKIP from a tracked head is permitted.
    let at_limit = daemon
        .reserve_nonce(nonce_request(
            &credentials,
            Uuid::new_v4(),
            head + MAX_NONCE_SKIP,
            false,
        ))
        .await
        .expect("skip at the limit is allowed");
    assert_eq!(at_limit.nonce, head + MAX_NONCE_SKIP);
    assert_eq!(
        tracked_nonce_gap_count(&daemon, &credentials),
        usize::try_from(MAX_NONCE_SKIP).expect("gap count")
    );
    let head = tracked_nonce_head(&daemon, &credentials).expect("head tracked");
    assert_eq!(head, 11 + MAX_NONCE_SKIP + 1);

    // The bound is measured from the tracked head, not from zero.
    let err = daemon
        .reserve_nonce(nonce_request(
            &credentials,
            Uuid::new_v4(),
            head + MAX_NONCE_SKIP + 1,
            true,
        ))
        .await
        .expect_err("skip past the head bound must fail");
    assert!(matches!(
        err,
        DaemonError::NonceSkipTooLarge {
            requested_skip,
            max_skip,
        } if requested_skip == MAX_NONCE_SKIP + 1 && max_skip == MAX_NONCE_SKIP
    ));

    let exact = daemon
        .reserve_nonce(nonce_request(
            &credentials,
            Uuid::new_v4(),
            head + MAX_NONCE_SKIP,
            true,
        ))
        .await
        .expect("exact skip at the limit is allowed");
    assert_eq!(exact.nonce, head + MAX_NONCE_SKIP);

    // Requests at or below the head never count as a skip.
    let low = daemon
        .reserve_nonce(nonce_request(&credentials, Uuid::new_v4(), 0, false))
        .await
        .expect("reusing a gap below the head is allowed");
    assert_eq!(low.nonce, 11);
}
