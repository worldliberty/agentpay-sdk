// Tests for agent-driven resource bounds, retention semantics, and admin
// authentication isolation.

use super::{
    AdminAuthSource, RecoverableAgentRequest, RecoverableAgentResponse, RecoverableAgentResult,
    MAX_NONCE_SKIP,
};

#[derive(Debug, Clone, Default)]
struct ExportCountingSignerBackend {
    inner: SoftwareSignerBackend,
    export_calls: Arc<AtomicUsize>,
}

impl ExportCountingSignerBackend {
    fn export_calls(&self) -> usize {
        self.export_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl VaultSignerBackend for ExportCountingSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        self.inner.backend_kind()
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        self.inner.create_vault_key(request).await
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        self.inner.sign_payload(vault_key_id, payload).await
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        self.inner.sign_digest(vault_key_id, digest).await
    }

    fn export_persistable_key_material(
        &self,
        vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        self.export_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.export_persistable_key_material(vault_key_ids)
    }

    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        self.inner.restore_persistable_key_material(persisted)
    }
}

async fn daemon_with_agent(
    config: DaemonConfig,
) -> (
    InMemoryDaemon<SoftwareSignerBackend>,
    AdminSession,
    AgentCredentials,
) {
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent key");
    (daemon, session, credentials)
}

fn nonce_request(
    credentials: &AgentCredentials,
    request_id: Uuid,
    min_nonce: u64,
    exact_nonce: bool,
) -> NonceReservationRequest {
    let now = time::OffsetDateTime::now_utc();
    NonceReservationRequest {
        request_id,
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce,
        exact_nonce,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    }
}

fn recoverable_release(
    agent_key_id: Uuid,
    recover_until: time::OffsetDateTime,
) -> RecoverableAgentResult {
    RecoverableAgentResult {
        agent_key_id,
        request: RecoverableAgentRequest::ReleaseNonce {
            reservation_id: Uuid::new_v4(),
        },
        recover_until,
        response: RecoverableAgentResponse::Unit,
    }
}

fn spend_event(
    agent_key_id: Uuid,
    amount_wei: u128,
    at: time::OffsetDateTime,
) -> vault_domain::SpendEvent {
    vault_domain::SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei,
        at,
        action_kind: vault_domain::ActionKind::Other,
    }
}

fn tracked_nonce_head(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    credentials: &AgentCredentials,
) -> Option<u64> {
    daemon
        .nonce_heads
        .read()
        .expect("nonce heads")
        .get(&credentials.agent_key.vault_key_id)
        .and_then(|chains| chains.get(&1))
        .copied()
}

fn tracked_nonce_gap_count(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    credentials: &AgentCredentials,
) -> usize {
    daemon
        .reusable_nonce_gaps
        .read()
        .expect("nonce gaps")
        .get(&credentials.agent_key.vault_key_id)
        .and_then(|chains| chains.get(&1))
        .map(|gaps| gaps.len())
        .unwrap_or_default()
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

#[tokio::test]
async fn manual_approval_requests_are_capped_per_agent() {
    let config = DaemonConfig {
        max_pending_manual_approval_requests_per_agent: 2,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
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
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let first_agent = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("first agent key");
    let second_agent = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("second agent key");

    let transfer = |amount_wei: u128| AgentAction::TransferNative {
        chain_id: 1,
        to: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("recipient"),
        amount_wei,
    };

    let mut pending_ids = Vec::new();
    for amount_wei in [1u128, 2] {
        let err = daemon
            .sign_for_agent(sign_request(&first_agent, transfer(amount_wei)))
            .await
            .expect_err("manual approval policy must gate the transfer");
        match err {
            DaemonError::ManualApprovalRequired {
                approval_request_id,
                ..
            } => pending_ids.push(approval_request_id),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    let err = daemon
        .sign_for_agent(sign_request(&first_agent, transfer(3)))
        .await
        .expect_err("third distinct pending request must exceed the per-agent cap");
    assert!(
        matches!(
            err,
            DaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id,
                max_pending: 2,
            } if agent_key_id == first_agent.agent_key.id
        ),
        "unexpected error: {err:?}"
    );
    assert!(err
        .to_string()
        .contains("already has 2 pending manual approval requests"));

    // Retrying an existing pending payload reuses the request instead of counting against the cap.
    let err = daemon
        .sign_for_agent(sign_request(&first_agent, transfer(1)))
        .await
        .expect_err("pending request is still pending");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRequired { approval_request_id, .. }
            if approval_request_id == pending_ids[0]
    ));

    // The cap is per agent key: another agent can still open requests.
    let err = daemon
        .sign_for_agent(sign_request(&second_agent, transfer(3)))
        .await
        .expect_err("second agent still gated by manual approval");
    assert!(matches!(err, DaemonError::ManualApprovalRequired { .. }));

    let pending_for_first = daemon
        .manual_approval_requests
        .read()
        .expect("manual approvals")
        .values()
        .filter(|request| {
            request.agent_key_id == first_agent.agent_key.id
                && request.status == ManualApprovalStatus::Pending
        })
        .count();
    assert_eq!(pending_for_first, 2);

    // Resolving one pending request frees a slot.
    daemon
        .decide_manual_approval_request(
            &session,
            pending_ids[0],
            ManualApprovalDecision::Reject,
            Some("no".to_string()),
        )
        .await
        .expect("reject pending request");
    let err = daemon
        .sign_for_agent(sign_request(&first_agent, transfer(3)))
        .await
        .expect_err("new request is gated by manual approval");
    assert!(matches!(err, DaemonError::ManualApprovalRequired { .. }));
}

#[test]
fn record_recoverable_agent_result_evicts_oldest_entries_beyond_cap() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
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

#[tokio::test]
async fn prune_spend_log_keeps_future_dated_events_and_drops_expired_ones() {
    let (daemon, _session, credentials) = daemon_with_agent(DaemonConfig::default()).await;
    let agent_key_id = credentials.agent_key.id;
    let now = time::OffsetDateTime::now_utc();

    daemon.spend_log.write().expect("spend log").extend([
        spend_event(agent_key_id, 1, now - time::Duration::days(9)),
        spend_event(agent_key_id, 2, now - time::Duration::hours(1)),
        // A backward clock step makes recent spends look future-dated; they
        // must survive pruning so limits cannot be bypassed.
        spend_event(agent_key_id, 3, now + time::Duration::hours(1)),
        spend_event(agent_key_id, 4, now + time::Duration::days(30)),
    ]);

    daemon.prune_spend_log(now).expect("prune");

    let mut retained = daemon
        .spend_log
        .read()
        .expect("spend log")
        .iter()
        .map(|event| event.amount_wei)
        .collect::<Vec<_>>();
    retained.sort_unstable();
    assert_eq!(retained, vec![2, 3, 4]);

    // Startup scrubbing follows the same rule.
    let mut state = PersistedDaemonState::default();
    state.spend_log.extend([
        spend_event(agent_key_id, 1, now - time::Duration::days(9)),
        spend_event(agent_key_id, 2, now - time::Duration::hours(1)),
        spend_event(agent_key_id, 3, now + time::Duration::hours(1)),
    ]);
    InMemoryDaemon::<SoftwareSignerBackend>::scrub_persisted_ephemeral_state(
        &DaemonConfig::default(),
        &mut state,
        now,
    )
    .expect("scrub");
    let mut retained = state
        .spend_log
        .iter()
        .map(|event| event.amount_wei)
        .collect::<Vec<_>>();
    retained.sort_unstable();
    assert_eq!(retained, vec![2, 3]);

    // Policy evaluation uses the same lower-bound-only rule, so future-dated
    // spends keep counting against limits.
    assert!(
        InMemoryDaemon::<SoftwareSignerBackend>::spend_event_is_retained(
            &spend_event(agent_key_id, 3, now + time::Duration::hours(1)),
            now - time::Duration::days(8),
        )
    );
}

#[tokio::test]
async fn future_dated_spends_count_against_window_limits_after_clock_step_back() {
    let (daemon, session, credentials) = daemon_with_agent(DaemonConfig::default()).await;
    let daily = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("daily policy");
    daemon
        .add_policy(&session, daily)
        .await
        .expect("add policy");

    let now = time::OffsetDateTime::now_utc();
    // Spend recorded before the host clock stepped back by an hour.
    daemon
        .spend_log
        .write()
        .expect("spend log")
        .push(spend_event(
            credentials.agent_key.id,
            90,
            now + time::Duration::hours(1),
        ));

    let transfer = |amount_wei: u128| AgentAction::TransferNative {
        chain_id: 1,
        to: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei,
    };

    let explanation = daemon
        .explain_for_agent(sign_request(&credentials, transfer(20)))
        .await
        .expect("explain");
    assert!(
        matches!(
            explanation.decision,
            vault_policy::PolicyDecision::Deny(PolicyError::WindowLimitExceeded {
                used_amount_wei: 90,
                ..
            })
        ),
        "future-dated spend must count against the daily window: {explanation:?}"
    );

    let err = daemon
        .sign_for_agent(sign_request(&credentials, transfer(20)))
        .await
        .expect_err("daily window must include the future-dated spend");
    assert!(
        matches!(
            err,
            DaemonError::Policy(PolicyError::WindowLimitExceeded {
                used_amount_wei: 90,
                requested_amount_wei: 20,
                ..
            })
        ),
        "unexpected error: {err:?}"
    );

    daemon
        .sign_for_agent(sign_request(&credentials, transfer(10)))
        .await
        .expect("spend within the remaining budget succeeds");
}

#[tokio::test]
async fn relay_password_failures_do_not_lock_out_local_admin() {
    let config = DaemonConfig {
        max_failed_admin_auth_attempts: 2,
        admin_auth_lockout: time::Duration::hours(1),
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    for _ in 0..3 {
        let err = daemon
            .apply_relay_manual_approval_decision(
                "wrong-password",
                Uuid::new_v4(),
                ManualApprovalDecision::Approve,
                None,
            )
            .await
            .expect_err("bad relay password must fail");
        assert!(matches!(err, DaemonError::AuthenticationFailed));
    }

    // The relay counter is now locked out, even for the correct password.
    let err = daemon
        .apply_relay_manual_approval_decision(
            "vault-password",
            Uuid::new_v4(),
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect_err("relay lockout applies to relay-sourced decisions");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
    assert!(daemon
        .relay_auth_state
        .read()
        .expect("relay auth state")
        .locked_until
        .is_some());

    // ...but the local administrator is unaffected.
    assert!(daemon
        .admin_auth_state
        .read()
        .expect("admin auth state")
        .locked_until
        .is_none());
    assert_eq!(
        daemon
            .admin_auth_state
            .read()
            .expect("admin auth state")
            .failed_attempts,
        0
    );
    let lease = daemon
        .issue_lease("vault-password")
        .await
        .expect("local admin must not be locked out by relay failures");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .list_policies(&session)
        .await
        .expect("local session works while relay is locked out");
}

#[tokio::test]
async fn local_admin_lockout_does_not_block_relay_decisions() {
    let config = DaemonConfig {
        max_failed_admin_auth_attempts: 2,
        admin_auth_lockout: time::Duration::hours(1),
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    for _ in 0..2 {
        let err = daemon
            .issue_lease("wrong-password")
            .await
            .expect_err("bad local password must fail");
        assert!(matches!(err, DaemonError::AuthenticationFailed));
    }
    let err = daemon
        .issue_lease("vault-password")
        .await
        .expect_err("local admin is locked out");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    // Relay decisions authenticate independently; the unknown id proves the
    // password check passed.
    let approval_request_id = Uuid::new_v4();
    let err = daemon
        .apply_relay_manual_approval_decision(
            "vault-password",
            approval_request_id,
            ManualApprovalDecision::Reject,
            None,
        )
        .await
        .expect_err("unknown approval id");
    assert!(matches!(
        err,
        DaemonError::UnknownManualApprovalRequest(id) if id == approval_request_id
    ));
    assert!(daemon
        .relay_auth_state
        .read()
        .expect("relay auth state")
        .locked_until
        .is_none());

    // Direct source routing sanity check.
    daemon
        .authenticate_password("vault-password", AdminAuthSource::Relay)
        .await
        .expect("relay source is not locked");
    let err = daemon
        .authenticate_password("vault-password", AdminAuthSource::Local)
        .await
        .expect_err("local source remains locked");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn issue_lease_authenticates_before_snapshotting_persistent_state() {
    let state_path = unique_state_path("auth-before-snapshot");
    let backend = ExportCountingSignerBackend::default();
    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        backend.clone(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("persistent daemon");
    let baseline = backend.export_calls();

    let err = daemon
        .issue_lease("wrong-password")
        .await
        .expect_err("bad password must fail");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
    assert_eq!(
        backend.export_calls(),
        baseline,
        "a failed password must never trigger a key-material snapshot"
    );

    daemon
        .issue_lease("vault-password")
        .await
        .expect("correct password issues a lease");
    assert!(
        backend.export_calls() > baseline,
        "successful authentication snapshots and persists state"
    );

    let _ = std::fs::remove_file(&state_path);
}

#[test]
fn validate_config_rejects_persisted_kdf_maxima_below_configured_params() {
    let mut config = DaemonConfig::default();
    config.max_persisted_argon2_memory_kib = config.argon2_memory_kib - 1;
    assert!(matches!(
        validate_config(&config),
        Err(DaemonError::InvalidConfig(message))
            if message.contains("argon2_memory_kib must not exceed max_persisted_argon2_memory_kib")
    ));

    let mut config = DaemonConfig::default();
    config.max_persisted_argon2_memory_kib = config.argon2_memory_kib;
    config.max_persisted_argon2_time_cost = config.argon2_time_cost;
    config.max_persisted_argon2_parallelism = config.argon2_parallelism;
    validate_config(&config).expect("maxima equal to the configured params are valid");
}
