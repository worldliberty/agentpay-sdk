//! Spend accounting and windowed spending limits.

use std::sync::Arc;

use agentpay_domain::{
    AdminAuth, AgentAction, AssetId, EntityScope, EvmAddress, KeySource, PolicyAttachment,
    PolicyType, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};

use super::support::{daemon_with_agent, policy_all_per_tx, sign_request, spend_event};
use crate::persistence::PersistedDaemonState;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn daemon_enforces_per_tx_limit() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(100))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    assert!(matches!(key.source, KeySource::Generated));

    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let token = "0x1000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x2000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 101,
        },
    );

    let result = daemon.sign_for_agent(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn client_requested_at_cannot_bypass_window_limits() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let policy = SpendingPolicy::new(
        0,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    daemon
        .add_policy(&session, policy)
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

    let token = "0x3000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x4000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let mut first = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 60,
        },
    );
    // Intentionally stale; daemon must not trust this for spend accounting.
    first.requested_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(30);
    daemon.sign_for_agent(first).await.expect("first sign");

    let mut second = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 60,
        },
    );
    second.requested_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(30);
    let err = daemon
        .sign_for_agent(second)
        .await
        .expect_err("daily limit must reject second request");

    assert!(matches!(err, DaemonError::Policy(_)));
}

#[tokio::test]
async fn spend_log_retention_prunes_out_of_window_entries() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let old_token = "0x9200000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let old_recipient = "0xa200000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    let future_token = "0x9400000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let future_recipient = "0xa400000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    daemon.spend_log.write().expect("log write").extend([
        agentpay_domain::SpendEvent {
            agent_key_id: agent_credentials.agent_key.id,
            chain_id: 1,
            asset: AssetId::Erc20(old_token.clone()),
            recipient: old_recipient.into(),
            amount_wei: 1,
            at: time::OffsetDateTime::now_utc() - time::Duration::days(30),
            approval_request_id: None,
        },
        agentpay_domain::SpendEvent {
            agent_key_id: agent_credentials.agent_key.id,
            chain_id: 1,
            asset: AssetId::Erc20(future_token.clone()),
            recipient: future_recipient.into(),
            amount_wei: 1,
            at: time::OffsetDateTime::now_utc() + time::Duration::days(30),
            approval_request_id: None,
        },
    ]);

    let token = "0x9300000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa300000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 1,
            },
        ))
        .await
        .expect("sign must pass");

    let log = daemon.spend_log.read().expect("log read");
    let now = time::OffsetDateTime::now_utc();
    assert_eq!(
        log.len(),
        2,
        "the expired event must be pruned; the newly signed and future-dated events remain"
    );
    assert!(
        log.iter()
            .all(|event| event.at >= now - time::Duration::days(8)),
        "no retained event may be older than the retention window"
    );
    assert!(
        log.iter()
            .any(|event| event.asset == AssetId::Erc20(future_token.clone())),
        "future-dated spends must survive pruning so a backward clock step cannot erase them"
    );
    assert!(
        !log.iter()
            .any(|event| event.asset == AssetId::Erc20(old_token.clone())),
        "spends older than the retention window must be pruned"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_sign_requests_do_not_race_policy_windows() {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );

    let session = AdminAuth::PeerCredentials;

    let policy = SpendingPolicy::new(
        0,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    daemon
        .add_policy(&session, policy)
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

    let token = "0x5000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x6000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let req1 = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 60,
        },
    );
    let req2 = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 60,
        },
    );

    let daemon_a = daemon.clone();
    let daemon_b = daemon.clone();
    let (res1, res2) = tokio::join!(daemon_a.sign_for_agent(req1), daemon_b.sign_for_agent(req2));

    let success_count = usize::from(res1.is_ok()) + usize::from(res2.is_ok());
    let failure_count = usize::from(res1.is_err()) + usize::from(res2.is_err());
    assert_eq!(success_count, 1, "exactly one request must pass");
    assert_eq!(failure_count, 1, "exactly one request must fail");
}

#[tokio::test]
async fn evaluate_for_agent_has_no_spend_side_effects() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("add spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::DailyMaxTxCount,
                1,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily tx count policy"),
        )
        .await
        .expect("add tx-count policy");

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
        token: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x6000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };
    let request = sign_request(&agent_credentials, action.clone());

    let first = daemon
        .evaluate_for_agent(request.clone())
        .await
        .expect("first evaluation should pass");
    assert_eq!(first.evaluated_policy_ids.len(), 2);
    assert_eq!(daemon.spend_log.read().expect("log read").len(), 0);

    let second = daemon
        .evaluate_for_agent(request.clone())
        .await
        .expect("second evaluation should also pass (no spend side effects)");
    assert_eq!(first.evaluated_policy_ids, second.evaluated_policy_ids);
    assert_eq!(daemon.spend_log.read().expect("log read").len(), 0);

    daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("sign should pass once");
    let err = daemon
        .evaluate_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("tx-count policy should deny after signed spend is recorded");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::TxCountLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn daily_spend_limit_counts_in_scope_history_across_assets_and_chains() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
            .expect("daily spend policy"),
        )
        .await
        .expect("add daily spend policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x5100000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x6100000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 70,
            },
        ))
        .await
        .expect("first spend should pass");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::TransferNative {
                chain_id: 10,
                to: "0x6200000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 20,
            },
        ))
        .await
        .expect("second spend should pass");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 137,
                token: "0x5200000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x6200000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 15,
            },
        ))
        .await
        .expect_err("daily limit should deny after aggregate usage reaches 90");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            ..
        })
    ));
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
            agentpay_policy::PolicyDecision::Deny(PolicyError::WindowLimitExceeded {
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
