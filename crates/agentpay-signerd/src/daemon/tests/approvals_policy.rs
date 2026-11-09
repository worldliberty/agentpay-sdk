//! Interaction between manual approvals, policy changes, spend limits, and
//! retention.

use agentpay_domain::{
    AdminAuth, AgentAction, EntityScope, EvmAddress, ManualApprovalDecision, ManualApprovalStatus,
    PolicyAttachment, PolicyType, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{policy_all_per_tx, sample_manual_approval_request, sign_request};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn manual_approval_retention_prunes_only_stale_terminal_entries() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            manual_approval_active_ttl: time::Duration::days(40),
            manual_approval_terminal_retention: time::Duration::days(1),
            ..DaemonConfig::default()
        },
    )
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

    let now = time::OffsetDateTime::now_utc();
    let stale_completed_id = Uuid::new_v4();
    let stale_rejected_id = Uuid::new_v4();
    let recent_completed_id = Uuid::new_v4();
    let old_pending_id = Uuid::new_v4();
    let old_approved_id = Uuid::new_v4();
    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write");

        let mut stale_completed = sample_manual_approval_request();
        stale_completed.id = stale_completed_id;
        stale_completed.agent_key_id = agent_credentials.agent_key.id;
        stale_completed.vault_key_id = key.id;
        stale_completed.created_at = now - time::Duration::days(3);
        stale_completed.updated_at = now - time::Duration::days(2);
        stale_completed.status = ManualApprovalStatus::Completed;
        stale_completed.completed_at = Some(now - time::Duration::days(2));
        requests.insert(stale_completed.id, stale_completed);

        let mut stale_rejected = sample_manual_approval_request();
        stale_rejected.id = stale_rejected_id;
        stale_rejected.agent_key_id = agent_credentials.agent_key.id;
        stale_rejected.vault_key_id = key.id;
        stale_rejected.created_at = now - time::Duration::days(3);
        stale_rejected.updated_at = now - time::Duration::days(2);
        stale_rejected.status = ManualApprovalStatus::Rejected;
        stale_rejected.rejection_reason = Some("too risky".to_string());
        requests.insert(stale_rejected.id, stale_rejected);

        let mut recent_completed = sample_manual_approval_request();
        recent_completed.id = recent_completed_id;
        recent_completed.agent_key_id = agent_credentials.agent_key.id;
        recent_completed.vault_key_id = key.id;
        recent_completed.created_at = now - time::Duration::hours(23);
        recent_completed.updated_at = now - time::Duration::hours(12);
        recent_completed.status = ManualApprovalStatus::Completed;
        recent_completed.completed_at = Some(now - time::Duration::hours(12));
        requests.insert(recent_completed.id, recent_completed);

        let mut old_pending = sample_manual_approval_request();
        old_pending.id = old_pending_id;
        old_pending.agent_key_id = agent_credentials.agent_key.id;
        old_pending.vault_key_id = key.id;
        old_pending.created_at = now - time::Duration::days(30);
        old_pending.updated_at = now - time::Duration::days(30);
        old_pending.status = ManualApprovalStatus::Pending;
        requests.insert(old_pending.id, old_pending);

        let mut old_approved = sample_manual_approval_request();
        old_approved.id = old_approved_id;
        old_approved.agent_key_id = agent_credentials.agent_key.id;
        old_approved.vault_key_id = key.id;
        old_approved.created_at = now - time::Duration::days(30);
        old_approved.updated_at = now - time::Duration::days(30);
        old_approved.status = ManualApprovalStatus::Approved;
        requests.insert(old_approved.id, old_approved);
    }

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x9400000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0xa400000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("sign must prune stale terminal approvals");

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("manual approval read");
    assert!(
        !requests.contains_key(&stale_completed_id),
        "stale completed requests must be pruned"
    );
    assert!(
        !requests.contains_key(&stale_rejected_id),
        "stale rejected requests must be pruned"
    );
    assert!(
        requests.contains_key(&recent_completed_id),
        "recent completed requests must remain within retention"
    );
    assert!(
        requests.contains_key(&old_pending_id),
        "pending requests must not be pruned by terminal retention"
    );
    assert!(
        requests.contains_key(&old_approved_id),
        "approved requests must not be pruned by terminal retention"
    );
}

#[tokio::test]
async fn approved_manual_approval_is_not_reused_after_triggering_policy_changes() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy_a = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy a");
    let manual_policy_a_id = manual_policy_a.id;
    daemon
        .add_policy(&session, manual_policy_a)
        .await
        .expect("add policy a");

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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let first_approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            first_approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve first request");

    daemon
        .disable_policy(&session, manual_policy_a_id)
        .await
        .expect("disable policy a");

    let manual_policy_b = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy b");
    let manual_policy_b_id = manual_policy_b.id;
    daemon
        .add_policy(&session, manual_policy_b)
        .await
        .expect("add policy b");

    let second_approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request, got {other:?}"),
    };
    assert_ne!(second_approval_request_id, first_approval_request_id);

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .clone();
    let first = requests
        .get(&first_approval_request_id)
        .cloned()
        .expect("first request");
    let second = requests
        .get(&second_approval_request_id)
        .cloned()
        .expect("second request");
    assert_eq!(first.status, ManualApprovalStatus::Approved);
    assert_eq!(first.triggered_by_policy_ids, vec![manual_policy_a_id]);
    assert_eq!(second.status, ManualApprovalStatus::Pending);
    assert_eq!(second.triggered_by_policy_ids, vec![manual_policy_b_id]);
}

#[tokio::test]
async fn rejected_manual_approval_is_not_reused_after_triggering_policy_changes() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy_a = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy a");
    let manual_policy_a_id = manual_policy_a.id;
    daemon
        .add_policy(&session, manual_policy_a)
        .await
        .expect("add policy a");

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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let first_approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            first_approval_request_id,
            ManualApprovalDecision::Reject,
            Some("policy a rejected".to_string()),
        )
        .await
        .expect("reject first request");

    daemon
        .disable_policy(&session, manual_policy_a_id)
        .await
        .expect("disable policy a");

    let manual_policy_b = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy b");
    let manual_policy_b_id = manual_policy_b.id;
    daemon
        .add_policy(&session, manual_policy_b)
        .await
        .expect("add policy b");

    let second_approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request, got {other:?}"),
    };
    assert_ne!(second_approval_request_id, first_approval_request_id);

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .clone();
    let first = requests
        .get(&first_approval_request_id)
        .cloned()
        .expect("first request");
    let second = requests
        .get(&second_approval_request_id)
        .cloned()
        .expect("second request");
    assert_eq!(first.status, ManualApprovalStatus::Rejected);
    assert_eq!(first.triggered_by_policy_ids, vec![manual_policy_a_id]);
    assert_eq!(second.status, ManualApprovalStatus::Pending);
    assert_eq!(second.triggered_by_policy_ids, vec![manual_policy_b_id]);
}

#[tokio::test]
async fn add_policy_prioritizes_retained_manual_approval_error_before_duplicate_id_conflict() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            manual_approval_active_ttl: time::Duration::minutes(1),
            ..DaemonConfig::default()
        },
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
        .expect("add manual policy");

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
        token: "0x1800000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2800000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 42,
    };
    let pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    let mut replacement = policy_all_per_tx(1_000_000_000_000_000_000);
    replacement.id = manual_policy.id;
    let err = daemon
        .add_policy(&session, replacement.clone())
        .await
        .expect_err("non-manual replacement must be blocked while approval is retained");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message)
            if message.contains("cannot change away from manual approval")
    ));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read after blocked replacement")
            .contains_key(&pending_id),
        "blocked replacement must not discard retained approval requests"
    );

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write before successful replacement");
        let stale_pending = requests
            .get_mut(&pending_id)
            .expect("pending request to expire");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(2);
        stale_pending.created_at = stale_at;
        stale_pending.updated_at = stale_at;
    }
    assert!(
        daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list approvals after active ttl")
            .is_empty(),
        "expired approvals must disappear from admin listings before replacement"
    );

    let err = daemon
        .add_policy(&session, replacement)
        .await
        .expect_err("duplicate policy id should still be rejected after retained approvals expire");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message) if message.contains("already exists")
    ));
    assert_eq!(
        daemon
            .policies
            .read()
            .expect("policy read after replacement")
            .get(&manual_policy.id)
            .expect("manual policy present")
            .policy_type,
        PolicyType::ManualApproval
    );
    assert!(
        !daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read after duplicate rejection")
            .contains_key(&pending_id),
        "duplicate rejection should still prune stale approvals that referenced the manual policy"
    );
}

#[tokio::test]
async fn completed_manual_approval_spend_counts_toward_later_auto_approved_limits() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                0,
                20,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
        .await
        .expect("add manual policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::DailyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily spend policy"),
        )
        .await
        .expect("add daily policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let token: EvmAddress = "0x1000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0x2000000000000000000000000000000000000000"
        .parse()
        .expect("recipient");

    for amount in [10_u128, 5, 5] {
        daemon
            .sign_for_agent(sign_request(
                &agent_credentials,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: token.clone(),
                    to: recipient.clone(),
                    amount_wei: amount,
                },
            ))
            .await
            .expect("auto-approved spend should sign");
    }

    for amount in [30_u128, 40] {
        let request = sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: recipient.clone(),
                amount_wei: amount,
            },
        );
        let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
            Err(DaemonError::ManualApprovalRequired {
                approval_request_id,
                ..
            }) => approval_request_id,
            other => panic!("expected manual approval request, got {other:?}"),
        };

        daemon
            .decide_manual_approval_request(
                &session,
                approval_request_id,
                ManualApprovalDecision::Approve,
                None,
            )
            .await
            .expect("approve request");

        daemon
            .sign_for_agent(request)
            .await
            .expect("approved request should sign");
    }

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 15,
            },
        ))
        .await
        .expect_err("later auto-approved spend should be denied after manual usage reaches 90");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            max_amount_wei: 100,
            ..
        })
    ));
}

#[tokio::test]
async fn completed_manual_approval_spend_counts_toward_later_weekly_limits() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                0,
                20,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
        .await
        .expect("add manual policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::WeeklyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("weekly spend policy"),
        )
        .await
        .expect("add weekly policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let token: EvmAddress = "0x1000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0x2000000000000000000000000000000000000000"
        .parse()
        .expect("recipient");

    for amount in [10_u128, 5, 5] {
        daemon
            .sign_for_agent(sign_request(
                &agent_credentials,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: token.clone(),
                    to: recipient.clone(),
                    amount_wei: amount,
                },
            ))
            .await
            .expect("auto-approved spend should sign");
    }

    for amount in [30_u128, 40] {
        let request = sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: recipient.clone(),
                amount_wei: amount,
            },
        );
        let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
            Err(DaemonError::ManualApprovalRequired {
                approval_request_id,
                ..
            }) => approval_request_id,
            other => panic!("expected manual approval request, got {other:?}"),
        };

        daemon
            .decide_manual_approval_request(
                &session,
                approval_request_id,
                ManualApprovalDecision::Approve,
                None,
            )
            .await
            .expect("approve request");

        daemon
            .sign_for_agent(request)
            .await
            .expect("approved request should sign");
    }

    {
        let mut spend_log = daemon.spend_log.write().expect("log write");
        for event in spend_log.iter_mut() {
            event.at -= time::Duration::days(2);
        }
    }

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 15,
            },
        ))
        .await
        .expect_err("later auto-approved spend should be denied after manual usage reaches the weekly limit");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            max_amount_wei: 100,
            ..
        })
    ));
}
