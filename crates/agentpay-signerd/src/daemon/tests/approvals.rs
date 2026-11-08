//! Manual approval request lifecycle.

use agentpay_domain::{
    AdminAuth, AgentAction, EntityScope, ManualApprovalDecision, ManualApprovalStatus,
    PolicyAttachment, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};

use super::support::sign_request;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn manual_approval_requests_cannot_be_decided_after_resolution() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
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

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Reject,
            Some("late rejection".to_string()),
        )
        .await
        .expect_err("resolved request must reject a second decision");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRequestNotPending {
            approval_request_id: id,
            status: ManualApprovalStatus::Approved,
        } if id == approval_request_id
    ));

    daemon
        .sign_for_agent(request)
        .await
        .expect("approved request should sign");

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Reject,
            Some("too late".to_string()),
        )
        .await
        .expect_err("completed request must reject later decisions");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRequestNotPending {
            approval_request_id: id,
            status: ManualApprovalStatus::Completed,
        } if id == approval_request_id
    ));
}

#[tokio::test]
async fn manual_approval_policy_hard_denies_amounts_above_maximum() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        10,
        100,
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

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 101,
            },
        ))
        .await
        .expect_err("amounts above manual approval max must be denied");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::AmountExceeded {
            policy_id,
            max_amount_wei: 100,
            requested_amount_wei: 101,
        }) if policy_id == manual_policy.id
    ));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .is_empty(),
        "hard-denied requests must not create manual approval entries"
    );
}

#[tokio::test]
async fn rejected_manual_approval_requests_block_new_matching_requests_while_retained() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
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
            amount_wei: 42,
        },
    );

    let rejected_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            rejected_id,
            ManualApprovalDecision::Reject,
            Some("not approved".to_string()),
        )
        .await
        .expect("reject request");

    let err = daemon
        .sign_for_agent(request.clone())
        .await
        .expect_err("retained rejected approval must block identical payloads");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRejected {
            approval_request_id
        } if approval_request_id == rejected_id
    ));

    {
        let requests = daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read");
        assert_eq!(
            requests
                .get(&rejected_id)
                .expect("rejected request should remain during retention")
                .status,
            ManualApprovalStatus::Rejected
        );
        assert_eq!(requests.len(), 1);
    }

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write");
        let rejected = requests
            .get_mut(&rejected_id)
            .expect("rejected request to age out");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::days(9);
        rejected.created_at = stale_at;
        rejected.updated_at = stale_at;
    }

    let replacement_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request after retention, got {other:?}"),
    };
    assert_ne!(replacement_id, rejected_id);
}

#[tokio::test]
async fn manual_approval_requests_expire_before_reuse() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            manual_approval_active_ttl: time::Duration::minutes(1),
            ..DaemonConfig::default()
        },
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
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

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1700000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2700000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 42,
    };

    let stale_pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write after first pending");
        let stale_pending = requests
            .get_mut(&stale_pending_id)
            .expect("stale pending request");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(2);
        stale_pending.created_at = stale_at;
        stale_pending.updated_at = stale_at;
    }
    assert!(
        daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list stale pending approvals")
            .is_empty(),
        "stale pending approvals must not be listed"
    );

    let fresh_pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request, got {other:?}"),
    };
    assert_ne!(
        fresh_pending_id, stale_pending_id,
        "expired pending approvals must not be reused"
    );
    assert!(
        !daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read after pending expiry")
            .contains_key(&stale_pending_id),
        "creating a fresh approval should prune the stale pending request"
    );

    daemon
        .decide_manual_approval_request(
            &session,
            fresh_pending_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve fresh request");

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write after approval");
        let stale_approved = requests
            .get_mut(&fresh_pending_id)
            .expect("stale approved request");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(2);
        stale_approved.created_at = stale_at;
        stale_approved.updated_at = stale_at;
    }
    assert!(
        daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list stale approved approvals")
            .is_empty(),
        "stale approved approvals must not be listed"
    );

    let replacement_pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected replacement manual approval request, got {other:?}"),
    };
    assert_ne!(
        replacement_pending_id, fresh_pending_id,
        "expired approved approvals must not be reused"
    );

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("manual approval read");
    assert!(
        !requests.contains_key(&fresh_pending_id),
        "creating a replacement approval should prune the stale approved request"
    );
    assert_eq!(
        requests
            .get(&replacement_pending_id)
            .expect("replacement pending request")
            .status,
        ManualApprovalStatus::Pending
    );
}

#[tokio::test]
async fn approving_manual_approval_request_requires_triggering_policy_to_remain_enabled() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let manual_policy_id = manual_policy.id;
    daemon
        .add_policy(&session, manual_policy)
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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .disable_policy(&session, manual_policy_id)
        .await
        .expect("disable policy");

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect_err("approval must fail when triggering policy is disabled");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message)
            if message.contains("references disabled policy")
                && message.contains(&manual_policy_id.to_string())
    ));

    let request = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .get(&approval_request_id)
        .cloned()
        .expect("request");
    assert_eq!(request.status, ManualApprovalStatus::Pending);
    assert!(request.rejection_reason.is_none());
}

#[tokio::test]
async fn approving_manual_approval_request_requires_triggering_policy_to_still_exist() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
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
    let manual_policy_id = manual_policy.id;
    daemon
        .add_policy(&session, manual_policy)
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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .policies
        .write()
        .expect("policies")
        .remove(&manual_policy_id);

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect_err("approval must fail when triggering policy is missing");
    assert!(matches!(err, DaemonError::UnknownPolicy(id) if id == manual_policy_id));

    let request = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .get(&approval_request_id)
        .cloned()
        .expect("request");
    assert_eq!(request.status, ManualApprovalStatus::Pending);
    assert!(request.rejection_reason.is_none());
}

#[tokio::test]
async fn manual_approval_requests_are_capped_per_agent() {
    let config = DaemonConfig {
        max_pending_manual_approval_requests_per_agent: 2,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), config).expect("daemon");
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
