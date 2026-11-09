use super::*;

#[test]
fn weekly_limit_and_manual_approval_paths_are_enforced() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let token = addr("0x3000000000000000000000000000000000000000");
    let recipient = addr("0x4000000000000000000000000000000000000000");

    let weekly_policy = SpendingPolicy::new(
        0,
        PolicyType::WeeklyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let weekly_history = vec![SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::Erc20(token.clone()),
        recipient: recipient.clone().into(),
        amount_wei: 80,
        at: now - Duration::days(2),
        approval_request_id: None,
    }];
    let weekly_action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 30,
    };
    assert!(matches!(
        engine.evaluate(
            &[weekly_policy],
            &PolicyAttachment::AllPolicies,
            &weekly_action,
            &weekly_history,
            agent_key_id,
            now
        ),
        Err(PolicyError::WindowLimitExceeded { .. })
    ));

    let manual_policy = SpendingPolicy::new_manual_approval(
        0,
        10,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let in_range = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 50,
    };
    assert!(matches!(
        engine.evaluate(
            std::slice::from_ref(&manual_policy),
            &PolicyAttachment::AllPolicies,
            &in_range,
            &[],
            agent_key_id,
            now
        ),
        Err(PolicyError::ManualApprovalRequired { .. })
    ));

    let below_range = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 5,
    };
    assert!(engine
        .evaluate(
            &[manual_policy],
            &PolicyAttachment::AllPolicies,
            &below_range,
            &[],
            agent_key_id,
            now
        )
        .is_ok());
}

#[test]
fn manual_approval_without_minimum_defaults_to_zero_and_reports_effective_threshold() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let recipient = addr("0x4000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new_with_range(
        0,
        PolicyType::ManualApproval,
        None,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");

    let zero_wei_action = AgentAction::TransferNative {
        chain_id: 1,
        to: recipient,
        amount_wei: 0,
    };

    assert_eq!(
        engine.evaluate(
            std::slice::from_ref(&policy),
            &PolicyAttachment::AllPolicies,
            &zero_wei_action,
            &[],
            agent_key_id,
            now
        ),
        Err(PolicyError::ManualApprovalRequired {
            policy_id: policy.id,
            min_amount_wei: Some(0),
            max_amount_wei: 100,
            requested_amount_wei: 0,
        })
    );
}

#[test]
fn manual_approval_above_max_is_hard_denied() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let recipient = addr("0x4000000000000000000000000000000000000000");
    let token = addr("0x5000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new_manual_approval(
        0,
        10,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");

    let above_max = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 101,
    };

    assert_eq!(
        engine.evaluate(
            std::slice::from_ref(&policy),
            &PolicyAttachment::AllPolicies,
            &above_max,
            &[],
            agent_key_id,
            now
        ),
        Err(PolicyError::AmountExceeded {
            policy_id: policy.id,
            max_amount_wei: 100,
            requested_amount_wei: 101,
        })
    );
}

#[test]
fn manual_approval_does_not_mask_daily_cap() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let token = addr("0x3000000000000000000000000000000000000000");
    let recipient = addr("0x4000000000000000000000000000000000000000");

    // Manual approval sorts first (priority 0): a first-error short-circuit
    // would have surfaced ManualApprovalRequired and hidden the daily cap.
    let manual_policy = SpendingPolicy::new_manual_approval(
        0,
        10,
        10_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let daily_policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 5_000,
    };

    let explanation = engine.explain(
        &[manual_policy.clone(), daily_policy.clone()],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        agent_key_id,
        now,
    );
    assert_eq!(
        explanation.evaluated_policy_ids,
        vec![manual_policy.id, daily_policy.id],
        "soft manual approval must not stop evaluation"
    );
    assert!(matches!(
        explanation.decision,
        PolicyDecision::Deny(PolicyError::WindowLimitExceeded {
            policy_id,
            used_amount_wei: 0,
            requested_amount_wei: 5_000,
            max_amount_wei: 100,
        }) if policy_id == daily_policy.id
    ));

    let result = engine.evaluate(
        &[manual_policy.clone(), daily_policy.clone()],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        agent_key_id,
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::WindowLimitExceeded { policy_id, .. }) if policy_id == daily_policy.id
    ));

    // Reversed priority order reaches the same hard denial.
    let mut daily_first = daily_policy;
    daily_first.priority = 0;
    let mut manual_last = manual_policy;
    manual_last.priority = 1;
    let result = engine.evaluate(
        &[manual_last, daily_first.clone()],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        agent_key_id,
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::WindowLimitExceeded { policy_id, .. }) if policy_id == daily_first.id
    ));
}

#[test]
fn manual_approval_does_not_mask_other_hard_limits() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let token = addr("0x3000000000000000000000000000000000000000");
    let recipient = addr("0x4000000000000000000000000000000000000000");
    let manual_policy = SpendingPolicy::new_manual_approval(
        0,
        10,
        10_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 5_000,
    };
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::Erc20(token),
        recipient: recipient.into(),
        amount_wei: 1,
        at: now - Duration::hours(1),
        approval_request_id: None,
    }];

    let per_tx = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    assert!(matches!(
        engine.evaluate(
            &[manual_policy.clone(), per_tx],
            &PolicyAttachment::AllPolicies,
            &action,
            &history,
            agent_key_id,
            now,
        ),
        Err(PolicyError::PerTxLimitExceeded { .. })
    ));

    let weekly = SpendingPolicy::new(
        1,
        PolicyType::WeeklyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    assert!(matches!(
        engine.evaluate(
            &[manual_policy.clone(), weekly],
            &PolicyAttachment::AllPolicies,
            &action,
            &history,
            agent_key_id,
            now,
        ),
        Err(PolicyError::WindowLimitExceeded { .. })
    ));

    let tx_count = SpendingPolicy::new_tx_count_limit(
        1,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    assert!(matches!(
        engine.evaluate(
            &[manual_policy, tx_count],
            &PolicyAttachment::AllPolicies,
            &action,
            &history,
            agent_key_id,
            now,
        ),
        Err(PolicyError::TxCountLimitExceeded { .. })
    ));
}

#[test]
fn manual_approval_is_returned_once_all_hard_limits_pass() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let manual_policy = SpendingPolicy::new_manual_approval(
        0,
        10,
        10_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let daily_policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        10_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut per_tx_policy = policy_all_per_tx(10_000);
    per_tx_policy.priority = 2;
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: addr("0x3000000000000000000000000000000000000000"),
        to: addr("0x4000000000000000000000000000000000000000"),
        amount_wei: 5_000,
    };

    let explanation = engine.explain(
        &[
            manual_policy.clone(),
            daily_policy.clone(),
            per_tx_policy.clone(),
        ],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        agent_key_id,
        now,
    );
    assert_eq!(
        explanation.evaluated_policy_ids,
        vec![manual_policy.id, daily_policy.id, per_tx_policy.id]
    );
    assert_eq!(
        explanation.decision,
        PolicyDecision::ManualApproval(vec![PolicyError::ManualApprovalRequired {
            policy_id: manual_policy.id,
            min_amount_wei: Some(10),
            max_amount_wei: 10_000,
            requested_amount_wei: 5_000,
        }])
    );
}

#[test]
fn policy_error_classifies_manual_approval_outcomes_as_soft() {
    let policy_id = Uuid::new_v4();
    assert!(PolicyError::ManualApprovalRequired {
        policy_id,
        min_amount_wei: None,
        max_amount_wei: 1,
        requested_amount_wei: 1,
    }
    .is_manual_approval_required());
    assert!(PolicyError::Eip712ManualApprovalRequired {
        policy_id: None,
        policy_suffix: String::new(),
    }
    .is_manual_approval_required());
    assert!(!PolicyError::NoAttachedPolicies.is_manual_approval_required());
    assert!(!PolicyError::AmountExceeded {
        policy_id,
        max_amount_wei: 1,
        requested_amount_wei: 2,
    }
    .is_manual_approval_required());
    assert!(!PolicyError::Eip712SigningDenied { policy_id }.is_manual_approval_required());
}
