//! `over_limit: manual_approval`: going beyond a per-payment, daily, weekly,
//! or daily-count limit holds the request for approval instead of denying it.

use agentpay_domain::{ApprovalLimit, ApprovalReason, OverLimit, RecipientId};

use super::*;

const TOKEN: &str = "0x3000000000000000000000000000000000000000";
const RECIPIENT: &str = "0x4000000000000000000000000000000000000000";

fn transfer(amount_wei: u128) -> AgentAction {
    AgentAction::Transfer {
        chain_id: 1,
        token: addr(TOKEN),
        to: addr(RECIPIENT),
        amount_wei,
    }
}

/// A policy of `policy_type` with `limit` that asks for approval beyond it.
fn soft(priority: u32, policy_type: PolicyType, limit: u128) -> SpendingPolicy {
    let mut policy = SpendingPolicy::new(
        priority,
        policy_type,
        limit,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
    .with_over_limit(OverLimit::ManualApproval)
    .expect("limit type");
    policy.priority = priority;
    policy
}

fn spent(agent_key_id: Uuid, amount_wei: u128, at: OffsetDateTime) -> SpendEvent {
    SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::Erc20(addr(TOKEN)),
        recipient: RecipientId::Evm(addr(RECIPIENT)),
        amount_wei,
        at,
        approval_request_id: None,
    }
}

fn decide(
    policies: &[SpendingPolicy],
    action: &AgentAction,
    history: &[SpendEvent],
    agent_key_id: Uuid,
    now: OffsetDateTime,
) -> PolicyDecision {
    PolicyEngine
        .explain(
            policies,
            &PolicyAttachment::AllPolicies,
            action,
            history,
            agent_key_id,
            now,
        )
        .decision
}

fn approval(
    policy: &SpendingPolicy,
    limit: ApprovalLimit,
    max: u128,
    used: u128,
    requested_amount_wei: u128,
) -> PolicyError {
    PolicyError::LimitApprovalRequired {
        policy_id: policy.id,
        limit,
        max,
        used,
        requested_amount_wei,
    }
}

#[test]
fn each_limit_kind_beyond_its_limit_asks_for_approval() {
    let agent = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let per_tx = soft(1, PolicyType::PerTxMaxSpending, 100);
    assert_eq!(
        decide(
            std::slice::from_ref(&per_tx),
            &transfer(150),
            &[],
            agent,
            now
        ),
        PolicyDecision::ManualApproval(vec![approval(
            &per_tx,
            ApprovalLimit::PerPayment,
            100,
            0,
            150
        )])
    );
    assert_eq!(
        decide(&[per_tx], &transfer(100), &[], agent, now),
        PolicyDecision::Allow,
        "at the limit the agent pays on its own"
    );

    let history = [
        spent(agent, 400, now - Duration::hours(2)),
        spent(agent, 300, now - Duration::days(3)),
    ];
    let daily = soft(1, PolicyType::DailyMaxSpending, 500);
    assert_eq!(
        decide(
            std::slice::from_ref(&daily),
            &transfer(150),
            &history,
            agent,
            now
        ),
        PolicyDecision::ManualApproval(vec![approval(&daily, ApprovalLimit::Daily, 500, 400, 150)])
    );
    let weekly = soft(1, PolicyType::WeeklyMaxSpending, 800);
    assert_eq!(
        decide(
            std::slice::from_ref(&weekly),
            &transfer(150),
            &history,
            agent,
            now
        ),
        PolicyDecision::ManualApproval(vec![approval(
            &weekly,
            ApprovalLimit::Weekly,
            800,
            700,
            150
        )])
    );
    let count = soft(1, PolicyType::DailyMaxTxCount, 1);
    assert_eq!(
        decide(
            std::slice::from_ref(&count),
            &transfer(5),
            &history,
            agent,
            now
        ),
        PolicyDecision::ManualApproval(vec![approval(&count, ApprovalLimit::DailyCount, 1, 1, 5)])
    );
}

#[test]
fn every_limit_a_payment_goes_beyond_is_reported_together() {
    let agent = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let per_tx = soft(1, PolicyType::PerTxMaxSpending, 100);
    let daily = soft(2, PolicyType::DailyMaxSpending, 500);
    let weekly = soft(3, PolicyType::WeeklyMaxSpending, 10_000);
    let history = [spent(agent, 450, now - Duration::hours(1))];
    let decision = decide(
        &[per_tx.clone(), daily.clone(), weekly],
        &transfer(200),
        &history,
        agent,
        now,
    );
    assert_eq!(
        decision,
        PolicyDecision::ManualApproval(vec![
            approval(&per_tx, ApprovalLimit::PerPayment, 100, 0, 200),
            approval(&daily, ApprovalLimit::Daily, 500, 450, 200),
        ])
    );
    // `evaluate` reports the first of them.
    let first = PolicyEngine
        .evaluate(
            &[per_tx.clone(), daily],
            &PolicyAttachment::AllPolicies,
            &transfer(200),
            &history,
            agent,
            now,
        )
        .expect_err("needs approval");
    assert_eq!(
        first,
        approval(&per_tx, ApprovalLimit::PerPayment, 100, 0, 200)
    );
}

#[test]
fn hard_limits_still_deny_and_deny_policies_are_unchanged() {
    let agent = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    // A gas cap denies even when an amount limit would only ask.
    let tx = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: addr(RECIPIENT),
            value_wei: 500,
            data_hex: "0x".into(),
            gas_limit: 21_000,
            max_fee_per_gas_wei: 1_000,
            max_priority_fee_per_gas_wei: 1,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    let decision = decide(
        &[
            soft(1, PolicyType::PerTxMaxSpending, 100),
            gas_policy(1, 1_000),
        ],
        &tx,
        &[],
        agent,
        now,
    );
    assert!(
        matches!(
            decision,
            PolicyDecision::Deny(PolicyError::GasLimitExceeded { .. })
        ),
        "{decision:?}"
    );

    // `over_limit: deny` (the default) keeps the hard denial.
    let hard = policy_all_per_tx(100);
    assert_eq!(hard.over_limit, OverLimit::Deny);
    assert!(matches!(
        decide(&[hard], &transfer(150), &[], agent, now),
        PolicyDecision::Deny(PolicyError::PerTxLimitExceeded { .. })
    ));
}

#[test]
fn only_limit_types_accept_over_limit_approval() {
    let error = gas_policy(1, 1_000)
        .with_over_limit(OverLimit::ManualApproval)
        .expect_err("gas caps stay hard");
    assert!(matches!(
        error,
        agentpay_domain::DomainError::OverLimitApprovalUnsupported
    ));
    for policy_type in [
        PolicyType::PerTxMaxSpending,
        PolicyType::DailyMaxSpending,
        PolicyType::WeeklyMaxSpending,
        PolicyType::DailyMaxTxCount,
    ] {
        assert!(SpendingPolicy::supports_over_limit_approval(policy_type));
    }
}

#[test]
fn limit_approvals_carry_an_operator_reason() {
    let policy_id = Uuid::new_v4();
    let per_payment = PolicyError::LimitApprovalRequired {
        policy_id,
        limit: ApprovalLimit::PerPayment,
        max: 100,
        used: 0,
        requested_amount_wei: 150,
    };
    assert!(per_payment.is_manual_approval_required());
    assert_eq!(per_payment.approval_policy_id(), Some(policy_id));
    assert_eq!(
        per_payment.approval_reason(),
        Some(ApprovalReason {
            limit: ApprovalLimit::PerPayment,
            policy_id: Some(policy_id),
            max: Some(100),
            used: None,
            requested_amount_wei: Some(150),
        })
    );
    let daily = PolicyError::LimitApprovalRequired {
        policy_id,
        limit: ApprovalLimit::Daily,
        max: 500,
        used: 450,
        requested_amount_wei: 100,
    };
    assert_eq!(daily.approval_reason().and_then(|r| r.used), Some(450));
    assert_eq!(PolicyError::NoApplicablePolicies.approval_reason(), None);
}
