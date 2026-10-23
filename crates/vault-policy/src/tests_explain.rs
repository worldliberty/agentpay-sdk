use std::str::FromStr;

use time::OffsetDateTime;
use uuid::Uuid;
use vault_domain::{
    AgentAction, EntityScope, EvmAddress, PolicyAttachment, PolicyType, SpendingPolicy,
};

use crate::{PolicyDecision, PolicyEngine, PolicyError};

fn addr(x: &str) -> EvmAddress {
    EvmAddress::from_str(x).expect("valid test address")
}

fn policy_all_per_tx(max: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        max,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

#[test]
fn explain_reports_denial_reason_and_evaluated_policy() {
    let engine = PolicyEngine::default();
    let policy = policy_all_per_tx(10);
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: addr("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        to: addr("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        amount_wei: 11,
    };

    let explanation = engine.explain(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert_eq!(explanation.attached_policy_ids, vec![policy.id]);
    assert_eq!(explanation.applicable_policy_ids, vec![policy.id]);
    assert_eq!(explanation.evaluated_policy_ids, vec![policy.id]);
    assert!(matches!(
        explanation.decision,
        PolicyDecision::Deny(PolicyError::PerTxLimitExceeded { .. })
    ));
}

#[test]
fn explain_reports_allow_for_valid_request() {
    let engine = PolicyEngine::default();
    let policy = policy_all_per_tx(10);
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: addr("0xcccccccccccccccccccccccccccccccccccccccc"),
        to: addr("0xdddddddddddddddddddddddddddddddddddddddd"),
        amount_wei: 10,
    };

    let explanation = engine.explain(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert_eq!(explanation.evaluated_policy_ids, vec![policy.id]);
    assert!(matches!(explanation.decision, PolicyDecision::Allow));
}
