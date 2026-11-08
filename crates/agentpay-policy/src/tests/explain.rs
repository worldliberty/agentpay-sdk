use super::*;

#[test]
fn explain_reports_denial_reason_and_evaluated_policy() {
    let engine = PolicyEngine;
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
    let engine = PolicyEngine;
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

#[test]
fn explain_reports_no_attached_policies_when_attachment_filters_everything() {
    let engine = PolicyEngine;
    let policy = policy_all_per_tx(100);
    let attachment =
        PolicyAttachment::policy_set(BTreeSet::from([Uuid::new_v4()])).expect("attachment");
    let action = AgentAction::TransferNative {
        chain_id: 1,
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 1,
    };

    let explanation = engine.explain(
        &[policy],
        &attachment,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        explanation.decision,
        super::PolicyDecision::Deny(PolicyError::NoAttachedPolicies)
    ));
    assert!(explanation.applicable_policy_ids.is_empty());
    assert!(explanation.evaluated_policy_ids.is_empty());
}

#[test]
fn explain_denies_agents_when_no_policies_exist_even_with_all_policies() {
    let engine = PolicyEngine;
    let action = AgentAction::TransferNative {
        chain_id: 1,
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 1,
    };

    let explanation = engine.explain(
        &[],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        explanation.decision,
        super::PolicyDecision::Deny(PolicyError::NoAttachedPolicies)
    ));
    assert!(explanation.attached_policy_ids.is_empty());
    assert!(explanation.applicable_policy_ids.is_empty());
    assert!(explanation.evaluated_policy_ids.is_empty());

    // Disabled policies do not count as attached either.
    let mut disabled = policy_all_per_tx(1_000);
    disabled.enabled = false;
    let result = engine.evaluate(
        &[disabled],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(result, Err(PolicyError::NoAttachedPolicies)));
}
