use super::*;

#[test]
fn eip712_with_no_attached_policies_requires_manual_approval_even_with_all_policies() {
    let engine = PolicyEngine;
    let result = engine.evaluate(
        &[],
        &PolicyAttachment::AllPolicies,
        &eip712_action(1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PolicyError::Eip712ManualApprovalRequired {
            policy_id: None,
            ..
        })
    ));
}

#[test]
fn eip712_allow_policy_allows_signing() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("policy");

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &eip712_action(1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(result.is_ok());
}

#[test]
fn eip712_deny_policy_rejects_signing() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new_eip712_signing(1, ApprovalType::Deny, EntityScope::All)
        .expect("policy");

    let result = engine.evaluate(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &eip712_action(1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PolicyError::Eip712SigningDenied { policy_id }) if policy_id == policy.id
    ));
}

#[test]
fn eip712_manual_policy_requires_manual_approval() {
    let engine = PolicyEngine;
    let policy =
        SpendingPolicy::new_eip712_signing(1, ApprovalType::ManualApproval, EntityScope::All)
            .expect("policy");

    let result = engine.evaluate(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &eip712_action(1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PolicyError::Eip712ManualApprovalRequired {
            policy_id: Some(id),
            ..
        }) if id == policy.id
    ));
}

#[test]
fn eip712_manual_approval_does_not_mask_deny_policy() {
    let engine = PolicyEngine;
    let manual_policy =
        SpendingPolicy::new_eip712_signing(0, ApprovalType::ManualApproval, EntityScope::All)
            .expect("policy");
    let deny_policy = SpendingPolicy::new_eip712_signing(1, ApprovalType::Deny, EntityScope::All)
        .expect("policy");

    let explanation = engine.explain(
        &[manual_policy.clone(), deny_policy.clone()],
        &PolicyAttachment::AllPolicies,
        &eip712_action(1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert_eq!(
        explanation.evaluated_policy_ids,
        vec![manual_policy.id, deny_policy.id]
    );
    assert!(matches!(
        explanation.decision,
        PolicyDecision::Deny(PolicyError::Eip712SigningDenied { policy_id })
            if policy_id == deny_policy.id
    ));
}

#[test]
fn eip712_allow_policy_denies_value_bearing_primary_types() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("policy");

    for primary_type in [
        "PermitSingle",
        "PermitBatch",
        "PermitTransferFrom",
        "PermitBatchTransferFrom",
        "Permit",
        "TransferWithAuthorization",
        "ReceiveWithAuthorization",
        "SafeTx",
        // Case variants must not slip through the denylist.
        "permitsingle",
        "SAFETX",
    ] {
        let action = eip712_action_with(
            1,
            primary_type,
            "0x1111111111111111111111111111111111111111",
        );
        let result = engine.evaluate(
            std::slice::from_ref(&policy),
            &PolicyAttachment::AllPolicies,
            &action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(
                &result,
                Err(PolicyError::Eip712ValueBearingTypeDenied {
                    policy_id,
                    primary_type: denied,
                }) if *policy_id == policy.id && denied == primary_type
            ),
            "{primary_type} must be denied under an allow policy, got {result:?}"
        );
    }
}

#[test]
fn permit2_bound_typed_data_is_refused_under_every_policy() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("policy");
    let action = eip712_action_with(1, "Mail", PERMIT2_CHECKSUMMED);

    let result = engine.evaluate(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PolicyError::Permit2TypedDataDenied { ref primary_type }) if primary_type == "Mail"
    ));

    // Neither a manual-approval policy nor the default (no eip712 policy:
    // manual approval) routes it to an operator.
    let manual =
        SpendingPolicy::new_eip712_signing(1, ApprovalType::ManualApproval, EntityScope::All)
            .expect("policy");
    let permit = eip712_action_with(1, "PermitBatch", PERMIT2_CHECKSUMMED);
    for policies in [vec![manual], vec![policy_all_per_tx(100)], Vec::new()] {
        let result = engine.evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &permit,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(
                result,
                Err(PolicyError::Permit2TypedDataDenied { ref primary_type }) if primary_type == "PermitBatch"
            ),
            "{result:?}"
        );
    }
}

#[test]
fn eip712_allow_policy_fails_closed_on_unparseable_typed_data() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("policy");
    let action = AgentAction::Eip712TypedData {
        typed_data: Eip712TypedData {
            typed_data_json: "{ not typed data".to_string(),
        },
    };

    let result = engine.evaluate(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PolicyError::Eip712ValueBearingTypeDenied { policy_id, .. }) if policy_id == policy.id
    ));
}

#[test]
fn eip712_manual_policy_routes_value_bearing_types_to_manual_approval() {
    let engine = PolicyEngine;
    let policy =
        SpendingPolicy::new_eip712_signing(1, ApprovalType::ManualApproval, EntityScope::All)
            .expect("policy");
    let action = eip712_action_with(1, "Permit", "0x1111111111111111111111111111111111111111");

    let result = engine.evaluate(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    // A human reviews it: manual approval is the intended path for value
    // bearing typed data that is not submitted as a typed action.
    assert!(matches!(
        result,
        Err(PolicyError::Eip712ManualApprovalRequired {
            policy_id: Some(policy_id),
            ..
        }) if policy_id == policy.id
    ));
}

#[test]
fn eip712_allow_and_manual_policies_route_value_bearing_types_to_manual_approval() {
    let engine = PolicyEngine;
    // The allow policy has the higher priority, so it is evaluated first.
    let allow = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("allow policy");
    let manual =
        SpendingPolicy::new_eip712_signing(2, ApprovalType::ManualApproval, EntityScope::All)
            .expect("manual policy");
    let policies = [allow.clone(), manual.clone()];

    for action in [
        eip712_action_with(1, "Permit", "0x1111111111111111111111111111111111111111"),
        eip712_action_with(
            1,
            "TransferWithAuthorization",
            "0x1111111111111111111111111111111111111111",
        ),
    ] {
        let explanation = engine.explain(
            &policies,
            &PolicyAttachment::AllPolicies,
            &action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(
                &explanation.decision,
                PolicyDecision::ManualApproval(outcomes) if matches!(
                    outcomes.as_slice(),
                    [PolicyError::Eip712ManualApprovalRequired {
                        policy_id: Some(policy_id),
                        ..
                    }] if *policy_id == manual.id
                )
            ),
            "value-bearing typed data must route to manual approval, got {explanation:?}"
        );
        assert_eq!(explanation.evaluated_policy_ids, vec![allow.id, manual.id]);
    }

    // Non-value-bearing typed data still needs the manual approval because the
    // manual policy applies.
    let benign = eip712_action_with(1, "Mail", "0x1111111111111111111111111111111111111111");
    let result = engine.evaluate(
        &policies,
        &PolicyAttachment::AllPolicies,
        &benign,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        result,
        Err(PolicyError::Eip712ManualApprovalRequired { .. })
    ));

    // An eip712 deny policy still hard-denies value-bearing typed data.
    let deny = SpendingPolicy::new_eip712_signing(3, ApprovalType::Deny, EntityScope::All)
        .expect("deny policy");
    let result = engine.evaluate(
        &[allow.clone(), manual.clone(), deny.clone()],
        &PolicyAttachment::AllPolicies,
        &eip712_action_with(1, "Permit", "0x1111111111111111111111111111111111111111"),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        result,
        Err(PolicyError::Eip712SigningDenied { policy_id }) if policy_id == deny.id
    ));

    // Without a manual policy the allow policy keeps hard-denying.
    let result = engine.evaluate(
        std::slice::from_ref(&allow),
        &PolicyAttachment::AllPolicies,
        &eip712_action_with(1, "Permit", "0x1111111111111111111111111111111111111111"),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        result,
        Err(PolicyError::Eip712ValueBearingTypeDenied { policy_id, .. }) if policy_id == allow.id
    ));
}

#[test]
fn typed_eip3009_action_is_unaffected_by_eip712_value_bearing_denylist() {
    // Typed EIP-3009 authorizations are evaluated by the spending policies,
    // not the eip712 path, so they keep working with amount scoping intact.
    let engine = PolicyEngine;
    let policy = policy_all_per_tx(1_000);
    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: Eip3009Transfer {
            chain_id: 1,
            token: addr("0x3000000000000000000000000000000000000000"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: addr("0x1000000000000000000000000000000000000000"),
            to: addr("0x4000000000000000000000000000000000000000"),
            amount_wei: 500,
            valid_after: 0,
            valid_before: u64::MAX,
            nonce_hex: format!("0x{}", "ab".repeat(32)),
        },
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(result.is_ok());
}
