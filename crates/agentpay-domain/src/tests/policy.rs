use super::*;

#[test]
fn all_scope_allows_any_value() {
    let addr = "0x2222222222222222222222222222222222222222"
        .parse::<EvmAddress>()
        .expect("must parse");
    let scope: EntityScope<EvmAddress> = EntityScope::All;

    assert!(scope.allows(&addr));
}

#[test]
fn policy_set_cannot_be_empty() {
    let empty = BTreeSet::new();
    let result = PolicyAttachment::policy_set(empty);
    assert!(matches!(result, Err(DomainError::EmptyPolicySet)));
}

#[test]
fn policy_attachment_applies_to_all_and_selected_ids() {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let attachment = PolicyAttachment::policy_set(BTreeSet::from([first])).expect("policy set");

    assert!(PolicyAttachment::AllPolicies.applies_to(first));
    assert!(attachment.applies_to(first));
    assert!(!attachment.applies_to(second));
}

#[test]
fn spending_policy_rejects_invalid_ranges_and_network_sets() {
    let recipient: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("recipient");
    let asset = AssetId::Erc20(
        "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("token"),
    );

    let err = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        0,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect_err("zero max amount");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new_manual_approval(
        1,
        0,
        10,
        EntityScope::Set(BTreeSet::from([recipient.clone()])),
        EntityScope::Set(BTreeSet::from([asset.clone()])),
        EntityScope::Set(BTreeSet::from([1])),
    )
    .expect_err("zero min amount");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new_manual_approval(
        1,
        11,
        10,
        EntityScope::Set(BTreeSet::from([recipient.clone()])),
        EntityScope::Set(BTreeSet::from([asset.clone()])),
        EntityScope::Set(BTreeSet::from([1])),
    )
    .expect_err("min greater than max");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::Set(BTreeSet::from([recipient])),
        EntityScope::Set(BTreeSet::from([asset])),
        EntityScope::Set(BTreeSet::from([0])),
    )
    .expect_err("zero chain id");
    assert!(matches!(err, DomainError::InvalidChainId));

    let err = SpendingPolicy::new_calldata_limit(
        1,
        0,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect_err("zero calldata bytes");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new_with_range(
        1,
        PolicyType::PerTxMaxCalldataBytes,
        Some(1),
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect_err("calldata policies must not accept amount ranges");
    assert!(matches!(err, DomainError::InvalidAmount));
}

#[test]
fn specialized_policies_use_dedicated_limits_and_support_legacy_deserialization() {
    fn assert_specialized_limit_round_trip(
        policy: SpendingPolicy,
        dedicated_field: &str,
        expected_limit: u128,
        legacy_limit: u128,
        accessor: fn(&SpendingPolicy) -> Option<u128>,
    ) {
        assert_eq!(policy.max_amount_wei, 0);
        assert_eq!(accessor(&policy), Some(expected_limit));

        let dedicated_json = serde_json::to_value(&policy).expect("serialize policy");
        let serde_json::Value::Object(mut dedicated_fields) = dedicated_json else {
            panic!("policy must serialize as an object");
        };
        assert_eq!(
            dedicated_fields.get("max_amount_wei"),
            Some(&serde_json::Value::String(expected_limit.to_string()))
        );
        assert_eq!(
            dedicated_fields.get(dedicated_field),
            Some(&serde_json::Value::String(expected_limit.to_string()))
        );

        let dedicated: SpendingPolicy =
            serde_json::from_value(serde_json::Value::Object(dedicated_fields.clone()))
                .expect("dedicated policy");
        assert_eq!(dedicated.max_amount_wei, 0);
        assert_eq!(accessor(&dedicated), Some(expected_limit));

        dedicated_fields.remove(dedicated_field);
        dedicated_fields.insert(
            "max_amount_wei".to_string(),
            serde_json::Value::String(legacy_limit.to_string()),
        );

        let legacy: SpendingPolicy =
            serde_json::from_value(serde_json::Value::Object(dedicated_fields))
                .expect("legacy policy");
        assert_eq!(legacy.max_amount_wei, 0);
        assert_eq!(accessor(&legacy), Some(legacy_limit));
    }

    let calldata_policy = SpendingPolicy::new_calldata_limit(
        1,
        32,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    assert_eq!(calldata_policy.max_calldata_bytes, Some(32));
    assert_specialized_limit_round_trip(
        calldata_policy,
        "max_calldata_bytes",
        32,
        64,
        SpendingPolicy::calldata_bytes_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_tx_count_limit(
            1,
            3,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_tx_count",
        3,
        4,
        SpendingPolicy::tx_count_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_fee_per_gas_limit(
            1,
            5,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_fee_per_gas_wei",
        5,
        6,
        SpendingPolicy::fee_per_gas_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_priority_fee_per_gas_limit(
            1,
            7,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_priority_fee_per_gas_wei",
        7,
        8,
        SpendingPolicy::priority_fee_per_gas_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_gas_spend_limit(
            1,
            9,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_gas_spend_wei",
        9,
        10,
        SpendingPolicy::gas_spend_limit_wei,
    );

    let non_calldata = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut non_calldata_json = serde_json::to_value(&non_calldata).expect("serialize policy");
    let serde_json::Value::Object(ref mut fields) = non_calldata_json else {
        panic!("policy must serialize as an object");
    };
    fields.remove("max_amount_wei");

    let err = serde_json::from_value::<SpendingPolicy>(non_calldata_json)
        .expect_err("missing max_amount_wei must fail for non-calldata policies");
    assert!(err.to_string().contains("missing field `max_amount_wei`"));
}

#[test]
fn specialized_policy_deserialization_requires_dedicated_or_legacy_limit_field() {
    let policy = SpendingPolicy::new_calldata_limit(
        1,
        32,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");

    let mut missing_limit_json = serde_json::to_value(&policy).expect("serialize policy");
    let serde_json::Value::Object(ref mut fields) = missing_limit_json else {
        panic!("policy must serialize as an object");
    };
    fields.remove("max_calldata_bytes");
    fields.remove("max_amount_wei");

    let err = serde_json::from_value::<SpendingPolicy>(missing_limit_json)
        .expect_err("missing specialized limit must fail");
    assert!(err
        .to_string()
        .contains("missing field `max_calldata_bytes` or legacy `max_amount_wei`"));
}

#[test]
fn spending_policy_deserialization_rejects_zero_and_inverted_amount_limits() {
    let policy = SpendingPolicy::new_manual_approval(
        1,
        5,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let base = serde_json::to_value(&policy).expect("serialize policy");
    serde_json::from_value::<SpendingPolicy>(base.clone()).expect("valid policy round-trips");

    let mut zero_max = base.clone();
    zero_max["max_amount_wei"] = serde_json::json!("0");
    let err = serde_json::from_value::<SpendingPolicy>(zero_max)
        .expect_err("zero max_amount_wei must fail");
    assert!(err
        .to_string()
        .contains("max_amount_wei must be greater than zero"));

    let mut inverted_range = base.clone();
    inverted_range["min_amount_wei"] = serde_json::json!("11");
    let err = serde_json::from_value::<SpendingPolicy>(inverted_range)
        .expect_err("min above max must fail");
    assert!(err
        .to_string()
        .contains("min_amount_wei must not exceed max_amount_wei"));

    let mut equal_range = base;
    equal_range["min_amount_wei"] = serde_json::json!("10");
    let equal = serde_json::from_value::<SpendingPolicy>(equal_range).expect("min == max is valid");
    assert_eq!(equal.min_amount_wei, Some(10));

    let per_tx = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut zero_per_tx = serde_json::to_value(&per_tx).expect("serialize policy");
    zero_per_tx["max_amount_wei"] = serde_json::json!("0");
    assert!(serde_json::from_value::<SpendingPolicy>(zero_per_tx).is_err());
}

#[test]
fn spending_policy_deserialization_rejects_zero_specialized_limits() {
    let calldata_policy = SpendingPolicy::new_calldata_limit(
        1,
        4,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut zero_dedicated = serde_json::to_value(&calldata_policy).expect("serialize policy");
    zero_dedicated["max_calldata_bytes"] = serde_json::json!("0");
    zero_dedicated["max_amount_wei"] = serde_json::json!("0");
    let err = serde_json::from_value::<SpendingPolicy>(zero_dedicated)
        .expect_err("zero calldata limit must fail");
    assert!(err
        .to_string()
        .contains("policy limit must be greater than zero"));

    let tx_count_policy = SpendingPolicy::new_tx_count_limit(
        1,
        3,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut zero_legacy = serde_json::to_value(&tx_count_policy).expect("serialize policy");
    let serde_json::Value::Object(ref mut fields) = zero_legacy else {
        panic!("policy must serialize as an object");
    };
    fields.remove("max_tx_count");
    fields.insert("max_amount_wei".to_string(), serde_json::json!("0"));
    assert!(serde_json::from_value::<SpendingPolicy>(zero_legacy).is_err());
}

#[test]
fn spending_policy_deserialization_validates_network_scope() {
    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([1_u64])),
    )
    .expect("policy");
    let base = serde_json::to_value(&policy).expect("serialize policy");

    let mut zero_chain = base.clone();
    zero_chain["networks"] =
        serde_json::to_value(EntityScope::Set(BTreeSet::from([0_u64]))).expect("scope");
    let err =
        serde_json::from_value::<SpendingPolicy>(zero_chain).expect_err("chain id 0 must fail");
    assert!(err
        .to_string()
        .contains("network set must not contain chain_id 0"));

    let mut empty_networks = base;
    empty_networks["networks"] =
        serde_json::to_value(EntityScope::<u64>::Set(BTreeSet::new())).expect("scope");
    let err = serde_json::from_value::<SpendingPolicy>(empty_networks)
        .expect_err("empty network set must fail");
    assert!(err
        .to_string()
        .contains("network set scope must not be empty"));

    let eip712 = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("policy");
    let mut eip712_zero_chain = serde_json::to_value(&eip712).expect("serialize policy");
    eip712_zero_chain["networks"] =
        serde_json::to_value(EntityScope::Set(BTreeSet::from([0_u64]))).expect("scope");
    let err = serde_json::from_value::<SpendingPolicy>(eip712_zero_chain)
        .expect_err("eip712 policy with chain id 0 must fail");
    assert!(err
        .to_string()
        .contains("network set must not contain chain_id 0"));
}

#[test]
fn asset_id_display_formats_native_and_erc20_variants() {
    let token: EvmAddress = "0x1234000000000000000000000000000000000000"
        .parse()
        .expect("token");

    assert_eq!(AssetId::NativeEth.to_string(), "native_eth");
    assert_eq!(AssetId::NativeSol.to_string(), "native_sol");
    assert_eq!(
        AssetId::Erc20(token).to_string(),
        "erc20:0x1234000000000000000000000000000000000000"
    );
}

#[test]
fn spending_policy_rejects_empty_network_sets() {
    let err = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::new()),
    )
    .expect_err("empty network set must fail");

    assert!(matches!(
        &err,
        DomainError::EmptyScope { scope } if *scope == "network set"
    ));
    assert_eq!(err.to_string(), "network set scope must not be empty");
}

#[test]
fn spend_event_ignores_legacy_action_kind_field() {
    let event = SpendEvent {
        agent_key_id: Uuid::nil(),
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: RecipientId::Evm(
            "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("addr"),
        ),
        amount_wei: 1,
        at: OffsetDateTime::UNIX_EPOCH,
        approval_request_id: None,
    };
    let mut value = serde_json::to_value(&event).expect("serialize spend event");
    // Persisted logs from before the Railgun removal carry an `action_kind`
    // discriminator; it must be ignored rather than fail the whole log.
    value["action_kind"] = serde_json::Value::String("shield".to_string());
    let legacy: SpendEvent = serde_json::from_value(value).expect("legacy spend event");
    assert_eq!(legacy, event);
}

#[test]
fn over_limit_defaults_to_deny_and_is_omitted_until_set() {
    let policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        500,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let legacy = serde_json::to_value(&policy).expect("encode");
    assert!(
        legacy.get("over_limit").is_none(),
        "deny is omitted, so policies stored before API 1.1 look the same"
    );
    let decoded: SpendingPolicy = serde_json::from_value(legacy.clone()).expect("legacy decode");
    assert_eq!(decoded.over_limit, OverLimit::Deny);
    assert_eq!(decoded, policy);

    let soft = policy
        .with_over_limit(OverLimit::ManualApproval)
        .expect("limit type");
    let encoded = serde_json::to_value(&soft).expect("encode");
    assert_eq!(encoded["over_limit"], "manual_approval");
    let decoded: SpendingPolicy = serde_json::from_value(encoded).expect("decode");
    assert_eq!(decoded, soft);
    assert!(decoded.may_require_manual_approval());
}

#[test]
fn over_limit_approval_is_refused_for_types_without_an_amount_or_count_limit() {
    let gas = SpendingPolicy::new(
        1,
        PolicyType::PerChainMaxGasSpend,
        1_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut encoded = serde_json::to_value(&gas).expect("encode");
    encoded["over_limit"] = serde_json::json!("manual_approval");
    let error = serde_json::from_value::<SpendingPolicy>(encoded)
        .expect_err("gas caps cannot ask for approval");
    assert!(error.to_string().contains("over_limit"), "{error}");
    assert!(!gas.may_require_manual_approval());
}

#[test]
fn approval_requests_stored_without_reasons_decode_with_none() {
    let action = AgentAction::Transfer {
        chain_id: 56,
        token: "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
            .parse()
            .expect("token"),
        to: "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
            .parse()
            .expect("to"),
        amount_wei: 1,
    };
    let request = ManualApprovalRequest {
        id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        vault_key_id: Uuid::new_v4(),
        request_payload_hash_hex: "00".repeat(32),
        chain_id: 56,
        asset: action.asset(),
        recipient: action.recipient(),
        amount_wei: 1,
        action,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        status: ManualApprovalStatus::Pending,
        triggered_by_policy_ids: Vec::new(),
        reasons: vec![ApprovalReason {
            limit: ApprovalLimit::DailyCount,
            policy_id: None,
            max: Some(3),
            used: Some(3),
            requested_amount_wei: Some(1),
        }],
        completed_at: None,
        rejection_reason: None,
    };
    let mut legacy = serde_json::to_value(&request).expect("encode");
    assert_eq!(legacy["reasons"][0]["limit"], "daily_count");
    assert_eq!(legacy["reasons"][0]["max"], "3");
    legacy.as_object_mut().expect("object").remove("reasons");
    let decoded: ManualApprovalRequest = serde_json::from_value(legacy).expect("legacy decode");
    assert!(decoded.reasons.is_empty());
}
