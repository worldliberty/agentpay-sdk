use super::*;

#[test]
fn per_tx_limit_is_enforced() {
    let engine = PolicyEngine;
    let token = addr("0x1000000000000000000000000000000000000000");
    let recipient = addr("0x2000000000000000000000000000000000000000");
    let policy = policy_all_per_tx(100);

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 101,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(
        result,
        Err(PolicyError::PerTxLimitExceeded { .. })
    ));
}

#[test]
fn daily_limit_sums_recent_usage() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let token = addr("0x3000000000000000000000000000000000000000");
    let recipient = addr("0x4000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([AssetId::Erc20(token.clone())])),
        EntityScope::Set(BTreeSet::from([1_u64])),
    )
    .expect("policy must build");

    let agent_key_id = Uuid::new_v4();
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::Erc20(token.clone()),
        recipient: recipient.clone().into(),
        amount_wei: 70,
        at: now - time::Duration::hours(2),
        approval_request_id: None,
    }];

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 31,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &history,
        agent_key_id,
        now,
    );

    assert!(matches!(
        result,
        Err(PolicyError::WindowLimitExceeded {
            used_amount_wei: 70,
            requested_amount_wei: 31,
            ..
        })
    ));
}

#[test]
fn daily_limit_counts_future_dated_usage_as_current() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let token = addr("0x3000000000000000000000000000000000000000");
    let recipient = addr("0x4000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([AssetId::Erc20(token.clone())])),
        EntityScope::Set(BTreeSet::from([1_u64])),
    )
    .expect("policy must build");

    let agent_key_id = Uuid::new_v4();
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::Erc20(token.clone()),
        recipient: recipient.clone().into(),
        amount_wei: 80,
        at: now + Duration::hours(1),
        approval_request_id: None,
    }];

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 30,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &history,
        agent_key_id,
        now,
    );

    // A backward clock step must not reset the budget: the 80 wei stamped
    // one hour "in the future" still counts against today's cap.
    assert!(matches!(
        result,
        Err(PolicyError::WindowLimitExceeded {
            used_amount_wei: 80,
            requested_amount_wei: 30,
            max_amount_wei: 100,
            ..
        })
    ));
}

#[test]
fn daily_limit_counts_all_in_scope_usage_across_assets_and_chains() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let token_a = addr("0x3000000000000000000000000000000000000000");
    let token_b = addr("0x5000000000000000000000000000000000000000");
    let recipient_a = addr("0x4000000000000000000000000000000000000000");
    let recipient_b = addr("0x6000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");

    let agent_key_id = Uuid::new_v4();
    let history = vec![
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token_a),
            recipient: recipient_a.into(),
            amount_wei: 70,
            at: now - time::Duration::hours(2),
            approval_request_id: None,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 10,
            asset: AssetId::NativeEth,
            recipient: recipient_b.clone().into(),
            amount_wei: 20,
            at: now - time::Duration::hours(1),
            approval_request_id: None,
        },
    ];

    let action = AgentAction::Transfer {
        chain_id: 137,
        token: token_b,
        to: recipient_b,
        amount_wei: 15,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &history,
        agent_key_id,
        now,
    );

    assert!(matches!(
        result,
        Err(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            ..
        })
    ));
}

#[test]
fn window_limit_fails_closed_on_usage_overflow() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let token = addr("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let recipient = addr("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    let policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");

    let agent_key_id = Uuid::new_v4();
    let history = vec![
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone().into(),
            amount_wei: u128::MAX,
            at: now - time::Duration::hours(2),
            approval_request_id: None,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone().into(),
            amount_wei: 1,
            at: now - time::Duration::hours(1),
            approval_request_id: None,
        },
    ];

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 1,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &history,
        agent_key_id,
        now,
    );

    assert!(matches!(
        result,
        Err(PolicyError::WindowLimitExceeded {
            used_amount_wei: u128::MAX,
            requested_amount_wei: 1,
            ..
        })
    ));
}

#[test]
fn per_chain_gas_limit_is_enforced_for_broadcast_tx() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let policy = gas_policy(1, 500_000_000_000_000);

    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: addr("0x1000000000000000000000000000000000000000"),
            value_wei: 0,
            data_hex: "0x".to_string(),
            gas_limit: 1_000_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        now,
    );

    assert!(matches!(result, Err(PolicyError::GasLimitExceeded { .. })));
}

#[test]
fn per_chain_gas_limit_allows_broadcast_within_cap() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let policy = gas_policy(1, 2_000_000_000_000_000);

    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: addr("0x1000000000000000000000000000000000000000"),
            value_wei: 0,
            data_hex: "0x".to_string(),
            gas_limit: 1_000_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        now,
    );

    assert!(result.is_ok());
}

#[test]
fn per_tx_max_fee_per_gas_is_enforced() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxFeePerGas,
        1_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = broadcast_action_with_fees(2_000_000_000, 1_000_000_000, "0x");

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        result,
        Err(PolicyError::MaxFeePerGasLimitExceeded { .. })
    ));
}

#[test]
fn per_tx_max_priority_fee_per_gas_is_enforced() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxPriorityFeePerGas,
        500_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = broadcast_action_with_fees(2_000_000_000, 1_000_000_000, "0x");

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        result,
        Err(PolicyError::PriorityFeePerGasLimitExceeded { .. })
    ));
}

#[test]
fn per_tx_max_calldata_bytes_is_enforced() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new_calldata_limit(
        0,
        3,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = broadcast_action_with_fees(2_000_000_000, 1_000_000_000, "0xdeadbeef");

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        result,
        Err(PolicyError::CalldataBytesLimitExceeded { .. })
    ));
}

#[test]
fn legacy_calldata_policies_still_use_max_amount_as_fallback_limit() {
    let policy = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxCalldataBytes,
        min_amount_wei: None,
        max_amount_wei: 3,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::All,
        assets: EntityScope::All,
        networks: EntityScope::All,
        approval_type: None,
        over_limit: agentpay_domain::OverLimit::Deny,
        enabled: true,
    };
    let action = broadcast_action_with_fees(2_000_000_000, 1_000_000_000, "0xdeadbeef");

    assert!(matches!(
        enforce_calldata_bytes_limit(&policy, &action),
        Err(PolicyError::CalldataBytesLimitExceeded {
            max_calldata_bytes: 3,
            requested_calldata_bytes: 4,
            ..
        })
    ));
}

#[test]
fn daily_tx_count_limit_is_enforced() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let recipient = addr("0x2000000000000000000000000000000000000000");
    let token = addr("0x3000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new(
        0,
        PolicyType::DailyMaxTxCount,
        2,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let agent_key_id = Uuid::new_v4();
    let history = vec![
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone().into(),
            amount_wei: 1,
            at: now - Duration::hours(2),
            approval_request_id: None,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone().into(),
            amount_wei: 1,
            at: now - Duration::hours(1),
            approval_request_id: None,
        },
    ];
    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 1,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &history,
        agent_key_id,
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::TxCountLimitExceeded { .. })
    ));
}

#[test]
fn daily_tx_count_limit_counts_future_dated_usage_as_current() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let recipient = addr("0x2000000000000000000000000000000000000000");
    let token = addr("0x3000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new(
        0,
        PolicyType::DailyMaxTxCount,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let agent_key_id = Uuid::new_v4();
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 1,
        asset: AssetId::Erc20(token.clone()),
        recipient: recipient.clone().into(),
        amount_wei: 1,
        at: now + Duration::hours(1),
        approval_request_id: None,
    }];
    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 1,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &history,
        agent_key_id,
        now,
    );

    assert!(matches!(
        result,
        Err(PolicyError::TxCountLimitExceeded {
            used_tx_count: 1,
            max_tx_count: 1,
            ..
        })
    ));
}

#[test]
fn fee_policy_is_not_applicable_when_action_lacks_metadata() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxFeePerGas,
        1_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: addr("0x1000000000000000000000000000000000000000"),
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 1,
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

#[test]
fn fee_and_calldata_limits_allow_broadcasts_within_cap() {
    let engine = PolicyEngine;
    let fee_policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxPriorityFeePerGas,
        1_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let calldata_policy = SpendingPolicy::new_calldata_limit(
        1,
        4,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = broadcast_action_with_fees(2_000_000_000, 1_000_000_000, "0xdeadbeef");

    let result = engine.evaluate(
        &[fee_policy, calldata_policy],
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(result.is_ok());
}

#[test]
fn tx_count_overflow_helper_saturates_at_max() {
    let mut counter = u128::MAX;

    assert!(increment_counter_or_mark_overflow(&mut counter));
    assert_eq!(counter, u128::MAX);
}

#[test]
fn optional_limit_helpers_allow_missing_or_in_range_metadata() {
    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxPriorityFeePerGas,
        1_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let plain_transfer = AgentAction::TransferNative {
        chain_id: 1,
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 1,
    };
    assert!(enforce_priority_fee_limit(&policy, &plain_transfer).is_ok());

    let broadcast = broadcast_action_with_fees(2_000_000_000, 1_000_000_000, "0xdeadbeef");
    assert!(enforce_priority_fee_limit(&policy, &broadcast).is_ok());

    let calldata_policy = SpendingPolicy::new_calldata_limit(
        0,
        4,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    assert!(enforce_calldata_bytes_limit(&calldata_policy, &plain_transfer).is_ok());
    assert!(enforce_calldata_bytes_limit(&calldata_policy, &broadcast).is_ok());
}

#[test]
fn gas_policy_is_not_applicable_when_action_lacks_metadata() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerChainMaxGasSpend,
        1_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: addr("0x1000000000000000000000000000000000000000"),
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 1,
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
