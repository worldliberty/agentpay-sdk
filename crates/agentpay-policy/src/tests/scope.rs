use super::*;

#[test]
fn wallet_maintenance_bypasses_spending_and_manual_policies() {
    let engine = PolicyEngine;
    let manual_policy = SpendingPolicy::new_manual_approval(
        0,
        1,
        1,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual policy");
    let spend_policy = policy_all_per_tx(1);
    let policies = vec![manual_policy, spend_policy];
    let agent_key_id = Uuid::new_v4();

    let explanation = engine.explain(
        &policies,
        &PolicyAttachment::AllPolicies,
        &solana_nonce_account_create_action(),
        &[],
        agent_key_id,
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(explanation.decision, PolicyDecision::Allow));
    assert_eq!(explanation.attached_policy_ids.len(), 2);
    assert!(explanation.applicable_policy_ids.is_empty());
    assert!(explanation.evaluated_policy_ids.is_empty());

    let result = engine.evaluate(
        &policies,
        &PolicyAttachment::AllPolicies,
        &solana_nonce_account_create_action(),
        &[],
        agent_key_id,
        OffsetDateTime::now_utc(),
    );
    assert!(result.is_ok());
}

#[test]
fn network_scope_is_enforced() {
    let engine = PolicyEngine;
    let token = addr("0x5000000000000000000000000000000000000000");
    let recipient = addr("0x6000000000000000000000000000000000000000");

    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([1_u64])),
    )
    .expect("policy");

    let action = AgentAction::Transfer {
        chain_id: 10,
        token,
        to: recipient,
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

    assert!(matches!(result, Err(PolicyError::NoApplicablePolicies)));
}

#[test]
fn solana_network_aliases_share_policy_scope() {
    let engine = PolicyEngine;
    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([SOLANA_DEVNET_CHAIN_ID])),
    )
    .expect("policy");
    let action = solana_spl_action(SOLANA_MAINNET_CHAIN_ID, 11);

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
        Err(PolicyError::PerTxLimitExceeded {
            max_amount_wei: 10,
            requested_amount_wei: 11,
            ..
        })
    ));
}

#[test]
fn solana_window_limits_count_all_network_aliases() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let policy = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([SOLANA_TESTNET_CHAIN_ID])),
    )
    .expect("policy");
    let history_action = solana_spl_action(SOLANA_MAINNET_CHAIN_ID, 7);
    let action = solana_spl_action(SOLANA_DEVNET_CHAIN_ID, 4);
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: SOLANA_MAINNET_CHAIN_ID,
        asset: history_action.asset(),
        recipient: history_action.recipient(),
        amount_wei: 7,
        at: now - Duration::hours(1),
        approval_request_id: None,
    }];

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
            used_amount_wei: 7,
            requested_amount_wei: 4,
            max_amount_wei: 10,
            ..
        })
    ));
}

#[test]
fn native_eth_scope_is_enforced() {
    let engine = PolicyEngine;
    let recipient = addr("0x7000000000000000000000000000000000000000");
    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([AssetId::NativeEth])),
        EntityScope::All,
    )
    .expect("policy");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: addr("0x8000000000000000000000000000000000000000"),
        to: recipient.clone(),
        amount_wei: 1,
    };

    let result = engine.evaluate(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(result, Err(PolicyError::NoApplicablePolicies)));

    let native_action = AgentAction::TransferNative {
        chain_id: 1,
        to: recipient,
        amount_wei: 1,
    };

    let result = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &native_action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(result.is_ok());
}

#[test]
fn policies_are_evaluated_in_priority_order() {
    let engine = PolicyEngine;
    let token = addr("0x5000000000000000000000000000000000000000");
    let recipient = addr("0x6000000000000000000000000000000000000000");

    let p1 = SpendingPolicy::new(
        10,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");

    let p2 = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 1,
    };

    let result = engine
        .evaluate(
            &[p1.clone(), p2.clone()],
            &PolicyAttachment::AllPolicies,
            &action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        )
        .expect("must pass");

    assert_eq!(result.evaluated_policy_ids, vec![p2.id, p1.id]);
}

#[test]
fn only_attached_policy_ids_are_used() {
    let engine = PolicyEngine;
    let token = addr("0x5000000000000000000000000000000000000000");
    let recipient = addr("0x6000000000000000000000000000000000000000");

    let included = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");

    let excluded = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");

    let mut only_included = BTreeSet::new();
    only_included.insert(included.id);

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 20,
    };

    let result = engine.evaluate(
        &[included.clone(), excluded],
        &PolicyAttachment::PolicySet(only_included),
        &action,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    let evaluation = result.expect("included policy should pass");
    assert_eq!(evaluation.evaluated_policy_ids, vec![included.id]);
}

#[test]
fn no_applicable_policy_fails_when_scope_does_not_match() {
    let engine = PolicyEngine;

    let token = addr("0x7777777777777777777777777777777777777777");
    let recipient = addr("0x8888888888888888888888888888888888888888");

    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([AssetId::Erc20(addr(
            "0x9999999999999999999999999999999999999999",
        ))])),
        EntityScope::All,
    )
    .expect("policy");

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
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(matches!(result, Err(PolicyError::NoApplicablePolicies)));
}

#[test]
fn equal_priority_policies_are_ordered_by_id() {
    let engine = PolicyEngine;
    let token = addr("0x1111111111111111111111111111111111111111");
    let recipient = addr("0x2222222222222222222222222222222222222222");

    let mut high_id = SpendingPolicy::new(
        5,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");
    high_id.id = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").expect("uuid");

    let mut low_id = SpendingPolicy::new(
        5,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy must build");
    low_id.id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 1,
    };

    let result = engine
        .evaluate(
            &[high_id.clone(), low_id.clone()],
            &PolicyAttachment::AllPolicies,
            &action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        )
        .expect("must pass");

    assert_eq!(result.evaluated_policy_ids, vec![low_id.id, high_id.id]);
}

#[test]
fn eip3009_broadcast_scope_is_enforced() {
    let engine = PolicyEngine;
    let token = addr("0x3000000000000000000000000000000000000000");
    let allowed_recipient = addr("0x4000000000000000000000000000000000000000");
    let denied_recipient = addr("0x5050505050505050505050505050505050505050");
    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::Set(BTreeSet::from([allowed_recipient.clone()])),
        EntityScope::Set(BTreeSet::from([AssetId::Erc20(token.clone())])),
        EntityScope::Set(BTreeSet::from([1_u64])),
    )
    .expect("policy");
    let calldata = {
        use alloy_sol_types::{sol, SolCall};
        sol! {
            function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);
        }
        transferWithAuthorizationCall {
            from: alloy_primitives::Address::from([0x11; 20]),
            to: alloy_primitives::Address::from([0x50; 20]),
            value: alloy_primitives::U256::from(10u64),
            validAfter: alloy_primitives::U256::from(1u64),
            validBefore: alloy_primitives::U256::from(2u64),
            nonce: [0x77; 32].into(),
            signature: vec![0x12].into(),
        }
        .abi_encode()
    };
    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: token,
            value_wei: 0,
            data_hex: format!(
                "0x{}",
                calldata
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            gas_limit: 50_000,
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
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(result, Err(PolicyError::NoApplicablePolicies)));
    assert_eq!(action.recipient(), denied_recipient);
}
