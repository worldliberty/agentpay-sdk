use std::collections::BTreeSet;
use std::str::FromStr;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vault_domain::{
    AgentAction, ApprovalType, AssetId, BroadcastTx, Eip712TypedData, EntityScope, EvmAddress,
    PolicyAttachment, PolicyType, SpendEvent, SpendingPolicy,
};

use crate::engine::{
    enforce_calldata_bytes_limit, enforce_priority_fee_limit, increment_counter_or_mark_overflow,
};

use super::{PolicyEngine, PolicyError};

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

fn gas_policy(chain_id: u64, max_gas_wei: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        0,
        PolicyType::PerChainMaxGasSpend,
        max_gas_wei,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([chain_id])),
    )
    .expect("policy")
}

fn broadcast_action_with_fees(
    max_fee_per_gas_wei: u128,
    max_priority_fee_per_gas_wei: u128,
    data_hex: &str,
) -> AgentAction {
    AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: addr("0x1000000000000000000000000000000000000000"),
            value_wei: 0,
            data_hex: data_hex.to_string(),
            gas_limit: 21_000,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    }
}

fn eip712_action(chain_id: u64) -> AgentAction {
    AgentAction::Eip712TypedData {
        typed_data: Eip712TypedData {
            typed_data_json: format!(
                r#"{{
  "types": {{
    "EIP712Domain": [
      {{ "name": "name", "type": "string" }},
      {{ "name": "version", "type": "string" }},
      {{ "name": "chainId", "type": "uint256" }},
      {{ "name": "verifyingContract", "type": "address" }}
    ],
    "Mail": [
      {{ "name": "contents", "type": "string" }}
    ]
  }},
  "primaryType": "Mail",
  "domain": {{
    "name": "AgentPay Test",
    "version": "1",
    "chainId": {chain_id},
    "verifyingContract": "0x1111111111111111111111111111111111111111"
  }},
  "message": {{
    "contents": "hello"
  }}
}}"#
            ),
        },
    }
}

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
fn eip712_defaults_to_allow_with_all_policies() {
    let engine = PolicyEngine;
    let result = engine.evaluate(
        &[],
        &PolicyAttachment::AllPolicies,
        &eip712_action(1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );

    assert!(result.is_ok());
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
        &[policy.clone()],
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
        &[policy.clone()],
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
        recipient: recipient.clone(),
        amount_wei: 70,
        at: now - time::Duration::hours(2),
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
fn daily_limit_ignores_future_dated_usage() {
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
        recipient: recipient.clone(),
        amount_wei: 80,
        at: now + Duration::hours(1),
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

    assert!(result.is_ok());
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
            recipient: recipient_a,
            amount_wei: 70,
            at: now - time::Duration::hours(2),
        },
        SpendEvent {
            agent_key_id,
            chain_id: 10,
            asset: AssetId::NativeEth,
            recipient: recipient_b.clone(),
            amount_wei: 20,
            at: now - time::Duration::hours(1),
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
            recipient: recipient.clone(),
            amount_wei: u128::MAX,
            at: now - time::Duration::hours(2),
        },
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone(),
            amount_wei: 1,
            at: now - time::Duration::hours(1),
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
            recipient: recipient.clone(),
            amount_wei: 1,
            at: now - Duration::hours(2),
        },
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone(),
            amount_wei: 1,
            at: now - Duration::hours(1),
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
fn daily_tx_count_limit_ignores_future_dated_usage() {
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
        recipient: recipient.clone(),
        amount_wei: 1,
        at: now + Duration::hours(1),
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

    assert!(result.is_ok());
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
fn explain_allows_unrestricted_agents_when_no_policies_exist() {
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

    assert!(matches!(explanation.decision, super::PolicyDecision::Allow));
    assert!(explanation.attached_policy_ids.is_empty());
    assert!(explanation.applicable_policy_ids.is_empty());
    assert!(explanation.evaluated_policy_ids.is_empty());
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
        recipient: recipient.clone(),
        amount_wei: 80,
        at: now - Duration::days(2),
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

#[test]
fn permit2_per_tx_limit_is_enforced() {
    let engine = PolicyEngine;
    let expiration =
        u64::try_from((OffsetDateTime::now_utc() + Duration::hours(2)).unix_timestamp())
            .expect("future unix timestamp");
    let sig_deadline =
        u64::try_from((OffsetDateTime::now_utc() + Duration::hours(1)).unix_timestamp())
            .expect("future unix timestamp");
    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: addr("0x000000000022d473030f116ddee9f6b43ac78ba3"),
            token: addr("0x1000000000000000000000000000000000000000"),
            spender: addr("0x2000000000000000000000000000000000000000"),
            amount_wei: 101,
            expiration,
            nonce: 1,
            sig_deadline,
        },
    };
    let result = engine.evaluate(
        &[policy_all_per_tx(100)],
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
