use std::collections::BTreeSet;
use std::str::FromStr;

use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vault_domain::{
    ActionKind, AgentAction, ApprovalType, AssetId, BroadcastTx, Eip712TypedData, EntityScope,
    EvmAddress, PolicyAttachment, PolicyType, RailgunAddress, SolanaAddress,
    SolanaNonceAccountCreate, SolanaSplTransfer, SpendEvent, SpendingPolicy,
    TempoSessionOpenTransaction, TempoSessionVoucher, TempoTxParams, SOLANA_DEVNET_CHAIN_ID,
    SOLANA_MAINNET_CHAIN_ID, SOLANA_TESTNET_CHAIN_ID, TEMPO_MAINNET_CHAIN_ID,
    TEMPO_MAINNET_ESCROW_CONTRACT,
};

use crate::engine::{
    enforce_calldata_bytes_limit, enforce_priority_fee_limit, increment_counter_or_mark_overflow,
};

use super::{PolicyDecision, PolicyEngine, PolicyError};

fn addr(x: &str) -> EvmAddress {
    EvmAddress::from_str(x).expect("valid test address")
}

fn solana_addr(x: &str) -> SolanaAddress {
    SolanaAddress::from_str(x).expect("valid test solana address")
}

fn solana_spl_action(chain_id: u64, amount_wei: u128) -> AgentAction {
    AgentAction::SolanaSplTransfer {
        transfer: SolanaSplTransfer {
            chain_id,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
            durable_nonce_account: None,
            fee_payer: solana_addr("11111111111111111111111111111111"),
            mint: solana_addr("So11111111111111111111111111111111111111112"),
            recipient_owner: solana_addr("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            amount_wei,
            decimals: 9,
            token_program: vault_domain::SolanaTokenProgram::Token,
            transfer_fee_wei: None,
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
        },
    }
}

fn solana_nonce_account_create_action() -> AgentAction {
    AgentAction::SolanaNonceAccountCreate {
        create: SolanaNonceAccountCreate {
            chain_id: SOLANA_DEVNET_CHAIN_ID,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
            fee_payer: solana_addr("11111111111111111111111111111111"),
            nonce_account: solana_addr("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
            seed: "agentpay-900000002-nonce".to_string(),
            rent_lamports: 1_500_000,
        },
    }
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
    eip712_action_with(
        chain_id,
        "Mail",
        "0x1111111111111111111111111111111111111111",
    )
}

fn eip712_action_with(chain_id: u64, primary_type: &str, verifying_contract: &str) -> AgentAction {
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
    "{primary_type}": [
      {{ "name": "contents", "type": "string" }}
    ]
  }},
  "primaryType": "{primary_type}",
  "domain": {{
    "name": "AgentPay Test",
    "version": "1",
    "chainId": {chain_id},
    "verifyingContract": "{verifying_contract}"
  }},
  "message": {{
    "contents": "hello"
  }}
}}"#
            ),
        },
    }
}

/// Canonical Permit2 deployment, EIP-55 checksummed as wallets emit it.
const PERMIT2_CHECKSUMMED: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

#[test]
fn per_tx_limit_is_enforced() {
    let engine = PolicyEngine::default();
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
fn eip712_with_no_attached_policies_requires_manual_approval_even_with_all_policies() {
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
fn wallet_maintenance_bypasses_spending_and_manual_policies() {
    let engine = PolicyEngine::default();
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
fn eip712_manual_policy_requires_manual_approval() {
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
        action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
        action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
            action_kind: ActionKind::Other,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 10,
            asset: AssetId::NativeEth,
            recipient: recipient_b.clone().into(),
            amount_wei: 20,
            at: now - time::Duration::hours(1),
            action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
        action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();

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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
            action_kind: ActionKind::Other,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone().into(),
            amount_wei: 1,
            at: now - time::Duration::hours(1),
            action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
            action_kind: ActionKind::Other,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 1,
            asset: AssetId::Erc20(token.clone()),
            recipient: recipient.clone().into(),
            amount_wei: 1,
            at: now - Duration::hours(1),
            action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
        action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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

#[test]
fn fee_and_calldata_limits_allow_broadcasts_within_cap() {
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
        action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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

fn railgun_test_address() -> RailgunAddress {
    "0zk1qyqqqqqdl645pcpreh6dga7xa0dfwx5ehmkmrkpaczj9cyqr0e0vchcaxfsa6au6f93dvr64skspz"
        .parse::<RailgunAddress>()
        .expect("railgun address")
}

fn railgun_token() -> EvmAddress {
    addr("0x1000000000000000000000000000000000000000")
}

fn shield_action(amount_wei: u128) -> AgentAction {
    AgentAction::Shield {
        chain_id: 56,
        token: railgun_token(),
        to_railgun_address: railgun_test_address(),
        amount_wei,
    }
}

fn unshield_action(amount_wei: u128) -> AgentAction {
    AgentAction::Unshield {
        chain_id: 56,
        token: railgun_token(),
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei,
        via_broadcaster: false,
    }
}

fn private_transfer_action(amount_wei: u128) -> AgentAction {
    AgentAction::PrivateTransfer {
        chain_id: 56,
        token: railgun_token(),
        to_railgun_address: railgun_test_address(),
        amount_wei,
        via_broadcaster: true,
    }
}

fn railgun_amount_policy(policy_type: PolicyType, max: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        1,
        policy_type,
        max,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

#[test]
fn per_tx_max_shield_amount_blocks_oversized_shield() {
    let engine = PolicyEngine::default();
    let policy = railgun_amount_policy(PolicyType::PerTxMaxShieldAmount, 100);

    let denied = engine.evaluate(
        &[policy.clone()],
        &PolicyAttachment::AllPolicies,
        &shield_action(101),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(
        denied,
        Err(PolicyError::PerTxLimitExceeded { .. })
    ));

    let allowed = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &shield_action(100),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(allowed.is_ok());
}

#[test]
fn per_tx_max_shield_amount_is_ignored_for_unshield_and_transfer() {
    let engine = PolicyEngine::default();
    let policy = railgun_amount_policy(PolicyType::PerTxMaxShieldAmount, 50);

    // Unshield is not constrained by a shield-amount cap.
    let unshield_ok = engine.evaluate(
        &[policy.clone()],
        &PolicyAttachment::AllPolicies,
        &unshield_action(10_000),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(unshield_ok.is_ok());

    // Plain ERC-20 transfer is also untouched.
    let transfer = AgentAction::Transfer {
        chain_id: 56,
        token: railgun_token(),
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 10_000,
    };
    let transfer_ok = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &transfer,
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(transfer_ok.is_ok());
}

#[test]
fn per_tx_max_unshield_amount_applies_to_both_unshield_and_private_transfer() {
    let engine = PolicyEngine::default();
    let policy = railgun_amount_policy(PolicyType::PerTxMaxUnshieldAmount, 100);

    for action in [unshield_action(101), private_transfer_action(101)] {
        let result = engine.evaluate(
            &[policy.clone()],
            &PolicyAttachment::AllPolicies,
            &action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(result, Err(PolicyError::PerTxLimitExceeded { .. })),
            "expected per-tx limit denial for {action:?}",
        );
    }
}

#[test]
fn daily_max_shield_amount_accumulates_shield_events_only() {
    let engine = PolicyEngine::default();
    let policy = railgun_amount_policy(PolicyType::DailyMaxShieldAmount, 100);
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();

    let history = vec![
        SpendEvent {
            agent_key_id,
            chain_id: 56,
            asset: AssetId::Erc20(railgun_token()),
            recipient: railgun_test_address().into(),
            amount_wei: 70,
            at: now - Duration::hours(2),
            action_kind: ActionKind::Shield,
        },
        // An unshield event in the same window must NOT count toward the shield cap.
        SpendEvent {
            agent_key_id,
            chain_id: 56,
            asset: AssetId::Erc20(railgun_token()),
            recipient: addr("0x2000000000000000000000000000000000000000").into(),
            amount_wei: 1_000_000,
            at: now - Duration::hours(1),
            action_kind: ActionKind::Unshield,
        },
    ];

    let allowed = engine.evaluate(
        &[policy.clone()],
        &PolicyAttachment::AllPolicies,
        &shield_action(30),
        &history,
        agent_key_id,
        now,
    );
    assert!(allowed.is_ok(), "70 + 30 == 100, exact fit must allow");

    let denied = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &shield_action(31),
        &history,
        agent_key_id,
        now,
    );
    assert!(matches!(
        denied,
        Err(PolicyError::WindowLimitExceeded { .. })
    ));
}

#[test]
fn daily_max_unshield_amount_aggregates_unshield_and_private_transfer() {
    let engine = PolicyEngine::default();
    let policy = railgun_amount_policy(PolicyType::DailyMaxUnshieldAmount, 200);
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();

    let history = vec![
        SpendEvent {
            agent_key_id,
            chain_id: 56,
            asset: AssetId::Erc20(railgun_token()),
            recipient: addr("0x2000000000000000000000000000000000000000").into(),
            amount_wei: 100,
            at: now - Duration::hours(3),
            action_kind: ActionKind::Unshield,
        },
        SpendEvent {
            agent_key_id,
            chain_id: 56,
            asset: AssetId::Erc20(railgun_token()),
            recipient: railgun_test_address().into(),
            amount_wei: 75,
            at: now - Duration::hours(1),
            action_kind: ActionKind::PrivateTransfer,
        },
        // A shield event must NOT count toward an unshield-bucket cap.
        SpendEvent {
            agent_key_id,
            chain_id: 56,
            asset: AssetId::Erc20(railgun_token()),
            recipient: railgun_test_address().into(),
            amount_wei: 10_000,
            at: now - Duration::hours(2),
            action_kind: ActionKind::Shield,
        },
    ];

    let denied = engine.evaluate(
        &[policy],
        &PolicyAttachment::AllPolicies,
        &unshield_action(30), // 100 + 75 + 30 = 205 > 200
        &history,
        agent_key_id,
        now,
    );
    assert!(matches!(
        denied,
        Err(PolicyError::WindowLimitExceeded { .. })
    ));
}

#[test]
fn poi_standby_blocks_private_transfer_after_recent_shield() {
    use crate::engine::RAILGUN_POI_STANDBY;
    use vault_domain::ActionKind;
    let engine = PolicyEngine::with_poi_standby(RAILGUN_POI_STANDBY);
    let agent_key_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    // Shield 10 minutes ago — well inside the 1h standby window.
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 56,
        asset: AssetId::Erc20(railgun_token()),
        recipient: railgun_test_address().into(),
        amount_wei: 100,
        at: now - Duration::minutes(10),
        action_kind: ActionKind::Shield,
    }];

    for action in [unshield_action(1), private_transfer_action(1)] {
        let result = engine.evaluate(
            &[policy_all_per_tx(1_000)],
            &PolicyAttachment::AllPolicies,
            &action,
            &history,
            agent_key_id,
            now,
        );
        match result {
            Err(PolicyError::PoiStandbyActive {
                standby_remaining_seconds,
                standby_required_seconds,
            }) => {
                assert_eq!(standby_required_seconds, 3600);
                // 10 minutes elapsed of 60 → ~50 minutes remaining.
                assert!(
                    (standby_remaining_seconds as i64 - 3000).abs() < 60,
                    "remaining {standby_remaining_seconds}s should be ~50 minutes",
                );
            }
            other => panic!("expected PoiStandbyActive, got {other:?}"),
        }
    }
}

#[test]
fn poi_standby_allows_private_transfer_after_window_lapses() {
    use crate::engine::RAILGUN_POI_STANDBY;
    use vault_domain::ActionKind;
    let engine = PolicyEngine::with_poi_standby(RAILGUN_POI_STANDBY);
    let agent_key_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    // Shield 2 hours ago — comfortably outside the 1h standby window.
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 56,
        asset: AssetId::Erc20(railgun_token()),
        recipient: railgun_test_address().into(),
        amount_wei: 100,
        at: now - Duration::hours(2),
        action_kind: ActionKind::Shield,
    }];

    let result = engine.evaluate(
        &[policy_all_per_tx(1_000)],
        &PolicyAttachment::AllPolicies,
        &private_transfer_action(1),
        &history,
        agent_key_id,
        now,
    );
    assert!(
        result.is_ok(),
        "stale shield must not gate the next private-transfer: {result:?}",
    );
}

#[test]
fn poi_standby_does_not_gate_shield_or_plain_transfer() {
    use crate::engine::RAILGUN_POI_STANDBY;
    use vault_domain::ActionKind;
    let engine = PolicyEngine::with_poi_standby(RAILGUN_POI_STANDBY);
    let agent_key_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    // Recent shield inside the standby window.
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 56,
        asset: AssetId::Erc20(railgun_token()),
        recipient: railgun_test_address().into(),
        amount_wei: 100,
        at: now - Duration::minutes(15),
        action_kind: ActionKind::Shield,
    }];

    // Back-to-back shields are fine — PoI gates the outflow side only.
    let shield_again = engine.evaluate(
        &[policy_all_per_tx(1_000)],
        &PolicyAttachment::AllPolicies,
        &shield_action(1),
        &history,
        agent_key_id,
        now,
    );
    assert!(
        shield_again.is_ok(),
        "shield must not gate a follow-up shield"
    );

    // Plain (non-Railgun) ERC-20 transfer must also be unaffected.
    let transfer = AgentAction::Transfer {
        chain_id: 56,
        token: railgun_token(),
        to: addr("0x2000000000000000000000000000000000000000"),
        amount_wei: 1,
    };
    let plain = engine.evaluate(
        &[policy_all_per_tx(1_000)],
        &PolicyAttachment::AllPolicies,
        &transfer,
        &history,
        agent_key_id,
        now,
    );
    assert!(
        plain.is_ok(),
        "PoI standby must not affect non-Railgun actions"
    );
}

#[test]
fn poi_standby_disabled_engine_keeps_legacy_behaviour() {
    // Tests that don't enable the standby (the default constructor) must
    // continue to allow private-transfer immediately after a shield. This
    // protects fixtures that pre-date the standby feature.
    use vault_domain::ActionKind;
    let engine = PolicyEngine::default();
    let agent_key_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: 56,
        asset: AssetId::Erc20(railgun_token()),
        recipient: railgun_test_address().into(),
        amount_wei: 100,
        at: now - Duration::seconds(1),
        action_kind: ActionKind::Shield,
    }];

    let result = engine.evaluate(
        &[policy_all_per_tx(1_000)],
        &PolicyAttachment::AllPolicies,
        &private_transfer_action(1),
        &history,
        agent_key_id,
        now,
    );
    assert!(
        result.is_ok(),
        "default engine must not gate by PoI standby: {result:?}",
    );
}

#[test]
fn transfer_per_tx_spending_policy_inherits_to_railgun_actions() {
    let engine = PolicyEngine::default();
    // A regular per-tx spending policy capped at 50 — applies to all spend
    // actions including the new Railgun variants without any explicit opt-in.
    let policy = policy_all_per_tx(50);

    for action in [
        shield_action(51),
        unshield_action(51),
        private_transfer_action(51),
    ] {
        let result = engine.evaluate(
            &[policy.clone()],
            &PolicyAttachment::AllPolicies,
            &action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        );
        assert!(
            matches!(result, Err(PolicyError::PerTxLimitExceeded { .. })),
            "expected inherited per-tx denial for {action:?}",
        );
    }
}

#[test]
fn manual_approval_does_not_mask_daily_cap() {
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
        action_kind: ActionKind::Other,
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
    let engine = PolicyEngine::default();
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
    assert!(matches!(
        explanation.decision,
        PolicyDecision::Deny(PolicyError::ManualApprovalRequired {
            policy_id,
            min_amount_wei: Some(10),
            max_amount_wei: 10_000,
            requested_amount_wei: 5_000,
        }) if policy_id == manual_policy.id
    ));
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

#[test]
fn eip712_manual_approval_does_not_mask_deny_policy() {
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
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
fn eip712_allow_policy_denies_permit2_domain_for_any_primary_type() {
    let engine = PolicyEngine::default();
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
        Err(PolicyError::Eip712ValueBearingTypeDenied {
            policy_id,
            ref primary_type,
        }) if policy_id == policy.id && primary_type == "Mail"
    ));
}

#[test]
fn eip712_allow_policy_fails_closed_on_unparseable_typed_data() {
    let engine = PolicyEngine::default();
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
    let engine = PolicyEngine::default();
    let policy =
        SpendingPolicy::new_eip712_signing(1, ApprovalType::ManualApproval, EntityScope::All)
            .expect("policy");
    let action = eip712_action_with(1, "PermitSingle", PERMIT2_CHECKSUMMED);

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
    let engine = PolicyEngine::default();
    // The allow policy has the higher priority, so it is evaluated first.
    let allow = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("allow policy");
    let manual =
        SpendingPolicy::new_eip712_signing(2, ApprovalType::ManualApproval, EntityScope::All)
            .expect("manual policy");
    let policies = [allow.clone(), manual.clone()];

    for action in [
        eip712_action_with(1, "PermitSingle", PERMIT2_CHECKSUMMED),
        eip712_action_with(1, "Mail", PERMIT2_CHECKSUMMED),
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
                PolicyDecision::Deny(PolicyError::Eip712ManualApprovalRequired {
                    policy_id: Some(policy_id),
                    ..
                }) if *policy_id == manual.id
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
        &eip712_action_with(1, "PermitSingle", PERMIT2_CHECKSUMMED),
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
        &eip712_action_with(1, "PermitSingle", PERMIT2_CHECKSUMMED),
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
fn typed_permit2_action_is_unaffected_by_eip712_value_bearing_denylist() {
    // The typed Permit2 action is evaluated by the spending policies, not the
    // eip712 path, so it keeps working with amount scoping intact.
    let engine = PolicyEngine::default();
    let policy = policy_all_per_tx(1_000);
    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: addr(PERMIT2_CHECKSUMMED),
            token: addr("0x3000000000000000000000000000000000000000"),
            spender: addr("0x4000000000000000000000000000000000000000"),
            amount_wei: 500,
            expiration: 1_000,
            nonce: 0,
            sig_deadline: 1_000,
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

const TEMPO_TOKEN: &str = "0x20c0000000000000000000000000000000000001";
const TEMPO_PAYEE: &str = "0x7777777777777777777777777777777777777777";
const TEMPO_PAYER: &str = "0x1111111111111111111111111111111111111111";

fn tempo_open_authorization(deposit_wei: u128) -> TempoSessionOpenTransaction {
    TempoSessionOpenTransaction {
        chain_id: TEMPO_MAINNET_CHAIN_ID,
        escrow_contract: addr(TEMPO_MAINNET_ESCROW_CONTRACT),
        token: addr(TEMPO_TOKEN),
        recipient: addr(TEMPO_PAYEE),
        payer: addr(TEMPO_PAYER),
        authorized_signer: addr(TEMPO_PAYER),
        salt_hex: format!("0x{}", "5a".repeat(32)),
        deposit_wei,
        tx: TempoTxParams {
            nonce: 0,
            nonce_key: None,
            gas_limit: 400_000,
            max_fee_per_gas_wei: 20_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000,
            valid_before: None,
            valid_after: None,
            fee_token: Some(addr(TEMPO_TOKEN)),
            fee_payer: false,
        },
    }
}

fn tempo_voucher_action(cumulative_amount_wei: u128) -> AgentAction {
    let open = tempo_open_authorization(1_000_000);
    let channel_id = open.channel_id().expect("channel id");
    AgentAction::TempoSessionVoucher {
        authorization: TempoSessionVoucher {
            chain_id: open.chain_id,
            escrow_contract: open.escrow_contract,
            token: open.token,
            recipient: open.recipient,
            payer: open.payer,
            authorized_signer: open.authorized_signer,
            salt_hex: open.salt_hex,
            channel_id_hex: format!(
                "0x{}",
                channel_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            cumulative_amount_wei,
        },
    }
}

fn tempo_spend_history(
    agent_key_id: Uuid,
    now: OffsetDateTime,
    amount_wei: u128,
) -> Vec<SpendEvent> {
    vec![SpendEvent {
        agent_key_id,
        chain_id: TEMPO_MAINNET_CHAIN_ID,
        asset: AssetId::Erc20(addr(TEMPO_TOKEN)),
        recipient: addr(TEMPO_PAYEE).into(),
        amount_wei,
        at: now - Duration::minutes(5),
        action_kind: ActionKind::Other,
    }]
}

#[test]
fn tempo_voucher_per_tx_limit_uses_full_cumulative_amount() {
    let engine = PolicyEngine::default();
    let now = OffsetDateTime::now_utc();
    let policies = [policy_all_per_tx(500)];

    let result = engine.evaluate(
        &policies,
        &PolicyAttachment::AllPolicies,
        &tempo_voucher_action(501),
        &[],
        Uuid::new_v4(),
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::PerTxLimitExceeded {
            requested_amount_wei: 501,
            ..
        })
    ));
    assert!(engine
        .evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &tempo_voucher_action(500),
            &[],
            Uuid::new_v4(),
            now,
        )
        .is_ok());
}

#[test]
fn tempo_voucher_skips_window_limits_but_open_does_not() {
    let engine = PolicyEngine::default();
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let policies = [
        SpendingPolicy::new(
            1,
            PolicyType::DailyMaxSpending,
            1_000,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("daily"),
        SpendingPolicy::new(
            2,
            PolicyType::WeeklyMaxSpending,
            1_000,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("weekly"),
        SpendingPolicy::new(
            3,
            PolicyType::DailyMaxTxCount,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("count"),
    ];
    // The deposit that funded the channel already used the full window budget.
    let history = tempo_spend_history(agent_key_id, now, 1_000);

    assert!(engine
        .evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &tempo_voucher_action(900),
            &history,
            agent_key_id,
            now,
        )
        .is_ok());

    let open = AgentAction::TempoSessionOpenTransaction {
        authorization: tempo_open_authorization(1),
    };
    assert!(matches!(
        engine.evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &open,
            &history,
            agent_key_id,
            now,
        ),
        Err(PolicyError::WindowLimitExceeded { .. })
    ));
}

#[test]
fn tempo_voucher_still_honors_manual_approval() {
    let engine = PolicyEngine::default();
    let now = OffsetDateTime::now_utc();
    let manual = SpendingPolicy::new_manual_approval(
        1,
        100,
        u128::MAX,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual");
    let result = engine.evaluate(
        &[manual],
        &PolicyAttachment::AllPolicies,
        &tempo_voucher_action(150),
        &[],
        Uuid::new_v4(),
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::ManualApprovalRequired { .. })
    ));
}
