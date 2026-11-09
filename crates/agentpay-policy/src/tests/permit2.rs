//! Permit2: a witness permit is a spend by its spender; approving the
//! canonical Permit2 skips spending limits but not fee and gas policies.

use agentpay_domain::{Permit2Permission, Permit2Witness, Permit2WitnessTransfer, PERMIT2_ADDRESS};
use alloy_primitives::{hex, Address, U256};
use alloy_sol_types::{sol, SolCall};

use super::*;

sol! {
    function approve(address spender, uint256 value);
}

const TOKEN: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const SPENDER: &str = "0x1111111111111111111111111111111111111111";

fn evaluate(policies: &[SpendingPolicy], action: &AgentAction) -> Result<(), PolicyError> {
    PolicyEngine
        .evaluate(
            policies,
            &PolicyAttachment::AllPolicies,
            action,
            &[],
            Uuid::new_v4(),
            OffsetDateTime::now_utc(),
        )
        .map(|_| ())
}

fn approve_broadcast(spender: &str) -> AgentAction {
    let data = approveCall {
        spender: Address::from_str(spender).expect("address"),
        value: U256::from(u128::MAX),
    }
    .abi_encode();
    AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: addr(TOKEN),
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(data)),
            gas_limit: 60_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    }
}

fn permit(amounts: &[u128]) -> AgentAction {
    AgentAction::Permit2WitnessTransfer {
        permit: Permit2WitnessTransfer {
            chain_id: 1,
            token: addr(TOKEN),
            permitted: amounts
                .iter()
                .map(|amount_wei| Permit2Permission {
                    amount_wei: *amount_wei,
                })
                .collect(),
            spender: addr(SPENDER),
            nonce: "1".into(),
            deadline: 1_900_000_000,
            witness: Permit2Witness::Challenge {
                challenge_hash: format!("0x{}", "ab".repeat(32)),
            },
        },
    }
}

#[test]
fn approving_permit2_skips_spending_limits_but_not_gas_policies() {
    let approval = approve_broadcast(PERMIT2_ADDRESS);
    assert_eq!(evaluate(&[policy_all_per_tx(100)], &approval), Ok(()));

    // 60k gas at 1 gwei is 6e13 wei.
    let result = evaluate(&[policy_all_per_tx(100), gas_policy(1, 1_000)], &approval);
    assert!(
        matches!(result, Err(PolicyError::GasLimitExceeded { .. })),
        "{result:?}"
    );

    // An agent with no policies is still refused.
    let result = evaluate(&[], &approval);
    assert!(
        matches!(result, Err(PolicyError::NoAttachedPolicies)),
        "{result:?}"
    );
}

#[test]
fn approving_any_other_spender_is_a_spend() {
    let result = evaluate(&[policy_all_per_tx(100)], &approve_broadcast(SPENDER));
    assert!(
        matches!(result, Err(PolicyError::PerTxLimitExceeded { .. })),
        "{result:?}"
    );
}

#[test]
fn a_permit_spends_its_total_and_its_spender_is_the_recipient() {
    assert_eq!(
        evaluate(&[policy_all_per_tx(100)], &permit(&[60, 40])),
        Ok(())
    );
    let result = evaluate(&[policy_all_per_tx(100)], &permit(&[60, 41]));
    assert!(
        matches!(
            result,
            Err(PolicyError::PerTxLimitExceeded {
                requested_amount_wei: 101,
                ..
            })
        ),
        "{result:?}"
    );

    let only = |recipient: &str| {
        SpendingPolicy::new(
            1,
            PolicyType::PerTxMaxSpending,
            1_000,
            EntityScope::Set(BTreeSet::from([addr(recipient)])),
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy")
    };
    assert_eq!(evaluate(&[only(SPENDER)], &permit(&[10])), Ok(()));
    let result = evaluate(
        &[only("0x2222222222222222222222222222222222222222")],
        &permit(&[10]),
    );
    assert!(
        matches!(result, Err(PolicyError::NoApplicablePolicies)),
        "{result:?}"
    );
}

fn approve_permit2_on(chain_id: u64, to: &str, max_fee_per_gas_wei: u128) -> AgentAction {
    let data = approveCall {
        spender: Address::from_str(PERMIT2_ADDRESS).expect("address"),
        value: U256::from(1u8),
    }
    .abi_encode();
    AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id,
            nonce: 0,
            to: addr(to),
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(data)),
            gas_limit: 50_000,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei: max_fee_per_gas_wei,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    }
}

const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";

/// An owner whose only row is USD1 on BSC: a per-payment limit, a fee cap,
/// one transaction a day.
fn usd1_on_bsc() -> Vec<SpendingPolicy> {
    let assets = EntityScope::Set(BTreeSet::from([AssetId::Erc20(addr(USD1))]));
    let bsc = EntityScope::Set(BTreeSet::from([56u64]));
    let row = |priority, policy_type, max| {
        SpendingPolicy::new(
            priority,
            policy_type,
            max,
            EntityScope::All,
            assets.clone(),
            bsc.clone(),
        )
        .expect("policy")
    };
    vec![
        row(1, PolicyType::PerTxMaxSpending, 10),
        row(2, PolicyType::PerTxMaxFeePerGas, 3_000_000_000),
        row(3, PolicyType::DailyMaxTxCount, 1),
    ]
}

/// Audit regression: the approval is matched on its network and token like
/// any other action; only the recipient scope and the amount are waived.
#[test]
fn a_permit2_approval_needs_a_policy_for_its_network_and_token() {
    let policies = usd1_on_bsc();
    assert_eq!(
        evaluate(&policies, &approve_permit2_on(56, USD1, 1_000_000_000)),
        Ok(())
    );
    for (chain, token) in [
        (1, USD1),                                          // a network no row covers
        (56, "0x00000000000000000000000000000000deadbeef"), // a token no row covers
    ] {
        let result = evaluate(&policies, &approve_permit2_on(chain, token, 1_000_000_000));
        assert!(
            matches!(result, Err(PolicyError::NoApplicablePolicies)),
            "chain {chain} token {token}: {result:?}"
        );
    }
}

#[test]
fn a_permit2_approval_obeys_fee_caps_and_the_daily_count() {
    let policies = usd1_on_bsc();
    let result = evaluate(&policies, &approve_permit2_on(56, USD1, 10u128.pow(18)));
    assert!(
        matches!(result, Err(PolicyError::MaxFeePerGasLimitExceeded { .. })),
        "{result:?}"
    );

    let agent = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let used = SpendEvent {
        agent_key_id: agent,
        chain_id: 56,
        asset: AssetId::Erc20(addr(USD1)),
        recipient: agentpay_domain::RecipientId::Evm(addr(SPENDER)),
        amount_wei: 1,
        at: now,
        approval_request_id: None,
    };
    let result = PolicyEngine
        .evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &approve_permit2_on(56, USD1, 1_000_000_000),
            &[used],
            agent,
            now,
        )
        .map(|_| ());
    assert!(
        matches!(result, Err(PolicyError::TxCountLimitExceeded { .. })),
        "{result:?}"
    );
}

#[test]
fn a_manual_approval_row_holds_a_permit2_approval_like_any_payment() {
    // Payments of 1 base unit and more need the owner; the approval moves
    // nothing but is held all the same.
    let manual = SpendingPolicy::new_manual_approval(
        1,
        1,
        u128::MAX,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let result = PolicyEngine.explain(
        &[policy_all_per_tx(100), manual],
        &PolicyAttachment::AllPolicies,
        &approve_permit2_on(56, USD1, 1_000_000_000),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert!(
        matches!(result.decision, PolicyDecision::ManualApproval(_)),
        "{result:?}"
    );
}
