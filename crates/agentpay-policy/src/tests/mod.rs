use std::collections::BTreeSet;
use std::str::FromStr;

use agentpay_domain::{
    AgentAction, ApprovalType, AssetId, BroadcastTx, Eip3009Transfer, Eip712TypedData, EntityScope,
    EvmAddress, PolicyAttachment, PolicyType, SolanaAddress, SolanaNonceAccountCreate,
    SolanaSplTransfer, SpendEvent, SpendingPolicy, TempoSessionV2CloseAuthorization,
    TempoSessionV2OpenTransaction, TempoSessionV2Voucher, TempoTxParams, SOLANA_DEVNET_CHAIN_ID,
    SOLANA_MAINNET_CHAIN_ID, SOLANA_TESTNET_CHAIN_ID, TEMPO_MAINNET_CHAIN_ID,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::engine::{
    enforce_calldata_bytes_limit, enforce_priority_fee_limit, increment_counter_or_mark_overflow,
};
use crate::{PolicyDecision, PolicyEngine, PolicyError};

mod eip712;
mod explain;
mod limits;
mod manual_approval;
mod over_limit;
mod permit2;
mod scope;
mod solana_payment;
mod tempo;

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
            token_program: agentpay_domain::SolanaTokenProgram::Token,
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
