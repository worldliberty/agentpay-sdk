//! EVM read helpers: `RpcChainInfo`, `RpcBlockNumber`, `RpcBalance`,
//! `RpcNonce`, `RpcFees`, `RpcGasEstimate`, `RpcTx`, `RpcReceipt`, `RpcCode`.
//!
//! They read the chain through the configured `rpc_url` of an EVM chain
//! (`network`, default `default_network`), after checking that the endpoint
//! reports the configured chain id. They sign nothing and change nothing.
//! Every one has the same access and errors:
//!
//! | | |
//! |---|---|
//! | Access | payments client allowlist |
//! | Auth | agent token, verified by the signer daemon |
//! | Side effects | none |
//! | Idempotent | yes (results follow the chain) |
//!
//! **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
//! `InvalidRequest` (unknown or non-EVM network, no `rpc_url`, bad
//! argument), `ChainRpc` (endpoint unreachable, failed, or on another chain).
//!
//! `uint256` values that may exceed `u128` (balances, transaction values) are
//! base-10 strings like the `*_wei` amounts.

use agentpay_domain::u128_as_decimal_string;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::evm::{EvmAsset, EvmReceipt};
use crate::auth::AgentAuth;
use crate::types::{DecimalU128, EvmAddress};

/// Parameters of `RpcChainInfo`, `RpcBlockNumber`, and `RpcFees`.
///
/// - `RpcChainInfo` and `RpcBlockNumber` return
///   [`EvmChainInfo`](crate::payments::PaymentsRpcResponse::EvmChainInfo):
///   the chain id the endpoint reports and its latest block number.
/// - `RpcFees` returns [`EvmFees`](crate::payments::PaymentsRpcResponse::EvmFees):
///   `eth_gasPrice` and, on EIP-1559 chains, the estimate the transaction
///   methods use.
///
/// `RpcChainInfo` request and response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcChainInfo.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcChainInfo.response.json")]
/// ```
///
/// `RpcBlockNumber`:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcBlockNumber.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcBlockNumber.response.json")]
/// ```
///
/// `RpcFees`:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcFees.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcFees.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmNetworkParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
}

/// Parameters of `RpcNonce` and `RpcCode`.
///
/// - `RpcNonce` returns [`EvmNonce`](crate::payments::PaymentsRpcResponse::EvmNonce):
///   the account's pending transaction count.
/// - `RpcCode` returns [`EvmCode`](crate::payments::PaymentsRpcResponse::EvmCode):
///   the code at the address (`"0x"` for a plain account).
///
/// `RpcNonce` request and response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcNonce.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcNonce.response.json")]
/// ```
///
/// `RpcCode`:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcCode.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcCode.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmAccountParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Account; default the agent's wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub address: Option<EvmAddress>,
}

/// Parameters of `RpcBalance`; returns
/// [`EvmBalance`](crate::payments::PaymentsRpcResponse::EvmBalance).
///
/// `asset` is a token key or ERC-20 contract address; without it the native
/// coin's balance is returned. Decimals resolve as for `Transfer`.
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcBalance.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcBalance.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmBalanceParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Account; default the agent's wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub address: Option<EvmAddress>,
    /// Token key or ERC-20 contract; default the native coin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub asset: Option<String>,
}

/// Parameters of `RpcGasEstimate`; returns
/// [`EvmGasEstimate`](crate::payments::PaymentsRpcResponse::EvmGasEstimate)
/// from `eth_estimateGas`.
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcGasEstimate.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcGasEstimate.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmGasEstimateParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Sender; default the agent's wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub from: Option<EvmAddress>,
    /// Recipient or contract.
    pub to: EvmAddress,
    /// Native value in wei (default `"0"`).
    #[serde(default, with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub value_wei: u128,
    /// Calldata as `0x`-prefixed hex (default `"0x"`).
    #[serde(default = "empty_calldata")]
    pub data_hex: String,
}

fn empty_calldata() -> String {
    "0x".to_string()
}

/// Parameters of `RpcTx` and `RpcReceipt`.
///
/// - `RpcTx` returns
///   [`EvmTransactionLookup`](crate::payments::PaymentsRpcResponse::EvmTransactionLookup).
/// - `RpcReceipt` returns
///   [`EvmReceiptLookup`](crate::payments::PaymentsRpcResponse::EvmReceiptLookup).
///
/// Either is `null` when the node does not know the transaction (yet).
///
/// `RpcTx` request and response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcTx.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcTx.response.json")]
/// ```
///
/// `RpcReceipt`:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcReceipt.request.json")]
/// ```
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/RpcReceipt.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmTxHashParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Transaction hash, `0x` + 64 hex characters.
    pub tx_hash: String,
}

/// `RpcChainInfo` / `RpcBlockNumber` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmChainInfo {
    /// Chain key.
    pub network: String,
    /// Chain id reported by the endpoint (equal to the configured one).
    pub chain_id: u64,
    /// Latest block number.
    pub block_number: u64,
}

/// `RpcBalance` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmBalance {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// The account.
    pub address: EvmAddress,
    /// The asset.
    pub asset: EvmAsset,
    /// Balance in the smallest unit (base-10 `uint256`).
    pub balance_wei: String,
    /// Balance in whole units, without trailing zeros (`"1.5"`, `"0"`).
    pub balance: String,
}

/// `RpcNonce` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmNonce {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// The account.
    pub address: EvmAddress,
    /// Pending transaction count (the next nonce the chain expects).
    pub nonce: u64,
}

/// `RpcFees` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmFees {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// `eth_gasPrice` in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub gas_price_wei: u128,
    /// Estimated `maxFeePerGas`; `null` when the chain has no base fee.
    #[serde(with = "u128_as_decimal_string::option")]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    pub max_fee_per_gas_wei: Option<u128>,
    /// Estimated `maxPriorityFeePerGas`; `null` when the chain has no base fee.
    #[serde(with = "u128_as_decimal_string::option")]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    pub max_priority_fee_per_gas_wei: Option<u128>,
}

/// `RpcGasEstimate` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmGasEstimate {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// Estimated gas limit.
    pub gas_limit: u64,
}

/// A transaction as the node reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmTransactionInfo {
    /// Transaction hash.
    pub tx_hash: String,
    /// Block number; `null` while pending.
    pub block_number: Option<u64>,
    /// Sender.
    pub from: EvmAddress,
    /// Recipient; `null` for a contract creation.
    pub to: Option<EvmAddress>,
    /// Nonce.
    pub nonce: u64,
    /// Native value in wei (base-10 `uint256`).
    pub value_wei: String,
    /// Calldata, `0x`-prefixed hex.
    pub input_hex: String,
    /// Gas limit.
    pub gas_limit: u64,
    /// Transaction type (`0` legacy, `2` EIP-1559, ...).
    pub tx_type: u8,
    /// Chain id in the transaction; `null` for pre-EIP-155 legacy transactions.
    pub chain_id: Option<u64>,
}

/// `RpcTx` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmTransactionLookup {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// The transaction; `null` when the node does not know it.
    pub transaction: Option<EvmTransactionInfo>,
}

/// `RpcReceipt` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmReceiptLookup {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// The receipt; `null` while the transaction is pending or unknown.
    pub receipt: Option<EvmReceipt>,
}

/// `RpcCode` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmCode {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// The account.
    pub address: EvmAddress,
    /// Code, `0x`-prefixed hex; `"0x"` for an account without code.
    pub code_hex: String,
}
