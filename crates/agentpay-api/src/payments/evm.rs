//! EVM payment methods: `Transfer`, `TransferNative`, `Approve`, `Broadcast`,
//! `SignTypedData`, and `ResumeApproved`.
//!
//! # Network and asset
//!
//! `network` is a chain key from the configuration (`"bsc"`, `"eth"`, ...) and
//! `asset` a token key (`"usd1"`) or an ERC-20 contract address. Both are
//! optional: an omitted `network` is the configuration's `default_network`
//! and an omitted `asset` its `default_asset` (`bsc` and `usd1` in the
//! built-in configuration). The chain must be an EVM chain with an `rpc_url`
//! whenever the method talks to the network.
//!
//! # Amounts
//!
//! `amount` is a positive decimal string in whole token units (`"1.5"`), with
//! at most as many fractional digits as the token has decimals. Decimals come
//! from the configuration; for an ERC-20 contract that is not configured, the
//! service reads `decimals()` and `symbol()` from the chain. Native coins use
//! the configured native deployment for the chain, else 18 decimals. Raw
//! values (`*_wei`) are base-10 strings in the smallest unit.
//!
//! # Sign only or send
//!
//! | Method | `broadcast: false` (default) | `broadcast: true` |
//! |---|---|---|
//! | `Transfer`, `TransferNative`, `Approve` | the signer daemon signs the typed action (`Transfer`, `TransferNative`, `Approve`) under the agent's policies and returns an [`EvmSignatureResult`]; no transaction and no network access (except a token-metadata lookup) | the service builds an EIP-1559 transaction, has it signed as a `BroadcastTx`, verifies it, sends it, and returns an [`EvmTransactionResult`] |
//! | `Broadcast` | the transaction is built, signed, and verified but not sent; `raw_tx_hex` can be sent later | as for the transfers |
//!
//! Policies apply either way, and a signature counts toward spending limits
//! whether or not it is ever sent.
//!
//! # The transaction pipeline (`broadcast: true` and `Broadcast`)
//!
//! 1. Connect to the chain's `rpc_url` and check that `eth_chainId` equals the
//!    configured `chain_id`; a mismatch fails with `ChainRpc` before anything is signed.
//! 2. Nonce: the explicit `nonce`, else the account's pending nonce. The
//!    signer daemon reserves it (`ReserveNonce`; exactly the given one when
//!    `nonce` is set, otherwise the lowest free nonce at or above it).
//! 3. Gas: the explicit `gas_limit`, else `eth_estimateGas`. Fees: the explicit
//!    values, else an EIP-1559 estimate from `eth_feeHistory` (falling back to
//!    `eth_gasPrice` on chains without base fees).
//! 4. Sign the `BroadcastTx` through the signer daemon. A policy denial fails
//!    with `Signer` and releases the nonce reservation.
//! 5. Verify the signed transaction before anything else: it must be an
//!    EIP-1559 transaction whose recovered signer is the agent's wallet and
//!    whose chain id, nonce, recipient, value, calldata, gas limit, and fees
//!    equal the request, with an empty access list and a hash that matches.
//!    Otherwise the call fails with `SignedTransactionMismatch` and nothing is sent.
//! 6. Send it with `eth_sendRawTransaction` (never retried; a node answer of
//!    "already known" counts as sent) and, with `wait_for_receipt`, poll for
//!    the receipt every 2 seconds for up to `receipt_timeout_secs` (default
//!    30, capped at 120).
//!
//! Signing consumes the nonce. When the signed transaction certainly never
//! reached the network (step 5 failed, the node answered the send with a
//! JSON-RPC error, or the connection to it could not be established), the
//! service hands the nonce back to the signer daemon (`ReleaseSignedNonce`),
//! so the next payment uses it instead of leaving a gap. After an ambiguous
//! failure (a timeout, a dropped connection, an HTTP error from a proxy) the
//! node may have the transaction, so the nonce stays used. Either way the
//! payment still counts toward the spending limits.
//!
//! # Manual approval
//!
//! When a policy holds the signature for an operator, the method waits up to
//! `approval_wait_secs` (default 0, capped at 600) for a decision. If none
//! arrives, it returns [`PaymentsRpcResponse::ManualApprovalPending`]
//! instead of failing. The service stores the exact action it asked to have
//! signed (a `0600` file in its state directory) and releases the nonce
//! reservation. After an operator approves the request, call
//! `ResumeApproved` with the `approval_request_id`: the service resends the
//! identical action (same payload bytes, so the approval applies), reserving
//! the same nonce again, and continues where the original call stopped.
//!
//! [`PaymentsRpcResponse::ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending

use agentpay_domain::u128_as_decimal_string;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::AgentAuth;
use crate::types::{AgentAction, DecimalU128, EvmAddress};

/// Options shared by `Transfer`, `TransferNative`, `Approve`, and `Broadcast`.
///
/// Its fields appear directly in the method's `params` (they are flattened).
/// The nonce, gas, fee, and receipt fields apply only to a transaction:
/// `Transfer`, `TransferNative`, and `Approve` reject them without
/// `broadcast: true`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmTxOptions {
    /// Send the transaction (`true`) or only sign (`false`, the default). See
    /// the [module documentation](self).
    #[serde(default)]
    pub broadcast: bool,
    /// After sending, wait for the receipt (default `false`).
    #[serde(default)]
    pub wait_for_receipt: bool,
    /// How long to wait for the receipt, in seconds (default 30, capped at 120).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub receipt_timeout_secs: Option<u64>,
    /// Explicit nonce; the signer daemon must be able to reserve exactly this
    /// nonce. Default: the account's pending nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub nonce: Option<u64>,
    /// Explicit gas limit. Default: `eth_estimateGas`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gas_limit: Option<u64>,
    /// Explicit `maxFeePerGas` in wei. Default: estimated.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_fee_per_gas_wei: Option<u128>,
    /// Explicit `maxPriorityFeePerGas` in wei. Default: estimated.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_priority_fee_per_gas_wei: Option<u128>,
    /// How long to wait for an operator when a policy requires manual
    /// approval, in seconds (default 0, capped at 600). Use a response timeout
    /// longer than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub approval_wait_secs: Option<u64>,
}

/// `Transfer`: send ERC-20 tokens.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`EvmSignature`] (sign only), [`EvmTransaction`] (`broadcast`), or [`ManualApprovalPending`] |
/// | Side effects | a signature (spend recorded by the signer daemon); with `broadcast`, a nonce reservation and an on-chain transaction; a pending-approval record |
/// | Idempotent | no: every call is a new payment |
///
/// The asset must be an ERC-20 deployment on the network (use
/// `TransferNative` for the native coin). Calldata is
/// `transfer(to, amount_wei)` sent to the token contract with zero value.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`
/// (policy denial, rejected approval, ...), `InvalidRequest`, `ChainRpc`,
/// `SignedTransactionMismatch`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/Transfer.request.json")]
/// ```
///
/// Response (broadcast and confirmed):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/Transfer.response.json")]
/// ```
///
/// [`EvmSignature`]: crate::payments::PaymentsRpcResponse::EvmSignature
/// [`EvmTransaction`]: crate::payments::PaymentsRpcResponse::EvmTransaction
/// [`ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TransferParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Token key or ERC-20 contract address; default `default_asset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub asset: Option<String>,
    /// Recipient.
    pub to: EvmAddress,
    /// Amount in whole token units, for example `"1.5"`.
    pub amount: String,
    /// Transaction options.
    #[serde(flatten)]
    #[ts(flatten)]
    pub options: EvmTxOptions,
}

/// `TransferNative`: send the chain's native coin (BNB, ETH, ...).
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`EvmSignature`] (sign only), [`EvmTransaction`] (`broadcast`), or [`ManualApprovalPending`] |
/// | Side effects | as for `Transfer` |
/// | Idempotent | no |
///
/// The transaction sends `amount` to `to` with empty calldata.
///
/// **Errors:** as for `Transfer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/TransferNative.request.json")]
/// ```
///
/// Response (signed only):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/TransferNative.response.json")]
/// ```
///
/// [`EvmSignature`]: crate::payments::PaymentsRpcResponse::EvmSignature
/// [`EvmTransaction`]: crate::payments::PaymentsRpcResponse::EvmTransaction
/// [`ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct TransferNativeParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Recipient.
    pub to: EvmAddress,
    /// Amount in whole native units, for example `"0.01"`.
    pub amount: String,
    /// Transaction options.
    #[serde(flatten)]
    #[ts(flatten)]
    pub options: EvmTxOptions,
}

/// `Approve`: set an ERC-20 allowance for a spender.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`EvmSignature`] (sign only), [`EvmTransaction`] (`broadcast`), or [`ManualApprovalPending`] |
/// | Side effects | as for `Transfer` |
/// | Idempotent | no |
///
/// Calldata is `approve(spender, amount_wei)` sent to the token contract.
/// Policies see the spender as the recipient.
///
/// **Errors:** as for `Transfer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/Approve.request.json")]
/// ```
///
/// Response (held for an operator):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/Approve.response.json")]
/// ```
///
/// [`EvmSignature`]: crate::payments::PaymentsRpcResponse::EvmSignature
/// [`EvmTransaction`]: crate::payments::PaymentsRpcResponse::EvmTransaction
/// [`ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ApproveParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Token key or ERC-20 contract address; default `default_asset`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub asset: Option<String>,
    /// Spender allowed to move the tokens.
    pub spender: EvmAddress,
    /// Allowance in whole token units.
    pub amount: String,
    /// Transaction options.
    #[serde(flatten)]
    #[ts(flatten)]
    pub options: EvmTxOptions,
}

/// `Broadcast`: sign (and optionally send) an agent-built transaction.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`EvmTransaction`] or [`ManualApprovalPending`] |
/// | Side effects | a nonce reservation and signature; with `broadcast`, an on-chain transaction; a pending-approval record |
/// | Idempotent | no |
///
/// The signer daemon accepts empty calldata (a native transfer of
/// `value_wei`) or a recognized token call (ERC-20 `transfer`/`approve`,
/// TIP-20 `transferWithMemo`, Permit2 `permit`, EIP-3009 `transferWithAuthorization` /
/// `receiveWithAuthorization`) with zero value, and evaluates its policies on
/// the decoded asset, recipient, and amount. Other calldata fails with
/// `Signer` / `InvalidAction`. Without `broadcast`, the verified signed
/// transaction is returned unsent.
///
/// **Errors:** as for `Transfer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/Broadcast.request.json")]
/// ```
///
/// Response (signed, not sent):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/Broadcast.response.json")]
/// ```
///
/// [`EvmTransaction`]: crate::payments::PaymentsRpcResponse::EvmTransaction
/// [`ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BroadcastParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// Chain key; default `default_network`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Recipient or token contract.
    pub to: EvmAddress,
    /// Native value in wei (default `"0"`).
    #[serde(default, with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub value_wei: u128,
    /// Calldata as `0x`-prefixed hex (default `"0x"`).
    #[serde(default = "empty_calldata")]
    pub data_hex: String,
    /// Transaction options.
    #[serde(flatten)]
    #[ts(flatten)]
    pub options: EvmTxOptions,
}

fn empty_calldata() -> String {
    "0x".to_string()
}

/// `SignTypedData`: sign EIP-712 typed data under the agent's policies.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`EvmSignature`] or [`ManualApprovalPending`] |
/// | Side effects | a signature; a pending-approval record |
/// | Idempotent | no |
///
/// `typed_data_json` is the `eth_signTypedData_v4` JSON object as a string;
/// its `domain.chainId` is required. Typed data that no `Eip712Signing`
/// policy covers needs manual approval. The result's `signature_hex` is the
/// 65-byte `r || s || v` signature with `v` = 27 or 28.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
/// `InvalidRequest`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/SignTypedData.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/SignTypedData.response.json")]
/// ```
///
/// [`EvmSignature`]: crate::payments::PaymentsRpcResponse::EvmSignature
/// [`ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SignTypedDataParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// EIP-712 typed data as a JSON string.
    pub typed_data_json: String,
    /// How long to wait for an operator, in seconds (default 0, capped at 600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub approval_wait_secs: Option<u64>,
}

/// `ResumeApproved`: continue a call that returned `ManualApprovalPending`.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token of the agent that made the original call |
/// | Response | what the original call returns: [`EvmSignature`], [`EvmTransaction`], or again [`ManualApprovalPending`] |
/// | Side effects | as for the original call; removes the pending-approval record once the request is decided |
/// | Idempotent | no: a completed resume removes the record |
///
/// The service resends the stored action unchanged. For a transaction it
/// first checks that the stored nonce is still unused on chain and reserves
/// exactly that nonce again; then it verifies, sends, and waits as the
/// original call asked. While the request is still pending the result is
/// `ManualApprovalPending` again. A rejected request fails with `Signer` /
/// `ManualApprovalRejected`. The record is removed once the resume succeeds
/// or fails for good, and kept after `SignerUnavailable`, `ChainRpc`, and `Persistence` errors so
/// the call can be retried. Records of other agents are invisible
/// (`UnknownPendingApproval`).
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`,
/// `UnknownPendingApproval`, `InvalidRequest` (the nonce was used meanwhile),
/// `ChainRpc`, `SignedTransactionMismatch`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/ResumeApproved.request.json")]
/// ```
///
/// Response (the approved `Approve` example, sent):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/evm/ResumeApproved.response.json")]
/// ```
///
/// [`EvmSignature`]: crate::payments::PaymentsRpcResponse::EvmSignature
/// [`EvmTransaction`]: crate::payments::PaymentsRpcResponse::EvmTransaction
/// [`ManualApprovalPending`]: crate::payments::PaymentsRpcResponse::ManualApprovalPending
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ResumeApprovedParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// The `approval_request_id` from `ManualApprovalPending`.
    pub approval_request_id: Uuid,
    /// How long to wait if the request is still pending, in seconds (default
    /// 0, capped at 600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub approval_wait_secs: Option<u64>,
}

/// The asset a payment moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmAsset {
    /// Token key in the configuration; `null` for an unconfigured contract
    /// (its metadata was read from the chain) or an unconfigured native coin.
    pub key: Option<String>,
    /// Ticker symbol; the contract address when the token reports none.
    pub symbol: String,
    /// Decimals of the smallest unit.
    pub decimals: u8,
    /// ERC-20 contract; `null` for the native coin.
    pub token: Option<EvmAddress>,
}

/// What a `Transfer`, `TransferNative`, or `Approve` moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmPayment {
    /// The asset.
    pub asset: EvmAsset,
    /// Recipient (`Transfer`, `TransferNative`) or spender (`Approve`).
    pub counterparty: EvmAddress,
    /// Amount in whole units, as requested (trimmed).
    pub amount: String,
    /// Amount in the asset's smallest unit.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
}

/// A transaction receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmReceipt {
    /// Transaction hash, `0x` + 64 hex characters.
    pub tx_hash: String,
    /// `true` when the transaction succeeded, `false` when it reverted.
    pub success: bool,
    /// Block number; `null` for a pending receipt.
    pub block_number: Option<u64>,
    /// Block hash; `null` for a pending receipt.
    pub block_hash: Option<String>,
    /// Gas used by this transaction.
    pub gas_used: u64,
    /// Price paid per gas, in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub effective_gas_price_wei: u128,
    /// Address of a created contract, if any.
    pub contract_address: Option<EvmAddress>,
}

/// A signed, verified, and possibly sent EIP-1559 transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmTransactionResult {
    /// Chain key.
    pub network: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// What a `Transfer`, `TransferNative`, or `Approve` moves; `null` for `Broadcast`.
    pub payment: Option<EvmPayment>,
    /// The agent's wallet (recovered from the signature).
    pub from: EvmAddress,
    /// Transaction recipient: the token contract for ERC-20 calls.
    pub to: EvmAddress,
    /// Native value in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub value_wei: u128,
    /// Calldata, `0x`-prefixed hex.
    pub data_hex: String,
    /// Nonce.
    pub nonce: u64,
    /// Gas limit.
    pub gas_limit: u64,
    /// `maxFeePerGas` in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub max_fee_per_gas_wei: u128,
    /// `maxPriorityFeePerGas` in wei.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub max_priority_fee_per_gas_wei: u128,
    /// Transaction hash, `0x` + 64 hex characters.
    pub tx_hash: String,
    /// The signed transaction, `0x`-prefixed hex (type `0x02` envelope).
    pub raw_tx_hex: String,
    /// Whether the service sent the transaction.
    pub broadcast: bool,
    /// The receipt, when `wait_for_receipt` found one.
    pub receipt: Option<EvmReceipt>,
    /// `true` when `wait_for_receipt` gave up before the receipt appeared;
    /// the transaction may still be mined.
    pub receipt_timed_out: bool,
}

/// A policy-checked signature that is not a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvmSignatureResult {
    /// Chain key; `null` for typed data.
    pub network: Option<String>,
    /// EVM chain id (the typed data's `domain.chainId`).
    pub chain_id: u64,
    /// What a `Transfer`, `TransferNative`, or `Approve` moves; `null` for typed data.
    pub payment: Option<EvmPayment>,
    /// The signed action. For `Transfer`, `TransferNative`, and `Approve` the
    /// signature covers the action's canonical compact JSON.
    pub action: AgentAction,
    /// For typed data, the 65-byte `r || s || v` signature (`v` = 27 or 28);
    /// otherwise the ASN.1 DER signature. `0x`-prefixed hex.
    pub signature_hex: String,
    /// `r` as `0x`-prefixed hex, when the signer reports it.
    pub r_hex: Option<String>,
    /// `s` as `0x`-prefixed hex, when the signer reports it.
    pub s_hex: Option<String>,
    /// Recovery id (`0` or `1`), when the signer reports it.
    pub v: Option<u64>,
}

/// A call stopped because a policy holds its signature for an operator.
///
/// Approve or reject `approval_request_id` with the signer daemon's
/// `DecideManualApprovalRequest` (for example `agentpay admin
/// approve-manual-approval-request`), then call `ResumeApproved`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ManualApprovalPendingResult {
    /// The approval request in the signer daemon.
    pub approval_request_id: Uuid,
    /// The method that was called, for example `"Transfer"`.
    pub method: String,
    /// Chain key; `null` for typed data.
    pub network: Option<String>,
    /// EVM chain id.
    pub chain_id: u64,
    /// What a `Transfer`, `TransferNative`, or `Approve` moves.
    pub payment: Option<EvmPayment>,
    /// The exact action waiting for approval, as `ResumeApproved` will resend it.
    pub action: AgentAction,
}
