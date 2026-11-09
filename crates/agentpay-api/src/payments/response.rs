//! [`PaymentsRpcResponse`]: the success body of every payments service method.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::{
    ActivityResult, AddTokenResult, EvmBalance, EvmChainInfo, EvmCode, EvmFees, EvmGasEstimate,
    EvmNonce, EvmReceiptLookup, EvmSignatureResult, EvmTransactionLookup, EvmTransactionResult,
    ManualApprovalPendingResult, MppFetchResult, PaymentsConfig, ProxyStartResult,
    ProxyStatusResult, SolanaTransferResult, TokenInfo, X402FetchResult,
};
use super::{
    FundingRequestResult, StatusResult, TelemetryStatusResult, WalletBalanceEntry,
    WalletSummaryResult,
};
use crate::HelloResponse;

/// Successful result of a payments service call, as carried in
/// [`WireResponse::body_json`](crate::WireResponse::body_json) when `ok` is `true`.
///
/// JSON: `{"type": "<Variant>", "data": <payload>}`. Each method documents which
/// variant it returns; clients should reject any other variant as a protocol
/// error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "type", content = "data")]
pub enum PaymentsRpcResponse {
    /// `Hello`: service version and capabilities.
    Hello(HelloResponse),
    /// `GetConfig` / `SetConfig`: the stored configuration.
    Config(PaymentsConfig),
    /// `TransferSol` / `TransferSpl`: the signed (and possibly broadcast) transfer.
    SolanaTransfer(SolanaTransferResult),
    /// `Transfer` / `TransferNative` / `Approve` with `broadcast`, `Broadcast`:
    /// the signed, verified, and possibly sent transaction.
    EvmTransaction(EvmTransactionResult),
    /// `Transfer` / `TransferNative` / `Approve` without `broadcast`,
    /// `SignTypedData`: a policy-checked signature.
    EvmSignature(EvmSignatureResult),
    /// An EVM method (or `ResumeApproved`) stopped while a policy holds its
    /// signature for an operator; continue with `ResumeApproved`.
    ManualApprovalPending(ManualApprovalPendingResult),
    /// `RpcChainInfo` / `RpcBlockNumber`.
    EvmChainInfo(EvmChainInfo),
    /// `RpcBalance`.
    EvmBalance(EvmBalance),
    /// `RpcNonce`.
    EvmNonce(EvmNonce),
    /// `RpcFees`.
    EvmFees(EvmFees),
    /// `RpcGasEstimate`.
    EvmGasEstimate(EvmGasEstimate),
    /// `RpcTx`.
    EvmTransactionLookup(EvmTransactionLookup),
    /// `RpcReceipt`.
    EvmReceiptLookup(EvmReceiptLookup),
    /// `RpcCode`.
    EvmCode(EvmCode),
    /// `X402Fetch`: the final HTTP response and the x402 payment made.
    X402Response(X402FetchResult),
    /// `MppFetch`: the final HTTP response and the MPP payment made.
    MppResponse(MppFetchResult),
    /// `ProxyStart`: the running proxy and its secret token.
    ProxyStarted(ProxyStartResult),
    /// `ProxyStop` / `ProxyStatus`: the proxy's state.
    ProxyStatus(ProxyStatusResult),
    /// `WalletSummary`: addresses and every configured balance.
    WalletSummary(WalletSummaryResult),
    /// `WalletBalance`: one balance.
    WalletBalance(WalletBalanceEntry),
    /// `FundingRequest`: address, URI, and QR code to fund the wallet.
    FundingRequest(FundingRequestResult),
    /// `Status`: the service's health as seen by the agent.
    Status(StatusResult),
    /// `TelemetryStatus` / `SetTelemetry`: whether telemetry is on.
    TelemetryStatus(TelemetryStatusResult),
    /// `AddToken` (API 1.1): the token entry and the stored configuration.
    TokenAdded(AddTokenResult),
    /// `LookupToken` (API 1.1): the token as read from the chain.
    TokenInfo(TokenInfo),
    /// `Activity` (API 1.1): the agent's recent payments and approval requests.
    Activity(ActivityResult),
}
