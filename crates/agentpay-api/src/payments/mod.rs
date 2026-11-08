//! The payments service API: [`PaymentsRpcRequest`], [`PaymentsRpcResponse`],
//! and [`WirePaymentsError`].
//!
//! AgentPay runs two local services that share this crate's framing,
//! envelopes, and versioning:
//!
//! - the **signer daemon** (`agentpay-daemon`, root): keys, policies, manual
//!   approvals, and signing ([`crate::rpc`]);
//! - the **payments service** (`agentpay-paymentd`, an unprivileged service
//!   account): chains, RPC endpoints, and payment flows (this module). It
//!   asks the signer daemon for every signature as the calling agent.
//!
//! Clients and agents talk to the payments service; only administration
//! (policies, keys, approvals) goes to the signer daemon directly.
//!
//! # Wire format
//!
//! Identical to the signer daemon: one length-prefixed [`WireRequest`]
//! frame whose `body_json` is a serialized [`PaymentsRpcRequest`], answered by
//! one [`WireResponse`] whose `body_json` is a [`PaymentsRpcResponse`] (`ok`) or
//! a [`WirePaymentsError`] (not `ok`).
//!
//! # Authentication
//!
//! Every method except `Hello` and the read-only `LookupToken` carries
//! `auth` ([`AgentAuth`]): the caller's
//! agent key id and bearer token. The service forwards them to the signer
//! daemon's `AuthenticateAgent` for every request (nothing is cached, so
//! revoking or rotating a token takes effect at once) and then acts as that
//! agent: every signature it requests is checked against that agent's
//! policies. The service never stores tokens.
//!
//! | Method | Auth | Response |
//! |---|---|---|
//! | `Hello` | none | `Hello` |
//! | [`GetConfig`](GetConfigParams) | agent token | `Config` |
//! | [`SetConfig`](SetConfigParams) | agent token | `Config` |
//! | [`TransferSol`](TransferSolParams) | agent token | `SolanaTransfer`, `ManualApprovalPending` |
//! | [`TransferSpl`](TransferSplParams) | agent token | `SolanaTransfer`, `ManualApprovalPending` |
//! | [`Transfer`](TransferParams) | agent token | `EvmSignature`, `EvmTransaction`, `ManualApprovalPending` |
//! | [`TransferNative`](TransferNativeParams) | agent token | `EvmSignature`, `EvmTransaction`, `ManualApprovalPending` |
//! | [`Approve`](ApproveParams) | agent token | `EvmSignature`, `EvmTransaction`, `ManualApprovalPending` |
//! | [`Broadcast`](BroadcastParams) | agent token | `EvmTransaction`, `ManualApprovalPending` |
//! | [`SignTypedData`](SignTypedDataParams) | agent token | `EvmSignature`, `ManualApprovalPending` |
//! | [`ResumeApproved`](ResumeApprovedParams) | agent token | as the resumed call |
//! | [`RpcChainInfo`](EvmNetworkParams), [`RpcBlockNumber`](EvmNetworkParams) | agent token | `EvmChainInfo` |
//! | [`RpcBalance`](EvmBalanceParams) | agent token | `EvmBalance` |
//! | [`RpcNonce`](EvmAccountParams) | agent token | `EvmNonce` |
//! | [`RpcFees`](EvmNetworkParams) | agent token | `EvmFees` |
//! | [`RpcGasEstimate`](EvmGasEstimateParams) | agent token | `EvmGasEstimate` |
//! | [`RpcTx`](EvmTxHashParams) | agent token | `EvmTransactionLookup` |
//! | [`RpcReceipt`](EvmTxHashParams) | agent token | `EvmReceiptLookup` |
//! | [`RpcCode`](EvmAccountParams) | agent token | `EvmCode` |
//! | [`X402Fetch`](X402FetchParams) | agent token | `X402Response` |
//! | [`MppFetch`](MppFetchParams) | agent token | `MppResponse` |
//! | [`ProxyStart`](ProxyStartParams) | agent token | `ProxyStarted` |
//! | [`ProxyStop`](ProxyParams), [`ProxyStatus`](ProxyParams) | agent token | `ProxyStatus` |
//! | [`WalletSummary`](WalletSummaryParams) | agent token | `WalletSummary` |
//! | [`WalletBalance`](WalletBalanceParams) | agent token | `WalletBalance` |
//! | [`FundingRequest`](FundingRequestParams) | agent token | `FundingRequest` |
//! | [`Status`](StatusParams) | agent token | `Status` |
//! | [`TelemetryStatus`](TelemetryStatusParams), [`SetTelemetry`](SetTelemetryParams) | agent token | `TelemetryStatus` |
//! | [`AddToken`](AddTokenParams) (API 1.1) | agent token | `TokenAdded` |
//! | [`LookupToken`](LookupTokenParams) (API 1.1) | none | `TokenInfo` |
//! | [`Activity`](ActivityParams) (API 1.1) | agent token | `Activity` |
//!
//! [`WireRequest`]: crate::WireRequest
//! [`WireResponse`]: crate::WireResponse

pub mod activity;
pub mod config;
mod error;
pub mod evm;
pub mod evm_rpc;
pub mod http;
pub mod mpp;
pub mod proxy;
mod response;
pub mod solana;
pub mod status;
pub mod telemetry;
pub mod wallet;
pub mod x402;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub use activity::{
    ActivityApproval, ActivityAsset, ActivityParams, ActivityResult, ActivitySpend,
};
pub use config::{
    AddTokenParams, AddTokenResult, ChainFamily, ChainProfile, GetConfigParams, LookupTokenParams,
    PaymentsConfig, SetConfigParams, TokenChainProfile, TokenInfo, TokenLimits, TokenProfile,
};
pub use error::WirePaymentsError;
pub use evm::{
    ApproveParams, BroadcastParams, EvmAsset, EvmPayment, EvmReceipt, EvmSignatureResult,
    EvmTransactionResult, EvmTxOptions, ManualApprovalPendingResult, ResumeApprovedParams,
    SignTypedDataParams, TransferNativeParams, TransferParams,
};
pub use evm_rpc::{
    EvmAccountParams, EvmBalance, EvmBalanceParams, EvmChainInfo, EvmCode, EvmFees, EvmGasEstimate,
    EvmGasEstimateParams, EvmNetworkParams, EvmNonce, EvmReceiptLookup, EvmTransactionInfo,
    EvmTransactionLookup, EvmTxHashParams,
};
pub use http::{HttpBody, HttpHeader, HttpRequest, HttpResponse};
pub use mpp::{MppCharge, MppFetchParams, MppFetchResult, MppPayment, MppSession};
pub use proxy::{ProxyParams, ProxyStartParams, ProxyStartResult, ProxyStatusResult};
pub use response::PaymentsRpcResponse;
pub use solana::{
    SolanaAmount, SolanaBroadcast, SolanaDurableNonce, SolanaNonceMode, SolanaTransferDetails,
    SolanaTransferOptions, SolanaTransferResult, SolanaTxStatus, TransferSolParams,
    TransferSplParams,
};
pub use status::{
    AgentStatus, ChainStatus, ConfigStatus, ServiceStatus, SignerStatus, StatusParams,
    StatusResult, StatusWarning, StatusWarningCode,
};
pub use telemetry::{
    SetTelemetryParams, TelemetryDisabledReason, TelemetryStatusParams, TelemetryStatusResult,
};
pub use wallet::{
    FundingGasHint, FundingQr, FundingRequestParams, FundingRequestResult, WalletAssetKind,
    WalletBalanceEntry, WalletBalanceParams, WalletSummaryParams, WalletSummaryResult,
};
pub use x402::{X402FetchParams, X402FetchResult, X402Payment};

use crate::auth::{AccessLevel, AgentAuth};

/// One payments service call, as carried in
/// [`WireRequest::body_json`](crate::WireRequest::body_json).
///
/// JSON: `{"method": "<Method>", "params": {...}}`; `Hello` has no `params`.
/// `Debug` is derived: [`AgentAuth`] redacts its token.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "method", content = "params")]
pub enum PaymentsRpcRequest {
    /// Handshake: returns the service's API version, release, and capabilities.
    ///
    /// | | |
    /// |---|---|
    /// | Access | payments client allowlist |
    /// | Auth | none |
    /// | Response | [`PaymentsRpcResponse::Hello`] |
    /// | Side effects | none; idempotent |
    /// | Errors | none |
    ///
    /// `capabilities` lists every payments method name plus dotted feature
    /// names. Compatibility follows the same major-version rule as the
    /// signer daemon.
    ///
    /// Request:
    ///
    /// ```json
    #[doc = include_str!("../../fixtures/payments/Hello.request.json")]
    /// ```
    ///
    /// Response:
    ///
    /// ```json
    #[doc = include_str!("../../fixtures/payments/Hello.response.json")]
    /// ```
    Hello,
    /// Read the configuration. See [`GetConfigParams`].
    GetConfig(GetConfigParams),
    /// Replace the configuration. See [`SetConfigParams`].
    SetConfig(SetConfigParams),
    /// Send native SOL. See [`TransferSolParams`].
    TransferSol(TransferSolParams),
    /// Send SPL Token or Token-2022 tokens. See [`TransferSplParams`].
    TransferSpl(TransferSplParams),
    /// Send ERC-20 tokens. See [`TransferParams`].
    Transfer(TransferParams),
    /// Send the native coin of an EVM chain. See [`TransferNativeParams`].
    TransferNative(TransferNativeParams),
    /// Set an ERC-20 allowance. See [`ApproveParams`].
    Approve(ApproveParams),
    /// Sign and optionally send an agent-built EVM transaction. See [`BroadcastParams`].
    Broadcast(BroadcastParams),
    /// Sign EIP-712 typed data. See [`SignTypedDataParams`].
    SignTypedData(SignTypedDataParams),
    /// Continue a call that returned `ManualApprovalPending`. See [`ResumeApprovedParams`].
    ResumeApproved(ResumeApprovedParams),
    /// Chain id and latest block of an EVM chain. See [`EvmNetworkParams`].
    RpcChainInfo(EvmNetworkParams),
    /// Latest block of an EVM chain. See [`EvmNetworkParams`].
    RpcBlockNumber(EvmNetworkParams),
    /// Native or ERC-20 balance. See [`EvmBalanceParams`].
    RpcBalance(EvmBalanceParams),
    /// Pending nonce of an account. See [`EvmAccountParams`].
    RpcNonce(EvmAccountParams),
    /// Current gas price and EIP-1559 fee estimate. See [`EvmNetworkParams`].
    RpcFees(EvmNetworkParams),
    /// `eth_estimateGas`. See [`EvmGasEstimateParams`].
    RpcGasEstimate(EvmGasEstimateParams),
    /// A transaction by hash. See [`EvmTxHashParams`].
    RpcTx(EvmTxHashParams),
    /// A receipt by transaction hash. See [`EvmTxHashParams`].
    RpcReceipt(EvmTxHashParams),
    /// Code at an address. See [`EvmAccountParams`].
    RpcCode(EvmAccountParams),
    /// Fetch a URL, paying an x402 `402`. See [`X402FetchParams`].
    X402Fetch(X402FetchParams),
    /// Fetch a URL, paying an MPP `402` (Tempo charge or session). See [`MppFetchParams`].
    MppFetch(MppFetchParams),
    /// Start the local paying proxy. See [`ProxyStartParams`].
    ProxyStart(ProxyStartParams),
    /// Stop the local paying proxy. See [`ProxyParams`].
    ProxyStop(ProxyParams),
    /// Report the local paying proxy's state. See [`ProxyParams`].
    ProxyStatus(ProxyParams),
    /// The agent's addresses and balances. See [`WalletSummaryParams`].
    WalletSummary(WalletSummaryParams),
    /// One balance of the agent's wallet. See [`WalletBalanceParams`].
    WalletBalance(WalletBalanceParams),
    /// Address, URI, and QR code to fund the wallet. See [`FundingRequestParams`].
    FundingRequest(FundingRequestParams),
    /// Health of the service as seen by the agent. See [`StatusParams`].
    Status(StatusParams),
    /// Whether anonymous telemetry is on. See [`TelemetryStatusParams`].
    TelemetryStatus(TelemetryStatusParams),
    /// Turn anonymous telemetry on or off. See [`SetTelemetryParams`].
    SetTelemetry(SetTelemetryParams),
    /// Add an ERC-20 token or SPL mint to the configuration, with metadata
    /// read from the chain (API 1.1). See [`AddTokenParams`].
    AddToken(AddTokenParams),
    /// Read a token's metadata from the chain, without credentials and
    /// without changing anything (API 1.1). See [`LookupTokenParams`].
    LookupToken(LookupTokenParams),
    /// The agent's recent payments and approval requests, with configured
    /// labels (API 1.1). See [`ActivityParams`].
    Activity(ActivityParams),
}

impl PaymentsRpcRequest {
    /// Every method name, in declaration order. Each is also a capability
    /// advertised by the payments service's `Hello`.
    pub const METHOD_NAMES: &'static [&'static str] = &[
        "Hello",
        "GetConfig",
        "SetConfig",
        "TransferSol",
        "TransferSpl",
        "Transfer",
        "TransferNative",
        "Approve",
        "Broadcast",
        "SignTypedData",
        "ResumeApproved",
        "RpcChainInfo",
        "RpcBlockNumber",
        "RpcBalance",
        "RpcNonce",
        "RpcFees",
        "RpcGasEstimate",
        "RpcTx",
        "RpcReceipt",
        "RpcCode",
        "X402Fetch",
        "MppFetch",
        "ProxyStart",
        "ProxyStop",
        "ProxyStatus",
        "WalletSummary",
        "WalletBalance",
        "FundingRequest",
        "Status",
        "TelemetryStatus",
        "SetTelemetry",
        "AddToken",
        "LookupToken",
        "Activity",
    ];

    /// Returns the wire name of this request's method (its `method` tag).
    #[must_use]
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::Hello => "Hello",
            Self::GetConfig(_) => "GetConfig",
            Self::SetConfig(_) => "SetConfig",
            Self::TransferSol(_) => "TransferSol",
            Self::TransferSpl(_) => "TransferSpl",
            Self::Transfer(_) => "Transfer",
            Self::TransferNative(_) => "TransferNative",
            Self::Approve(_) => "Approve",
            Self::Broadcast(_) => "Broadcast",
            Self::SignTypedData(_) => "SignTypedData",
            Self::ResumeApproved(_) => "ResumeApproved",
            Self::RpcChainInfo(_) => "RpcChainInfo",
            Self::RpcBlockNumber(_) => "RpcBlockNumber",
            Self::RpcBalance(_) => "RpcBalance",
            Self::RpcNonce(_) => "RpcNonce",
            Self::RpcFees(_) => "RpcFees",
            Self::RpcGasEstimate(_) => "RpcGasEstimate",
            Self::RpcTx(_) => "RpcTx",
            Self::RpcReceipt(_) => "RpcReceipt",
            Self::RpcCode(_) => "RpcCode",
            Self::X402Fetch(_) => "X402Fetch",
            Self::MppFetch(_) => "MppFetch",
            Self::ProxyStart(_) => "ProxyStart",
            Self::ProxyStop(_) => "ProxyStop",
            Self::ProxyStatus(_) => "ProxyStatus",
            Self::WalletSummary(_) => "WalletSummary",
            Self::WalletBalance(_) => "WalletBalance",
            Self::FundingRequest(_) => "FundingRequest",
            Self::Status(_) => "Status",
            Self::TelemetryStatus(_) => "TelemetryStatus",
            Self::SetTelemetry(_) => "SetTelemetry",
            Self::AddToken(_) => "AddToken",
            Self::LookupToken(_) => "LookupToken",
            Self::Activity(_) => "Activity",
        }
    }

    /// The agent credentials the request carries; `None` only for `Hello`
    /// and `LookupToken`.
    #[must_use]
    pub fn agent_auth(&self) -> Option<&AgentAuth> {
        match self {
            Self::Hello | Self::LookupToken(_) => None,
            Self::GetConfig(GetConfigParams { auth })
            | Self::SetConfig(SetConfigParams { auth, .. })
            | Self::TransferSol(TransferSolParams { auth, .. })
            | Self::TransferSpl(TransferSplParams { auth, .. })
            | Self::Transfer(TransferParams { auth, .. })
            | Self::TransferNative(TransferNativeParams { auth, .. })
            | Self::Approve(ApproveParams { auth, .. })
            | Self::Broadcast(BroadcastParams { auth, .. })
            | Self::SignTypedData(SignTypedDataParams { auth, .. })
            | Self::ResumeApproved(ResumeApprovedParams { auth, .. })
            | Self::RpcChainInfo(EvmNetworkParams { auth, .. })
            | Self::RpcBlockNumber(EvmNetworkParams { auth, .. })
            | Self::RpcBalance(EvmBalanceParams { auth, .. })
            | Self::RpcNonce(EvmAccountParams { auth, .. })
            | Self::RpcFees(EvmNetworkParams { auth, .. })
            | Self::RpcGasEstimate(EvmGasEstimateParams { auth, .. })
            | Self::RpcTx(EvmTxHashParams { auth, .. })
            | Self::RpcReceipt(EvmTxHashParams { auth, .. })
            | Self::RpcCode(EvmAccountParams { auth, .. })
            | Self::X402Fetch(X402FetchParams { auth, .. })
            | Self::MppFetch(MppFetchParams { auth, .. })
            | Self::ProxyStart(ProxyStartParams { auth, .. })
            | Self::ProxyStop(ProxyParams { auth })
            | Self::ProxyStatus(ProxyParams { auth })
            | Self::WalletSummary(WalletSummaryParams { auth })
            | Self::WalletBalance(WalletBalanceParams { auth, .. })
            | Self::FundingRequest(FundingRequestParams { auth, .. })
            | Self::Status(StatusParams { auth })
            | Self::TelemetryStatus(TelemetryStatusParams { auth })
            | Self::SetTelemetry(SetTelemetryParams { auth, .. })
            | Self::AddToken(AddTokenParams { auth, .. })
            | Self::Activity(ActivityParams { auth, .. }) => Some(auth),
        }
    }

    /// Returns the peer allowlist that governs this request. The payments
    /// service has a single client allowlist, so this only separates the
    /// unauthenticated handshake from authenticated methods.
    #[must_use]
    pub fn access_level(&self) -> AccessLevel {
        match self.agent_auth() {
            None => AccessLevel::Any,
            Some(_) => AccessLevel::Agent,
        }
    }

    /// Wipes secret material (agent tokens) in place.
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::Hello | Self::LookupToken(_) => {}
            Self::GetConfig(GetConfigParams { auth })
            | Self::SetConfig(SetConfigParams { auth, .. })
            | Self::TransferSol(TransferSolParams { auth, .. })
            | Self::TransferSpl(TransferSplParams { auth, .. })
            | Self::Transfer(TransferParams { auth, .. })
            | Self::TransferNative(TransferNativeParams { auth, .. })
            | Self::Approve(ApproveParams { auth, .. })
            | Self::Broadcast(BroadcastParams { auth, .. })
            | Self::SignTypedData(SignTypedDataParams { auth, .. })
            | Self::ResumeApproved(ResumeApprovedParams { auth, .. })
            | Self::RpcChainInfo(EvmNetworkParams { auth, .. })
            | Self::RpcBlockNumber(EvmNetworkParams { auth, .. })
            | Self::RpcBalance(EvmBalanceParams { auth, .. })
            | Self::RpcNonce(EvmAccountParams { auth, .. })
            | Self::RpcFees(EvmNetworkParams { auth, .. })
            | Self::RpcGasEstimate(EvmGasEstimateParams { auth, .. })
            | Self::RpcTx(EvmTxHashParams { auth, .. })
            | Self::RpcReceipt(EvmTxHashParams { auth, .. })
            | Self::RpcCode(EvmAccountParams { auth, .. })
            | Self::ProxyStart(ProxyStartParams { auth, .. })
            | Self::ProxyStop(ProxyParams { auth })
            | Self::ProxyStatus(ProxyParams { auth })
            | Self::WalletSummary(WalletSummaryParams { auth })
            | Self::WalletBalance(WalletBalanceParams { auth, .. })
            | Self::FundingRequest(FundingRequestParams { auth, .. })
            | Self::Status(StatusParams { auth })
            | Self::TelemetryStatus(TelemetryStatusParams { auth })
            | Self::SetTelemetry(SetTelemetryParams { auth, .. })
            | Self::AddToken(AddTokenParams { auth, .. })
            | Self::Activity(ActivityParams { auth, .. }) => auth.zeroize_secrets(),
            Self::X402Fetch(X402FetchParams { auth, request, .. })
            | Self::MppFetch(MppFetchParams { auth, request, .. }) => {
                auth.zeroize_secrets();
                request.zeroize_secrets();
            }
        }
    }
}
