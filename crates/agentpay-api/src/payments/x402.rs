//! `X402Fetch`: fetch an HTTP resource and pay an x402 `402 Payment Required`
//! answer with an EIP-3009 authorization signed by the signer daemon.
//!
//! # Flow
//!
//! 1. The service sends the request (see [`crate::payments::http`] for the
//!    request rules). Any status but `402` is returned as it is, with
//!    `payment: null`.
//! 2. A `402` is parsed as x402 **v2** (`PAYMENT-REQUIRED` header, base64
//!    JSON) or, failing that, **v1** (JSON body with `x402Version: 1` and
//!    `accepts`). Anything else fails with `Merchant`.
//! 3. The first requirement the service can pay is chosen: scheme `exact`
//!    on an EVM (`eip155`) network, an `asset` contract with its EIP-712
//!    domain `name` and `version` in `extra`, and `extra.assetTransferMethod`
//!    absent or `eip3009`, whose amount (`amount` in v2,
//!    `maxAmountRequired` in v1) equals `expected_amount` and does not
//!    exceed `max_amount` when those are given. If none qualifies, the call
//!    fails with `InvalidRequest` and nothing is signed.
//! 4. The signer daemon signs an `Eip3009TransferWithAuthorization` action
//!    (`from` the agent's wallet, `to` = `payTo`, `value` = the amount,
//!    `validAfter` = now - 600 s, `validBefore` = now + `maxTimeoutSeconds`,
//!    a random 32-byte nonce) under the agent's policies. The service checks
//!    that the signature recovers to the wallet over the EIP-712 digest it
//!    computed itself (`SignedTransactionMismatch` otherwise).
//! 5. The request is sent once more with the payment header (`X-PAYMENT`
//!    for v1, `PAYMENT-SIGNATURE` for v2; base64 JSON as the x402 reference
//!    clients build it, with the chosen requirement echoed unchanged as
//!    `accepted` in v2). The merchant settles the authorization; its
//!    `PAYMENT-RESPONSE` / `X-PAYMENT-RESPONSE` header is decoded into
//!    `payment.payment_response`.
//!
//! The authorization moves funds only when the merchant (or its
//! facilitator) submits it on chain, before `validBefore`. A signature
//! counts toward the agent's spending limits when it is made.
//!
//! # Manual approval
//!
//! The authorization is bound to the merchant's requirement and a fresh
//! nonce, so resending the call creates a new approval request. When a
//! policy needs an operator, the call waits up to `approval_wait_secs`
//! (default 0, capped at 600) and fails with `ManualApprovalPending` when
//! nobody decides in time. Set `approval_wait_secs` long enough for the
//! operator to approve while the call waits.

use agentpay_domain::u128_as_decimal_string;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::http::{HttpRequest, HttpResponse};
use crate::auth::AgentAuth;
use crate::types::{DecimalU128, EvmAddress};

/// `X402Fetch`: fetch a URL, paying an x402 `402` answer.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`X402Response`] |
/// | Side effects | HTTP requests to `url`; on a `402`, one policy-checked EIP-3009 signature (spend recorded by the signer daemon) that the merchant can settle on chain |
/// | Idempotent | no: every paid call is a new payment |
///
/// See the [module documentation](self) for the flow.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`
/// (policy denial, rejected approval, ...), `ManualApprovalPending`,
/// `InvalidRequest` (bad request, no payable requirement), `Merchant`
/// (unreachable, unusable `402`), `SignedTransactionMismatch`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/x402/X402Fetch.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/x402/X402Fetch.response.json")]
/// ```
///
/// [`X402Response`]: crate::payments::PaymentsRpcResponse::X402Response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct X402FetchParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// The HTTP request.
    #[serde(flatten)]
    #[ts(flatten)]
    pub request: HttpRequest,
    /// Only pay a requirement of exactly this amount, in the asset's base
    /// units (the requirement's own unit).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub expected_amount: Option<u128>,
    /// Never pay a requirement above this amount, in the asset's base units.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_amount: Option<u128>,
    /// How long to wait for an operator when a policy requires manual
    /// approval, in seconds (default 0, capped at 600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub approval_wait_secs: Option<u64>,
}

/// The x402 payment an `X402Fetch` made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct X402Payment {
    /// x402 protocol version of the merchant's `402` (1 or 2).
    pub x402_version: u8,
    /// Payment scheme (`"exact"`).
    pub scheme: String,
    /// The requirement's network as the merchant named it: a v1 name
    /// (`"base-sepolia"`) or a v2 CAIP-2 id (`"eip155:84532"`).
    pub network: String,
    /// EVM chain id of that network.
    pub chain_id: u64,
    /// Token contract (the EIP-712 verifying contract).
    pub asset: EvmAddress,
    /// Recipient (`payTo`).
    pub pay_to: EvmAddress,
    /// Amount authorized, in the asset's base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount: u128,
    /// The paying wallet (the authorization's `from`).
    pub from: EvmAddress,
    /// Authorization `validAfter` (Unix seconds).
    pub valid_after: u64,
    /// Authorization `validBefore` (Unix seconds).
    pub valid_before: u64,
    /// Authorization nonce, `0x` + 64 hex characters.
    pub nonce_hex: String,
    /// The merchant's decoded `PAYMENT-RESPONSE` (v2) or `X-PAYMENT-RESPONSE`
    /// (v1) header: its settlement result, typically
    /// `{"success": true, "transaction": "0x...", "network": ..., "payer": ...}`.
    /// `null` when the header is missing; a header that is not base64 JSON is
    /// returned as a string.
    #[ts(type = "unknown")]
    pub payment_response: Option<serde_json::Value>,
}

/// Result of `X402Fetch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct X402FetchResult {
    /// The final response: the paid retry's, or the first one when it was
    /// not a `402`.
    pub response: HttpResponse,
    /// The payment made; `null` when the first response was not a `402`.
    pub payment: Option<X402Payment>,
}
