//! `MppFetch`: fetch an HTTP resource and pay an MPP (`WWW-Authenticate:
//! Payment`) `402` answer with Tempo: a one-off **charge** or a reusable
//! **session** (TIP-1034 payment channel, "sessions v2").
//!
//! # Challenge selection
//!
//! The service parses every `Payment` challenge of the `402` and only
//! considers `tempo` challenges with intent `charge` or `session`. Then, in
//! this order:
//!
//! 1. With `currency`, only challenges paying in that token remain.
//! 2. With `session_key` naming a persisted channel (read **before**
//!    selection), only session challenges for that exact channel remain: same
//!    origin, chain, token, recipient, and, when the challenge names one,
//!    channel id. If none remains, the call fails with `InvalidRequest`.
//! 3. Session challenges for the legacy escrow protocol (sessions v1: an
//!    `escrowContract` other than the TIP-1034 reserve precompile, or
//!    `sessionProtocol: "v1"`) are never paid. If only such challenges are
//!    offered, the call fails with `InvalidRequest`.
//! 4. The remaining challenges are ranked: session challenges first when
//!    `session_key` is given, charge challenges first otherwise; then Tempo
//!    mainnet over Moderato (or the reverse when the URL names a testnet);
//!    then an explicit `sessionProtocol: "v2"` marker breaks ties between
//!    session challenges. A caller-sent `Accept-Payment` header ranks first.
//!
//! The chosen challenge is echoed back unchanged, including `opaque`, and the
//! credential travels in the header the challenge names (`Authorization`, or
//! `Payment-Authorization` when the challenge's `header` parameter asks for it).
//!
//! # Charge
//!
//! The service pays `amount` of `currency` to `recipient` with a TIP-20
//! `transferWithMemo` whose memo binds the payment to the challenge (the
//! challenge's own `memo`, else the MPP attribution memo for its id and
//! realm), sent as an EIP-1559 transaction through the same pipeline as
//! `Transfer` (signed as a policy-checked `BroadcastTx`, verified, sent, and
//! waited for). It then retries the request with a `hash` credential.
//! Challenges with `splits`, or whose `supportedModes` exclude `push`, are
//! refused. The chain must be a configured Tempo chain (`tempo`,
//! `tempo-testnet`, ...) with an `rpc_url`. As for any EIP-1559 transaction
//! on Tempo, the fee is paid in the wallet's default Tempo fee token.
//!
//! # Session (TIP-1034, sessions v2)
//!
//! - **Open**: when no channel is persisted under `session_key` (or without
//!   `session_key`), the service builds a Tempo transaction calling the
//!   reserve precompile's `open` with `deposit` (default: the challenge's
//!   `suggestedDeposit`, else its `amount`; capped by `max_deposit`) and a
//!   random salt, and a voucher for the first `amount`. The signer daemon
//!   signs both (`TempoSessionV2OpenTransaction`, `TempoSessionV2Voucher`)
//!   and derives the channel id itself. The merchant broadcasts the open
//!   (sponsoring its fee when the challenge sets `feePayer`).
//! - **Reuse**: a persisted channel pays with a voucher for the new
//!   cumulative amount. When that exceeds the deposit, a top-up
//!   (`TempoSessionV2TopUpTransaction`, to the larger of `deposit` and the
//!   required amount, capped by `max_deposit`) is POSTed to the URL first.
//! - **Close**: with `close_session`, or for a channel opened without
//!   `session_key`, the service signs a voucher and a cooperative close
//!   authorization (`TempoSessionV2CloseAuthorization`) for the final
//!   amount and POSTs them to the URL after the paid response.
//! - **Receipts**: the merchant's `Payment-Receipt` must name the channel
//!   the service paid; otherwise the call fails with `Merchant` and the
//!   persisted state is not advanced.
//! - **Streams**: for a `text/event-stream` response the service reads the
//!   stream to its end (at most 8 MiB and the request timeout), answers each
//!   `payment-need-voucher` event with a voucher (topping up first when
//!   needed, within `max_deposit`), records `payment-receipt` events, and
//!   then returns the collected body. Events are not delivered to the caller
//!   while the stream is open: this method is not suitable for long-lived
//!   streams.
//!
//! The service checks everything the signer daemon returns: transaction
//! signatures recover to the wallet over the Tempo signing hash it computed
//! itself, and voucher signatures over the TIP-1034 EIP-712 digests
//! (`SignedTransactionMismatch` otherwise).
//!
//! Persisted channels live in the service's state directory
//! (`mpp-sessions.json`, mode `0600`, written atomically), keyed by agent
//! and `session_key`. They hold no secrets. Calls that use the same
//! `session_key` run one at a time. A merchant answer of `410 Gone` to a
//! voucher discards the persisted channel and opens a new one.
//!
//! # Manual approval
//!
//! Charges and session transactions are bound to the merchant's challenge,
//! a fresh nonce, and (for sessions) a 25-second expiring-nonce window, so a
//! resent call creates a new approval request. When a policy needs an
//! operator, the call waits up to `approval_wait_secs` (default 0, capped at
//! 600) and fails with `ManualApprovalPending` otherwise. A session open or
//! top-up must be approved within its 25-second window.

use agentpay_domain::u128_as_decimal_string;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::http::{HttpRequest, HttpResponse};
use crate::auth::AgentAuth;
use crate::types::DecimalU128;

/// Longest `session_key`, in bytes.
pub const MAX_SESSION_KEY_BYTES: usize = 64;

/// `MppFetch`: fetch a URL, paying an MPP `402` with a Tempo charge or session.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`MppResponse`] |
/// | Side effects | HTTP requests to `url`; on a `402`, policy-checked signatures (spend recorded by the signer daemon): a charge transaction sent on chain, or session transactions and vouchers the merchant settles; a persisted session record |
/// | Idempotent | no: every paid call is a new payment |
///
/// See the [module documentation](self) for selection, charges, and sessions.
/// All amounts are in the token's base units (the unit of the challenge's
/// own `amount`), for example `"10000"` for 0.01 of a 6-decimal stablecoin.
///
/// `session_key` names a persisted channel: 1 to [`MAX_SESSION_KEY_BYTES`]
/// characters from `A-Z a-z 0-9 . _ : -`.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`
/// (policy denial, rejected approval, ...), `ManualApprovalPending`,
/// `InvalidRequest` (bad request, nothing payable, amount or deposit
/// limits, sessions v1), `Merchant` (unreachable, unusable challenge or
/// receipt, failed management request), `ChainRpc`,
/// `SignedTransactionMismatch`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/mpp/MppFetch.request.json")]
/// ```
///
/// Response (a session voucher on a persisted channel):
///
/// ```json
#[doc = include_str!("../../fixtures/payments/mpp/MppFetch.response.json")]
/// ```
///
/// [`MppResponse`]: crate::payments::PaymentsRpcResponse::MppResponse
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MppFetchParams {
    /// Agent credentials.
    pub auth: AgentAuth,
    /// The HTTP request.
    #[serde(flatten)]
    #[ts(flatten)]
    pub request: HttpRequest,
    /// Only pay a challenge of exactly this amount (base units).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub amount: Option<u128>,
    /// Deposit for a new session channel and the default top-up target (base
    /// units); default the challenge's `suggestedDeposit`, else its `amount`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub deposit: Option<u128>,
    /// Cap on a session channel's total deposit, top-ups included (base
    /// units). An explicit `deposit` above it is refused; a default deposit
    /// is lowered to it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_deposit: Option<u128>,
    /// Only pay challenges in this token: an EVM token address, a Solana mint,
    /// or `"sol"` (compared case-insensitively for EVM addresses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub currency: Option<String>,
    /// Only pay challenges on this configured network (a key of the
    /// configuration's `chains`, for example `"base"` or `"solana-mainnet"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub network: Option<String>,
    /// Persist the session channel under this name and reuse it on later
    /// calls. Without it, a session channel is closed after the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub session_key: Option<String>,
    /// Close the session channel after the paid response and forget it.
    #[serde(default)]
    pub close_session: bool,
    /// How long to wait for an operator when a policy requires manual
    /// approval, in seconds (default 0, capped at 600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub approval_wait_secs: Option<u64>,
}

/// A charge an `MppFetch` paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MppCharge {
    /// Configured chain key the payment is on.
    pub network: String,
    /// The credential sent: `"hash"` (AgentPay broadcast the transaction and
    /// it was confirmed), `"transaction"` (a signed transaction the merchant
    /// broadcasts), `"authorization"` (an EIP-3009 authorization the merchant
    /// submits), or `"signature"` (Solana: AgentPay broadcast the transaction).
    pub credential_type: String,
    /// The transaction: EVM `0x` + 64 hex, Solana base58 signature; `null`
    /// for an `authorization` (see the receipt's `reference`).
    pub tx_hash: Option<String>,
    /// Tempo: the 32-byte memo, `0x` + 64 hex; `null` for other methods.
    pub memo_hex: Option<String>,
}

/// The session channel an `MppFetch` used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MppSession {
    /// The persisted channel's name; `null` for a one-call channel.
    pub session_key: Option<String>,
    /// TIP-1034 channel id, `0x` + 64 hex.
    pub channel_id: String,
    /// Whether this call opened the channel.
    pub opened: bool,
    /// Total deposit after this call (base units).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub deposit: u128,
    /// Deposit added by top-ups in this call (base units).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub topped_up: u128,
    /// Highest cumulative amount the agent has signed for the channel (base units).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub cumulative_amount: u128,
    /// Vouchers signed in this call (stream vouchers included).
    pub vouchers: u32,
    /// Whether the channel was closed (and forgotten) by this call.
    pub closed: bool,
    /// The merchant's decoded receipt for the close, if any.
    #[ts(type = "unknown")]
    pub close_receipt: Option<serde_json::Value>,
}

/// The MPP payment an `MppFetch` made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MppPayment {
    /// The paid challenge's id.
    pub challenge_id: String,
    /// The challenge's realm.
    pub realm: String,
    /// `"tempo"`, `"evm"`, `"arbitrum"`, or `"solana"`.
    pub method: String,
    /// `"charge"` or `"session"`.
    pub intent: String,
    /// Session protocol: `"v2"` for sessions, `null` for charges.
    pub session_protocol: Option<String>,
    /// Chain id (Solana clusters use AgentPay's ids, for example 900000001
    /// for mainnet).
    pub chain_id: u64,
    /// Configured network key the payment is on.
    pub network: String,
    /// Token paid: an EVM token address, a Solana mint, or `"sol"`.
    pub currency: String,
    /// Merchant: an EVM address or a Solana wallet.
    pub recipient: String,
    /// The challenge amount (base units).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount: u128,
    /// Set for a charge.
    pub charge: Option<MppCharge>,
    /// Set for a session.
    pub session: Option<MppSession>,
    /// The merchant's decoded `Payment-Receipt` for the paid response (for a
    /// stream, its last `payment-receipt` event), if any.
    #[ts(type = "unknown")]
    pub receipt: Option<serde_json::Value>,
}

/// Result of `MppFetch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct MppFetchResult {
    /// The final response: the paid retry's, or the first one when it was
    /// not a `402`.
    pub response: HttpResponse,
    /// The payment made; `null` when nothing was paid.
    pub payment: Option<MppPayment>,
}
