//! Agent methods: authentication, policy summary and evaluation, nonce management, and signing.
//!
//! Every agent method authenticates with `agent_key_id` + `agent_auth_token`
//! inside the request and must come from a peer on the agent allowlist. For
//! the methods that carry a request with timestamps, the
//! [`SignRequest`] freshness rules apply: `requested_at < expires_at`,
//! `expires_at` in the future, `requested_at` at most 30 s ahead of the daemon
//! clock, and a lifetime of at most 5 minutes.
//!
//! # Typical EVM broadcast flow
//!
//! 1. `ReserveNonce` with the account's pending nonce from RPC as `min_nonce`.
//! 2. Build a `BroadcastTx` action with the reserved nonce and call
//!    `SignForAgent`; the response carries `raw_tx_hex` and `tx_hash_hex`.
//! 3. Broadcast `raw_tx_hex` with `eth_sendRawTransaction`. If the
//!    transaction is abandoned before signing, `ReleaseNonce` returns the
//!    nonce to the pool. If it was signed but the send provably never
//!    reached the network, `ReleaseSignedNonce` returns it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::auth::AgentAuth;
use crate::types::{
    NonceReleaseRequest, NonceReservationRequest, SignRequest, SignedNonceReleaseRequest,
};

/// `AuthenticateAgent`: verifies an agent token and returns the agent's identity
/// and wallet addresses.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::AgentIdentity`](crate::DaemonRpcResponse::AgentIdentity) |
/// | Side effects | none |
/// | Idempotent | yes |
///
/// The payments service (`agentpay-paymentd`) calls it to authenticate each
/// of its own callers: it forwards the caller's credentials and serves the
/// request only when the signer daemon accepts them. Agents can also call it
/// to check a token and learn their addresses. The request carries no
/// timestamps, so it is not subject to the freshness rules and consumes no
/// request id.
///
/// **Errors:** `AgentAuthenticationFailed` (unknown agent or wrong token),
/// `UnknownVaultKey`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AuthenticateAgent.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AuthenticateAgent.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AuthenticateAgentParams {
    /// The agent credentials to verify.
    pub auth: AgentAuth,
}

/// `AgentPolicySummary`: lists the enabled policies that govern the agent.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::AgentPolicySummary`](crate::DaemonRpcResponse::AgentPolicySummary) |
/// | Side effects | none |
/// | Idempotent | yes |
///
/// Read-only. It reports each policy's id, priority, type, and asset and
/// network scope, but no limit amounts and no recipients (those stay
/// admin-only). `spending_policy_count == 0` means every payment will be
/// denied until an operator sets limits; the payments service's `Status`
/// turns that into a warning. Like `AuthenticateAgent`, the request has no
/// timestamps and consumes no request id.
///
/// **Errors:** `AgentAuthenticationFailed`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AgentPolicySummary.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AgentPolicySummary.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentPolicySummaryParams {
    /// The agent credentials.
    pub auth: AgentAuth,
}

/// `EvaluateForAgent`: checks whether a request would be allowed, without signing.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::PolicyEvaluation`](crate::DaemonRpcResponse::PolicyEvaluation) |
/// | Side effects | none: no spend is recorded and `request_id` is not consumed |
/// | Idempotent | yes |
///
/// A denial is reported as an error (`Policy`), including the soft
/// `ManualApprovalRequired` policy outcome; use `ExplainForAgent` for a
/// report instead of an error.
///
/// **Errors:** `AgentAuthenticationFailed`, `InvalidRequestTimestamps`,
/// `RequestExpired`, `PayloadTooLarge`, `PayloadActionMismatch`,
/// `InvalidAction`, `Policy`.
///
/// Request (`payload` is the canonical JSON of `action`, as bytes):
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/EvaluateForAgent.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/EvaluateForAgent.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EvaluateForAgentParams {
    /// The request to evaluate.
    pub request: SignRequest,
}

/// `ExplainForAgent`: explains the policy decision for a request, without signing.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::PolicyExplanation`](crate::DaemonRpcResponse::PolicyExplanation) |
/// | Side effects | none: no spend is recorded and `request_id` is not consumed |
/// | Idempotent | yes |
///
/// Unlike `EvaluateForAgent`, a policy denial is returned as
/// `decision: {"decision": "deny", "reason": <PolicyError>}`, not as an error.
///
/// **Errors:** `AgentAuthenticationFailed`, `InvalidRequestTimestamps`,
/// `RequestExpired`, `PayloadTooLarge`, `PayloadActionMismatch`,
/// `InvalidAction`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ExplainForAgent.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ExplainForAgent.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ExplainForAgentParams {
    /// The request to explain.
    pub request: SignRequest,
}

/// `ReserveNonce`: reserves a unique EVM nonce for a future `BroadcastTx`.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::NonceReservation`](crate::DaemonRpcResponse::NonceReservation) |
/// | Side effects | persists the reservation (2-minute TTL) and consumes `request_id` |
/// | Idempotent | yes per `request_id`: resending the identical request returns the same reservation |
///
/// The daemon hands out the lowest nonce `>= min_nonce` that is neither
/// reserved nor already signed for this vault key and chain, reusing released
/// gaps. With `exact_nonce`, it reserves exactly `min_nonce` or fails.
///
/// **Errors:** `AgentAuthenticationFailed`, `InvalidRequestTimestamps`,
/// `RequestExpired`, `RequestReplayDetected`, `TooManyTrackedReplayIds`,
/// `InvalidNonceReservation`, `NonceSkipTooLarge`,
/// `TooManyActiveNonceReservations`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ReserveNonce.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ReserveNonce.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ReserveNonceParams {
    /// The reservation request.
    pub request: NonceReservationRequest,
}

/// `ReleaseNonce`: releases an unused nonce reservation.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token; the reservation must belong to the agent |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | removes the reservation, returns the nonce to the pool, consumes `request_id` |
/// | Idempotent | yes per `request_id`: resending the identical request succeeds again |
///
/// **Errors:** `AgentAuthenticationFailed` (also when the reservation belongs
/// to another agent), `InvalidRequestTimestamps`, `RequestExpired`,
/// `RequestReplayDetected`, `TooManyTrackedReplayIds`,
/// `UnknownNonceReservation`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ReleaseNonce.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ReleaseNonce.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ReleaseNonceParams {
    /// The release request.
    pub request: NonceReleaseRequest,
}

/// `ReleaseSignedNonce`: returns the nonce of a signed `BroadcastTx` that
/// never reached the network, so the next transaction does not leave a gap.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token; the transaction must have been signed for this agent |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | forgets the signed transaction, returns its nonce to the pool (unless it is reserved again), drops the recorded signature so a retry of the signing request cannot return it, consumes `request_id` |
/// | Idempotent | yes per `request_id`: resending the identical request succeeds again |
///
/// Signing a `BroadcastTx` consumes its nonce: the daemon never hands it out
/// again, so if the send fails, the next transaction gets the following nonce
/// and waits forever behind the gap. This method closes the gap.
///
/// **Only call it when the transaction certainly never reached a node**: the
/// `eth_sendRawTransaction` request could not be delivered (the connection
/// was refused), the node answered it with a JSON-RPC error (nodes do not
/// relay transactions they reject), or it was never sent at all (for example
/// the signed transaction failed local verification). After a timeout, a lost
/// response, or an HTTP error from a proxy, the node may have the transaction,
/// so keep the nonce. A released nonce is handed out again, and a second
/// transaction with the same nonce replaces or races the first: both were
/// allowed by policy, and at most one can be mined.
///
/// The spend stays counted against the agent's daily and weekly limits: the
/// daemon cannot see the network, and refunding it on the agent's word would
/// let an agent that broadcasts the transaction itself spend past its limits.
/// A transaction can be released once, within 10 minutes of signing.
///
/// **Errors:** `AgentAuthenticationFailed` (also when another agent signed the
/// transaction), `InvalidRequestTimestamps`, `RequestExpired`,
/// `RequestReplayDetected`, `TooManyTrackedReplayIds`,
/// `UnknownSignedTransaction` (not signed by this daemon, already released,
/// or signed more than 10 minutes ago), `InvalidNonceReservation` (`chain_id`
/// or `nonce` do not match the transaction, or a malformed hash),
/// `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ReleaseSignedNonce.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ReleaseSignedNonce.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ReleaseSignedNonceParams {
    /// The release request.
    pub request: SignedNonceReleaseRequest,
}

/// `SignForAgent`: evaluates policies and, when allowed, signs the action.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::Signature`](crate::DaemonRpcResponse::Signature) |
/// | Side effects | records the spend for window limits, consumes `request_id` and (for `BroadcastTx`) the nonce reservation, completes an approved manual approval request, tracks Tempo channel deposits, persists state |
/// | Idempotent | yes per `request_id`: resending the identical request (same payload) returns the recorded signature for up to 8 days; the same `request_id` with a different payload fails with `RequestReplayDetected` |
///
/// What is signed depends on the action: `BroadcastTx` produces a signed
/// EIP-1559 (type `0x02`) transaction; EIP-3009, Tempo session, and EIP-712
/// actions sign their EIP-712 digest (`r_hex`, `s_hex`, `v`); Solana actions
/// produce a signed transaction (`raw_tx_base64`, `tx_id`); `Approve`,
/// `Transfer`, and `TransferNative` return a DER signature over the payload.
///
/// **Errors:** `AgentAuthenticationFailed`, `InvalidRequestTimestamps`,
/// `RequestExpired`, `RequestReplayDetected`, `TooManyTrackedReplayIds`,
/// `PayloadTooLarge`, `PayloadActionMismatch`, `InvalidAction`, `Policy`,
/// `ManualApprovalRequired` (see [`approvals`](super::approvals)),
/// `ManualApprovalRejected`, `TooManyPendingManualApprovalRequests`,
/// `MissingNonceReservation`, `UnknownVaultKey`, `Signer`, `Persistence`.
///
/// Request (a 1 USD1 ERC-20 transfer on BNB Smart Chain, using the nonce
/// reserved in the `ReserveNonce` example):
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/SignForAgent.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/SignForAgent.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SignForAgentParams {
    /// The request to sign.
    pub request: SignRequest,
}
