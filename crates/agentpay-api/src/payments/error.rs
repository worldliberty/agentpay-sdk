//! [`WirePaymentsError`]: the error body of a failed payments service call.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::WireDaemonError;

/// Serializable payments service error (`WireResponse.ok == false`).
///
/// JSON: `{"kind": "<Kind>"}` for kinds without data, otherwise
/// `{"kind": "<Kind>", "data": ...}`. The `kind` names are stable within a
/// major API version; new kinds may be added in minor versions, so clients
/// must treat an unknown `kind` as a generic failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", content = "data")]
pub enum WirePaymentsError {
    /// The signer daemon rejected the agent credentials (unknown agent key or
    /// wrong token). `{"kind": "AgentAuthenticationFailed"}`.
    AgentAuthenticationFailed,
    /// The signer daemon could not be reached or answered with something the
    /// service did not understand. Retry later; check that the signer daemon
    /// is running. `data` is a human-readable reason.
    SignerUnavailable(String),
    /// The signer daemon refused a request made on the agent's behalf, for
    /// example a policy denial or a rejected manual approval. `data` is the
    /// signer daemon's own error, unchanged.
    Signer(WireDaemonError),
    /// A signature is still waiting for an operator's decision after the
    /// service stopped waiting. Approve or reject the request, then resend the
    /// same call.
    ManualApprovalPending {
        /// The pending approval request in the signer daemon.
        approval_request_id: Uuid,
    },
    /// The configuration failed validation; nothing was changed. `data` is a
    /// human-readable reason.
    InvalidConfig(String),
    /// Saving the service's state failed; nothing was changed. `data` is a
    /// human-readable reason.
    Persistence(String),
    /// The request is well-formed but cannot be carried out as asked, for
    /// example an unknown or wrong-family network, an amount with too many
    /// decimals, or a missing token account. Nothing was signed. `data` is a
    /// human-readable reason.
    InvalidRequest(String),
    /// A chain RPC call failed or returned something unusable (unreachable
    /// endpoint, wrong cluster, rejected transaction). Retrying may help.
    /// `data` is a human-readable reason that never includes the RPC URL.
    ChainRpc(String),
    /// The transaction the signer daemon returned does not match the
    /// request, so the service refused to return or broadcast it. This
    /// indicates a bug or tampering; do not retry blindly. `data` names the
    /// mismatching field.
    SignedTransactionMismatch(String),
    /// `ResumeApproved` names no pending approval stored for this agent:
    /// never created, already completed, or created by another agent.
    UnknownPendingApproval(Uuid),
    /// The paid HTTP endpoint (the merchant) failed: it could not be
    /// reached or timed out, or it answered with a payment challenge,
    /// receipt, or management response the service cannot accept
    /// (malformed, unsupported, or inconsistent with what was paid). `data`
    /// is a human-readable reason that says whether anything was signed.
    Merchant(String),
    /// An unexpected internal failure. `data` is a human-readable reason.
    Internal(String),
}
