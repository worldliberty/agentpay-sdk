//! Manual-approval methods.
//!
//! # Semantics
//!
//! When a `ManualApproval` policy (or an `Eip712Signing` policy with
//! `approval_type: "manual_approval"`, or the default gate for typed data
//! with no explicit `Eip712Signing` policy) covers a `SignForAgent` request,
//! and no hard limit denies it, the daemon:
//!
//! 1. creates (or reuses) a [`ManualApprovalRequest`](crate::types::ManualApprovalRequest)
//!    keyed by the agent key, the SHA-256 of the request `payload`, and the
//!    triggering policy ids;
//! 2. fails the call with `ManualApprovalRequired { approval_request_id }`
//!    without signing, spending, or consuming the `request_id`.
//!
//! An operator lists pending requests and decides them with
//! `DecideManualApprovalRequest`. The agent then **resends the same action**
//! (any `request_id` and fresh timestamps; the payload bytes must be
//! identical). Depending on the decision the retry is signed (the request
//! becomes `completed`), fails with `ManualApprovalRejected`, or fails again
//! with `ManualApprovalRequired` while still pending. Pending and approved
//! requests expire after 24 hours; each agent key may hold at most 64 pending
//! requests. Solana transfers need a durable nonce account to be eligible.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::AdminAuth;
use crate::types::ManualApprovalDecision;

/// `ListManualApprovalRequests`: lists retained approval requests, newest first.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::ManualApprovalRequests`](crate::DaemonRpcResponse::ManualApprovalRequests) |
/// | Side effects | none; idempotent |
///
/// Includes every status; filter on `status == "pending"` for the queue.
///
/// **Errors:** the admin-auth kinds only.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListManualApprovalRequests.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListManualApprovalRequests.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListManualApprovalRequestsParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
}

/// `DecideManualApprovalRequest`: approves or rejects a pending request.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease (on macOS, typically a lease from a Touch ID challenge with purpose `approve:<approval_request_id>`) |
/// | Response | [`DaemonRpcResponse::ManualApprovalRequest`](crate::DaemonRpcResponse::ManualApprovalRequest) |
/// | Side effects | persists the new status |
/// | Idempotent | no: deciding a non-pending request fails |
///
/// Approval requires every triggering policy to still exist and be enabled.
///
/// **Errors:** admin-auth kinds, `UnknownManualApprovalRequest` (unknown or
/// expired), `ManualApprovalRequestNotPending`, `UnknownPolicy` or
/// `InvalidPolicy` (when approving: a triggering policy was removed, disabled,
/// or is no longer a manual-approval policy), `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/DecideManualApprovalRequest.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/DecideManualApprovalRequest.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DecideManualApprovalRequestParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Approval request to decide.
    pub approval_request_id: Uuid,
    /// The decision.
    pub decision: ManualApprovalDecision,
    /// Optional reason, recorded (trimmed) only for rejections; `null` otherwise.
    pub rejection_reason: Option<String>,
}
