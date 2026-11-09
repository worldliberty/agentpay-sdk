//! Spending-policy methods.
//!
//! Policies are evaluated before every agent signature: for each request the
//! daemon selects the enabled policies attached to the agent key whose
//! recipient, asset, and network scopes match the action, and evaluates them
//! in ascending `priority`. Any hard limit denies the request; a
//! manual-approval rule holds it for an operator decision.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::AdminAuth;
use crate::types::SpendingPolicy;

/// `AddPolicy`: adds a new spending policy.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | persists the policy |
/// | Idempotent | no: an existing `id` fails with `InvalidPolicy` |
///
/// The policy applies immediately to agent keys attached to `AllPolicies`.
/// Agent keys attached to a `PolicySet` are not changed; attach the new id
/// with `RefreshAgentKey`.
///
/// **Errors:** admin-auth kinds, `InvalidPolicy` (duplicate id, invalid
/// limits, or a policy referenced by retained approval requests changing away
/// from `ManualApproval`), `Persistence`. Malformed policies (for example a
/// zero cap) fail earlier: the request does not decode, and the connection is
/// closed without a response.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AddPolicy.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AddPolicy.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AddPolicyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// The policy to add; its `id` must be new.
    pub policy: SpendingPolicy,
}

/// `ListPolicies`: lists every policy (enabled or not), ordered by priority.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::Policies`](crate::DaemonRpcResponse::Policies) |
/// | Side effects | none; idempotent |
///
/// **Errors:** the admin-auth kinds only.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListPolicies.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListPolicies.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListPoliciesParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
}

/// `ListPolicySummaries`: lists the id and enabled state of every policy.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::PolicySummaries`](crate::DaemonRpcResponse::PolicySummaries) |
/// | Side effects | none; idempotent |
///
/// **Errors:** the admin-auth kinds only.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListPolicySummaries.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListPolicySummaries.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListPolicySummariesParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
}

/// `DisablePolicy`: disables a policy and detaches it from every `PolicySet`.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | persists `enabled: false` and removes the id from agent `PolicySet` attachments |
/// | Idempotent | yes: disabling a disabled policy succeeds |
///
/// Disabled policies stay listed but are ignored during evaluation. There is
/// no re-enable method; add a new policy instead.
///
/// **Errors:** admin-auth kinds, `UnknownPolicy`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/DisablePolicy.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/DisablePolicy.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct DisablePolicyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Policy to disable.
    pub policy_id: Uuid,
}
