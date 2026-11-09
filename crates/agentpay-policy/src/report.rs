use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::PolicyError;

/// Successful policy evaluation details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PolicyEvaluation {
    /// Policies evaluated (priority order, low to high numeric priority).
    pub evaluated_policy_ids: Vec<Uuid>,
}

/// Policy decision for an explanation report.
///
/// JSON: `{"decision": "allow"}`, `{"decision": "deny", "reason": <PolicyError>}`,
/// or `{"decision": "manual_approval", "reason": [<PolicyError>, ...]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "decision", content = "reason", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Request satisfies all applicable policies.
    Allow,
    /// Request was denied by policy engine (a hard denial; it wins over any
    /// manual-approval outcome).
    Deny(PolicyError),
    /// No policy denies the request, but it needs an operator decision
    /// (API 1.1): every soft outcome, in evaluation order (never empty). Each
    /// is `ManualApprovalRequired`, `LimitApprovalRequired`, or
    /// `Eip712ManualApprovalRequired`. `SignForAgent` turns them into one
    /// manual approval request keyed by all their policies.
    ManualApproval(Vec<PolicyError>),
}

/// Full policy explanation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PolicyExplanation {
    /// Enabled policy ids attached to the agent (priority order).
    pub attached_policy_ids: Vec<Uuid>,
    /// Attached policy ids whose recipient/asset/network scope matched the action.
    pub applicable_policy_ids: Vec<Uuid>,
    /// Policy ids evaluated in order up to decision point.
    pub evaluated_policy_ids: Vec<Uuid>,
    /// Final allow/deny decision.
    pub decision: PolicyDecision,
}
