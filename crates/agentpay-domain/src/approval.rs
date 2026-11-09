//! Manual-approval requests raised when a policy requires an operator decision.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;

use crate::schema::{DecimalU128, Timestamp};
use crate::{AgentAction, AssetId, RecipientId};

/// An operator's decision on a pending request. JSON: `"approve"` or `"reject"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ManualApprovalDecision {
    /// Allow the agent's next identical sign request to be signed.
    Approve,
    /// Refuse the request; identical retries fail with `ManualApprovalRejected`.
    Reject,
}

/// Lifecycle state of a manual approval request.
///
/// `pending` -> `approved` -> `completed` (signed), or `pending` -> `rejected`.
/// JSON: `"pending"`, `"approved"`, `"rejected"`, or `"completed"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ManualApprovalStatus {
    /// Waiting for an operator decision.
    Pending,
    /// Approved; the agent's next identical sign request will be signed.
    Approved,
    /// Rejected by an operator.
    Rejected,
    /// Approved and consumed by a successful signature.
    Completed,
}

/// Which rule held a request for approval. JSON: `"per_payment"`, `"daily"`,
/// `"weekly"`, `"daily_count"`, `"policy"`, or `"eip712"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLimit {
    /// The amount is beyond a per-payment limit (`PerTxMaxSpending`).
    PerPayment,
    /// The rolling 24-hour amount would go beyond a daily limit (`DailyMaxSpending`).
    Daily,
    /// The rolling 7-day amount would go beyond a weekly limit (`WeeklyMaxSpending`).
    Weekly,
    /// The rolling 24-hour transaction count would go beyond a daily count
    /// limit (`DailyMaxTxCount`).
    DailyCount,
    /// A `ManualApproval` policy covers the amount.
    Policy,
    /// Typed-data signing needs approval (an `Eip712Signing` manual-approval
    /// policy, or the default for typed data without one).
    Eip712,
}

/// Why a request waits for an operator decision: one triggering rule.
///
/// Units: `max` and `used` are in the asset's base units, except for
/// `daily_count`, where they count transactions. `requested_amount_wei` is
/// always the amount of this request in base units. All three are decimal
/// strings, `null` where they do not apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ApprovalReason {
    /// The rule that was triggered.
    pub limit: ApprovalLimit,
    /// The policy that holds the request; `null` for the default EIP-712 gate.
    pub policy_id: Option<Uuid>,
    /// The limit: the per-payment, daily, or weekly cap, the daily count cap,
    /// or a `ManualApproval` policy's upper bound; `null` for `eip712`.
    #[serde(with = "crate::u128_as_decimal_string::option")]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    pub max: Option<u128>,
    /// Already used inside the window before this request (`daily`,
    /// `weekly`, `daily_count`); `null` otherwise.
    #[serde(with = "crate::u128_as_decimal_string::option")]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    pub used: Option<u128>,
    /// The amount of this request, in base units; `null` for `eip712`.
    #[serde(with = "crate::u128_as_decimal_string::option")]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    pub requested_amount_wei: Option<u128>,
}

/// A sign request held for an operator decision because a policy requires
/// manual approval.
///
/// Pending and approved requests expire after 24 hours; terminal requests are
/// retained for 8 days, then pruned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ManualApprovalRequest {
    /// Approval request id (the `approval_request_id` in `ManualApprovalRequired`).
    pub id: Uuid,
    /// Agent key that asked for the signature.
    pub agent_key_id: Uuid,
    /// Vault key that would sign.
    pub vault_key_id: Uuid,
    /// SHA-256 of the sign request `payload`, lowercase hex without `0x`.
    /// Retries match an existing approval by agent key and this hash.
    pub request_payload_hash_hex: String,
    /// The action awaiting approval.
    pub action: AgentAction,
    /// Policy chain id of the action (EVM chain id or the internal Solana id).
    pub chain_id: u64,
    /// Asset the action moves.
    pub asset: AssetId,
    /// Recipient (or spender) the action targets.
    pub recipient: RecipientId,
    /// Amount the action moves, in the asset's base units (decimal string).
    #[serde(with = "crate::u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
    /// Creation timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub created_at: OffsetDateTime,
    /// Last status change (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub updated_at: OffsetDateTime,
    /// Current lifecycle state.
    pub status: ManualApprovalStatus,
    /// Policies whose manual-approval rule triggered this request (may be
    /// empty for the default EIP-712 approval gate).
    pub triggered_by_policy_ids: Vec<Uuid>,
    /// Why the request waits, one entry per triggered rule (API 1.1), for
    /// example the daily limit and its usage. Recorded when the request is
    /// created; `[]` for requests created before reasons existed.
    #[serde(default)]
    pub reasons: Vec<ApprovalReason>,
    /// When the approved request was consumed by a signature (UTC), else `null`.
    #[schemars(with = "Option<Timestamp>")]
    #[ts(as = "Option<Timestamp>")]
    pub completed_at: Option<OffsetDateTime>,
    /// Operator-supplied reason for a rejection, else `null`.
    pub rejection_reason: Option<String>,
}
