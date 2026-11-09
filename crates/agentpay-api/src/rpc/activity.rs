//! `AgentActivity` (API 1.1): what an agent has recently spent and which of
//! its payments wait (or waited) for an operator, for the agent itself.
//!
//! Strictly scoped to the authenticated agent key: the daemon returns only
//! that agent's spend log entries and manual approval requests, never another
//! agent's. Nothing returned is secret: amounts, assets, recipients, times,
//! and the agent's own pending actions with their reasons.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;

use agentpay_domain::u128_as_decimal_string;

use crate::auth::AgentAuth;
use crate::types::{AssetId, DecimalU128, ManualApprovalRequest, RecipientId, Timestamp};

/// Entries per list when `limit` is absent.
pub const DEFAULT_ACTIVITY_LIMIT: u16 = 50;

/// Largest `limit`; larger values are capped.
pub const MAX_ACTIVITY_LIMIT: u16 = 200;

/// `AgentActivity`: the calling agent's recent spends and approval requests.
///
/// | | |
/// |---|---|
/// | Access | agent allowlist |
/// | Auth | agent token |
/// | Response | [`DaemonRpcResponse::AgentActivity`](crate::DaemonRpcResponse::AgentActivity) |
/// | Side effects | none |
/// | Idempotent | yes (results follow new spends and decisions) |
/// | Since | API 1.1.0 (capability `AgentActivity`) |
///
/// - `spends`: the agent's spend log entries (every signature that counts
///   toward its limits), newest first, at or after `since` when given. The
///   log keeps 8 days.
/// - `approvals`: the agent's manual approval requests: every pending one
///   first (newest first, regardless of `since`), then the decided ones
///   (`approved`, `rejected`, `completed`) by last change, newest first,
///   changed at or after `since` when given. Decided requests are kept for 8
///   days, pending ones expire after 24 hours.
///
/// Each list holds at most `limit` entries (default
/// [`DEFAULT_ACTIVITY_LIMIT`], capped at [`MAX_ACTIVITY_LIMIT`]; `0` returns
/// empty lists). The request carries no timestamps, so it is not subject to
/// the signing freshness rules and consumes no request id.
///
/// **Errors:** `AgentAuthenticationFailed`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AgentActivity.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/AgentActivity.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentActivityParams {
    /// The agent's credentials; the result covers this agent only.
    pub auth: AgentAuth,
    /// Only spends at or after, and decided requests changed at or after,
    /// this time (UTC); absent: everything retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Timestamp>")]
    #[ts(optional, as = "Option<Timestamp>")]
    pub since: Option<OffsetDateTime>,
    /// Entries per list (default 50, capped at 200).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub limit: Option<u16>,
}

/// One signature that counted toward the agent's limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentSpend {
    /// Policy chain id (EVM chain id, or `900000001` for every Solana cluster).
    pub chain_id: u64,
    /// The asset spent.
    pub asset: AssetId,
    /// The recipient (or spender).
    pub recipient: RecipientId,
    /// Amount in the asset's base units (decimal string).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub amount_wei: u128,
    /// When it was signed (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub at: OffsetDateTime,
    /// The approval request that let it go beyond the agent's limits;
    /// `null` when it was within them.
    pub approval_request_id: Option<Uuid>,
}

/// Result of `AgentActivity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentActivityReport {
    /// The agent the report covers.
    pub agent_key_id: Uuid,
    /// Spends, newest first.
    pub spends: Vec<AgentSpend>,
    /// Approval requests: pending first, then decided ones (see
    /// [`AgentActivityParams`]).
    pub approvals: Vec<ManualApprovalRequest>,
    /// When the report was made (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub as_of: OffsetDateTime,
}
