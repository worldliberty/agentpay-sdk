//! `Activity` (API 1.1): the calling agent's recent payments and approval
//! requests, as the signer daemon's `AgentActivity` reports them, with the
//! network, symbol, decimals, and a human-readable amount added from the
//! payments configuration.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::AgentAuth;
use crate::rpc::activity::AgentSpend;
use crate::types::{ManualApprovalRequest, Timestamp};

/// `Activity`: the calling agent's recent payments and approval requests.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`PaymentsRpcResponse::Activity`](crate::payments::PaymentsRpcResponse::Activity) |
/// | Side effects | none |
/// | Idempotent | yes (results follow new payments and decisions) |
/// | Since | API 1.1.0 (capability `Activity`) |
///
/// The service forwards `since` and `limit` to the signer daemon's
/// `AgentActivity` (see [`AgentActivityParams`](crate::rpc::AgentActivityParams):
/// spends newest first; pending requests first, then decided ones; at most
/// `limit` per list, default 50, capped at 200) and adds to each entry what
/// the configuration knows about its asset on its chain. The result covers
/// only the calling agent.
///
/// **Labels:** `network` is the first configured chain key (in key order)
/// whose `chain_id` is the entry's (the Solana policy id `900000001` matches
/// any Solana cluster); `symbol` and `decimals` come from the configured
/// token with a deployment of the entry's asset on that network (the native
/// deployment for a native coin); `amount` is the base-unit amount in whole
/// tokens. Each is `null` when the configuration does not know it.
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/Activity.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/Activity.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ActivityParams {
    /// Agent credentials; the result covers this agent only.
    pub auth: AgentAuth,
    /// Only payments at or after, and decided requests changed at or after,
    /// this time (UTC); absent: everything the signer daemon retains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<Timestamp>")]
    #[ts(optional, as = "Option<Timestamp>")]
    pub since: Option<OffsetDateTime>,
    /// Entries per list (default 50, capped at 200).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub limit: Option<u16>,
}

/// What the configuration says about an entry's asset on its chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ActivityAsset {
    /// Configured chain key, for example `"bsc"`; `null` when no configured
    /// chain has the entry's chain id.
    pub network: Option<String>,
    /// Token symbol, for example `"USD1"`; `null` when the asset is not configured.
    pub symbol: Option<String>,
    /// Token decimals; `null` when the asset is not configured.
    pub decimals: Option<u8>,
    /// The amount in whole tokens (for example `"150"`); `null` without `decimals`.
    pub amount: Option<String>,
}

/// One payment, with its configured labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ActivitySpend {
    /// The signer daemon's record.
    #[serde(flatten)]
    #[ts(flatten)]
    pub spend: AgentSpend,
    /// Labels from the configuration.
    #[serde(flatten)]
    #[ts(flatten)]
    pub labels: ActivityAsset,
}

/// One approval request, with its configured labels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ActivityApproval {
    /// The signer daemon's request, reasons included.
    #[serde(flatten)]
    #[ts(flatten)]
    pub request: ManualApprovalRequest,
    /// Labels from the configuration.
    #[serde(flatten)]
    #[ts(flatten)]
    pub labels: ActivityAsset,
}

/// Result of `Activity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ActivityResult {
    /// The calling agent.
    pub agent_key_id: Uuid,
    /// Payments, newest first.
    pub spends: Vec<ActivitySpend>,
    /// Approval requests: pending first, then decided ones.
    pub approvals: Vec<ActivityApproval>,
    /// When the signer daemon made the report (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub as_of: OffsetDateTime,
}
