//! Spending limits: one row of per-transaction, daily, and weekly caps per
//! network and asset, managed as a whole for one agent key.
//!
//! A spending limit is a convenience view over ordinary spending policies.
//! `SetSpendingLimits` (and `BootstrapWallet`) turns each [`SpendingLimit`]
//! into policies scoped to exactly that network and asset, attaches exactly
//! those policies to the agent key (a `PolicySet`), and `ListSpendingLimits`
//! reads them back together with what the agent has spent.
//!
//! # Deny by default
//!
//! An agent may spend **only** the assets that have a limit row. There is no
//! "unrestricted" fallback: an asset without a row (on a network without a
//! row for it) has no applicable policy, and the signer daemon denies every
//! payment in it with `NoApplicablePolicies`. To let an agent spend a new
//! token, add a row for it; to stop it, remove the row. Every policy a row
//! creates, gas caps included, is scoped to that row's asset, so a row never
//! makes another asset spendable.
//!
//! # Beyond a limit: approval
//!
//! A row's per-payment, daily, weekly, and daily-count limits are the
//! amounts an agent may pay **on its own**. A payment beyond any of them is
//! not denied: `SignForAgent` holds it as a manual approval request
//! (`ManualApprovalRequired`), and an operator approves or rejects it with
//! `DecideManualApprovalRequest`. The request lists every limit it goes
//! beyond in `reasons`; an approved payment counts toward the windows like
//! any other. Gas and fee caps stay hard limits, and an asset without a row
//! is still never spendable. (API 1.1; API 1.0 had a separate
//! `manual_approval_min_wei` instead, now removed.)
//!
//! # Rows and the policies behind them
//!
//! | Field | Policy |
//! |---|---|
//! | `per_tx_max_wei` | `PerTxMaxSpending`, `over_limit: manual_approval` |
//! | `daily_max_wei` | `DailyMaxSpending` (rolling 24 hours), `over_limit: manual_approval` |
//! | `weekly_max_wei` | `WeeklyMaxSpending` (rolling 7 days), `over_limit: manual_approval` |
//! | `max_gas_per_tx_wei` | `PerChainMaxGasSpend` (`gas_limit * max_fee_per_gas` of one transaction) |
//! | `max_fee_per_gas_wei` | `PerTxMaxFeePerGas` |
//! | `max_priority_fee_per_gas_wei` | `PerTxMaxPriorityFeePerGas` |
//! | `daily_max_tx_count` | `DailyMaxTxCount` (rolling 24 hours), `over_limit: manual_approval` |
//!
//! Every policy has recipient scope "all", asset scope `{asset}`, and network
//! scope `{chain_id}`. A row read back from policies ignores a legacy
//! `ManualApproval` range policy of the same network and asset; replacing
//! the rows retires it. Generic EIP-712 (`Eip712Signing`) policies are not
//! spending limits: `SetSpendingLimits` keeps the ones attached to the agent.
//!
//! # Usage
//!
//! Usage comes from the signer daemon's spend log, exactly as the policy
//! engine counts it: every signature for the agent, asset, and network in the
//! rolling window, including spends stamped in the future after a clock step.
//! A signed transaction counts even if it was never broadcast or failed on
//! chain; the daemon cannot see the network.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;

use agentpay_domain::u128_as_decimal_string;

use crate::auth::AdminAuth;
use crate::types::{AssetId, DecimalU128, Timestamp};

/// Maximum number of rows in one limit set.
pub const MAX_SPENDING_LIMITS: usize = 64;

/// One network and asset an agent may spend, with its caps.
///
/// All amounts are in the asset's base units (wei, token base units,
/// lamports) as decimal strings. Validation (`InvalidSpendingLimits`):
///
/// - `chain_id` is not 0. Solana rows use any Solana id (`900000001`,
///   `900000002`, `900000003`) and are reported as `900000001`, because every
///   Solana cluster shares one policy network.
/// - `asset` matches the chain family: `native_eth` or `erc20` on EVM chains,
///   `native_sol` or `spl_token` on Solana.
/// - `0 < per_tx_max_wei <= daily_max_wei <= weekly_max_wei`.
/// - The optional caps, when set, are greater than zero; the gas and fee caps
///   are EVM-only.
/// - No two rows name the same network and asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SpendingLimit {
    /// Network: an EVM chain id (`56` for BNB Smart Chain) or a Solana id.
    pub chain_id: u64,
    /// The asset this row allows.
    pub asset: AssetId,
    /// Largest single payment the agent makes on its own; beyond it, a
    /// payment waits for approval.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub per_tx_max_wei: u128,
    /// Total over any rolling 24 hours the agent spends on its own.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub daily_max_wei: u128,
    /// Total over any rolling 7 days the agent spends on its own.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub weekly_max_wei: u128,
    /// EVM only: largest `gas_limit * max_fee_per_gas` of one transaction, in wei.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_gas_per_tx_wei: Option<u128>,
    /// EVM only: largest `maxFeePerGas`, in wei.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_fee_per_gas_wei: Option<u128>,
    /// EVM only: largest `maxPriorityFeePerGas`, in wei.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub max_priority_fee_per_gas_wei: Option<u128>,
    /// Most signatures over any rolling 24 hours.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(optional, as = "Option<DecimalU128>")]
    pub daily_max_tx_count: Option<u128>,
}

/// What an agent has spent of one [`SpendingLimit`], and what is left.
///
/// Windows are rolling and end now: "24h" is the last 24 hours, "7d" the
/// last 7 days. `remaining_*` never goes below zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SpendingUsage {
    /// Signed in the last 24 hours, in base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub spent_24h_wei: u128,
    /// Signed in the last 7 days, in base units.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub spent_7d_wei: u128,
    /// Signatures in the last 24 hours.
    pub tx_count_24h: u64,
    /// `daily_max_wei - spent_24h_wei`.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub remaining_24h_wei: u128,
    /// `weekly_max_wei - spent_7d_wei`.
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub remaining_7d_wei: u128,
    /// The largest payment that fits right now: the least of
    /// `per_tx_max_wei`, `remaining_24h_wei`, and `remaining_7d_wei` (0 when
    /// `daily_max_tx_count` is used up).
    #[serde(with = "u128_as_decimal_string")]
    #[schemars(with = "DecimalU128")]
    #[ts(as = "DecimalU128")]
    pub available_now_wei: u128,
}

/// One row of a [`SpendingLimitsReport`]: the limit, its policies, and usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SpendingLimitStatus {
    /// The limit, as read back from the policies.
    pub limit: SpendingLimit,
    /// The policies that enforce it, ascending.
    pub policy_ids: Vec<Uuid>,
    /// Spent and remaining amounts.
    pub usage: SpendingUsage,
}

/// An agent's spending limits with their usage, returned by
/// `ListSpendingLimits`, `SetSpendingLimits`, and `BootstrapWallet`.
///
/// Rows are read from the enabled policies that govern the agent: a network
/// and asset appear when single-network, single-asset, all-recipient policies
/// give them a per-transaction, daily, and weekly cap (when several policies
/// cap the same thing, the smallest cap is shown, since all of them apply).
/// Any other enabled spending policy that governs the agent, such as one
/// added with `AddPolicy` for several assets or for chosen recipients, is
/// listed in `other_policy_ids`: it still applies, but this view cannot show
/// it as a row. `SetSpendingLimits` detaches such policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SpendingLimitsReport {
    /// The agent key.
    pub agent_key_id: Uuid,
    /// One row per network and asset, sorted by `chain_id`, then `asset`.
    pub limits: Vec<SpendingLimitStatus>,
    /// Enabled spending policies of the agent that are not part of a row, ascending.
    pub other_policy_ids: Vec<Uuid>,
    /// When usage was computed (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub as_of: OffsetDateTime,
}

/// `ListSpendingLimits`: an agent's spending limits and how much of each it has used.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::SpendingLimits`](crate::DaemonRpcResponse::SpendingLimits) |
/// | Side effects | none |
/// | Idempotent | yes (usage follows the spend log) |
///
/// See the [module docs](self) for how rows are derived from policies and how
/// usage is counted.
///
/// **Errors:** admin-auth kinds, `UnknownAgentKey`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListSpendingLimits.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListSpendingLimits.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListSpendingLimitsParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// The agent key.
    pub agent_key_id: Uuid,
}

/// `SetSpendingLimits`: replaces an agent's spending limits, atomically.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::SpendingLimits`](crate::DaemonRpcResponse::SpendingLimits) |
/// | Side effects | adds one policy per configured cap; attaches exactly those (plus the agent's `Eip712Signing` policies) as the agent's `PolicySet`; disables the agent's previous spending policies that no other agent key can be governed by; persists |
/// | Idempotent | yes in effect: the same limits give the same rows (with new policy ids) |
///
/// Deny by default: after the call the agent can spend only the listed
/// network and asset pairs (see the [module docs](self)). The agent's token
/// does not change and its spend history is kept, so lowering a cap below
/// what was already spent blocks further payments until the window rolls on.
/// Previous policies that another agent key still uses are left enabled and
/// only detached from this one; an agent key attached to `AllPolicies` uses
/// every enabled policy, so while one exists nothing is disabled. Either the
/// whole change is applied or nothing is.
///
/// **Errors:** admin-auth kinds, `UnknownAgentKey`, `InvalidSpendingLimits`
/// (empty list, more than [`MAX_SPENDING_LIMITS`] rows, or a row that fails
/// validation), `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/SetSpendingLimits.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/SetSpendingLimits.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SetSpendingLimitsParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// The agent key.
    pub agent_key_id: Uuid,
    /// The complete new limit set: 1 to [`MAX_SPENDING_LIMITS`] rows. To stop
    /// an agent from spending at all, revoke its key instead.
    pub limits: Vec<SpendingLimit>,
}
