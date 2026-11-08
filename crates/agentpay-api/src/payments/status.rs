//! `Status`: a health report of the payments service, as seen by one agent.
//!
//! It answers "can this agent pay right now, and if not, why": whether the
//! signer daemon answers and speaks a compatible API version, whether the
//! configuration is valid, which chains answer, who the agent is, whether any
//! spending policy governs it, and whether telemetry is on. Problems that
//! need a person are listed in `warnings`, each with a stable `code` that
//! clients can map to their own wording.
//!
//! # Checks
//!
//! - **Signer daemon:** `Hello` over the signer socket; `compatible` follows
//!   the major-version rule of the handshake.
//! - **Configuration:** the stored configuration is validated again.
//! - **Chains:** every configured chain with an `rpc_url` is checked in
//!   parallel (at most 16 at a time), each within 5 seconds: EVM chains must
//!   answer `eth_chainId` with the configured id and `eth_blockNumber`;
//!   Solana chains must serve the configured cluster (genesis hash, except
//!   for loopback URLs) and answer `getLatestBlockhash`. When `rpc_url`
//!   fails, the chain's `fallback_rpc_urls` are tried in order and
//!   `using_backup_rpc` says that one of them answered. Chains without an
//!   `rpc_url` are listed with `reachable: null`.
//! - **Policies:** the signer daemon's `AgentPolicySummary`. With no
//!   spending policy the agent cannot spend: every payment is denied until an
//!   operator sets limits (`no_spending_policy`).
//!
//! # Warning codes
//!
//! | Code | Meaning |
//! |---|---|
//! | `signer_incompatible` | the signer daemon speaks another major API version |
//! | `signer_unavailable` | the signer daemon did not answer `Hello` (it answered the authentication, so this is transient) |
//! | `invalid_config` | the configuration failed validation |
//! | `no_spending_policy` | no spending policy governs the agent, so it cannot spend until limits are set |
//! | `policy_status_unavailable` | the signer daemon could not report the agent's policies |
//! | `default_network_unconfigured` | the default network has no `rpc_url` |
//! | `chain_unreachable` | a configured chain did not answer (`network` names it) |
//! | `no_evm_address` | the vault key has no EVM address (an `ed25519` key) |
//! | `no_solana_address` | the signer backend cannot sign for Solana |

use agentpay_domain::{EvmAddress, KeyAlgorithm, SolanaAddress};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use super::{ChainFamily, WirePaymentsError};
use crate::auth::AgentAuth;
use crate::types::AgentPolicySummary;

/// `Status`: the service's health as seen by the calling agent.
///
/// | | |
/// |---|---|
/// | Access | payments client allowlist |
/// | Auth | agent token, verified by the signer daemon |
/// | Response | [`Status`](crate::payments::PaymentsRpcResponse::Status) |
/// | Side effects | none |
/// | Idempotent | yes (results follow the chains and the signer daemon) |
///
/// Takes at most about 10 seconds: the chain checks share a 5-second budget
/// per chain and run in parallel. Failed checks are reported in the result,
/// never as an error. If the signer daemon is down, the call fails with
/// `SignerUnavailable` before any check, because it authenticates the
/// caller; a client should show that as "signer daemon unreachable".
///
/// **Errors:** `AgentAuthenticationFailed`, `SignerUnavailable`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/Status.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/payments/wallet/Status.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StatusParams {
    /// Agent credentials.
    pub auth: AgentAuth,
}

/// The result of `Status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StatusResult {
    /// The payments service.
    pub service: ServiceStatus,
    /// The signer daemon.
    pub signer: SignerStatus,
    /// The calling agent.
    pub agent: AgentStatus,
    /// The configuration.
    pub config: ConfigStatus,
    /// One entry per configured chain, sorted by key.
    pub chains: Vec<ChainStatus>,
    /// The policies that govern the agent; `null` when the signer daemon
    /// could not report them (see `warnings`).
    pub policies: Option<AgentPolicySummary>,
    /// Whether the agent can spend at all: at least one spending policy governs it.
    pub can_spend: bool,
    /// Whether anonymous telemetry is being sent (see `TelemetryStatus`).
    pub telemetry_enabled: bool,
    /// Problems that need attention; empty when everything is fine.
    pub warnings: Vec<StatusWarning>,
}

/// The payments service's own versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ServiceStatus {
    /// The wire-contract version it implements.
    pub api_version: String,
    /// Its release version.
    pub service_version: String,
}

/// What the signer daemon's `Hello` reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SignerStatus {
    /// Whether it answered `Hello`.
    pub reachable: bool,
    /// Its API version; `null` when it did not answer.
    pub api_version: Option<String>,
    /// Its release version; `null` when it did not answer.
    pub daemon_version: Option<String>,
    /// Whether its API version is compatible with the payments service's.
    pub compatible: bool,
}

/// The calling agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentStatus {
    /// The agent key.
    pub agent_key_id: Uuid,
    /// The vault key that signs for it.
    pub vault_key_id: Uuid,
    /// The vault key's algorithm.
    pub algorithm: KeyAlgorithm,
    /// The wallet's EVM address; `null` for an `ed25519` key.
    pub evm_address: Option<EvmAddress>,
    /// The wallet's Solana address; `null` when the backend cannot sign for Solana.
    pub solana_address: Option<SolanaAddress>,
}

/// The configuration, summarized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ConfigStatus {
    /// Whether it passes validation.
    pub valid: bool,
    /// Why not; `null` when valid.
    pub error: Option<String>,
    /// The default network.
    pub default_network: String,
    /// The default asset.
    pub default_asset: String,
    /// Configured chains.
    pub chain_count: u32,
    /// Configured tokens.
    pub token_count: u32,
}

/// One configured chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ChainStatus {
    /// Chain key.
    pub network: String,
    /// Chain id (internal ids for Solana clusters).
    pub chain_id: u64,
    /// Display name.
    pub chain_name: String,
    /// Family.
    pub family: ChainFamily,
    /// Whether it has an `rpc_url`.
    pub rpc_configured: bool,
    /// Whether the endpoint answered as the configured chain; `null` when
    /// there is no `rpc_url` to check.
    pub reachable: Option<bool>,
    /// Latest block number (EVM only); `null` otherwise.
    pub block_number: Option<u64>,
    /// Whether the check was answered by one of the chain's
    /// `fallback_rpc_urls` because `rpc_url` failed (API 1.1); `false` when
    /// it was answered by `rpc_url` or not at all. Which backup answered is
    /// never reported.
    pub using_backup_rpc: bool,
    /// Why the check failed; `null` otherwise. Never contains the URL.
    pub error: Option<WirePaymentsError>,
}

/// A problem `Status` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct StatusWarning {
    /// Stable code (see the [module docs](self)).
    pub code: StatusWarningCode,
    /// An English explanation.
    pub message: String,
    /// The chain it concerns, for chain warnings; `null` otherwise.
    pub network: Option<String>,
}

/// Stable warning codes; clients must treat unknown codes as generic warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum StatusWarningCode {
    /// The signer daemon speaks another major API version.
    SignerIncompatible,
    /// The signer daemon did not answer `Hello`.
    SignerUnavailable,
    /// The configuration failed validation.
    InvalidConfig,
    /// No spending policy governs the agent: it cannot spend until limits are set.
    NoSpendingPolicy,
    /// The signer daemon could not report the agent's policies.
    PolicyStatusUnavailable,
    /// The default network has no `rpc_url`.
    DefaultNetworkUnconfigured,
    /// A configured chain did not answer.
    ChainUnreachable,
    /// The vault key has no EVM address.
    NoEvmAddress,
    /// The signer backend cannot sign for Solana.
    NoSolanaAddress,
}
