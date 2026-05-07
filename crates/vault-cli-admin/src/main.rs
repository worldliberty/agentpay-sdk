use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use vault_daemon::{DaemonError, KeyManagerDaemonApi};
use vault_domain::{
    canonical_policy_chain_id, is_solana_chain_id, AdminSession, AgentAction,
    ApprovalType as DomainApprovalType, AssetId, EntityScope, EvmAddress, KeyAlgorithm,
    ManualApprovalDecision, ManualApprovalRequest, PolicyAttachment, PolicyType, RecipientId,
    RelayConfig, SolanaAddress, SpendingPolicy, DEFAULT_MAX_GAS_SPEND_PER_CHAIN_WEI,
};
use vault_signer::KeyCreateRequest;
use vault_transport_unix::{assert_root_owned_daemon_socket_path, UnixDaemonClient};
use zeroize::Zeroize;

mod io_utils;
mod shared_config;
mod tui;

use io_utils::*;

#[derive(Debug, Parser)]
#[command(name = "agentpay-admin")]
#[command(about = "Admin CLI for configuring vault policies and agent keys")]
struct Cli {
    #[arg(
        long,
        default_value_t = false,
        help = "Read vault password from stdin (trailing newlines are trimmed)"
    )]
    vault_password_stdin: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Do not prompt for password; require --vault-password-stdin"
    )]
    non_interactive: bool,
    #[arg(
        long,
        short = 'f',
        value_enum,
        value_name = "text|json",
        help = "Output format"
    )]
    format: Option<OutputFormat>,
    #[arg(
        long,
        short = 'j',
        default_value_t = false,
        help = "Shortcut for --format json"
    )]
    json: bool,
    #[arg(
        long,
        short = 'q',
        default_value_t = false,
        help = "Suppress non-essential status messages in text mode"
    )]
    quiet: bool,
    #[arg(
        long,
        short = 'o',
        value_name = "PATH",
        help = "Write final command output to PATH (use '-' for stdout)"
    )]
    output: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = false,
        requires = "output",
        help = "Allow replacing an existing output file"
    )]
    overwrite: bool,
    #[arg(
        long,
        env = "AGENTPAY_DAEMON_SOCKET",
        value_name = "PATH",
        help = "Always-on daemon unix socket path (default: $AGENTPAY_HOME/daemon.sock or ~/.agentpay/daemon.sock)"
    )]
    daemon_socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug)]
enum OutputTarget {
    Stdout,
    File { path: PathBuf, overwrite: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ApprovalTypeArg {
    Allow,
    ManualApproval,
    Deny,
}

impl From<ApprovalTypeArg> for DomainApprovalType {
    fn from(value: ApprovalTypeArg) -> Self {
        match value {
            ApprovalTypeArg::Allow => Self::Allow,
            ApprovalTypeArg::ManualApproval => Self::ManualApproval,
            ApprovalTypeArg::Deny => Self::Deny,
        }
    }
}

#[derive(Debug, Args)]
struct BootstrapCommandArgs {
    #[arg(
        long,
        default_value_t = false,
        help = "Load per-token bootstrap policies from the saved shared config instead of legacy global defaults"
    )]
    from_shared_config: bool,
    #[arg(
        long,
        default_value_t = 1_000_000_000_000_000_000u128,
        value_parser = parse_positive_u128
    )]
    per_tx_max_wei: u128,
    #[arg(
        long,
        default_value_t = 5_000_000_000_000_000_000u128,
        value_parser = parse_positive_u128
    )]
    daily_max_wei: u128,
    #[arg(
        long,
        default_value_t = 20_000_000_000_000_000_000u128,
        value_parser = parse_positive_u128
    )]
    weekly_max_wei: u128,
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_GAS_SPEND_PER_CHAIN_WEI,
        value_parser = parse_positive_u128
    )]
    max_gas_per_chain_wei: u128,
    #[arg(long, default_value_t = 0u128, value_parser = parse_non_negative_u128)]
    daily_max_tx_count: u128,
    #[arg(long, default_value_t = 0u128, value_parser = parse_non_negative_u128)]
    per_tx_max_fee_per_gas_wei: u128,
    #[arg(long, default_value_t = 0u128, value_parser = parse_non_negative_u128)]
    per_tx_max_priority_fee_per_gas_wei: u128,
    #[arg(long, default_value_t = 0u128, value_parser = parse_non_negative_u128)]
    per_tx_max_calldata_bytes: u128,
    #[arg(long)]
    token: Vec<EvmAddress>,
    #[arg(long, default_value_t = false)]
    allow_native_eth: bool,
    #[arg(long, value_parser = parse_positive_u64)]
    network: Option<u64>,
    #[arg(long)]
    recipient: Option<EvmAddress>,
    #[arg(
        long,
        value_name = "UUID",
        help = "Attach new agent key to an explicit existing policy id (repeatable)"
    )]
    attach_policy_id: Vec<Uuid>,
    #[arg(
        long,
        default_value_t = false,
        help = "Attach the agent key to the current enabled daemon policies in addition to any policies created during this bootstrap"
    )]
    attach_bootstrap_policies: bool,
    #[arg(
        long,
        value_name = "UUID",
        requires = "existing_vault_public_key",
        help = "Reuse an existing vault key id instead of generating a fresh wallet"
    )]
    existing_vault_key_id: Option<Uuid>,
    #[arg(
        long,
        value_name = "HEX",
        requires = "existing_vault_key_id",
        help = "Reuse an existing vault public key instead of generating a fresh wallet"
    )]
    existing_vault_public_key: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = [
            "existing_vault_key_id",
            "existing_vault_public_key",
            "print_vault_private_key"
        ],
        help = "Import an existing software-wallet private key from a private file"
    )]
    import_vault_private_key_file: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    print_agent_auth_token: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Include the vault private key in bootstrap output when generating a new software wallet (high risk)"
    )]
    print_vault_private_key: bool,
}

#[derive(Debug, Args)]
struct RotateAgentAuthTokenCommandArgs {
    #[arg(long, value_name = "UUID", help = "Agent key id to rotate")]
    agent_key_id: Uuid,
    #[arg(long, default_value_t = false)]
    print_agent_auth_token: bool,
}

#[derive(Debug, Args)]
struct RevokeAgentKeyCommandArgs {
    #[arg(long, value_name = "UUID", help = "Agent key id to revoke")]
    agent_key_id: Uuid,
}

#[derive(Debug, Args)]
struct ExportVaultPrivateKeyCommandArgs {
    #[arg(long, value_name = "UUID", help = "Vault key id to export")]
    vault_key_id: Uuid,
}

#[derive(Debug, Args)]
struct AddManualApprovalPolicyCommandArgs {
    #[arg(long, default_value_t = 100u32)]
    priority: u32,
    #[arg(long, value_parser = parse_positive_u128)]
    min_amount_wei: u128,
    #[arg(long, value_parser = parse_positive_u128)]
    max_amount_wei: u128,
    #[arg(long)]
    token: Vec<EvmAddress>,
    #[arg(long, default_value_t = false)]
    allow_native_eth: bool,
    #[arg(long, value_parser = parse_positive_u64)]
    network: Option<u64>,
    #[arg(long)]
    recipient: Option<EvmAddress>,
}

#[derive(Debug, Args)]
struct AddEip712SigningPolicyCommandArgs {
    #[arg(long, default_value_t = 100u32)]
    priority: u32,
    #[arg(long, value_enum, default_value_t = ApprovalTypeArg::ManualApproval)]
    approval_type: ApprovalTypeArg,
    #[arg(long, value_parser = parse_positive_u64)]
    network: Option<u64>,
}

#[derive(Debug, Args)]
struct ApproveManualApprovalRequestCommandArgs {
    #[arg(long, value_name = "UUID")]
    approval_request_id: Uuid,
}

#[derive(Debug, Args)]
struct RejectManualApprovalRequestCommandArgs {
    #[arg(long, value_name = "UUID")]
    approval_request_id: Uuid,
    #[arg(long)]
    rejection_reason: Option<String>,
}

#[derive(Debug, Args)]
struct SetRelayConfigCommandArgs {
    #[arg(long)]
    relay_url: Option<String>,
    #[arg(long)]
    frontend_url: Option<String>,
    #[arg(
        long,
        default_value_t = false,
        conflicts_with_all = ["relay_url", "frontend_url"]
    )]
    clear: bool,
}

#[derive(Debug, Args, Default)]
struct ListPoliciesCommandArgs {
    #[arg(
        long,
        value_name = "UUID",
        help = "Filter to specific policy id values (repeatable)"
    )]
    policy_id: Vec<Uuid>,
}

#[derive(Debug, Args)]
struct SetupCommandArgs {
    #[arg(
        value_name = "ARGS",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Additional setup arguments handled by the TypeScript wrapper"
    )]
    forwarded_args: Vec<String>,
}

#[derive(Debug, Args)]
struct TuiCommandArgs {
    #[arg(
        long,
        default_value_t = false,
        help = "Include the new agent auth token in bootstrap output so the wrapper can import it"
    )]
    print_agent_auth_token: bool,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Create spending policies and issue a vault key + agent key")]
    Bootstrap(Box<BootstrapCommandArgs>),
    #[command(about = "Export the private key for an existing software-backed vault key")]
    ExportVaultPrivateKey(ExportVaultPrivateKeyCommandArgs),
    #[command(about = "Rotate the bearer token for an existing agent key")]
    RotateAgentAuthToken(RotateAgentAuthTokenCommandArgs),
    #[command(about = "Revoke an existing agent key and invalidate its bearer token")]
    RevokeAgentKey(RevokeAgentKeyCommandArgs),
    #[command(
        about = "Create a manual-approval policy for matching destination/token/amount requests"
    )]
    AddManualApprovalPolicy(AddManualApprovalPolicyCommandArgs),
    #[command(about = "Create an EIP-712 signing policy for matching network scopes")]
    AddEip712SigningPolicy(AddEip712SigningPolicyCommandArgs),
    #[command(about = "List spending policies and inspect policy contents")]
    ListPolicies(ListPoliciesCommandArgs),
    #[command(about = "List manual approval requests")]
    ListManualApprovalRequests,
    #[command(about = "Approve a pending manual approval request")]
    ApproveManualApprovalRequest(ApproveManualApprovalRequestCommandArgs),
    #[command(about = "Reject a pending manual approval request")]
    RejectManualApprovalRequest(RejectManualApprovalRequestCommandArgs),
    #[command(about = "Legacy relay config command (ignored in this release)")]
    SetRelayConfig(SetRelayConfigCommandArgs),
    #[command(about = "Legacy relay config command (ignored in this release)")]
    GetRelayConfig,
    #[command(about = "Launch interactive terminal UI for bootstrap configuration")]
    Tui(TuiCommandArgs),
    #[command(
        about = "Install daemon autostart and bootstrap wallet access via the TypeScript wrapper"
    )]
    Setup(SetupCommandArgs),
}

#[derive(Debug, Serialize)]
struct BootstrapOutput {
    state_file: String,
    lease_id: String,
    lease_expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weekly_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_max_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weekly_max_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_gas_per_chain_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_max_tx_count: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_tx_count_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes_policy_id: Option<String>,
    vault_key_id: String,
    vault_key_algorithm: String,
    vault_public_key: String,
    solana_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_private_key: Option<String>,
    agent_key_id: String,
    agent_auth_token: String,
    agent_auth_token_redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_scope: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_policies: Vec<TokenPolicyOutput>,
    destination_override_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    destination_overrides: Vec<DestinationOverrideOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_destination_overrides: Vec<TokenDestinationOverrideOutput>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_manual_approval_policies: Vec<TokenManualApprovalPolicyOutput>,
    policy_attachment: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attached_policy_ids: Vec<String>,
    policy_note: String,
}

#[derive(Debug, Serialize)]
struct ExportVaultPrivateKeyOutput {
    vault_key_id: String,
    vault_private_key: String,
}

#[derive(Debug, Serialize)]
struct DestinationOverrideOutput {
    recipient: String,
    per_tx_policy_id: String,
    daily_policy_id: String,
    weekly_policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_policy_id: Option<String>,
    per_tx_max_wei: String,
    daily_max_wei: String,
    weekly_max_wei: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_gas_per_chain_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_max_tx_count: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_tx_count_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes_policy_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenPolicyOutput {
    token_key: String,
    symbol: String,
    chain_key: String,
    chain_id: u64,
    asset_scope: String,
    recipient_scope: String,
    per_tx_policy_id: String,
    daily_policy_id: String,
    weekly_policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_policy_id: Option<String>,
    per_tx_max_wei: String,
    daily_max_wei: String,
    weekly_max_wei: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_gas_per_chain_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_max_tx_count: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_tx_count_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes_policy_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenDestinationOverrideOutput {
    token_key: String,
    symbol: String,
    chain_key: String,
    chain_id: u64,
    recipient: String,
    asset_scope: String,
    per_tx_policy_id: String,
    daily_policy_id: String,
    weekly_policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_policy_id: Option<String>,
    per_tx_max_wei: String,
    daily_max_wei: String,
    weekly_max_wei: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_gas_per_chain_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_max_tx_count: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily_tx_count_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_wei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_priority_fee_per_gas_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_tx_max_calldata_bytes_policy_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenManualApprovalPolicyOutput {
    token_key: String,
    symbol: String,
    chain_key: String,
    chain_id: u64,
    priority: u32,
    min_amount_wei: String,
    max_amount_wei: String,
    asset_scope: String,
    recipient_scope: String,
    policy_id: String,
}

#[derive(Debug, Serialize)]
struct RotateAgentAuthTokenOutput {
    agent_key_id: String,
    agent_auth_token: String,
    agent_auth_token_redacted: bool,
}

#[derive(Debug, Serialize)]
struct RevokeAgentKeyOutput {
    agent_key_id: String,
    revoked: bool,
}

#[derive(Debug, Serialize)]
struct ManualApprovalPolicyOutput {
    policy_id: String,
    priority: u32,
    min_amount_wei: String,
    max_amount_wei: String,
    network_scope: String,
    asset_scope: String,
    recipient_scope: String,
}

#[derive(Debug, Serialize)]
struct Eip712SigningPolicyOutput {
    policy_id: String,
    priority: u32,
    approval_type: String,
    network_scope: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DestinationPolicyOverride {
    recipient: EvmAddress,
    per_tx_max_wei: u128,
    daily_max_wei: u128,
    weekly_max_wei: u128,
    max_gas_per_chain_wei: u128,
    daily_max_tx_count: u128,
    per_tx_max_fee_per_gas_wei: u128,
    per_tx_max_priority_fee_per_gas_wei: u128,
    per_tx_max_calldata_bytes: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenAddress {
    Evm(EvmAddress),
    Solana(SolanaAddress),
}

impl TokenAddress {
    pub(crate) fn parse(label: &str, chain_id: u64, value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if is_solana_chain_id(chain_id) {
            trimmed
                .parse::<SolanaAddress>()
                .map(Self::Solana)
                .map_err(|err| anyhow::anyhow!("invalid {label} address: {err}"))
        } else {
            trimmed
                .parse::<EvmAddress>()
                .map(Self::Evm)
                .map_err(|err| anyhow::anyhow!("invalid {label} address: {err}"))
        }
    }
}

impl std::fmt::Display for TokenAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Evm(address) => std::fmt::Display::fmt(address, f),
            Self::Solana(address) => std::fmt::Display::fmt(address, f),
        }
    }
}

fn parse_token_recipient(label: &str, chain_id: u64, value: &str) -> Result<RecipientId> {
    let trimmed = value.trim();
    if is_solana_chain_id(chain_id) {
        trimmed
            .parse::<SolanaAddress>()
            .map(RecipientId::Solana)
            .map_err(|err| anyhow::anyhow!("invalid {label}: {err}"))
    } else {
        trimmed
            .parse::<EvmAddress>()
            .map(RecipientId::Evm)
            .map_err(|err| anyhow::anyhow!("invalid {label}: {err}"))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TokenPolicyConfig {
    token_key: String,
    symbol: String,
    chain_key: String,
    chain_id: u64,
    is_native: bool,
    address: Option<TokenAddress>,
    per_tx_max_wei: u128,
    daily_max_wei: u128,
    weekly_max_wei: u128,
    max_gas_per_chain_wei: u128,
    daily_max_tx_count: u128,
    per_tx_max_fee_per_gas_wei: u128,
    per_tx_max_priority_fee_per_gas_wei: u128,
    per_tx_max_calldata_bytes: u128,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenSelectorConfig {
    token_key: String,
    symbol: String,
    chain_key: String,
    chain_id: u64,
    is_native: bool,
    address: Option<TokenAddress>,
}

impl TokenSelectorConfig {
    fn from_token_policy(policy: &TokenPolicyConfig) -> Self {
        Self {
            token_key: policy.token_key.clone(),
            symbol: policy.symbol.clone(),
            chain_key: policy.chain_key.clone(),
            chain_id: policy.chain_id,
            is_native: policy.is_native,
            address: policy.address.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TokenDestinationPolicyOverride {
    token_key: String,
    chain_key: String,
    recipient: RecipientId,
    per_tx_max_wei: u128,
    daily_max_wei: u128,
    weekly_max_wei: u128,
    max_gas_per_chain_wei: u128,
    daily_max_tx_count: u128,
    per_tx_max_fee_per_gas_wei: u128,
    per_tx_max_priority_fee_per_gas_wei: u128,
    per_tx_max_calldata_bytes: u128,
}

#[derive(Debug, Clone)]
pub(crate) struct TokenManualApprovalPolicyConfig {
    token_key: String,
    symbol: String,
    chain_key: String,
    chain_id: u64,
    is_native: bool,
    address: Option<TokenAddress>,
    priority: u32,
    recipient: Option<RecipientId>,
    min_amount_wei: u128,
    max_amount_wei: u128,
}

#[derive(Debug, Clone)]
pub(crate) struct BootstrapParams {
    per_tx_max_wei: u128,
    daily_max_wei: u128,
    weekly_max_wei: u128,
    max_gas_per_chain_wei: u128,
    daily_max_tx_count: u128,
    per_tx_max_fee_per_gas_wei: u128,
    per_tx_max_priority_fee_per_gas_wei: u128,
    per_tx_max_calldata_bytes: u128,
    tokens: Vec<EvmAddress>,
    allow_native_eth: bool,
    network: Option<u64>,
    recipient: Option<EvmAddress>,
    use_per_token_bootstrap: bool,
    attach_bootstrap_policies: bool,
    token_selectors: Vec<TokenSelectorConfig>,
    token_policies: Vec<TokenPolicyConfig>,
    destination_overrides: Vec<DestinationPolicyOverride>,
    token_destination_overrides: Vec<TokenDestinationPolicyOverride>,
    token_manual_approval_policies: Vec<TokenManualApprovalPolicyConfig>,
    attach_policy_ids: Vec<Uuid>,
    print_agent_auth_token: bool,
    print_vault_private_key: bool,
    existing_agent_key_id: Option<Uuid>,
    existing_vault_key_id: Option<Uuid>,
    existing_vault_public_key: Option<String>,
    import_vault_private_key: Option<String>,
}

#[derive(Debug, Clone)]
struct RotateAgentAuthTokenParams {
    agent_key_id: Uuid,
    print_agent_auth_token: bool,
}

#[derive(Debug, Clone)]
struct RevokeAgentKeyParams {
    agent_key_id: Uuid,
}

#[derive(Debug, Clone)]
struct ExportVaultPrivateKeyParams {
    vault_key_id: Uuid,
}

#[derive(Debug, Clone)]
struct AddManualApprovalPolicyParams {
    priority: u32,
    min_amount_wei: u128,
    max_amount_wei: u128,
    tokens: Vec<EvmAddress>,
    allow_native_eth: bool,
    network: Option<u64>,
    recipient: Option<EvmAddress>,
}

#[derive(Debug, Clone)]
struct AddEip712SigningPolicyParams {
    priority: u32,
    approval_type: DomainApprovalType,
    network: Option<u64>,
}

#[derive(Debug, Clone)]
struct DecideManualApprovalRequestParams {
    approval_request_id: Uuid,
    decision: ManualApprovalDecision,
    rejection_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct SetRelayConfigParams {
    relay_url: Option<String>,
    frontend_url: Option<String>,
    clear: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Commands::Setup(args) = &cli.command {
        let forwarded = if args.forwarded_args.is_empty() {
            String::new()
        } else {
            format!(" {}", args.forwarded_args.join(" "))
        };
        bail!(
            "`setup` is implemented by the TypeScript wrapper, not the raw Rust binary. In local development run `node dist/cli.cjs admin setup{forwarded}` after `npm run build`, or `pnpm exec agentpay admin setup{forwarded}`."
        );
    }
    let output_format = resolve_output_format(cli.format, cli.json)?;
    let output_target = resolve_output_target(cli.output, cli.overwrite)?;
    let daemon_socket = resolve_daemon_socket_path(cli.daemon_socket)?;
    let mut vault_password = resolve_vault_password(cli.vault_password_stdin, cli.non_interactive)?;

    let socket_client = Arc::new(UnixDaemonClient::new_with_expected_server_euid(
        daemon_socket.clone(),
        std::time::Duration::from_secs(10),
        0,
    ));
    let daemon_api = socket_client as Arc<dyn KeyManagerDaemonApi>;
    let state_file_display = format!("daemon_socket:{}", daemon_socket.display());

    let result = match cli.command {
        Commands::Bootstrap(args) => {
            let BootstrapCommandArgs {
                from_shared_config,
                per_tx_max_wei,
                daily_max_wei,
                weekly_max_wei,
                max_gas_per_chain_wei,
                daily_max_tx_count,
                per_tx_max_fee_per_gas_wei,
                per_tx_max_priority_fee_per_gas_wei,
                per_tx_max_calldata_bytes,
                token,
                allow_native_eth,
                network,
                recipient,
                attach_policy_id,
                attach_bootstrap_policies,
                existing_vault_key_id,
                existing_vault_public_key,
                import_vault_private_key_file,
                print_agent_auth_token,
                print_vault_private_key,
            } = *args;
            let import_vault_private_key = import_vault_private_key_file
                .as_ref()
                .map(|path| read_secret_from_file(path, "imported vault private key"))
                .transpose()?;
            let params = if from_shared_config {
                let shared_config = shared_config::LoadedConfig::load_default()?;
                build_shared_config_bootstrap_params(
                    &shared_config.config,
                    print_agent_auth_token,
                    network,
                    attach_policy_id,
                    attach_bootstrap_policies,
                    existing_vault_key_id,
                    existing_vault_public_key,
                    import_vault_private_key,
                )?
            } else {
                BootstrapParams {
                    per_tx_max_wei,
                    daily_max_wei,
                    weekly_max_wei,
                    max_gas_per_chain_wei,
                    daily_max_tx_count,
                    per_tx_max_fee_per_gas_wei,
                    per_tx_max_priority_fee_per_gas_wei,
                    per_tx_max_calldata_bytes,
                    tokens: token,
                    allow_native_eth,
                    network,
                    recipient,
                    use_per_token_bootstrap: false,
                    attach_bootstrap_policies,
                    token_selectors: Vec::new(),
                    token_policies: Vec::new(),
                    destination_overrides: Vec::new(),
                    token_destination_overrides: Vec::new(),
                    token_manual_approval_policies: Vec::new(),
                    attach_policy_ids: attach_policy_id,
                    print_agent_auth_token,
                    print_vault_private_key,
                    existing_agent_key_id: None,
                    existing_vault_key_id,
                    existing_vault_public_key,
                    import_vault_private_key,
                }
            };
            let output = execute_bootstrap(
                daemon_api.clone(),
                &vault_password,
                &state_file_display,
                params,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("bootstrap complete", output_format, cli.quiet);
            print_bootstrap_output(&output, output_format, &output_target)
        }
        Commands::ExportVaultPrivateKey(args) => {
            let params = ExportVaultPrivateKeyParams {
                vault_key_id: args.vault_key_id,
            };
            let output = execute_export_vault_private_key(
                daemon_api.clone(),
                &vault_password,
                params,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("vault private key exported", output_format, cli.quiet);
            print_export_vault_private_key_output(&output, output_format, &output_target)
        }
        Commands::RotateAgentAuthToken(args) => {
            let params = RotateAgentAuthTokenParams {
                agent_key_id: args.agent_key_id,
                print_agent_auth_token: args.print_agent_auth_token,
            };
            let output = execute_rotate_agent_auth_token(
                daemon_api.clone(),
                &vault_password,
                params,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("agent auth token rotated", output_format, cli.quiet);
            print_rotate_agent_auth_token_output(&output, output_format, &output_target)
        }
        Commands::RevokeAgentKey(args) => {
            let params = RevokeAgentKeyParams {
                agent_key_id: args.agent_key_id,
            };
            let output =
                execute_revoke_agent_key(daemon_api.clone(), &vault_password, params, |message| {
                    print_status(message, output_format, cli.quiet)
                })
                .await?;
            print_status("agent key revoked", output_format, cli.quiet);
            print_revoke_agent_key_output(&output, output_format, &output_target)
        }
        Commands::AddManualApprovalPolicy(args) => {
            let params = AddManualApprovalPolicyParams {
                priority: args.priority,
                min_amount_wei: args.min_amount_wei,
                max_amount_wei: args.max_amount_wei,
                tokens: args.token,
                allow_native_eth: args.allow_native_eth,
                network: args.network,
                recipient: args.recipient,
            };
            let output = execute_add_manual_approval_policy(
                daemon_api.clone(),
                &vault_password,
                params,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("manual approval policy created", output_format, cli.quiet);
            print_manual_approval_policy_output(&output, output_format, &output_target)
        }
        Commands::AddEip712SigningPolicy(args) => {
            let params = AddEip712SigningPolicyParams {
                priority: args.priority,
                approval_type: args.approval_type.into(),
                network: args.network,
            };
            let output = execute_add_eip712_signing_policy(
                daemon_api.clone(),
                &vault_password,
                params,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("eip712 signing policy created", output_format, cli.quiet);
            print_eip712_signing_policy_output(&output, output_format, &output_target)
        }
        Commands::ListPolicies(args) => {
            let output = execute_list_policies(
                daemon_api.clone(),
                &vault_password,
                &args.policy_id,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_policies_output(&output, output_format, &output_target)
        }
        Commands::ListManualApprovalRequests => {
            let output = execute_list_manual_approval_requests(
                daemon_api.clone(),
                &vault_password,
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_manual_approval_requests_output(&output, output_format, &output_target)
        }
        Commands::ApproveManualApprovalRequest(args) => {
            let output = execute_decide_manual_approval_request(
                daemon_api.clone(),
                &vault_password,
                DecideManualApprovalRequestParams {
                    approval_request_id: args.approval_request_id,
                    decision: ManualApprovalDecision::Approve,
                    rejection_reason: None,
                },
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("manual approval request updated", output_format, cli.quiet);
            print_manual_approval_request_output(&output, output_format, &output_target)
        }
        Commands::RejectManualApprovalRequest(args) => {
            let output = execute_decide_manual_approval_request(
                daemon_api.clone(),
                &vault_password,
                DecideManualApprovalRequestParams {
                    approval_request_id: args.approval_request_id,
                    decision: ManualApprovalDecision::Reject,
                    rejection_reason: args.rejection_reason,
                },
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_status("manual approval request updated", output_format, cli.quiet);
            print_manual_approval_request_output(&output, output_format, &output_target)
        }
        Commands::SetRelayConfig(args) => {
            let output = execute_set_relay_config(
                daemon_api.clone(),
                &vault_password,
                SetRelayConfigParams {
                    relay_url: args.relay_url,
                    frontend_url: args.frontend_url,
                    clear: args.clear,
                },
                |message| print_status(message, output_format, cli.quiet),
            )
            .await?;
            print_relay_config_output(&output, output_format, &output_target)
        }
        Commands::GetRelayConfig => {
            let output = execute_get_relay_config(daemon_api.clone(), &vault_password, |message| {
                print_status(message, output_format, cli.quiet)
            })
            .await?;
            print_relay_config_output(&output, output_format, &output_target)
        }
        Commands::Tui(args) => {
            validate_tui_vault_password(daemon_api.clone(), &vault_password, |message| {
                print_status(message, output_format, cli.quiet)
            })
            .await?;
            let shared_config = shared_config::LoadedConfig::load_default()?;
            if let Some(output) = tui::run_bootstrap_tui(
                &shared_config.config,
                args.print_agent_auth_token,
                |params, on_status| {
                    let mut status_error = None;
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(execute_bootstrap(
                            daemon_api.clone(),
                            &vault_password,
                            &state_file_display,
                            params,
                            |message| {
                                if status_error.is_none() {
                                    status_error = on_status(message).err();
                                }
                            },
                        ))
                    })
                    .and_then(|output| match status_error {
                        Some(err) => Err(err),
                        None => Ok(output),
                    })
                },
            )? {
                print_status("bootstrap complete", output_format, cli.quiet);
                print_bootstrap_output(&output, output_format, &output_target)
            } else {
                print_status("tui canceled", output_format, cli.quiet);
                Ok(())
            }
        }
        Commands::Setup(_) => unreachable!("setup is handled before daemon initialization"),
    };

    vault_password.zeroize();
    result
}

async fn validate_tui_vault_password(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    mut on_status: impl FnMut(&str),
) -> Result<(), DaemonError> {
    on_status("issuing admin lease");
    daemon.issue_lease(vault_password).await?;
    Ok(())
}

async fn execute_bootstrap(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    state_file_display: &str,
    mut params: BootstrapParams,
    mut on_status: impl FnMut(&str),
) -> Result<BootstrapOutput> {
    if params.use_per_token_bootstrap || !params.token_policies.is_empty() {
        return execute_per_token_bootstrap(
            daemon,
            vault_password,
            state_file_display,
            params,
            on_status,
        )
        .await;
    }

    validate_policy_limits(
        params.per_tx_max_wei,
        params.daily_max_wei,
        params.weekly_max_wei,
    )?;
    validate_destination_policy_overrides(&params)?;
    on_status("initializing daemon");

    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease: lease.clone(),
    };
    let result = async {
        let asset_scope = build_asset_scope(&params.tokens, params.allow_native_eth);
        let network_scope = build_network_scope(params.network);
        let recipient_scope: EntityScope<EvmAddress> = params
            .recipient
            .clone()
            .map(single_scope)
            .unwrap_or(EntityScope::All);
        let default_limits = PolicyLimitConfig::from_params(&params);
        let default_bundle = build_policy_bundle(
            DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE,
            &default_limits,
            lift_evm_recipient_scope(recipient_scope.clone()),
            asset_scope.clone(),
            network_scope.clone(),
        )?;

        let mut destination_override_bundles = Vec::with_capacity(params.destination_overrides.len());
        for (index, destination_override) in params
            .destination_overrides
            .iter()
            .cloned()
            .enumerate()
        {
            let priority_base = policy_bundle_priority_base(
                DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE,
                index,
                "destination overrides",
            )?;
            let bundle = build_policy_bundle(
                priority_base,
                &PolicyLimitConfig::from_destination_override(&destination_override),
                single_scope(RecipientId::Evm(destination_override.recipient.clone())),
                asset_scope.clone(),
                network_scope.clone(),
            )?;
            destination_override_bundles.push((destination_override, bundle));
        }

        validate_existing_policy_attachments(daemon.as_ref(), &session, &params.attach_policy_ids)
            .await?;

        on_status("registering spending policies");
        register_policy_bundle(daemon.as_ref(), &session, &default_bundle).await?;
        for (_, bundle) in &destination_override_bundles {
            register_policy_bundle(daemon.as_ref(), &session, bundle).await?;
        }

        let mut created_policy_ids = default_bundle.policy_ids();
        for (_, bundle) in &destination_override_bundles {
            created_policy_ids.extend(bundle.policy_ids());
        }

        let attach_bootstrap_policy_ids = resolve_attach_bootstrap_policy_ids(
            daemon.as_ref(),
            &session,
            params.attach_bootstrap_policies,
        )
        .await?;
        let (policy_attachment, policy_attachment_label, attached_policy_ids, mut policy_note) =
            resolve_bootstrap_policy_attachment(
                created_policy_ids,
                attach_bootstrap_policy_ids,
                &params.attach_policy_ids,
            )?;

        if !params.destination_overrides.is_empty() {
            policy_note.push_str(&format!(
                "; {} destination override(s) apply as stricter overlays and do not replace the default limits",
                params.destination_overrides.len()
            ));
        }

        let (
            vault_key_id,
            vault_key_algorithm,
            vault_public_key,
            solana_public_key,
            vault_private_key,
            key_status_message,
        ) =
            resolve_bootstrap_vault_material(daemon.as_ref(), &session, &mut params, &mut policy_note)
                .await?;
        on_status(key_status_message);
        let mut agent_credentials = if let Some(existing_agent_key_id) = params.existing_agent_key_id
        {
            policy_note.push_str("; refreshed the existing agent key attachment");
            daemon
                .refresh_agent_key(
                    &session,
                    existing_agent_key_id,
                    vault_key_id,
                    policy_attachment.clone(),
                )
                .await?
        } else {
            daemon
                .create_agent_key(&session, vault_key_id, policy_attachment)
                .await?
        };
        let agent_auth_token = if params.print_agent_auth_token {
            std::mem::take(&mut *agent_credentials.auth_token)
        } else {
            agent_credentials.auth_token.zeroize();
            "<redacted>".to_string()
        };

        let destination_override_outputs = destination_override_bundles
            .iter()
            .map(|(destination_override, bundle)| DestinationOverrideOutput {
                recipient: destination_override.recipient.to_string(),
                per_tx_policy_id: bundle.per_tx.id.to_string(),
                daily_policy_id: bundle.daily.id.to_string(),
                weekly_policy_id: bundle.weekly.id.to_string(),
                gas_policy_id: bundle.gas.as_ref().map(|policy| policy.id.to_string()),
                per_tx_max_wei: destination_override.per_tx_max_wei.to_string(),
                daily_max_wei: destination_override.daily_max_wei.to_string(),
                weekly_max_wei: destination_override.weekly_max_wei.to_string(),
                max_gas_per_chain_wei: (destination_override.max_gas_per_chain_wei > 0)
                    .then(|| destination_override.max_gas_per_chain_wei.to_string()),
                daily_max_tx_count: (destination_override.daily_max_tx_count > 0)
                    .then(|| destination_override.daily_max_tx_count.to_string()),
                daily_tx_count_policy_id: bundle
                    .daily_tx_count
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
                per_tx_max_fee_per_gas_wei: (destination_override.per_tx_max_fee_per_gas_wei > 0)
                    .then(|| destination_override.per_tx_max_fee_per_gas_wei.to_string()),
                per_tx_max_fee_per_gas_policy_id: bundle
                    .per_tx_max_fee
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
                per_tx_max_priority_fee_per_gas_wei: (destination_override
                    .per_tx_max_priority_fee_per_gas_wei
                    > 0)
                    .then(|| {
                        destination_override
                            .per_tx_max_priority_fee_per_gas_wei
                            .to_string()
                    }),
                per_tx_max_priority_fee_per_gas_policy_id: bundle
                    .per_tx_max_priority_fee
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
                per_tx_max_calldata_bytes: (destination_override.per_tx_max_calldata_bytes > 0)
                    .then(|| destination_override.per_tx_max_calldata_bytes.to_string()),
                per_tx_max_calldata_bytes_policy_id: bundle
                    .per_tx_max_calldata_bytes
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
            })
            .collect::<Vec<_>>();

        Ok(BootstrapOutput {
            state_file: state_file_display.to_string(),
            lease_id: lease.lease_id.to_string(),
            lease_expires_at: lease
                .expires_at
                .format(&Rfc3339)
                .context("failed to format lease expiry as RFC3339")?,
            per_tx_policy_id: Some(default_bundle.per_tx.id.to_string()),
            daily_policy_id: Some(default_bundle.daily.id.to_string()),
            weekly_policy_id: Some(default_bundle.weekly.id.to_string()),
            gas_policy_id: default_bundle.gas.as_ref().map(|policy| policy.id.to_string()),
            per_tx_max_wei: Some(params.per_tx_max_wei.to_string()),
            daily_max_wei: Some(params.daily_max_wei.to_string()),
            weekly_max_wei: Some(params.weekly_max_wei.to_string()),
            max_gas_per_chain_wei: (params.max_gas_per_chain_wei > 0)
                .then(|| params.max_gas_per_chain_wei.to_string()),
            daily_max_tx_count: (params.daily_max_tx_count > 0)
                .then(|| params.daily_max_tx_count.to_string()),
            daily_tx_count_policy_id: default_bundle
                .daily_tx_count
                .as_ref()
                .map(|policy| policy.id.to_string()),
            per_tx_max_fee_per_gas_wei: (params.per_tx_max_fee_per_gas_wei > 0)
                .then(|| params.per_tx_max_fee_per_gas_wei.to_string()),
            per_tx_max_fee_per_gas_policy_id: default_bundle
                .per_tx_max_fee
                .as_ref()
                .map(|policy| policy.id.to_string()),
            per_tx_max_priority_fee_per_gas_wei: (params.per_tx_max_priority_fee_per_gas_wei > 0)
                .then(|| params.per_tx_max_priority_fee_per_gas_wei.to_string()),
            per_tx_max_priority_fee_per_gas_policy_id: default_bundle
                .per_tx_max_priority_fee
                .as_ref()
                .map(|policy| policy.id.to_string()),
            per_tx_max_calldata_bytes: (params.per_tx_max_calldata_bytes > 0)
                .then(|| params.per_tx_max_calldata_bytes.to_string()),
            per_tx_max_calldata_bytes_policy_id: default_bundle
                .per_tx_max_calldata_bytes
                .as_ref()
                .map(|policy| policy.id.to_string()),
            vault_key_id: vault_key_id.to_string(),
            vault_key_algorithm: format_key_algorithm(vault_key_algorithm).to_string(),
            vault_public_key,
            solana_public_key,
            vault_private_key,
            agent_key_id: agent_credentials.agent_key.id.to_string(),
            agent_auth_token,
            agent_auth_token_redacted: !params.print_agent_auth_token,
            network_scope: Some(describe_network_scope(&network_scope)),
            asset_scope: Some(describe_asset_scope(&asset_scope)),
            recipient_scope: Some(describe_recipient_scope(&recipient_scope)),
            token_policies: Vec::new(),
            destination_override_count: destination_override_outputs.len(),
            destination_overrides: destination_override_outputs,
            token_destination_overrides: Vec::new(),
            token_manual_approval_policies: Vec::new(),
            policy_attachment: policy_attachment_label,
            attached_policy_ids,
            policy_note,
        })
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_per_token_bootstrap(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    state_file_display: &str,
    mut params: BootstrapParams,
    mut on_status: impl FnMut(&str),
) -> Result<BootstrapOutput> {
    validate_per_token_bootstrap_params(&params)?;
    on_status("initializing daemon");

    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease: lease.clone(),
    };

    let result = async {
        let (effective_token_policies, synthesized_unrestricted_token_policies) =
            resolve_effective_token_policies(daemon.as_ref(), &session, &params).await?;
        let mut token_policy_bundles = Vec::with_capacity(effective_token_policies.len());
        for (index, token_policy) in effective_token_policies.iter().cloned().enumerate() {
            let asset_scope = build_asset_scope_for_token_policy(&token_policy)?;
            let network_scope = build_network_scope(Some(token_policy.chain_id));
            let priority_base = policy_bundle_priority_base(
                DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE,
                index,
                "token policies",
            )?;
            let bundle = build_policy_bundle(
                priority_base,
                &PolicyLimitConfig::from_token_policy(&token_policy),
                EntityScope::All,
                asset_scope.clone(),
                network_scope.clone(),
            )?;
            token_policy_bundles.push((token_policy, asset_scope, network_scope, bundle));
        }

        let mut token_destination_override_bundles =
            Vec::with_capacity(params.token_destination_overrides.len());
        for (index, destination_override) in params
            .token_destination_overrides
            .iter()
            .cloned()
            .enumerate()
        {
            let token_policy = effective_token_policies
                .iter()
                .find(|policy| {
                    policy.token_key == destination_override.token_key
                        && policy.chain_key == destination_override.chain_key
                })
                .cloned()
                .with_context(|| {
                    format!(
                        "unknown token selector for destination override: {}:{}",
                        destination_override.token_key, destination_override.chain_key
                    )
                })?;
            let asset_scope = build_asset_scope_for_token_policy(&token_policy)?;
            let network_scope = build_network_scope(Some(token_policy.chain_id));
            let priority_base = policy_bundle_priority_base(
                DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE,
                index,
                "token destination overrides",
            )?;
            let bundle = build_policy_bundle(
                priority_base,
                &PolicyLimitConfig::from_token_destination_override(&destination_override),
                single_scope(destination_override.recipient.clone()),
                asset_scope.clone(),
                network_scope.clone(),
            )?;
            token_destination_override_bundles.push((
                destination_override,
                token_policy,
                asset_scope,
                network_scope,
                bundle,
            ));
        }

        let mut token_manual_approval_policies =
            Vec::with_capacity(params.token_manual_approval_policies.len());
        for manual_approval in params.token_manual_approval_policies.iter().cloned() {
            let asset_scope = build_asset_scope_for_token_manual_approval(&manual_approval)?;
            let network_scope = build_network_scope(Some(manual_approval.chain_id));
            let recipient_scope = manual_approval
                .recipient
                .clone()
                .map_or(EntityScope::All, single_scope);
            let policy = SpendingPolicy::new_manual_approval_with_recipient_scope(
                manual_approval.priority,
                manual_approval.min_amount_wei,
                manual_approval.max_amount_wei,
                recipient_scope.clone(),
                asset_scope.clone(),
                network_scope.clone(),
            )?;
            token_manual_approval_policies.push((
                manual_approval,
                asset_scope,
                recipient_scope,
                network_scope,
                policy,
            ));
        }

        validate_existing_policy_attachments(daemon.as_ref(), &session, &params.attach_policy_ids)
            .await?;

        on_status("registering spending policies");
        for (_, _, _, bundle) in &token_policy_bundles {
            register_policy_bundle(daemon.as_ref(), &session, bundle).await?;
        }
        for (_, _, _, _, bundle) in &token_destination_override_bundles {
            register_policy_bundle(daemon.as_ref(), &session, bundle).await?;
        }
        for (_, _, _, _, policy) in &token_manual_approval_policies {
            daemon.add_policy(&session, policy.clone()).await?;
        }

        let mut created_policy_ids = BTreeSet::new();
        for (_, _, _, bundle) in &token_policy_bundles {
            created_policy_ids.extend(bundle.policy_ids());
        }
        for (_, _, _, _, bundle) in &token_destination_override_bundles {
            created_policy_ids.extend(bundle.policy_ids());
        }
        for (_, _, _, _, policy) in &token_manual_approval_policies {
            created_policy_ids.insert(policy.id);
        }

        let attach_bootstrap_policy_ids = resolve_attach_bootstrap_policy_ids(
            daemon.as_ref(),
            &session,
            params.attach_bootstrap_policies,
        )
        .await?;
        let (policy_attachment, policy_attachment_label, attached_policy_ids, mut policy_note) =
            resolve_bootstrap_policy_attachment(
                created_policy_ids,
                attach_bootstrap_policy_ids,
                &params.attach_policy_ids,
            )?;
        if !token_policy_bundles.is_empty() {
            policy_note.push_str(&format!(
                "; {} per-token policy bundle(s) created",
                token_policy_bundles.len()
            ));
        }
        if synthesized_unrestricted_token_policies > 0 {
            policy_note.push_str(&format!(
                "; {} token selector(s) had no default limits, so scoped unrestricted base policies were created to keep them active",
                synthesized_unrestricted_token_policies
            ));
        }
        if !token_destination_override_bundles.is_empty() {
            policy_note.push_str(&format!(
                "; {} per-token destination override(s) apply as stricter overlays",
                token_destination_override_bundles.len()
            ));
        }
        if !token_manual_approval_policies.is_empty() {
            policy_note.push_str(&format!(
                "; {} token manual approval policy/policies created",
                token_manual_approval_policies.len()
            ));
        }
        if token_policy_bundles.is_empty()
            && token_destination_override_bundles.is_empty()
            && token_manual_approval_policies.is_empty()
        {
            policy_note.push_str(
                "; shared-config bootstrap created no token policies, so the agent remains unrestricted until policies are added",
            );
        }

        let (
            vault_key_id,
            vault_key_algorithm,
            vault_public_key,
            solana_public_key,
            vault_private_key,
            key_status_message,
        ) =
            resolve_bootstrap_vault_material(
                daemon.as_ref(),
                &session,
                &mut params,
                &mut policy_note,
            )
            .await?;
        on_status(key_status_message);
        let mut agent_credentials =
            if let Some(existing_agent_key_id) = params.existing_agent_key_id {
                policy_note.push_str("; refreshed the existing agent key attachment");
                daemon
                    .refresh_agent_key(
                        &session,
                        existing_agent_key_id,
                        vault_key_id,
                        policy_attachment.clone(),
                    )
                    .await?
            } else {
                daemon
                    .create_agent_key(&session, vault_key_id, policy_attachment)
                    .await?
            };
        let agent_auth_token = if params.print_agent_auth_token {
            std::mem::take(&mut *agent_credentials.auth_token)
        } else {
            agent_credentials.auth_token.zeroize();
            "<redacted>".to_string()
        };

        let token_policy_outputs = token_policy_bundles
            .iter()
            .map(|(token_policy, asset_scope, _, bundle)| TokenPolicyOutput {
                token_key: token_policy.token_key.clone(),
                symbol: token_policy.symbol.clone(),
                chain_key: token_policy.chain_key.clone(),
                chain_id: token_policy.chain_id,
                asset_scope: describe_asset_scope(asset_scope),
                recipient_scope: "all recipients".to_string(),
                per_tx_policy_id: bundle.per_tx.id.to_string(),
                daily_policy_id: bundle.daily.id.to_string(),
                weekly_policy_id: bundle.weekly.id.to_string(),
                gas_policy_id: bundle.gas.as_ref().map(|policy| policy.id.to_string()),
                per_tx_max_wei: token_policy.per_tx_max_wei.to_string(),
                daily_max_wei: token_policy.daily_max_wei.to_string(),
                weekly_max_wei: token_policy.weekly_max_wei.to_string(),
                max_gas_per_chain_wei: (token_policy.max_gas_per_chain_wei > 0)
                    .then(|| token_policy.max_gas_per_chain_wei.to_string()),
                daily_max_tx_count: (token_policy.daily_max_tx_count > 0)
                    .then(|| token_policy.daily_max_tx_count.to_string()),
                daily_tx_count_policy_id: bundle
                    .daily_tx_count
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
                per_tx_max_fee_per_gas_wei: (token_policy.per_tx_max_fee_per_gas_wei > 0)
                    .then(|| token_policy.per_tx_max_fee_per_gas_wei.to_string()),
                per_tx_max_fee_per_gas_policy_id: bundle
                    .per_tx_max_fee
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
                per_tx_max_priority_fee_per_gas_wei: (token_policy
                    .per_tx_max_priority_fee_per_gas_wei
                    > 0)
                .then(|| token_policy.per_tx_max_priority_fee_per_gas_wei.to_string()),
                per_tx_max_priority_fee_per_gas_policy_id: bundle
                    .per_tx_max_priority_fee
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
                per_tx_max_calldata_bytes: (token_policy.per_tx_max_calldata_bytes > 0)
                    .then(|| token_policy.per_tx_max_calldata_bytes.to_string()),
                per_tx_max_calldata_bytes_policy_id: bundle
                    .per_tx_max_calldata_bytes
                    .as_ref()
                    .map(|policy| policy.id.to_string()),
            })
            .collect::<Vec<_>>();

        let token_destination_override_outputs = token_destination_override_bundles
            .iter()
            .map(
                |(destination_override, token_policy, asset_scope, _, bundle)| {
                    TokenDestinationOverrideOutput {
                        token_key: destination_override.token_key.clone(),
                        symbol: token_policy.symbol.clone(),
                        chain_key: destination_override.chain_key.clone(),
                        chain_id: token_policy.chain_id,
                        recipient: destination_override.recipient.to_string(),
                        asset_scope: describe_asset_scope(asset_scope),
                        per_tx_policy_id: bundle.per_tx.id.to_string(),
                        daily_policy_id: bundle.daily.id.to_string(),
                        weekly_policy_id: bundle.weekly.id.to_string(),
                        gas_policy_id: bundle.gas.as_ref().map(|policy| policy.id.to_string()),
                        per_tx_max_wei: destination_override.per_tx_max_wei.to_string(),
                        daily_max_wei: destination_override.daily_max_wei.to_string(),
                        weekly_max_wei: destination_override.weekly_max_wei.to_string(),
                        max_gas_per_chain_wei: (destination_override.max_gas_per_chain_wei > 0)
                            .then(|| destination_override.max_gas_per_chain_wei.to_string()),
                        daily_max_tx_count: (destination_override.daily_max_tx_count > 0)
                            .then(|| destination_override.daily_max_tx_count.to_string()),
                        daily_tx_count_policy_id: bundle
                            .daily_tx_count
                            .as_ref()
                            .map(|policy| policy.id.to_string()),
                        per_tx_max_fee_per_gas_wei: (destination_override
                            .per_tx_max_fee_per_gas_wei
                            > 0)
                        .then(|| destination_override.per_tx_max_fee_per_gas_wei.to_string()),
                        per_tx_max_fee_per_gas_policy_id: bundle
                            .per_tx_max_fee
                            .as_ref()
                            .map(|policy| policy.id.to_string()),
                        per_tx_max_priority_fee_per_gas_wei: (destination_override
                            .per_tx_max_priority_fee_per_gas_wei
                            > 0)
                        .then(|| {
                            destination_override
                                .per_tx_max_priority_fee_per_gas_wei
                                .to_string()
                        }),
                        per_tx_max_priority_fee_per_gas_policy_id: bundle
                            .per_tx_max_priority_fee
                            .as_ref()
                            .map(|policy| policy.id.to_string()),
                        per_tx_max_calldata_bytes: (destination_override.per_tx_max_calldata_bytes
                            > 0)
                        .then(|| destination_override.per_tx_max_calldata_bytes.to_string()),
                        per_tx_max_calldata_bytes_policy_id: bundle
                            .per_tx_max_calldata_bytes
                            .as_ref()
                            .map(|policy| policy.id.to_string()),
                    }
                },
            )
            .collect::<Vec<_>>();

        let token_manual_approval_outputs = token_manual_approval_policies
            .iter()
            .map(
                |(manual_approval, asset_scope, recipient_scope, _, policy)| {
                    TokenManualApprovalPolicyOutput {
                        token_key: manual_approval.token_key.clone(),
                        symbol: manual_approval.symbol.clone(),
                        chain_key: manual_approval.chain_key.clone(),
                        chain_id: manual_approval.chain_id,
                        priority: manual_approval.priority,
                        min_amount_wei: manual_approval.min_amount_wei.to_string(),
                        max_amount_wei: manual_approval.max_amount_wei.to_string(),
                        asset_scope: describe_asset_scope(asset_scope),
                        recipient_scope: describe_recipient_scope(recipient_scope),
                        policy_id: policy.id.to_string(),
                    }
                },
            )
            .collect::<Vec<_>>();

        Ok(BootstrapOutput {
            state_file: state_file_display.to_string(),
            lease_id: lease.lease_id.to_string(),
            lease_expires_at: lease
                .expires_at
                .format(&Rfc3339)
                .context("failed to format lease expiry as RFC3339")?,
            per_tx_policy_id: None,
            daily_policy_id: None,
            weekly_policy_id: None,
            gas_policy_id: None,
            per_tx_max_wei: None,
            daily_max_wei: None,
            weekly_max_wei: None,
            max_gas_per_chain_wei: None,
            daily_max_tx_count: None,
            daily_tx_count_policy_id: None,
            per_tx_max_fee_per_gas_wei: None,
            per_tx_max_fee_per_gas_policy_id: None,
            per_tx_max_priority_fee_per_gas_wei: None,
            per_tx_max_priority_fee_per_gas_policy_id: None,
            per_tx_max_calldata_bytes: None,
            per_tx_max_calldata_bytes_policy_id: None,
            vault_key_id: vault_key_id.to_string(),
            vault_key_algorithm: format_key_algorithm(vault_key_algorithm).to_string(),
            vault_public_key,
            solana_public_key,
            vault_private_key,
            agent_key_id: agent_credentials.agent_key.id.to_string(),
            agent_auth_token,
            agent_auth_token_redacted: !params.print_agent_auth_token,
            network_scope: None,
            asset_scope: None,
            recipient_scope: None,
            token_policies: token_policy_outputs,
            destination_override_count: token_destination_override_outputs.len(),
            destination_overrides: Vec::new(),
            token_destination_overrides: token_destination_override_outputs,
            token_manual_approval_policies: token_manual_approval_outputs,
            policy_attachment: policy_attachment_label,
            attached_policy_ids,
            policy_note,
        })
    }
    .await;

    session.vault_password.zeroize();
    result
}

fn build_shared_config_bootstrap_params(
    config: &shared_config::WlfiConfig,
    print_agent_auth_token: bool,
    network: Option<u64>,
    attach_policy_ids: Vec<Uuid>,
    attach_bootstrap_policies: bool,
    existing_vault_key_id: Option<Uuid>,
    existing_vault_public_key: Option<String>,
    import_vault_private_key: Option<String>,
) -> Result<BootstrapParams> {
    let reuse_existing_wallet =
        existing_vault_key_id.is_some() || existing_vault_public_key.is_some();
    let mut params = tui::build_bootstrap_params_from_shared_config(
        config,
        print_agent_auth_token,
        reuse_existing_wallet,
    )?;
    if network.is_some() {
        params.network = network;
    }
    params.attach_policy_ids = attach_policy_ids;
    params.attach_bootstrap_policies = attach_bootstrap_policies;
    params.existing_vault_key_id = existing_vault_key_id;
    params.existing_vault_public_key = existing_vault_public_key;
    params.import_vault_private_key = import_vault_private_key;
    Ok(params)
}

async fn resolve_bootstrap_vault_material(
    daemon: &dyn KeyManagerDaemonApi,
    session: &AdminSession,
    params: &mut BootstrapParams,
    policy_note: &mut String,
) -> Result<(
    Uuid,
    KeyAlgorithm,
    String,
    String,
    Option<String>,
    &'static str,
)> {
    let wallet_key_algorithm = KeyAlgorithm::Secp256k1;
    if let Some(mut private_key_hex) = params.import_vault_private_key.take() {
        if params.existing_vault_key_id.is_some() || params.existing_vault_public_key.is_some() {
            private_key_hex.zeroize();
            bail!("imported private key conflicts with existing wallet reuse metadata");
        }

        let vault_key = daemon
            .create_vault_key(
                session,
                KeyCreateRequest::Import {
                    private_key_hex: private_key_hex.clone(),
                },
            )
            .await?;
        private_key_hex.zeroize();
        let solana_public_key = daemon.solana_public_key_hex(session, vault_key.id).await?;
        policy_note.push_str("; restored the wallet from an imported private key");
        return Ok((
            vault_key.id,
            vault_key.algorithm,
            vault_key.public_key_hex,
            solana_public_key,
            None,
            "importing vault and creating agent keys",
        ));
    }

    match (
        params.existing_vault_key_id,
        params.existing_vault_public_key.as_ref(),
    ) {
        (Some(vault_key_id), Some(vault_public_key)) => {
            let solana_public_key = daemon.solana_public_key_hex(session, vault_key_id).await?;
            policy_note.push_str("; reused the existing wallet address");
            Ok((
                vault_key_id,
                wallet_key_algorithm,
                vault_public_key.clone(),
                solana_public_key,
                None,
                "creating agent key",
            ))
        }
        (Some(_), None) => {
            bail!("existing wallet metadata is incomplete: wallet.vaultPublicKey is required");
        }
        (None, Some(_)) => {
            bail!("existing wallet metadata is incomplete: wallet.vaultKeyId is required");
        }
        (None, None) => {
            let vault_key = daemon
                .create_vault_key(session, KeyCreateRequest::Generate)
                .await?;
            let solana_public_key = daemon.solana_public_key_hex(session, vault_key.id).await?;
            let vault_private_key = if params.print_vault_private_key {
                daemon
                    .export_vault_private_key(session, vault_key.id)
                    .await?
            } else {
                None
            };
            Ok((
                vault_key.id,
                vault_key.algorithm,
                vault_key.public_key_hex,
                solana_public_key,
                vault_private_key,
                "creating vault and agent keys",
            ))
        }
    }
}

async fn execute_export_vault_private_key(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: ExportVaultPrivateKeyParams,
    mut on_status: impl FnMut(&str),
) -> Result<ExportVaultPrivateKeyOutput> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("exporting vault private key");
        let exported = daemon
            .export_vault_private_key(&session, params.vault_key_id)
            .await?;
        let vault_private_key = exported.ok_or_else(|| {
            anyhow::anyhow!(
                "vault key '{}' is not exportable with the configured signer backend",
                params.vault_key_id
            )
        })?;
        Ok(ExportVaultPrivateKeyOutput {
            vault_key_id: params.vault_key_id.to_string(),
            vault_private_key,
        })
    }
    .await;

    session.vault_password.zeroize();
    result
}

#[derive(Debug, Clone, Copy)]
struct PolicyLimitConfig {
    per_tx_max_wei: u128,
    daily_max_wei: u128,
    weekly_max_wei: u128,
    max_gas_per_chain_wei: u128,
    daily_max_tx_count: u128,
    per_tx_max_fee_per_gas_wei: u128,
    per_tx_max_priority_fee_per_gas_wei: u128,
    per_tx_max_calldata_bytes: u128,
}

impl PolicyLimitConfig {
    fn from_params(params: &BootstrapParams) -> Self {
        Self {
            per_tx_max_wei: params.per_tx_max_wei,
            daily_max_wei: params.daily_max_wei,
            weekly_max_wei: params.weekly_max_wei,
            max_gas_per_chain_wei: params.max_gas_per_chain_wei,
            daily_max_tx_count: params.daily_max_tx_count,
            per_tx_max_fee_per_gas_wei: params.per_tx_max_fee_per_gas_wei,
            per_tx_max_priority_fee_per_gas_wei: params.per_tx_max_priority_fee_per_gas_wei,
            per_tx_max_calldata_bytes: params.per_tx_max_calldata_bytes,
        }
    }

    fn from_token_policy(token_policy: &TokenPolicyConfig) -> Self {
        Self {
            per_tx_max_wei: token_policy.per_tx_max_wei,
            daily_max_wei: token_policy.daily_max_wei,
            weekly_max_wei: token_policy.weekly_max_wei,
            max_gas_per_chain_wei: token_policy.max_gas_per_chain_wei,
            daily_max_tx_count: token_policy.daily_max_tx_count,
            per_tx_max_fee_per_gas_wei: token_policy.per_tx_max_fee_per_gas_wei,
            per_tx_max_priority_fee_per_gas_wei: token_policy.per_tx_max_priority_fee_per_gas_wei,
            per_tx_max_calldata_bytes: token_policy.per_tx_max_calldata_bytes,
        }
    }

    fn from_destination_override(destination_override: &DestinationPolicyOverride) -> Self {
        Self {
            per_tx_max_wei: destination_override.per_tx_max_wei,
            daily_max_wei: destination_override.daily_max_wei,
            weekly_max_wei: destination_override.weekly_max_wei,
            max_gas_per_chain_wei: destination_override.max_gas_per_chain_wei,
            daily_max_tx_count: destination_override.daily_max_tx_count,
            per_tx_max_fee_per_gas_wei: destination_override.per_tx_max_fee_per_gas_wei,
            per_tx_max_priority_fee_per_gas_wei: destination_override
                .per_tx_max_priority_fee_per_gas_wei,
            per_tx_max_calldata_bytes: destination_override.per_tx_max_calldata_bytes,
        }
    }

    fn from_token_destination_override(
        destination_override: &TokenDestinationPolicyOverride,
    ) -> Self {
        Self {
            per_tx_max_wei: destination_override.per_tx_max_wei,
            daily_max_wei: destination_override.daily_max_wei,
            weekly_max_wei: destination_override.weekly_max_wei,
            max_gas_per_chain_wei: destination_override.max_gas_per_chain_wei,
            daily_max_tx_count: destination_override.daily_max_tx_count,
            per_tx_max_fee_per_gas_wei: destination_override.per_tx_max_fee_per_gas_wei,
            per_tx_max_priority_fee_per_gas_wei: destination_override
                .per_tx_max_priority_fee_per_gas_wei,
            per_tx_max_calldata_bytes: destination_override.per_tx_max_calldata_bytes,
        }
    }
}

#[derive(Debug)]
struct PolicyBundle {
    per_tx: SpendingPolicy,
    daily: SpendingPolicy,
    weekly: SpendingPolicy,
    gas: Option<SpendingPolicy>,
    daily_tx_count: Option<SpendingPolicy>,
    per_tx_max_fee: Option<SpendingPolicy>,
    per_tx_max_priority_fee: Option<SpendingPolicy>,
    per_tx_max_calldata_bytes: Option<SpendingPolicy>,
}

impl PolicyBundle {
    fn policies(&self) -> Vec<&SpendingPolicy> {
        let mut policies = vec![&self.per_tx, &self.daily, &self.weekly];
        if let Some(policy) = &self.gas {
            policies.push(policy);
        }
        if let Some(policy) = &self.daily_tx_count {
            policies.push(policy);
        }
        if let Some(policy) = &self.per_tx_max_fee {
            policies.push(policy);
        }
        if let Some(policy) = &self.per_tx_max_priority_fee {
            policies.push(policy);
        }
        if let Some(policy) = &self.per_tx_max_calldata_bytes {
            policies.push(policy);
        }
        policies
    }

    fn policy_ids(&self) -> BTreeSet<Uuid> {
        self.policies()
            .into_iter()
            .map(|policy| policy.id)
            .collect()
    }
}

const DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE: u32 = 1_000;
const BOOTSTRAP_POLICY_PRIORITY_STRIDE: u32 = 100;
const DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE: u32 = 10_000;
const POLICY_BUNDLE_PRIORITY_SLOTS: u32 = 8;

fn policy_bundle_priority_base(priority_base: u32, index: usize, label: &str) -> Result<u32> {
    let index = u32::try_from(index)
        .with_context(|| format!("too many {label}; policy priority index exceeds u32"))?;
    let priority_offset = index
        .checked_mul(BOOTSTRAP_POLICY_PRIORITY_STRIDE)
        .with_context(|| format!("too many {label}; policy priority overflow"))?;
    let priority_base = priority_base
        .checked_add(priority_offset)
        .with_context(|| format!("too many {label}; policy priority overflow"))?;
    policy_bundle_priority(priority_base, POLICY_BUNDLE_PRIORITY_SLOTS - 1)
        .with_context(|| format!("too many {label}; policy priority overflow"))?;
    Ok(priority_base)
}

fn policy_bundle_priority(priority_base: u32, offset: u32) -> Result<u32> {
    priority_base
        .checked_add(offset)
        .context("invalid policy configuration: priority overflow")
}

fn lift_evm_recipient_scope(scope: EntityScope<EvmAddress>) -> EntityScope<RecipientId> {
    match scope {
        EntityScope::All => EntityScope::All,
        EntityScope::Set(values) => {
            EntityScope::Set(values.into_iter().map(RecipientId::Evm).collect())
        }
    }
}

fn build_policy_bundle(
    priority_base: u32,
    limits: &PolicyLimitConfig,
    recipient_scope: EntityScope<RecipientId>,
    asset_scope: EntityScope<AssetId>,
    network_scope: EntityScope<u64>,
) -> Result<PolicyBundle> {
    let per_tx_priority = policy_bundle_priority(priority_base, 0)?;
    let daily_priority = policy_bundle_priority(priority_base, 1)?;
    let weekly_priority = policy_bundle_priority(priority_base, 2)?;
    let gas_priority = policy_bundle_priority(priority_base, 3)?;
    let daily_tx_count_priority = policy_bundle_priority(priority_base, 4)?;
    let per_tx_max_fee_priority = policy_bundle_priority(priority_base, 5)?;
    let per_tx_max_priority_fee_priority = policy_bundle_priority(priority_base, 6)?;
    let per_tx_max_calldata_priority = policy_bundle_priority(priority_base, 7)?;

    Ok(PolicyBundle {
        per_tx: SpendingPolicy::new_with_recipient_scope(
            per_tx_priority,
            PolicyType::PerTxMaxSpending,
            limits.per_tx_max_wei,
            recipient_scope.clone(),
            asset_scope.clone(),
            network_scope.clone(),
        )
        .context("invalid policy configuration")?,
        daily: SpendingPolicy::new_with_recipient_scope(
            daily_priority,
            PolicyType::DailyMaxSpending,
            limits.daily_max_wei,
            recipient_scope.clone(),
            asset_scope.clone(),
            network_scope.clone(),
        )
        .context("invalid policy configuration")?,
        weekly: SpendingPolicy::new_with_recipient_scope(
            weekly_priority,
            PolicyType::WeeklyMaxSpending,
            limits.weekly_max_wei,
            recipient_scope.clone(),
            asset_scope.clone(),
            network_scope.clone(),
        )
        .context("invalid policy configuration")?,
        gas: (limits.max_gas_per_chain_wei > 0)
            .then(|| {
                SpendingPolicy::new_gas_spend_limit_with_recipient_scope(
                    gas_priority,
                    limits.max_gas_per_chain_wei,
                    recipient_scope.clone(),
                    EntityScope::All,
                    network_scope.clone(),
                )
            })
            .transpose()
            .context("invalid policy configuration")?,
        daily_tx_count: (limits.daily_max_tx_count > 0)
            .then(|| {
                SpendingPolicy::new_tx_count_limit_with_recipient_scope(
                    daily_tx_count_priority,
                    limits.daily_max_tx_count,
                    recipient_scope.clone(),
                    asset_scope.clone(),
                    network_scope.clone(),
                )
            })
            .transpose()
            .context("invalid policy configuration")?,
        per_tx_max_fee: (limits.per_tx_max_fee_per_gas_wei > 0)
            .then(|| {
                SpendingPolicy::new_fee_per_gas_limit_with_recipient_scope(
                    per_tx_max_fee_priority,
                    limits.per_tx_max_fee_per_gas_wei,
                    recipient_scope.clone(),
                    asset_scope.clone(),
                    network_scope.clone(),
                )
            })
            .transpose()
            .context("invalid policy configuration")?,
        per_tx_max_priority_fee: (limits.per_tx_max_priority_fee_per_gas_wei > 0)
            .then(|| {
                SpendingPolicy::new_priority_fee_per_gas_limit_with_recipient_scope(
                    per_tx_max_priority_fee_priority,
                    limits.per_tx_max_priority_fee_per_gas_wei,
                    recipient_scope.clone(),
                    asset_scope.clone(),
                    network_scope.clone(),
                )
            })
            .transpose()
            .context("invalid policy configuration")?,
        per_tx_max_calldata_bytes: (limits.per_tx_max_calldata_bytes > 0)
            .then(|| {
                SpendingPolicy::new_calldata_limit_with_recipient_scope(
                    per_tx_max_calldata_priority,
                    limits.per_tx_max_calldata_bytes,
                    recipient_scope,
                    asset_scope,
                    network_scope,
                )
            })
            .transpose()
            .context("invalid policy configuration")?,
    })
}

async fn register_policy_bundle(
    daemon: &dyn KeyManagerDaemonApi,
    session: &AdminSession,
    bundle: &PolicyBundle,
) -> Result<()> {
    for policy in bundle.policies() {
        daemon.add_policy(session, policy.clone()).await?;
    }
    Ok(())
}

fn validate_destination_policy_overrides(params: &BootstrapParams) -> Result<()> {
    if params.recipient.is_some() && !params.destination_overrides.is_empty() {
        bail!(
            "destination overrides require the default recipient scope to cover every destination"
        );
    }

    let defaults = PolicyLimitConfig::from_params(params);
    let mut seen_recipients = BTreeSet::new();
    for destination_override in &params.destination_overrides {
        validate_policy_limits(
            destination_override.per_tx_max_wei,
            destination_override.daily_max_wei,
            destination_override.weekly_max_wei,
        )?;
        if !seen_recipients.insert(destination_override.recipient.clone()) {
            bail!(
                "duplicate destination override recipient: {}",
                destination_override.recipient
            );
        }
        let recipient = destination_override.recipient.to_string();
        validate_required_overlay_limit(
            &recipient,
            "per-tx max",
            defaults.per_tx_max_wei,
            destination_override.per_tx_max_wei,
        )?;
        validate_required_overlay_limit(
            &recipient,
            "daily max",
            defaults.daily_max_wei,
            destination_override.daily_max_wei,
        )?;
        validate_required_overlay_limit(
            &recipient,
            "weekly max",
            defaults.weekly_max_wei,
            destination_override.weekly_max_wei,
        )?;
        validate_optional_overlay_limit(
            &recipient,
            "max gas per chain",
            defaults.max_gas_per_chain_wei,
            destination_override.max_gas_per_chain_wei,
        )?;
        validate_optional_overlay_limit(
            &recipient,
            "daily max tx count",
            defaults.daily_max_tx_count,
            destination_override.daily_max_tx_count,
        )?;
        validate_optional_overlay_limit(
            &recipient,
            "per-tx max fee per gas",
            defaults.per_tx_max_fee_per_gas_wei,
            destination_override.per_tx_max_fee_per_gas_wei,
        )?;
        validate_optional_overlay_limit(
            &recipient,
            "per-tx max priority fee per gas",
            defaults.per_tx_max_priority_fee_per_gas_wei,
            destination_override.per_tx_max_priority_fee_per_gas_wei,
        )?;
        validate_optional_overlay_limit(
            &recipient,
            "per-tx max calldata bytes",
            defaults.per_tx_max_calldata_bytes,
            destination_override.per_tx_max_calldata_bytes,
        )?;
    }
    Ok(())
}

fn validate_per_token_bootstrap_params(params: &BootstrapParams) -> Result<()> {
    if !params.destination_overrides.is_empty() {
        bail!("legacy destination overrides cannot be mixed with per-token policies");
    }
    if params.recipient.is_some() {
        bail!("global recipient scope is not supported with per-token policies");
    }
    if params.token_policies.is_empty() && !params.token_destination_overrides.is_empty() {
        bail!("per-token destination overrides require at least one per-token policy");
    }

    let mut seen_selectors = BTreeSet::new();
    for token_selector in &params.token_selectors {
        validate_token_selector(
            &token_selector.token_key,
            &token_selector.chain_key,
            token_selector.chain_id,
            token_selector.is_native,
            token_selector.address.as_ref(),
        )?;
        if !seen_selectors.insert((
            token_selector.token_key.clone(),
            token_selector.chain_key.clone(),
        )) {
            bail!(
                "duplicate token selector: {}:{}",
                token_selector.token_key,
                token_selector.chain_key
            );
        }
    }

    for token_policy in &params.token_policies {
        validate_token_selector(
            &token_policy.token_key,
            &token_policy.chain_key,
            token_policy.chain_id,
            token_policy.is_native,
            token_policy.address.as_ref(),
        )?;

        validate_policy_limits(
            token_policy.per_tx_max_wei,
            token_policy.daily_max_wei,
            token_policy.weekly_max_wei,
        )?;
    }

    let mut seen_overrides = BTreeSet::new();
    for destination_override in &params.token_destination_overrides {
        let Some(token_policy) = params.token_policies.iter().find(|policy| {
            policy.token_key == destination_override.token_key
                && policy.chain_key == destination_override.chain_key
        }) else {
            bail!(
                "destination override references unknown token selector '{}:{}'",
                destination_override.token_key,
                destination_override.chain_key
            );
        };

        let recipient = destination_override.recipient.to_string();
        if !seen_overrides.insert((
            destination_override.token_key.clone(),
            destination_override.chain_key.clone(),
            recipient.clone(),
        )) {
            bail!(
                "duplicate per-token destination override: {}:{} for {}",
                destination_override.token_key,
                destination_override.chain_key,
                recipient
            );
        }

        validate_policy_limits(
            destination_override.per_tx_max_wei,
            destination_override.daily_max_wei,
            destination_override.weekly_max_wei,
        )?;
        validate_token_destination_override_overlay(
            &recipient,
            &PolicyLimitConfig::from_token_policy(token_policy),
            &PolicyLimitConfig::from_token_destination_override(destination_override),
        )?;
    }

    for manual_approval in &params.token_manual_approval_policies {
        let Some(token_selector) = params.token_selectors.iter().find(|selector| {
            selector.token_key == manual_approval.token_key
                && selector.chain_key == manual_approval.chain_key
        }) else {
            bail!(
                "manual approval policy references unknown token selector '{}:{}'",
                manual_approval.token_key,
                manual_approval.chain_key
            );
        };
        if token_selector.chain_id != manual_approval.chain_id {
            bail!(
                "manual approval policy '{}:{}' must match chain id {}",
                manual_approval.token_key,
                manual_approval.chain_key,
                token_selector.chain_id
            );
        }
        if manual_approval.min_amount_wei == 0 || manual_approval.max_amount_wei == 0 {
            bail!(
                "manual approval policy '{}:{}' requires non-zero min/max amounts",
                manual_approval.token_key,
                manual_approval.chain_key
            );
        }
        if manual_approval.min_amount_wei > manual_approval.max_amount_wei {
            bail!(
                "manual approval policy '{}:{}' min amount must be less than or equal to max amount",
                manual_approval.token_key,
                manual_approval.chain_key
            );
        }
        if manual_approval.is_native != token_selector.is_native
            || manual_approval.address != token_selector.address
        {
            bail!(
                "manual approval policy '{}:{}' must match the saved token asset scope",
                manual_approval.token_key,
                manual_approval.chain_key
            );
        }
    }

    Ok(())
}

fn validate_token_selector(
    token_key: &str,
    chain_key: &str,
    chain_id: u64,
    is_native: bool,
    address: Option<&TokenAddress>,
) -> Result<()> {
    if token_key.trim().is_empty() || chain_key.trim().is_empty() {
        bail!("token policy selectors must include token and chain keys");
    }
    if chain_id == 0 {
        bail!(
            "token policy '{}' chain '{}' must have a non-zero chain id",
            token_key,
            chain_key
        );
    }
    if is_native {
        if address.is_some() {
            bail!(
                "token policy '{}:{}' must not set an address when native",
                token_key,
                chain_key
            );
        }
    } else if address.is_none() {
        bail!(
            "token policy '{}:{}' requires a token address",
            token_key,
            chain_key
        );
    }
    Ok(())
}

fn build_asset_scope_for_token_policy(
    token_policy: &TokenPolicyConfig,
) -> Result<EntityScope<AssetId>> {
    build_asset_scope_for_token_selector(
        &token_policy.token_key,
        &token_policy.chain_key,
        token_policy.chain_id,
        token_policy.is_native,
        token_policy.address.as_ref(),
    )
}

fn build_asset_scope_for_token_manual_approval(
    manual_approval: &TokenManualApprovalPolicyConfig,
) -> Result<EntityScope<AssetId>> {
    build_asset_scope_for_token_selector(
        &manual_approval.token_key,
        &manual_approval.chain_key,
        manual_approval.chain_id,
        manual_approval.is_native,
        manual_approval.address.as_ref(),
    )
}

fn build_asset_scope_for_token_selector(
    token_key: &str,
    chain_key: &str,
    chain_id: u64,
    is_native: bool,
    address: Option<&TokenAddress>,
) -> Result<EntityScope<AssetId>> {
    if is_native {
        if address.is_some() {
            bail!(
                "token policy '{}:{}' must not include an address for native asset scope",
                token_key,
                chain_key
            );
        }
        Ok(single_scope(if is_solana_chain_id(chain_id) {
            AssetId::NativeSol
        } else {
            AssetId::NativeEth
        }))
    } else {
        let address = address.with_context(|| {
            format!(
                "token policy '{}:{}' requires a token address",
                token_key, chain_key
            )
        })?;
        Ok(single_scope(match address {
            TokenAddress::Evm(a) => AssetId::Erc20(a.clone()),
            TokenAddress::Solana(a) => AssetId::SplToken(a.clone()),
        }))
    }
}

fn validate_token_destination_override_overlay(
    recipient: &str,
    defaults: &PolicyLimitConfig,
    override_limits: &PolicyLimitConfig,
) -> Result<()> {
    validate_required_overlay_limit(
        recipient,
        "per-tx max",
        defaults.per_tx_max_wei,
        override_limits.per_tx_max_wei,
    )?;
    validate_required_overlay_limit(
        recipient,
        "daily max",
        defaults.daily_max_wei,
        override_limits.daily_max_wei,
    )?;
    validate_required_overlay_limit(
        recipient,
        "weekly max",
        defaults.weekly_max_wei,
        override_limits.weekly_max_wei,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "max gas per chain",
        defaults.max_gas_per_chain_wei,
        override_limits.max_gas_per_chain_wei,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "daily max tx count",
        defaults.daily_max_tx_count,
        override_limits.daily_max_tx_count,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "per-tx max fee per gas",
        defaults.per_tx_max_fee_per_gas_wei,
        override_limits.per_tx_max_fee_per_gas_wei,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "per-tx max priority fee per gas",
        defaults.per_tx_max_priority_fee_per_gas_wei,
        override_limits.per_tx_max_priority_fee_per_gas_wei,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "per-tx max calldata bytes",
        defaults.per_tx_max_calldata_bytes,
        override_limits.per_tx_max_calldata_bytes,
    )?;
    Ok(())
}

fn validate_required_overlay_limit(
    recipient: &str,
    label: &str,
    default_value: u128,
    override_value: u128,
) -> Result<()> {
    if override_value > default_value {
        bail!(
            "destination override for {recipient} must not increase {label} above the default value"
        );
    }
    Ok(())
}

fn validate_optional_overlay_limit(
    recipient: &str,
    label: &str,
    default_value: u128,
    override_value: u128,
) -> Result<()> {
    if default_value == 0 {
        return Ok(());
    }
    if override_value == 0 {
        bail!(
            "destination override for {recipient} must keep {label} enabled because the default value is enabled"
        );
    }
    if override_value > default_value {
        bail!(
            "destination override for {recipient} must not increase {label} above the default value"
        );
    }
    Ok(())
}

async fn execute_rotate_agent_auth_token(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: RotateAgentAuthTokenParams,
    mut on_status: impl FnMut(&str),
) -> Result<RotateAgentAuthTokenOutput> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("rotating agent auth token");
        let mut agent_auth_token = daemon
            .rotate_agent_auth_token(&session, params.agent_key_id)
            .await?;

        if params.print_agent_auth_token {
            Ok(RotateAgentAuthTokenOutput {
                agent_key_id: params.agent_key_id.to_string(),
                agent_auth_token,
                agent_auth_token_redacted: false,
            })
        } else {
            agent_auth_token.zeroize();
            Ok(RotateAgentAuthTokenOutput {
                agent_key_id: params.agent_key_id.to_string(),
                agent_auth_token: "<redacted>".to_string(),
                agent_auth_token_redacted: true,
            })
        }
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_revoke_agent_key(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: RevokeAgentKeyParams,
    mut on_status: impl FnMut(&str),
) -> Result<RevokeAgentKeyOutput> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("revoking agent key");
        daemon
            .revoke_agent_key(&session, params.agent_key_id)
            .await?;
        Ok(RevokeAgentKeyOutput {
            agent_key_id: params.agent_key_id.to_string(),
            revoked: true,
        })
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_add_manual_approval_policy(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: AddManualApprovalPolicyParams,
    mut on_status: impl FnMut(&str),
) -> Result<ManualApprovalPolicyOutput> {
    if params.min_amount_wei > params.max_amount_wei {
        bail!("--min-amount-wei must be less than or equal to --max-amount-wei");
    }

    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let recipients = params
        .recipient
        .clone()
        .map_or(EntityScope::All, single_scope);
    let assets = build_asset_scope(&params.tokens, params.allow_native_eth);
    let networks = build_network_scope(params.network);
    let policy = SpendingPolicy::new_manual_approval(
        params.priority,
        params.min_amount_wei,
        params.max_amount_wei,
        recipients.clone(),
        assets.clone(),
        networks.clone(),
    )?;
    let policy_id = policy.id;

    let result = async {
        on_status("creating manual approval policy");
        daemon.add_policy(&session, policy).await?;
        Ok(ManualApprovalPolicyOutput {
            policy_id: policy_id.to_string(),
            priority: params.priority,
            min_amount_wei: params.min_amount_wei.to_string(),
            max_amount_wei: params.max_amount_wei.to_string(),
            network_scope: describe_network_scope(&networks),
            asset_scope: describe_asset_scope(&assets),
            recipient_scope: describe_recipient_scope(&recipients),
        })
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_add_eip712_signing_policy(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: AddEip712SigningPolicyParams,
    mut on_status: impl FnMut(&str),
) -> Result<Eip712SigningPolicyOutput> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let networks = build_network_scope(params.network);
    let policy = SpendingPolicy::new_eip712_signing(
        params.priority,
        params.approval_type,
        networks.clone(),
    )?;
    let policy_id = policy.id;

    let result = async {
        on_status("creating eip712 signing policy");
        daemon.add_policy(&session, policy).await?;
        Ok(Eip712SigningPolicyOutput {
            policy_id: policy_id.to_string(),
            priority: params.priority,
            approval_type: describe_approval_type(params.approval_type).to_string(),
            network_scope: describe_network_scope(&networks),
        })
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_list_manual_approval_requests(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    mut on_status: impl FnMut(&str),
) -> Result<Vec<ManualApprovalRequest>> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("listing manual approval requests");
        Ok(daemon.list_manual_approval_requests(&session).await?)
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_list_policies(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    policy_ids: &[Uuid],
    mut on_status: impl FnMut(&str),
) -> Result<Vec<SpendingPolicy>> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("listing policies");
        let policies = daemon.list_policies(&session).await?;
        if policy_ids.is_empty() {
            return Ok(policies);
        }

        let requested = policy_ids.iter().copied().collect::<BTreeSet<_>>();
        let filtered = policies
            .into_iter()
            .filter(|policy| requested.contains(&policy.id))
            .collect::<Vec<_>>();
        let found = filtered
            .iter()
            .map(|policy| policy.id)
            .collect::<BTreeSet<_>>();
        let missing = requested
            .difference(&found)
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            bail!("unknown --policy-id value(s): {}", missing.join(", "));
        }
        Ok(filtered)
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_decide_manual_approval_request(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: DecideManualApprovalRequestParams,
    mut on_status: impl FnMut(&str),
) -> Result<ManualApprovalRequest> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("updating manual approval request");
        Ok(daemon
            .decide_manual_approval_request(
                &session,
                params.approval_request_id,
                params.decision,
                params.rejection_reason,
            )
            .await?)
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn execute_set_relay_config(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    params: SetRelayConfigParams,
    mut on_status: impl FnMut(&str),
) -> Result<RelayConfig> {
    let requested_update =
        params.clear || params.relay_url.is_some() || params.frontend_url.is_some();
    on_status(if requested_update {
        "ignoring legacy relay configuration update"
    } else {
        "legacy relay configuration is ignored in this release"
    });
    execute_get_relay_config(daemon, vault_password, |_| {}).await
}

async fn execute_get_relay_config(
    daemon: Arc<dyn KeyManagerDaemonApi>,
    vault_password: &str,
    mut on_status: impl FnMut(&str),
) -> Result<RelayConfig> {
    on_status("issuing admin lease");
    let lease = daemon.issue_lease(vault_password).await?;
    let mut session = AdminSession {
        vault_password: vault_password.to_string(),
        lease,
    };

    let result = async {
        on_status("reading relay configuration");
        Ok(daemon.get_relay_config(&session).await?)
    }
    .await;

    session.vault_password.zeroize();
    result
}

async fn validate_existing_policy_attachments(
    daemon: &dyn KeyManagerDaemonApi,
    session: &AdminSession,
    attach_policy_ids: &[Uuid],
) -> Result<()> {
    if attach_policy_ids.is_empty() {
        return Ok(());
    }

    let existing_policy_ids = daemon
        .list_policy_summaries(session)
        .await?
        .into_iter()
        .map(|summary| summary.id)
        .collect::<BTreeSet<_>>();
    let missing = attach_policy_ids
        .iter()
        .copied()
        .filter(|policy_id| !existing_policy_ids.contains(policy_id))
        .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(());
    }

    let joined = missing
        .into_iter()
        .map(|policy_id| policy_id.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    bail!("unknown --attach-policy-id value(s): {joined}");
}

async fn resolve_attach_bootstrap_policy_ids(
    daemon: &dyn KeyManagerDaemonApi,
    session: &AdminSession,
    attach_bootstrap_policies: bool,
) -> Result<BTreeSet<Uuid>> {
    if !attach_bootstrap_policies {
        return Ok(BTreeSet::new());
    }

    Ok(daemon
        .list_policy_summaries(session)
        .await?
        .into_iter()
        .filter(|summary| summary.enabled)
        .map(|summary| summary.id)
        .collect())
}

async fn resolve_effective_token_policies(
    daemon: &dyn KeyManagerDaemonApi,
    session: &AdminSession,
    params: &BootstrapParams,
) -> Result<(Vec<TokenPolicyConfig>, usize)> {
    let has_enabled_daemon_policies = daemon
        .list_policy_summaries(session)
        .await?
        .into_iter()
        .any(|summary| summary.enabled);
    let requires_scoped_unrestricted_selectors = has_enabled_daemon_policies
        || !params.attach_policy_ids.is_empty()
        || !params.token_policies.is_empty()
        || !params.token_destination_overrides.is_empty()
        || !params.token_manual_approval_policies.is_empty();
    if !requires_scoped_unrestricted_selectors {
        return Ok((params.token_policies.clone(), 0));
    }

    let mut effective_policies = params.token_policies.clone();
    let configured_selectors = effective_policies
        .iter()
        .map(|policy| (policy.token_key.clone(), policy.chain_key.clone()))
        .collect::<BTreeSet<_>>();
    let mut synthesized_count = 0usize;
    for selector in &params.token_selectors {
        if configured_selectors.contains(&(selector.token_key.clone(), selector.chain_key.clone()))
        {
            continue;
        }

        synthesized_count += 1;
        effective_policies.push(TokenPolicyConfig {
            token_key: selector.token_key.clone(),
            symbol: selector.symbol.clone(),
            chain_key: selector.chain_key.clone(),
            chain_id: selector.chain_id,
            is_native: selector.is_native,
            address: selector.address.clone(),
            per_tx_max_wei: u128::MAX,
            daily_max_wei: u128::MAX,
            weekly_max_wei: u128::MAX,
            max_gas_per_chain_wei: 0,
            daily_max_tx_count: 0,
            per_tx_max_fee_per_gas_wei: 0,
            per_tx_max_priority_fee_per_gas_wei: 0,
            per_tx_max_calldata_bytes: 0,
        });
    }

    Ok((effective_policies, synthesized_count))
}

fn resolve_bootstrap_policy_attachment(
    created_policy_ids: impl IntoIterator<Item = Uuid>,
    attach_bootstrap_policy_ids: impl IntoIterator<Item = Uuid>,
    attach_policy_ids: &[Uuid],
) -> Result<(PolicyAttachment, String, Vec<String>, String)> {
    let created_policy_ids = created_policy_ids.into_iter().collect::<BTreeSet<_>>();
    let attach_bootstrap_policy_ids = attach_bootstrap_policy_ids
        .into_iter()
        .collect::<BTreeSet<_>>();
    let explicit_policy_ids = attach_policy_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut policy_set_ids = attach_bootstrap_policy_ids.clone();
    policy_set_ids.extend(created_policy_ids.iter().copied());
    policy_set_ids.extend(explicit_policy_ids.iter().copied());

    if policy_set_ids.is_empty() {
        return Ok((
            PolicyAttachment::AllPolicies,
            "all_policies".to_string(),
            Vec::new(),
            "agent key is attached to all policies".to_string(),
        ));
    }

    let attached_policy_ids = policy_set_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let base_policy_note = match (created_policy_ids.len(), explicit_policy_ids.len()) {
        (created_count, 0) => format!(
            "agent key is attached to {created_count} bootstrap-created policy id(s)"
        ),
        (0, explicit_count) => {
            format!("agent key is attached to {explicit_count} explicit policy id(s)")
        }
        (created_count, explicit_count) => format!(
            "agent key is attached to {created_count} bootstrap-created policy id(s) and {explicit_count} explicit policy id(s)"
        ),
    };
    let existing_policy_count = attach_bootstrap_policy_ids
        .difference(&created_policy_ids)
        .count();
    let policy_note = if existing_policy_count == 0 {
        base_policy_note
    } else if explicit_policy_ids.is_empty() && created_policy_ids.is_empty() {
        format!("agent key is attached to {existing_policy_count} existing enabled policy id(s)")
    } else {
        format!("{base_policy_note} plus {existing_policy_count} existing enabled policy id(s)")
    };

    Ok((
        PolicyAttachment::policy_set(policy_set_ids)
            .context("invalid policy attachment configuration")?,
        "policy_set".to_string(),
        attached_policy_ids,
        policy_note,
    ))
}

fn validate_policy_limits(per_tx: u128, daily: u128, weekly: u128) -> Result<()> {
    if daily < per_tx {
        bail!(
            "--daily-max-wei ({daily}) must be greater than or equal to --per-tx-max-wei ({per_tx})"
        );
    }
    if weekly < daily {
        bail!(
            "--weekly-max-wei ({weekly}) must be greater than or equal to --daily-max-wei ({daily})"
        );
    }
    Ok(())
}

fn parse_positive_u128(input: &str) -> Result<u128, String> {
    let parsed = input
        .parse::<u128>()
        .map_err(|_| "must be a valid unsigned integer".to_string())?;
    if parsed == 0 {
        return Err("must be greater than zero".to_string());
    }
    Ok(parsed)
}

fn resolve_daemon_socket_path(cli_value: Option<PathBuf>) -> Result<PathBuf> {
    let path = match cli_value {
        Some(path) => path,
        None => agentpay_home_dir()?.join("daemon.sock"),
    };

    assert_root_owned_daemon_socket_path(&path).map_err(anyhow::Error::msg)
}

fn agentpay_home_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGENTPAY_HOME") {
        let candidate = PathBuf::from(path);
        if candidate.as_os_str().is_empty() {
            bail!("AGENTPAY_HOME must not be empty");
        }
        return Ok(candidate);
    }

    let Some(home) = std::env::var_os("HOME") else {
        bail!("HOME is not set; use AGENTPAY_HOME to choose config directory");
    };
    Ok(PathBuf::from(home).join(".agentpay"))
}

fn parse_non_negative_u128(input: &str) -> Result<u128, String> {
    input
        .parse::<u128>()
        .map_err(|_| "must be a valid unsigned integer".to_string())
}

fn parse_positive_u64(input: &str) -> Result<u64, String> {
    let parsed = input
        .parse::<u64>()
        .map_err(|_| "must be a valid unsigned integer".to_string())?;
    if parsed == 0 {
        return Err("must be greater than zero".to_string());
    }
    Ok(parsed)
}

fn display_optional_output_value(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("unlimited")
}

fn describe_policy_type(policy_type: PolicyType) -> &'static str {
    match policy_type {
        PolicyType::DailyMaxSpending => "daily_max_spending",
        PolicyType::DailyMaxTxCount => "daily_max_tx_count",
        PolicyType::WeeklyMaxSpending => "weekly_max_spending",
        PolicyType::PerTxMaxSpending => "per_tx_max_spending",
        PolicyType::PerTxMaxFeePerGas => "per_tx_max_fee_per_gas",
        PolicyType::PerTxMaxPriorityFeePerGas => "per_tx_max_priority_fee_per_gas",
        PolicyType::PerTxMaxCalldataBytes => "per_tx_max_calldata_bytes",
        PolicyType::PerChainMaxGasSpend => "per_chain_max_gas_spend",
        PolicyType::ManualApproval => "manual_approval",
        PolicyType::Eip712Signing => "eip712_signing",
    }
}

fn describe_approval_type(approval_type: DomainApprovalType) -> &'static str {
    match approval_type {
        DomainApprovalType::Allow => "allow",
        DomainApprovalType::ManualApproval => "manual_approval",
        DomainApprovalType::Deny => "deny",
    }
}

fn print_bootstrap_output(
    output: &BootstrapOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => {
            let mut lines = vec![
                format!("State File: {}", output.state_file),
                "Lease".to_string(),
                format!("  ID: {}", output.lease_id),
                format!("  Expires At: {}", output.lease_expires_at),
                format!("  Agent Policy Attachment: {}", output.policy_attachment),
                "Keys".to_string(),
                format!("  Vault Key ID: {}", output.vault_key_id),
                format!("  Vault Public Key: {}", output.vault_public_key),
                format!("  Solana Public Key: {}", output.solana_public_key),
                output
                    .vault_private_key
                    .as_ref()
                    .map(|value| format!("  Vault Private Key: {value}"))
                    .unwrap_or_default(),
                format!("  Agent Key ID: {}", output.agent_key_id),
                format!("  Agent Auth Token: {}", output.agent_auth_token),
            ];
            if output.token_policies.is_empty() {
                lines.push("Policies".to_string());
                if let Some(value) = &output.per_tx_policy_id {
                    lines.push(format!("  Per-Tx: {value}"));
                }
                if let Some(value) = &output.daily_policy_id {
                    lines.push(format!("  Daily: {value}"));
                }
                if let Some(value) = &output.weekly_policy_id {
                    lines.push(format!("  Weekly: {value}"));
                }
                if let Some(value) = &output.gas_policy_id {
                    lines.push(format!("  Per-Chain Max Gas: {value}"));
                }
                if let Some(value) = &output.per_tx_max_wei {
                    lines.push(format!("  Per-Tx Limit (wei): {value}"));
                }
                if let Some(value) = &output.daily_max_wei {
                    lines.push(format!("  Daily Limit (wei): {value}"));
                }
                if let Some(value) = &output.weekly_max_wei {
                    lines.push(format!("  Weekly Limit (wei): {value}"));
                }
                if let Some(value) = &output.max_gas_per_chain_wei {
                    lines.push(format!("  Per-Chain Max Gas Limit (wei): {value}"));
                }
                if let Some(value) = &output.daily_max_tx_count {
                    lines.push(format!("  Daily Tx Count Limit: {value}"));
                }
                if let Some(id) = &output.daily_tx_count_policy_id {
                    lines.push(format!("  Daily Tx Count: {id}"));
                }
                if let Some(value) = &output.per_tx_max_fee_per_gas_wei {
                    lines.push(format!("  Per-Tx Max Fee Per Gas Limit (wei): {value}"));
                }
                if let Some(id) = &output.per_tx_max_fee_per_gas_policy_id {
                    lines.push(format!("  Per-Tx Max Fee Per Gas: {id}"));
                }
                if let Some(value) = &output.per_tx_max_priority_fee_per_gas_wei {
                    lines.push(format!(
                        "  Per-Tx Max Priority Fee Per Gas Limit (wei): {value}"
                    ));
                }
                if let Some(id) = &output.per_tx_max_priority_fee_per_gas_policy_id {
                    lines.push(format!("  Per-Tx Max Priority Fee Per Gas: {id}"));
                }
                if let Some(value) = &output.per_tx_max_calldata_bytes {
                    lines.push(format!("  Per-Tx Max Calldata Bytes Limit: {value}"));
                }
                if let Some(id) = &output.per_tx_max_calldata_bytes_policy_id {
                    lines.push(format!("  Per-Tx Max Calldata Bytes: {id}"));
                }
                if let Some(value) = &output.network_scope {
                    lines.push(format!("  Network Scope: {value}"));
                }
                if let Some(value) = &output.asset_scope {
                    lines.push(format!("  Asset Scope: {value}"));
                }
                if let Some(value) = &output.recipient_scope {
                    lines.push(format!("  Recipient Scope: {value}"));
                }
            } else {
                lines.push("Per-Token Policies".to_string());
                for token_policy in &output.token_policies {
                    lines.push(format!(
                        "  {}:{} ({})",
                        token_policy.token_key, token_policy.chain_key, token_policy.symbol
                    ));
                    lines.push(format!("    Chain ID: {}", token_policy.chain_id));
                    lines.push(format!("    Asset Scope: {}", token_policy.asset_scope));
                    lines.push(format!(
                        "    Limits: per-tx={} daily={} weekly={} gas={}",
                        token_policy.per_tx_max_wei,
                        token_policy.daily_max_wei,
                        token_policy.weekly_max_wei,
                        display_optional_output_value(&token_policy.max_gas_per_chain_wei)
                    ));
                    if let Some(value) = &token_policy.daily_max_tx_count {
                        lines.push(format!("    Daily Tx Count Limit: {value}"));
                    }
                    if let Some(value) = &token_policy.per_tx_max_fee_per_gas_wei {
                        lines.push(format!("    Per-Tx Max Fee/Gas Limit (wei): {value}"));
                    }
                    if let Some(value) = &token_policy.per_tx_max_priority_fee_per_gas_wei {
                        lines.push(format!(
                            "    Per-Tx Max Priority Fee/Gas Limit (wei): {value}"
                        ));
                    }
                    if let Some(value) = &token_policy.per_tx_max_calldata_bytes {
                        lines.push(format!("    Per-Tx Max Calldata Bytes Limit: {value}"));
                    }
                    lines.push(format!(
                        "    Policy IDs: per_tx={} daily={} weekly={} gas={}",
                        token_policy.per_tx_policy_id,
                        token_policy.daily_policy_id,
                        token_policy.weekly_policy_id,
                        display_optional_output_value(&token_policy.gas_policy_id)
                    ));
                }
            }
            lines.push(format!(
                "  Destination Override Count: {}",
                output.destination_override_count
            ));
            if output.agent_auth_token == "<redacted>" {
                lines.push(
                    "  Note: pass --print-agent-auth-token to intentionally print secret credentials"
                        .to_string(),
                );
            } else {
                lines.push(
                    "  Warning: keep the agent auth token and any exported private key carefully."
                        .to_string(),
                );
            }
            if !output.destination_overrides.is_empty() {
                lines.push("Destination Overrides".to_string());
                for destination_override in &output.destination_overrides {
                    lines.push(format!("  Recipient: {}", destination_override.recipient));
                    lines.push(format!(
                        "    Limits (wei): per-tx={} daily={} weekly={} gas={}",
                        destination_override.per_tx_max_wei,
                        destination_override.daily_max_wei,
                        destination_override.weekly_max_wei,
                        display_optional_output_value(&destination_override.max_gas_per_chain_wei)
                    ));
                    if let Some(value) = &destination_override.daily_max_tx_count {
                        lines.push(format!("    Daily Tx Count Limit: {value}"));
                    }
                    if let Some(value) = &destination_override.per_tx_max_fee_per_gas_wei {
                        lines.push(format!("    Per-Tx Max Fee/Gas Limit (wei): {value}"));
                    }
                    if let Some(value) = &destination_override.per_tx_max_priority_fee_per_gas_wei {
                        lines.push(format!(
                            "    Per-Tx Max Priority Fee/Gas Limit (wei): {value}"
                        ));
                    }
                    if let Some(value) = &destination_override.per_tx_max_calldata_bytes {
                        lines.push(format!("    Per-Tx Max Calldata Bytes Limit: {value}"));
                    }
                    lines.push(format!(
                        "    Policy IDs: per_tx={} daily={} weekly={} gas={}",
                        destination_override.per_tx_policy_id,
                        destination_override.daily_policy_id,
                        destination_override.weekly_policy_id,
                        display_optional_output_value(&destination_override.gas_policy_id)
                    ));
                }
            }
            if !output.token_destination_overrides.is_empty() {
                lines.push("Per-Token Destination Overrides".to_string());
                for destination_override in &output.token_destination_overrides {
                    lines.push(format!(
                        "  {}:{} ({}) -> {}",
                        destination_override.token_key,
                        destination_override.chain_key,
                        destination_override.symbol,
                        destination_override.recipient
                    ));
                    lines.push(format!(
                        "    Limits: per-tx={} daily={} weekly={} gas={}",
                        destination_override.per_tx_max_wei,
                        destination_override.daily_max_wei,
                        destination_override.weekly_max_wei,
                        display_optional_output_value(&destination_override.max_gas_per_chain_wei)
                    ));
                    if let Some(value) = &destination_override.daily_max_tx_count {
                        lines.push(format!("    Daily Tx Count Limit: {value}"));
                    }
                    if let Some(value) = &destination_override.per_tx_max_fee_per_gas_wei {
                        lines.push(format!("    Per-Tx Max Fee/Gas Limit (wei): {value}"));
                    }
                    if let Some(value) = &destination_override.per_tx_max_priority_fee_per_gas_wei {
                        lines.push(format!(
                            "    Per-Tx Max Priority Fee/Gas Limit (wei): {value}"
                        ));
                    }
                    if let Some(value) = &destination_override.per_tx_max_calldata_bytes {
                        lines.push(format!("    Per-Tx Max Calldata Bytes Limit: {value}"));
                    }
                    lines.push(format!(
                        "    Policy IDs: per_tx={} daily={} weekly={} gas={}",
                        destination_override.per_tx_policy_id,
                        destination_override.daily_policy_id,
                        destination_override.weekly_policy_id,
                        display_optional_output_value(&destination_override.gas_policy_id)
                    ));
                }
            }
            if !output.token_manual_approval_policies.is_empty() {
                lines.push("Per-Token Manual Approval Policies".to_string());
                for manual_approval in &output.token_manual_approval_policies {
                    lines.push(format!(
                        "  {}:{} ({})",
                        manual_approval.token_key,
                        manual_approval.chain_key,
                        manual_approval.symbol
                    ));
                    lines.push(format!("    Chain ID: {}", manual_approval.chain_id));
                    lines.push(format!("    Priority: {}", manual_approval.priority));
                    lines.push(format!(
                        "    Amount Range (wei): {} -> {}",
                        manual_approval.min_amount_wei, manual_approval.max_amount_wei
                    ));
                    lines.push(format!("    Asset Scope: {}", manual_approval.asset_scope));
                    lines.push(format!(
                        "    Recipient Scope: {}",
                        manual_approval.recipient_scope
                    ));
                    lines.push(format!("    Policy ID: {}", manual_approval.policy_id));
                }
            }
            if !output.attached_policy_ids.is_empty() {
                lines.push("Attached Policy IDs".to_string());
                for policy_id in &output.attached_policy_ids {
                    lines.push(format!("  {policy_id}"));
                }
            }
            lines.push("Policy Note".to_string());
            lines.push(format!("  {}", output.policy_note));
            lines
                .into_iter()
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join("\n")
        }
    };
    emit_output(&rendered, target)
}

fn print_export_vault_private_key_output(
    output: &ExportVaultPrivateKeyOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => [
            format!("Vault Key ID: {}", output.vault_key_id),
            format!("Vault Private Key: {}", output.vault_private_key),
            "Warning: this is raw wallet key material; store it offline and delete any transient copies immediately.".to_string(),
        ]
        .join("\n"),
    };
    emit_output(&rendered, target)
}

fn print_rotate_agent_auth_token_output(
    output: &RotateAgentAuthTokenOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => {
            let mut lines = vec![
                format!("Agent Key ID: {}", output.agent_key_id),
                format!("Agent Auth Token: {}", output.agent_auth_token),
            ];
            if output.agent_auth_token_redacted {
                lines.push(
                    "Note: pass --print-agent-auth-token to intentionally print secret credentials"
                        .to_string(),
                );
            }
            lines.join("\n")
        }
    };
    emit_output(&rendered, target)
}

fn print_revoke_agent_key_output(
    output: &RevokeAgentKeyOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => format!(
            "Agent Key ID: {}\nRevoked: {}",
            output.agent_key_id, output.revoked
        ),
    };
    emit_output(&rendered, target)
}

fn print_manual_approval_policy_output(
    output: &ManualApprovalPolicyOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => vec![
            format!("Policy ID: {}", output.policy_id),
            format!("Priority: {}", output.priority),
            format!(
                "Amount Range (wei): {}..={}",
                output.min_amount_wei, output.max_amount_wei
            ),
            format!("Networks: {}", output.network_scope),
            format!("Assets: {}", output.asset_scope),
            format!("Recipients: {}", output.recipient_scope),
        ]
        .join(
            "
",
        ),
    };
    emit_output(&rendered, target)
}

fn print_eip712_signing_policy_output(
    output: &Eip712SigningPolicyOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => vec![
            format!("Policy ID: {}", output.policy_id),
            format!("Priority: {}", output.priority),
            format!("Approval Type: {}", output.approval_type),
            format!("Networks: {}", output.network_scope),
        ]
        .join("\n"),
    };
    emit_output(&rendered, target)
}

fn render_policy_text(policy: &SpendingPolicy) -> String {
    let mut lines = vec![
        format!("Policy ID: {}", policy.id),
        format!("Priority: {}", policy.priority),
        format!("Type: {}", describe_policy_type(policy.policy_type)),
        format!("Enabled: {}", policy.enabled),
        format!("Networks: {}", describe_network_scope(&policy.networks)),
        format!("Assets: {}", describe_asset_scope(&policy.assets)),
        format!(
            "Recipients: {}",
            describe_recipient_scope(&policy.recipients)
        ),
    ];

    match policy.policy_type {
        PolicyType::DailyMaxSpending
        | PolicyType::WeeklyMaxSpending
        | PolicyType::PerTxMaxSpending => {
            lines.push(format!("Max Amount (wei): {}", policy.max_amount_wei));
        }
        PolicyType::ManualApproval => {
            lines.push(format!(
                "Min Amount (wei): {}",
                policy.min_amount_wei.unwrap_or(1)
            ));
            lines.push(format!("Max Amount (wei): {}", policy.max_amount_wei));
        }
        PolicyType::DailyMaxTxCount => {
            lines.push(format!(
                "Max Tx Count: {}",
                policy.tx_count_limit().unwrap_or_default()
            ));
        }
        PolicyType::PerTxMaxFeePerGas => {
            lines.push(format!(
                "Max Fee/Gas (wei): {}",
                policy.fee_per_gas_limit().unwrap_or_default()
            ));
        }
        PolicyType::PerTxMaxPriorityFeePerGas => {
            lines.push(format!(
                "Max Priority Fee/Gas (wei): {}",
                policy.priority_fee_per_gas_limit().unwrap_or_default()
            ));
        }
        PolicyType::PerTxMaxCalldataBytes => {
            lines.push(format!(
                "Max Calldata Bytes: {}",
                policy.calldata_bytes_limit().unwrap_or_default()
            ));
        }
        PolicyType::PerChainMaxGasSpend => {
            lines.push(format!(
                "Max Gas Spend (wei): {}",
                policy.gas_spend_limit_wei().unwrap_or_default()
            ));
        }
        PolicyType::Eip712Signing => {
            lines.push(format!(
                "Approval Type: {}",
                describe_approval_type(
                    policy
                        .eip712_approval_type()
                        .unwrap_or(DomainApprovalType::ManualApproval)
                )
            ));
        }
    }

    lines.join("\n")
}

fn print_policies_output(
    output: &[SpendingPolicy],
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => {
            if output.is_empty() {
                "No policies.".to_string()
            } else {
                output
                    .iter()
                    .map(render_policy_text)
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
        }
    };
    emit_output(&rendered, target)
}

fn print_manual_approval_requests_output(
    output: &[ManualApprovalRequest],
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => {
            if output.is_empty() {
                "No manual approval requests".to_string()
            } else {
                output
                    .iter()
                    .map(render_manual_approval_request_text)
                    .collect::<Vec<_>>()
                    .join(
                        "

",
                    )
            }
        }
    };
    emit_output(&rendered, target)
}

fn print_manual_approval_request_output(
    output: &ManualApprovalRequest,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => render_manual_approval_request_text(output),
    };
    emit_output(&rendered, target)
}

fn render_manual_approval_request_text(output: &ManualApprovalRequest) -> String {
    let created_at = output
        .created_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| output.created_at.to_string());
    let updated_at = output
        .updated_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| output.updated_at.to_string());
    let completed_at = output
        .completed_at
        .and_then(|value| value.format(&Rfc3339).ok());
    let mut lines = vec![
        format!("Request ID: {}", output.id),
        format!("Status: {:?}", output.status),
        format!("Agent Key ID: {}", output.agent_key_id),
        format!("Vault Key ID: {}", output.vault_key_id),
        format!("Chain ID: {}", output.chain_id),
        format!("Asset: {}", output.asset),
        format!("Recipient: {}", output.recipient),
        format!("Amount (wei): {}", output.amount_wei),
        format!("Payload Hash: {}", output.request_payload_hash_hex),
        format!("Created At: {created_at}"),
        format!("Updated At: {updated_at}"),
    ];
    if let Some(completed_at) = completed_at {
        lines.push(format!("Completed At: {completed_at}"));
    }
    if let Some(reason) = &output.rejection_reason {
        lines.push(format!("Rejection Reason: {reason}"));
    }
    if !output.triggered_by_policy_ids.is_empty() {
        lines.push(format!(
            "Triggered By Policies: {}",
            output
                .triggered_by_policy_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Ok(Some(primary_type)) = output.action.eip712_primary_type() {
        lines.push(format!("EIP712 Primary Type: {primary_type}"));
    }
    if let Ok(Some(verifying_contract)) = output.action.eip712_verifying_contract() {
        lines.push(format!("EIP712 Verifying Contract: {}", verifying_contract));
    }
    if let Ok(Some(signing_hash)) = output.action.signing_hash() {
        lines.push(format!("Signing Hash: 0x{}", hex::encode(signing_hash)));
    }
    if let AgentAction::Eip712TypedData { typed_data } = &output.action {
        let rendered_typed_data =
            serde_json::from_str::<serde_json::Value>(&typed_data.typed_data_json)
                .ok()
                .and_then(|value| serde_json::to_string_pretty(&value).ok())
                .unwrap_or_else(|| typed_data.typed_data_json.clone());
        lines.push(format!("Typed Data JSON:\n{rendered_typed_data}"));
    }
    lines.join(
        "
",
    )
}

fn print_relay_config_output(
    output: &RelayConfig,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => vec![
            format!(
                "Relay URL: {}",
                output.relay_url.as_deref().unwrap_or("<unset>")
            ),
            format!(
                "Frontend URL: {}",
                output.frontend_url.as_deref().unwrap_or("<unset>")
            ),
            format!("Daemon ID: {}", output.daemon_id_hex),
            format!("Daemon Public Key: {}", output.daemon_public_key_hex),
        ]
        .join(
            "
",
        ),
    };
    emit_output(&rendered, target)
}

fn build_asset_scope(tokens: &[EvmAddress], allow_native_eth: bool) -> EntityScope<AssetId> {
    if tokens.is_empty() && !allow_native_eth {
        return EntityScope::All;
    }

    let mut set = BTreeSet::new();
    if allow_native_eth {
        set.insert(AssetId::NativeEth);
    }
    for token in tokens {
        set.insert(AssetId::Erc20(token.clone()));
    }
    EntityScope::Set(set)
}

fn build_network_scope(network: Option<u64>) -> EntityScope<u64> {
    match network {
        Some(chain_id) => single_scope(canonical_policy_chain_id(chain_id)),
        None => EntityScope::All,
    }
}

fn describe_network_scope(scope: &EntityScope<u64>) -> String {
    match scope {
        EntityScope::All => "all networks".to_string(),
        EntityScope::Set(values) => values
            .iter()
            .map(|chain_id| canonical_policy_chain_id(*chain_id).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn describe_asset_scope(scope: &EntityScope<AssetId>) -> String {
    match scope {
        EntityScope::All => "all assets".to_string(),
        EntityScope::Set(values) => values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn describe_recipient_scope<T>(scope: &EntityScope<T>) -> String
where
    T: std::fmt::Display + Ord,
{
    match scope {
        EntityScope::All => "all recipients".to_string(),
        EntityScope::Set(values) => values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}

fn format_key_algorithm(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Secp256k1 => "secp256k1",
        KeyAlgorithm::Ed25519 => "ed25519",
    }
}

fn single_scope<T: Ord>(value: T) -> EntityScope<T> {
    let mut set = BTreeSet::new();
    set.insert(value);
    EntityScope::Set(set)
}

#[cfg(test)]
mod tests {
    use super::{
        build_asset_scope, build_network_scope, build_policy_bundle,
        build_shared_config_bootstrap_params, describe_recipient_scope, ensure_output_parent,
        execute_add_manual_approval_policy, execute_bootstrap,
        execute_decide_manual_approval_request, execute_export_vault_private_key,
        execute_get_relay_config, execute_list_manual_approval_requests, execute_list_policies,
        execute_revoke_agent_key, execute_rotate_agent_auth_token, execute_set_relay_config,
        parse_non_negative_u128, parse_positive_u128, parse_positive_u64,
        policy_bundle_priority_base, print_bootstrap_output, print_manual_approval_policy_output,
        print_manual_approval_request_output, print_manual_approval_requests_output,
        print_relay_config_output, print_revoke_agent_key_output,
        print_rotate_agent_auth_token_output, render_policy_text,
        resolve_bootstrap_policy_attachment, resolve_daemon_socket_path, resolve_output_format,
        resolve_output_target, should_print_status, single_scope,
        validate_existing_policy_attachments, validate_password, validate_policy_limits,
        validate_tui_vault_password, write_output_file, AddManualApprovalPolicyParams,
        BootstrapParams, Cli, Commands, DecideManualApprovalRequestParams,
        DestinationPolicyOverride, DomainApprovalType, ExportVaultPrivateKeyParams,
        ManualApprovalPolicyOutput, OutputFormat, OutputTarget, PolicyLimitConfig,
        RevokeAgentKeyOutput, RevokeAgentKeyParams, RotateAgentAuthTokenOutput,
        RotateAgentAuthTokenParams, SetRelayConfigParams, TokenAddress,
        TokenDestinationPolicyOverride, TokenManualApprovalPolicyConfig, TokenPolicyConfig,
        TokenSelectorConfig, BOOTSTRAP_POLICY_PRIORITY_STRIDE,
        DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE, DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE,
        POLICY_BUNDLE_PRIORITY_SLOTS,
    };
    use crate::{
        shared_config::{
            TokenChainProfile, TokenManualApprovalProfile, TokenPolicyProfile, TokenProfile,
            WalletProfile, WlfiConfig,
        },
        tui,
    };
    use clap::Parser;
    use serde_json::to_vec;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;
    use vault_daemon::{DaemonError, InMemoryDaemon, KeyManagerDaemonApi};
    use vault_domain::{
        AdminSession, AgentAction, AssetId, EntityScope, EvmAddress, ManualApprovalDecision,
        ManualApprovalStatus, PolicyAttachment, PolicyType, RelayConfig, SignRequest,
        SpendingPolicy, SOLANA_DEVNET_CHAIN_ID, SOLANA_POLICY_CHAIN_ID,
    };
    use vault_signer::{KeyCreateRequest, SoftwareSignerBackend};
    use zeroize::Zeroize;

    #[test]
    fn resolve_output_format_defaults_to_text() {
        let format = resolve_output_format(None, false).expect("format");
        assert!(matches!(format, OutputFormat::Text));
    }

    #[test]
    fn resolve_output_format_json_shortcut() {
        let format = resolve_output_format(None, true).expect("format");
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn resolve_output_format_rejects_text_conflict_with_json_shortcut() {
        let err = resolve_output_format(Some(OutputFormat::Text), true).expect_err("must fail");
        assert!(err.to_string().contains("--format text"));
    }

    #[test]
    fn resolve_output_format_allows_json_redundancy() {
        let format = resolve_output_format(Some(OutputFormat::Json), true).expect("format");
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn policy_bundle_priority_base_rejects_token_policy_overflow() {
        let max_index = usize::try_from(
            (u32::MAX
                - (DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE + POLICY_BUNDLE_PRIORITY_SLOTS - 1))
                / BOOTSTRAP_POLICY_PRIORITY_STRIDE,
        )
        .expect("usize");

        assert!(policy_bundle_priority_base(
            DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE,
            max_index,
            "token policies",
        )
        .is_ok());

        let err = policy_bundle_priority_base(
            DEFAULT_BOOTSTRAP_POLICY_PRIORITY_BASE,
            max_index + 1,
            "token policies",
        )
        .expect_err("must reject overflow");
        assert!(err.to_string().contains("too many token policies"));
    }

    #[test]
    fn policy_bundle_priority_base_rejects_destination_override_overflow() {
        let max_index = usize::try_from(
            (u32::MAX
                - (DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE + POLICY_BUNDLE_PRIORITY_SLOTS - 1))
                / BOOTSTRAP_POLICY_PRIORITY_STRIDE,
        )
        .expect("usize");

        assert!(policy_bundle_priority_base(
            DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE,
            max_index,
            "destination overrides",
        )
        .is_ok());

        let err = policy_bundle_priority_base(
            DESTINATION_OVERRIDE_POLICY_PRIORITY_BASE,
            max_index + 1,
            "destination overrides",
        )
        .expect_err("must reject overflow");
        assert!(err.to_string().contains("too many destination overrides"));
    }

    #[test]
    fn build_policy_bundle_rejects_priority_overflow() {
        let limits = PolicyLimitConfig {
            per_tx_max_wei: 1,
            daily_max_wei: 2,
            weekly_max_wei: 3,
            max_gas_per_chain_wei: 0,
            daily_max_tx_count: 0,
            per_tx_max_fee_per_gas_wei: 0,
            per_tx_max_priority_fee_per_gas_wei: 0,
            per_tx_max_calldata_bytes: 4,
        };

        let err = build_policy_bundle(
            u32::MAX - (POLICY_BUNDLE_PRIORITY_SLOTS - 2),
            &limits,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect_err("must reject overflow");

        assert!(err.to_string().contains("priority overflow"));
    }

    #[test]
    fn validate_password_rejects_whitespace_only() {
        let err = validate_password("   ".to_string(), "argument").expect_err("must fail");
        assert!(err.to_string().contains("must not be empty or whitespace"));
    }

    #[test]
    fn cli_rejects_inline_vault_password_argument() {
        let err = Cli::try_parse_from([
            "agentpay-admin",
            "--vault-password",
            "vault-secret",
            "bootstrap",
        ])
        .expect_err("must reject");
        assert!(err.to_string().contains("--vault-password"));
    }

    #[test]
    fn validate_policy_limits_enforce_ordering() {
        let err = validate_policy_limits(10, 9, 20).expect_err("must fail");
        assert!(err.to_string().contains("--daily-max-wei"));

        let err = validate_policy_limits(10, 10, 9).expect_err("must fail");
        assert!(err.to_string().contains("--weekly-max-wei"));
    }

    #[test]
    fn build_asset_scope_supports_native_and_erc20_sets() {
        let token: EvmAddress = "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token");

        let all_scope = build_asset_scope(&[], false);
        assert!(matches!(all_scope, EntityScope::All));

        let native_only = build_asset_scope(&[], true);
        assert!(matches!(
            native_only,
            EntityScope::Set(values) if values.contains(&AssetId::NativeEth) && values.len() == 1
        ));

        let mixed = build_asset_scope(std::slice::from_ref(&token), true);
        assert!(matches!(
            mixed,
            EntityScope::Set(values)
                if values.contains(&AssetId::NativeEth)
                && values.contains(&AssetId::Erc20(token))
        ));
    }

    #[test]
    fn build_network_scope_supports_all_or_specific_chain() {
        assert!(matches!(build_network_scope(None), EntityScope::All));
        assert!(matches!(
            build_network_scope(Some(1)),
            EntityScope::Set(values) if values.contains(&1)
        ));
        assert!(matches!(
            build_network_scope(Some(SOLANA_DEVNET_CHAIN_ID)),
            EntityScope::Set(values) if values.contains(&SOLANA_POLICY_CHAIN_ID) && values.len() == 1
        ));
    }

    #[test]
    fn describe_recipient_scope_supports_all_or_specific_recipient() {
        assert_eq!(
            describe_recipient_scope(&EntityScope::<EvmAddress>::All),
            "all recipients"
        );

        let recipient: EvmAddress = "0x1000000000000000000000000000000000000001"
            .parse()
            .expect("recipient");
        let mut recipients = std::collections::BTreeSet::new();
        recipients.insert(recipient.clone());

        assert_eq!(
            describe_recipient_scope(&EntityScope::Set(recipients)),
            recipient.to_string()
        );
    }

    #[tokio::test]
    async fn validate_existing_policy_attachments_rejects_unknown_policy_ids() {
        let daemon = test_daemon();
        let lease = daemon.issue_lease("vault-password").await.expect("lease");
        let mut session = vault_domain::AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };

        let missing = Uuid::parse_str("00000000-0000-0000-0000-000000000111").expect("uuid");
        let err = validate_existing_policy_attachments(daemon.as_ref(), &session, &[missing])
            .await
            .expect_err("must reject unknown policy id");

        session.vault_password.zeroize();
        assert!(err
            .to_string()
            .contains("unknown --attach-policy-id value(s):"));
        assert!(err.to_string().contains(&missing.to_string()));
    }

    #[test]
    fn status_printing_only_in_text_when_not_quiet() {
        assert!(should_print_status(OutputFormat::Text, false));
        assert!(!should_print_status(OutputFormat::Text, true));
        assert!(!should_print_status(OutputFormat::Json, false));
    }

    #[test]
    fn resolve_output_target_maps_dash_to_stdout() {
        let target = resolve_output_target(Some("-".into()), false).expect("target");
        assert!(matches!(target, OutputTarget::Stdout));
    }

    #[test]
    fn resolve_output_target_rejects_overwrite_with_stdout() {
        let err = resolve_output_target(Some("-".into()), true).expect_err("must fail");
        assert!(err.to_string().contains("--overwrite cannot be used"));
    }

    #[test]
    fn output_file_write_respects_overwrite_flag() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agentpay-admin-cli-output-{}-{}.txt",
            std::process::id(),
            unique
        ));
        std::fs::write(&path, "existing\n").expect("seed");

        let err = write_output_file(&path, "next", false).expect_err("must fail");
        assert!(err.to_string().contains("already exists"));

        write_output_file(&path, "next", true).expect("overwrite");
        let updated = std::fs::read_to_string(&path).expect("read");
        assert_eq!(updated, "next\n");

        std::fs::remove_file(&path).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn output_file_write_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let target = std::env::temp_dir().join(format!(
            "agentpay-admin-cli-symlink-target-{}-{}.txt",
            std::process::id(),
            unique
        ));
        let link = std::env::temp_dir().join(format!(
            "agentpay-admin-cli-symlink-link-{}-{}.txt",
            std::process::id(),
            unique
        ));
        std::fs::write(&target, "seed\n").expect("seed");
        symlink(&target, &link).expect("symlink");

        let err = ensure_output_parent(&link).expect_err("must fail");
        assert!(err.to_string().contains("must not be a symlink"));

        std::fs::remove_file(&link).expect("cleanup link");
        std::fs::remove_file(&target).expect("cleanup target");
    }

    #[test]
    fn canonical_bootstrap_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "bootstrap",
        ])
        .expect("parse");
        assert!(matches!(cli.command, Commands::Bootstrap(_)));
    }

    #[test]
    fn bootstrap_supports_explicit_agent_policy_attachment_flags() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "bootstrap",
            "--from-shared-config",
            "--attach-bootstrap-policies",
            "--attach-policy-id",
            "00000000-0000-0000-0000-000000000001",
            "--attach-policy-id",
            "00000000-0000-0000-0000-000000000002",
        ])
        .expect("parse");

        let Commands::Bootstrap(args) = cli.command else {
            panic!("expected bootstrap command");
        };
        assert!(args.from_shared_config);
        assert!(args.attach_bootstrap_policies);
        assert_eq!(args.attach_policy_id.len(), 2);
    }

    #[test]
    fn bootstrap_supports_existing_wallet_reuse_flags() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "bootstrap",
            "--from-shared-config",
            "--existing-vault-key-id",
            "00000000-0000-0000-0000-000000000003",
            "--existing-vault-public-key",
            "03abcdef",
        ])
        .expect("parse");

        let Commands::Bootstrap(args) = cli.command else {
            panic!("expected bootstrap command");
        };
        assert_eq!(
            args.existing_vault_key_id,
            Some(Uuid::parse_str("00000000-0000-0000-0000-000000000003").expect("valid uuid"),)
        );
        assert_eq!(args.existing_vault_public_key.as_deref(), Some("03abcdef"));
    }

    #[test]
    fn shared_config_bootstrap_params_reuse_existing_agent_key_when_wallet_metadata_is_supplied() {
        let existing_agent_key_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000011").expect("agent key uuid");
        let existing_vault_key_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000022").expect("vault key uuid");
        let mut config = WlfiConfig::default();
        config.wallet = Some(WalletProfile {
            vault_key_id: Some(existing_vault_key_id.to_string()),
            vault_public_key: "03abcdef".to_string(),
            address: Some("0x0000000000000000000000000000000000000001".to_string()),
            agent_key_id: Some(existing_agent_key_id.to_string()),
            policy_attachment: "all_policies".to_string(),
            attached_policy_ids: Vec::new(),
            policy_note: None,
            network_scope: None,
            asset_scope: None,
            recipient_scope: None,
            extra: Default::default(),
        });

        let params = build_shared_config_bootstrap_params(
            &config,
            true,
            None,
            Vec::new(),
            false,
            Some(existing_vault_key_id),
            Some("03abcdef".to_string()),
            None,
        )
        .expect("shared-config reuse params");

        assert_eq!(params.existing_agent_key_id, Some(existing_agent_key_id));
        assert_eq!(params.existing_vault_key_id, Some(existing_vault_key_id));
        assert_eq!(
            params.existing_vault_public_key.as_deref(),
            Some("03abcdef")
        );
    }

    #[test]
    fn bootstrap_command_accepts_explicit_vault_private_key_export_flag() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "bootstrap",
            "--print-vault-private-key",
        ])
        .expect("parse");

        let Commands::Bootstrap(args) = cli.command else {
            panic!("expected bootstrap command");
        };
        assert!(args.print_vault_private_key);
    }

    #[test]
    fn bootstrap_command_accepts_import_vault_private_key_file() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "bootstrap",
            "--import-vault-private-key-file",
            "/tmp/wallet.key",
        ])
        .expect("parse");

        let Commands::Bootstrap(args) = cli.command else {
            panic!("expected bootstrap command");
        };
        assert_eq!(
            args.import_vault_private_key_file,
            Some(PathBuf::from("/tmp/wallet.key"))
        );
    }

    #[test]
    fn export_vault_private_key_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "export-vault-private-key",
            "--vault-key-id",
            "00000000-0000-0000-0000-000000000001",
        ])
        .expect("parse");

        let Commands::ExportVaultPrivateKey(args) = cli.command else {
            panic!("expected export-vault-private-key command");
        };
        assert_eq!(
            args.vault_key_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid")
        );
    }

    #[test]
    fn shared_config_bootstrap_params_keep_default_inventory_unrestricted() {
        let params =
            tui::build_bootstrap_params_from_shared_config(&WlfiConfig::default(), false, false)
                .expect("params");
        assert!(params.use_per_token_bootstrap);
        assert!(params.token_policies.is_empty());
        assert!(params.tokens.is_empty());
        assert!(params.token_destination_overrides.is_empty());
        assert!(params.token_manual_approval_policies.is_empty());
    }

    #[test]
    fn tui_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "tui",
        ])
        .expect("parse");
        let Commands::Tui(args) = cli.command else {
            panic!("expected tui command");
        };
        assert!(!args.print_agent_auth_token);
    }

    #[test]
    fn tui_command_accepts_print_agent_auth_token_flag() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "tui",
            "--print-agent-auth-token",
        ])
        .expect("parse");
        let Commands::Tui(args) = cli.command else {
            panic!("expected tui command");
        };
        assert!(args.print_agent_auth_token);
    }

    #[test]
    fn setup_command_is_accepted() {
        let cli =
            Cli::try_parse_from(["agentpay-admin", "setup", "--network", "56"]).expect("parse");
        let Commands::Setup(args) = cli.command else {
            panic!("expected setup command");
        };
        assert_eq!(args.forwarded_args, vec!["--network", "56"]);
    }

    #[test]
    fn rotate_agent_auth_token_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "rotate-agent-auth-token",
            "--agent-key-id",
            "00000000-0000-0000-0000-000000000001",
        ])
        .expect("parse");

        let Commands::RotateAgentAuthToken(args) = cli.command else {
            panic!("expected rotate-agent-auth-token command");
        };
        assert_eq!(
            args.agent_key_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid")
        );
        assert!(!args.print_agent_auth_token);
    }

    #[test]
    fn revoke_agent_key_command_is_accepted() {
        let cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "revoke-agent-key",
            "--agent-key-id",
            "00000000-0000-0000-0000-000000000001",
        ])
        .expect("parse");

        let Commands::RevokeAgentKey(args) = cli.command else {
            panic!("expected revoke-agent-key command");
        };
        assert_eq!(
            args.agent_key_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid")
        );
    }

    fn test_bootstrap_params(print_agent_auth_token: bool) -> BootstrapParams {
        BootstrapParams {
            per_tx_max_wei: 1_000_000_000_000_000_000,
            daily_max_wei: 5_000_000_000_000_000_000,
            weekly_max_wei: 20_000_000_000_000_000_000,
            max_gas_per_chain_wei: 1_000_000_000_000_000,
            daily_max_tx_count: 0,
            per_tx_max_fee_per_gas_wei: 0,
            per_tx_max_priority_fee_per_gas_wei: 0,
            per_tx_max_calldata_bytes: 0,
            tokens: Vec::new(),
            allow_native_eth: true,
            network: Some(1),
            recipient: None,
            use_per_token_bootstrap: false,
            attach_bootstrap_policies: false,
            token_selectors: Vec::new(),
            token_policies: Vec::new(),
            destination_overrides: Vec::new(),
            token_destination_overrides: Vec::new(),
            token_manual_approval_policies: Vec::new(),
            attach_policy_ids: Vec::new(),
            print_agent_auth_token,
            print_vault_private_key: false,
            existing_agent_key_id: None,
            existing_vault_key_id: None,
            existing_vault_public_key: None,
            import_vault_private_key: None,
        }
    }

    fn test_per_token_bootstrap_params(print_agent_auth_token: bool) -> BootstrapParams {
        let token_policies = vec![
            TokenPolicyConfig {
                token_key: "eth".to_string(),
                symbol: "ETH".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: true,
                address: None,
                per_tx_max_wei: 100,
                daily_max_wei: 500,
                weekly_max_wei: 1_000,
                max_gas_per_chain_wei: 1_000_000,
                daily_max_tx_count: 0,
                per_tx_max_fee_per_gas_wei: 0,
                per_tx_max_priority_fee_per_gas_wei: 0,
                per_tx_max_calldata_bytes: 0,
            },
            TokenPolicyConfig {
                token_key: "usd1".to_string(),
                symbol: "USD1".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: false,
                address: Some(TokenAddress::Evm(
                    "0x1000000000000000000000000000000000000000"
                        .parse()
                        .expect("usd1 address"),
                )),
                per_tx_max_wei: 250,
                daily_max_wei: 1_000,
                weekly_max_wei: 2_000,
                max_gas_per_chain_wei: 1_000_000,
                daily_max_tx_count: 0,
                per_tx_max_fee_per_gas_wei: 0,
                per_tx_max_priority_fee_per_gas_wei: 0,
                per_tx_max_calldata_bytes: 0,
            },
        ];

        BootstrapParams {
            per_tx_max_wei: 0,
            daily_max_wei: 0,
            weekly_max_wei: 0,
            max_gas_per_chain_wei: 0,
            daily_max_tx_count: 0,
            per_tx_max_fee_per_gas_wei: 0,
            per_tx_max_priority_fee_per_gas_wei: 0,
            per_tx_max_calldata_bytes: 0,
            tokens: Vec::new(),
            allow_native_eth: false,
            network: None,
            recipient: None,
            use_per_token_bootstrap: true,
            attach_bootstrap_policies: false,
            token_selectors: token_policies
                .iter()
                .map(TokenSelectorConfig::from_token_policy)
                .collect(),
            token_policies,
            destination_overrides: Vec::new(),
            token_destination_overrides: Vec::new(),
            token_manual_approval_policies: Vec::new(),
            attach_policy_ids: Vec::new(),
            print_agent_auth_token,
            print_vault_private_key: false,
            existing_agent_key_id: None,
            existing_vault_key_id: None,
            existing_vault_public_key: None,
            import_vault_private_key: None,
        }
    }

    fn test_daemon() -> Arc<dyn KeyManagerDaemonApi> {
        Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        )
    }

    fn build_sign_request(
        agent_key_id: &str,
        agent_auth_token: &str,
        action: AgentAction,
    ) -> SignRequest {
        let now = time::OffsetDateTime::now_utc();
        SignRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: Uuid::parse_str(agent_key_id).expect("agent key uuid"),
            agent_auth_token: agent_auth_token.to_string().into(),
            payload: to_vec(&action).expect("action payload"),
            action,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        }
    }

    async fn create_existing_vault_key(daemon: Arc<dyn KeyManagerDaemonApi>) -> (Uuid, String) {
        let lease = daemon
            .issue_lease("vault-password")
            .await
            .expect("issue lease");
        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };
        let vault_key = daemon
            .create_vault_key(&session, KeyCreateRequest::Generate)
            .await
            .expect("create vault key");
        (vault_key.id, vault_key.public_key_hex)
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("agentpay-admin-{label}-{unique:x}.txt"))
    }

    fn read_output(path: &PathBuf) -> String {
        fs::read_to_string(path).expect("read output file")
    }

    async fn seed_manual_approval_request(
        daemon: Arc<dyn KeyManagerDaemonApi>,
    ) -> (Uuid, AdminSession) {
        let lease = daemon
            .issue_lease("vault-password")
            .await
            .expect("issue lease");
        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };
        daemon
            .add_policy(
                &session,
                SpendingPolicy::new_manual_approval(
                    0,
                    1,
                    100,
                    EntityScope::All,
                    EntityScope::All,
                    EntityScope::All,
                )
                .expect("manual approval policy"),
            )
            .await
            .expect("add policy");
        let vault_key = daemon
            .create_vault_key(&session, KeyCreateRequest::Generate)
            .await
            .expect("vault key");
        let agent_credentials = daemon
            .create_agent_key(&session, vault_key.id, PolicyAttachment::AllPolicies)
            .await
            .expect("agent");
        let request = build_sign_request(
            &agent_credentials.agent_key.id.to_string(),
            &agent_credentials.auth_token,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 42,
            },
        );
        let approval_request_id = match daemon.sign_for_agent(request).await {
            Err(DaemonError::ManualApprovalRequired {
                approval_request_id,
                ..
            }) => approval_request_id,
            other => panic!("expected manual approval request, got {other:?}"),
        };
        (approval_request_id, session)
    }

    #[tokio::test]
    async fn execute_bootstrap_creates_destination_override_policy_sets() {
        let daemon = test_daemon();
        let mut params = test_bootstrap_params(true);
        params
            .destination_overrides
            .push(DestinationPolicyOverride {
                recipient: "0x1000000000000000000000000000000000000001"
                    .parse()
                    .expect("recipient"),
                per_tx_max_wei: 100,
                daily_max_wei: 200,
                weekly_max_wei: 300,
                max_gas_per_chain_wei: 400,
                daily_max_tx_count: 2,
                per_tx_max_fee_per_gas_wei: 3,
                per_tx_max_priority_fee_per_gas_wei: 4,
                per_tx_max_calldata_bytes: 5,
            });

        let output = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert_eq!(output.destination_override_count, 1);
        assert_eq!(output.destination_overrides.len(), 1);
        let override_output = &output.destination_overrides[0];
        assert_eq!(
            override_output.recipient,
            "0x1000000000000000000000000000000000000001"
        );
        assert_eq!(override_output.per_tx_max_wei, "100");
        assert_eq!(override_output.daily_max_tx_count.as_deref(), Some("2"));
        assert!(output.policy_note.contains("stricter overlays"));
    }

    #[tokio::test]
    async fn execute_bootstrap_supports_per_token_policy_bundles() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_per_token_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert_eq!(output.token_policies.len(), 2);
        assert!(output.per_tx_policy_id.is_none());
        assert_eq!(output.policy_attachment, "policy_set");
        assert!(!output.attached_policy_ids.is_empty());
        assert!(output
            .attached_policy_ids
            .contains(&output.token_policies[0].per_tx_policy_id));

        let native_err = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::TransferNative {
                    chain_id: 1,
                    to: "0x2000000000000000000000000000000000000001"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 150,
                },
            ))
            .await
            .expect_err("native transfer must exceed ETH per-tx policy");
        assert!(matches!(native_err, DaemonError::Policy(_)));

        let erc20_signature = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: "0x1000000000000000000000000000000000000000"
                        .parse()
                        .expect("token"),
                    to: "0x2000000000000000000000000000000000000002"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 200,
                },
            ))
            .await
            .expect("erc20 transfer should use the USD1 token policy");
        assert!(!erc20_signature.bytes.is_empty());
    }

    #[tokio::test]
    async fn execute_bootstrap_supports_unrestricted_shared_config_inventory() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let mut params = test_per_token_bootstrap_params(true);
        params.token_policies.clear();

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert_eq!(output.policy_attachment, "all_policies");
        assert!(output.attached_policy_ids.is_empty());
        assert!(output.policy_note.contains("remains unrestricted"));

        daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::TransferNative {
                    chain_id: 1,
                    to: "0x2000000000000000000000000000000000000001"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 150,
                },
            ))
            .await
            .expect("unrestricted shared-config agent should sign without policy failures");
    }

    #[tokio::test]
    async fn execute_bootstrap_keeps_selector_active_after_manual_approval_is_removed() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let lease = daemon.issue_lease("vault-password").await.expect("lease");
        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };
        daemon
            .add_policy(
                &session,
                SpendingPolicy::new(
                    1,
                    PolicyType::PerTxMaxSpending,
                    100,
                    EntityScope::All,
                    EntityScope::Set(std::collections::BTreeSet::from([AssetId::Erc20(
                        "0x9000000000000000000000000000000000000000"
                            .parse()
                            .expect("other token"),
                    )])),
                    EntityScope::Set(std::collections::BTreeSet::from([56])),
                )
                .expect("other token policy"),
            )
            .await
            .expect("seed unrelated policy");

        let mut initial = test_per_token_bootstrap_params(true);
        initial.token_policies.clear();
        initial
            .token_manual_approval_policies
            .push(TokenManualApprovalPolicyConfig {
                token_key: "usd1".to_string(),
                symbol: "USD1".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: false,
                address: Some(TokenAddress::Evm(
                    "0x1000000000000000000000000000000000000000"
                        .parse()
                        .expect("usd1 address"),
                )),
                priority: 100,
                recipient: None,
                min_amount_wei: 10,
                max_amount_wei: 20,
            });

        let bootstrap = execute_bootstrap(
            daemon_api.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            initial,
            |_| {},
        )
        .await
        .expect("bootstrap");
        let removed_manual_policy_id =
            Uuid::parse_str(&bootstrap.token_manual_approval_policies[0].policy_id)
                .expect("manual policy id");
        daemon
            .disable_policy(&session, removed_manual_policy_id)
            .await
            .expect("disable removed manual approval");

        let mut refreshed_params = test_per_token_bootstrap_params(true);
        refreshed_params.token_policies.clear();
        refreshed_params.existing_agent_key_id =
            Some(Uuid::parse_str(&bootstrap.agent_key_id).expect("agent key uuid"));
        refreshed_params.existing_vault_key_id =
            Some(Uuid::parse_str(&bootstrap.vault_key_id).expect("vault key uuid"));
        refreshed_params.existing_vault_public_key = Some(bootstrap.vault_public_key.clone());

        let refreshed = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            refreshed_params,
            |_| {},
        )
        .await
        .expect("refresh bootstrap");

        assert_eq!(refreshed.agent_key_id, bootstrap.agent_key_id);
        assert_eq!(refreshed.policy_attachment, "policy_set");
        assert!(!refreshed.attached_policy_ids.is_empty());
        assert!(refreshed
            .policy_note
            .contains("scoped unrestricted base policies were created"));

        let signature = daemon
            .sign_for_agent(build_sign_request(
                &refreshed.agent_key_id,
                &refreshed.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: "0x1000000000000000000000000000000000000000"
                        .parse()
                        .expect("usd1 address"),
                    to: "0x2000000000000000000000000000000000000002"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 5,
                },
            ))
            .await
            .expect("selector should remain active after manual approval removal");
        assert!(!signature.bytes.is_empty());
    }

    #[tokio::test]
    async fn shared_config_refresh_keeps_usd1_bsc_active_after_manual_approval_is_removed() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();

        let mut config_with_manual_approval = WlfiConfig::default();
        config_with_manual_approval
            .tokens
            .get_mut("usd1")
            .expect("usd1 token")
            .manual_approval_policies
            .push(TokenManualApprovalProfile {
                priority: 100,
                recipient: None,
                min_amount: None,
                max_amount: None,
                min_amount_decimal: Some("0.0001".to_string()),
                max_amount_decimal: Some("0.2".to_string()),
                min_amount_wei: None,
                max_amount_wei: None,
                extra: Default::default(),
            });

        let initial = tui::build_bootstrap_params_from_shared_config(
            &config_with_manual_approval,
            true,
            false,
        )
        .expect("shared-config params");
        let bootstrap = execute_bootstrap(
            daemon_api.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            initial,
            |_| {},
        )
        .await
        .expect("bootstrap with manual approval");
        assert!(!bootstrap.token_manual_approval_policies.is_empty());

        let mut refreshed_params =
            tui::build_bootstrap_params_from_shared_config(&WlfiConfig::default(), true, false)
                .expect("shared-config params without manual approval");
        refreshed_params.existing_vault_key_id =
            Some(Uuid::parse_str(&bootstrap.vault_key_id).expect("vault key uuid"));
        refreshed_params.existing_vault_public_key = Some(bootstrap.vault_public_key.clone());

        let refreshed = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            refreshed_params,
            |_| {},
        )
        .await
        .expect("refresh bootstrap");

        let signature = daemon
            .sign_for_agent(build_sign_request(
                &refreshed.agent_key_id,
                &refreshed.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 56,
                    token: "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d"
                        .parse()
                        .expect("usd1 address"),
                    to: "0x2000000000000000000000000000000000000002"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 5,
                },
            ))
            .await
            .expect("usd1:bsc should remain active after manual approval removal");
        assert!(!signature.bytes.is_empty());
    }

    #[tokio::test]
    async fn shared_config_bootstrap_accepts_native_sol_manual_approval() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();

        let mut config_with_sol_manual = WlfiConfig::default();
        config_with_sol_manual
            .tokens
            .get_mut("sol")
            .expect("sol token")
            .manual_approval_policies
            .push(TokenManualApprovalProfile {
                priority: 100,
                recipient: None,
                min_amount: None,
                max_amount: None,
                min_amount_decimal: Some("0.00002".to_string()),
                max_amount_decimal: Some("0.00003".to_string()),
                min_amount_wei: None,
                max_amount_wei: None,
                extra: Default::default(),
            });

        let params =
            tui::build_bootstrap_params_from_shared_config(&config_with_sol_manual, true, false)
                .expect("shared-config params");
        assert!(params
            .token_manual_approval_policies
            .iter()
            .any(|policy| policy.token_key == "sol" && policy.is_native));

        let bootstrap = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap with native sol manual approval");

        let sol_manual_policies = bootstrap
            .token_manual_approval_policies
            .iter()
            .filter(|policy| policy.token_key == "sol")
            .collect::<Vec<_>>();
        assert!(!sol_manual_policies.is_empty());
        assert!(sol_manual_policies
            .iter()
            .all(|policy| policy.asset_scope == "native_sol"));
    }

    #[tokio::test]
    async fn shared_config_reuse_existing_wallet_refreshes_agent_key_after_manual_policy_is_removed(
    ) {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let initial = execute_bootstrap(
            daemon_api.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            build_shared_config_bootstrap_params(
                &WlfiConfig::default(),
                true,
                None,
                Vec::new(),
                false,
                None,
                None,
                None,
            )
            .expect("initial shared-config params"),
            |_| {},
        )
        .await
        .expect("initial bootstrap");

        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease: daemon
                .issue_lease("vault-password")
                .await
                .expect("issue lease"),
        };
        let recipient = "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("recipient");
        let usd1_bsc: EvmAddress = "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d"
            .parse()
            .expect("usd1 bsc");
        let manual_policy = SpendingPolicy::new_manual_approval(
            100,
            10,
            20,
            EntityScope::All,
            single_scope(AssetId::Erc20(usd1_bsc.clone())),
            single_scope(56),
        )
        .expect("manual policy");
        daemon
            .add_policy(&session, manual_policy)
            .await
            .expect("add manual policy");

        let mut refreshed_config = WlfiConfig::default();
        refreshed_config.agent_key_id = Some(initial.agent_key_id.clone());
        refreshed_config.wallet = Some(WalletProfile {
            vault_key_id: Some(initial.vault_key_id.clone()),
            vault_public_key: initial.vault_public_key.clone(),
            address: Some("0x733a79fbd299111906835396f6a8b177f187b5ff".to_string()),
            agent_key_id: Some(initial.agent_key_id.clone()),
            policy_attachment: initial.policy_attachment.clone(),
            attached_policy_ids: initial.attached_policy_ids.clone(),
            policy_note: Some(initial.policy_note.clone()),
            network_scope: None,
            asset_scope: None,
            recipient_scope: None,
            extra: Default::default(),
        });

        let refreshed = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            build_shared_config_bootstrap_params(
                &refreshed_config,
                true,
                None,
                Vec::new(),
                false,
                Some(Uuid::parse_str(&initial.vault_key_id).expect("vault key uuid")),
                Some(initial.vault_public_key.clone()),
                None,
            )
            .expect("refreshed shared-config params"),
            |_| {},
        )
        .await
        .expect("refresh bootstrap");

        assert_eq!(refreshed.agent_key_id, initial.agent_key_id);
        assert!(refreshed
            .policy_note
            .contains("refreshed the existing agent key attachment"));

        let signature = daemon
            .sign_for_agent(build_sign_request(
                &refreshed.agent_key_id,
                &refreshed.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 56,
                    token: usd1_bsc,
                    to: recipient,
                    amount_wei: 100,
                },
            ))
            .await
            .expect("usd1 bsc transfer should remain allowed after refresh");
        assert!(!signature.bytes.is_empty());
    }

    #[tokio::test]
    async fn shared_config_refresh_keeps_usd1_bsc_active_with_native_limit_inventory() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();

        let mut config_with_native_limits = WlfiConfig::default();
        config_with_native_limits.tokens.insert(
            "bnb".to_string(),
            TokenProfile {
                name: Some("BNB".to_string()),
                symbol: "BNB".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([(
                    "bsc".to_string(),
                    TokenChainProfile {
                        chain_id: 56,
                        is_native: true,
                        address: None,
                        decimals: 18,
                        default_policy: Some(TokenPolicyProfile {
                            per_tx_amount_decimal: Some("0.01".to_string()),
                            daily_amount_decimal: Some("0.2".to_string()),
                            weekly_amount_decimal: Some("1.4".to_string()),
                            ..Default::default()
                        }),
                        extra: Default::default(),
                    },
                )]),
                extra: Default::default(),
            },
        );
        config_with_native_limits.tokens.insert(
            "eth".to_string(),
            TokenProfile {
                name: Some("ETH".to_string()),
                symbol: "ETH".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([(
                    "eth".to_string(),
                    TokenChainProfile {
                        chain_id: 1,
                        is_native: true,
                        address: None,
                        decimals: 18,
                        default_policy: Some(TokenPolicyProfile {
                            per_tx_amount_decimal: Some("100".to_string()),
                            daily_amount_decimal: Some("1000".to_string()),
                            weekly_amount_decimal: Some("10000".to_string()),
                            ..Default::default()
                        }),
                        extra: Default::default(),
                    },
                )]),
                extra: Default::default(),
            },
        );
        config_with_native_limits
            .tokens
            .get_mut("usd1")
            .expect("usd1 token")
            .manual_approval_policies
            .push(TokenManualApprovalProfile {
                priority: 100,
                recipient: None,
                min_amount: None,
                max_amount: None,
                min_amount_decimal: Some("0.0001".to_string()),
                max_amount_decimal: Some("0.2".to_string()),
                min_amount_wei: None,
                max_amount_wei: None,
                extra: Default::default(),
            });

        let initial =
            tui::build_bootstrap_params_from_shared_config(&config_with_native_limits, true, false)
                .expect("shared-config params");
        let bootstrap = execute_bootstrap(
            daemon_api.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            initial,
            |_| {},
        )
        .await
        .expect("bootstrap with native limits and manual approval");

        config_with_native_limits
            .tokens
            .get_mut("usd1")
            .expect("usd1 token")
            .manual_approval_policies
            .clear();
        let mut refreshed_params =
            tui::build_bootstrap_params_from_shared_config(&config_with_native_limits, true, false)
                .expect("shared-config params without manual approval");
        refreshed_params.existing_vault_key_id =
            Some(Uuid::parse_str(&bootstrap.vault_key_id).expect("vault key uuid"));
        refreshed_params.existing_vault_public_key = Some(bootstrap.vault_public_key.clone());

        let refreshed = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            refreshed_params,
            |_| {},
        )
        .await
        .expect("refresh bootstrap");

        let signature = daemon
            .sign_for_agent(build_sign_request(
                &refreshed.agent_key_id,
                &refreshed.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 56,
                    token: "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d"
                        .parse()
                        .expect("usd1 address"),
                    to: "0x2000000000000000000000000000000000000002"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 5,
                },
            ))
            .await
            .expect("usd1:bsc should remain active with native limits inventory");
        assert!(!signature.bytes.is_empty());
    }

    #[test]
    fn validate_per_token_bootstrap_allows_manual_approvals_without_default_policies() {
        let mut params = test_per_token_bootstrap_params(false);
        params.token_policies.clear();
        params
            .token_manual_approval_policies
            .push(TokenManualApprovalPolicyConfig {
                token_key: "usd1".to_string(),
                symbol: "USD1".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: false,
                address: Some(TokenAddress::Evm(
                    "0x1000000000000000000000000000000000000000"
                        .parse()
                        .expect("usd1 address"),
                )),
                priority: 100,
                recipient: None,
                min_amount_wei: 10,
                max_amount_wei: 20,
            });

        super::validate_per_token_bootstrap_params(&params)
            .expect("manual approvals without default limits");
    }

    #[tokio::test]
    async fn execute_bootstrap_manual_approval_spend_counts_toward_later_auto_limits() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let mut params = test_per_token_bootstrap_params(true);
        let usd1_address: EvmAddress = "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("usd1 address");
        let recipient: EvmAddress = "0x2000000000000000000000000000000000000002"
            .parse()
            .expect("recipient");

        let usd1_policy = params
            .token_policies
            .iter_mut()
            .find(|policy| policy.token_key == "usd1" && policy.chain_key == "ethereum")
            .expect("usd1 token policy");
        usd1_policy.per_tx_max_wei = 100;
        usd1_policy.daily_max_wei = 100;
        usd1_policy.weekly_max_wei = 100;

        params
            .token_manual_approval_policies
            .push(TokenManualApprovalPolicyConfig {
                token_key: "usd1".to_string(),
                symbol: "USD1".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: false,
                address: Some(TokenAddress::Evm(usd1_address.clone())),
                priority: 100,
                recipient: None,
                min_amount_wei: 20,
                max_amount_wei: 1_000,
            });

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        let lease = daemon.issue_lease("vault-password").await.expect("lease");
        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };

        for amount in [10_u128, 5, 5] {
            daemon
                .sign_for_agent(build_sign_request(
                    &output.agent_key_id,
                    &output.agent_auth_token,
                    AgentAction::Transfer {
                        chain_id: 1,
                        token: usd1_address.clone(),
                        to: recipient.clone(),
                        amount_wei: amount,
                    },
                ))
                .await
                .expect("auto-approved spend should sign");
        }

        for amount in [30_u128, 40] {
            let request = build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: usd1_address.clone(),
                    to: recipient.clone(),
                    amount_wei: amount,
                },
            );
            let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
                Err(DaemonError::ManualApprovalRequired {
                    approval_request_id,
                    ..
                }) => approval_request_id,
                other => panic!("expected manual approval request, got {other:?}"),
            };

            daemon
                .decide_manual_approval_request(
                    &session,
                    approval_request_id,
                    ManualApprovalDecision::Approve,
                    None,
                )
                .await
                .expect("approve request");

            daemon
                .sign_for_agent(request)
                .await
                .expect("approved request should sign");
        }

        let err = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: usd1_address,
                    to: recipient,
                    amount_wei: 15,
                },
            ))
            .await
            .expect_err("later auto-approved spend should be denied after manual usage reaches 90");
        let DaemonError::Policy(policy_err) = err else {
            panic!("expected policy rejection, got {err:?}");
        };
        let rendered = policy_err.to_string();
        assert!(rendered.contains("window usage 90 + requested 15 > max 100"));
    }

    #[tokio::test]
    async fn execute_bootstrap_reuses_existing_wallet_when_requested() {
        let daemon = test_daemon();
        let (vault_key_id, vault_public_key) = create_existing_vault_key(daemon.clone()).await;
        let mut params = test_per_token_bootstrap_params(true);
        params.existing_vault_key_id = Some(vault_key_id);
        params.existing_vault_public_key = Some(vault_public_key.clone());

        let output = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert_eq!(output.vault_key_id, vault_key_id.to_string());
        assert_eq!(output.vault_public_key, vault_public_key);
        assert!(output
            .policy_note
            .contains("reused the existing wallet address"));
    }

    #[tokio::test]
    async fn execute_bootstrap_reuses_existing_agent_key_and_preserves_spend_history() {
        let daemon = test_daemon();
        let usd1_address: EvmAddress = "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("usd1 address");
        let recipient: EvmAddress = "0x2000000000000000000000000000000000000002"
            .parse()
            .expect("recipient");

        let mut initial_params = test_per_token_bootstrap_params(true);
        let initial_usd1_policy = initial_params
            .token_policies
            .iter_mut()
            .find(|policy| policy.token_key == "usd1" && policy.chain_key == "ethereum")
            .expect("usd1 policy");
        initial_usd1_policy.per_tx_max_wei = 100;
        initial_usd1_policy.daily_max_wei = 100;
        initial_usd1_policy.weekly_max_wei = 100;

        let first = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            initial_params,
            |_| {},
        )
        .await
        .expect("initial bootstrap");

        daemon
            .sign_for_agent(build_sign_request(
                &first.agent_key_id,
                &first.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: usd1_address.clone(),
                    to: recipient.clone(),
                    amount_wei: 100,
                },
            ))
            .await
            .expect("initial spend should consume the full daily limit");

        let mut updated_params = test_per_token_bootstrap_params(true);
        let updated_usd1_policy = updated_params
            .token_policies
            .iter_mut()
            .find(|policy| policy.token_key == "usd1" && policy.chain_key == "ethereum")
            .expect("usd1 policy");
        updated_usd1_policy.per_tx_max_wei = 50;
        updated_usd1_policy.daily_max_wei = 102;
        updated_usd1_policy.weekly_max_wei = 102;
        updated_params.existing_agent_key_id =
            Some(Uuid::parse_str(&first.agent_key_id).expect("agent key uuid"));
        updated_params.existing_vault_key_id =
            Some(Uuid::parse_str(&first.vault_key_id).expect("vault key uuid"));
        updated_params.existing_vault_public_key = Some(first.vault_public_key.clone());

        let refreshed = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            updated_params,
            |_| {},
        )
        .await
        .expect("refresh bootstrap");

        assert_eq!(refreshed.agent_key_id, first.agent_key_id);
        assert_ne!(refreshed.agent_auth_token, first.agent_auth_token);
        assert!(refreshed
            .policy_note
            .contains("refreshed the existing agent key attachment"));

        let err = daemon
            .sign_for_agent(build_sign_request(
                &refreshed.agent_key_id,
                &refreshed.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: usd1_address,
                    to: recipient,
                    amount_wei: 3,
                },
            ))
            .await
            .expect_err("refreshed bootstrap must preserve prior spend usage");
        let DaemonError::Policy(policy_err) = err else {
            panic!("expected policy rejection, got {err:?}");
        };
        let rendered = policy_err.to_string();
        assert!(rendered.contains("window usage 100 + requested 3 > max 102"));
    }

    #[tokio::test]
    async fn execute_bootstrap_manual_approval_spend_counts_toward_later_daily_tx_count_limits() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let mut params = test_per_token_bootstrap_params(true);
        let usd1_address: EvmAddress = "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("usd1 address");
        let recipient: EvmAddress = "0x2000000000000000000000000000000000000002"
            .parse()
            .expect("recipient");

        let usd1_policy = params
            .token_policies
            .iter_mut()
            .find(|policy| policy.token_key == "usd1" && policy.chain_key == "ethereum")
            .expect("usd1 token policy");
        usd1_policy.per_tx_max_wei = 1_000;
        usd1_policy.daily_max_wei = 1_000;
        usd1_policy.weekly_max_wei = 1_000;
        usd1_policy.daily_max_tx_count = 5;

        params
            .token_manual_approval_policies
            .push(TokenManualApprovalPolicyConfig {
                token_key: "usd1".to_string(),
                symbol: "USD1".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: false,
                address: Some(TokenAddress::Evm(usd1_address.clone())),
                priority: 100,
                recipient: None,
                min_amount_wei: 20,
                max_amount_wei: 1_000,
            });

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        let lease = daemon.issue_lease("vault-password").await.expect("lease");
        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };

        for amount in [10_u128, 5, 5] {
            daemon
                .sign_for_agent(build_sign_request(
                    &output.agent_key_id,
                    &output.agent_auth_token,
                    AgentAction::Transfer {
                        chain_id: 1,
                        token: usd1_address.clone(),
                        to: recipient.clone(),
                        amount_wei: amount,
                    },
                ))
                .await
                .expect("auto-approved spend should sign");
        }

        for amount in [30_u128, 40] {
            let request = build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: usd1_address.clone(),
                    to: recipient.clone(),
                    amount_wei: amount,
                },
            );
            let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
                Err(DaemonError::ManualApprovalRequired {
                    approval_request_id,
                    ..
                }) => approval_request_id,
                other => panic!("expected manual approval request, got {other:?}"),
            };

            daemon
                .decide_manual_approval_request(
                    &session,
                    approval_request_id,
                    ManualApprovalDecision::Approve,
                    None,
                )
                .await
                .expect("approve request");

            daemon
                .sign_for_agent(request)
                .await
                .expect("approved request should sign");
        }

        let err = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: usd1_address,
                    to: recipient,
                    amount_wei: 1,
                },
            ))
            .await
            .expect_err("later auto-approved spend should be denied after manual usage reaches the daily tx-count limit");
        let DaemonError::Policy(policy_err) = err else {
            panic!("expected policy rejection, got {err:?}");
        };
        let rendered = policy_err.to_string();
        assert!(rendered.contains("tx_count usage 5 + 1 > max 5"));
    }

    #[tokio::test]
    async fn execute_bootstrap_allows_per_token_unlimited_gas_defaults() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let mut params = test_per_token_bootstrap_params(true);
        for token_policy in &mut params.token_policies {
            token_policy.max_gas_per_chain_wei = 0;
        }

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert!(output
            .token_policies
            .iter()
            .all(|token_policy| token_policy.gas_policy_id.is_none()));
        assert!(output
            .token_policies
            .iter()
            .all(|token_policy| token_policy.max_gas_per_chain_wei.is_none()));
    }

    #[tokio::test]
    async fn execute_bootstrap_applies_per_token_destination_overrides() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let mut params = test_per_token_bootstrap_params(true);
        params
            .token_destination_overrides
            .push(TokenDestinationPolicyOverride {
                token_key: "eth".to_string(),
                chain_key: "ethereum".to_string(),
                recipient: "0x3000000000000000000000000000000000000003"
                    .parse()
                    .expect("recipient"),
                per_tx_max_wei: 50,
                daily_max_wei: 250,
                weekly_max_wei: 500,
                max_gas_per_chain_wei: 1_000_000,
                daily_max_tx_count: 0,
                per_tx_max_fee_per_gas_wei: 0,
                per_tx_max_priority_fee_per_gas_wei: 0,
                per_tx_max_calldata_bytes: 0,
            });

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert_eq!(output.token_destination_overrides.len(), 1);

        let strict_err = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::TransferNative {
                    chain_id: 1,
                    to: "0x3000000000000000000000000000000000000003"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 75,
                },
            ))
            .await
            .expect_err("override recipient should be constrained by stricter ETH limit");
        assert!(matches!(strict_err, DaemonError::Policy(_)));

        let allowed_elsewhere = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                AgentAction::TransferNative {
                    chain_id: 1,
                    to: "0x3000000000000000000000000000000000000004"
                        .parse()
                        .expect("recipient"),
                    amount_wei: 75,
                },
            ))
            .await
            .expect("non-overridden recipient should keep the default ETH limit");
        assert!(!allowed_elsewhere.bytes.is_empty());
    }

    #[tokio::test]
    async fn execute_bootstrap_destination_override_applies_stricter_limit() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                Default::default(),
            )
            .expect("daemon"),
        );
        let daemon_api: Arc<dyn KeyManagerDaemonApi> = daemon.clone();
        let mut params = test_bootstrap_params(true);
        params.per_tx_max_wei = 1_000;
        params.daily_max_wei = 5_000;
        params.weekly_max_wei = 20_000;
        params
            .destination_overrides
            .push(DestinationPolicyOverride {
                recipient: "0x2000000000000000000000000000000000000002"
                    .parse()
                    .expect("recipient"),
                per_tx_max_wei: 100,
                daily_max_wei: 500,
                weekly_max_wei: 1_000,
                max_gas_per_chain_wei: params.max_gas_per_chain_wei,
                daily_max_tx_count: 0,
                per_tx_max_fee_per_gas_wei: 0,
                per_tx_max_priority_fee_per_gas_wei: 0,
                per_tx_max_calldata_bytes: 0,
            });

        let output = execute_bootstrap(
            daemon_api,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        let strict_action = AgentAction::TransferNative {
            chain_id: 1,
            to: "0x2000000000000000000000000000000000000002"
                .parse()
                .expect("recipient"),
            amount_wei: 150,
        };
        let err = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                strict_action,
            ))
            .await
            .expect_err("override recipient should be constrained by stricter limit");
        assert!(matches!(err, DaemonError::Policy(_)));

        let allowed_elsewhere = AgentAction::TransferNative {
            chain_id: 1,
            to: "0x2000000000000000000000000000000000000003"
                .parse()
                .expect("recipient"),
            amount_wei: 150,
        };
        let signature = daemon
            .sign_for_agent(build_sign_request(
                &output.agent_key_id,
                &output.agent_auth_token,
                allowed_elsewhere,
            ))
            .await
            .expect("non-overridden recipient should use default limit");
        assert!(!signature.bytes.is_empty());
    }

    #[tokio::test]
    async fn execute_bootstrap_rejects_destination_override_that_relaxes_default() {
        let daemon = test_daemon();
        let mut params = test_bootstrap_params(true);
        params
            .destination_overrides
            .push(DestinationPolicyOverride {
                recipient: "0x1000000000000000000000000000000000000001"
                    .parse()
                    .expect("recipient"),
                per_tx_max_wei: params.per_tx_max_wei + 1,
                daily_max_wei: params.daily_max_wei,
                weekly_max_wei: params.weekly_max_wei,
                max_gas_per_chain_wei: params.max_gas_per_chain_wei,
                daily_max_tx_count: params.daily_max_tx_count,
                per_tx_max_fee_per_gas_wei: params.per_tx_max_fee_per_gas_wei,
                per_tx_max_priority_fee_per_gas_wei: params.per_tx_max_priority_fee_per_gas_wei,
                per_tx_max_calldata_bytes: params.per_tx_max_calldata_bytes,
            });

        let err = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect_err("override must be rejected");
        assert!(err
            .to_string()
            .contains("must not increase per-tx max above the default value"));
    }

    #[tokio::test]
    async fn execute_bootstrap_emits_rfc3339_lease_expiry() {
        let daemon = test_daemon();
        let output = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert!(time::OffsetDateTime::parse(
            &output.lease_expires_at,
            &time::format_description::well_known::Rfc3339
        )
        .is_ok());
        assert!(output.lease_expires_at.contains('T'));
    }

    #[tokio::test]
    async fn execute_bootstrap_does_not_export_private_key_when_printing_agent_token() {
        let daemon = test_daemon();
        let output = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert!(output.vault_private_key.is_none());
    }

    #[tokio::test]
    async fn execute_bootstrap_exports_software_private_key_only_when_requested() {
        let daemon = test_daemon();
        let mut params = test_bootstrap_params(true);
        params.print_vault_private_key = true;
        let output = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        let private_key = output
            .vault_private_key
            .as_ref()
            .expect("software backend should export private key when requested");
        assert_eq!(private_key.len(), 64);
        assert!(private_key.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn execute_bootstrap_can_restore_wallet_from_imported_private_key() {
        let daemon = test_daemon();
        let expected_private_key = "11".repeat(32);
        let mut params = test_bootstrap_params(true);
        params.import_vault_private_key = Some(expected_private_key.clone());
        let output = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect("bootstrap");

        let lease = daemon
            .issue_lease("vault-password")
            .await
            .expect("issue lease");
        let mut session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };
        let exported = daemon
            .export_vault_private_key(
                &session,
                Uuid::parse_str(&output.vault_key_id).expect("vault key uuid"),
            )
            .await
            .expect("export")
            .expect("software key");
        session.vault_password.zeroize();

        assert_eq!(exported, expected_private_key);
        assert!(output
            .policy_note
            .contains("restored the wallet from an imported private key"));
        assert!(output.vault_private_key.is_none());
    }

    #[tokio::test]
    async fn execute_export_vault_private_key_returns_existing_software_key_material() {
        let daemon = test_daemon();
        let bootstrap = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        let output = execute_export_vault_private_key(
            daemon,
            "vault-password",
            ExportVaultPrivateKeyParams {
                vault_key_id: Uuid::parse_str(&bootstrap.vault_key_id).expect("vault key uuid"),
            },
            |_| {},
        )
        .await
        .expect("export");

        assert_eq!(output.vault_key_id, bootstrap.vault_key_id);
        assert_eq!(output.vault_private_key.len(), 64);
        assert!(output
            .vault_private_key
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn execute_rotate_agent_auth_token_redacts_by_default() {
        let daemon = test_daemon();
        let bootstrap = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        let output = execute_rotate_agent_auth_token(
            daemon,
            "vault-password",
            RotateAgentAuthTokenParams {
                agent_key_id: Uuid::parse_str(&bootstrap.agent_key_id).expect("agent key uuid"),
                print_agent_auth_token: false,
            },
            |_| {},
        )
        .await
        .expect("rotate output");

        assert_eq!(output.agent_key_id, bootstrap.agent_key_id);
        assert_eq!(output.agent_auth_token, "<redacted>");
        assert!(output.agent_auth_token_redacted);
    }

    #[tokio::test]
    async fn execute_rotate_agent_auth_token_can_print_new_secret() {
        let daemon = test_daemon();
        let bootstrap = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        let output = execute_rotate_agent_auth_token(
            daemon,
            "vault-password",
            RotateAgentAuthTokenParams {
                agent_key_id: Uuid::parse_str(&bootstrap.agent_key_id).expect("agent key uuid"),
                print_agent_auth_token: true,
            },
            |_| {},
        )
        .await
        .expect("rotate output");

        assert_eq!(output.agent_key_id, bootstrap.agent_key_id);
        assert!(!output.agent_auth_token_redacted);
        assert_ne!(output.agent_auth_token, bootstrap.agent_auth_token);
        assert!(!output.agent_auth_token.is_empty());
    }

    #[tokio::test]
    async fn execute_revoke_agent_key_revokes_existing_agent_credentials() {
        let daemon = test_daemon();
        let bootstrap = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        let output = execute_revoke_agent_key(
            daemon,
            "vault-password",
            RevokeAgentKeyParams {
                agent_key_id: Uuid::parse_str(&bootstrap.agent_key_id).expect("agent key uuid"),
            },
            |_| {},
        )
        .await
        .expect("revoke output");

        assert_eq!(output.agent_key_id, bootstrap.agent_key_id);
        assert!(output.revoked);
    }

    #[tokio::test]
    async fn execute_bootstrap_rejects_unknown_attachment_before_mutating_policies() {
        let daemon = test_daemon();
        let mut params = test_bootstrap_params(true);
        params.attach_policy_ids =
            vec![Uuid::parse_str("00000000-0000-0000-0000-000000000222").expect("uuid")];

        let err = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            params,
            |_| {},
        )
        .await
        .expect_err("bootstrap must fail for unknown attachment id");

        assert!(err
            .to_string()
            .contains("unknown --attach-policy-id value(s):"));

        let lease = daemon.issue_lease("vault-password").await.expect("lease");
        let mut session = vault_domain::AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };
        let policies = daemon.list_policies(&session).await.expect("list policies");
        session.vault_password.zeroize();

        assert!(
            policies.is_empty(),
            "bootstrap failure must not register policies"
        );
    }

    #[tokio::test]
    async fn execute_bootstrap_attaches_created_policies_by_default() {
        let output = execute_bootstrap(
            test_daemon(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("bootstrap");

        assert_eq!(output.policy_attachment, "policy_set");
        assert_eq!(output.attached_policy_ids.len(), 4);
        assert!(output
            .attached_policy_ids
            .contains(output.per_tx_policy_id.as_ref().expect("per-tx policy id")));
        assert!(output
            .attached_policy_ids
            .contains(output.daily_policy_id.as_ref().expect("daily policy id")));
        assert!(output
            .attached_policy_ids
            .contains(output.weekly_policy_id.as_ref().expect("weekly policy id")));
        assert!(output
            .attached_policy_ids
            .contains(output.gas_policy_id.as_ref().expect("gas policy id")));
        assert!(output
            .policy_note
            .contains("bootstrap-created policy id(s)"));
    }

    #[tokio::test]
    async fn execute_bootstrap_attach_bootstrap_policies_refreshes_existing_enabled_policies() {
        let daemon = test_daemon();
        let initial = execute_bootstrap(
            daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            test_bootstrap_params(true),
            |_| {},
        )
        .await
        .expect("initial bootstrap");

        let manual = execute_add_manual_approval_policy(
            daemon.clone(),
            "vault-password",
            AddManualApprovalPolicyParams {
                priority: 100,
                min_amount_wei: 10,
                max_amount_wei: 20,
                tokens: vec!["0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("usd1 token")],
                allow_native_eth: false,
                network: Some(1),
                recipient: None,
            },
            |_| {},
        )
        .await
        .expect("manual approval policy");

        let mut refresh = test_bootstrap_params(true);
        refresh.attach_bootstrap_policies = true;
        refresh.existing_agent_key_id =
            Some(Uuid::parse_str(&initial.agent_key_id).expect("agent key uuid"));
        refresh.existing_vault_key_id =
            Some(Uuid::parse_str(&initial.vault_key_id).expect("vault key uuid"));
        refresh.existing_vault_public_key = Some(initial.vault_public_key.clone());

        let refreshed = execute_bootstrap(
            daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            refresh,
            |_| {},
        )
        .await
        .expect("refreshed bootstrap");

        assert!(refreshed.attached_policy_ids.contains(&manual.policy_id));
        assert!(refreshed
            .policy_note
            .contains("existing enabled policy id(s)"));
    }

    #[tokio::test]
    async fn execute_list_policies_filters_requested_ids() {
        let daemon = test_daemon();
        let lease = daemon.issue_lease("vault-password").await.expect("lease");
        let session = AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        };
        let daily = SpendingPolicy::new(
            1,
            PolicyType::DailyMaxSpending,
            100,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("daily policy");
        let manual = SpendingPolicy::new_manual_approval(
            2,
            10,
            20,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("manual policy");
        daemon
            .add_policy(&session, daily)
            .await
            .expect("add daily policy");
        daemon
            .add_policy(&session, manual.clone())
            .await
            .expect("add manual policy");

        let filtered =
            execute_list_policies(daemon.clone(), "vault-password", &[manual.id], |_| {})
                .await
                .expect("filter policies");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, manual.id);

        let err = execute_list_policies(
            daemon,
            "vault-password",
            &[Uuid::parse_str("00000000-0000-0000-0000-000000000999").expect("uuid")],
            |_| {},
        )
        .await
        .expect_err("missing policy id must fail");
        assert!(err.to_string().contains("unknown --policy-id value(s):"));
    }

    #[test]
    fn manual_approval_and_legacy_relay_commands_are_accepted() {
        let list_policies_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "list-policies",
            "--policy-id",
            "00000000-0000-0000-0000-000000000125",
            "--policy-id",
            "00000000-0000-0000-0000-000000000126",
        ])
        .expect("parse list policies");
        let Commands::ListPolicies(args) = list_policies_cli.command else {
            panic!("expected list-policies");
        };
        assert_eq!(args.policy_id.len(), 2);

        let list_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "list-manual-approval-requests",
        ])
        .expect("parse list");
        assert!(matches!(
            list_cli.command,
            Commands::ListManualApprovalRequests
        ));

        let approve_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "approve-manual-approval-request",
            "--approval-request-id",
            "00000000-0000-0000-0000-000000000123",
        ])
        .expect("parse approve");
        let Commands::ApproveManualApprovalRequest(args) = approve_cli.command else {
            panic!("expected approve-manual-approval-request");
        };
        assert_eq!(
            args.approval_request_id,
            Uuid::parse_str("00000000-0000-0000-0000-000000000123").expect("uuid")
        );

        let reject_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "reject-manual-approval-request",
            "--approval-request-id",
            "00000000-0000-0000-0000-000000000124",
            "--rejection-reason",
            "too risky",
        ])
        .expect("parse reject");
        let Commands::RejectManualApprovalRequest(args) = reject_cli.command else {
            panic!("expected reject-manual-approval-request");
        };
        assert_eq!(args.rejection_reason.as_deref(), Some("too risky"));

        let add_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "add-manual-approval-policy",
            "--priority",
            "7",
            "--min-amount-wei",
            "10",
            "--max-amount-wei",
            "20",
            "--allow-native-eth",
            "--network",
            "1",
        ])
        .expect("parse add manual approval policy");
        let Commands::AddManualApprovalPolicy(args) = add_cli.command else {
            panic!("expected add-manual-approval-policy");
        };
        assert_eq!(args.priority, 7);
        assert!(args.allow_native_eth);

        let set_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "set-relay-config",
            "--relay-url",
            "https://relay.example",
            "--frontend-url",
            "https://frontend.example",
        ])
        .expect("parse set relay config");
        let Commands::SetRelayConfig(args) = set_cli.command else {
            panic!("expected set-relay-config");
        };
        assert_eq!(args.relay_url.as_deref(), Some("https://relay.example"));
        assert_eq!(
            args.frontend_url.as_deref(),
            Some("https://frontend.example")
        );

        let get_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "get-relay-config",
        ])
        .expect("parse get relay config");
        assert!(matches!(get_cli.command, Commands::GetRelayConfig));

        let add_eip712_cli = Cli::try_parse_from([
            "agentpay-admin",
            "--daemon-socket",
            "/tmp/agentpay.sock",
            "add-eip712-signing-policy",
            "--approval-type",
            "manual-approval",
        ])
        .expect("parse add eip712 policy");
        assert!(matches!(
            add_eip712_cli.command,
            Commands::AddEip712SigningPolicy(_)
        ));
    }

    #[test]
    fn render_policy_text_includes_manual_approval_range() {
        let policy = SpendingPolicy::new_manual_approval(
            7,
            10,
            20,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("manual policy");

        let rendered = render_policy_text(&policy);
        assert!(rendered.contains("Type: manual_approval"));
        assert!(rendered.contains("Min Amount (wei): 10"));
        assert!(rendered.contains("Max Amount (wei): 20"));
    }

    #[test]
    fn render_policy_text_includes_eip712_approval_type() {
        let policy = SpendingPolicy::new_eip712_signing(
            7,
            DomainApprovalType::ManualApproval,
            EntityScope::All,
        )
        .expect("eip712 policy");

        let rendered = render_policy_text(&policy);
        assert!(rendered.contains("Type: eip712_signing"));
        assert!(rendered.contains("Approval Type: manual_approval"));
    }

    #[tokio::test]
    async fn manual_approval_execute_helpers_roundtrip() {
        let daemon = test_daemon();
        let (approval_request_id, mut session) = seed_manual_approval_request(daemon.clone()).await;

        let mut list_statuses = Vec::new();
        let requests =
            execute_list_manual_approval_requests(daemon.clone(), "vault-password", |msg| {
                list_statuses.push(msg.to_string());
            })
            .await
            .expect("list requests");
        assert!(requests
            .iter()
            .any(|request| request.id == approval_request_id));
        assert_eq!(
            list_statuses,
            vec![
                "issuing admin lease".to_string(),
                "listing manual approval requests".to_string()
            ]
        );

        let mut approve_statuses = Vec::new();
        let approved = execute_decide_manual_approval_request(
            daemon.clone(),
            "vault-password",
            DecideManualApprovalRequestParams {
                approval_request_id,
                decision: ManualApprovalDecision::Approve,
                rejection_reason: None,
            },
            |msg| approve_statuses.push(msg.to_string()),
        )
        .await
        .expect("approve request");
        assert_eq!(approved.id, approval_request_id);
        assert_eq!(approved.status, ManualApprovalStatus::Approved);
        assert_eq!(
            approve_statuses,
            vec![
                "issuing admin lease".to_string(),
                "updating manual approval request".to_string()
            ]
        );

        session.vault_password.zeroize();
    }

    #[tokio::test]
    async fn validate_tui_vault_password_accepts_correct_password() {
        let daemon = test_daemon();
        let mut statuses = Vec::new();

        validate_tui_vault_password(daemon, "vault-password", |msg| {
            statuses.push(msg.to_string())
        })
        .await
        .expect("correct password should unlock tui");

        assert_eq!(statuses, vec!["issuing admin lease".to_string()]);
    }

    #[tokio::test]
    async fn validate_tui_vault_password_rejects_wrong_password() {
        let daemon = test_daemon();
        let mut statuses = Vec::new();

        let err = validate_tui_vault_password(daemon, "wrong-password", |msg| {
            statuses.push(msg.to_string())
        })
        .await
        .expect_err("wrong password must fail before entering tui");

        assert!(matches!(err, DaemonError::AuthenticationFailed));
        assert_eq!(statuses, vec!["issuing admin lease".to_string()]);
    }

    #[tokio::test]
    async fn relay_config_helpers_are_noops() {
        let daemon = test_daemon();
        let set_output = execute_set_relay_config(
            daemon.clone(),
            "vault-password",
            SetRelayConfigParams {
                relay_url: None,
                frontend_url: Some("https://frontend.example".to_string()),
                clear: false,
            },
            |_| {},
        )
        .await
        .expect("set relay config should be ignored");
        assert_eq!(set_output.frontend_url, None);
        assert!(!set_output.daemon_id_hex.trim().is_empty());
        assert!(!set_output.daemon_public_key_hex.trim().is_empty());

        let get_output = execute_get_relay_config(daemon, "vault-password", |_| {})
            .await
            .expect("get relay config should return the current daemon config");
        assert_eq!(get_output.frontend_url, None);
        assert!(!get_output.daemon_id_hex.trim().is_empty());
        assert!(!get_output.daemon_public_key_hex.trim().is_empty());
    }

    #[tokio::test]
    async fn output_renderers_cover_text_sections() {
        let global_daemon = test_daemon();
        let mut global_params = test_bootstrap_params(false);
        global_params.print_vault_private_key = true;
        global_params
            .destination_overrides
            .push(DestinationPolicyOverride {
                recipient: "0x3000000000000000000000000000000000000003"
                    .parse()
                    .expect("recipient"),
                per_tx_max_wei: 100,
                daily_max_wei: 200,
                weekly_max_wei: 300,
                max_gas_per_chain_wei: 400,
                daily_max_tx_count: 2,
                per_tx_max_fee_per_gas_wei: 3,
                per_tx_max_priority_fee_per_gas_wei: 4,
                per_tx_max_calldata_bytes: 5,
            });
        let global_output = execute_bootstrap(
            global_daemon.clone(),
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            global_params,
            |_| {},
        )
        .await
        .expect("global bootstrap");
        let global_path = unique_temp_path("bootstrap-global");
        let global_target = OutputTarget::File {
            path: global_path.clone(),
            overwrite: true,
        };
        print_bootstrap_output(&global_output, OutputFormat::Text, &global_target)
            .expect("render global bootstrap");
        let global_text = read_output(&global_path);
        assert!(global_text.contains("Policies"));
        assert!(global_text.contains("Vault Private Key:"));
        assert!(global_text.contains("Destination Overrides"));
        assert!(global_text.contains("Note: pass --print-agent-auth-token"));
        fs::remove_file(&global_path).expect("cleanup global output");

        let per_token_daemon = test_daemon();
        let mut per_token_params = test_per_token_bootstrap_params(true);
        per_token_params
            .token_destination_overrides
            .push(TokenDestinationPolicyOverride {
                token_key: "eth".to_string(),
                chain_key: "ethereum".to_string(),
                recipient: "0x3000000000000000000000000000000000000003"
                    .parse()
                    .expect("recipient"),
                per_tx_max_wei: 50,
                daily_max_wei: 250,
                weekly_max_wei: 500,
                max_gas_per_chain_wei: 1_000_000,
                daily_max_tx_count: 0,
                per_tx_max_fee_per_gas_wei: 0,
                per_tx_max_priority_fee_per_gas_wei: 0,
                per_tx_max_calldata_bytes: 0,
            });
        per_token_params.token_manual_approval_policies.push(
            super::TokenManualApprovalPolicyConfig {
                token_key: "eth".to_string(),
                symbol: "ETH".to_string(),
                chain_key: "ethereum".to_string(),
                chain_id: 1,
                is_native: true,
                address: None,
                priority: 9,
                recipient: Some(
                    "0x4000000000000000000000000000000000000004"
                        .parse()
                        .expect("recipient"),
                ),
                min_amount_wei: 10,
                max_amount_wei: 20,
            },
        );
        let per_token_output = execute_bootstrap(
            per_token_daemon,
            "vault-password",
            "daemon_socket:/tmp/agentpay.sock",
            per_token_params,
            |_| {},
        )
        .await
        .expect("per-token bootstrap");
        let per_token_path = unique_temp_path("bootstrap-per-token");
        let per_token_target = OutputTarget::File {
            path: per_token_path.clone(),
            overwrite: true,
        };
        print_bootstrap_output(&per_token_output, OutputFormat::Text, &per_token_target)
            .expect("render per-token bootstrap");
        let per_token_text = read_output(&per_token_path);
        assert!(per_token_text.contains("Per-Token Policies"));
        assert!(per_token_text.contains("Per-Token Destination Overrides"));
        assert!(per_token_text.contains("Per-Token Manual Approval Policies"));
        assert!(per_token_text.contains("Attached Policy IDs"));
        assert!(per_token_text.contains("Warning: keep the agent auth token"));
        fs::remove_file(&per_token_path).expect("cleanup per-token output");
    }

    #[tokio::test]
    async fn output_renderers_cover_manual_approval_and_relay_text() {
        let daemon = test_daemon();
        let (approval_request_id, mut session) = seed_manual_approval_request(daemon.clone()).await;
        let request = daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list manual approvals")
            .into_iter()
            .find(|item| item.id == approval_request_id)
            .expect("request");

        let requests_path = unique_temp_path("manual-requests");
        let requests_target = OutputTarget::File {
            path: requests_path.clone(),
            overwrite: true,
        };
        print_manual_approval_requests_output(&[], OutputFormat::Text, &requests_target)
            .expect("render empty requests");
        assert_eq!(
            read_output(&requests_path).trim_end(),
            "No manual approval requests"
        );

        print_manual_approval_request_output(&request, OutputFormat::Text, &requests_target)
            .expect("render single request");
        let single_text = read_output(&requests_path);
        assert!(single_text.contains("Request ID:"));
        assert!(single_text.contains("Triggered By Policies:"));

        print_manual_approval_requests_output(
            std::slice::from_ref(&request),
            OutputFormat::Text,
            &requests_target,
        )
        .expect("render request list");
        let list_text = read_output(&requests_path);
        assert!(list_text.contains("Status: Pending"));
        fs::remove_file(&requests_path).expect("cleanup manual approval output");

        let relay_output = RelayConfig {
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: None,
            daemon_id_hex: "daemon-id".to_string(),
            daemon_public_key_hex: "daemon-pub".to_string(),
        };
        let relay_path = unique_temp_path("relay-config");
        let relay_target = OutputTarget::File {
            path: relay_path.clone(),
            overwrite: true,
        };
        print_relay_config_output(&relay_output, OutputFormat::Text, &relay_target)
            .expect("render relay config");
        let relay_text = read_output(&relay_path);
        assert!(relay_text.contains("Relay URL: https://relay.example"));
        assert!(relay_text.contains("Frontend URL: <unset>"));
        fs::remove_file(&relay_path).expect("cleanup relay output");

        let rotate_path = unique_temp_path("rotate-output");
        let rotate_target = OutputTarget::File {
            path: rotate_path.clone(),
            overwrite: true,
        };
        print_rotate_agent_auth_token_output(
            &RotateAgentAuthTokenOutput {
                agent_key_id: "agent-key".to_string(),
                agent_auth_token: "<redacted>".to_string(),
                agent_auth_token_redacted: true,
            },
            OutputFormat::Text,
            &rotate_target,
        )
        .expect("render rotate output");
        assert!(read_output(&rotate_path).contains("Note: pass --print-agent-auth-token"));
        fs::remove_file(&rotate_path).expect("cleanup rotate output");

        let revoke_path = unique_temp_path("revoke-output");
        let revoke_target = OutputTarget::File {
            path: revoke_path.clone(),
            overwrite: true,
        };
        print_revoke_agent_key_output(
            &RevokeAgentKeyOutput {
                agent_key_id: "agent-key".to_string(),
                revoked: true,
            },
            OutputFormat::Text,
            &revoke_target,
        )
        .expect("render revoke output");
        assert!(read_output(&revoke_path).contains("Revoked: true"));
        fs::remove_file(&revoke_path).expect("cleanup revoke output");

        let policy_path = unique_temp_path("policy-output");
        let policy_target = OutputTarget::File {
            path: policy_path.clone(),
            overwrite: true,
        };
        print_manual_approval_policy_output(
            &ManualApprovalPolicyOutput {
                policy_id: "policy-id".to_string(),
                priority: 7,
                min_amount_wei: "10".to_string(),
                max_amount_wei: "20".to_string(),
                network_scope: "1".to_string(),
                asset_scope: "native_eth".to_string(),
                recipient_scope: "all recipients".to_string(),
            },
            OutputFormat::Text,
            &policy_target,
        )
        .expect("render manual approval policy");
        assert!(read_output(&policy_path).contains("Amount Range (wei): 10..=20"));
        fs::remove_file(&policy_path).expect("cleanup policy output");

        session.vault_password.zeroize();
    }

    #[test]
    fn helper_parsers_and_policy_attachment_resolution_cover_remaining_paths() {
        assert_eq!(parse_positive_u128("10").expect("parse"), 10);
        assert_eq!(parse_non_negative_u128("0").expect("parse"), 0);
        assert_eq!(parse_positive_u64("12").expect("parse"), 12);
        assert!(parse_positive_u128("0").is_err());
        assert!(parse_positive_u64("0").is_err());
        assert!(parse_non_negative_u128("nope").is_err());

        let created = Uuid::parse_str("00000000-0000-0000-0000-000000000101").expect("uuid");
        let explicit = Uuid::parse_str("00000000-0000-0000-0000-000000000202").expect("uuid");

        let created_only = resolve_bootstrap_policy_attachment([created], [], &[])
            .expect("created-only attachment");
        assert_eq!(created_only.1, "policy_set");
        assert_eq!(created_only.2.len(), 1);
        assert!(created_only.3.contains("bootstrap-created policy"));

        let explicit_only = resolve_bootstrap_policy_attachment([], [], &[explicit])
            .expect("explicit-only attachment");
        assert_eq!(explicit_only.2, vec![explicit.to_string()]);
        assert!(explicit_only.3.contains("explicit policy"));

        let mixed = resolve_bootstrap_policy_attachment([created], [], &[explicit])
            .expect("mixed attachment");
        assert_eq!(mixed.2.len(), 2);
        assert!(mixed
            .3
            .contains("bootstrap-created policy id(s) and 1 explicit policy id(s)"));

        let unrestricted =
            resolve_bootstrap_policy_attachment([], [], &[]).expect("unrestricted attachment");
        assert!(matches!(unrestricted.0, PolicyAttachment::AllPolicies));
        assert_eq!(unrestricted.1, "all_policies");
        assert!(unrestricted.2.is_empty());
        assert!(unrestricted.3.contains("all policies"));
    }

    #[test]
    #[cfg(unix)]
    fn resolve_daemon_socket_path_rejects_non_root_owned_socket() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("wa-{unique:x}"));
        std::fs::create_dir_all(&root).expect("create root directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("secure root directory permissions");

        let socket_path = root.join("daemon.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind socket");
        if unsafe { libc::geteuid() } == 0 {
            let rc = unsafe { libc::fchown(listener.as_raw_fd(), 1, libc::gid_t::MAX) };
            assert_eq!(
                rc,
                0,
                "must set non-root owner for root-mode test: {}",
                std::io::Error::last_os_error()
            );
        }

        let err = resolve_daemon_socket_path(Some(socket_path.clone())).expect_err("must reject");
        assert!(err.to_string().contains("must be owned by root"));

        drop(listener);
        std::fs::remove_file(&socket_path).expect("cleanup socket");
        std::fs::remove_dir_all(&root).expect("cleanup root directory");
    }
}
