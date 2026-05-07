use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Terminal;
use uuid::Uuid;
use vault_domain::EvmAddress;

use crate::shared_config::{
    ChainProfile, LoadedConfig, TokenChainProfile, TokenDestinationOverrideProfile,
    TokenManualApprovalProfile, TokenPolicyProfile, TokenProfile, WlfiConfig,
};
use crate::{
    BootstrapParams, TokenDestinationPolicyOverride, TokenManualApprovalPolicyConfig,
    TokenPolicyConfig, TokenSelectorConfig,
};

mod amounts;
mod token_rpc;
mod utils;

use amounts::{
    format_gwei_amount, format_token_amount, parse_legacy_amount, parse_optional_gwei_amount,
    parse_required_token_amount,
};
use token_rpc::fetch_token_metadata;
use utils::*;

fn fetch_token_metadata_sync(
    chain_key: String,
    rpc_url: String,
    expected_chain_id: u64,
    is_native: bool,
    address: Option<EvmAddress>,
) -> Result<token_rpc::FetchedTokenMetadata> {
    std::thread::spawn(move || -> Result<token_rpc::FetchedTokenMetadata> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for token metadata refresh")?;
        runtime.block_on(async move {
            fetch_token_metadata(
                &chain_key,
                &rpc_url,
                expected_chain_id,
                is_native,
                address.as_ref(),
            )
            .await
        })
    })
    .join()
    .map_err(|panic| {
        let payload = if let Some(message) = panic.downcast_ref::<&str>() {
            *message
        } else if let Some(message) = panic.downcast_ref::<String>() {
            message.as_str()
        } else {
            "unknown panic"
        };
        anyhow!("token metadata refresh thread panicked: {payload}")
    })?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Tokens,
    Networks,
    Bootstrap,
}

impl View {
    const ALL: [Self; 3] = [Self::Tokens, Self::Networks, Self::Bootstrap];

    fn title(self) -> &'static str {
        match self {
            Self::Tokens => "Tokens",
            Self::Networks => "Networks",
            Self::Bootstrap => "Bootstrap",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Tokens => {
                "Saved tokens are the source of truth. Each token owns its default limits, destination overrides, manual approvals, and network mappings."
            }
            Self::Networks => {
                "Saved networks provide the RPC endpoints and chain ids used for token metadata inference and policy expansion."
            }
            Self::Bootstrap => {
                "Review the saved token inventory and bootstrap all configured token policies in one run."
            }
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Tokens => Self::Networks,
            Self::Networks => Self::Bootstrap,
            Self::Bootstrap => Self::Tokens,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Tokens => Self::Bootstrap,
            Self::Networks => Self::Tokens,
            Self::Bootstrap => Self::Networks,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingDiscardAction {
    NextView,
    PreviousView,
    ReloadCurrentView,
    NewTokenDraft,
    NewNetworkDraft,
    CycleSavedToken(i8),
    CycleSavedNetwork(i8),
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingDeleteAction {
    DeleteDestinationOverride(usize),
    DeleteManualApproval(usize),
    DeleteToken(String),
    DeleteNetwork(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageLevel {
    Info,
    Success,
    Error,
}

impl MessageLevel {
    fn style(self) -> Style {
        match self {
            Self::Info => Style::default().fg(Color::Cyan),
            Self::Success => Style::default().fg(Color::Green),
            Self::Error => Style::default().fg(Color::Red),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    SelectedToken,
    TokenKey,
    TokenName,
    TokenSymbol,
    NetworkMembership,
    EditingNetwork,
    NetworkIsNative,
    NetworkAddress,
    RefreshTokenMetadata,
    TokenDecimals,
    PerTxLimit,
    DailyLimit,
    WeeklyLimit,
    ShowAdvanced,
    MaxGasPerChainWei,
    DailyMaxTxCount,
    PerTxMaxFeePerGasGwei,
    PerTxMaxPriorityFeePerGasWei,
    PerTxMaxCalldataBytes,
    DestinationOverrides,
    SelectedDestinationOverride,
    OverrideRecipientAddress,
    OverridePerTxLimit,
    OverrideDailyLimit,
    OverrideWeeklyLimit,
    OverrideMaxGasPerChainWei,
    OverrideDailyMaxTxCount,
    OverridePerTxMaxFeePerGasGwei,
    OverridePerTxMaxPriorityFeePerGasWei,
    OverridePerTxMaxCalldataBytes,
    DeleteDestinationOverride,
    ManualApprovals,
    SelectedManualApproval,
    ManualApprovalRecipientAddress,
    ManualApprovalMinAmount,
    ManualApprovalMaxAmount,
    ManualApprovalPriority,
    DeleteManualApproval,
    SaveToken,
    DeleteToken,
    SelectedNetwork,
    ChainConfigKey,
    ChainConfigId,
    ChainConfigName,
    ChainConfigRpcUrl,
    ChainConfigUseAsActive,
    SaveNetwork,
    DeleteNetwork,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldInteraction {
    Edit,
    Select,
    Action,
    ReadOnly,
}

impl FieldInteraction {
    fn badge(self) -> &'static str {
        match self {
            Self::Edit => "[E]",
            Self::Select => "[S]",
            Self::Action => "[A]",
            Self::ReadOnly => "[R]",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LimitDraft {
    per_tx_limit: String,
    daily_limit: String,
    weekly_limit: String,
    max_gas_per_chain_wei: String,
    daily_max_tx_count: String,
    per_tx_max_fee_per_gas_gwei: String,
    per_tx_max_priority_fee_per_gas_wei: String,
    per_tx_max_calldata_bytes: String,
}

impl LimitDraft {
    fn empty() -> Self {
        Self {
            per_tx_limit: String::new(),
            daily_limit: String::new(),
            weekly_limit: String::new(),
            max_gas_per_chain_wei: String::new(),
            daily_max_tx_count: String::new(),
            per_tx_max_fee_per_gas_gwei: String::new(),
            per_tx_max_priority_fee_per_gas_wei: String::new(),
            per_tx_max_calldata_bytes: String::new(),
        }
    }

    fn from_policy(policy: Option<&TokenPolicyProfile>, decimals: u8) -> Self {
        let Some(policy) = policy else {
            return Self::empty();
        };

        Self {
            per_tx_limit: display_policy_amount(
                policy.per_tx_amount_decimal.as_deref(),
                policy.per_tx_limit.as_deref(),
                policy.per_tx_amount,
                decimals,
            )
            .unwrap_or_default(),
            daily_limit: display_policy_amount(
                policy.daily_amount_decimal.as_deref(),
                policy.daily_limit.as_deref(),
                policy.daily_amount,
                decimals,
            )
            .unwrap_or_default(),
            weekly_limit: display_policy_amount(
                policy.weekly_amount_decimal.as_deref(),
                policy.weekly_limit.as_deref(),
                policy.weekly_amount,
                decimals,
            )
            .unwrap_or_default(),
            max_gas_per_chain_wei: policy.max_gas_per_chain_wei.clone().unwrap_or_default(),
            daily_max_tx_count: policy.daily_max_tx_count.clone().unwrap_or_default(),
            per_tx_max_fee_per_gas_gwei: display_policy_gwei(
                policy.per_tx_max_fee_per_gas_gwei.as_deref(),
                policy.per_tx_max_fee_per_gas_wei.as_deref(),
            )
            .unwrap_or_default(),
            per_tx_max_priority_fee_per_gas_wei: policy
                .per_tx_max_priority_fee_per_gas_wei
                .clone()
                .unwrap_or_default(),
            per_tx_max_calldata_bytes: policy.per_tx_max_calldata_bytes.clone().unwrap_or_default(),
        }
    }

    fn is_empty(&self) -> bool {
        self.per_tx_limit.trim().is_empty()
            && self.daily_limit.trim().is_empty()
            && self.weekly_limit.trim().is_empty()
            && self.max_gas_per_chain_wei.trim().is_empty()
            && self.daily_max_tx_count.trim().is_empty()
            && self.per_tx_max_fee_per_gas_gwei.trim().is_empty()
            && self.per_tx_max_priority_fee_per_gas_wei.trim().is_empty()
            && self.per_tx_max_calldata_bytes.trim().is_empty()
    }

    fn as_token_level_policy(&self, validation_decimals: u8) -> Result<Option<TokenPolicyProfile>> {
        if self.is_empty() {
            return Ok(None);
        }
        validate_limit_draft(self, validation_decimals)?;

        let per_tx_max_fee_per_gas_wei =
            parse_optional_gwei_amount("max fee per gas", Some(&self.per_tx_max_fee_per_gas_gwei))?;
        let daily_max_tx_count =
            parse_optional_non_negative_u128("daily max tx count", &self.daily_max_tx_count)?;
        let per_tx_max_priority_fee_per_gas_wei = parse_optional_non_negative_u128(
            "max priority fee per gas",
            &self.per_tx_max_priority_fee_per_gas_wei,
        )?;
        let per_tx_max_calldata_bytes = parse_optional_non_negative_u128(
            "max calldata bytes",
            &self.per_tx_max_calldata_bytes,
        )?;

        Ok(Some(TokenPolicyProfile {
            per_tx_amount: None,
            daily_amount: None,
            weekly_amount: None,
            per_tx_amount_decimal: Some(self.per_tx_limit.trim().to_string()),
            daily_amount_decimal: Some(self.daily_limit.trim().to_string()),
            weekly_amount_decimal: Some(self.weekly_limit.trim().to_string()),
            per_tx_limit: None,
            daily_limit: None,
            weekly_limit: None,
            max_gas_per_chain_wei: optional_trimmed(&self.max_gas_per_chain_wei),
            daily_max_tx_count: optional_non_zero_string(daily_max_tx_count),
            per_tx_max_fee_per_gas_gwei: (per_tx_max_fee_per_gas_wei > 0)
                .then(|| self.per_tx_max_fee_per_gas_gwei.trim().to_string()),
            per_tx_max_fee_per_gas_wei: optional_non_zero_string(per_tx_max_fee_per_gas_wei),
            per_tx_max_priority_fee_per_gas_wei: optional_non_zero_string(
                per_tx_max_priority_fee_per_gas_wei,
            ),
            per_tx_max_calldata_bytes: optional_non_zero_string(per_tx_max_calldata_bytes),
            extra: BTreeMap::new(),
        }))
    }

    fn as_chain_policy(&self, decimals: u8) -> Result<Option<TokenPolicyProfile>> {
        let Some(mut policy) = self.as_token_level_policy(decimals)? else {
            return Ok(None);
        };
        policy.per_tx_limit = Some(
            parse_required_token_amount("per-tx limit", &self.per_tx_limit, decimals)?.to_string(),
        );
        policy.daily_limit = Some(
            parse_required_token_amount("daily limit", &self.daily_limit, decimals)?.to_string(),
        );
        policy.weekly_limit = Some(
            parse_required_token_amount("weekly limit", &self.weekly_limit, decimals)?.to_string(),
        );
        Ok(Some(policy))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TokenNetworkDraft {
    chain_key: String,
    chain_id: String,
    is_native: bool,
    address: String,
    decimals: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DestinationOverrideDraft {
    recipient_address: String,
    limits: LimitDraft,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ManualApprovalDraft {
    recipient_address: String,
    min_amount: String,
    max_amount: String,
    priority: String,
}

#[derive(Debug, Clone, Default)]
struct TokenDraft {
    source_key: Option<String>,
    key: String,
    name: String,
    symbol: String,
    limits: LimitDraft,
    networks: Vec<TokenNetworkDraft>,
    cached_networks: BTreeMap<String, TokenNetworkDraft>,
    selected_network: usize,
    available_network_index: usize,
    destination_overrides: Vec<DestinationOverrideDraft>,
    selected_override: usize,
    manual_approvals: Vec<ManualApprovalDraft>,
    selected_manual_approval: usize,
}

impl TokenDraft {
    fn blank(config: &WlfiConfig) -> Self {
        let mut draft = Self {
            limits: LimitDraft::empty(),
            ..Self::default()
        };
        if !config.chains.is_empty() {
            draft.available_network_index = 0;
        }
        draft
    }

    fn from_profile(token_key: &str, profile: &TokenProfile, config: &WlfiConfig) -> Self {
        let mut networks = profile
            .chains
            .iter()
            .map(|(chain_key, chain_profile)| TokenNetworkDraft {
                chain_key: chain_key.clone(),
                chain_id: chain_profile.chain_id.to_string(),
                is_native: chain_profile.is_native,
                address: chain_profile.address.clone().unwrap_or_default(),
                decimals: chain_profile.decimals.to_string(),
            })
            .collect::<Vec<_>>();
        networks.sort_by(|left, right| left.chain_key.cmp(&right.chain_key));

        let selected_decimals = networks
            .first()
            .and_then(|network| network.decimals.parse::<u8>().ok())
            .unwrap_or(18);
        let policy = profile
            .default_policy
            .as_ref()
            .or_else(|| first_chain_policy(profile));
        let destination_overrides = profile
            .destination_overrides
            .iter()
            .map(|override_profile| DestinationOverrideDraft {
                recipient_address: override_profile.recipient.clone(),
                limits: LimitDraft::from_policy(Some(&override_profile.limits), selected_decimals),
            })
            .collect::<Vec<_>>();
        let manual_approvals = profile
            .manual_approval_policies
            .iter()
            .map(|manual| ManualApprovalDraft {
                recipient_address: manual.recipient.clone().unwrap_or_default(),
                min_amount: display_manual_amount(
                    manual.min_amount_decimal.as_deref(),
                    manual.min_amount_wei.as_deref(),
                    manual.min_amount,
                    selected_decimals,
                )
                .unwrap_or_default(),
                max_amount: display_manual_amount(
                    manual.max_amount_decimal.as_deref(),
                    manual.max_amount_wei.as_deref(),
                    manual.max_amount,
                    selected_decimals,
                )
                .unwrap_or_default(),
                priority: if manual.priority == 0 {
                    "100".to_string()
                } else {
                    manual.priority.to_string()
                },
            })
            .collect::<Vec<_>>();

        let available_network_index = sorted_chain_keys(config)
            .iter()
            .position(|chain_key| {
                networks
                    .first()
                    .map(|network| &network.chain_key == chain_key)
                    .unwrap_or(false)
            })
            .unwrap_or(0);

        Self {
            source_key: Some(token_key.to_string()),
            key: token_key.to_string(),
            name: profile.name.clone().unwrap_or_default(),
            symbol: profile.symbol.clone(),
            limits: LimitDraft::from_policy(policy, selected_decimals),
            networks,
            cached_networks: BTreeMap::new(),
            selected_network: 0,
            available_network_index,
            destination_overrides,
            selected_override: 0,
            manual_approvals,
            selected_manual_approval: 0,
        }
    }

    fn selected_network(&self) -> Option<&TokenNetworkDraft> {
        self.networks.get(self.selected_network)
    }

    fn selected_network_mut(&mut self) -> Option<&mut TokenNetworkDraft> {
        self.networks.get_mut(self.selected_network)
    }

    fn min_network_decimals(&self) -> Result<u8> {
        let mut decimals = self
            .networks
            .iter()
            .map(|network| {
                parse_positive_u64("token network decimals", &network.decimals).and_then(|value| {
                    if value > u8::MAX as u64 {
                        bail!("token network decimals must be <= {}", u8::MAX);
                    }
                    Ok(value as u8)
                })
            })
            .collect::<Result<Vec<_>>>()?;
        decimals.sort_unstable();
        decimals
            .into_iter()
            .next()
            .context("select at least one network for the token")
    }

    fn normalize(&mut self) {
        if self.networks.is_empty() {
            self.selected_network = 0;
        } else if self.selected_network >= self.networks.len() {
            self.selected_network = self.networks.len() - 1;
        }
        if self.destination_overrides.is_empty() {
            self.selected_override = 0;
        } else if self.selected_override >= self.destination_overrides.len() {
            self.selected_override = self.destination_overrides.len() - 1;
        }
        if self.manual_approvals.is_empty() {
            self.selected_manual_approval = 0;
        } else if self.selected_manual_approval >= self.manual_approvals.len() {
            self.selected_manual_approval = self.manual_approvals.len() - 1;
        }
    }

    fn toggle_network_membership(&mut self, config: &WlfiConfig) -> Result<()> {
        let available = sorted_chain_keys(config);
        let Some(chain_key) = available.get(self.available_network_index) else {
            bail!("save a network before adding it to a token");
        };
        if let Some(index) = self
            .networks
            .iter()
            .position(|network| network.chain_key == *chain_key)
        {
            let removed = self.networks.remove(index);
            self.cached_networks
                .insert(removed.chain_key.clone(), removed);
            self.normalize();
            return Ok(());
        }

        let chain_profile = config
            .chains
            .get(chain_key)
            .with_context(|| format!("saved network '{}' does not exist", chain_key))?;
        let mut restored = self
            .cached_networks
            .remove(chain_key)
            .unwrap_or(TokenNetworkDraft {
                chain_key: chain_key.clone(),
                chain_id: chain_profile.chain_id.to_string(),
                is_native: false,
                address: String::new(),
                decimals: String::new(),
            });
        restored.chain_key = chain_key.clone();
        restored.chain_id = chain_profile.chain_id.to_string();
        self.networks.push(restored);
        self.networks
            .sort_by(|left, right| left.chain_key.cmp(&right.chain_key));
        self.selected_network = self
            .networks
            .iter()
            .position(|network| network.chain_key == *chain_key)
            .unwrap_or(0);
        Ok(())
    }

    fn to_profile(&self, config: &WlfiConfig) -> Result<(Option<String>, String, TokenProfile)> {
        let token_key = self.key.trim().to_lowercase();
        if token_key.is_empty() {
            bail!("token key is required");
        }
        if self.name.trim().is_empty() {
            bail!("fetch token metadata before saving the token");
        }
        if self.symbol.trim().is_empty() {
            bail!("fetch token metadata before saving the token");
        }
        if self.networks.is_empty() {
            bail!("select at least one network for the token");
        }

        let validation_decimals = self.min_network_decimals()?;
        let default_policy = self.limits.as_token_level_policy(validation_decimals)?;

        let mut chains = BTreeMap::new();
        for network in &self.networks {
            let chain_key = network.chain_key.trim().to_lowercase();
            let chain_profile = config
                .chains
                .get(&chain_key)
                .with_context(|| format!("unknown saved network '{}'", chain_key))?;
            let decimals = parse_positive_u64(
                &format!("token '{}:{}' decimals", token_key, chain_key),
                &network.decimals,
            )?;
            if decimals > u8::MAX as u64 {
                bail!(
                    "token '{}:{}' decimals must be <= {}",
                    token_key,
                    chain_key,
                    u8::MAX
                );
            }
            let is_native = network.is_native;
            let address = if is_native {
                if !network.address.trim().is_empty() {
                    bail!(
                        "token '{}:{}' must not set an address when native",
                        token_key,
                        chain_key
                    );
                }
                None
            } else {
                Some(
                    crate::TokenAddress::parse(
                        &format!("token '{}:{}'", token_key, chain_key),
                        chain_profile.chain_id,
                        &network.address,
                    )?
                    .to_string(),
                )
            };
            chains.insert(
                chain_key.clone(),
                TokenChainProfile {
                    chain_id: chain_profile.chain_id,
                    is_native,
                    address,
                    decimals: decimals as u8,
                    default_policy: self.limits.as_chain_policy(decimals as u8)?,
                    extra: BTreeMap::new(),
                },
            );
        }

        let destination_overrides = self
            .destination_overrides
            .iter()
            .map(|override_draft| {
                let trimmed = override_draft.recipient_address.trim();
                let recipient = trimmed
                    .parse::<vault_domain::RecipientId>()
                    .map_err(|err| {
                        anyhow::anyhow!("invalid destination override recipient: {err}")
                    })?
                    .to_string();
                Ok(TokenDestinationOverrideProfile {
                    recipient,
                    limits: override_draft
                        .limits
                        .as_token_level_policy(validation_decimals)?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let manual_approval_policies = self
            .manual_approvals
            .iter()
            .map(|manual_draft| {
                let priority =
                    parse_positive_u64("manual approval priority", &manual_draft.priority)?;
                if priority > u32::MAX as u64 {
                    bail!("manual approval priority must be <= {}", u32::MAX);
                }
                parse_required_token_amount(
                    "manual approval min amount",
                    &manual_draft.min_amount,
                    validation_decimals,
                )?;
                parse_required_token_amount(
                    "manual approval max amount",
                    &manual_draft.max_amount,
                    validation_decimals,
                )?;
                Ok(TokenManualApprovalProfile {
                    priority: priority as u32,
                    recipient: if manual_draft.recipient_address.trim().is_empty() {
                        None
                    } else {
                        let trimmed = manual_draft.recipient_address.trim();
                        Some(
                            trimmed
                                .parse::<vault_domain::RecipientId>()
                                .map_err(|err| {
                                    anyhow::anyhow!("invalid manual approval recipient: {err}")
                                })?
                                .to_string(),
                        )
                    },
                    min_amount: None,
                    max_amount: None,
                    min_amount_decimal: Some(manual_draft.min_amount.trim().to_string()),
                    max_amount_decimal: Some(manual_draft.max_amount.trim().to_string()),
                    min_amount_wei: None,
                    max_amount_wei: None,
                    extra: BTreeMap::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok((
            self.source_key.clone(),
            token_key,
            TokenProfile {
                name: Some(self.name.trim().to_string()),
                symbol: self.symbol.trim().to_string(),
                default_policy,
                destination_overrides,
                manual_approval_policies,
                chains,
                extra: BTreeMap::new(),
            },
        ))
    }
}

#[derive(Debug, Clone, Default)]
struct NetworkDraft {
    source_key: Option<String>,
    key: String,
    chain_id: String,
    name: String,
    rpc_url: String,
    use_as_active: bool,
}

impl NetworkDraft {
    fn blank() -> Self {
        Self::default()
    }

    fn from_profile(key: &str, profile: &ChainProfile, config: &WlfiConfig) -> Self {
        Self {
            source_key: Some(key.to_string()),
            key: key.to_string(),
            chain_id: profile.chain_id.to_string(),
            name: profile.name.clone(),
            rpc_url: profile.rpc_url.clone().unwrap_or_default(),
            use_as_active: config.chain_name.as_deref() == Some(key)
                || config.chain_id == Some(profile.chain_id),
        }
    }

    fn to_profile(&self) -> Result<(Option<String>, String, ChainProfile, bool)> {
        let key = self.key.trim().to_lowercase();
        if key.is_empty() {
            bail!("network key is required");
        }
        let chain_id = parse_positive_u64("network chain id", &self.chain_id)?;
        let name = if self.name.trim().is_empty() {
            key.clone()
        } else {
            self.name.trim().to_string()
        };
        let rpc_url = parse_optional_rpc_url("network rpc url", &self.rpc_url)?;
        Ok((
            self.source_key.clone(),
            key,
            ChainProfile {
                chain_id,
                name,
                rpc_url,
                extra: BTreeMap::new(),
            },
            self.use_as_active,
        ))
    }
}

#[derive(Debug)]
struct AppState {
    view: View,
    selected: usize,
    config_path: PathBuf,
    shared_config_draft: WlfiConfig,
    token_draft: TokenDraft,
    network_draft: NetworkDraft,
    show_advanced: bool,
    print_agent_auth_token: bool,
    token_dirty: bool,
    network_dirty: bool,
    pending_discard_action: Option<PendingDiscardAction>,
    pending_delete_action: Option<PendingDeleteAction>,
    message: Option<String>,
    message_level: MessageLevel,
}

impl AppState {
    fn from_shared_config(config: &WlfiConfig, print_agent_auth_token: bool) -> Self {
        let token_draft = sorted_token_keys(config)
            .first()
            .and_then(|token_key| {
                config
                    .tokens
                    .get(token_key)
                    .map(|profile| TokenDraft::from_profile(token_key, profile, config))
            })
            .unwrap_or_else(|| TokenDraft::blank(config));
        let network_draft = sorted_chain_keys(config)
            .first()
            .and_then(|chain_key| {
                config
                    .chains
                    .get(chain_key)
                    .map(|profile| NetworkDraft::from_profile(chain_key, profile, config))
            })
            .unwrap_or_else(NetworkDraft::blank);

        Self {
            view: View::Tokens,
            selected: 0,
            config_path: crate::shared_config::default_config_path()
                .unwrap_or_else(|_| PathBuf::from("config.json")),
            shared_config_draft: config.clone(),
            token_draft,
            network_draft,
            show_advanced: false,
            print_agent_auth_token,
            token_dirty: false,
            network_dirty: false,
            pending_discard_action: None,
            pending_delete_action: None,
            message: None,
            message_level: MessageLevel::Info,
        }
    }

    fn visible_fields(&self) -> Vec<Field> {
        match self.view {
            View::Tokens => {
                let mut fields = vec![
                    Field::SelectedToken,
                    Field::TokenKey,
                    Field::TokenName,
                    Field::TokenSymbol,
                    Field::NetworkMembership,
                ];
                if !self.token_draft.networks.is_empty() {
                    fields.extend([
                        Field::EditingNetwork,
                        Field::NetworkIsNative,
                        Field::NetworkAddress,
                        Field::RefreshTokenMetadata,
                        Field::TokenDecimals,
                    ]);
                }
                fields.extend([
                    Field::PerTxLimit,
                    Field::DailyLimit,
                    Field::WeeklyLimit,
                    Field::ShowAdvanced,
                    Field::DestinationOverrides,
                ]);
                if self.show_advanced {
                    fields.extend([
                        Field::MaxGasPerChainWei,
                        Field::DailyMaxTxCount,
                        Field::PerTxMaxFeePerGasGwei,
                        Field::PerTxMaxPriorityFeePerGasWei,
                        Field::PerTxMaxCalldataBytes,
                    ]);
                }
                if !self.token_draft.destination_overrides.is_empty() {
                    fields.extend([
                        Field::SelectedDestinationOverride,
                        Field::OverrideRecipientAddress,
                        Field::OverridePerTxLimit,
                        Field::OverrideDailyLimit,
                        Field::OverrideWeeklyLimit,
                        Field::DeleteDestinationOverride,
                    ]);
                    if self.show_advanced {
                        fields.extend([
                            Field::OverrideMaxGasPerChainWei,
                            Field::OverrideDailyMaxTxCount,
                            Field::OverridePerTxMaxFeePerGasGwei,
                            Field::OverridePerTxMaxPriorityFeePerGasWei,
                            Field::OverridePerTxMaxCalldataBytes,
                        ]);
                    }
                }
                fields.push(Field::ManualApprovals);
                if !self.token_draft.manual_approvals.is_empty() {
                    fields.extend([
                        Field::SelectedManualApproval,
                        Field::ManualApprovalRecipientAddress,
                        Field::ManualApprovalMinAmount,
                        Field::ManualApprovalMaxAmount,
                        Field::ManualApprovalPriority,
                        Field::DeleteManualApproval,
                    ]);
                }
                fields.extend([Field::SaveToken, Field::DeleteToken]);
                fields
            }
            View::Networks => vec![
                Field::SelectedNetwork,
                Field::ChainConfigKey,
                Field::ChainConfigId,
                Field::ChainConfigName,
                Field::ChainConfigRpcUrl,
                Field::ChainConfigUseAsActive,
                Field::SaveNetwork,
                Field::DeleteNetwork,
            ],
            View::Bootstrap => vec![Field::Execute],
        }
    }

    fn normalize_selection(&mut self) {
        let len = self.visible_fields().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
        self.token_draft.normalize();
    }

    fn selected_field(&self) -> Field {
        self.visible_fields()[self.selected]
    }

    fn select_field(&mut self, target: Field) {
        if let Some(index) = self
            .visible_fields()
            .iter()
            .position(|field| *field == target)
        {
            self.selected = index;
        }
    }

    fn active_draft_dirty(&self) -> bool {
        match self.view {
            View::Tokens => self.token_dirty,
            View::Networks => self.network_dirty,
            View::Bootstrap => false,
        }
    }

    fn active_draft_label(&self) -> &'static str {
        match self.view {
            View::Tokens => "token draft",
            View::Networks => "network draft",
            View::Bootstrap => "current view",
        }
    }

    fn clear_pending_discard(&mut self) {
        self.pending_discard_action = None;
    }

    fn clear_pending_delete(&mut self) {
        self.pending_delete_action = None;
    }

    fn clear_message(&mut self) {
        self.message = None;
        self.message_level = MessageLevel::Info;
    }

    fn set_info_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
        self.message_level = MessageLevel::Info;
    }

    fn set_success_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
        self.message_level = MessageLevel::Success;
    }

    fn set_error_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
        self.message_level = MessageLevel::Error;
    }

    fn mark_token_dirty(&mut self) {
        self.token_dirty = true;
        self.clear_pending_discard();
        self.clear_pending_delete();
    }

    fn mark_network_dirty(&mut self) {
        self.network_dirty = true;
        self.clear_pending_discard();
        self.clear_pending_delete();
    }

    fn confirm_discard(&mut self, action: PendingDiscardAction) -> bool {
        if !self.active_draft_dirty() {
            self.clear_pending_discard();
            return true;
        }

        if self.pending_discard_action == Some(action) {
            self.clear_pending_discard();
            return true;
        }

        self.clear_pending_delete();
        self.pending_discard_action = Some(action);
        self.set_info_message(format!(
            "unsaved changes in the {}; repeat the action to discard them or save first",
            self.active_draft_label()
        ));
        false
    }

    fn confirm_delete(&mut self, action: PendingDeleteAction, label: &str) -> bool {
        if self.pending_delete_action == Some(action.clone()) {
            self.clear_pending_delete();
            return true;
        }

        self.clear_pending_discard();
        self.pending_delete_action = Some(action);
        self.set_info_message(format!("repeat the action to confirm deleting {label}"));
        false
    }

    fn next_view(&mut self) {
        self.view = self.view.next();
        self.selected = 0;
        self.clear_pending_discard();
        self.clear_pending_delete();
        self.clear_message();
        self.normalize_selection();
    }

    fn previous_view(&mut self) {
        self.view = self.view.previous();
        self.selected = 0;
        self.clear_pending_discard();
        self.clear_pending_delete();
        self.clear_message();
        self.normalize_selection();
    }

    fn select_next(&mut self) {
        let len = self.visible_fields().len();
        if len > 0 {
            self.selected = (self.selected + 1) % len;
        }
    }

    fn select_prev(&mut self) {
        let len = self.visible_fields().len();
        if len > 0 {
            self.selected = if self.selected == 0 {
                len - 1
            } else {
                self.selected - 1
            };
        }
    }

    fn reload_current_view(&mut self) {
        match self.view {
            View::Tokens => {
                let source_key = self.token_draft.source_key.clone();
                self.load_token_draft(source_key.as_deref());
            }
            View::Networks => {
                let source_key = self.network_draft.source_key.clone();
                self.load_network_draft(source_key.as_deref());
            }
            View::Bootstrap => {}
        }
    }

    fn request_next_view(&mut self) {
        if self.confirm_discard(PendingDiscardAction::NextView) {
            self.next_view();
        }
    }

    fn request_previous_view(&mut self) {
        if self.confirm_discard(PendingDiscardAction::PreviousView) {
            self.previous_view();
        }
    }

    fn request_reload_current_view(&mut self) -> bool {
        if !self.confirm_discard(PendingDiscardAction::ReloadCurrentView) {
            return false;
        }
        self.reload_current_view();
        true
    }

    fn request_new_current_draft(&mut self) {
        match self.view {
            View::Tokens => {
                if self.confirm_discard(PendingDiscardAction::NewTokenDraft) {
                    self.new_token_draft();
                }
            }
            View::Networks => {
                if self.confirm_discard(PendingDiscardAction::NewNetworkDraft) {
                    self.new_network_draft();
                }
            }
            View::Bootstrap => {}
        }
    }

    fn request_cancel(&mut self) -> bool {
        self.confirm_discard(PendingDiscardAction::Cancel)
    }

    fn load_token_draft(&mut self, token_key: Option<&str>) {
        self.token_draft = token_key
            .and_then(|token_key| {
                self.shared_config_draft
                    .tokens
                    .get(token_key)
                    .map(|profile| {
                        TokenDraft::from_profile(token_key, profile, &self.shared_config_draft)
                    })
            })
            .or_else(|| {
                sorted_token_keys(&self.shared_config_draft)
                    .first()
                    .and_then(|token_key| {
                        self.shared_config_draft
                            .tokens
                            .get(token_key)
                            .map(|profile| {
                                TokenDraft::from_profile(
                                    token_key,
                                    profile,
                                    &self.shared_config_draft,
                                )
                            })
                    })
            })
            .unwrap_or_else(|| TokenDraft::blank(&self.shared_config_draft));
        self.token_dirty = false;
        self.clear_pending_discard();
        self.clear_pending_delete();
        self.normalize_selection();
    }

    fn load_network_draft(&mut self, chain_key: Option<&str>) {
        self.network_draft = chain_key
            .and_then(|chain_key| {
                self.shared_config_draft
                    .chains
                    .get(chain_key)
                    .map(|profile| {
                        NetworkDraft::from_profile(chain_key, profile, &self.shared_config_draft)
                    })
            })
            .or_else(|| {
                sorted_chain_keys(&self.shared_config_draft)
                    .first()
                    .and_then(|chain_key| {
                        self.shared_config_draft
                            .chains
                            .get(chain_key)
                            .map(|profile| {
                                NetworkDraft::from_profile(
                                    chain_key,
                                    profile,
                                    &self.shared_config_draft,
                                )
                            })
                    })
            })
            .unwrap_or_else(NetworkDraft::blank);
        self.network_dirty = false;
        self.clear_pending_discard();
        self.clear_pending_delete();
        self.normalize_selection();
    }

    fn new_token_draft(&mut self) {
        self.token_draft = TokenDraft::blank(&self.shared_config_draft);
        self.token_dirty = false;
        self.clear_pending_discard();
        self.clear_pending_delete();
        self.set_success_message("new token draft ready");
    }

    fn new_network_draft(&mut self) {
        self.network_draft = NetworkDraft::blank();
        self.network_dirty = false;
        self.clear_pending_discard();
        self.clear_pending_delete();
        self.select_field(Field::ChainConfigKey);
        self.set_success_message("new network draft ready");
    }

    fn request_delete_destination_override(&mut self) {
        if self.token_draft.destination_overrides.is_empty() {
            self.delete_destination_override();
            return;
        }
        let target =
            PendingDeleteAction::DeleteDestinationOverride(self.token_draft.selected_override);
        if self.confirm_delete(target, "the selected destination override") {
            self.delete_destination_override();
        }
    }

    fn request_delete_manual_approval(&mut self) {
        if self.token_draft.manual_approvals.is_empty() {
            self.delete_manual_approval();
            return;
        }
        let target =
            PendingDeleteAction::DeleteManualApproval(self.token_draft.selected_manual_approval);
        if self.confirm_delete(target, "the selected manual approval policy") {
            self.delete_manual_approval();
        }
    }

    fn request_delete_token(&mut self) -> Result<()> {
        let has_candidate =
            self.token_draft.source_key.is_some() || !self.token_draft.key.trim().is_empty();
        if !has_candidate {
            return self.delete_token_config();
        }
        let target = PendingDeleteAction::DeleteToken(self.pending_token_delete_key()?);
        if self.confirm_delete(target, "the selected token") {
            return self.delete_token_config();
        }
        Ok(())
    }

    fn request_delete_network(&mut self) -> Result<()> {
        let has_candidate =
            self.network_draft.source_key.is_some() || !self.network_draft.key.trim().is_empty();
        if !has_candidate {
            return self.delete_network_config();
        }
        let target = PendingDeleteAction::DeleteNetwork(self.pending_network_delete_key()?);
        if self.confirm_delete(target, "the selected network") {
            return self.delete_network_config();
        }
        Ok(())
    }

    fn step_selected(&mut self, direction: i8) {
        match self.selected_field() {
            Field::SelectedToken => self.request_cycle_saved_token(direction),
            Field::NetworkMembership => self.cycle_available_network(direction),
            Field::EditingNetwork => self.cycle_selected_network_mapping(direction),
            Field::NetworkIsNative => {
                if let Some(network) = self.token_draft.selected_network_mut() {
                    network.is_native = !network.is_native;
                    if network.is_native {
                        network.address.clear();
                    }
                    self.mark_token_dirty();
                }
            }
            Field::SelectedDestinationOverride => {
                self.clear_pending_delete();
                cycle_index(
                    &mut self.token_draft.selected_override,
                    self.token_draft.destination_overrides.len(),
                    direction,
                );
            }
            Field::SelectedManualApproval => {
                self.clear_pending_delete();
                cycle_index(
                    &mut self.token_draft.selected_manual_approval,
                    self.token_draft.manual_approvals.len(),
                    direction,
                );
            }
            Field::SelectedNetwork => self.request_cycle_saved_network(direction),
            Field::ShowAdvanced => {
                self.show_advanced = !self.show_advanced;
            }
            Field::ChainConfigUseAsActive => {
                self.network_draft.use_as_active = !self.network_draft.use_as_active;
                self.mark_network_dirty();
            }
            _ => {}
        }
    }

    fn request_cycle_saved_token(&mut self, direction: i8) {
        if self.confirm_discard(PendingDiscardAction::CycleSavedToken(direction)) {
            self.cycle_saved_token(direction);
        }
    }

    fn cycle_saved_token(&mut self, direction: i8) {
        let saved = sorted_token_keys(&self.shared_config_draft);
        if saved.is_empty() {
            self.new_token_draft();
            return;
        }
        let mut entries = saved;
        entries.push("<new>".to_string());
        let current = self
            .token_draft
            .source_key
            .clone()
            .unwrap_or_else(|| "<new>".to_string());
        let mut index = entries
            .iter()
            .position(|entry| *entry == current)
            .unwrap_or(entries.len() - 1);
        cycle_index(&mut index, entries.len(), direction);
        if entries[index] == "<new>" {
            self.new_token_draft();
        } else {
            let key = entries[index].clone();
            self.load_token_draft(Some(&key));
            self.clear_message();
        }
    }

    fn request_cycle_saved_network(&mut self, direction: i8) {
        if self.confirm_discard(PendingDiscardAction::CycleSavedNetwork(direction)) {
            self.cycle_saved_network(direction);
        }
    }

    fn cycle_saved_network(&mut self, direction: i8) {
        let saved = sorted_chain_keys(&self.shared_config_draft);
        if saved.is_empty() {
            self.new_network_draft();
            return;
        }
        let mut entries = saved;
        entries.push("<new>".to_string());
        let current = self
            .network_draft
            .source_key
            .clone()
            .unwrap_or_else(|| "<new>".to_string());
        let mut index = entries
            .iter()
            .position(|entry| *entry == current)
            .unwrap_or(entries.len() - 1);
        cycle_index(&mut index, entries.len(), direction);
        if entries[index] == "<new>" {
            self.new_network_draft();
        } else {
            let key = entries[index].clone();
            self.load_network_draft(Some(&key));
            self.clear_message();
        }
    }

    fn cycle_available_network(&mut self, direction: i8) {
        let available = sorted_chain_keys(&self.shared_config_draft);
        if available.is_empty() {
            self.set_error_message(
                "save a network in the Networks view before attaching it to a token",
            );
            return;
        }
        if available.len() == 1 {
            self.token_draft.available_network_index = 0;
            self.set_info_message(format!(
                "only one saved network is available ({}) — add another in Networks to multi-select",
                available[0]
            ));
            return;
        }
        cycle_index(
            &mut self.token_draft.available_network_index,
            available.len(),
            direction,
        );
        let focus_index = self.token_draft.available_network_index + 1;
        let focus = &available[self.token_draft.available_network_index];
        self.set_info_message(format!(
            "network focus: {} ({}/{}) — press Space or Enter to toggle it",
            focus,
            focus_index,
            available.len()
        ));
    }

    fn cycle_selected_network_mapping(&mut self, direction: i8) {
        cycle_index(
            &mut self.token_draft.selected_network,
            self.token_draft.networks.len(),
            direction,
        );
    }

    fn selected_text_field_mut(&mut self, selected_field: Field) -> Option<&mut String> {
        match selected_field {
            Field::TokenKey => Some(&mut self.token_draft.key),
            Field::NetworkAddress => self
                .token_draft
                .selected_network_mut()
                .map(|network| &mut network.address),
            Field::PerTxLimit => Some(&mut self.token_draft.limits.per_tx_limit),
            Field::DailyLimit => Some(&mut self.token_draft.limits.daily_limit),
            Field::WeeklyLimit => Some(&mut self.token_draft.limits.weekly_limit),
            Field::MaxGasPerChainWei => Some(&mut self.token_draft.limits.max_gas_per_chain_wei),
            Field::DailyMaxTxCount => Some(&mut self.token_draft.limits.daily_max_tx_count),
            Field::PerTxMaxFeePerGasGwei => {
                Some(&mut self.token_draft.limits.per_tx_max_fee_per_gas_gwei)
            }
            Field::PerTxMaxPriorityFeePerGasWei => {
                Some(&mut self.token_draft.limits.per_tx_max_priority_fee_per_gas_wei)
            }
            Field::PerTxMaxCalldataBytes => {
                Some(&mut self.token_draft.limits.per_tx_max_calldata_bytes)
            }
            Field::OverrideRecipientAddress => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.recipient_address),
            Field::OverridePerTxLimit => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.per_tx_limit),
            Field::OverrideDailyLimit => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.daily_limit),
            Field::OverrideWeeklyLimit => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.weekly_limit),
            Field::OverrideMaxGasPerChainWei => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.max_gas_per_chain_wei),
            Field::OverrideDailyMaxTxCount => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.daily_max_tx_count),
            Field::OverridePerTxMaxFeePerGasGwei => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.per_tx_max_fee_per_gas_gwei),
            Field::OverridePerTxMaxPriorityFeePerGasWei => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.per_tx_max_priority_fee_per_gas_wei),
            Field::OverridePerTxMaxCalldataBytes => self
                .token_draft
                .destination_overrides
                .get_mut(self.token_draft.selected_override)
                .map(|item| &mut item.limits.per_tx_max_calldata_bytes),
            Field::ManualApprovalRecipientAddress => self
                .token_draft
                .manual_approvals
                .get_mut(self.token_draft.selected_manual_approval)
                .map(|item| &mut item.recipient_address),
            Field::ManualApprovalMinAmount => self
                .token_draft
                .manual_approvals
                .get_mut(self.token_draft.selected_manual_approval)
                .map(|item| &mut item.min_amount),
            Field::ManualApprovalMaxAmount => self
                .token_draft
                .manual_approvals
                .get_mut(self.token_draft.selected_manual_approval)
                .map(|item| &mut item.max_amount),
            Field::ManualApprovalPriority => self
                .token_draft
                .manual_approvals
                .get_mut(self.token_draft.selected_manual_approval)
                .map(|item| &mut item.priority),
            Field::ChainConfigKey => Some(&mut self.network_draft.key),
            Field::ChainConfigId => Some(&mut self.network_draft.chain_id),
            Field::ChainConfigName => Some(&mut self.network_draft.name),
            Field::ChainConfigRpcUrl => Some(&mut self.network_draft.rpc_url),
            _ => None,
        }
    }

    fn edit_selected(&mut self, key: KeyEvent) {
        let selected_field = self.selected_field();
        match key.code {
            KeyCode::Backspace => {
                let changed = if let Some(target) = self.selected_text_field_mut(selected_field) {
                    target.pop();
                    true
                } else {
                    false
                };
                if changed {
                    self.record_selected_text_change(selected_field);
                }
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                if is_allowed_input_char(selected_field, ch) {
                    let changed = if let Some(target) = self.selected_text_field_mut(selected_field)
                    {
                        target.push(ch);
                        true
                    } else {
                        false
                    };
                    if changed {
                        self.record_selected_text_change(selected_field);
                    }
                } else {
                    self.set_error_message(format!(
                        "invalid character '{ch}' for the selected field"
                    ));
                }
            }
            _ => {}
        }
    }

    fn record_selected_text_change(&mut self, selected_field: Field) {
        if field_uses_network_draft(selected_field) {
            self.mark_network_dirty();
        } else {
            self.mark_token_dirty();
        }
        self.clear_message();
    }

    fn paste_selected(&mut self, pasted: &str) {
        let selected_field = self.selected_field();
        let sanitized = pasted
            .trim()
            .chars()
            .filter(|ch| !matches!(ch, '\r' | '\n' | '\t'))
            .collect::<String>();
        let sanitized = sanitized.trim();
        if sanitized.is_empty() {
            return;
        }

        if let Some(invalid) = sanitized
            .chars()
            .find(|ch| !is_allowed_input_char(selected_field, *ch))
        {
            self.set_error_message(format!(
                "invalid character '{invalid}' for the selected field"
            ));
            return;
        }

        let changed = if let Some(target) = self.selected_text_field_mut(selected_field) {
            target.push_str(sanitized);
            true
        } else {
            false
        };
        if changed {
            self.record_selected_text_change(selected_field);
        }
    }

    fn add_destination_override(&mut self) {
        self.token_draft
            .destination_overrides
            .push(DestinationOverrideDraft {
                recipient_address: String::new(),
                limits: self.token_draft.limits.clone(),
            });
        self.token_draft.selected_override = self
            .token_draft
            .destination_overrides
            .len()
            .saturating_sub(1);
        self.mark_token_dirty();
        self.set_success_message("destination override added");
    }

    fn delete_destination_override(&mut self) {
        if self.token_draft.destination_overrides.is_empty() {
            self.set_info_message("no destination override is selected");
            return;
        }
        self.token_draft
            .destination_overrides
            .remove(self.token_draft.selected_override);
        self.token_draft.normalize();
        self.mark_token_dirty();
        self.set_success_message("destination override removed");
    }

    fn add_manual_approval(&mut self) {
        self.token_draft.manual_approvals.push(ManualApprovalDraft {
            recipient_address: String::new(),
            min_amount: self.token_draft.limits.daily_limit.clone(),
            max_amount: self.token_draft.limits.weekly_limit.clone(),
            priority: "100".to_string(),
        });
        self.token_draft.selected_manual_approval =
            self.token_draft.manual_approvals.len().saturating_sub(1);
        self.mark_token_dirty();
        self.set_success_message("manual approval policy added");
    }

    fn delete_manual_approval(&mut self) {
        if self.token_draft.manual_approvals.is_empty() {
            self.set_info_message("no manual approval policy is selected");
            return;
        }
        self.token_draft
            .manual_approvals
            .remove(self.token_draft.selected_manual_approval);
        self.token_draft.normalize();
        self.mark_token_dirty();
        self.set_success_message("manual approval policy removed");
    }

    fn refresh_token_metadata(&mut self) -> Result<()> {
        let selected_network = self
            .token_draft
            .selected_network()
            .cloned()
            .context("select a token network first")?;
        let chain_profile = self
            .shared_config_draft
            .chains
            .get(&selected_network.chain_key)
            .with_context(|| format!("unknown saved network '{}'", selected_network.chain_key))?;
        if vault_domain::is_solana_chain_id(chain_profile.chain_id) {
            // SPL token metadata fetching is not yet wired up here; let the
            // user fill name/symbol/decimals manually instead of attempting an
            // EVM-style RPC call against a Solana endpoint.
            bail!(
                "metadata refresh from RPC is not yet supported for Solana tokens; \
                 enter name, symbol, and decimals manually for '{}'",
                selected_network.chain_key
            );
        }
        let rpc_url = chain_profile
            .rpc_url
            .as_deref()
            .or(self.shared_config_draft.rpc_url.as_deref())
            .context("the selected network needs an rpc url before metadata can be fetched")?;
        let address = if selected_network.is_native {
            None
        } else {
            Some(parse_address("token address", &selected_network.address)?)
        };
        let metadata = fetch_token_metadata_sync(
            selected_network.chain_key.clone(),
            rpc_url.to_string(),
            chain_profile.chain_id,
            selected_network.is_native,
            address,
        )?;

        self.token_draft.name = metadata.name;
        self.token_draft.symbol = metadata.symbol;
        if self.token_draft.key.trim().is_empty() {
            self.token_draft.key = self.token_draft.symbol.to_lowercase();
        }
        if let Some(network) = self.token_draft.selected_network_mut() {
            network.chain_id = metadata.chain_id.to_string();
            network.decimals = metadata.decimals.to_string();
        }
        self.mark_token_dirty();
        self.set_success_message("token metadata refreshed from rpc");
        Ok(())
    }

    fn selected_token_requires_metadata_refresh(&self) -> bool {
        let Some(selected_network) = self.token_draft.selected_network() else {
            return false;
        };
        let has_asset_locator =
            selected_network.is_native || !selected_network.address.trim().is_empty();
        let missing_metadata = self.token_draft.name.trim().is_empty()
            || self.token_draft.symbol.trim().is_empty()
            || selected_network.chain_id.trim().is_empty()
            || selected_network.decimals.trim().is_empty();
        has_asset_locator && missing_metadata
    }

    fn persist_shared_config(&mut self) -> Result<()> {
        let loaded = LoadedConfig {
            path: self.config_path.clone(),
            config: self.shared_config_draft.clone(),
        };
        loaded.save()
    }

    fn token_config_save_candidate(&self) -> Result<(String, WlfiConfig)> {
        let (source_key, token_key, token_profile) =
            self.token_draft.to_profile(&self.shared_config_draft)?;
        let mut candidate = self.shared_config_draft.clone();
        if let Some(old_key) = source_key.as_ref() {
            if old_key != &token_key {
                candidate.tokens.remove(old_key);
            }
        }
        candidate.tokens.insert(token_key.clone(), token_profile);

        let token_selectors = resolve_all_token_selectors(&candidate)?;
        let token_policies = resolve_all_token_policies(&candidate)?;
        let _ = resolve_all_token_destination_overrides(&candidate, &token_policies)?;
        let _ = resolve_all_token_manual_approval_policies(&candidate, &token_selectors)?;

        Ok((token_key, candidate))
    }

    fn finalize_saved_token_config(
        &mut self,
        token_key: &str,
        candidate: WlfiConfig,
    ) -> Result<()> {
        self.shared_config_draft = candidate;
        self.persist_shared_config()?;
        self.load_token_draft(Some(token_key));
        self.set_success_message(format!("saved token '{}'", token_key));
        Ok(())
    }

    fn delete_token_config(&mut self) -> Result<()> {
        let key = self
            .token_draft
            .source_key
            .clone()
            .or_else(|| {
                let trimmed = self.token_draft.key.trim().to_lowercase();
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .context("no saved token is selected")?;
        if self.shared_config_draft.tokens.remove(&key).is_none() {
            bail!("no saved token exists for '{}'", key);
        }
        self.persist_shared_config()?;
        self.load_token_draft(None);
        self.set_success_message(format!("deleted token '{}'", key));
        Ok(())
    }

    fn network_config_save_candidate(&self) -> Result<(String, WlfiConfig)> {
        let (source_key, chain_key, profile, use_as_active) = self.network_draft.to_profile()?;
        let mut candidate = self.shared_config_draft.clone();

        if let Some(old_key) = source_key.as_ref() {
            if old_key != &chain_key {
                if candidate.chains.remove(old_key).is_none() {
                    bail!("no saved network exists for '{}'", old_key);
                }
                for token_profile in candidate.tokens.values_mut() {
                    if let Some(chain_profile) = token_profile.chains.remove(old_key) {
                        token_profile
                            .chains
                            .insert(chain_key.clone(), chain_profile);
                    }
                }
            }
        }

        candidate.chains.insert(chain_key.clone(), profile.clone());
        if use_as_active {
            candidate.chain_id = Some(profile.chain_id);
            candidate.chain_name = Some(profile.name.clone());
            candidate.rpc_url = profile.rpc_url.clone();
        }

        Ok((chain_key, candidate))
    }

    fn finalize_saved_network_config(
        &mut self,
        chain_key: &str,
        candidate: WlfiConfig,
    ) -> Result<()> {
        self.shared_config_draft = candidate;
        self.persist_shared_config()?;
        self.load_network_draft(Some(chain_key));
        let token_source_key = self.token_draft.source_key.clone();
        self.load_token_draft(token_source_key.as_deref());
        self.set_success_message(format!("saved network '{}'", chain_key));
        Ok(())
    }

    fn save_network_config(&mut self) -> Result<()> {
        let (chain_key, candidate) = self.network_config_save_candidate()?;
        self.finalize_saved_network_config(&chain_key, candidate)
    }

    fn delete_network_config(&mut self) -> Result<()> {
        let key = self
            .network_draft
            .source_key
            .clone()
            .or_else(|| {
                let trimmed = self.network_draft.key.trim().to_lowercase();
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .context("no saved network is selected")?;
        if let Some(token_key) =
            self.shared_config_draft
                .tokens
                .iter()
                .find_map(|(token_key, token_profile)| {
                    token_profile
                        .chains
                        .contains_key(&key)
                        .then_some(token_key.clone())
                })
        {
            bail!(
                "network '{}' is still used by token '{}'; remove the mapping first",
                key,
                token_key
            );
        }
        if self.shared_config_draft.chains.remove(&key).is_none() {
            bail!("no saved network exists for '{}'", key);
        }
        self.persist_shared_config()?;
        self.load_network_draft(None);
        self.set_success_message(format!("deleted network '{}'", key));
        Ok(())
    }

    fn pending_token_delete_key(&self) -> Result<String> {
        self.token_draft
            .source_key
            .clone()
            .or_else(|| {
                let trimmed = self.token_draft.key.trim().to_lowercase();
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .context("no saved token is selected")
    }

    fn pending_network_delete_key(&self) -> Result<String> {
        self.network_draft
            .source_key
            .clone()
            .or_else(|| {
                let trimmed = self.network_draft.key.trim().to_lowercase();
                (!trimmed.is_empty()).then_some(trimmed)
            })
            .context("no saved network is selected")
    }

    fn build_params(&self) -> Result<BootstrapParams> {
        build_bootstrap_params_from_shared_config(
            &self.shared_config_draft,
            self.print_agent_auth_token,
            true,
        )
    }
}

pub(crate) fn build_bootstrap_params_from_shared_config(
    config: &WlfiConfig,
    print_agent_auth_token: bool,
    reuse_existing_wallet: bool,
) -> Result<BootstrapParams> {
    let token_selectors = resolve_all_token_selectors(config)?;
    let token_policies = resolve_all_token_policies(config)?;
    let token_destination_overrides =
        resolve_all_token_destination_overrides(config, &token_policies)?;
    let token_manual_approval_policies =
        resolve_all_token_manual_approval_policies(config, &token_selectors)?;

    let (existing_agent_key_id, existing_vault_key_id, existing_vault_public_key) =
        if reuse_existing_wallet {
            let wallet = config.wallet.as_ref();
            let parsed_agent_key_id = wallet
                .and_then(|profile| profile.agent_key_id.as_deref())
                .or(config.agent_key_id.as_deref())
                .map(|value| {
                    Uuid::parse_str(value).with_context(|| {
                        format!("wallet.agentKeyId '{value}' must be a valid UUID")
                    })
                })
                .transpose()?;
            let parsed_vault_key_id = wallet
                .and_then(|profile| profile.vault_key_id.as_deref())
                .map(|value| {
                    Uuid::parse_str(value).with_context(|| {
                        format!("wallet.vaultKeyId '{value}' must be a valid UUID")
                    })
                })
                .transpose()?;
            let vault_public_key = wallet.and_then(|profile| {
                let trimmed = profile.vault_public_key.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });
            (parsed_agent_key_id, parsed_vault_key_id, vault_public_key)
        } else {
            (None, None, None)
        };

    Ok(BootstrapParams {
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
        token_selectors,
        token_policies,
        destination_overrides: Vec::new(),
        token_destination_overrides,
        token_manual_approval_policies,
        attach_policy_ids: Vec::new(),
        print_agent_auth_token,
        print_vault_private_key: false,
        existing_agent_key_id,
        existing_vault_key_id,
        existing_vault_public_key,
        import_vault_private_key: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedLimitFields {
    per_tx_max_wei: u128,
    daily_max_wei: u128,
    weekly_max_wei: u128,
    max_gas_per_chain_wei: u128,
    daily_max_tx_count: u128,
    per_tx_max_fee_per_gas_wei: u128,
    per_tx_max_priority_fee_per_gas_wei: u128,
    per_tx_max_calldata_bytes: u128,
}

impl ResolvedLimitFields {
    fn from_token_policy(policy: &TokenPolicyConfig) -> Self {
        Self {
            per_tx_max_wei: policy.per_tx_max_wei,
            daily_max_wei: policy.daily_max_wei,
            weekly_max_wei: policy.weekly_max_wei,
            max_gas_per_chain_wei: policy.max_gas_per_chain_wei,
            daily_max_tx_count: policy.daily_max_tx_count,
            per_tx_max_fee_per_gas_wei: policy.per_tx_max_fee_per_gas_wei,
            per_tx_max_priority_fee_per_gas_wei: policy.per_tx_max_priority_fee_per_gas_wei,
            per_tx_max_calldata_bytes: policy.per_tx_max_calldata_bytes,
        }
    }

    fn from_override(override_policy: &TokenDestinationPolicyOverride) -> Self {
        Self {
            per_tx_max_wei: override_policy.per_tx_max_wei,
            daily_max_wei: override_policy.daily_max_wei,
            weekly_max_wei: override_policy.weekly_max_wei,
            max_gas_per_chain_wei: override_policy.max_gas_per_chain_wei,
            daily_max_tx_count: override_policy.daily_max_tx_count,
            per_tx_max_fee_per_gas_wei: override_policy.per_tx_max_fee_per_gas_wei,
            per_tx_max_priority_fee_per_gas_wei: override_policy
                .per_tx_max_priority_fee_per_gas_wei,
            per_tx_max_calldata_bytes: override_policy.per_tx_max_calldata_bytes,
        }
    }
}

enum LoopAction {
    Continue,
    RefreshTokenMetadata,
    SaveTokenAndApply,
    SaveNetworkAndApply,
    ApplyAndExit(Box<BootstrapParams>),
    Cancel,
}

pub(crate) fn run_bootstrap_tui<T>(
    shared_config: &WlfiConfig,
    print_agent_auth_token: bool,
    on_apply: impl FnMut(BootstrapParams, &mut dyn FnMut(&str) -> Result<()>) -> Result<T>,
) -> Result<Option<T>> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal backend")?;

    let run_result = run_event_loop(
        &mut terminal,
        AppState::from_shared_config(shared_config, print_agent_auth_token),
        on_apply,
    );
    let cleanup_result = cleanup_terminal(&mut terminal);
    match (run_result, cleanup_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(run_err), Ok(())) => Err(run_err),
        (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
        (Err(run_err), Err(cleanup_err)) => Err(run_err.context(cleanup_err.to_string())),
    }
}

fn cleanup_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    )
    .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;
    Ok(())
}

fn render_frame<B: Backend>(terminal: &mut Terminal<B>, app: &AppState) -> Result<()> {
    terminal
        .draw(|frame| draw_ui(frame, app))
        .context("failed to render tui frame")?;
    Ok(())
}

fn refresh_metadata_with_progress<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut AppState,
) -> Result<()> {
    app.set_info_message("refreshing token metadata from rpc");
    render_frame(terminal, app)?;
    app.refresh_token_metadata()
}

fn apply_with_progress<T, B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut AppState,
    params: BootstrapParams,
    on_apply: &mut impl FnMut(BootstrapParams, &mut dyn FnMut(&str) -> Result<()>) -> Result<T>,
) -> Result<T> {
    app.set_info_message("applying wallet changes");
    render_frame(terminal, app)?;

    let mut on_status = |message: &str| -> Result<()> {
        app.set_info_message(message);
        render_frame(terminal, app)
    };

    on_apply(params, &mut on_status)
}

fn run_save_token_and_apply<T, B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut AppState,
    on_apply: &mut impl FnMut(BootstrapParams, &mut dyn FnMut(&str) -> Result<()>) -> Result<T>,
) -> Result<(T, String)> {
    if app.selected_token_requires_metadata_refresh() {
        refresh_metadata_with_progress(terminal, app)?;
    }

    let (token_key, candidate) = app.token_config_save_candidate()?;
    let success_message = format!("saved token '{}'", token_key);
    let params =
        build_bootstrap_params_from_shared_config(&candidate, app.print_agent_auth_token, true)
            .map_err(|err| anyhow!("{success_message} but failed to apply to wallet: {err}"))?;
    let output = apply_with_progress(terminal, app, params, on_apply)?;
    app.finalize_saved_token_config(&token_key, candidate)?;
    Ok((output, format!("{success_message} and applied to wallet")))
}

fn run_save_network_and_apply<T, B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut AppState,
    on_apply: &mut impl FnMut(BootstrapParams, &mut dyn FnMut(&str) -> Result<()>) -> Result<T>,
) -> Result<(T, String)> {
    let (chain_key, candidate) = app.network_config_save_candidate()?;
    let success_message = format!("saved network '{}'", chain_key);
    let params =
        build_bootstrap_params_from_shared_config(&candidate, app.print_agent_auth_token, true)
            .map_err(|err| anyhow!("{success_message} but failed to apply to wallet: {err}"))?;
    let output = apply_with_progress(terminal, app, params, on_apply)?;
    app.finalize_saved_network_config(&chain_key, candidate)?;
    Ok((output, format!("{success_message} and applied to wallet")))
}

fn run_event_loop<T, B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: AppState,
    mut on_apply: impl FnMut(BootstrapParams, &mut dyn FnMut(&str) -> Result<()>) -> Result<T>,
) -> Result<Option<T>> {
    let mut last_output = None;
    loop {
        app.normalize_selection();
        render_frame(terminal, &app)?;

        if !event::poll(Duration::from_millis(250)).context("failed to poll terminal events")? {
            continue;
        }

        match handle_terminal_event(
            &mut app,
            event::read().context("failed to read terminal event")?,
        )? {
            LoopAction::Continue => {}
            LoopAction::RefreshTokenMetadata => {
                if let Err(err) = refresh_metadata_with_progress(terminal, &mut app) {
                    app.set_error_message(err.to_string());
                }
            }
            LoopAction::SaveTokenAndApply => {
                match run_save_token_and_apply(terminal, &mut app, &mut on_apply) {
                    Ok((output, success_message)) => {
                        last_output = Some(output);
                        app.set_success_message(success_message);
                    }
                    Err(err) => {
                        app.set_error_message(err.to_string());
                    }
                }
            }
            LoopAction::SaveNetworkAndApply => {
                match run_save_network_and_apply(terminal, &mut app, &mut on_apply) {
                    Ok((output, success_message)) => {
                        last_output = Some(output);
                        app.set_success_message(success_message);
                    }
                    Err(err) => {
                        app.set_error_message(err.to_string());
                    }
                }
            }
            LoopAction::ApplyAndExit(params) => {
                match apply_with_progress(terminal, &mut app, *params, &mut on_apply) {
                    Ok(output) => return Ok(Some(output)),
                    Err(err) => {
                        app.set_error_message(err.to_string());
                    }
                }
            }
            LoopAction::Cancel => return Ok(last_output),
        }
    }
}

fn handle_terminal_event(app: &mut AppState, event: Event) -> Result<LoopAction> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => handle_key_event(app, key),
        Event::Paste(data) => {
            app.paste_selected(&data);
            Ok(LoopAction::Continue)
        }
        _ => Ok(LoopAction::Continue),
    }
}

fn handle_key_event(app: &mut AppState, key: KeyEvent) -> Result<LoopAction> {
    if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if app.view == View::Tokens && app.token_dirty {
            return Ok(LoopAction::SaveTokenAndApply);
        }
        if app.view == View::Networks && app.network_dirty {
            return Ok(LoopAction::SaveNetworkAndApply);
        }
        match app.build_params() {
            Ok(params) => return Ok(LoopAction::ApplyAndExit(Box::new(params))),
            Err(err) => {
                app.set_error_message(err.to_string());
                return Ok(LoopAction::Continue);
            }
        }
    }

    if key.code == KeyCode::Char('r') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if app.request_reload_current_view() {
            app.set_success_message("reloaded saved data into the current draft");
        }
        return Ok(LoopAction::Continue);
    }

    if key.code == KeyCode::Char('n') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.request_new_current_draft();
        return Ok(LoopAction::Continue);
    }

    if key.code == KeyCode::Char('o') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if app.view == View::Tokens {
            app.add_destination_override();
        }
        return Ok(LoopAction::Continue);
    }

    if key.code == KeyCode::Char('m') && key.modifiers.contains(KeyModifiers::CONTROL) {
        if app.view == View::Tokens {
            app.add_manual_approval();
        }
        return Ok(LoopAction::Continue);
    }

    if field_interaction(app.selected_field()) == FieldInteraction::Edit
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
    {
        match key.code {
            KeyCode::Char(_) | KeyCode::Backspace => {
                app.edit_selected(key);
                return Ok(LoopAction::Continue);
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Esc => {
            return Ok(if app.request_cancel() {
                LoopAction::Cancel
            } else {
                LoopAction::Continue
            });
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Ok(if app.request_cancel() {
                LoopAction::Cancel
            } else {
                LoopAction::Continue
            });
        }
        KeyCode::Char('q') if key.modifiers.is_empty() => {
            return Ok(if app.request_cancel() {
                LoopAction::Cancel
            } else {
                LoopAction::Continue
            });
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_next();
            app.clear_message();
            return Ok(LoopAction::Continue);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_prev();
            app.clear_message();
            return Ok(LoopAction::Continue);
        }
        KeyCode::BackTab => {
            app.request_previous_view();
            return Ok(LoopAction::Continue);
        }
        KeyCode::Tab => {
            app.request_next_view();
            return Ok(LoopAction::Continue);
        }
        KeyCode::Home => {
            app.selected = 0;
            return Ok(LoopAction::Continue);
        }
        KeyCode::End => {
            app.selected = app.visible_fields().len().saturating_sub(1);
            return Ok(LoopAction::Continue);
        }
        KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('a') => {
            app.clear_message();
            app.step_selected(-1);
            return Ok(LoopAction::Continue);
        }
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('d') => {
            app.clear_message();
            app.step_selected(1);
            return Ok(LoopAction::Continue);
        }
        KeyCode::Char(' ') => match app.selected_field() {
            Field::NetworkMembership => {
                if let Err(err) = app
                    .token_draft
                    .toggle_network_membership(&app.shared_config_draft)
                {
                    app.set_error_message(err.to_string());
                } else {
                    app.mark_token_dirty();
                    app.set_success_message("updated token network selection");
                }
                return Ok(LoopAction::Continue);
            }
            Field::SelectedToken
            | Field::EditingNetwork
            | Field::SelectedDestinationOverride
            | Field::SelectedManualApproval
            | Field::SelectedNetwork
            | Field::NetworkIsNative
            | Field::ShowAdvanced
            | Field::ChainConfigUseAsActive => {
                app.step_selected(1);
                return Ok(LoopAction::Continue);
            }
            _ => {}
        },
        KeyCode::Char('[') if key.modifiers.is_empty() => {
            app.request_previous_view();
            return Ok(LoopAction::Continue);
        }
        KeyCode::Char(']') if key.modifiers.is_empty() => {
            app.request_next_view();
            return Ok(LoopAction::Continue);
        }
        KeyCode::Enter => match app.selected_field() {
            Field::Execute => match app.build_params() {
                Ok(params) => return Ok(LoopAction::ApplyAndExit(Box::new(params))),
                Err(err) => {
                    app.set_error_message(err.to_string());
                    return Ok(LoopAction::Continue);
                }
            },
            Field::NetworkMembership => {
                if let Err(err) = app
                    .token_draft
                    .toggle_network_membership(&app.shared_config_draft)
                {
                    app.set_error_message(err.to_string());
                } else {
                    app.mark_token_dirty();
                    app.set_success_message("updated token network selection");
                }
                return Ok(LoopAction::Continue);
            }
            Field::RefreshTokenMetadata => {
                return Ok(LoopAction::RefreshTokenMetadata);
            }
            Field::DestinationOverrides => {
                app.add_destination_override();
                return Ok(LoopAction::Continue);
            }
            Field::DeleteDestinationOverride => {
                app.request_delete_destination_override();
                return Ok(LoopAction::Continue);
            }
            Field::ManualApprovals => {
                app.add_manual_approval();
                return Ok(LoopAction::Continue);
            }
            Field::DeleteManualApproval => {
                app.request_delete_manual_approval();
                return Ok(LoopAction::Continue);
            }
            Field::SaveToken => {
                return Ok(LoopAction::SaveTokenAndApply);
            }
            Field::DeleteToken => {
                if let Err(err) = app.request_delete_token() {
                    app.set_error_message(err.to_string());
                }
                return Ok(LoopAction::Continue);
            }
            Field::SaveNetwork => {
                if let Err(err) = app.save_network_config() {
                    app.set_error_message(err.to_string());
                }
                return Ok(LoopAction::Continue);
            }
            Field::DeleteNetwork => {
                if let Err(err) = app.request_delete_network() {
                    app.set_error_message(err.to_string());
                }
                return Ok(LoopAction::Continue);
            }
            Field::SelectedToken
            | Field::EditingNetwork
            | Field::SelectedDestinationOverride
            | Field::SelectedManualApproval
            | Field::SelectedNetwork
            | Field::NetworkIsNative
            | Field::ShowAdvanced
            | Field::ChainConfigUseAsActive => {
                app.step_selected(1);
                return Ok(LoopAction::Continue);
            }
            _ => {}
        },
        _ => {}
    }

    app.edit_selected(key);
    Ok(LoopAction::Continue)
}

fn draw_ui(frame: &mut ratatui::Frame<'_>, app: &AppState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(18),
            Constraint::Length(8),
            Constraint::Length(3),
        ])
        .split(frame.area());

    let header_lines = vec![
        Line::from(Span::styled(
            "AgentPay Admin Policy Editor",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(app.view.description()),
        Line::from(
            View::ALL
                .iter()
                .map(|view| {
                    let style = if *view == app.view {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    Span::styled(format!(" {} ", view.title()), style)
                })
                .collect::<Vec<_>>(),
        ),
    ];
    let header =
        Paragraph::new(header_lines).block(Block::default().borders(Borders::ALL).title("Views"));
    frame.render_widget(header, areas[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(53), Constraint::Percentage(47)])
        .split(areas[1]);

    let fields = app.visible_fields();
    let items: Vec<ListItem<'_>> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let selected = index == app.selected;
            let style = if selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(field_display_label(*field), style),
                Span::styled(": ", style),
                Span::styled(field_value(app, *field), style),
            ]))
        })
        .collect();
    let form = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(app.view.title()),
    );
    frame.render_widget(form, body[0]);

    let panel = Paragraph::new(build_panel_lines(app))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(build_panel_title(app.view)),
        );
    frame.render_widget(panel, body[1]);

    let help = Paragraph::new(build_help_lines(app.view))
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL).title("Keys"));
    frame.render_widget(help, areas[2]);

    let default_message =
        "Ready. Start with tokens; saved tokens expand across all selected networks at bootstrap.";
    let message = app.message.as_deref().unwrap_or(default_message);
    let style = status_message_style(app);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(message, style)))
            .block(Block::default().borders(Borders::ALL).title("Status")),
        areas[3],
    );
}

fn status_message_style(app: &AppState) -> Style {
    if app.message.is_some() {
        app.message_level.style()
    } else {
        Style::default().fg(Color::Green)
    }
}

fn build_help_lines(view: View) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("Legend: [E] edit [S] select/toggle [A] Enter [R] read-only"),
        Line::from("Views: Tab/Shift+Tab or ]/["),
        Line::from("Move: ↑/↓ j/k Home End"),
        Line::from("Use: ←/→ h/l a/d Space Enter"),
        Line::from("Drafts: Ctrl+N new, Ctrl+R reload, Ctrl+S bootstrap"),
        Line::from("Paste: terminal paste appends into editable fields."),
    ];
    match view {
        View::Tokens => {
            lines.push(Line::from(
                "Network Multi-Select: use ←/→ h/l a/d to move the >focus< marker across saved networks, then Space/Enter to toggle the focused network.",
            ));
            lines.push(Line::from(
                "Tokens: Ctrl+O add override, Ctrl+M add manual approval",
            ));
            lines.push(Line::from(
                "RPC fields are [R]; use [A] Fetch Metadata to refresh them.",
            ));
            lines.push(Line::from(
                "Advanced [S] exposes gas, fee, tx count, and calldata limits.",
            ));
        }
        View::Networks => {
            lines.push(Line::from(
                "Networks: save an rpc url before fetching token metadata.",
            ));
        }
        View::Bootstrap => {
            lines.push(Line::from(
                "Bootstrap uses every saved token, override, and manual approval.",
            ));
        }
    }
    lines
}

fn build_panel_title(view: View) -> &'static str {
    match view {
        View::Tokens => "Token Inventory",
        View::Networks => "Network Inventory",
        View::Bootstrap => "Bootstrap Summary",
    }
}

fn build_panel_lines(app: &AppState) -> Vec<Line<'static>> {
    match app.view {
        View::Tokens => build_token_panel_lines(app),
        View::Networks => build_network_panel_lines(app),
        View::Bootstrap => build_bootstrap_panel_lines(app),
    }
}

fn build_token_panel_lines(app: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "Saved tokens",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if app.shared_config_draft.tokens.is_empty() {
        lines.push(Line::from("No saved tokens yet."));
    } else {
        for token_key in sorted_token_keys(&app.shared_config_draft)
            .into_iter()
            .take(6)
        {
            if let Some(profile) = app.shared_config_draft.tokens.get(&token_key) {
                lines.push(Line::from(render_saved_token_summary(&token_key, profile)));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Current token draft",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.extend(render_token_draft_lines(
        &app.token_draft,
        app.show_advanced,
    ));
    lines
}

fn build_network_panel_lines(app: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "Saved networks",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    if app.shared_config_draft.chains.is_empty() {
        lines.push(Line::from("No saved networks yet."));
    } else {
        for chain_key in sorted_chain_keys(&app.shared_config_draft) {
            let profile = &app.shared_config_draft.chains[&chain_key];
            let active =
                if app.shared_config_draft.chain_name.as_deref() == Some(chain_key.as_str()) {
                    " (active)"
                } else {
                    ""
                };
            let rpc = profile
                .rpc_url
                .as_deref()
                .map(|value| format!(" @ {value}"))
                .unwrap_or_default();
            lines.push(Line::from(format!(
                "{} — chain {}{}{}",
                chain_key, profile.chain_id, rpc, active
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Current network draft",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(format!(
        "key={} chain_id={} name={}",
        if app.network_draft.key.trim().is_empty() {
            "<new>"
        } else {
            app.network_draft.key.trim()
        },
        blank_if_empty(&app.network_draft.chain_id),
        blank_if_empty(&app.network_draft.name)
    )));
    lines.push(Line::from(format!(
        "rpc={}",
        blank_if_empty(&app.network_draft.rpc_url)
    )));
    lines.push(Line::from(format!(
        "active network: {}",
        bool_label(app.network_draft.use_as_active)
    )));
    lines
}

fn build_bootstrap_panel_lines(app: &AppState) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        "Saved token policies",
        Style::default().add_modifier(Modifier::BOLD),
    ))];
    match resolve_all_token_policies(&app.shared_config_draft) {
        Ok(token_policies) => {
            lines.push(Line::from(format!(
                "{} per-token policy bundle(s) are ready.",
                token_policies.len()
            )));
        }
        Err(err) => lines.push(Line::from(format!("Not ready yet: {}", err))),
    }
    match resolve_all_token_policies(&app.shared_config_draft)
        .and_then(|token_policies| {
            resolve_all_token_destination_overrides(&app.shared_config_draft, &token_policies)
                .map(|overrides| (token_policies, overrides))
        })
        .and_then(|(_token_policies, overrides)| {
            resolve_all_token_selectors(&app.shared_config_draft)
                .and_then(|token_selectors| {
                    resolve_all_token_manual_approval_policies(
                        &app.shared_config_draft,
                        &token_selectors,
                    )
                })
                .map(|manual| (overrides, manual))
        }) {
        Ok((overrides, manual_approvals)) => {
            lines.push(Line::from(format!(
                "{} destination override(s); {} manual approval policy/policies.",
                overrides.len(),
                manual_approvals.len()
            )));
        }
        Err(err) => lines.push(Line::from(format!("Validation: {}", err))),
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Execution",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(
        "Bootstrap applies every saved token across its selected networks.",
    ));
    lines
}

fn field_label(field: Field) -> &'static str {
    match field {
        Field::SelectedToken => "Selected Token",
        Field::TokenKey => "Token Key",
        Field::TokenName => "Token Name (RPC)",
        Field::TokenSymbol => "Token Symbol (RPC)",
        Field::NetworkMembership => "Network Multi-Select",
        Field::EditingNetwork => "Editing Network",
        Field::NetworkIsNative => "Native Asset",
        Field::NetworkAddress => "Token Address",
        Field::RefreshTokenMetadata => "Fetch Metadata",
        Field::TokenDecimals => "Token Decimals (RPC)",
        Field::PerTxLimit => "Per-Tx Limit",
        Field::DailyLimit => "Daily Limit",
        Field::WeeklyLimit => "Weekly Limit",
        Field::ShowAdvanced => "Advanced",
        Field::MaxGasPerChainWei => "Max Gas Spend Per Chain (wei)",
        Field::DailyMaxTxCount => "Daily Max Tx Count",
        Field::PerTxMaxFeePerGasGwei => "Max Fee Per Gas (gwei)",
        Field::PerTxMaxPriorityFeePerGasWei => "Max Priority Fee Per Gas (wei)",
        Field::PerTxMaxCalldataBytes => "Max Calldata Bytes",
        Field::DestinationOverrides => "Add Destination Override",
        Field::SelectedDestinationOverride => "Selected Override",
        Field::OverrideRecipientAddress => "Override Recipient",
        Field::OverridePerTxLimit => "Override Per-Tx Limit",
        Field::OverrideDailyLimit => "Override Daily Limit",
        Field::OverrideWeeklyLimit => "Override Weekly Limit",
        Field::OverrideMaxGasPerChainWei => "Override Gas/Chain (wei)",
        Field::OverrideDailyMaxTxCount => "Override Daily Tx Count",
        Field::OverridePerTxMaxFeePerGasGwei => "Override Max Fee/Gas (gwei)",
        Field::OverridePerTxMaxPriorityFeePerGasWei => "Override Priority Fee/Gas (wei)",
        Field::OverridePerTxMaxCalldataBytes => "Override Calldata Bytes",
        Field::DeleteDestinationOverride => "Delete Override",
        Field::ManualApprovals => "Add Manual Approval",
        Field::SelectedManualApproval => "Selected Manual Approval",
        Field::ManualApprovalRecipientAddress => "Approval Recipient",
        Field::ManualApprovalMinAmount => "Approval Min Amount",
        Field::ManualApprovalMaxAmount => "Approval Max Amount",
        Field::ManualApprovalPriority => "Approval Priority",
        Field::DeleteManualApproval => "Delete Manual Approval",
        Field::SaveToken => "Save Token",
        Field::DeleteToken => "Delete Token",
        Field::SelectedNetwork => "Selected Network",
        Field::ChainConfigKey => "Network Key",
        Field::ChainConfigId => "Network Chain ID",
        Field::ChainConfigName => "Network Name",
        Field::ChainConfigRpcUrl => "Network RPC URL",
        Field::ChainConfigUseAsActive => "Use As Active Network",
        Field::SaveNetwork => "Save Network",
        Field::DeleteNetwork => "Delete Network",
        Field::Execute => "Bootstrap",
    }
}

fn field_interaction(field: Field) -> FieldInteraction {
    match field {
        Field::SelectedToken
        | Field::NetworkMembership
        | Field::EditingNetwork
        | Field::NetworkIsNative
        | Field::ShowAdvanced
        | Field::SelectedDestinationOverride
        | Field::SelectedManualApproval
        | Field::SelectedNetwork
        | Field::ChainConfigUseAsActive => FieldInteraction::Select,
        Field::TokenKey
        | Field::NetworkAddress
        | Field::PerTxLimit
        | Field::DailyLimit
        | Field::WeeklyLimit
        | Field::MaxGasPerChainWei
        | Field::DailyMaxTxCount
        | Field::PerTxMaxFeePerGasGwei
        | Field::PerTxMaxPriorityFeePerGasWei
        | Field::PerTxMaxCalldataBytes
        | Field::OverrideRecipientAddress
        | Field::OverridePerTxLimit
        | Field::OverrideDailyLimit
        | Field::OverrideWeeklyLimit
        | Field::OverrideMaxGasPerChainWei
        | Field::OverrideDailyMaxTxCount
        | Field::OverridePerTxMaxFeePerGasGwei
        | Field::OverridePerTxMaxPriorityFeePerGasWei
        | Field::OverridePerTxMaxCalldataBytes
        | Field::ManualApprovalRecipientAddress
        | Field::ManualApprovalMinAmount
        | Field::ManualApprovalMaxAmount
        | Field::ManualApprovalPriority
        | Field::ChainConfigKey
        | Field::ChainConfigId
        | Field::ChainConfigName
        | Field::ChainConfigRpcUrl => FieldInteraction::Edit,
        Field::RefreshTokenMetadata
        | Field::DestinationOverrides
        | Field::DeleteDestinationOverride
        | Field::ManualApprovals
        | Field::DeleteManualApproval
        | Field::SaveToken
        | Field::DeleteToken
        | Field::SaveNetwork
        | Field::DeleteNetwork
        | Field::Execute => FieldInteraction::Action,
        Field::TokenName | Field::TokenSymbol | Field::TokenDecimals => FieldInteraction::ReadOnly,
    }
}

fn field_display_label(field: Field) -> String {
    format!(
        "{} {}",
        field_interaction(field).badge(),
        field_label(field)
    )
}

fn field_value(app: &AppState, field: Field) -> String {
    match field {
        Field::SelectedToken => app
            .token_draft
            .source_key
            .clone()
            .unwrap_or_else(|| "<new token>".to_string()),
        Field::TokenKey => blank_if_empty(&app.token_draft.key),
        Field::TokenName => blank_if_empty(&app.token_draft.name),
        Field::TokenSymbol => blank_if_empty(&app.token_draft.symbol),
        Field::NetworkMembership => {
            render_network_membership_value(&app.token_draft, &app.shared_config_draft)
        }
        Field::EditingNetwork => app
            .token_draft
            .selected_network()
            .map(|network| network.chain_key.clone())
            .unwrap_or_else(|| "<none>".to_string()),
        Field::NetworkIsNative => app
            .token_draft
            .selected_network()
            .map(|network| bool_label(network.is_native).to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        Field::NetworkAddress => app
            .token_draft
            .selected_network()
            .map(|network| {
                if network.is_native {
                    "native".to_string()
                } else {
                    blank_if_empty(&network.address)
                }
            })
            .unwrap_or_else(|| "n/a".to_string()),
        Field::RefreshTokenMetadata => "press Enter".to_string(),
        Field::TokenDecimals => app
            .token_draft
            .selected_network()
            .map(|network| blank_if_empty(&network.decimals))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::PerTxLimit => blank_if_empty(&app.token_draft.limits.per_tx_limit),
        Field::DailyLimit => blank_if_empty(&app.token_draft.limits.daily_limit),
        Field::WeeklyLimit => blank_if_empty(&app.token_draft.limits.weekly_limit),
        Field::ShowAdvanced => bool_label(app.show_advanced).to_string(),
        Field::MaxGasPerChainWei => {
            display_unlimited_if_empty(&app.token_draft.limits.max_gas_per_chain_wei)
        }
        Field::DailyMaxTxCount => {
            display_unlimited_if_empty(&app.token_draft.limits.daily_max_tx_count)
        }
        Field::PerTxMaxFeePerGasGwei => {
            display_unlimited_if_empty(&app.token_draft.limits.per_tx_max_fee_per_gas_gwei)
        }
        Field::PerTxMaxPriorityFeePerGasWei => {
            display_unlimited_if_empty(&app.token_draft.limits.per_tx_max_priority_fee_per_gas_wei)
        }
        Field::PerTxMaxCalldataBytes => {
            display_unlimited_if_empty(&app.token_draft.limits.per_tx_max_calldata_bytes)
        }
        Field::DestinationOverrides => format!(
            "{} saved draft(s) — press Enter",
            app.token_draft.destination_overrides.len()
        ),
        Field::SelectedDestinationOverride => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(render_destination_override_label)
            .unwrap_or_else(|| "<none>".to_string()),
        Field::OverrideRecipientAddress => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| blank_if_empty(&item.recipient_address))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverridePerTxLimit => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| blank_if_empty(&item.limits.per_tx_limit))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverrideDailyLimit => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| blank_if_empty(&item.limits.daily_limit))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverrideWeeklyLimit => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| blank_if_empty(&item.limits.weekly_limit))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverrideMaxGasPerChainWei => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| display_unlimited_if_empty(&item.limits.max_gas_per_chain_wei))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverrideDailyMaxTxCount => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| display_unlimited_if_empty(&item.limits.daily_max_tx_count))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverridePerTxMaxFeePerGasGwei => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| display_unlimited_if_empty(&item.limits.per_tx_max_fee_per_gas_gwei))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverridePerTxMaxPriorityFeePerGasWei => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| {
                display_unlimited_if_empty(&item.limits.per_tx_max_priority_fee_per_gas_wei)
            })
            .unwrap_or_else(|| "n/a".to_string()),
        Field::OverridePerTxMaxCalldataBytes => app
            .token_draft
            .destination_overrides
            .get(app.token_draft.selected_override)
            .map(|item| display_unlimited_if_empty(&item.limits.per_tx_max_calldata_bytes))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::DeleteDestinationOverride => "press Enter; repeat to confirm".to_string(),
        Field::ManualApprovals => format!(
            "{} saved draft(s) — press Enter",
            app.token_draft.manual_approvals.len()
        ),
        Field::SelectedManualApproval => app
            .token_draft
            .manual_approvals
            .get(app.token_draft.selected_manual_approval)
            .map(render_manual_approval_label)
            .unwrap_or_else(|| "<none>".to_string()),
        Field::ManualApprovalRecipientAddress => app
            .token_draft
            .manual_approvals
            .get(app.token_draft.selected_manual_approval)
            .map(|item| blank_if_empty(&item.recipient_address))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::ManualApprovalMinAmount => app
            .token_draft
            .manual_approvals
            .get(app.token_draft.selected_manual_approval)
            .map(|item| blank_if_empty(&item.min_amount))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::ManualApprovalMaxAmount => app
            .token_draft
            .manual_approvals
            .get(app.token_draft.selected_manual_approval)
            .map(|item| blank_if_empty(&item.max_amount))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::ManualApprovalPriority => app
            .token_draft
            .manual_approvals
            .get(app.token_draft.selected_manual_approval)
            .map(|item| blank_if_empty(&item.priority))
            .unwrap_or_else(|| "n/a".to_string()),
        Field::DeleteManualApproval => "press Enter; repeat to confirm".to_string(),
        Field::SaveToken => "press Enter".to_string(),
        Field::DeleteToken => "press Enter; repeat to confirm".to_string(),
        Field::SelectedNetwork => app
            .network_draft
            .source_key
            .clone()
            .unwrap_or_else(|| "<new network>".to_string()),
        Field::ChainConfigKey => blank_if_empty(&app.network_draft.key),
        Field::ChainConfigId => blank_if_empty(&app.network_draft.chain_id),
        Field::ChainConfigName => blank_if_empty(&app.network_draft.name),
        Field::ChainConfigRpcUrl => blank_if_empty(&app.network_draft.rpc_url),
        Field::ChainConfigUseAsActive => bool_label(app.network_draft.use_as_active).to_string(),
        Field::SaveNetwork => "press Enter".to_string(),
        Field::DeleteNetwork => "press Enter; repeat to confirm".to_string(),
        Field::Execute => "press Enter".to_string(),
    }
}

fn blank_if_empty(value: &str) -> String {
    if value.trim().is_empty() {
        "<blank>".to_string()
    } else {
        value.trim().to_string()
    }
}

fn display_unlimited_if_empty(value: &str) -> String {
    if value.trim().is_empty() {
        "unlimited".to_string()
    } else {
        value.trim().to_string()
    }
}

fn field_uses_network_draft(field: Field) -> bool {
    matches!(
        field,
        Field::ChainConfigKey
            | Field::ChainConfigId
            | Field::ChainConfigName
            | Field::ChainConfigRpcUrl
    )
}

fn render_network_membership_value(token_draft: &TokenDraft, config: &WlfiConfig) -> String {
    let available = sorted_chain_keys(config);
    if available.is_empty() {
        return "no saved networks; add one in Networks view first".to_string();
    }
    let focus_index = token_draft
        .available_network_index
        .min(available.len().saturating_sub(1));
    let selected = available
        .iter()
        .enumerate()
        .map(|(index, chain_key)| {
            let checked = token_draft
                .networks
                .iter()
                .any(|network| network.chain_key == *chain_key);
            let label = if index == focus_index {
                format!(">{chain_key}<")
            } else {
                chain_key.clone()
            };
            format!("[{}] {}", if checked { "x" } else { " " }, label)
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("focus {}/{} {}", focus_index + 1, available.len(), selected)
}

fn render_destination_override_label(override_item: &DestinationOverrideDraft) -> String {
    if override_item.recipient_address.trim().is_empty() {
        "<recipient required>".to_string()
    } else {
        override_item.recipient_address.trim().to_string()
    }
}

fn render_manual_approval_label(manual_approval: &ManualApprovalDraft) -> String {
    let recipient = if manual_approval.recipient_address.trim().is_empty() {
        "all recipients"
    } else {
        manual_approval.recipient_address.trim()
    };
    format!(
        "{} -> {}..{}",
        recipient,
        blank_if_empty(&manual_approval.min_amount),
        blank_if_empty(&manual_approval.max_amount)
    )
}

fn render_token_draft_lines(token_draft: &TokenDraft, show_advanced: bool) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(format!(
        "{} ({})",
        if token_draft.name.trim().is_empty() {
            "<name pending>"
        } else {
            token_draft.name.trim()
        },
        if token_draft.symbol.trim().is_empty() {
            token_draft.key.trim()
        } else {
            token_draft.symbol.trim()
        }
    ))];
    if token_draft.networks.is_empty() {
        lines.push(Line::from("No network mappings yet."));
    } else {
        lines.push(Line::from("Network mappings:"));
        for network in token_draft.networks.iter().take(4) {
            let address = if network.is_native {
                "native".to_string()
            } else {
                blank_if_empty(&network.address)
            };
            lines.push(Line::from(format!(
                "- {} / chain {} / decimals {} / {}",
                network.chain_key,
                blank_if_empty(&network.chain_id),
                blank_if_empty(&network.decimals),
                address
            )));
        }
    }
    lines.push(Line::from(format!(
        "Default limits: per-tx {} / daily {} / weekly {}.",
        blank_if_empty(&token_draft.limits.per_tx_limit),
        blank_if_empty(&token_draft.limits.daily_limit),
        blank_if_empty(&token_draft.limits.weekly_limit),
    )));
    if show_advanced {
        lines.push(Line::from(format!(
            "Advanced limits: gas {} wei / daily tx {} / max fee {} gwei / priority fee {} wei / calldata {} bytes.",
            display_unlimited_if_empty(&token_draft.limits.max_gas_per_chain_wei),
            display_unlimited_if_empty(&token_draft.limits.daily_max_tx_count),
            display_unlimited_if_empty(&token_draft.limits.per_tx_max_fee_per_gas_gwei),
            display_unlimited_if_empty(&token_draft.limits.per_tx_max_priority_fee_per_gas_wei),
            display_unlimited_if_empty(&token_draft.limits.per_tx_max_calldata_bytes),
        )));
    }
    lines.push(Line::from(format!(
        "{} destination override(s); {} manual approval policy/policies.",
        token_draft.destination_overrides.len(),
        token_draft.manual_approvals.len()
    )));
    lines
}

fn render_saved_token_summary(token_key: &str, profile: &TokenProfile) -> String {
    let decimals = profile
        .chains
        .values()
        .next()
        .map(|chain| chain.decimals)
        .unwrap_or(18);
    let limits = LimitDraft::from_policy(
        profile
            .default_policy
            .as_ref()
            .or_else(|| first_chain_policy(profile)),
        decimals,
    );
    let networks = profile
        .chains
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} ({}) — networks [{}] — default per-tx {} / daily {} / weekly {} — overrides {} — manual approvals {}",
        profile.name.as_deref().unwrap_or(&profile.symbol),
        token_key,
        networks,
        blank_if_empty(&limits.per_tx_limit),
        blank_if_empty(&limits.daily_limit),
        blank_if_empty(&limits.weekly_limit),
        profile.destination_overrides.len(),
        profile.manual_approval_policies.len(),
    )
}

fn first_chain_policy(profile: &TokenProfile) -> Option<&TokenPolicyProfile> {
    profile
        .chains
        .values()
        .find_map(|chain_profile| chain_profile.default_policy.as_ref())
}

fn sorted_token_keys(config: &WlfiConfig) -> Vec<String> {
    let mut keys = config.tokens.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

fn sorted_chain_keys(config: &WlfiConfig) -> Vec<String> {
    let mut keys = config.chains.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

fn cycle_index(index: &mut usize, len: usize, direction: i8) {
    if len == 0 {
        *index = 0;
        return;
    }
    if direction < 0 {
        *index = if *index == 0 { len - 1 } else { *index - 1 };
    } else {
        *index = (*index + 1) % len;
    }
}

fn validate_limit_draft(limits: &LimitDraft, decimals: u8) -> Result<()> {
    if limits.is_empty() {
        return Ok(());
    }
    parse_required_token_amount("per-tx limit", &limits.per_tx_limit, decimals)?;
    parse_required_token_amount("daily limit", &limits.daily_limit, decimals)?;
    parse_required_token_amount("weekly limit", &limits.weekly_limit, decimals)?;
    if !limits.max_gas_per_chain_wei.trim().is_empty() {
        parse_positive_u128("max gas spend per chain", &limits.max_gas_per_chain_wei)?;
    }
    parse_optional_non_negative_u128("daily max tx count", &limits.daily_max_tx_count)?;
    parse_optional_gwei_amount("max fee per gas", Some(&limits.per_tx_max_fee_per_gas_gwei))?;
    parse_optional_non_negative_u128(
        "max priority fee per gas",
        &limits.per_tx_max_priority_fee_per_gas_wei,
    )?;
    parse_optional_non_negative_u128("max calldata bytes", &limits.per_tx_max_calldata_bytes)?;
    Ok(())
}

fn display_policy_amount(
    decimal_value: Option<&str>,
    raw_value: Option<&str>,
    legacy_value: Option<f64>,
    decimals: u8,
) -> Result<String> {
    if let Some(value) = decimal_value {
        if !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
    }
    if let Some(value) = raw_value {
        if !value.trim().is_empty() {
            let raw = parse_positive_u128("policy amount", value)?;
            return format_token_amount(raw, decimals);
        }
    }
    if let Some(value) = legacy_value {
        return format_token_amount(
            parse_legacy_amount("policy amount", value, decimals)?,
            decimals,
        );
    }
    Ok(String::new())
}

fn display_policy_gwei(gwei_value: Option<&str>, raw_wei_value: Option<&str>) -> Result<String> {
    if let Some(value) = gwei_value {
        if !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
    }
    if let Some(value) = raw_wei_value {
        if !value.trim().is_empty() {
            return format_gwei_amount(parse_non_negative_u128("policy gwei", value)?);
        }
    }
    Ok(String::new())
}

fn optional_trimmed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn optional_non_zero_string(value: u128) -> Option<String> {
    (value > 0).then(|| value.to_string())
}

fn parse_optional_non_negative_u128(label: &str, value: &str) -> Result<u128> {
    if value.trim().is_empty() {
        Ok(0)
    } else {
        parse_non_negative_u128(label, value)
    }
}

fn display_manual_amount(
    decimal_value: Option<&str>,
    raw_value: Option<&str>,
    legacy_value: Option<f64>,
    decimals: u8,
) -> Result<String> {
    if let Some(value) = decimal_value {
        if !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
    }
    if let Some(value) = raw_value {
        if !value.trim().is_empty() {
            return format_token_amount(
                parse_positive_u128("manual approval amount", value)?,
                decimals,
            );
        }
    }
    if let Some(value) = legacy_value {
        return format_token_amount(
            parse_legacy_amount("manual approval amount", value, decimals)?,
            decimals,
        );
    }
    Ok(String::new())
}

fn resolve_all_token_policies(config: &WlfiConfig) -> Result<Vec<TokenPolicyConfig>> {
    let mut token_policies = Vec::new();
    for token_key in sorted_token_keys(config) {
        let token_profile = &config.tokens[&token_key];
        for (chain_key, chain_profile) in token_profile.chains.iter() {
            let Some(policy) = token_profile
                .default_policy
                .as_ref()
                .or(chain_profile.default_policy.as_ref())
            else {
                continue;
            };
            token_policies.push(resolve_token_policy_config(
                &token_key,
                token_profile,
                chain_key,
                chain_profile,
                policy,
            )?);
        }
    }
    Ok(token_policies)
}

fn resolve_all_token_selectors(config: &WlfiConfig) -> Result<Vec<TokenSelectorConfig>> {
    let mut token_selectors = Vec::new();
    for token_key in sorted_token_keys(config) {
        let token_profile = &config.tokens[&token_key];
        let mut chain_keys = token_profile.chains.keys().cloned().collect::<Vec<_>>();
        chain_keys.sort();
        for chain_key in chain_keys {
            let chain_profile = &token_profile.chains[&chain_key];
            token_selectors.push(resolve_token_selector_config(
                &token_key,
                token_profile,
                &chain_key,
                chain_profile,
            )?);
        }
    }
    Ok(token_selectors)
}

fn resolve_token_policy_config(
    token_key: &str,
    token_profile: &TokenProfile,
    chain_key: &str,
    chain_profile: &TokenChainProfile,
    policy: &TokenPolicyProfile,
) -> Result<TokenPolicyConfig> {
    let decimals = chain_profile.decimals;
    let per_tx_max_wei = resolve_required_policy_amount(
        "per-tx limit",
        policy.per_tx_amount_decimal.as_deref(),
        policy.per_tx_limit.as_deref(),
        policy.per_tx_amount,
        decimals,
    )?;
    let daily_max_wei = resolve_required_policy_amount(
        "daily limit",
        policy.daily_amount_decimal.as_deref(),
        policy.daily_limit.as_deref(),
        policy.daily_amount,
        decimals,
    )?;
    let weekly_max_wei = resolve_required_policy_amount(
        "weekly limit",
        policy.weekly_amount_decimal.as_deref(),
        policy.weekly_limit.as_deref(),
        policy.weekly_amount,
        decimals,
    )?;

    Ok(TokenPolicyConfig {
        token_key: token_key.to_string(),
        symbol: token_profile.symbol.clone(),
        chain_key: chain_key.to_string(),
        chain_id: chain_profile.chain_id,
        is_native: chain_profile.is_native,
        address: if chain_profile.is_native {
            None
        } else {
            Some(crate::TokenAddress::parse(
                &format!("token '{}:{}'", token_key, chain_key),
                chain_profile.chain_id,
                chain_profile.address.as_deref().unwrap_or_default(),
            )?)
        },
        per_tx_max_wei,
        daily_max_wei,
        weekly_max_wei,
        max_gas_per_chain_wei: resolve_optional_policy_value(
            policy.max_gas_per_chain_wei.as_deref(),
        )?,
        daily_max_tx_count: resolve_optional_policy_value(policy.daily_max_tx_count.as_deref())?,
        per_tx_max_fee_per_gas_wei: resolve_optional_gwei_or_wei(
            policy.per_tx_max_fee_per_gas_gwei.as_deref(),
            policy.per_tx_max_fee_per_gas_wei.as_deref(),
        )?,
        per_tx_max_priority_fee_per_gas_wei: resolve_optional_policy_value(
            policy.per_tx_max_priority_fee_per_gas_wei.as_deref(),
        )?,
        per_tx_max_calldata_bytes: resolve_optional_policy_value(
            policy.per_tx_max_calldata_bytes.as_deref(),
        )?,
    })
}

fn resolve_all_token_destination_overrides(
    config: &WlfiConfig,
    token_policies: &[TokenPolicyConfig],
) -> Result<Vec<TokenDestinationPolicyOverride>> {
    let mut overrides = Vec::new();
    let mut seen = BTreeSet::new();
    for token_key in sorted_token_keys(config) {
        let token_profile = &config.tokens[&token_key];
        for override_profile in &token_profile.destination_overrides {
            for (chain_key, chain_profile) in &token_profile.chains {
                let recipient = crate::parse_token_recipient(
                    "destination override recipient",
                    chain_profile.chain_id,
                    &override_profile.recipient,
                )?;
                if !seen.insert((token_key.clone(), chain_key.clone(), recipient.clone())) {
                    bail!(
                        "duplicate per-token destination override: {}:{} for {}",
                        token_key,
                        chain_key,
                        recipient
                    );
                }
                let default_policy = token_policies
                    .iter()
                    .find(|policy| policy.token_key == token_key && policy.chain_key == *chain_key)
                    .with_context(|| {
                        format!(
                            "destination override references unknown token selector '{}:{}'",
                            token_key, chain_key
                        )
                    })?;
                let default_limits = ResolvedLimitFields::from_token_policy(default_policy);
                let resolved = TokenDestinationPolicyOverride {
                    token_key: token_key.clone(),
                    chain_key: chain_key.clone(),
                    recipient: recipient.clone(),
                    per_tx_max_wei: resolve_policy_amount_or_default(
                        override_profile.limits.per_tx_amount_decimal.as_deref(),
                        override_profile.limits.per_tx_limit.as_deref(),
                        override_profile.limits.per_tx_amount,
                        default_limits.per_tx_max_wei,
                        chain_profile.decimals,
                    )?,
                    daily_max_wei: resolve_policy_amount_or_default(
                        override_profile.limits.daily_amount_decimal.as_deref(),
                        override_profile.limits.daily_limit.as_deref(),
                        override_profile.limits.daily_amount,
                        default_limits.daily_max_wei,
                        chain_profile.decimals,
                    )?,
                    weekly_max_wei: resolve_policy_amount_or_default(
                        override_profile.limits.weekly_amount_decimal.as_deref(),
                        override_profile.limits.weekly_limit.as_deref(),
                        override_profile.limits.weekly_amount,
                        default_limits.weekly_max_wei,
                        chain_profile.decimals,
                    )?,
                    max_gas_per_chain_wei: resolve_optional_policy_value_or_default(
                        override_profile.limits.max_gas_per_chain_wei.as_deref(),
                        default_limits.max_gas_per_chain_wei,
                    )?,
                    daily_max_tx_count: resolve_optional_policy_value_or_default(
                        override_profile.limits.daily_max_tx_count.as_deref(),
                        default_limits.daily_max_tx_count,
                    )?,
                    per_tx_max_fee_per_gas_wei: resolve_gwei_or_wei_or_default(
                        override_profile
                            .limits
                            .per_tx_max_fee_per_gas_gwei
                            .as_deref(),
                        override_profile
                            .limits
                            .per_tx_max_fee_per_gas_wei
                            .as_deref(),
                        default_limits.per_tx_max_fee_per_gas_wei,
                    )?,
                    per_tx_max_priority_fee_per_gas_wei: resolve_optional_policy_value_or_default(
                        override_profile
                            .limits
                            .per_tx_max_priority_fee_per_gas_wei
                            .as_deref(),
                        default_limits.per_tx_max_priority_fee_per_gas_wei,
                    )?,
                    per_tx_max_calldata_bytes: resolve_optional_policy_value_or_default(
                        override_profile.limits.per_tx_max_calldata_bytes.as_deref(),
                        default_limits.per_tx_max_calldata_bytes,
                    )?,
                };
                if ResolvedLimitFields::from_override(&resolved) == default_limits {
                    continue;
                }
                validate_destination_override_overlay(
                    &recipient.to_string(),
                    &default_limits,
                    &ResolvedLimitFields::from_override(&resolved),
                )?;
                overrides.push(resolved);
            }
        }
    }
    Ok(overrides)
}

fn resolve_all_token_manual_approval_policies(
    config: &WlfiConfig,
    token_selectors: &[TokenSelectorConfig],
) -> Result<Vec<TokenManualApprovalPolicyConfig>> {
    let mut policies = Vec::new();
    for token_key in sorted_token_keys(config) {
        let token_profile = &config.tokens[&token_key];
        for manual_profile in &token_profile.manual_approval_policies {
            for (chain_key, chain_profile) in &token_profile.chains {
                let token_selector = token_selectors
                    .iter()
                    .find(|selector| {
                        selector.token_key == token_key && selector.chain_key == *chain_key
                    })
                    .with_context(|| {
                        format!(
                            "manual approval references unknown token selector '{}:{}'",
                            token_key, chain_key
                        )
                    })?;
                policies.push(TokenManualApprovalPolicyConfig {
                    token_key: token_key.clone(),
                    symbol: token_profile.symbol.clone(),
                    chain_key: chain_key.clone(),
                    chain_id: chain_profile.chain_id,
                    is_native: token_selector.is_native,
                    address: token_selector.address.clone(),
                    priority: if manual_profile.priority == 0 {
                        100
                    } else {
                        manual_profile.priority
                    },
                    recipient: match manual_profile.recipient.as_deref() {
                        Some(value) if !value.trim().is_empty() => {
                            Some(crate::parse_token_recipient(
                                "manual approval recipient",
                                chain_profile.chain_id,
                                value,
                            )?)
                        }
                        _ => None,
                    },
                    min_amount_wei: resolve_required_policy_amount(
                        "manual approval min amount",
                        manual_profile.min_amount_decimal.as_deref(),
                        manual_profile.min_amount_wei.as_deref(),
                        manual_profile.min_amount,
                        chain_profile.decimals,
                    )?,
                    max_amount_wei: resolve_required_policy_amount(
                        "manual approval max amount",
                        manual_profile.max_amount_decimal.as_deref(),
                        manual_profile.max_amount_wei.as_deref(),
                        manual_profile.max_amount,
                        chain_profile.decimals,
                    )?,
                });
            }
        }
    }
    Ok(policies)
}

fn resolve_token_selector_config(
    token_key: &str,
    token_profile: &TokenProfile,
    chain_key: &str,
    chain_profile: &TokenChainProfile,
) -> Result<TokenSelectorConfig> {
    Ok(TokenSelectorConfig {
        token_key: token_key.to_string(),
        symbol: token_profile.symbol.clone(),
        chain_key: chain_key.to_string(),
        chain_id: chain_profile.chain_id,
        is_native: chain_profile.is_native,
        address: chain_profile_address(token_key, chain_key, chain_profile)?,
    })
}

fn chain_profile_address(
    token_key: &str,
    chain_key: &str,
    chain_profile: &TokenChainProfile,
) -> Result<Option<crate::TokenAddress>> {
    chain_profile
        .address
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            crate::TokenAddress::parse(
                &format!("token '{}:{}'", token_key, chain_key),
                chain_profile.chain_id,
                value,
            )
        })
        .transpose()
}

fn resolve_required_policy_amount(
    label: &str,
    decimal_value: Option<&str>,
    raw_value: Option<&str>,
    legacy_value: Option<f64>,
    decimals: u8,
) -> Result<u128> {
    if let Some(value) = decimal_value {
        if !value.trim().is_empty() {
            return parse_required_token_amount(label, value, decimals);
        }
    }
    if let Some(value) = raw_value {
        if !value.trim().is_empty() {
            return parse_positive_u128(label, value);
        }
    }
    if let Some(value) = legacy_value {
        return parse_legacy_amount(label, value, decimals);
    }
    bail!("{label} is required");
}

fn resolve_policy_amount_or_default(
    decimal_value: Option<&str>,
    raw_value: Option<&str>,
    legacy_value: Option<f64>,
    default_value: u128,
    decimals: u8,
) -> Result<u128> {
    if let Some(value) = decimal_value {
        if !value.trim().is_empty() {
            return parse_required_token_amount("policy amount", value, decimals);
        }
    }
    if let Some(value) = raw_value {
        if !value.trim().is_empty() {
            return parse_positive_u128("policy amount", value);
        }
    }
    if let Some(value) = legacy_value {
        return parse_legacy_amount("policy amount", value, decimals);
    }
    Ok(default_value)
}

fn resolve_optional_gwei_or_wei(
    gwei_value: Option<&str>,
    raw_wei_value: Option<&str>,
) -> Result<u128> {
    if let Some(value) = gwei_value {
        if !value.trim().is_empty() {
            return parse_optional_gwei_amount("gwei value", Some(value));
        }
    }
    resolve_optional_policy_value(raw_wei_value)
}

fn resolve_gwei_or_wei_or_default(
    gwei_value: Option<&str>,
    raw_wei_value: Option<&str>,
    default_value: u128,
) -> Result<u128> {
    if let Some(value) = gwei_value {
        if !value.trim().is_empty() {
            return parse_optional_gwei_amount("gwei value", Some(value));
        }
    }
    resolve_optional_policy_value_or_default(raw_wei_value, default_value)
}

fn resolve_optional_policy_value(value: Option<&str>) -> Result<u128> {
    match value {
        Some(value) if !value.trim().is_empty() => parse_non_negative_u128("policy value", value),
        _ => Ok(0),
    }
}

fn resolve_optional_policy_value_or_default(
    value: Option<&str>,
    default_value: u128,
) -> Result<u128> {
    match value {
        Some(value) if !value.trim().is_empty() => parse_non_negative_u128("policy value", value),
        _ => Ok(default_value),
    }
}

fn validate_destination_override_overlay(
    recipient: &str,
    defaults: &ResolvedLimitFields,
    override_limits: &ResolvedLimitFields,
) -> Result<()> {
    validate_overlay_limit(
        recipient,
        "per-tx max",
        defaults.per_tx_max_wei,
        override_limits.per_tx_max_wei,
    )?;
    validate_overlay_limit(
        recipient,
        "daily max",
        defaults.daily_max_wei,
        override_limits.daily_max_wei,
    )?;
    validate_overlay_limit(
        recipient,
        "weekly max",
        defaults.weekly_max_wei,
        override_limits.weekly_max_wei,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "gas max",
        defaults.max_gas_per_chain_wei,
        override_limits.max_gas_per_chain_wei,
    )?;
    validate_optional_overlay_limit(
        recipient,
        "daily tx count",
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

fn validate_overlay_limit(
    recipient: &str,
    label: &str,
    defaults: u128,
    overlay: u128,
) -> Result<()> {
    if overlay > defaults {
        bail!(
            "destination override for {recipient} must not increase {label} above the default value"
        );
    }
    Ok(())
}

fn validate_optional_overlay_limit(
    recipient: &str,
    label: &str,
    defaults: u128,
    overlay: u128,
) -> Result<()> {
    match (defaults == 0, overlay == 0) {
        (true, false) => bail!(
            "destination override for {recipient} must keep {label} disabled because the default value is disabled"
        ),
        (false, true) => bail!(
            "destination override for {recipient} must keep {label} enabled because the default value is enabled"
        ),
        _ if overlay > defaults => bail!(
            "destination override for {recipient} must not increase {label} above the default value"
        ),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_with_progress, build_bootstrap_panel_lines, build_token_panel_lines,
        handle_key_event, handle_terminal_event, resolve_all_token_manual_approval_policies,
        resolve_all_token_selectors, resolve_gwei_or_wei_or_default, resolve_optional_gwei_or_wei,
        resolve_optional_policy_value, resolve_optional_policy_value_or_default,
        resolve_policy_amount_or_default, resolve_required_policy_amount,
        run_save_network_and_apply, run_save_token_and_apply, status_message_style,
        validate_destination_override_overlay, validate_optional_overlay_limit,
        validate_overlay_limit, AppState, ChainProfile, Event, Field, KeyCode, KeyEvent,
        KeyModifiers, LoopAction, ManualApprovalDraft, MessageLevel, NetworkDraft,
        PendingDeleteAction, PendingDiscardAction, ResolvedLimitFields, TokenChainProfile,
        TokenDestinationOverrideProfile, TokenDraft, TokenManualApprovalProfile, TokenNetworkDraft,
        TokenPolicyProfile, TokenProfile, View, WlfiConfig,
    };
    use crate::shared_config::WalletProfile;
    use ratatui::{backend::TestBackend, style::Color, Terminal};
    use std::collections::BTreeMap;
    use std::fs;
    use uuid::Uuid;

    fn sample_policy(per_tx: &str, daily: &str, weekly: &str) -> TokenPolicyProfile {
        TokenPolicyProfile {
            per_tx_amount: None,
            daily_amount: None,
            weekly_amount: None,
            per_tx_amount_decimal: Some(per_tx.to_string()),
            daily_amount_decimal: Some(daily.to_string()),
            weekly_amount_decimal: Some(weekly.to_string()),
            per_tx_limit: Some(per_tx.to_string()),
            daily_limit: Some(daily.to_string()),
            weekly_limit: Some(weekly.to_string()),
            max_gas_per_chain_wei: Some("1000000000000000".to_string()),
            daily_max_tx_count: Some("0".to_string()),
            per_tx_max_fee_per_gas_gwei: Some("25".to_string()),
            per_tx_max_fee_per_gas_wei: Some("25000000000".to_string()),
            per_tx_max_priority_fee_per_gas_wei: Some("0".to_string()),
            per_tx_max_calldata_bytes: Some("0".to_string()),
            extra: BTreeMap::new(),
        }
    }

    fn empty_config() -> WlfiConfig {
        WlfiConfig {
            rpc_url: None,
            chain_id: None,
            chain_name: None,
            daemon_socket: None,
            state_file: None,
            rust_bin_dir: None,
            agent_key_id: None,
            agent_auth_token: None,
            wallet: None,
            chains: BTreeMap::new(),
            tokens: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    fn sample_config() -> WlfiConfig {
        let mut config = empty_config();
        config.chains.insert(
            "eth".to_string(),
            ChainProfile {
                chain_id: 1,
                name: "eth".to_string(),
                rpc_url: Some("https://rpc.ethereum.example".to_string()),
                extra: BTreeMap::new(),
            },
        );
        config.chains.insert(
            "bsc".to_string(),
            ChainProfile {
                chain_id: 56,
                name: "bsc".to_string(),
                rpc_url: Some("https://rpc.bsc.example".to_string()),
                extra: BTreeMap::new(),
            },
        );
        config.tokens.insert(
            "usd1".to_string(),
            TokenProfile {
                name: Some("USD1".to_string()),
                symbol: "USD1".to_string(),
                default_policy: Some(sample_policy("10", "100", "500")),
                destination_overrides: vec![TokenDestinationOverrideProfile {
                    recipient: "0x1000000000000000000000000000000000000001".to_string(),
                    limits: sample_policy("5", "50", "200"),
                }],
                manual_approval_policies: vec![TokenManualApprovalProfile {
                    priority: 120,
                    recipient: None,
                    min_amount: None,
                    max_amount: None,
                    min_amount_decimal: Some("250".to_string()),
                    max_amount_decimal: Some("500".to_string()),
                    min_amount_wei: None,
                    max_amount_wei: None,
                    extra: BTreeMap::new(),
                }],
                chains: BTreeMap::from([
                    (
                        "eth".to_string(),
                        TokenChainProfile {
                            chain_id: 1,
                            is_native: false,
                            address: Some("0x1000000000000000000000000000000000000000".to_string()),
                            decimals: 6,
                            default_policy: Some(sample_policy("10", "100", "500")),
                            extra: BTreeMap::new(),
                        },
                    ),
                    (
                        "bsc".to_string(),
                        TokenChainProfile {
                            chain_id: 56,
                            is_native: false,
                            address: Some("0x2000000000000000000000000000000000000000".to_string()),
                            decimals: 6,
                            default_policy: Some(sample_policy("10", "100", "500")),
                            extra: BTreeMap::new(),
                        },
                    ),
                ]),
                extra: BTreeMap::new(),
            },
        );
        config
    }

    fn temp_config_path(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("agentpay-admin-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp config dir");
        dir.join("config.json")
    }

    #[test]
    fn view_and_message_level_helpers_cover_navigation_and_labels() {
        assert_eq!(View::Tokens.title(), "Tokens");
        assert!(View::Tokens.description().contains("source of truth"));
        assert_eq!(View::Tokens.next(), View::Networks);
        assert_eq!(View::Networks.next(), View::Bootstrap);
        assert_eq!(View::Bootstrap.next(), View::Tokens);
        assert_eq!(View::Tokens.previous(), View::Bootstrap);
        assert_eq!(View::Networks.previous(), View::Tokens);
        assert_eq!(View::Bootstrap.previous(), View::Networks);

        assert_eq!(
            MessageLevel::Info.style(),
            ratatui::style::Style::default().fg(Color::Cyan)
        );
        assert_eq!(
            MessageLevel::Success.style(),
            ratatui::style::Style::default().fg(Color::Green)
        );
        assert_eq!(
            MessageLevel::Error.style(),
            ratatui::style::Style::default().fg(Color::Red)
        );

        let mut app = AppState::from_shared_config(&sample_config(), false);
        assert_eq!(app.active_draft_label(), "token draft");
        app.token_dirty = true;
        assert!(app.active_draft_dirty());

        app.view = View::Networks;
        assert_eq!(app.active_draft_label(), "network draft");
        app.network_dirty = true;
        assert!(app.active_draft_dirty());

        app.view = View::Bootstrap;
        assert_eq!(app.active_draft_label(), "current view");
        assert!(!app.active_draft_dirty());
    }

    #[test]
    fn limit_draft_roundtrip_and_empty_policy_helpers_cover_chain_paths() {
        let empty = super::LimitDraft::from_policy(None, 6);
        assert_eq!(empty, super::LimitDraft::empty());
        assert!(empty.is_empty());
        assert!(empty
            .as_token_level_policy(6)
            .expect("empty token-level policy")
            .is_none());
        assert!(empty
            .as_chain_policy(6)
            .expect("empty chain policy")
            .is_none());

        let draft =
            super::LimitDraft::from_policy(Some(&sample_policy("12.5", "100", "500.25")), 6);
        assert_eq!(draft.per_tx_limit, "12.5");
        assert_eq!(draft.daily_limit, "100");
        assert_eq!(draft.weekly_limit, "500.25");
        assert_eq!(draft.max_gas_per_chain_wei, "1000000000000000");
        assert_eq!(draft.per_tx_max_fee_per_gas_gwei, "25");

        let token_policy = draft
            .as_token_level_policy(6)
            .expect("token-level policy")
            .expect("present token-level policy");
        assert_eq!(token_policy.per_tx_amount_decimal.as_deref(), Some("12.5"));
        assert_eq!(token_policy.daily_amount_decimal.as_deref(), Some("100"));
        assert_eq!(
            token_policy.weekly_amount_decimal.as_deref(),
            Some("500.25")
        );
        assert_eq!(
            token_policy.per_tx_max_fee_per_gas_wei.as_deref(),
            Some("25000000000")
        );
        assert!(token_policy.daily_max_tx_count.is_none());

        let chain_policy = draft
            .as_chain_policy(6)
            .expect("chain policy")
            .expect("present chain policy");
        assert_eq!(chain_policy.per_tx_limit.as_deref(), Some("12500000"));
        assert_eq!(chain_policy.daily_limit.as_deref(), Some("100000000"));
        assert_eq!(chain_policy.weekly_limit.as_deref(), Some("500250000"));
    }

    #[test]
    fn token_draft_without_limits_preserves_missing_default_policy() {
        let config = WlfiConfig::default();
        let draft = TokenDraft::from_profile(
            "usd1",
            config.tokens.get("usd1").expect("usd1 token"),
            &config,
        );
        let (_, _, profile) = draft.to_profile(&config).expect("token profile");

        assert!(profile.default_policy.is_none());
        assert!(profile
            .chains
            .values()
            .all(|chain_profile| chain_profile.default_policy.is_none()));
    }

    #[test]
    fn field_visibility_and_selection_helpers_cover_view_transitions() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.message = Some("stale".to_string());
        app.pending_discard_action = Some(PendingDiscardAction::NextView);
        app.pending_delete_action = Some(PendingDeleteAction::DeleteToken("usd1".to_string()));
        app.selected = usize::MAX;
        app.normalize_selection();
        assert_eq!(app.selected, app.visible_fields().len() - 1);

        app.next_view();
        assert_eq!(app.view, View::Networks);
        assert_eq!(app.selected, 0);
        assert!(app.message.is_none());
        assert!(app.pending_discard_action.is_none());
        assert!(app.pending_delete_action.is_none());
        assert!(app.visible_fields().contains(&Field::DeleteNetwork));

        app.previous_view();
        assert_eq!(app.view, View::Tokens);

        app.view = View::Bootstrap;
        assert_eq!(app.visible_fields(), vec![Field::Execute]);
        app.select_next();
        assert_eq!(app.selected, 0);
        app.select_prev();
        assert_eq!(app.selected, 0);
        assert!(app.request_reload_current_view());
        app.request_new_current_draft();
        assert_eq!(app.view, View::Bootstrap);
        assert!(app.request_cancel());
    }

    #[test]
    fn delete_key_and_pending_selection_helpers_cover_errors_and_normalization() {
        let mut app = AppState::from_shared_config(&empty_config(), false);
        assert!(app.pending_token_delete_key().is_err());

        app.view = View::Networks;
        assert!(app.pending_network_delete_key().is_err());

        app.view = View::Tokens;
        app.token_draft.key = "  MixedToken  ".to_string();
        assert_eq!(
            app.pending_token_delete_key().expect("pending token key"),
            "mixedtoken"
        );

        app.view = View::Networks;
        app.network_draft.key = "  ExampleChain  ".to_string();
        assert_eq!(
            app.pending_network_delete_key()
                .expect("pending network key"),
            "examplechain"
        );
    }

    #[test]
    fn save_and_apply_helpers_return_success_messages() {
        let token_config_path = temp_config_path("token-save-success");
        let mut token_app = AppState::from_shared_config(&sample_config(), false);
        token_app.config_path = token_config_path.clone();
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let (token_output, token_message) =
            run_save_token_and_apply(&mut terminal, &mut token_app, &mut |params, on_status| {
                on_status("token apply hook").expect("status");
                Ok(params.token_policies.len())
            })
            .expect("save token and apply");
        assert_eq!(token_output, 2);
        assert!(token_message.contains("saved token"));
        fs::remove_dir_all(token_config_path.parent().expect("temp config dir"))
            .expect("remove temp token config dir");

        let network_config_path = temp_config_path("network-save-success");
        let mut network_app = AppState::from_shared_config(&sample_config(), false);
        network_app.config_path = network_config_path.clone();
        network_app.view = View::Networks;
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let (network_output, network_message) = run_save_network_and_apply(
            &mut terminal,
            &mut network_app,
            &mut |params, on_status| {
                on_status("network apply hook").expect("status");
                Ok(params.token_policies.len())
            },
        )
        .expect("save network and apply");
        assert_eq!(network_output, 2);
        assert!(network_message.contains("saved network"));
        fs::remove_dir_all(network_config_path.parent().expect("temp config dir"))
            .expect("remove temp network config dir");
    }

    #[test]
    fn save_and_apply_token_keeps_disk_config_unchanged_when_apply_fails() {
        let original = sample_config();
        let config_path = temp_config_path("token-apply-failure");
        original
            .write_to_path(&config_path)
            .expect("write original config");

        let mut app = AppState::from_shared_config(&original, false);
        app.config_path = config_path.clone();
        app.token_draft.limits.daily_limit = "321".to_string();
        app.token_dirty = true;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let error = run_save_token_and_apply(&mut terminal, &mut app, &mut |_params,
                                                                            _on_status|
         -> anyhow::Result<
            (),
        > {
            Err(anyhow::anyhow!("authentication failed"))
        })
        .expect_err("apply should fail");

        assert!(error.to_string().contains("authentication failed"));
        assert_eq!(
            WlfiConfig::read_from_path(&config_path).expect("read persisted config"),
            original
        );
        assert_eq!(app.shared_config_draft, original);
        assert_eq!(app.token_draft.limits.daily_limit, "321");
        fs::remove_dir_all(config_path.parent().expect("temp config dir"))
            .expect("remove temp config dir");
    }

    #[test]
    fn save_and_apply_network_keeps_disk_config_unchanged_when_apply_fails() {
        let original = sample_config();
        let config_path = temp_config_path("network-apply-failure");
        original
            .write_to_path(&config_path)
            .expect("write original config");

        let mut app = AppState::from_shared_config(&original, false);
        app.config_path = config_path.clone();
        app.view = View::Networks;
        app.network_draft.rpc_url = "https://rpc.updated.example".to_string();
        app.network_dirty = true;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let error = run_save_network_and_apply(
            &mut terminal,
            &mut app,
            &mut |_params, _on_status| -> anyhow::Result<()> {
                Err(anyhow::anyhow!("authentication failed"))
            },
        )
        .expect_err("apply should fail");

        assert!(error.to_string().contains("authentication failed"));
        assert_eq!(
            WlfiConfig::read_from_path(&config_path).expect("read persisted config"),
            original
        );
        assert_eq!(app.shared_config_draft, original);
        assert_eq!(app.network_draft.rpc_url, "https://rpc.updated.example");
        fs::remove_dir_all(config_path.parent().expect("temp config dir"))
            .expect("remove temp config dir");
    }

    #[test]
    fn policy_value_resolution_and_overlay_helpers_cover_remaining_branches() {
        assert_eq!(
            resolve_required_policy_amount("limit", Some("1.5"), None, None, 6)
                .expect("decimal amount"),
            1_500_000
        );
        assert_eq!(
            resolve_required_policy_amount("limit", None, Some("42"), None, 6).expect("raw amount"),
            42
        );
        assert_eq!(
            resolve_required_policy_amount("limit", None, None, Some(2.5), 6)
                .expect("legacy amount"),
            2_500_000
        );
        assert!(resolve_required_policy_amount("limit", None, None, None, 6).is_err());

        assert_eq!(
            resolve_policy_amount_or_default(Some("3"), None, None, 9, 6).expect("decimal"),
            3_000_000
        );
        assert_eq!(
            resolve_policy_amount_or_default(None, Some("7"), None, 9, 6).expect("raw"),
            7
        );
        assert_eq!(
            resolve_policy_amount_or_default(None, None, Some(1.25), 9, 6).expect("legacy"),
            1_250_000
        );
        assert_eq!(
            resolve_policy_amount_or_default(None, None, None, 9, 6).expect("default"),
            9
        );

        assert_eq!(
            resolve_optional_gwei_or_wei(Some("2"), None).expect("gwei"),
            2_000_000_000
        );
        assert_eq!(
            resolve_optional_gwei_or_wei(None, Some("5")).expect("wei"),
            5
        );
        assert_eq!(
            resolve_gwei_or_wei_or_default(None, None, 11).expect("default"),
            11
        );
        assert_eq!(resolve_optional_policy_value(None).expect("none"), 0);
        assert_eq!(
            resolve_optional_policy_value_or_default(None, 13).expect("default"),
            13
        );

        let defaults = ResolvedLimitFields {
            per_tx_max_wei: 100,
            daily_max_wei: 200,
            weekly_max_wei: 300,
            max_gas_per_chain_wei: 400,
            daily_max_tx_count: 5,
            per_tx_max_fee_per_gas_wei: 6,
            per_tx_max_priority_fee_per_gas_wei: 7,
            per_tx_max_calldata_bytes: 8,
        };
        let tighter = ResolvedLimitFields {
            per_tx_max_wei: 90,
            daily_max_wei: 190,
            weekly_max_wei: 290,
            max_gas_per_chain_wei: 300,
            daily_max_tx_count: 4,
            per_tx_max_fee_per_gas_wei: 5,
            per_tx_max_priority_fee_per_gas_wei: 6,
            per_tx_max_calldata_bytes: 7,
        };
        validate_destination_override_overlay("recipient", &defaults, &tighter)
            .expect("tighter overlay");

        assert!(validate_overlay_limit("recipient", "per-tx max", 100, 101).is_err());
        assert!(validate_optional_overlay_limit("recipient", "gas max", 0, 1).is_err());
        assert!(validate_optional_overlay_limit("recipient", "gas max", 10, 0).is_err());
        assert!(validate_optional_overlay_limit("recipient", "gas max", 10, 11).is_err());
        validate_optional_overlay_limit("recipient", "gas max", 10, 9).expect("valid optional");
    }

    #[test]
    fn tokens_view_is_default_and_not_numbered() {
        let app = AppState::from_shared_config(&sample_config(), false);
        assert_eq!(app.view, View::Tokens);
        assert_eq!(app.visible_fields()[0], Field::SelectedToken);
    }

    #[test]
    fn token_panel_mentions_overrides_and_manual_approvals() {
        let app = AppState::from_shared_config(&sample_config(), false);
        let rendered = build_token_panel_lines(&app)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("USD1 (usd1)"));
        assert!(rendered.contains("overrides 1"));
        assert!(rendered.contains("manual approvals 1"));
    }

    #[test]
    fn build_params_expands_multi_network_token_and_manual_approval() {
        let app = AppState::from_shared_config(&sample_config(), false);
        let params = app.build_params().expect("params");
        assert_eq!(params.token_selectors.len(), 2);
        assert_eq!(params.token_policies.len(), 2);
        assert_eq!(params.token_destination_overrides.len(), 2);
        assert_eq!(params.token_manual_approval_policies.len(), 2);
    }

    #[test]
    fn build_params_skips_empty_destination_override_limits() {
        let mut config = sample_config();
        if let Some(token) = config.tokens.get_mut("usd1") {
            token.destination_overrides = vec![TokenDestinationOverrideProfile {
                recipient: "0x1000000000000000000000000000000000000001".to_string(),
                limits: TokenPolicyProfile::default(),
            }];
        }

        let app = AppState::from_shared_config(&config, false);
        let params = app.build_params().expect("params");
        assert_eq!(params.token_policies.len(), 2);
        assert_eq!(params.token_destination_overrides.len(), 0);
    }

    #[test]
    fn build_params_reuses_existing_wallet_metadata_when_available() {
        let mut config = sample_config();
        config.wallet = Some(WalletProfile {
            vault_key_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
            vault_public_key: "031111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            address: Some("0x1111111111111111111111111111111111111111".to_string()),
            agent_key_id: Some("22222222-2222-2222-2222-222222222222".to_string()),
            policy_attachment: "policy_set".to_string(),
            attached_policy_ids: Vec::new(),
            policy_note: None,
            network_scope: None,
            asset_scope: None,
            recipient_scope: None,
            extra: BTreeMap::new(),
        });

        let app = AppState::from_shared_config(&config, false);
        let params = app.build_params().expect("params");
        assert_eq!(
            params
                .existing_vault_key_id
                .map(|value| value.to_string())
                .as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            params.existing_vault_public_key.as_deref(),
            Some("031111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(
            params
                .existing_agent_key_id
                .map(|value| value.to_string())
                .as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
    }

    #[test]
    fn build_params_allows_unrestricted_default_shared_config() {
        let params =
            super::build_bootstrap_params_from_shared_config(&WlfiConfig::default(), false, false)
                .expect("params");
        assert!(params.use_per_token_bootstrap);
        assert_eq!(params.token_selectors.len(), 9);
        assert!(params.token_policies.is_empty());
        assert!(params.token_destination_overrides.is_empty());
        assert!(params.token_manual_approval_policies.is_empty());
    }

    #[test]
    fn resolve_manual_approval_uses_all_token_networks() {
        let config = sample_config();
        let token_selectors = resolve_all_token_selectors(&config).expect("token selectors");
        let manual = resolve_all_token_manual_approval_policies(&config, &token_selectors)
            .expect("manual approvals");
        assert_eq!(manual.len(), 2);
        assert_eq!(manual[0].priority, 120);
    }

    #[test]
    fn build_params_allows_manual_approval_without_default_limits_for_usd1_bsc() {
        let mut config = sample_config();
        let token = config.tokens.get_mut("usd1").expect("usd1 token");
        token.default_policy = None;
        token.destination_overrides.clear();
        for chain in token.chains.values_mut() {
            chain.default_policy = None;
        }

        let token_selectors = resolve_all_token_selectors(&config).expect("token selectors");
        let manual = resolve_all_token_manual_approval_policies(&config, &token_selectors)
            .expect("manual approvals");
        assert_eq!(manual.len(), 2);
        assert!(manual.iter().any(|policy| {
            policy.token_key == "usd1"
                && policy.chain_key == "bsc"
                && policy.address
                    == Some(crate::TokenAddress::Evm(
                        "0x2000000000000000000000000000000000000000"
                            .parse()
                            .expect("bsc usd1 address"),
                    ))
        }));

        let params = super::build_bootstrap_params_from_shared_config(&config, false, false)
            .expect("params");
        assert_eq!(params.token_selectors.len(), 2);
        assert!(params.token_policies.is_empty());
        assert!(params.token_destination_overrides.is_empty());
        assert_eq!(params.token_manual_approval_policies.len(), 2);
        assert!(params.token_manual_approval_policies.iter().any(|policy| {
            policy.token_key == "usd1"
                && policy.chain_key == "bsc"
                && policy.address
                    == Some(crate::TokenAddress::Evm(
                        "0x2000000000000000000000000000000000000000"
                            .parse()
                            .expect("bsc usd1 address"),
                    ))
        }));
    }

    #[test]
    fn network_membership_toggle_adds_saved_network_to_new_token() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.new_token_draft();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::NetworkMembership)
            .expect("network membership field");

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("handle");

        assert_eq!(app.token_draft.networks.len(), 1);
    }

    #[test]
    fn bootstrap_panel_mentions_manual_approval_counts() {
        let app = AppState::from_shared_config(&sample_config(), false);
        let rendered = build_bootstrap_panel_lines(&app)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("2 destination override(s); 2 manual approval policy/policies."));
    }

    #[test]
    fn token_limit_fields_are_decimal_strings_not_raw_wei_labels() {
        let config = sample_config();
        let app = AppState::from_shared_config(&config, false);
        assert_eq!(super::field_label(Field::PerTxLimit), "Per-Tx Limit");
        assert_eq!(super::field_value(&app, Field::PerTxLimit), "10");
    }

    #[test]
    fn field_display_labels_show_interaction_badges() {
        assert_eq!(super::field_display_label(Field::TokenKey), "[E] Token Key");
        assert_eq!(
            super::field_display_label(Field::SelectedToken),
            "[S] Selected Token"
        );
        assert_eq!(
            super::field_display_label(Field::RefreshTokenMetadata),
            "[A] Fetch Metadata"
        );
        assert_eq!(
            super::field_display_label(Field::TokenName),
            "[R] Token Name (RPC)"
        );
    }

    #[test]
    fn token_help_lines_include_interaction_legend() {
        let rendered = super::build_help_lines(View::Tokens)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("Legend: [E] edit [S] select/toggle [A] Enter [R] read-only"));
        assert!(rendered.contains("Use: ←/→ h/l a/d Space Enter"));
        assert!(
            rendered.contains("Network Multi-Select: use ←/→ h/l a/d to move the >focus< marker")
        );
        assert!(rendered.contains("Paste: terminal paste appends into editable fields."));
        assert!(rendered.contains("RPC fields are [R]; use [A] Fetch Metadata to refresh them."));
    }

    #[test]
    fn render_network_membership_marks_the_focused_network_inline() {
        let config = sample_config();
        let mut draft = TokenDraft::blank(&config);
        draft.available_network_index = 1;
        draft
            .toggle_network_membership(&config)
            .expect("toggle focused network");

        let rendered = super::render_network_membership_value(&draft, &config);
        assert!(rendered.contains("focus 2/2"));
        assert!(rendered.contains("[ ] bsc"));
        assert!(rendered.contains("[x] >eth<"));
    }

    #[test]
    fn save_token_defers_apply_to_event_loop_when_metadata_is_complete() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        let config_root =
            std::env::temp_dir().join(format!("agentpay-admin-save-token-{}", Uuid::new_v4()));
        fs::create_dir_all(&config_root).expect("create temp config root");
        app.config_path = config_root.join("config.json");
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::SaveToken)
            .expect("save token field");

        let action = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("handle");

        assert!(matches!(action, LoopAction::SaveTokenAndApply));

        fs::remove_dir_all(config_root).expect("cleanup temp config root");
    }

    #[test]
    fn ctrl_s_saves_dirty_token_before_bootstrap() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.token_draft.key.push('x');
        app.mark_token_dirty();

        let action = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        )
        .expect("handle ctrl+s");

        assert!(matches!(action, LoopAction::SaveTokenAndApply));
    }

    #[test]
    fn ctrl_s_saves_dirty_network_before_bootstrap() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.view = View::Networks;
        app.network_draft.name.push('x');
        app.mark_network_dirty();

        let action = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
        )
        .expect("handle ctrl+s");

        assert!(matches!(action, LoopAction::SaveNetworkAndApply));
    }

    #[test]
    fn paste_event_appends_trimmed_text_to_editable_fields() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.view = View::Networks;
        app.network_draft.rpc_url.clear();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::ChainConfigRpcUrl)
            .expect("chain config rpc field");

        let action = handle_terminal_event(
            &mut app,
            Event::Paste(" https://bsc.drpc.org \n".to_string()),
        )
        .expect("handle paste");

        assert!(matches!(action, LoopAction::Continue));
        assert_eq!(app.network_draft.rpc_url, "https://bsc.drpc.org");
        assert!(app.network_dirty);
    }

    #[test]
    fn paste_event_rejects_invalid_chars_for_selected_field() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        let original_key = app.token_draft.key.clone();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::TokenKey)
            .expect("token key field");

        let action = handle_terminal_event(&mut app, Event::Paste("bad key".to_string()))
            .expect("handle invalid paste");

        assert!(matches!(action, LoopAction::Continue));
        assert_eq!(app.token_draft.key, original_key);
        assert_eq!(
            app.message.as_deref(),
            Some("invalid character ' ' for the selected field")
        );
    }

    #[test]
    fn refresh_metadata_action_is_deferred_to_event_loop_for_progress_rendering() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::RefreshTokenMetadata)
            .expect("refresh metadata field");

        let action = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("handle");

        assert!(matches!(action, LoopAction::RefreshTokenMetadata));
    }

    #[test]
    fn apply_with_progress_surfaces_bootstrap_status_messages() {
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).expect("terminal");
        let mut app = AppState::from_shared_config(&sample_config(), false);
        let params = app.build_params().expect("params");

        let output =
            apply_with_progress(&mut terminal, &mut app, params, &mut |params, on_status| {
                assert_eq!(params.token_policies.len(), 2);
                on_status("initializing daemon")?;
                on_status("registering spending policies")?;
                Ok("ok".to_string())
            })
            .expect("apply succeeds");

        assert_eq!(output, "ok");
        assert_eq!(
            app.message.as_deref(),
            Some("registering spending policies")
        );
    }

    #[test]
    fn status_message_style_uses_message_severity() {
        let mut app = AppState::from_shared_config(&sample_config(), false);

        app.set_info_message("loading");
        assert_eq!(app.message_level, MessageLevel::Info);
        assert_eq!(status_message_style(&app).fg, Some(Color::Cyan));

        app.set_success_message("saved");
        assert_eq!(app.message_level, MessageLevel::Success);
        assert_eq!(status_message_style(&app).fg, Some(Color::Green));

        app.set_error_message("failed");
        assert_eq!(app.message_level, MessageLevel::Error);
        assert_eq!(status_message_style(&app).fg, Some(Color::Red));
    }

    #[test]
    fn advanced_fields_are_hidden_by_default() {
        let app = AppState::from_shared_config(&sample_config(), false);
        let fields = app.visible_fields();
        assert!(fields.contains(&Field::ShowAdvanced));
        assert!(!fields.contains(&Field::MaxGasPerChainWei));
        assert!(!fields.contains(&Field::PerTxMaxFeePerGasGwei));
        assert!(!fields.contains(&Field::OverrideMaxGasPerChainWei));
    }

    #[test]
    fn advanced_fields_show_unlimited_when_enabled_without_values() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.show_advanced = true;
        app.token_draft.limits.max_gas_per_chain_wei.clear();
        app.token_draft.limits.daily_max_tx_count.clear();
        app.token_draft.limits.per_tx_max_fee_per_gas_gwei.clear();
        app.token_draft
            .limits
            .per_tx_max_priority_fee_per_gas_wei
            .clear();
        app.token_draft.limits.per_tx_max_calldata_bytes.clear();

        assert_eq!(
            super::field_value(&app, Field::MaxGasPerChainWei),
            "unlimited"
        );
        assert_eq!(
            super::field_value(&app, Field::DailyMaxTxCount),
            "unlimited"
        );
        assert_eq!(
            super::field_value(&app, Field::PerTxMaxFeePerGasGwei),
            "unlimited"
        );
    }

    #[test]
    fn default_token_address_field_uses_seeded_erc20_address() {
        let mut app = AppState::from_shared_config(&WlfiConfig::default(), false);
        app.load_token_draft(Some("usd1"));
        assert_eq!(
            super::field_value(&app, Field::NetworkAddress),
            "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d"
        );
    }

    #[test]
    fn tab_requires_confirmation_before_discarding_dirty_token_draft() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::TokenKey)
            .expect("token key field");

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        )
        .expect("edit token key");
        assert!(app.token_dirty);

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .expect("first tab");
        assert_eq!(app.view, View::Tokens);
        assert!(app
            .message
            .as_deref()
            .expect("discard warning")
            .contains("unsaved changes in the token draft"));

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE))
            .expect("second tab");
        assert_eq!(app.view, View::Networks);
    }

    #[test]
    fn reload_requires_confirmation_before_discarding_dirty_network_draft() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.view = View::Networks;
        let original_name = app.network_draft.name.clone();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::ChainConfigName)
            .expect("chain config name field");

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        )
        .expect("edit network name");
        assert!(app.network_dirty);
        assert!(app.network_draft.name.ends_with('x'));

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        )
        .expect("first reload");
        assert!(app.network_draft.name.ends_with('x'));
        assert!(app
            .message
            .as_deref()
            .expect("discard warning")
            .contains("unsaved changes in the network draft"));

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
        )
        .expect("second reload");
        assert_eq!(app.network_draft.name, original_name);
        assert!(!app.network_dirty);
    }

    #[test]
    fn cycling_saved_token_requires_confirmation_when_current_draft_is_dirty() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::TokenKey)
            .expect("token key field");
        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
        )
        .expect("edit token key");

        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::SelectedToken)
            .expect("selected token field");

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .expect("first cycle");
        assert_eq!(app.token_draft.source_key.as_deref(), Some("usd1"));
        assert!(app
            .message
            .as_deref()
            .expect("discard warning")
            .contains("unsaved changes in the token draft"));

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .expect("second cycle");
        assert!(app.token_draft.source_key.is_none());
        assert!(!app.token_dirty);
    }

    #[test]
    fn q_requires_confirmation_before_canceling_dirty_token_draft() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.token_draft.key.push('x');
        app.mark_token_dirty();

        let action = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        )
        .expect("first cancel");
        assert!(matches!(action, LoopAction::Continue));
        assert!(app
            .message
            .as_deref()
            .expect("discard warning")
            .contains("unsaved changes in the token draft"));

        let action = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
        )
        .expect("second cancel");
        assert!(matches!(action, LoopAction::Cancel));
    }

    #[test]
    fn escape_requires_confirmation_before_canceling_dirty_network_draft() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.view = View::Networks;
        app.network_draft.name.push('x');
        app.mark_network_dirty();

        let action = handle_key_event(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("first cancel");
        assert!(matches!(action, LoopAction::Continue));
        assert!(app
            .message
            .as_deref()
            .expect("discard warning")
            .contains("unsaved changes in the network draft"));

        let action = handle_key_event(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
            .expect("second cancel");
        assert!(matches!(action, LoopAction::Cancel));
    }

    #[test]
    fn delete_manual_approval_requires_confirmation() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::DeleteManualApproval)
            .expect("delete manual approval field");

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("first delete");
        assert_eq!(app.token_draft.manual_approvals.len(), 1);
        assert!(app
            .message
            .as_deref()
            .expect("confirmation")
            .contains("repeat the action to confirm deleting the selected manual approval policy"));

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("second delete");
        assert!(app.token_draft.manual_approvals.is_empty());
    }

    #[test]
    fn changing_selected_manual_approval_restarts_delete_confirmation() {
        let mut config = sample_config();
        let token = config.tokens.get_mut("usd1").expect("usd1 token");
        let mut second_policy = token.manual_approval_policies[0].clone();
        second_policy.priority = 200;
        second_policy.min_amount_decimal = Some("600".to_string());
        second_policy.max_amount_decimal = Some("900".to_string());
        token.manual_approval_policies.push(second_policy);

        let mut app = AppState::from_shared_config(&config, false);
        let delete_field = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::DeleteManualApproval)
            .expect("delete manual approval field");
        let selected_field = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::SelectedManualApproval)
            .expect("selected manual approval field");

        app.selected = delete_field;
        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("first delete");
        assert_eq!(app.token_draft.manual_approvals.len(), 2);

        app.selected = selected_field;
        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .expect("cycle manual approval");
        assert_eq!(app.token_draft.selected_manual_approval, 1);

        app.selected = delete_field;
        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("re-arm delete for second selection");
        assert_eq!(app.token_draft.manual_approvals.len(), 2);
        assert!(app
            .message
            .as_deref()
            .expect("renewed confirmation")
            .contains("repeat the action to confirm deleting the selected manual approval policy"));

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("delete selected manual approval");
        assert_eq!(app.token_draft.manual_approvals.len(), 1);
        assert_eq!(app.token_draft.manual_approvals[0].priority, "120");
    }

    #[test]
    fn changing_selected_override_restarts_delete_confirmation() {
        let mut config = sample_config();
        let token = config.tokens.get_mut("usd1").expect("usd1 token");
        let mut second_override = token.destination_overrides[0].clone();
        second_override.recipient = "0x2000000000000000000000000000000000000002".to_string();
        token.destination_overrides.push(second_override);

        let mut app = AppState::from_shared_config(&config, false);
        let delete_field = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::DeleteDestinationOverride)
            .expect("delete override field");
        let selected_field = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::SelectedDestinationOverride)
            .expect("selected override field");

        app.selected = delete_field;
        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("first delete");
        assert_eq!(app.token_draft.destination_overrides.len(), 2);

        app.selected = selected_field;
        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Right, KeyModifiers::NONE))
            .expect("cycle override");
        assert_eq!(app.token_draft.selected_override, 1);

        app.selected = delete_field;
        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("re-arm delete for second selection");
        assert_eq!(app.token_draft.destination_overrides.len(), 2);
        assert!(app
            .message
            .as_deref()
            .expect("renewed confirmation")
            .contains("repeat the action to confirm deleting the selected destination override"));

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("delete selected override");
        assert_eq!(app.token_draft.destination_overrides.len(), 1);
        assert_eq!(
            app.token_draft.destination_overrides[0].recipient_address,
            "0x1000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn delete_token_requires_confirmation() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        let config_root =
            std::env::temp_dir().join(format!("agentpay-admin-delete-token-{}", Uuid::new_v4()));
        fs::create_dir_all(&config_root).expect("create temp config root");
        app.config_path = config_root.join("config.json");
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::DeleteToken)
            .expect("delete token field");

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("first delete");
        assert!(app.shared_config_draft.tokens.contains_key("usd1"));
        assert!(app
            .message
            .as_deref()
            .expect("confirmation")
            .contains("repeat the action to confirm deleting the selected token"));

        let _ = handle_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
            .expect("second delete");
        assert!(!app.shared_config_draft.tokens.contains_key("usd1"));

        fs::remove_dir_all(config_root).expect("cleanup temp config root");
    }

    #[test]
    fn token_draft_validation_errors_cover_remaining_paths() {
        let config = sample_config();
        let mut draft = TokenDraft::blank(&config);

        assert!(draft.selected_network_mut().is_none());
        assert!(draft
            .min_network_decimals()
            .expect_err("empty draft must fail")
            .to_string()
            .contains("select at least one network for the token"));
        assert!(draft
            .to_profile(&config)
            .expect_err("missing key must fail")
            .to_string()
            .contains("token key is required"));

        draft.key = "usd1".to_string();
        assert!(draft
            .to_profile(&config)
            .expect_err("missing name must fail")
            .to_string()
            .contains("fetch token metadata before saving the token"));

        draft.name = "USD1".to_string();
        assert!(draft
            .to_profile(&config)
            .expect_err("missing symbol must fail")
            .to_string()
            .contains("fetch token metadata before saving the token"));

        draft.symbol = "USD1".to_string();
        assert!(draft
            .to_profile(&config)
            .expect_err("missing network must fail")
            .to_string()
            .contains("select at least one network for the token"));

        draft.limits = super::LimitDraft::from_policy(Some(&sample_policy("10", "100", "500")), 6);
        draft.networks.push(TokenNetworkDraft {
            chain_key: "eth".to_string(),
            chain_id: "1".to_string(),
            is_native: false,
            address: "0x1000000000000000000000000000000000000000".to_string(),
            decimals: "999".to_string(),
        });
        assert!(draft
            .to_profile(&config)
            .expect_err("large decimals must fail")
            .to_string()
            .contains("decimals must be <= 255"));

        draft.networks[0].decimals = "6".to_string();
        draft.networks[0].is_native = true;
        assert!(draft
            .to_profile(&config)
            .expect_err("native token with address must fail")
            .to_string()
            .contains("must not set an address when native"));

        draft.networks[0].is_native = false;
        draft.networks[0].chain_key = "missing".to_string();
        assert!(draft
            .to_profile(&config)
            .expect_err("unknown chain must fail")
            .to_string()
            .contains("unknown saved network 'missing'"));

        draft.networks[0].chain_key = "eth".to_string();
        draft
            .destination_overrides
            .push(super::DestinationOverrideDraft {
                recipient_address: "not-an-address".to_string(),
                limits: draft.limits.clone(),
            });
        assert!(draft
            .to_profile(&config)
            .expect_err("invalid override recipient must fail")
            .to_string()
            .contains("destination override recipient"));

        draft.destination_overrides.clear();
        draft.manual_approvals.push(ManualApprovalDraft {
            recipient_address: String::new(),
            min_amount: "1".to_string(),
            max_amount: "2".to_string(),
            priority: (u32::MAX as u64 + 1).to_string(),
        });
        assert!(draft
            .to_profile(&config)
            .expect_err("large priority must fail")
            .to_string()
            .contains("manual approval priority must be <= 4294967295"));

        draft.manual_approvals[0].priority = "10".to_string();
        draft.manual_approvals[0].recipient_address = "not-an-address".to_string();
        assert!(draft
            .to_profile(&config)
            .expect_err("invalid manual approval recipient must fail")
            .to_string()
            .contains("manual approval recipient"));
    }

    #[test]
    fn token_draft_membership_and_normalize_cover_remaining_branches() {
        let empty = empty_config();
        let mut empty_draft = TokenDraft::blank(&empty);
        assert!(empty_draft
            .toggle_network_membership(&empty)
            .expect_err("empty config must fail")
            .to_string()
            .contains("save a network before adding it to a token"));

        let config = sample_config();
        let mut draft = TokenDraft::blank(&config);
        draft.available_network_index = 1;
        draft
            .toggle_network_membership(&config)
            .expect("add network");
        assert_eq!(draft.networks.len(), 1);
        assert_eq!(draft.networks[0].chain_key, "eth");

        draft
            .destination_overrides
            .push(super::DestinationOverrideDraft::default());
        draft.manual_approvals.push(ManualApprovalDraft::default());
        draft.selected_network = usize::MAX;
        draft.selected_override = usize::MAX;
        draft.selected_manual_approval = usize::MAX;

        draft
            .toggle_network_membership(&config)
            .expect("remove network");
        assert!(draft.networks.is_empty());
        assert_eq!(draft.selected_network, 0);
        assert_eq!(draft.selected_override, 0);
        assert_eq!(draft.selected_manual_approval, 0);
    }

    #[test]
    fn token_draft_readding_network_restores_previous_values() {
        let config = sample_config();
        let mut draft = TokenDraft::blank(&config);
        draft.available_network_index = 1;
        draft
            .toggle_network_membership(&config)
            .expect("add network");
        draft.networks[0].is_native = true;
        draft.networks[0].address = "native".to_string();
        draft.networks[0].decimals = "9".to_string();

        draft
            .toggle_network_membership(&config)
            .expect("remove network");
        assert!(draft.networks.is_empty());

        draft
            .toggle_network_membership(&config)
            .expect("restore network");
        assert_eq!(draft.networks.len(), 1);
        assert!(draft.networks[0].is_native);
        assert_eq!(draft.networks[0].address, "native");
        assert_eq!(draft.networks[0].decimals, "9");
    }

    #[test]
    fn network_draft_to_profile_defaults_name_and_optional_rpc() {
        let draft = NetworkDraft::blank();
        assert!(draft
            .to_profile()
            .expect_err("blank key must fail")
            .to_string()
            .contains("network key is required"));

        let mut draft = NetworkDraft::blank();
        draft.key = " BSC ".to_string();
        draft.chain_id = "56".to_string();
        let (source_key, chain_key, profile, use_as_active) =
            draft.to_profile().expect("network profile");
        assert!(source_key.is_none());
        assert_eq!(chain_key, "bsc");
        assert_eq!(profile.name, "bsc");
        assert_eq!(profile.rpc_url, None);
        assert!(!use_as_active);
    }

    #[test]
    fn network_draft_to_profile_rejects_invalid_rpc_url() {
        let mut draft = NetworkDraft::blank();
        draft.key = " sol ".to_string();
        draft.chain_id = "101".to_string();
        draft.rpc_url = "not-a-url".to_string();

        assert!(draft
            .to_profile()
            .expect_err("invalid rpc url")
            .to_string()
            .contains("network rpc url must be a valid http(s) URL"));
    }

    #[test]
    fn network_draft_to_profile_accepts_loopback_http_rpc_url() {
        let mut draft = NetworkDraft::blank();
        draft.key = " sol ".to_string();
        draft.chain_id = "101".to_string();
        draft.rpc_url = "http://127.0.0.1:8899".to_string();

        let (_, chain_key, profile, _) = draft.to_profile().expect("network profile");
        assert_eq!(chain_key, "sol");
        assert_eq!(profile.rpc_url.as_deref(), Some("http://127.0.0.1:8899"));
    }

    #[test]
    fn app_state_network_draft_navigation_helpers_cover_remaining_paths() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.view = View::Networks;
        app.network_draft.name.push('x');
        app.mark_network_dirty();

        app.request_previous_view();
        assert_eq!(app.view, View::Networks);
        assert!(app
            .message
            .as_deref()
            .expect("discard warning")
            .contains("unsaved changes in the network draft"));

        app.request_previous_view();
        assert_eq!(app.view, View::Tokens);

        app.view = View::Networks;
        app.load_network_draft(Some("missing"));
        assert_eq!(app.network_draft.source_key.as_deref(), Some("bsc"));

        app.request_new_current_draft();
        assert!(app.network_draft.source_key.is_none());
        assert_eq!(app.message.as_deref(), Some("new network draft ready"));
        assert_eq!(app.selected_field(), Field::ChainConfigKey);

        app.cycle_saved_network(1);
        assert_eq!(app.network_draft.source_key.as_deref(), Some("bsc"));
        app.cycle_saved_network(-1);
        assert!(app.network_draft.source_key.is_none());
    }

    #[test]
    fn step_selected_and_delete_network_cover_remaining_network_paths() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);

        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::NetworkMembership)
            .expect("network membership field");
        app.step_selected(1);
        assert_eq!(app.token_draft.available_network_index, 1);
        assert_eq!(
            app.message.as_deref(),
            Some("network focus: eth (2/2) — press Space or Enter to toggle it")
        );

        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::EditingNetwork)
            .expect("editing network field");
        app.step_selected(1);
        assert_eq!(app.token_draft.selected_network, 1);

        app.token_draft.networks[app.token_draft.selected_network].address =
            "0x3000000000000000000000000000000000000000".to_string();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::NetworkIsNative)
            .expect("network native field");
        app.step_selected(1);
        let selected_network = app
            .token_draft
            .selected_network()
            .expect("selected network");
        assert!(selected_network.is_native);
        assert!(selected_network.address.is_empty());

        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::ShowAdvanced)
            .expect("show advanced field");
        app.step_selected(1);
        assert!(app.show_advanced);

        app.view = View::Networks;
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::SelectedNetwork)
            .expect("selected network field");
        app.step_selected(1);
        assert_eq!(app.network_draft.source_key.as_deref(), Some("eth"));

        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::ChainConfigUseAsActive)
            .expect("use as active field");
        app.step_selected(1);
        assert!(app.network_draft.use_as_active);
        assert!(app.network_dirty);

        let mut empty_app = AppState::from_shared_config(&empty_config(), false);
        empty_app.view = View::Networks;
        assert!(empty_app
            .request_delete_network()
            .expect_err("blank network delete must fail")
            .to_string()
            .contains("no saved network is selected"));

        let mut deleting_app = AppState::from_shared_config(&config, false);
        deleting_app.view = View::Networks;
        deleting_app
            .request_delete_network()
            .expect("first delete only arms confirmation");
        assert_eq!(
            deleting_app.pending_delete_action,
            Some(PendingDeleteAction::DeleteNetwork("bsc".to_string()))
        );
        assert!(deleting_app
            .request_delete_network()
            .expect_err("network still referenced by token must fail")
            .to_string()
            .contains("network 'bsc' is still used by token 'usd1'"));
    }

    #[test]
    fn network_membership_reports_when_only_one_saved_network_exists() {
        let mut config = empty_config();
        config.chains.insert(
            "eth".to_string(),
            ChainProfile {
                chain_id: 1,
                name: "eth".to_string(),
                rpc_url: Some("https://rpc.ethereum.example".to_string()),
                extra: BTreeMap::new(),
            },
        );

        let mut app = AppState::from_shared_config(&config, false);
        app.new_token_draft();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::NetworkMembership)
            .expect("network membership field");

        app.step_selected(1);
        assert_eq!(app.token_draft.available_network_index, 0);
        assert_eq!(
            app.message.as_deref(),
            Some("only one saved network is available (eth) — add another in Networks to multi-select")
        );
    }

    #[test]
    fn network_membership_accepts_ad_keys_as_focus_navigation_fallback() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.new_token_draft();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::NetworkMembership)
            .expect("network membership field");

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        )
        .expect("move focus right");
        assert_eq!(app.token_draft.available_network_index, 1);

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
        )
        .expect("move focus left");
        assert_eq!(app.token_draft.available_network_index, 0);
    }

    #[test]
    fn switching_to_new_network_focuses_key_field_for_immediate_typing() {
        let config = sample_config();
        let mut app = AppState::from_shared_config(&config, false);
        app.view = View::Networks;
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::SelectedNetwork)
            .expect("selected network field");

        app.cycle_saved_network(-1);
        assert!(app.network_draft.source_key.is_none());
        assert_eq!(app.selected_field(), Field::ChainConfigKey);

        let _ = handle_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
        )
        .expect("type into new network key");

        assert_eq!(app.network_draft.key, "s");
        assert!(app.network_dirty);
    }

    #[test]
    fn editing_network_name_accepts_letters_that_overlap_navigation_shortcuts() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.view = View::Networks;
        app.request_new_current_draft();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::ChainConfigName)
            .expect("network name field");

        let selected = app.selected;
        for ch in "sepolia".chars() {
            let _ = handle_key_event(
                &mut app,
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
            )
            .expect("type network name");
        }

        assert_eq!(app.selected, selected);
        assert_eq!(app.network_draft.name, "sepolia");
        assert!(app.network_dirty);
    }

    #[test]
    fn editing_network_rpc_url_accepts_http_prefix() {
        let mut app = AppState::from_shared_config(&sample_config(), false);
        app.view = View::Networks;
        app.request_new_current_draft();
        app.selected = app
            .visible_fields()
            .iter()
            .position(|field| *field == Field::ChainConfigRpcUrl)
            .expect("network rpc url field");

        let selected = app.selected;
        for ch in "http".chars() {
            let _ = handle_key_event(
                &mut app,
                KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
            )
            .expect("type rpc prefix");
        }

        assert_eq!(app.selected, selected);
        assert_eq!(app.network_draft.rpc_url, "http");
        assert!(app.network_dirty);
    }

    #[test]
    fn token_address_parse_dispatches_on_chain_id() {
        let mainnet = crate::TokenAddress::parse(
            "usdc on solana-mainnet",
            900_000_001,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )
        .expect("parses solana mint");
        assert!(matches!(mainnet, crate::TokenAddress::Solana(_)));

        let evm = crate::TokenAddress::parse(
            "usd1 on bsc",
            56,
            "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d",
        )
        .expect("parses evm address");
        assert!(matches!(evm, crate::TokenAddress::Evm(_)));

        assert!(crate::TokenAddress::parse(
            "evm chain rejects base58",
            1,
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        )
        .is_err());
        assert!(crate::TokenAddress::parse(
            "solana chain rejects 0x address",
            900_000_001,
            "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d",
        )
        .is_err());
    }

    #[test]
    fn parse_token_recipient_dispatches_on_chain_id() {
        let solana = crate::parse_token_recipient(
            "manual approval recipient",
            900_000_002,
            "CnPoSPKXu7wJqxe59Fs72tkBeALovhsCxYNKuPHYZRzG",
        )
        .expect("parses solana recipient");
        assert!(matches!(solana, vault_domain::RecipientId::Solana(_)));

        let evm = crate::parse_token_recipient(
            "manual approval recipient",
            56,
            "0x4a66BE5e29d1cBA04a60aF7348403253b4B9404e",
        )
        .expect("parses evm recipient");
        assert!(matches!(evm, vault_domain::RecipientId::Evm(_)));

        assert!(crate::parse_token_recipient(
            "manual approval recipient",
            1,
            "CnPoSPKXu7wJqxe59Fs72tkBeALovhsCxYNKuPHYZRzG",
        )
        .is_err());
    }

    #[test]
    fn build_bootstrap_params_from_shared_config_accepts_solana_token() {
        let mut config = empty_config();
        config.chains.insert(
            "solana-mainnet".to_string(),
            ChainProfile {
                chain_id: 900_000_001,
                name: "Solana".to_string(),
                rpc_url: Some("https://api.mainnet-beta.solana.com".to_string()),
                extra: BTreeMap::new(),
            },
        );
        config.chains.insert(
            "solana-devnet".to_string(),
            ChainProfile {
                chain_id: 900_000_002,
                name: "Solana Devnet".to_string(),
                rpc_url: Some("https://api.devnet.solana.com".to_string()),
                extra: BTreeMap::new(),
            },
        );
        config.tokens.insert(
            "usdc".to_string(),
            TokenProfile {
                name: Some("USDC".to_string()),
                symbol: "USDC".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([
                    (
                        "solana-mainnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_001,
                            is_native: false,
                            address: Some(
                                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                            ),
                            decimals: 6,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                    (
                        "solana-devnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_002,
                            is_native: false,
                            address: Some(
                                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU".to_string(),
                            ),
                            decimals: 6,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                ]),
                extra: BTreeMap::new(),
            },
        );

        let params = super::build_bootstrap_params_from_shared_config(&config, false, false)
            .expect("solana token selectors");
        let solana_selectors: Vec<_> = params
            .token_selectors
            .iter()
            .filter(|s| s.token_key == "usdc")
            .collect();
        assert_eq!(solana_selectors.len(), 2);
        for selector in solana_selectors {
            assert!(matches!(
                selector.address,
                Some(crate::TokenAddress::Solana(_))
            ));
        }
    }

    #[test]
    fn solana_manual_approval_recipient_parses_as_solana() {
        let mut config = empty_config();
        config.chains.insert(
            "solana-mainnet".to_string(),
            ChainProfile {
                chain_id: 900_000_001,
                name: "Solana".to_string(),
                rpc_url: Some("https://api.mainnet-beta.solana.com".to_string()),
                extra: BTreeMap::new(),
            },
        );
        config.tokens.insert(
            "usdc".to_string(),
            TokenProfile {
                name: Some("USDC".to_string()),
                symbol: "USDC".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: vec![TokenManualApprovalProfile {
                    priority: 100,
                    recipient: Some("CnPoSPKXu7wJqxe59Fs72tkBeALovhsCxYNKuPHYZRzG".to_string()),
                    min_amount: None,
                    max_amount: None,
                    min_amount_decimal: Some("1".to_string()),
                    max_amount_decimal: Some("10".to_string()),
                    min_amount_wei: None,
                    max_amount_wei: None,
                    extra: BTreeMap::new(),
                }],
                chains: BTreeMap::from([(
                    "solana-mainnet".to_string(),
                    TokenChainProfile {
                        chain_id: 900_000_001,
                        is_native: false,
                        address: Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string()),
                        decimals: 6,
                        default_policy: None,
                        extra: BTreeMap::new(),
                    },
                )]),
                extra: BTreeMap::new(),
            },
        );

        let token_selectors = resolve_all_token_selectors(&config).expect("token selectors");
        let manual = resolve_all_token_manual_approval_policies(&config, &token_selectors)
            .expect("manual approvals");
        assert_eq!(manual.len(), 1);
        assert!(matches!(
            manual[0].recipient,
            Some(vault_domain::RecipientId::Solana(_))
        ));
    }
}
