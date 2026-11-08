//! Spending policies, their scopes and limits, and the spend log they read.

mod wire;

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;

use crate::u128_as_decimal_string;
use crate::{DomainError, EntityScope, EvmAddress, RecipientId, SolanaAddress};

/// The asset an action moves.
///
/// JSON: `{"kind": "native_eth"}`, `{"kind": "native_sol"}`,
/// `{"kind": "erc20", "value": "0x<token>"}`, or
/// `{"kind": "spl_token", "value": "<base58 mint>"}`.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema, TS,
)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AssetId {
    /// The chain's native coin on any EVM chain (ETH, BNB, ...).
    NativeEth,
    /// Native SOL.
    NativeSol,
    /// An ERC-20 / TIP-20 token, by contract address.
    Erc20(EvmAddress),
    /// An SPL (or Token-2022) token, by mint address.
    SplToken(SolanaAddress),
}

impl Display for AssetId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NativeEth => f.write_str("native_eth"),
            Self::NativeSol => f.write_str("native_sol"),
            Self::Erc20(token) => write!(f, "erc20:{token}"),
            Self::SplToken(mint) => write!(f, "spl:{mint}"),
        }
    }
}

/// What a [`SpendingPolicy`] limits. JSON: the variant name, for example `"PerTxMaxSpending"`.
///
/// Spending windows are rolling (the last 24 hours or 7 days), per agent key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum PolicyType {
    /// Total amount per rolling 24 hours (`max_amount_wei`).
    DailyMaxSpending,
    /// Signed transactions per rolling 24 hours (`max_tx_count`).
    DailyMaxTxCount,
    /// Total amount per rolling 7 days (`max_amount_wei`).
    WeeklyMaxSpending,
    /// Amount of a single action (`max_amount_wei`).
    PerTxMaxSpending,
    /// Broadcast `maxFeePerGas` (`max_fee_per_gas_wei`).
    PerTxMaxFeePerGas,
    /// Broadcast `maxPriorityFeePerGas` (`max_priority_fee_per_gas_wei`).
    PerTxMaxPriorityFeePerGas,
    /// Broadcast calldata length (`max_calldata_bytes`).
    PerTxMaxCalldataBytes,
    /// Gas spend per chain per rolling 24 hours (`max_gas_spend_wei`).
    PerChainMaxGasSpend,
    /// Amounts in `[min_amount_wei, max_amount_wei]` need an operator decision.
    ManualApproval,
    /// Generic EIP-712 typed-data signing (`approval_type`).
    Eip712Signing,
}

/// Outcome an `Eip712Signing` policy prescribes. JSON: `"allow"`, `"manual_approval"`, or `"deny"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalType {
    /// Sign without asking (value-bearing typed data is still refused).
    Allow,
    /// Hold the request for an operator decision.
    ManualApproval,
    /// Refuse the request.
    Deny,
}

/// What happens when a request goes beyond a limit policy's limit. JSON:
/// `"deny"` (the default; omitted when encoding) or `"manual_approval"`.
///
/// Only the four limit types ([`SpendingPolicy::supports_over_limit_approval`])
/// accept `manual_approval`: there, a request beyond the limit becomes a
/// manual approval request instead of a denial, so the limit is the amount an
/// agent may pay without asking.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum OverLimit {
    /// Refuse the request.
    #[default]
    Deny,
    /// Hold the request for an operator decision.
    ManualApproval,
}

impl OverLimit {
    /// `true` for [`OverLimit::Deny`].
    #[must_use]
    pub fn is_deny(&self) -> bool {
        *self == Self::Deny
    }
}

/// A spending policy: a scoped limit evaluated before every agent signature.
///
/// The JSON encoding is described by the `SpendingPolicy` schema: one
/// dedicated optional limit field per [`PolicyType`], amounts as decimal
/// strings. Decoding re-validates every invariant (non-zero caps, ordered
/// manual-approval range, non-empty network sets).
#[derive(Debug, Clone, PartialEq, Eq, TS)]
#[ts(as = "wire::SpendingPolicyWire")]
pub struct SpendingPolicy {
    /// Policy id; `AddPolicy` rejects an id that already exists.
    pub id: Uuid,
    /// Evaluation order: lower values are evaluated first.
    pub priority: u32,
    /// What the policy limits.
    pub policy_type: PolicyType,
    /// `ManualApproval` only: inclusive lower bound of the gated amount range.
    pub min_amount_wei: Option<u128>,
    /// Amount cap (or `ManualApproval` upper bound) in base units; 0 for
    /// specialized and `Eip712Signing` policies.
    pub max_amount_wei: u128,
    /// `DailyMaxTxCount` limit.
    pub max_tx_count: Option<u128>,
    /// `PerTxMaxFeePerGas` limit, in wei.
    pub max_fee_per_gas_wei: Option<u128>,
    /// `PerTxMaxPriorityFeePerGas` limit, in wei.
    pub max_priority_fee_per_gas_wei: Option<u128>,
    /// `PerTxMaxCalldataBytes` limit, in bytes.
    pub max_calldata_bytes: Option<u128>,
    /// `PerChainMaxGasSpend` limit, in wei.
    pub max_gas_spend_wei: Option<u128>,
    /// Recipients (or spenders) in scope.
    pub recipients: EntityScope<RecipientId>,
    /// Assets in scope.
    pub assets: EntityScope<AssetId>,
    /// Policy chain ids in scope.
    pub networks: EntityScope<u64>,
    /// `Eip712Signing` outcome; `None` for every other type.
    pub approval_type: Option<ApprovalType>,
    /// What happens beyond the limit (limit types only; `Deny` otherwise).
    pub over_limit: OverLimit,
    /// Disabled policies are ignored during evaluation.
    pub enabled: bool,
}

impl SpendingPolicy {
    pub fn new(
        priority: u32,
        policy_type: PolicyType,
        max_amount_wei: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_with_recipient_scope(
            priority,
            policy_type,
            max_amount_wei,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_with_recipient_scope(
        priority: u32,
        policy_type: PolicyType,
        max_amount_wei: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        match policy_type {
            PolicyType::DailyMaxTxCount => Self::new_tx_count_limit_with_recipient_scope(
                priority,
                max_amount_wei,
                recipients,
                assets,
                networks,
            ),
            PolicyType::PerTxMaxFeePerGas => Self::new_fee_per_gas_limit_with_recipient_scope(
                priority,
                max_amount_wei,
                recipients,
                assets,
                networks,
            ),
            PolicyType::PerTxMaxPriorityFeePerGas => {
                Self::new_priority_fee_per_gas_limit_with_recipient_scope(
                    priority,
                    max_amount_wei,
                    recipients,
                    assets,
                    networks,
                )
            }
            PolicyType::PerTxMaxCalldataBytes => Self::new_calldata_limit_with_recipient_scope(
                priority,
                max_amount_wei,
                recipients,
                assets,
                networks,
            ),
            PolicyType::PerChainMaxGasSpend => Self::new_gas_spend_limit_with_recipient_scope(
                priority,
                max_amount_wei,
                recipients,
                assets,
                networks,
            ),
            _ => Self::new_with_range_and_recipient_scope(
                priority,
                policy_type,
                None,
                max_amount_wei,
                recipients,
                assets,
                networks,
            ),
        }
    }

    pub fn new_manual_approval(
        priority: u32,
        min_amount_wei: u128,
        max_amount_wei: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_manual_approval_with_recipient_scope(
            priority,
            min_amount_wei,
            max_amount_wei,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_manual_approval_with_recipient_scope(
        priority: u32,
        min_amount_wei: u128,
        max_amount_wei: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_with_range_and_recipient_scope(
            priority,
            PolicyType::ManualApproval,
            Some(min_amount_wei),
            max_amount_wei,
            recipients,
            assets,
            networks,
        )
    }

    pub fn new_eip712_signing(
        priority: u32,
        approval_type: ApprovalType,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::validate_network_scope(&networks)?;

        Ok(Self {
            id: Uuid::new_v4(),
            priority,
            policy_type: PolicyType::Eip712Signing,
            min_amount_wei: None,
            max_amount_wei: 0,
            max_tx_count: None,
            max_fee_per_gas_wei: None,
            max_priority_fee_per_gas_wei: None,
            max_calldata_bytes: None,
            max_gas_spend_wei: None,
            recipients: EntityScope::All,
            assets: EntityScope::All,
            networks,
            approval_type: Some(approval_type),
            over_limit: OverLimit::Deny,
            enabled: true,
        })
    }

    pub fn new_calldata_limit(
        priority: u32,
        max_calldata_bytes: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_calldata_limit_with_recipient_scope(
            priority,
            max_calldata_bytes,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_calldata_limit_with_recipient_scope(
        priority: u32,
        max_calldata_bytes: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_specialized_limit(
            priority,
            PolicyType::PerTxMaxCalldataBytes,
            max_calldata_bytes,
            recipients,
            assets,
            networks,
        )
    }

    pub fn new_tx_count_limit(
        priority: u32,
        max_tx_count: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_tx_count_limit_with_recipient_scope(
            priority,
            max_tx_count,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_tx_count_limit_with_recipient_scope(
        priority: u32,
        max_tx_count: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_specialized_limit(
            priority,
            PolicyType::DailyMaxTxCount,
            max_tx_count,
            recipients,
            assets,
            networks,
        )
    }

    pub fn new_fee_per_gas_limit(
        priority: u32,
        max_fee_per_gas_wei: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_fee_per_gas_limit_with_recipient_scope(
            priority,
            max_fee_per_gas_wei,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_fee_per_gas_limit_with_recipient_scope(
        priority: u32,
        max_fee_per_gas_wei: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_specialized_limit(
            priority,
            PolicyType::PerTxMaxFeePerGas,
            max_fee_per_gas_wei,
            recipients,
            assets,
            networks,
        )
    }

    pub fn new_priority_fee_per_gas_limit(
        priority: u32,
        max_priority_fee_per_gas_wei: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_priority_fee_per_gas_limit_with_recipient_scope(
            priority,
            max_priority_fee_per_gas_wei,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_priority_fee_per_gas_limit_with_recipient_scope(
        priority: u32,
        max_priority_fee_per_gas_wei: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_specialized_limit(
            priority,
            PolicyType::PerTxMaxPriorityFeePerGas,
            max_priority_fee_per_gas_wei,
            recipients,
            assets,
            networks,
        )
    }

    pub fn new_gas_spend_limit(
        priority: u32,
        max_gas_spend_wei: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_gas_spend_limit_with_recipient_scope(
            priority,
            max_gas_spend_wei,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_gas_spend_limit_with_recipient_scope(
        priority: u32,
        max_gas_spend_wei: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_specialized_limit(
            priority,
            PolicyType::PerChainMaxGasSpend,
            max_gas_spend_wei,
            recipients,
            assets,
            networks,
        )
    }

    pub fn new_with_range(
        priority: u32,
        policy_type: PolicyType,
        min_amount_wei: Option<u128>,
        max_amount_wei: u128,
        recipients: EntityScope<EvmAddress>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        Self::new_with_range_and_recipient_scope(
            priority,
            policy_type,
            min_amount_wei,
            max_amount_wei,
            map_evm_recipient_scope(recipients),
            assets,
            networks,
        )
    }

    pub fn new_with_range_and_recipient_scope(
        priority: u32,
        policy_type: PolicyType,
        min_amount_wei: Option<u128>,
        max_amount_wei: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        if Self::uses_dedicated_limit_field(policy_type) {
            if min_amount_wei.is_some() {
                return Err(DomainError::InvalidAmount);
            }
            return Self::new_with_recipient_scope(
                priority,
                policy_type,
                max_amount_wei,
                recipients,
                assets,
                networks,
            );
        }

        if max_amount_wei == 0 {
            return Err(DomainError::InvalidAmount);
        }
        if matches!(min_amount_wei, Some(0)) {
            return Err(DomainError::InvalidAmount);
        }
        if let Some(min_amount_wei) = min_amount_wei {
            if min_amount_wei > max_amount_wei {
                return Err(DomainError::InvalidAmount);
            }
        }

        Self::validate_network_scope(&networks)?;

        Ok(Self {
            id: Uuid::new_v4(),
            priority,
            policy_type,
            min_amount_wei,
            max_amount_wei,
            max_tx_count: None,
            max_fee_per_gas_wei: None,
            max_priority_fee_per_gas_wei: None,
            max_calldata_bytes: None,
            max_gas_spend_wei: None,
            recipients,
            assets,
            networks,
            approval_type: None,
            over_limit: OverLimit::Deny,
            enabled: true,
        })
    }

    pub fn tx_count_limit(&self) -> Option<u128> {
        self.specialized_limit(self.max_tx_count, PolicyType::DailyMaxTxCount)
    }

    #[must_use]
    pub fn fee_per_gas_limit(&self) -> Option<u128> {
        self.specialized_limit(self.max_fee_per_gas_wei, PolicyType::PerTxMaxFeePerGas)
    }

    #[must_use]
    pub fn priority_fee_per_gas_limit(&self) -> Option<u128> {
        self.specialized_limit(
            self.max_priority_fee_per_gas_wei,
            PolicyType::PerTxMaxPriorityFeePerGas,
        )
    }

    #[must_use]
    pub fn calldata_bytes_limit(&self) -> Option<u128> {
        self.specialized_limit(self.max_calldata_bytes, PolicyType::PerTxMaxCalldataBytes)
    }

    #[must_use]
    pub fn gas_spend_limit_wei(&self) -> Option<u128> {
        self.specialized_limit(self.max_gas_spend_wei, PolicyType::PerChainMaxGasSpend)
    }

    /// Whether `policy_type` accepts [`OverLimit::ManualApproval`]: the
    /// per-transaction, daily, and weekly amount limits and the daily
    /// transaction count.
    #[must_use]
    pub fn supports_over_limit_approval(policy_type: PolicyType) -> bool {
        matches!(
            policy_type,
            PolicyType::PerTxMaxSpending
                | PolicyType::DailyMaxSpending
                | PolicyType::WeeklyMaxSpending
                | PolicyType::DailyMaxTxCount
        )
    }

    /// Sets what happens beyond the limit; fails for a type that does not
    /// support [`OverLimit::ManualApproval`].
    pub fn with_over_limit(mut self, over_limit: OverLimit) -> Result<Self, DomainError> {
        if over_limit == OverLimit::ManualApproval
            && !Self::supports_over_limit_approval(self.policy_type)
        {
            return Err(DomainError::OverLimitApprovalUnsupported);
        }
        self.over_limit = over_limit;
        Ok(self)
    }

    /// Whether this policy can hold a request for an operator decision: a
    /// `ManualApproval` policy, a manual-approval `Eip712Signing` policy, or
    /// a limit policy with `over_limit: manual_approval`.
    #[must_use]
    pub fn may_require_manual_approval(&self) -> bool {
        self.policy_type == PolicyType::ManualApproval
            || self.eip712_approval_type() == Some(ApprovalType::ManualApproval)
            || self.over_limit == OverLimit::ManualApproval
    }

    #[must_use]
    pub fn eip712_approval_type(&self) -> Option<ApprovalType> {
        (self.policy_type == PolicyType::Eip712Signing)
            .then_some(self.approval_type)
            .flatten()
    }

    fn normalize_limits(mut self) -> Self {
        match self.policy_type {
            PolicyType::DailyMaxTxCount => {
                Self::migrate_legacy_limit(&mut self.max_tx_count, &mut self.max_amount_wei);
            }
            PolicyType::PerTxMaxFeePerGas => {
                Self::migrate_legacy_limit(&mut self.max_fee_per_gas_wei, &mut self.max_amount_wei);
            }
            PolicyType::PerTxMaxPriorityFeePerGas => {
                Self::migrate_legacy_limit(
                    &mut self.max_priority_fee_per_gas_wei,
                    &mut self.max_amount_wei,
                );
            }
            PolicyType::PerTxMaxCalldataBytes => {
                Self::migrate_legacy_limit(&mut self.max_calldata_bytes, &mut self.max_amount_wei);
            }
            PolicyType::PerChainMaxGasSpend => {
                Self::migrate_legacy_limit(&mut self.max_gas_spend_wei, &mut self.max_amount_wei);
            }
            _ => {}
        }

        self
    }

    fn uses_amount_limit_field(policy_type: PolicyType) -> bool {
        matches!(
            policy_type,
            PolicyType::DailyMaxSpending
                | PolicyType::WeeklyMaxSpending
                | PolicyType::PerTxMaxSpending
                | PolicyType::ManualApproval
        )
    }

    fn uses_dedicated_limit_field(policy_type: PolicyType) -> bool {
        matches!(
            policy_type,
            PolicyType::DailyMaxTxCount
                | PolicyType::PerTxMaxFeePerGas
                | PolicyType::PerTxMaxPriorityFeePerGas
                | PolicyType::PerTxMaxCalldataBytes
                | PolicyType::PerChainMaxGasSpend
        )
    }

    fn has_specialized_limit(
        policy_type: PolicyType,
        legacy_limit: Option<u128>,
        max_tx_count: Option<u128>,
        max_fee_per_gas_wei: Option<u128>,
        max_priority_fee_per_gas_wei: Option<u128>,
        max_calldata_bytes: Option<u128>,
        max_gas_spend_wei: Option<u128>,
    ) -> bool {
        match policy_type {
            PolicyType::DailyMaxTxCount => max_tx_count.or(legacy_limit).is_some(),
            PolicyType::PerTxMaxFeePerGas => max_fee_per_gas_wei.or(legacy_limit).is_some(),
            PolicyType::PerTxMaxPriorityFeePerGas => {
                max_priority_fee_per_gas_wei.or(legacy_limit).is_some()
            }
            PolicyType::PerTxMaxCalldataBytes => max_calldata_bytes.or(legacy_limit).is_some(),
            PolicyType::PerChainMaxGasSpend => max_gas_spend_wei.or(legacy_limit).is_some(),
            _ => true,
        }
    }

    fn missing_specialized_limit_message(policy_type: PolicyType) -> &'static str {
        match policy_type {
            PolicyType::DailyMaxTxCount => {
                "missing field `max_tx_count` or legacy `max_amount_wei`"
            }
            PolicyType::PerTxMaxFeePerGas => {
                "missing field `max_fee_per_gas_wei` or legacy `max_amount_wei`"
            }
            PolicyType::PerTxMaxPriorityFeePerGas => {
                "missing field `max_priority_fee_per_gas_wei` or legacy `max_amount_wei`"
            }
            PolicyType::PerTxMaxCalldataBytes => {
                "missing field `max_calldata_bytes` or legacy `max_amount_wei`"
            }
            PolicyType::PerChainMaxGasSpend => {
                "missing field `max_gas_spend_wei` or legacy `max_amount_wei`"
            }
            _ => "missing specialized limit field",
        }
    }

    fn specialized_limit(
        &self,
        dedicated_limit: Option<u128>,
        policy_type: PolicyType,
    ) -> Option<u128> {
        dedicated_limit.or_else(|| {
            (self.policy_type == policy_type && self.max_amount_wei > 0)
                .then_some(self.max_amount_wei)
        })
    }

    fn serialized_max_amount_wei(&self) -> Option<u128> {
        if let Some(amount_limit_wei) =
            Self::uses_amount_limit_field(self.policy_type).then_some(self.max_amount_wei)
        {
            return Some(amount_limit_wei);
        }

        self.tx_count_limit()
            .or_else(|| self.fee_per_gas_limit())
            .or_else(|| self.priority_fee_per_gas_limit())
            .or_else(|| self.calldata_bytes_limit())
            .or_else(|| self.gas_spend_limit_wei())
    }

    fn migrate_legacy_limit(limit: &mut Option<u128>, max_amount_wei: &mut u128) {
        if limit.is_none() && *max_amount_wei > 0 {
            *limit = Some(*max_amount_wei);
        }
        *max_amount_wei = 0;
    }

    fn new_specialized_limit(
        priority: u32,
        policy_type: PolicyType,
        limit: u128,
        recipients: EntityScope<RecipientId>,
        assets: EntityScope<AssetId>,
        networks: EntityScope<u64>,
    ) -> Result<Self, DomainError> {
        if !Self::uses_dedicated_limit_field(policy_type) || limit == 0 {
            return Err(DomainError::InvalidAmount);
        }
        Self::validate_network_scope(&networks)?;

        let mut policy = Self {
            id: Uuid::new_v4(),
            priority,
            policy_type,
            min_amount_wei: None,
            max_amount_wei: 0,
            max_tx_count: None,
            max_fee_per_gas_wei: None,
            max_priority_fee_per_gas_wei: None,
            max_calldata_bytes: None,
            max_gas_spend_wei: None,
            recipients,
            assets,
            networks,
            approval_type: None,
            over_limit: OverLimit::Deny,
            enabled: true,
        };

        match policy_type {
            PolicyType::DailyMaxTxCount => policy.max_tx_count = Some(limit),
            PolicyType::PerTxMaxFeePerGas => policy.max_fee_per_gas_wei = Some(limit),
            PolicyType::PerTxMaxPriorityFeePerGas => {
                policy.max_priority_fee_per_gas_wei = Some(limit);
            }
            PolicyType::PerTxMaxCalldataBytes => policy.max_calldata_bytes = Some(limit),
            PolicyType::PerChainMaxGasSpend => policy.max_gas_spend_wei = Some(limit),
            _ => return Err(DomainError::InvalidAmount),
        }

        Ok(policy)
    }

    fn validate_network_scope(networks: &EntityScope<u64>) -> Result<(), DomainError> {
        if let EntityScope::Set(values) = networks {
            if values.is_empty() {
                return Err(DomainError::EmptyScope {
                    scope: "network set",
                });
            }
            if values.contains(&0) {
                return Err(DomainError::InvalidChainId);
            }
        }

        Ok(())
    }

    /// Wire-format counterpart of [`Self::validate_network_scope`] with static
    /// messages suitable for `serde::de::Error::custom`.
    fn validate_wire_network_scope(networks: &EntityScope<u64>) -> Result<(), &'static str> {
        Self::validate_network_scope(networks).map_err(|err| match err {
            DomainError::EmptyScope { .. } => "network set scope must not be empty",
            _ => "network set must not contain chain_id 0",
        })
    }

    /// Re-applies the limit invariants enforced by the `new_*` constructors to
    /// a policy that arrived over the wire (persisted state, admin API), so a
    /// hand-edited or corrupted payload cannot smuggle in a zero cap or an
    /// inverted manual-approval range.
    fn validate_wire_limits(&self) -> Result<(), &'static str> {
        if Self::uses_amount_limit_field(self.policy_type) {
            if self.max_amount_wei == 0 {
                return Err("max_amount_wei must be greater than zero");
            }
            if self
                .min_amount_wei
                .is_some_and(|min_amount_wei| min_amount_wei > self.max_amount_wei)
            {
                return Err("min_amount_wei must not exceed max_amount_wei");
            }
            return Ok(());
        }

        let limit = match self.policy_type {
            PolicyType::DailyMaxTxCount => self.tx_count_limit(),
            PolicyType::PerTxMaxFeePerGas => self.fee_per_gas_limit(),
            PolicyType::PerTxMaxPriorityFeePerGas => self.priority_fee_per_gas_limit(),
            PolicyType::PerTxMaxCalldataBytes => self.calldata_bytes_limit(),
            PolicyType::PerChainMaxGasSpend => self.gas_spend_limit_wei(),
            _ => return Ok(()),
        };
        if limit.unwrap_or_default() == 0 {
            return Err("policy limit must be greater than zero");
        }

        Ok(())
    }
}

/// Which policies govern an agent key.
///
/// JSON: `"AllPolicies"` or `{"PolicySet": ["<policy uuid>", ...]}` (non-empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum PolicyAttachment {
    /// Applies every enabled policy available at evaluation time.
    ///
    /// This attachment is intentionally dynamic, so policies added later will
    /// also apply to the agent.
    AllPolicies,
    /// Applies only the explicitly attached policy ids.
    ///
    /// This attachment is intentionally static. Adding a new policy later does
    /// not retroactively attach it to existing agent keys.
    PolicySet(BTreeSet<Uuid>),
}

impl PolicyAttachment {
    pub fn policy_set(policies: BTreeSet<Uuid>) -> Result<Self, DomainError> {
        if policies.is_empty() {
            return Err(DomainError::EmptyPolicySet);
        }

        Ok(Self::PolicySet(policies))
    }

    #[must_use]
    pub fn applies_to(&self, policy_id: Uuid) -> bool {
        match self {
            Self::AllPolicies => true,
            Self::PolicySet(ids) => ids.contains(&policy_id),
        }
    }
}

/// One signed spend, recorded for rolling-window limits (persisted, not on the wire).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendEvent {
    /// Agent key that spent.
    pub agent_key_id: Uuid,
    /// Policy chain id of the spend.
    pub chain_id: u64,
    /// Asset spent.
    pub asset: AssetId,
    /// Recipient of the spend.
    pub recipient: RecipientId,
    /// Amount in base units.
    #[serde(with = "u128_as_decimal_string")]
    pub amount_wei: u128,
    /// When the spend was signed.
    pub at: OffsetDateTime,
    /// The manual approval request that let this spend through (API 1.1);
    /// `None` when it was within the agent's limits, and for spends recorded
    /// before approval ids were kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
}

fn map_evm_recipient_scope(scope: EntityScope<EvmAddress>) -> EntityScope<RecipientId> {
    match scope {
        EntityScope::All => EntityScope::All,
        EntityScope::Set(values) => {
            EntityScope::Set(values.into_iter().map(RecipientId::Evm).collect())
        }
    }
}
