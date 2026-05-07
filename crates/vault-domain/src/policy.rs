use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::u128_as_decimal_string;
use crate::{DomainError, EntityScope, EvmAddress, RecipientId, SolanaAddress};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AssetId {
    NativeEth,
    NativeSol,
    Erc20(EvmAddress),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyType {
    DailyMaxSpending,
    DailyMaxTxCount,
    WeeklyMaxSpending,
    PerTxMaxSpending,
    PerTxMaxFeePerGas,
    PerTxMaxPriorityFeePerGas,
    PerTxMaxCalldataBytes,
    PerChainMaxGasSpend,
    ManualApproval,
    Eip712Signing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalType {
    Allow,
    ManualApproval,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendingPolicy {
    pub id: Uuid,
    pub priority: u32,
    pub policy_type: PolicyType,
    pub min_amount_wei: Option<u128>,
    pub max_amount_wei: u128,
    pub max_tx_count: Option<u128>,
    pub max_fee_per_gas_wei: Option<u128>,
    pub max_priority_fee_per_gas_wei: Option<u128>,
    pub max_calldata_bytes: Option<u128>,
    pub max_gas_spend_wei: Option<u128>,
    pub recipients: EntityScope<RecipientId>,
    pub assets: EntityScope<AssetId>,
    pub networks: EntityScope<u64>,
    pub approval_type: Option<ApprovalType>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SpendingPolicyWire {
    id: Uuid,
    priority: u32,
    policy_type: PolicyType,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    min_amount_wei: Option<u128>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    max_amount_wei: Option<u128>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    max_tx_count: Option<u128>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    max_fee_per_gas_wei: Option<u128>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    max_priority_fee_per_gas_wei: Option<u128>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    max_calldata_bytes: Option<u128>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    max_gas_spend_wei: Option<u128>,
    recipients: EntityScope<RecipientId>,
    assets: EntityScope<AssetId>,
    networks: EntityScope<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_type: Option<ApprovalType>,
    enabled: bool,
}

impl From<&SpendingPolicy> for SpendingPolicyWire {
    fn from(policy: &SpendingPolicy) -> Self {
        Self {
            id: policy.id,
            priority: policy.priority,
            policy_type: policy.policy_type,
            min_amount_wei: policy.min_amount_wei,
            max_amount_wei: policy.serialized_max_amount_wei(),
            max_tx_count: policy.tx_count_limit(),
            max_fee_per_gas_wei: policy.fee_per_gas_limit(),
            max_priority_fee_per_gas_wei: policy.priority_fee_per_gas_limit(),
            max_calldata_bytes: policy.calldata_bytes_limit(),
            max_gas_spend_wei: policy.gas_spend_limit_wei(),
            recipients: policy.recipients.clone(),
            assets: policy.assets.clone(),
            networks: policy.networks.clone(),
            approval_type: policy.approval_type,
            enabled: policy.enabled,
        }
    }
}

impl SpendingPolicyWire {
    fn try_into_policy(self) -> Result<SpendingPolicy, &'static str> {
        let Self {
            id,
            priority,
            policy_type,
            min_amount_wei,
            max_amount_wei,
            max_tx_count,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            max_calldata_bytes,
            max_gas_spend_wei,
            recipients,
            assets,
            networks,
            approval_type,
            enabled,
        } = self;

        if policy_type == PolicyType::Eip712Signing {
            if min_amount_wei.is_some()
                || max_amount_wei.is_some()
                || max_tx_count.is_some()
                || max_fee_per_gas_wei.is_some()
                || max_priority_fee_per_gas_wei.is_some()
                || max_calldata_bytes.is_some()
                || max_gas_spend_wei.is_some()
            {
                return Err("eip712_signing does not accept numeric limit fields");
            }

            return Ok(SpendingPolicy {
                id,
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
                approval_type: Some(approval_type.ok_or("missing field `approval_type`")?),
                enabled,
            });
        }

        if approval_type.is_some() {
            return Err("field `approval_type` is only valid for `eip712_signing`");
        }

        let max_amount_wei = if SpendingPolicy::uses_amount_limit_field(policy_type) {
            max_amount_wei.ok_or("missing field `max_amount_wei`")?
        } else if !SpendingPolicy::has_specialized_limit(
            policy_type,
            max_amount_wei,
            max_tx_count,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            max_calldata_bytes,
            max_gas_spend_wei,
        ) {
            return Err(SpendingPolicy::missing_specialized_limit_message(
                policy_type,
            ));
        } else {
            max_amount_wei.unwrap_or_default()
        };

        Ok(SpendingPolicy {
            id,
            priority,
            policy_type,
            min_amount_wei,
            max_amount_wei,
            max_tx_count,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            max_calldata_bytes,
            max_gas_spend_wei,
            recipients,
            assets,
            networks,
            approval_type: None,
            enabled,
        }
        .normalize_limits())
    }
}

impl Serialize for SpendingPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SpendingPolicyWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SpendingPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        SpendingPolicyWire::deserialize(deserializer)?
            .try_into_policy()
            .map_err(serde::de::Error::custom)
    }
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendEvent {
    pub agent_key_id: Uuid,
    pub chain_id: u64,
    pub asset: AssetId,
    pub recipient: RecipientId,
    #[serde(with = "u128_as_decimal_string")]
    pub amount_wei: u128,
    pub at: OffsetDateTime,
}

fn map_evm_recipient_scope(scope: EntityScope<EvmAddress>) -> EntityScope<RecipientId> {
    match scope {
        EntityScope::All => EntityScope::All,
        EntityScope::Set(values) => {
            EntityScope::Set(values.into_iter().map(RecipientId::Evm).collect())
        }
    }
}
