//! The JSON encoding of [`SpendingPolicy`] (persisted state and the daemon API).
//!
//! Each policy type carries its limit in a dedicated optional field; decoding
//! re-validates every invariant the constructors enforce, so a hand-edited or
//! hostile payload cannot smuggle in a zero cap or an inverted range.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use super::{ApprovalType, AssetId, OverLimit, PolicyType, SpendingPolicy};
use crate::schema::DecimalU128;
use crate::{EntityScope, RecipientId};

/// A spending policy as sent over the wire. Exactly the limit field that
/// matches `policy_type` is required; the others are omitted.
#[derive(Debug, Serialize, Deserialize, JsonSchema, TS)]
#[schemars(rename = "SpendingPolicy")]
#[ts(rename = "SpendingPolicy")]
pub(super) struct SpendingPolicyWire {
    /// Policy id chosen by the admin client (UUID v4); `AddPolicy` rejects an
    /// id that already exists.
    id: Uuid,
    /// Evaluation order: lower values are evaluated first.
    priority: u32,
    /// What the policy limits.
    policy_type: PolicyType,
    /// `ManualApproval` only: lower bound (inclusive) of the amount range that
    /// needs approval, in base units. Absent means 0.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    min_amount_wei: Option<u128>,
    /// Amount cap in base units for `DailyMaxSpending`, `WeeklyMaxSpending`,
    /// `PerTxMaxSpending`, and the upper bound (inclusive) for `ManualApproval`;
    /// must be > 0. Specialized types echo their own limit here for older
    /// clients and accept it as a legacy alias on input. Absent for `Eip712Signing`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    max_amount_wei: Option<u128>,
    /// `DailyMaxTxCount`: maximum signed transactions per rolling 24 hours.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    max_tx_count: Option<u128>,
    /// `PerTxMaxFeePerGas`: maximum EIP-1559 `maxFeePerGas`, in wei.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    max_fee_per_gas_wei: Option<u128>,
    /// `PerTxMaxPriorityFeePerGas`: maximum `maxPriorityFeePerGas`, in wei.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    max_priority_fee_per_gas_wei: Option<u128>,
    /// `PerTxMaxCalldataBytes`: maximum broadcast calldata length, in bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    max_calldata_bytes: Option<u128>,
    /// `PerChainMaxGasSpend`: maximum `gas_limit * max_fee_per_gas` per
    /// rolling 24 hours and chain, in wei.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::u128_as_decimal_string::option"
    )]
    #[schemars(with = "Option<DecimalU128>")]
    #[ts(as = "Option<DecimalU128>")]
    max_gas_spend_wei: Option<u128>,
    /// Recipients (or spenders) the policy applies to.
    recipients: EntityScope<RecipientId>,
    /// Assets the policy applies to.
    assets: EntityScope<AssetId>,
    /// Policy chain ids the policy applies to; a `Set` must be non-empty and
    /// must not contain `0`.
    networks: EntityScope<u64>,
    /// `Eip712Signing` only (required there): what to do with typed-data
    /// signing requests in scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approval_type: Option<ApprovalType>,
    /// `PerTxMaxSpending`, `DailyMaxSpending`, `WeeklyMaxSpending`, and
    /// `DailyMaxTxCount` only: what happens to a request beyond the limit.
    /// `"deny"` (the default, omitted when encoding) refuses it;
    /// `"manual_approval"` holds it for an operator decision instead (API 1.1).
    #[serde(default, skip_serializing_if = "OverLimit::is_deny")]
    over_limit: OverLimit,
    /// Disabled policies stay listed but are ignored during evaluation.
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
            over_limit: policy.over_limit,
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
            over_limit,
            enabled,
        } = self;
        if over_limit == OverLimit::ManualApproval
            && !SpendingPolicy::supports_over_limit_approval(policy_type)
        {
            return Err("field `over_limit` may be `manual_approval` only for PerTxMaxSpending, DailyMaxSpending, WeeklyMaxSpending, and DailyMaxTxCount");
        }

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
            SpendingPolicy::validate_wire_network_scope(&networks)?;

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
                over_limit,
                enabled,
            });
        }

        if approval_type.is_some() {
            return Err("field `approval_type` is only valid for `eip712_signing`");
        }
        SpendingPolicy::validate_wire_network_scope(&networks)?;

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

        let policy = SpendingPolicy {
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
            over_limit,
            enabled,
        }
        .normalize_limits();
        policy.validate_wire_limits()?;
        Ok(policy)
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

impl JsonSchema for SpendingPolicy {
    fn schema_name() -> Cow<'static, str> {
        SpendingPolicyWire::schema_name()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        SpendingPolicyWire::json_schema(generator)
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
