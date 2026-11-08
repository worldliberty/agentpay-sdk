use agentpay_domain::schema::DecimalU128;
use agentpay_domain::{u128_as_decimal_string, ApprovalLimit, ApprovalReason};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;
use uuid::Uuid;

/// Why the policy engine refused (or held) a request.
///
/// JSON: externally tagged, for example `"NoAttachedPolicies"` or
/// `{"PerTxLimitExceeded": {"policy_id": "...", "max_amount_wei": "100", "requested_amount_wei": "250"}}`.
/// Every `u128` amount, count, or limit is a decimal string.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum PolicyError {
    /// The agent key has no enabled policies attached; nothing can be signed.
    #[error("no enabled policies attached to this agent key")]
    NoAttachedPolicies,
    /// No attached policy scope covers this recipient/asset/network.
    #[error("no policy scope allows recipient/asset/network for this action")]
    NoApplicablePolicies,
    /// A `PerTxMaxSpending` policy caps the amount of a single action.
    #[error(
        "policy {policy_id} rejected request: per transaction max {max_amount_wei} < requested {requested_amount_wei}"
    )]
    PerTxLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Configured cap, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_amount_wei: u128,
        /// Amount the request asked for, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_amount_wei: u128,
    },
    /// An amount cap was exceeded.
    #[error(
        "policy {policy_id} rejected request: amount max {max_amount_wei} < requested {requested_amount_wei}"
    )]
    AmountExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Configured cap, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_amount_wei: u128,
        /// Amount the request asked for, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_amount_wei: u128,
    },
    /// A rolling-window (`DailyMaxSpending`/`WeeklyMaxSpending`) cap would be exceeded.
    #[error(
        "policy {policy_id} rejected request: window usage {used_amount_wei} + requested {requested_amount_wei} > max {max_amount_wei}"
    )]
    WindowLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Amount already spent inside the window, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        used_amount_wei: u128,
        /// Amount the request asked for, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_amount_wei: u128,
        /// Configured cap, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_amount_wei: u128,
    },
    /// A `PerChainMaxGasSpend` cap would be exceeded.
    #[error(
        "policy {policy_id} rejected request: gas max {max_gas_wei} < requested {requested_gas_wei}"
    )]
    GasLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Configured gas-spend cap, in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_gas_wei: u128,
        /// Gas spend the request would add (`gas_limit * max_fee_per_gas`), in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_gas_wei: u128,
    },
    /// A `PerTxMaxFeePerGas` cap was exceeded.
    #[error(
        "policy {policy_id} rejected request: max_fee_per_gas_wei {max_fee_per_gas_wei} < requested {requested_max_fee_per_gas_wei}"
    )]
    MaxFeePerGasLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Configured cap, in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_fee_per_gas_wei: u128,
        /// Requested `maxFeePerGas`, in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_max_fee_per_gas_wei: u128,
    },
    /// A `PerTxMaxPriorityFeePerGas` cap was exceeded.
    #[error(
        "policy {policy_id} rejected request: max_priority_fee_per_gas_wei {max_priority_fee_per_gas_wei} < requested {requested_max_priority_fee_per_gas_wei}"
    )]
    PriorityFeePerGasLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Configured cap, in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_priority_fee_per_gas_wei: u128,
        /// Requested `maxPriorityFeePerGas`, in wei.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_max_priority_fee_per_gas_wei: u128,
    },
    /// A `PerTxMaxCalldataBytes` cap was exceeded.
    #[error(
        "policy {policy_id} rejected request: calldata max bytes {max_calldata_bytes} < requested {requested_calldata_bytes}"
    )]
    CalldataBytesLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Configured cap, in bytes.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_calldata_bytes: u128,
        /// Calldata length of the request, in bytes.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_calldata_bytes: u128,
    },
    /// A `DailyMaxTxCount` cap would be exceeded.
    #[error(
        "policy {policy_id} rejected request: tx_count usage {used_tx_count} + 1 > max {max_tx_count}"
    )]
    TxCountLimitExceeded {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Transactions already signed inside the window.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        used_tx_count: u128,
        /// Configured cap.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_tx_count: u128,
    },
    /// A gas/fee policy applies but the action carries no transaction metadata.
    #[error(
        "policy {policy_id} rejected request: missing required transaction metadata ({metadata})"
    )]
    MissingTransactionMetadata {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Name of the missing metadata.
        metadata: String,
    },
    /// A `ManualApproval` policy covers this amount. Soft outcome: `SignForAgent`
    /// turns it into a manual approval request (wire error `ManualApprovalRequired`).
    #[error(
        "policy {policy_id} requires manual approval for requested amount {requested_amount_wei} within range {min_amount_wei:?}..={max_amount_wei}"
    )]
    ManualApprovalRequired {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// Lower bound of the gated range, in base units (`null` means 0).
        #[serde(with = "u128_as_decimal_string::option")]
        #[schemars(with = "Option<DecimalU128>")]
        #[ts(as = "Option<DecimalU128>")]
        min_amount_wei: Option<u128>,
        /// Configured cap, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max_amount_wei: u128,
        /// Amount the request asked for, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_amount_wei: u128,
    },
    /// An `Eip712Signing` policy with `approval_type: "deny"` refused typed data.
    #[error("policy {policy_id} rejected request: eip712 signing is denied")]
    Eip712SigningDenied {
        /// Policy that refused the request.
        policy_id: Uuid,
    },
    /// A blanket `Eip712Signing = Allow` policy was asked to sign typed data
    /// that moves funds or grants allowances (Permit2, ERC-2612 `Permit`,
    /// EIP-3009 authorizations, Safe transactions, or anything domain-bound to
    /// the canonical Permit2 contract). Those payloads bypass amount, asset,
    /// and recipient scoping when signed through the generic typed-data path,
    /// so they must go through the typed `Eip3009*` actions or an eip712
    /// manual-approval policy instead.
    #[error(
        "policy {policy_id} rejected request: eip712 primaryType `{primary_type}` moves funds or grants allowances and cannot be signed under an allow eip712 policy; submit it as a typed eip3009 action or use an eip712 manual-approval policy"
    )]
    Eip712ValueBearingTypeDenied {
        /// Policy that refused the request.
        policy_id: Uuid,
        /// The refused EIP-712 `primaryType`.
        primary_type: String,
    },
    /// Generic EIP-712 typed data bound to the canonical Permit2 contract
    /// (API 1.1). Refused under every policy, manual approval included: a
    /// Permit2 signature can move any token the wallet has approved Permit2
    /// for, which MPP `permit2` payments leave unlimited, and the generic
    /// path cannot apply spending limits to it. Permit2 permits are signed
    /// only as the policy-checked `Permit2WitnessTransfer` action.
    #[error(
        "eip712 primaryType `{primary_type}` is bound to the Permit2 contract and can move funds without spending limits; AgentPay signs Permit2 permits only as Permit2WitnessTransfer actions"
    )]
    Permit2TypedDataDenied {
        /// The refused EIP-712 `primaryType`.
        primary_type: String,
    },
    /// A per-payment, daily, weekly, or daily-count limit with
    /// `over_limit: manual_approval` would be exceeded (API 1.1). Soft
    /// outcome, like `ManualApprovalRequired`: within its limits an agent pays
    /// on its own, beyond them `SignForAgent` holds the request for approval.
    #[error(
        "policy {policy_id} requires manual approval: {limit:?} limit {max}, used {used}, requested amount {requested_amount_wei}"
    )]
    LimitApprovalRequired {
        /// Policy whose limit would be exceeded.
        policy_id: Uuid,
        /// Which limit: `per_payment`, `daily`, `weekly`, or `daily_count`.
        limit: ApprovalLimit,
        /// The limit, in base units (transactions for `daily_count`).
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        max: u128,
        /// Used inside the window before this request, in the same unit as
        /// `max`; `0` for `per_payment`.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        used: u128,
        /// Amount the request asked for, in base units.
        #[serde(with = "u128_as_decimal_string")]
        #[schemars(with = "DecimalU128")]
        #[ts(as = "DecimalU128")]
        requested_amount_wei: u128,
    },
    /// Typed-data signing needs an operator decision (soft outcome, like
    /// `ManualApprovalRequired`).
    #[error("eip712 signing requires manual approval{policy_suffix}")]
    Eip712ManualApprovalRequired {
        /// Policy that requires approval, or `null` for the default EIP-712 gate.
        policy_id: Option<Uuid>,
        /// Human-readable suffix naming the policy, if any.
        policy_suffix: String,
    },
}

impl PolicyError {
    /// Returns whether this outcome routes the request to a human instead of
    /// rejecting it outright.
    ///
    /// Manual-approval outcomes are *soft*: the policy engine keeps evaluating
    /// the remaining applicable policies so a hard limit (daily cap, per-tx
    /// max, gas cap, ...) still denies the request instead of being masked by
    /// the approval prompt.
    #[must_use]
    pub fn is_manual_approval_required(&self) -> bool {
        matches!(
            self,
            Self::ManualApprovalRequired { .. }
                | Self::LimitApprovalRequired { .. }
                | Self::Eip712ManualApprovalRequired { .. }
        )
    }

    /// The policy that holds the request, for a soft outcome with one.
    #[must_use]
    pub fn approval_policy_id(&self) -> Option<Uuid> {
        match self {
            Self::ManualApprovalRequired { policy_id, .. }
            | Self::LimitApprovalRequired { policy_id, .. } => Some(*policy_id),
            Self::Eip712ManualApprovalRequired { policy_id, .. } => *policy_id,
            _ => None,
        }
    }

    /// The operator-facing reason of a soft outcome; `None` for denials.
    #[must_use]
    pub fn approval_reason(&self) -> Option<ApprovalReason> {
        match self {
            Self::ManualApprovalRequired {
                policy_id,
                max_amount_wei,
                requested_amount_wei,
                ..
            } => Some(ApprovalReason {
                limit: ApprovalLimit::Policy,
                policy_id: Some(*policy_id),
                max: Some(*max_amount_wei),
                used: None,
                requested_amount_wei: Some(*requested_amount_wei),
            }),
            Self::LimitApprovalRequired {
                policy_id,
                limit,
                max,
                used,
                requested_amount_wei,
            } => Some(ApprovalReason {
                limit: *limit,
                policy_id: Some(*policy_id),
                max: Some(*max),
                used: (*limit != ApprovalLimit::PerPayment).then_some(*used),
                requested_amount_wei: Some(*requested_amount_wei),
            }),
            Self::Eip712ManualApprovalRequired { policy_id, .. } => Some(ApprovalReason {
                limit: ApprovalLimit::Eip712,
                policy_id: *policy_id,
                max: None,
                used: None,
                requested_amount_wei: None,
            }),
            _ => None,
        }
    }
}
