use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyError {
    #[error("no enabled policies attached to this agent key")]
    NoAttachedPolicies,
    #[error("no policy scope allows recipient/asset/network for this action")]
    NoApplicablePolicies,
    #[error(
        "policy {policy_id} rejected request: per transaction max {max_amount_wei} < requested {requested_amount_wei}"
    )]
    PerTxLimitExceeded {
        policy_id: Uuid,
        max_amount_wei: u128,
        requested_amount_wei: u128,
    },
    #[error(
        "policy {policy_id} rejected request: amount max {max_amount_wei} < requested {requested_amount_wei}"
    )]
    AmountExceeded {
        policy_id: Uuid,
        max_amount_wei: u128,
        requested_amount_wei: u128,
    },
    #[error(
        "policy {policy_id} rejected request: window usage {used_amount_wei} + requested {requested_amount_wei} > max {max_amount_wei}"
    )]
    WindowLimitExceeded {
        policy_id: Uuid,
        used_amount_wei: u128,
        requested_amount_wei: u128,
        max_amount_wei: u128,
    },
    #[error(
        "policy {policy_id} rejected request: gas max {max_gas_wei} < requested {requested_gas_wei}"
    )]
    GasLimitExceeded {
        policy_id: Uuid,
        max_gas_wei: u128,
        requested_gas_wei: u128,
    },
    #[error(
        "policy {policy_id} rejected request: max_fee_per_gas_wei {max_fee_per_gas_wei} < requested {requested_max_fee_per_gas_wei}"
    )]
    MaxFeePerGasLimitExceeded {
        policy_id: Uuid,
        max_fee_per_gas_wei: u128,
        requested_max_fee_per_gas_wei: u128,
    },
    #[error(
        "policy {policy_id} rejected request: max_priority_fee_per_gas_wei {max_priority_fee_per_gas_wei} < requested {requested_max_priority_fee_per_gas_wei}"
    )]
    PriorityFeePerGasLimitExceeded {
        policy_id: Uuid,
        max_priority_fee_per_gas_wei: u128,
        requested_max_priority_fee_per_gas_wei: u128,
    },
    #[error(
        "policy {policy_id} rejected request: calldata max bytes {max_calldata_bytes} < requested {requested_calldata_bytes}"
    )]
    CalldataBytesLimitExceeded {
        policy_id: Uuid,
        max_calldata_bytes: u128,
        requested_calldata_bytes: u128,
    },
    #[error(
        "policy {policy_id} rejected request: tx_count usage {used_tx_count} + 1 > max {max_tx_count}"
    )]
    TxCountLimitExceeded {
        policy_id: Uuid,
        used_tx_count: u128,
        max_tx_count: u128,
    },
    #[error(
        "policy {policy_id} rejected request: missing required transaction metadata ({metadata})"
    )]
    MissingTransactionMetadata { policy_id: Uuid, metadata: String },
    #[error(
        "policy {policy_id} requires manual approval for requested amount {requested_amount_wei} within range {min_amount_wei:?}..={max_amount_wei}"
    )]
    ManualApprovalRequired {
        policy_id: Uuid,
        min_amount_wei: Option<u128>,
        max_amount_wei: u128,
        requested_amount_wei: u128,
    },
    #[error("policy {policy_id} rejected request: eip712 signing is denied")]
    Eip712SigningDenied { policy_id: Uuid },
    /// A blanket `Eip712Signing = Allow` policy was asked to sign typed data
    /// that moves funds or grants allowances (Permit2, ERC-2612 `Permit`,
    /// EIP-3009 authorizations, Safe transactions, or anything domain-bound to
    /// the canonical Permit2 contract). Those payloads bypass amount, asset,
    /// and recipient scoping when signed through the generic typed-data path,
    /// so they must go through the typed `Permit2Permit` / `Eip3009*` actions
    /// or an eip712 manual-approval policy instead.
    #[error(
        "policy {policy_id} rejected request: eip712 primaryType `{primary_type}` moves funds or grants allowances and cannot be signed under an allow eip712 policy; submit it as a typed permit2/eip3009 action or use an eip712 manual-approval policy"
    )]
    Eip712ValueBearingTypeDenied {
        policy_id: Uuid,
        primary_type: String,
    },
    #[error("eip712 signing requires manual approval{policy_suffix}")]
    Eip712ManualApprovalRequired {
        policy_id: Option<Uuid>,
        policy_suffix: String,
    },
    /// Railgun Proof of Innocence "unshield-only standby period": the wallet
    /// shielded recently and a private-transfer / third-party-unshield is not
    /// allowed until `standby_remaining_seconds` elapses.
    ///
    /// This is a protocol-level constraint, not a configurable policy: most
    /// public Waku broadcasters refuse to relay transactions that skip the
    /// standby window, so submitting the action early would burn the
    /// shielded balance with no on-chain outcome.
    #[error(
        "railgun PoI standby active: last shield {standby_remaining_seconds}s ago, must wait \
         {standby_required_seconds}s total before unshield / private-transfer"
    )]
    PoiStandbyActive {
        standby_remaining_seconds: u64,
        standby_required_seconds: u64,
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
            Self::ManualApprovalRequired { .. } | Self::Eip712ManualApprovalRequired { .. }
        )
    }
}
