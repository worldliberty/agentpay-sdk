//! Domain types that appear on the wire.
//!
//! Most are defined in `agentpay-domain`, `agentpay-policy`, and `agentpay-signer` and
//! re-exported here unchanged, so the daemon, the bundled clients, and this
//! contract share one definition. Each type documents its JSON encoding.
//!
//! # Encoding conventions
//!
//! | Rust type | JSON |
//! |---|---|
//! | `Uuid` | lowercase hyphenated string, `"2f6c1d9e-1b7a-4c7e-9f00-6a1e2b3c4d5e"` |
//! | `u128` amounts and limits | decimal string ([`DecimalU128`]), `"1000000000000000000"` |
//! | `u64` chain ids, nonces, gas | JSON number |
//! | `OffsetDateTime` | 9-element array ([`Timestamp`]), `[2026, 309, 12, 30, 0, 0, 0, 0, 0]` |
//! | `Vec<u8>` | array of byte values, `[123, 34, 107]` |
//! | EVM address | `0x` + 40 hex chars; emitted lower case |
//! | Solana address | base58 string |
//! | hex payloads | documented per field (`_hex` suffix); `0x` only where stated |
//!
//! Amount fields named `*_wei` carry the asset's smallest unit: wei for native
//! EVM coins, token base units for ERC-20/TIP-20/SPL tokens, lamports for SOL.
//!
//! # Chain ids
//!
//! EVM and Tempo actions use the EVM chain id (`1`, `56`, `4217`, ...).
//! Solana actions use internal ids ([`SOLANA_MAINNET_CHAIN_ID`] and friends),
//! which policies see as [`SOLANA_POLICY_CHAIN_ID`].

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

pub use agentpay_domain::schema::{DecimalU128, Timestamp};
pub use agentpay_domain::{
    AgentAction, AgentKey, ApprovalType, AssetId, BroadcastTx, Eip3009Transfer, Eip712TypedData,
    EntityScope, EvmAddress, KeyAlgorithm, KeySource, ManualApprovalDecision,
    ManualApprovalRequest, ManualApprovalStatus, NonceReleaseRequest, NonceReservation,
    NonceReservationRequest, PolicyAttachment, PolicyType, RecipientId, SignRequest, Signature,
    SignedNonceReleaseRequest, SolanaAddress, SolanaNonceAccountCreate, SolanaPaymentAsset,
    SolanaPaymentLeg, SolanaPaymentTransaction, SolanaSolTransfer, SolanaSplTransfer,
    SolanaTokenProgram, SpendingPolicy, TempoSessionV2CloseAuthorization,
    TempoSessionV2OpenTransaction, TempoSessionV2TopUpTransaction, TempoSessionV2Voucher,
    TempoTxParams, VaultKey, SOLANA_DEVNET_CHAIN_ID, SOLANA_MAINNET_CHAIN_ID,
    SOLANA_POLICY_CHAIN_ID, SOLANA_TESTNET_CHAIN_ID,
};
pub use agentpay_policy::{PolicyDecision, PolicyError, PolicyEvaluation, PolicyExplanation};
pub use agentpay_signer::{KeyCreateRequest, SignerError};

/// Compact policy metadata, for callers that only need ids and enabled state.
///
/// JSON: `{"id": "<policy uuid>", "enabled": true}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct PolicySummary {
    /// Policy id.
    pub id: Uuid,
    /// Whether the policy is evaluated (`false` after `DisablePolicy`).
    pub enabled: bool,
}

/// Who an agent token belongs to and which addresses it signs for, returned by
/// `AuthenticateAgent`.
///
/// Holds public data only. The payments service uses it to authenticate its
/// callers and to learn the wallet addresses it builds transactions for.
///
/// JSON:
/// ```json
/// {"agent_key": {...}, "vault_key": {...}, "evm_address": "0x...", "solana_address": "9xQe..."}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentIdentity {
    /// The authenticated agent key.
    pub agent_key: AgentKey,
    /// Public metadata of the vault key that signs for this agent.
    pub vault_key: VaultKey,
    /// EVM (and Tempo) address of a `secp256k1` vault key, lower case; `null`
    /// for an `ed25519` key.
    pub evm_address: Option<EvmAddress>,
    /// Solana address (base58 Ed25519 public key) that the vault key signs
    /// Solana actions with; `null` when the signer backend cannot sign for
    /// Solana (the Linux TPM backend).
    pub solana_address: Option<SolanaAddress>,
}

/// The enabled policies that govern an agent, returned by `AgentPolicySummary`.
///
/// It shows what limits the agent is under without their amounts or
/// recipient lists (those stay admin-only, in `ListPolicies`). An agent with
/// `spending_policy_count == 0` cannot spend at all: the signer daemon
/// denies every payment (`NoAttachedPolicies` or `NoApplicablePolicies`)
/// until an operator adds limits.
///
/// JSON:
/// ```json
/// {"attachment": "AllPolicies", "policies": [{"id": "...", "priority": 10, "policy_type": "PerTxMaxSpending", "assets": {"mode": "All"}, "networks": {"mode": "All"}}], "spending_policy_count": 1}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentPolicySummary {
    /// How the agent key is attached to policies (`"AllPolicies"` or a `PolicySet`).
    pub attachment: PolicyAttachment,
    /// Enabled policies that apply to the agent, in evaluation order
    /// (ascending `priority`, then id).
    pub policies: Vec<AgentPolicyInfo>,
    /// How many of `policies` limit payments, that is every type except
    /// `Eip712Signing`. Zero means the agent cannot spend.
    pub spending_policy_count: u32,
}

/// One policy in an [`AgentPolicySummary`]: its kind and scope, without
/// limits or recipients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentPolicyInfo {
    /// Policy id.
    pub id: Uuid,
    /// Evaluation order: lower values are evaluated first.
    pub priority: u32,
    /// What the policy limits.
    pub policy_type: PolicyType,
    /// Assets in scope.
    pub assets: EntityScope<AssetId>,
    /// Policy chain ids in scope.
    pub networks: EntityScope<u64>,
}
