//! Domain model for the vault daemon, policy engine, and Agentic SDK.
//!
//! This crate is intentionally dependency-light and transport-agnostic so that
//! all higher-level crates share a single, strongly typed model.

#![forbid(unsafe_code)]

mod action;
mod address;
mod approval;
mod constants;
mod error;
mod keys;
mod nonce;
mod policy;
mod request;
pub mod schema;
mod scope;
pub mod serde_helpers;
mod session;
mod signature;
pub mod u128_as_decimal_string;

pub use action::{
    action_from_erc20_calldata, parse_erc20_call, AgentAction, BroadcastTx, Eip3009Transfer,
    Eip712TypedData, Erc20Call, Permit2Permission, Permit2Witness, Permit2WitnessTransfer,
    SolanaNonceAccountCreate, SolanaPaymentAsset, SolanaPaymentLeg, SolanaPaymentTransaction,
    SolanaSolTransfer, SolanaSplTransfer, SolanaTokenProgram, TempoSessionV2CloseAuthorization,
    TempoSessionV2OpenTransaction, TempoSessionV2TopUpTransaction, TempoSessionV2Voucher,
    TempoTxParams, PERMIT2_ADDRESS, PERMIT2_MAX_DEADLINE_SECS, PERMIT2_MAX_ENTRIES,
    PERMIT2_MAX_EXTERNAL_ID_BYTES,
};
pub use address::{EvmAddress, RecipientId, SolanaAddress};
pub use approval::{
    ApprovalLimit, ApprovalReason, ManualApprovalDecision, ManualApprovalRequest,
    ManualApprovalStatus,
};
pub use constants::{
    canonical_policy_chain_id, is_solana_chain_id, is_tempo_chain_id,
    DEFAULT_MAX_GAS_SPEND_PER_CHAIN_WEI, EIP7702_TX_TYPE, SOLANA_DEVNET_CHAIN_ID,
    SOLANA_MAINNET_CHAIN_ID, SOLANA_NONCE_ACCOUNT_DATA_LEN_BYTES,
    SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS, SOLANA_NONCE_ACCOUNT_RENT_EXEMPT_MINIMUM_LAMPORTS,
    SOLANA_PAYMENT_MAX_COMPUTE_UNIT_LIMIT, SOLANA_PAYMENT_MAX_LEGS, SOLANA_PAYMENT_MAX_MEMO_BYTES,
    SOLANA_POLICY_CHAIN_ID, SOLANA_TESTNET_CHAIN_ID, TEMPO_CHANNEL_RESERVE_CONTRACT,
    TEMPO_MAINNET_CHAIN_ID, TEMPO_TESTNET_CHAIN_ID, TEMPO_TX_TYPE,
};
pub use error::DomainError;
pub use keys::{AgentCredentials, AgentKey, KeyAlgorithm, KeySource, VaultKey};
pub use nonce::{
    NonceReleaseRequest, NonceReservation, NonceReservationRequest, SignedNonceReleaseRequest,
};
pub use policy::{
    ApprovalType, AssetId, OverLimit, PolicyAttachment, PolicyType, SpendEvent, SpendingPolicy,
};
pub use request::SignRequest;
pub use scope::EntityScope;
pub use session::{AdminAuth, AdminChallenge, AdminCredential, AdminLease, AdminSession};
pub use signature::Signature;

#[cfg(test)]
mod tests;
