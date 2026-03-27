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
mod scope;
pub mod serde_helpers;
mod session;
mod signature;
mod u128_as_decimal_string;

pub use action::{
    action_from_erc20_calldata, parse_erc20_call, AgentAction, BroadcastTx, Eip3009Transfer,
    Erc20Call, Permit2Permit, TempoSessionOpenTransaction, TempoSessionTopUpTransaction,
    TempoSessionVoucher,
};
pub use address::EvmAddress;
pub use approval::{
    manual_approval_capability_hash, manual_approval_capability_token, ManualApprovalDecision,
    ManualApprovalRequest, ManualApprovalStatus, RelayConfig, RelayFeedbackStatus,
};
pub use constants::{DEFAULT_MAX_GAS_SPEND_PER_CHAIN_WEI, EIP7702_TX_TYPE};
pub use error::DomainError;
pub use keys::{AgentCredentials, AgentKey, KeySource, VaultKey};
pub use nonce::{NonceReleaseRequest, NonceReservation, NonceReservationRequest};
pub use policy::{AssetId, PolicyAttachment, PolicyType, SpendEvent, SpendingPolicy};
pub use request::SignRequest;
pub use scope::EntityScope;
pub use session::{AdminSession, Lease};
pub use signature::Signature;

#[cfg(test)]
mod tests;
