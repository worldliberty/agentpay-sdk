//! Core daemon authorization and signing pipeline.
//!
//! This crate is transport-agnostic: CLIs, SDKs, and XPC adapters call the
//! same [`KeyManagerDaemonApi`] trait.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use argon2::password_hash::rand_core::OsRng as PasswordOsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, ParamsBuilder};
use async_trait::async_trait;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vault_domain::{
    manual_approval_capability_token, AdminSession, AgentAction, AgentCredentials, AgentKey,
    KeyAlgorithm, Lease, ManualApprovalDecision, ManualApprovalRequest, ManualApprovalStatus,
    NonceReleaseRequest, NonceReservation, NonceReservationRequest, PolicyAttachment, RelayConfig,
    SignRequest, Signature, SpendEvent, SpendingPolicy, VaultKey,
};
use vault_policy::{
    PolicyDecision, PolicyEngine, PolicyError, PolicyEvaluation, PolicyExplanation,
};
use vault_signer::{KeyCreateRequest, SignerError, VaultSignerBackend};
use zeroize::{Zeroize, Zeroizing};

mod persistence;

pub use persistence::PersistentStoreConfig;
use persistence::{EncryptedStateStore, PersistedDaemonState};

type ReusableNonceGaps = HashMap<Uuid, HashMap<u64, BTreeSet<u64>>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegistrationSnapshot {
    pub relay_config: RelayConfig,
    #[serde(with = "vault_domain::serde_helpers::zeroizing_string")]
    pub relay_private_key_hex: Zeroizing<String>,
    pub vault_public_key_hex: Option<String>,
    pub ethereum_address: Option<String>,
    pub policies: Vec<SpendingPolicy>,
    pub agent_keys: Vec<AgentKey>,
    pub manual_approval_requests: Vec<ManualApprovalRequest>,
}

include!("daemon_parts/types_api_rpc.rs");
include!("daemon_parts/core_helpers.rs");
include!("daemon_parts/api_impl_and_utils.rs");

#[cfg(test)]
mod tests;
