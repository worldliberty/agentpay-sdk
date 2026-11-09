//! Signer backend contract shared by every key store the daemon can use.

use std::collections::HashMap;
use std::fmt;

use agentpay_domain::{KeyAlgorithm, Signature, VaultKey};
use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Logical backend category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// In-process software signer; key material is persisted in the encrypted daemon state.
    Software,
    /// TPM 2.0 seal/unseal backend (Linux).
    Tpm,
}

/// Key creation request from daemon/admin.
///
/// Import variants carry raw private key material: it is wrapped in [`Zeroizing`] so it is
/// wiped on drop and redacted from `Debug` output. The serde shape is a plain hex string.
///
/// JSON (externally tagged): `"Generate"`,
/// `{"GenerateWithAlgorithm": {"algorithm": "ed25519"}}`,
/// `{"Import": {"private_key_hex": "<64 hex chars>"}}`, or
/// `{"ImportWithAlgorithm": {"algorithm": "secp256k1", "private_key_hex": "..."}}`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum KeyCreateRequest {
    /// Generate a fresh secp256k1 private key.
    Generate,
    /// Generate a fresh private key with an explicit algorithm.
    GenerateWithAlgorithm {
        /// Algorithm of the new key.
        algorithm: KeyAlgorithm,
    },
    /// Import an existing hex-encoded 32-byte secp256k1 private key.
    Import {
        /// Private key as 64 hex characters, with or without `0x`. Secret.
        #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
        #[schemars(with = "String")]
        #[ts(as = "String")]
        private_key_hex: Zeroizing<String>,
    },
    /// Import an existing hex-encoded 32-byte private key with an explicit algorithm.
    ImportWithAlgorithm {
        /// Algorithm of the imported key.
        algorithm: KeyAlgorithm,
        /// Private key (secp256k1 scalar or Ed25519 seed) as 64 hex
        /// characters, with or without `0x`. Secret.
        #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
        #[schemars(with = "String")]
        #[ts(as = "String")]
        private_key_hex: Zeroizing<String>,
    },
}

impl fmt::Debug for KeyCreateRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generate => formatter.write_str("Generate"),
            Self::GenerateWithAlgorithm { algorithm } => formatter
                .debug_struct("GenerateWithAlgorithm")
                .field("algorithm", algorithm)
                .finish(),
            Self::Import { .. } => formatter
                .debug_struct("Import")
                .field("private_key_hex", &"<redacted>")
                .finish(),
            Self::ImportWithAlgorithm { algorithm, .. } => formatter
                .debug_struct("ImportWithAlgorithm")
                .field("algorithm", algorithm)
                .field("private_key_hex", &"<redacted>")
                .finish(),
        }
    }
}

/// Errors returned by signer backends.
///
/// JSON (externally tagged): for example `"InvalidPrivateKey"` or
/// `{"Unsupported": "broadcast transaction type 0x04 is unsupported for signing"}`.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub enum SignerError {
    /// Unknown key identifier.
    #[error("unknown vault key id: {0}")]
    UnknownKey(Uuid),
    /// Invalid import key material.
    #[error("invalid private key")]
    InvalidPrivateKey,
    /// Operation is intentionally unsupported by backend.
    #[error("backend operation unsupported: {0}")]
    Unsupported(String),
    /// Caller does not satisfy backend security requirements.
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// Backend-specific failure.
    #[error("internal backend failure: {0}")]
    Internal(String),
}

/// Backend interface used by the daemon.
// `async_trait` marks the boxed futures it generates `#[must_use]`, which they already are.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait VaultSignerBackend: Send + Sync {
    /// Returns backend category.
    fn backend_kind(&self) -> BackendKind;

    /// Creates a vault key according to request.
    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError>;

    /// Signs payload with key `vault_key_id`.
    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError>;

    /// Returns the Solana Ed25519 public key derived for `vault_key_id`.
    fn solana_public_key_hex(&self, vault_key_id: Uuid) -> Result<String, SignerError> {
        let _ = vault_key_id;
        Err(unsupported_solana())
    }

    /// Signs a Solana message with the Ed25519 signer derived for `vault_key_id`.
    async fn sign_solana_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        let _ = (vault_key_id, payload);
        Err(unsupported_solana())
    }

    /// Signs a prehashed 32-byte digest with key `vault_key_id`.
    ///
    /// For Ethereum transactions this is the Keccak-256 transaction-signing prehash.
    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError>;

    /// Exports persistable key material for the requested vault key IDs.
    fn export_persistable_key_material(
        &self,
        _vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        Ok(HashMap::new())
    }

    /// Restores persistable key material previously exported by this backend.
    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        if persisted.is_empty() {
            return Ok(());
        }
        Err(SignerError::Unsupported(
            "backend does not support persisted key material".to_string(),
        ))
    }

    /// Deletes a backend key if it exists. Used to roll back key creation when persisting
    /// daemon state fails.
    fn delete_vault_key_if_present(&self, _vault_key_id: Uuid) -> Result<(), SignerError> {
        Ok(())
    }
}

fn unsupported_solana() -> SignerError {
    SignerError::Unsupported("backend does not support Solana signing".to_string())
}
