//! Signer backends for vault keys.
//!
//! The daemon depends on [`VaultSignerBackend`] so hardware-backed (Secure
//! Enclave), software-backed, and future TEE-backed implementations can be
//! swapped without changing policy logic.

pub mod railgun;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use k256::elliptic_curve::rand_core::OsRng as Secp256k1OsRng;
use rand::random;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use vault_domain::{
    KeyAlgorithm, KeySource, RailgunDecryptedNote, RailgunMerklePath, RailgunNoteCiphertext,
    RailgunNoteInput, RailgunNullifier, RailgunViewingPublicKeys, RailgunWitnessBundle, Signature,
    VaultKey,
};
use zeroize::Zeroizing;

#[cfg(target_os = "windows")]
mod windows_tpm;
#[cfg(target_os = "windows")]
pub use windows_tpm::{WindowsTpmKeyBlob, WindowsTpmSignerBackend};

#[cfg(target_os = "linux")]
mod linux_tpm;
#[cfg(target_os = "linux")]
pub use linux_tpm::{LinuxTpmKeyBlob, LinuxTpmSignerBackend};

#[cfg(all(target_os = "macos", not(coverage)))]
use core_foundation::base::{TCFType, ToVoid};
#[cfg(all(target_os = "macos", not(coverage)))]
use core_foundation::string::CFString;
#[cfg(all(target_os = "macos", not(coverage)))]
use security_framework::access_control::{ProtectionMode, SecAccessControl};
#[cfg(all(target_os = "macos", not(coverage)))]
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
};
#[cfg(all(target_os = "macos", not(coverage)))]
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
#[cfg(all(target_os = "macos", not(coverage)))]
use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
#[cfg(all(target_os = "macos", not(coverage)))]
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
};

/// Logical backend category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS Secure Enclave + Keychain backend.
    SecureEnclave,
    /// Hardware-backed remote TEE backend.
    Tee,
    /// In-process software signer backend.
    Software,
    /// TPM 2.0 Seal/Unseal backend (Windows/Linux).
    Tpm,
}

/// Key creation request from daemon/admin.
///
/// Import variants carry raw private key material: it is wrapped in
/// [`Zeroizing`] so it is wiped on drop and redacted from `Debug` output. The
/// serde shape is unchanged (a plain hex string).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyCreateRequest {
    /// Generate a fresh private key.
    Generate,
    /// Generate a fresh private key with an explicit algorithm.
    GenerateWithAlgorithm { algorithm: KeyAlgorithm },
    /// Import an existing hex-encoded 32-byte secp256k1 private key.
    Import {
        #[serde(with = "vault_domain::serde_helpers::zeroizing_string")]
        private_key_hex: Zeroizing<String>,
    },
    /// Import an existing hex-encoded 32-byte private key with an explicit algorithm.
    ImportWithAlgorithm {
        algorithm: KeyAlgorithm,
        #[serde(with = "vault_domain::serde_helpers::zeroizing_string")]
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
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Railgun crypto primitive (poseidon / babyjub / EdDSA / bech32m / AES /
    /// X25519 / BIP32) failed for reasons internal to the port.
    #[error("railgun crypto error: {0}")]
    RailgunCrypto(String),
}

/// Backend interface used by daemon.
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
    ///
    /// Software secp256k1 vault keys derive a deterministic Ed25519 signer from
    /// the same 32-byte private key material. Hardware backends that cannot
    /// expose or derive that material should leave this unsupported.
    fn solana_public_key_hex(&self, vault_key_id: Uuid) -> Result<String, SignerError> {
        let _ = vault_key_id;
        Err(SignerError::Unsupported(
            "backend does not support Solana signing".to_string(),
        ))
    }

    /// Signs a Solana message with the Ed25519 signer derived for `vault_key_id`.
    async fn sign_solana_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        let _ = (vault_key_id, payload);
        Err(SignerError::Unsupported(
            "backend does not support Solana signing".to_string(),
        ))
    }

    /// Signs a prehashed 32-byte digest with key `vault_key_id`.
    ///
    /// Digest format is caller-defined; for Ethereum transactions this must be
    /// Keccak-256 transaction-signing prehash.
    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError>;

    /// Returns the encoded Railgun shielded address (`0zk1...`) derived from
    /// the spending + viewing keys for the wallet rooted at `vault_key_id`.
    ///
    /// The default implementation rejects unsupported. Backends that can
    /// derive Baby Jubjub key material override this. Hardware backends that
    /// cannot extract the raw secp256k1 master have nothing to derive from
    /// and should leave the default in place.
    async fn railgun_master_public_key(&self, _vault_key_id: Uuid) -> Result<String, SignerError> {
        Err(SignerError::Unsupported(
            "backend does not support Railgun key derivation".to_string(),
        ))
    }

    /// Returns the X25519 viewing public key + Baby Jubjub spending master
    /// public key for trial-decrypting incoming notes and pinning the spend
    /// authority in zk witnesses.
    async fn railgun_viewing_public_key(
        &self,
        _vault_key_id: Uuid,
    ) -> Result<RailgunViewingPublicKeys, SignerError> {
        Err(SignerError::Unsupported(
            "backend does not support Railgun key derivation".to_string(),
        ))
    }

    /// Computes the Poseidon nullifier for a spent note without exposing the
    /// spending key. Called once per spent note during proof preparation;
    /// the returned 32-byte field element is fed back into the circuit and
    /// also published on-chain to mark the note as spent.
    async fn railgun_compute_nullifier(
        &self,
        _vault_key_id: Uuid,
        _note: &RailgunNoteInput,
    ) -> Result<RailgunNullifier, SignerError> {
        Err(SignerError::Unsupported(
            "backend does not support Railgun nullifier derivation".to_string(),
        ))
    }

    /// Attempts to decrypt one on-chain commitment ciphertext using the
    /// viewing key derived for `vault_key_id`. Returns `Ok(None)` if the
    /// note was sent to a different wallet (decryption did not authenticate).
    async fn railgun_decrypt_note(
        &self,
        _vault_key_id: Uuid,
        _ciphertext: &RailgunNoteCiphertext,
    ) -> Result<Option<RailgunDecryptedNote>, SignerError> {
        Err(SignerError::Unsupported(
            "backend does not support Railgun note decryption".to_string(),
        ))
    }

    /// Bundles the spending-key-derived inputs needed by the snarkjs prover
    /// for an unshield or private-transfer proof: per-note nullifiers,
    /// per-note Baby Jubjub spend signatures, and the spend authority
    /// public key. The sidecar feeds the bundle directly into the circuit
    /// as private witnesses.
    ///
    /// `notes`, `merkle_paths`, and the prover's recipient-and-output list
    /// (passed opaquely through `recipients_payload_hex`) must be index-
    /// aligned; the daemon does not validate semantic alignment.
    async fn railgun_witness_inputs(
        &self,
        _vault_key_id: Uuid,
        _notes: &[RailgunNoteInput],
        _merkle_paths: &[RailgunMerklePath],
        _recipients_payload_hex: &str,
    ) -> Result<RailgunWitnessBundle, SignerError> {
        Err(SignerError::Unsupported(
            "backend does not support Railgun witness generation".to_string(),
        ))
    }

    /// Exports persistable key material for the requested vault key IDs.
    ///
    /// Backends that keep private keys outside daemon persistence (for example
    /// Secure Enclave) should return an empty map.
    fn export_persistable_key_material(
        &self,
        _vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        Ok(HashMap::new())
    }

    /// Restores persistable key material previously exported by this backend.
    ///
    /// Backends that do not support material export/import return an error when
    /// non-empty state is provided.
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

    /// Deletes a backend key if it exists.
    ///
    /// Daemon rollback paths use this to clean up backend-created key material
    /// when daemon state persistence fails after key creation.
    fn delete_vault_key_if_present(&self, _vault_key_id: Uuid) -> Result<(), SignerError> {
        Ok(())
    }
}

/// Optional extension for backends capable of cryptographic attestation.
#[async_trait]
pub trait AttestableSignerBackend: VaultSignerBackend {
    /// Returns an attestation document proving key/backend identity.
    async fn attestation_document(&self) -> Result<Vec<u8>, SignerError>;
}

/// Pure software signer for development and tests.
#[derive(Debug, Clone, Default)]
pub struct SoftwareSignerBackend {
    keys: Arc<RwLock<HashMap<Uuid, SoftwareSigningKey>>>,
}

#[derive(Debug, Clone)]
enum SoftwareSigningKey {
    Secp256k1(SigningKey),
    Ed25519(Ed25519SigningKey),
}

impl SoftwareSignerBackend {
    fn secp256k1_public_key_hex(signing_key: &SigningKey) -> String {
        let verifying_key = signing_key.verifying_key();
        hex::encode(verifying_key.to_encoded_point(false).as_bytes())
    }

    fn ed25519_public_key_hex(signing_key: &Ed25519SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    fn derive_ed25519_from_secp256k1(signing_key: &SigningKey) -> Ed25519SigningKey {
        let private_key_bytes = Zeroizing::new(signing_key.to_bytes());
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&private_key_bytes);
        Ed25519SigningKey::from_bytes(&seed)
    }

    fn solana_signing_key(signing_key: &SoftwareSigningKey) -> Ed25519SigningKey {
        match signing_key {
            SoftwareSigningKey::Secp256k1(signing_key) => {
                Self::derive_ed25519_from_secp256k1(signing_key)
            }
            SoftwareSigningKey::Ed25519(signing_key) => signing_key.clone(),
        }
    }

    fn ed25519_signature(payload: &[u8], signing_key: &Ed25519SigningKey) -> Signature {
        let signature = signing_key.sign(payload);
        Signature {
            bytes: signature.to_bytes().to_vec(),
            signature_base58: Some(bs58::encode(signature.to_bytes()).into_string()),
            ..Signature::default()
        }
    }

    fn map_recoverable_digest_signature<T, E>(
        result: Result<(EcdsaSignature, T), E>,
    ) -> Result<Signature, SignerError>
    where
        E: std::fmt::Display,
    {
        let (signature, _) = result.map_err(|err| {
            SignerError::Internal(format!(
                "recoverable digest signature creation failed: {err}"
            ))
        })?;
        Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
    }

    fn parse_import_secp256k1_key(private_key_hex: &str) -> Result<SigningKey, SignerError> {
        let raw = Zeroizing::new(
            hex::decode(
                private_key_hex
                    .strip_prefix("0x")
                    .unwrap_or(private_key_hex),
            )
            .map_err(|_| SignerError::InvalidPrivateKey)?,
        );
        if raw.len() != 32 {
            return Err(SignerError::InvalidPrivateKey);
        }
        SigningKey::from_slice(&raw).map_err(|_| SignerError::InvalidPrivateKey)
    }

    fn parse_import_ed25519_key(private_key_hex: &str) -> Result<Ed25519SigningKey, SignerError> {
        let raw = Zeroizing::new(
            hex::decode(
                private_key_hex
                    .strip_prefix("0x")
                    .unwrap_or(private_key_hex),
            )
            .map_err(|_| SignerError::InvalidPrivateKey)?,
        );
        let bytes = Zeroizing::new(
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| SignerError::InvalidPrivateKey)?,
        );
        Ok(Ed25519SigningKey::from_bytes(&bytes))
    }
}

#[async_trait]
impl VaultSignerBackend for SoftwareSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Software
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        let (signing_key, source, algorithm, public_key_hex) = match request {
            KeyCreateRequest::Generate => {
                let key = SigningKey::random(&mut Secp256k1OsRng);
                let public_key_hex = Self::secp256k1_public_key_hex(&key);
                (
                    SoftwareSigningKey::Secp256k1(key),
                    KeySource::Generated,
                    KeyAlgorithm::Secp256k1,
                    public_key_hex,
                )
            }
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
            } => {
                let key = SigningKey::random(&mut Secp256k1OsRng);
                let public_key_hex = Self::secp256k1_public_key_hex(&key);
                (
                    SoftwareSigningKey::Secp256k1(key),
                    KeySource::Generated,
                    KeyAlgorithm::Secp256k1,
                    public_key_hex,
                )
            }
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            } => {
                let seed = Zeroizing::new(random::<[u8; 32]>());
                let key = Ed25519SigningKey::from_bytes(&seed);
                let public_key_hex = Self::ed25519_public_key_hex(&key);
                (
                    SoftwareSigningKey::Ed25519(key),
                    KeySource::Generated,
                    KeyAlgorithm::Ed25519,
                    public_key_hex,
                )
            }
            KeyCreateRequest::Import { private_key_hex } => {
                let key = Self::parse_import_secp256k1_key(&private_key_hex)?;
                let public_key_hex = Self::secp256k1_public_key_hex(&key);
                (
                    SoftwareSigningKey::Secp256k1(key),
                    KeySource::Imported,
                    KeyAlgorithm::Secp256k1,
                    public_key_hex,
                )
            }
            KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
                private_key_hex,
            } => {
                let key = Self::parse_import_secp256k1_key(&private_key_hex)?;
                let public_key_hex = Self::secp256k1_public_key_hex(&key);
                (
                    SoftwareSigningKey::Secp256k1(key),
                    KeySource::Imported,
                    KeyAlgorithm::Secp256k1,
                    public_key_hex,
                )
            }
            KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
                private_key_hex,
            } => {
                let key = Self::parse_import_ed25519_key(&private_key_hex)?;
                let public_key_hex = Self::ed25519_public_key_hex(&key);
                (
                    SoftwareSigningKey::Ed25519(key),
                    KeySource::Imported,
                    KeyAlgorithm::Ed25519,
                    public_key_hex,
                )
            }
            // Railgun keys are derived on demand from the existing Secp256k1
            // master inside the railgun_* trait methods rather than persisted
            // as independent vault keys. The standalone create/import paths
            // are intentionally rejected to keep the trust boundary narrow
            // (only one private key lives in the daemon per wallet).
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::RailgunSpending | KeyAlgorithm::RailgunViewing,
            }
            | KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::RailgunSpending | KeyAlgorithm::RailgunViewing,
                ..
            } => {
                return Err(SignerError::Unsupported(
                    "Railgun keys are derived from the existing secp256k1 master; \
                     use the railgun_* signer methods instead of creating a standalone key"
                        .to_string(),
                ));
            }
        };

        let key_id = Uuid::new_v4();
        let created_at = OffsetDateTime::now_utc();

        self.keys
            .write()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?
            .insert(key_id, signing_key);

        Ok(VaultKey {
            id: key_id,
            source,
            algorithm,
            public_key_hex,
            created_at,
        })
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
        let signing_key = keys
            .get(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        match signing_key {
            SoftwareSigningKey::Secp256k1(signing_key) => {
                let signature: EcdsaSignature = signing_key.sign(payload);
                Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
            }
            SoftwareSigningKey::Ed25519(signing_key) => {
                Ok(Self::ed25519_signature(payload, signing_key))
            }
        }
    }

    fn solana_public_key_hex(&self, vault_key_id: Uuid) -> Result<String, SignerError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
        let signing_key = keys
            .get(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        Ok(Self::ed25519_public_key_hex(&Self::solana_signing_key(
            signing_key,
        )))
    }

    async fn sign_solana_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
        let signing_key = keys
            .get(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        Ok(Self::ed25519_signature(
            payload,
            &Self::solana_signing_key(signing_key),
        ))
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
        let signing_key = keys
            .get(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        match signing_key {
            SoftwareSigningKey::Secp256k1(signing_key) => Self::map_recoverable_digest_signature(
                signing_key.sign_prehash_recoverable(&digest),
            ),
            SoftwareSigningKey::Ed25519(_) => Err(SignerError::Unsupported(
                "ed25519 keys do not support prehashed digest signing".to_string(),
            )),
        }
    }

    fn export_persistable_key_material(
        &self,
        vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
        let mut exported = HashMap::with_capacity(vault_key_ids.len());
        for vault_key_id in vault_key_ids {
            let signing_key = keys
                .get(vault_key_id)
                .ok_or(SignerError::UnknownKey(*vault_key_id))?;
            match signing_key {
                SoftwareSigningKey::Secp256k1(signing_key) => {
                    let private_key_bytes = Zeroizing::new(signing_key.to_bytes());
                    exported.insert(
                        *vault_key_id,
                        Zeroizing::new(format!("secp256k1:{}", hex::encode(&*private_key_bytes))),
                    );
                }
                SoftwareSigningKey::Ed25519(signing_key) => {
                    let private_key_bytes = Zeroizing::new(signing_key.to_bytes());
                    exported.insert(
                        *vault_key_id,
                        Zeroizing::new(format!("ed25519:{}", hex::encode(&*private_key_bytes))),
                    );
                }
            }
        }
        Ok(exported)
    }

    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        let mut restored = HashMap::with_capacity(persisted.len());
        for (vault_key_id, private_key_hex) in persisted {
            let normalized = private_key_hex.as_str();
            let (prefix, material) = normalized
                .split_once(':')
                .unwrap_or(("secp256k1", normalized));
            let signing_key = match prefix {
                "secp256k1" => {
                    SoftwareSigningKey::Secp256k1(Self::parse_import_secp256k1_key(material)?)
                }
                "ed25519" => SoftwareSigningKey::Ed25519(Self::parse_import_ed25519_key(material)?),
                _ => {
                    return Err(SignerError::Internal(format!(
                        "unsupported persisted software key algorithm '{prefix}'"
                    )))
                }
            };
            restored.insert(*vault_key_id, signing_key);
        }
        *self
            .keys
            .write()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))? = restored;
        Ok(())
    }

    fn delete_vault_key_if_present(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
        self.keys
            .write()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?
            .remove(&vault_key_id);
        Ok(())
    }

    // Railgun derivation surface. The software backend is the only one
    // capable of supporting Railgun (Secure Enclave / TPM keys cannot be
    // extracted to feed Baby Jubjub derivation). Track 2 Phase B landed the
    // primitives in `crate::railgun::*`; the three key-derivation methods
    // below are wired through `wallet::derive_wallet_keys`, which uses the
    // existing secp256k1 vault key bytes as the Railgun BIP-32 seed (the
    // daemon never owns an independent BIP-39 mnemonic for the user). Each
    // wallet thus has a single deterministic Railgun shielded address.
    //
    // `decrypt_note` and `witness_inputs` remain `Unsupported`: they require
    // wire-format details (note plaintext layout, prover input assembly) that
    // live in the Track 3 engine fork and the Track 4 prover sidecar
    // respectively. Phase B only owns the primitives, not the orchestration.

    async fn railgun_master_public_key(&self, vault_key_id: Uuid) -> Result<String, SignerError> {
        let keys = self.derive_railgun_wallet_keys(vault_key_id)?;
        Ok(keys.encoded_address)
    }

    async fn railgun_viewing_public_key(
        &self,
        vault_key_id: Uuid,
    ) -> Result<RailgunViewingPublicKeys, SignerError> {
        let keys = self.derive_railgun_wallet_keys(vault_key_id)?;
        Ok(RailgunViewingPublicKeys {
            viewing_pubkey_hex: hex::encode(keys.viewing_public_key),
            master_pubkey_hex: hex::encode(keys.master_public_key),
        })
    }

    async fn railgun_compute_nullifier(
        &self,
        vault_key_id: Uuid,
        note: &RailgunNoteInput,
    ) -> Result<RailgunNullifier, SignerError> {
        let keys = self.derive_railgun_wallet_keys(vault_key_id)?;
        let nullifier =
            crate::railgun::wallet::get_nullifier(&keys.nullifying_key, note.leaf_index)?;
        Ok(RailgunNullifier {
            nullifier_hex: hex::encode(nullifier),
        })
    }

    async fn railgun_decrypt_note(
        &self,
        vault_key_id: Uuid,
        ciphertext: &RailgunNoteCiphertext,
    ) -> Result<Option<RailgunDecryptedNote>, SignerError> {
        let keys = self.derive_railgun_wallet_keys(vault_key_id)?;

        fn decode_fixed<const N: usize>(label: &str, value: &str) -> Result<[u8; N], SignerError> {
            let normalized = value.strip_prefix("0x").unwrap_or(value);
            let bytes = hex::decode(normalized)
                .map_err(|e| SignerError::RailgunCrypto(format!("{label} hex: {e}")))?;
            <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| {
                SignerError::RailgunCrypto(format!("{label} must encode exactly {N} bytes"))
            })
        }

        let ephemeral_pub =
            decode_fixed::<32>("ephemeralPubkeyHex", &ciphertext.ephemeral_pubkey_hex)?;
        let iv = decode_fixed::<16>("ivHex", &ciphertext.iv_hex)?;
        let tag = decode_fixed::<16>("tagHex", &ciphertext.tag_hex)?;

        let mut ct_bytes = Vec::with_capacity(ciphertext.data_chunks_hex.len() * 32);
        for (i, chunk_hex) in ciphertext.data_chunks_hex.iter().enumerate() {
            let chunk = decode_fixed::<32>(&format!("dataChunksHex[{i}]"), chunk_hex)?;
            ct_bytes.extend_from_slice(&chunk);
        }

        let chunks = crate::railgun::wallet::decrypt_note_chunks(
            &keys.viewing_private_key,
            &ephemeral_pub,
            &iv,
            &ct_bytes,
            &tag,
        )?;

        Ok(chunks.map(|cs| RailgunDecryptedNote {
            chunks_hex: cs.into_iter().map(|c| hex::encode(c)).collect(),
        }))
    }

    async fn railgun_witness_inputs(
        &self,
        vault_key_id: Uuid,
        notes: &[RailgunNoteInput],
        merkle_paths: &[RailgunMerklePath],
        recipients_payload_hex: &str,
    ) -> Result<RailgunWitnessBundle, SignerError> {
        // Currently unused; reserved for future Railgun variants that bind the
        // signature to specific Merkle paths. The sidecar still passes them so
        // the trait shape stays stable.
        let _ = merkle_paths;

        let keys = self.derive_railgun_wallet_keys(vault_key_id)?;

        // Contract: `recipients_payload_hex` is the sidecar's pre-computed
        // Poseidon digest of the full Railgun-side message
        // (poseidon([merkleRoot, boundParamsHash, ...nullifiers, ...commitmentsOut])).
        // We require it pre-hashed so the daemon does not have to know the
        // exact Railgun message-assembly shape (which changes per protocol
        // version) — only sign it under the spending key.
        let normalized = recipients_payload_hex
            .strip_prefix("0x")
            .unwrap_or(recipients_payload_hex);
        let payload_bytes = hex::decode(normalized)
            .map_err(|e| SignerError::RailgunCrypto(format!("recipients_payload_hex: {e}")))?;
        if payload_bytes.len() != 32 {
            return Err(SignerError::RailgunCrypto(format!(
                "recipients_payload_hex must encode exactly 32 bytes (the sidecar's pre-hashed \
                 Poseidon digest); got {} bytes",
                payload_bytes.len()
            )));
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&payload_bytes);

        let mut nullifiers_hex = Vec::with_capacity(notes.len());
        for note in notes {
            let nullifier =
                crate::railgun::wallet::get_nullifier(&keys.nullifying_key, note.leaf_index)?;
            nullifiers_hex.push(hex::encode(nullifier));
        }

        let signature = crate::railgun::eddsa::sign_poseidon(&keys.spending_private_key, &digest)?;

        let pubkey_packed = crate::railgun::babyjubjub::pack_point(
            &crate::railgun::eddsa::prv_to_pub(&keys.spending_private_key),
        );

        Ok(RailgunWitnessBundle {
            nullifiers_hex,
            spending_signatures_hex: vec![hex::encode(signature.to_unpacked_xy_s_bytes())],
            spend_authority_pubkey_hex: hex::encode(pubkey_packed),
        })
    }
}

impl SoftwareSignerBackend {
    /// Derives the full Railgun wallet (index 0) from the existing secp256k1
    /// vault key. Used by the `railgun_*` trait methods to keep the wallet
    /// keys ephemeral — nothing about the Railgun keypair is persisted in
    /// daemon state; each call re-derives from the underlying secp256k1
    /// material.
    fn derive_railgun_wallet_keys(
        &self,
        vault_key_id: Uuid,
    ) -> Result<crate::railgun::wallet::RailgunWalletKeys, SignerError> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
        let signing_key = keys
            .get(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        let raw = match signing_key {
            SoftwareSigningKey::Secp256k1(sk) => Zeroizing::new(sk.to_bytes()),
            SoftwareSigningKey::Ed25519(_) => {
                return Err(SignerError::Unsupported(
                    "Railgun derivation requires a secp256k1 vault key; Ed25519-only keys cannot \
                     seed a Railgun wallet"
                        .to_string(),
                ));
            }
        };
        // Wallet index 0 is the only one we surface today; per-wallet
        // multiplicity (different shielded addresses for the same root key)
        // lands when there's a product reason to expose it.
        crate::railgun::wallet::derive_wallet_keys(raw.as_ref(), 0)
    }
}

/// Real macOS Secure Enclave signer.
///
/// Generated keys are permanent Keychain items with `PRIVATE_KEY_USAGE`
/// access control and `kSecAttrTokenIDSecureEnclave` token binding.
#[derive(Debug, Clone)]
pub struct SecureEnclaveSignerBackend {
    label_prefix: String,
}

impl Default for SecureEnclaveSignerBackend {
    fn default() -> Self {
        Self::new("com.agentpay.vault")
    }
}

impl SecureEnclaveSignerBackend {
    /// Creates backend with a key label prefix.
    #[must_use]
    pub fn new(label_prefix: impl Into<String>) -> Self {
        Self {
            label_prefix: label_prefix.into(),
        }
    }

    fn key_label(&self, key_id: Uuid) -> String {
        format!("{}.{key_id}", self.label_prefix)
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn require_root_euid(euid: u32) -> Result<(), SignerError> {
        if euid != 0 {
            return Err(SignerError::PermissionDenied(
                "secure enclave backend requires root daemon context".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn require_root() -> Result<(), SignerError> {
        Self::require_root_euid(unsafe { libc::geteuid() })
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn make_access_control() -> Result<SecAccessControl, SignerError> {
        SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|err| SignerError::Internal(format!("unable to create access control: {err}")))
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn generate_secure_enclave_key(&self, key_id: Uuid) -> Result<SecKey, SignerError> {
        let label = self.key_label(key_id);
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_label(label)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(Self::make_access_control()?);

        SecKey::new(&options).map_err(|err| {
            SignerError::Internal(format!("secure enclave key generation failed: {err}"))
        })
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn find_private_key(&self, key_id: Uuid) -> Result<SecKey, SignerError> {
        let label = self.key_label(key_id);
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(&label)
            .load_refs(true)
            .limit(Limit::All)
            .ignore_legacy_keychains();

        let mut results = search
            .search()
            .map_err(|err| SignerError::Internal(format!("key lookup failed: {err}")))?;
        if results.is_empty() {
            return Err(SignerError::UnknownKey(key_id));
        }
        if results.len() > 1 {
            return Err(SignerError::Internal(format!(
                "multiple keychain private keys matched label for vault key {key_id}; refusing ambiguous lookup"
            )));
        }

        let first = results
            .pop()
            .ok_or_else(|| SignerError::Internal("missing search result".to_string()))?;

        match first {
            SearchResult::Ref(Reference::Key(key)) => {
                Self::validate_secure_enclave_key_attributes(&key, key_id)?;
                Ok(key)
            }
            _ => Err(SignerError::Internal(
                "unexpected keychain search result type".to_string(),
            )),
        }
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn validate_secure_enclave_key_attributes(
        key: &SecKey,
        key_id: Uuid,
    ) -> Result<(), SignerError> {
        let attrs = key.attributes();
        let token_attr = attrs
            .find(unsafe { kSecAttrTokenID }.to_void())
            .ok_or_else(|| {
                SignerError::Internal(format!(
                    "resolved key for vault key {key_id} is missing token-id attribute"
                ))
            })?;
        let token_value = format!("{}", unsafe {
            CFString::wrap_under_get_rule(token_attr.cast())
        });
        let expected_secure_enclave_token = format!("{}", unsafe {
            CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave)
        });
        if token_value != expected_secure_enclave_token {
            return Err(SignerError::Internal(format!(
                "resolved key for vault key {key_id} is not secure-enclave backed"
            )));
        }

        let access_control = attrs
            .find(unsafe { kSecAttrAccessControl }.to_void())
            .ok_or_else(|| {
                SignerError::Internal(format!(
                    "resolved key for vault key {key_id} is missing access-control metadata"
                ))
            })?;
        if access_control.is_null() {
            return Err(SignerError::Internal(format!(
                "resolved key for vault key {key_id} has null access-control metadata"
            )));
        }

        Ok(())
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn public_key_hex(private_key: &SecKey) -> Result<String, SignerError> {
        let public_key = private_key
            .public_key()
            .ok_or_else(|| SignerError::Internal("missing public key".to_string()))?;
        let data = public_key.external_representation().ok_or_else(|| {
            SignerError::Internal("missing public key representation".to_string())
        })?;
        Ok(hex::encode(data.bytes()))
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    fn delete_if_present(&self, key_id: Uuid) -> Result<(), SignerError> {
        match self.find_private_key(key_id) {
            Ok(key) => key
                .delete()
                .map_err(|err| SignerError::Internal(format!("key cleanup failed: {err}"))),
            Err(SignerError::UnknownKey(_)) => Ok(()),
            Err(other) => Err(other),
        }
    }
}

#[async_trait]
impl VaultSignerBackend for SecureEnclaveSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::SecureEnclave
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        #[cfg(any(not(target_os = "macos"), coverage))]
        {
            let _ = request;
            return Err(SignerError::Unsupported(
                "Secure Enclave backend requires macOS".to_string(),
            ));
        }

        #[cfg(all(target_os = "macos", not(coverage)))]
        {
            match request {
                KeyCreateRequest::Generate
                | KeyCreateRequest::GenerateWithAlgorithm {
                    algorithm: KeyAlgorithm::Secp256k1,
                } => {
                    Self::require_root()?;
                    let key_id = Uuid::new_v4();
                    let private_key = self.generate_secure_enclave_key(key_id)?;
                    let public_key_hex = Self::public_key_hex(&private_key)?;
                    Ok(VaultKey {
                        id: key_id,
                        source: KeySource::Generated,
                        algorithm: KeyAlgorithm::Secp256k1,
                        public_key_hex,
                        created_at: OffsetDateTime::now_utc(),
                    })
                }
                KeyCreateRequest::GenerateWithAlgorithm {
                    algorithm: KeyAlgorithm::Ed25519,
                } => Err(SignerError::Unsupported(
                    "Secure Enclave backend does not support Ed25519 keys".to_string(),
                )),
                KeyCreateRequest::GenerateWithAlgorithm {
                    algorithm: KeyAlgorithm::RailgunSpending | KeyAlgorithm::RailgunViewing,
                } => Err(SignerError::Unsupported(
                    "Secure Enclave backend does not support Railgun keys; Railgun requires \
                     extractable software-resident key material for zk witness generation"
                        .to_string(),
                )),
                KeyCreateRequest::Import { .. } | KeyCreateRequest::ImportWithAlgorithm { .. } => Err(SignerError::Unsupported(
                    "Secure Enclave keys are non-importable; use a non-enclave backend for imports"
                        .to_string(),
                )),
            }
        }
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        #[cfg(any(not(target_os = "macos"), coverage))]
        {
            let _ = (vault_key_id, payload);
            return Err(SignerError::Unsupported(
                "Secure Enclave backend requires macOS".to_string(),
            ));
        }

        #[cfg(all(target_os = "macos", not(coverage)))]
        {
            Self::require_root()?;
            let private_key = self.find_private_key(vault_key_id)?;
            let bytes = private_key
                .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, payload)
                .map_err(|err| {
                    SignerError::Internal(format!("signature creation failed: {err}"))
                })?;
            Ok(Signature::from_der(bytes))
        }
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        #[cfg(any(not(target_os = "macos"), coverage))]
        {
            let _ = (vault_key_id, digest);
            return Err(SignerError::Unsupported(
                "Secure Enclave backend requires macOS".to_string(),
            ));
        }

        #[cfg(all(target_os = "macos", not(coverage)))]
        {
            Self::require_root()?;
            let private_key = self.find_private_key(vault_key_id)?;
            let bytes = private_key
                .create_signature(Algorithm::ECDSASignatureDigestX962, &digest)
                .map_err(|err| {
                    SignerError::Internal(format!("digest signature creation failed: {err}"))
                })?;
            Ok(Signature::from_der(bytes))
        }
    }

    fn delete_vault_key_if_present(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
        #[cfg(any(not(target_os = "macos"), coverage))]
        {
            let _ = vault_key_id;
            return Ok(());
        }

        #[cfg(all(target_os = "macos", not(coverage)))]
        {
            Self::require_root()?;
            self.delete_if_present(vault_key_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use async_trait::async_trait;
    use uuid::Uuid;

    use vault_domain::KeyAlgorithm;

    use super::{
        AttestableSignerBackend, BackendKind, KeyCreateRequest, SecureEnclaveSignerBackend,
        Signature, SignerError, SoftwareSignerBackend, VaultKey, VaultSignerBackend,
    };

    #[derive(Default)]
    struct DummyTeeBackend;

    #[async_trait]
    impl VaultSignerBackend for DummyTeeBackend {
        fn backend_kind(&self) -> BackendKind {
            BackendKind::Tee
        }

        async fn create_vault_key(
            &self,
            _request: KeyCreateRequest,
        ) -> Result<VaultKey, SignerError> {
            Err(SignerError::Unsupported("not implemented".to_string()))
        }

        async fn sign_payload(
            &self,
            _vault_key_id: Uuid,
            _payload: &[u8],
        ) -> Result<Signature, SignerError> {
            Err(SignerError::Unsupported("not implemented".to_string()))
        }

        async fn sign_digest(
            &self,
            _vault_key_id: Uuid,
            _digest: [u8; 32],
        ) -> Result<Signature, SignerError> {
            Err(SignerError::Unsupported("not implemented".to_string()))
        }
    }

    #[async_trait]
    impl AttestableSignerBackend for DummyTeeBackend {
        async fn attestation_document(&self) -> Result<Vec<u8>, SignerError> {
            Ok(vec![0xde, 0xad, 0xbe, 0xef])
        }
    }

    fn poison_backend_lock(backend: &SoftwareSignerBackend) {
        let clone = backend.clone();
        let _ = std::thread::spawn(move || {
            let _guard = clone.keys.write().expect("write lock");
            panic!("poison signer backend lock");
        })
        .join();
    }

    #[tokio::test]
    async fn trait_defaults_and_backend_kinds_cover_remaining_variants() {
        let backend = DummyTeeBackend;
        assert_eq!(backend.backend_kind(), BackendKind::Tee);
        assert!(matches!(
            backend.create_vault_key(KeyCreateRequest::Generate).await,
            Err(SignerError::Unsupported(message)) if message == "not implemented"
        ));
        assert!(matches!(
            backend.sign_payload(Uuid::new_v4(), b"payload").await,
            Err(SignerError::Unsupported(message)) if message == "not implemented"
        ));
        assert!(matches!(
            backend.sign_digest(Uuid::new_v4(), [0x11; 32]).await,
            Err(SignerError::Unsupported(message)) if message == "not implemented"
        ));
        assert!(matches!(
            backend.solana_public_key_hex(Uuid::new_v4()),
            Err(SignerError::Unsupported(message)) if message == "backend does not support Solana signing"
        ));
        assert!(matches!(
            backend.sign_solana_payload(Uuid::new_v4(), b"payload").await,
            Err(SignerError::Unsupported(message)) if message == "backend does not support Solana signing"
        ));
        assert_eq!(
            backend
                .export_persistable_key_material(&[])
                .expect("default export"),
            HashMap::new()
        );
        backend
            .delete_vault_key_if_present(Uuid::new_v4())
            .expect("default delete");
        assert!(backend
            .restore_persistable_key_material(&HashMap::new())
            .is_ok());
        assert!(matches!(
            backend.restore_persistable_key_material(&HashMap::from([(
                Uuid::new_v4(),
                "11".repeat(32).into()
            )])),
            Err(SignerError::Unsupported(_))
        ));
        assert_eq!(
            backend.attestation_document().await.expect("attestation"),
            vec![0xde, 0xad, 0xbe, 0xef]
        );

        let software = SoftwareSignerBackend::default();
        assert_eq!(software.backend_kind(), BackendKind::Software);

        let enclave = SecureEnclaveSignerBackend::new("com.agentpay.coverage");
        assert_eq!(enclave.backend_kind(), BackendKind::SecureEnclave);
        assert_eq!(
            enclave.key_label(Uuid::nil()),
            "com.agentpay.coverage.00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn key_create_request_debug_redacts_private_key_material() {
        let secret = "11".repeat(32);
        let import = KeyCreateRequest::Import {
            private_key_hex: secret.clone().into(),
        };
        let import_with_algorithm = KeyCreateRequest::ImportWithAlgorithm {
            algorithm: KeyAlgorithm::Ed25519,
            private_key_hex: secret.clone().into(),
        };

        for rendered in [format!("{import:?}"), format!("{import_with_algorithm:?}")] {
            assert!(!rendered.contains(&secret), "{rendered}");
            assert!(rendered.contains("<redacted>"), "{rendered}");
        }
        assert!(format!("{import_with_algorithm:?}").contains("Ed25519"));
        assert_eq!(format!("{:?}", KeyCreateRequest::Generate), "Generate");
        assert_eq!(
            format!(
                "{:?}",
                KeyCreateRequest::GenerateWithAlgorithm {
                    algorithm: KeyAlgorithm::Secp256k1
                }
            ),
            "GenerateWithAlgorithm { algorithm: Secp256k1 }"
        );
    }

    #[test]
    fn key_create_request_serde_shape_is_a_plain_hex_string() {
        let secret = "11".repeat(32);
        let import = KeyCreateRequest::Import {
            private_key_hex: secret.clone().into(),
        };

        let json = serde_json::to_string(&import).expect("serialize");
        assert_eq!(
            json,
            format!(r#"{{"Import":{{"private_key_hex":"{secret}"}}}}"#)
        );
        let decoded: KeyCreateRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, import);

        let with_algorithm: KeyCreateRequest = serde_json::from_str(&format!(
            r#"{{"ImportWithAlgorithm":{{"algorithm":"ed25519","private_key_hex":"{secret}"}}}}"#
        ))
        .expect("deserialize legacy shape");
        assert_eq!(
            with_algorithm,
            KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
                private_key_hex: secret.into(),
            }
        );
    }

    #[tokio::test]
    async fn import_path_marks_keys_as_imported_and_accepts_prefixed_hex() {
        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: format!("0x{}", "11".repeat(32)).into(),
            })
            .await
            .expect("must import key");

        assert_eq!(key.source, vault_domain::KeySource::Imported);
        assert!(!key.public_key_hex.is_empty());
    }

    #[tokio::test]
    async fn software_backend_rejects_unknown_keys_and_poisoned_locks() {
        let backend = SoftwareSignerBackend::default();
        let unknown = Uuid::new_v4();
        assert!(matches!(
            backend.sign_payload(unknown, b"payload").await,
            Err(SignerError::UnknownKey(id)) if id == unknown
        ));
        assert!(matches!(
            backend.sign_digest(unknown, [0x11; 32]).await,
            Err(SignerError::UnknownKey(id)) if id == unknown
        ));
        assert!(matches!(
            backend.export_persistable_key_material(&[unknown]),
            Err(SignerError::UnknownKey(id)) if id == unknown
        ));

        let poisoned = SoftwareSignerBackend::default();
        poison_backend_lock(&poisoned);
        assert!(matches!(
            poisoned.create_vault_key(KeyCreateRequest::Generate).await,
            Err(SignerError::Internal(_))
        ));
        assert!(matches!(
            poisoned.sign_payload(Uuid::new_v4(), b"payload").await,
            Err(SignerError::Internal(_))
        ));
        assert!(matches!(
            poisoned.sign_digest(Uuid::new_v4(), [0x22; 32]).await,
            Err(SignerError::Internal(_))
        ));
        assert!(matches!(
            poisoned.export_persistable_key_material(&[]),
            Err(SignerError::Internal(_))
        ));
        assert!(matches!(
            poisoned.restore_persistable_key_material(&HashMap::new()),
            Err(SignerError::Internal(_))
        ));
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    #[test]
    fn secure_enclave_root_requirement_helper_covers_root_and_non_root() {
        assert!(SecureEnclaveSignerBackend::require_root_euid(0).is_ok());
        assert!(matches!(
            SecureEnclaveSignerBackend::require_root_euid(501),
            Err(SignerError::PermissionDenied(_))
        ));
    }

    #[tokio::test]
    async fn generated_key_can_sign_payload() {
        use k256::ecdsa::Signature as K256Signature;

        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        let sig = backend
            .sign_payload(key.id, b"payload")
            .await
            .expect("must sign");

        let parsed = K256Signature::from_der(&sig.bytes).expect("must be DER");
        assert!(!parsed.to_bytes().is_empty());
    }

    #[tokio::test]
    async fn secp256k1_key_derives_solana_public_key_and_signer() {
        use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};

        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: "11".repeat(32).into(),
            })
            .await
            .expect("must import key");

        let solana_public_key_hex = backend
            .solana_public_key_hex(key.id)
            .expect("solana public key");
        assert_eq!(solana_public_key_hex.len(), 64);
        assert_ne!(solana_public_key_hex, key.public_key_hex);

        let signature = backend
            .sign_solana_payload(key.id, b"solana-message")
            .await
            .expect("must sign solana payload");
        assert_eq!(signature.bytes.len(), 64);
        assert!(signature.signature_base58.is_some());

        let public_key_bytes = <[u8; 32]>::try_from(
            hex::decode(solana_public_key_hex)
                .expect("public key hex")
                .as_slice(),
        )
        .expect("public key bytes");
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).expect("verifying key");
        let ed25519_signature =
            Ed25519Signature::from_slice(&signature.bytes).expect("ed25519 signature");
        verifying_key
            .verify(b"solana-message", &ed25519_signature)
            .expect("valid ed25519 signature");
    }

    #[tokio::test]
    async fn generated_key_can_sign_digest() {
        use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        let digest = [0x42u8; 32];
        let sig = backend
            .sign_digest(key.id, digest)
            .await
            .expect("must sign digest");

        let parsed = K256Signature::from_der(&sig.bytes).expect("must be DER");
        let verifying_key = VerifyingKey::from_sec1_bytes(
            &hex::decode(&key.public_key_hex).expect("public key hex"),
        )
        .expect("verifying key");
        let recovery_id = RecoveryId::trial_recovery_from_prehash(&verifying_key, &digest, &parsed)
            .expect("must derive recovery id");
        let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed, recovery_id)
            .expect("must recover verifying key");
        assert_eq!(recovered, verifying_key);
    }

    #[tokio::test]
    async fn import_rejects_bad_key() {
        let backend = SoftwareSignerBackend::default();
        let result = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: "0x1234".to_string().into(),
            })
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn software_backend_can_export_and_restore_key_material() {
        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        let exported = backend
            .export_persistable_key_material(&[key.id])
            .expect("must export key material");
        assert!(exported.contains_key(&key.id));

        let restored_backend = SoftwareSignerBackend::default();
        restored_backend
            .restore_persistable_key_material(&exported)
            .expect("must restore key material");
        let sig = restored_backend
            .sign_payload(key.id, b"payload")
            .await
            .expect("must sign with restored key");
        assert!(!sig.bytes.is_empty());
    }

    #[tokio::test]
    async fn software_signer_helpers_cover_public_key_and_invalid_restore_paths() {
        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        let stored = backend.keys.read().expect("read keys");
        let signing_key = stored.get(&key.id).expect("stored signing key");
        match signing_key {
            crate::SoftwareSigningKey::Secp256k1(signing_key) => {
                assert_eq!(
                    SoftwareSignerBackend::secp256k1_public_key_hex(signing_key),
                    key.public_key_hex
                );
            }
            crate::SoftwareSigningKey::Ed25519(signing_key) => {
                assert_eq!(
                    SoftwareSignerBackend::ed25519_public_key_hex(signing_key),
                    key.public_key_hex
                );
            }
        }
        drop(stored);

        let imported =
            SoftwareSignerBackend::parse_import_secp256k1_key(&format!("0x{}", "22".repeat(32)))
                .expect("must parse prefixed import key");
        assert_eq!(imported.to_bytes().len(), 32);
        assert!(matches!(
            SoftwareSignerBackend::parse_import_secp256k1_key("not-hex"),
            Err(SignerError::InvalidPrivateKey)
        ));
        assert!(matches!(
            backend.restore_persistable_key_material(&HashMap::from([(
                Uuid::new_v4(),
                "not-hex".to_string().into()
            )])),
            Err(SignerError::InvalidPrivateKey)
        ));
        assert_eq!(
            backend
                .export_persistable_key_material(&[])
                .expect("empty export"),
            HashMap::new()
        );
    }

    #[test]
    fn software_signer_maps_recoverable_digest_failures_to_internal_errors() {
        struct TestRecoverableError;

        impl std::fmt::Display for TestRecoverableError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("injected recoverable signing failure")
            }
        }

        let result = SoftwareSignerBackend::map_recoverable_digest_signature::<(), _>(Err(
            TestRecoverableError,
        ));

        assert!(matches!(
            result,
            Err(SignerError::Internal(message))
                if message
                    == "recoverable digest signature creation failed: injected recoverable signing failure"
        ));
    }

    #[cfg(any(not(target_os = "macos"), coverage))]
    #[tokio::test]
    async fn secure_enclave_backend_is_explicitly_unsupported_off_macos() {
        let backend = SecureEnclaveSignerBackend::default();
        assert!(matches!(
            backend.create_vault_key(KeyCreateRequest::Generate).await,
            Err(SignerError::Unsupported(message)) if message.contains("requires macOS")
        ));
        assert!(matches!(
            backend
                .create_vault_key(KeyCreateRequest::Import {
                    private_key_hex: "11".repeat(32).into()
                })
                .await,
            Err(SignerError::Unsupported(message)) if message.contains("requires macOS")
        ));
        assert!(matches!(
            backend.sign_payload(Uuid::new_v4(), b"payload").await,
            Err(SignerError::Unsupported(message)) if message.contains("requires macOS")
        ));
        assert!(matches!(
            backend.sign_digest(Uuid::new_v4(), [7u8; 32]).await,
            Err(SignerError::Unsupported(message)) if message.contains("requires macOS")
        ));
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    #[tokio::test]
    async fn secure_enclave_import_is_explicitly_unsupported() {
        use super::SecureEnclaveSignerBackend;

        let backend = SecureEnclaveSignerBackend::default();
        let result = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: "0x11".repeat(32).into(),
            })
            .await;

        assert!(matches!(result, Err(SignerError::Unsupported(_))));
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    #[tokio::test]
    async fn secure_enclave_generate_requires_root_context() {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "coverage test expects non-root runtime"
        );

        let backend = SecureEnclaveSignerBackend::default();
        let result = backend.create_vault_key(KeyCreateRequest::Generate).await;

        assert!(matches!(result, Err(SignerError::PermissionDenied(_))));
    }

    #[cfg(all(target_os = "macos", not(coverage)))]
    #[tokio::test]
    async fn secure_enclave_sign_requires_root_context() {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "coverage test expects non-root runtime"
        );

        let backend = SecureEnclaveSignerBackend::default();
        let result = backend.sign_payload(Uuid::new_v4(), b"payload").await;

        assert!(matches!(result, Err(SignerError::PermissionDenied(_))));
    }

    #[cfg(all(
        target_os = "macos",
        not(coverage),
        feature = "interactive-secure-enclave-tests"
    ))]
    #[tokio::test]
    async fn secure_enclave_can_generate_and_sign() {
        use core_foundation::base::{TCFType, ToVoid};
        use security_framework::item::{
            ItemClass, ItemSearchOptions, KeyClass, Limit, Reference, SearchResult,
        };
        use security_framework_sys::item::{
            kSecAttrAccessControl, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
        };

        use super::SecureEnclaveSignerBackend;

        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let backend = SecureEnclaveSignerBackend::new("com.agentpay.vault.test");
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create secure enclave key");

        let sig = backend
            .sign_payload(key.id, b"payload")
            .await
            .expect("must sign");
        assert!(!sig.bytes.is_empty());

        let label = format!("com.agentpay.vault.test.{}", key.id);
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(&label)
            .load_refs(true)
            .limit(Limit::Max(1))
            .ignore_legacy_keychains();

        let results = search.search().expect("search must succeed");
        assert_eq!(results.len(), 1);

        let private_key = match &results[0] {
            SearchResult::Ref(Reference::Key(key)) => key,
            _ => panic!("unexpected key search result"),
        };

        let attrs = private_key.attributes();
        let token = attrs
            .find(unsafe { kSecAttrTokenID }.to_void())
            .expect("secure enclave token id must be present");
        let token_string = format!("{}", unsafe {
            core_foundation::string::CFString::wrap_under_get_rule(token.cast())
        });
        let expected = format!("{}", unsafe {
            core_foundation::string::CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave)
        });
        assert_eq!(token_string, expected);

        assert!(
            attrs
                .find(unsafe { kSecAttrAccessControl }.to_void())
                .is_some(),
            "access-control metadata must be present"
        );

        backend
            .delete_if_present(key.id)
            .expect("cleanup should not fail");
    }

    #[tokio::test]
    async fn software_backend_rejects_railgun_key_creation_with_phase_b_marker() {
        let backend = SoftwareSignerBackend::default();
        for algorithm in [
            vault_domain::KeyAlgorithm::RailgunSpending,
            vault_domain::KeyAlgorithm::RailgunViewing,
        ] {
            let err = backend
                .create_vault_key(KeyCreateRequest::GenerateWithAlgorithm { algorithm })
                .await
                .expect_err("railgun keys are not generated standalone");
            assert!(
                matches!(err, SignerError::Unsupported(msg) if msg.contains("railgun_")
                || msg.contains("Railgun keys are derived"))
            );
        }
    }

    #[tokio::test]
    async fn software_backend_railgun_key_derivation_returns_real_address() {
        // Phase B step 3 wired the three key-derivation methods through
        // `wallet::derive_wallet_keys`. With a real secp256k1 vault key in
        // place, all three return concrete values; the two unimplemented
        // methods (`decrypt_note`, `witness_inputs`) keep returning
        // `Unsupported` but with sharper error messages that explicitly
        // name the Track 3 / Track 4 dependency.
        use vault_domain::{
            RailgunMerklePath, RailgunNoteCiphertext, RailgunNoteInput, RailgunTreeNumber,
        };

        let backend = SoftwareSignerBackend::default();
        let vault_key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("create secp256k1 vault key");

        let address = backend
            .railgun_master_public_key(vault_key.id)
            .await
            .expect("master public key derivation succeeds");
        assert!(
            address.starts_with("0zk1"),
            "encoded address must use the 0zk1 bech32 HRP, got {address}",
        );

        let viewing = backend
            .railgun_viewing_public_key(vault_key.id)
            .await
            .expect("viewing public key derivation succeeds");
        assert_eq!(
            viewing.viewing_pubkey_hex.len(),
            64,
            "viewing pub is a 32-byte hex string",
        );
        assert_eq!(
            viewing.master_pubkey_hex.len(),
            64,
            "master pub is a 32-byte hex string",
        );

        let note = RailgunNoteInput {
            chain_id: 1,
            tree_number: RailgunTreeNumber::Utxo,
            leaf_index: 42,
            commitment_hex: "00".repeat(32),
            random_hex: "11".repeat(32),
            token: "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            value_wei: 1,
        };
        let nullifier = backend
            .railgun_compute_nullifier(vault_key.id, &note)
            .await
            .expect("nullifier derivation succeeds");
        assert_eq!(
            nullifier.nullifier_hex.len(),
            64,
            "nullifier is a 32-byte hex string",
        );

        // Determinism check: same vault key + same leaf index → same nullifier
        // (this is what makes Railgun "compute then publish" sound on-chain).
        let nullifier2 = backend
            .railgun_compute_nullifier(vault_key.id, &note)
            .await
            .expect("nullifier derivation succeeds on repeat");
        assert_eq!(
            nullifier, nullifier2,
            "nullifier derivation must be deterministic"
        );

        // decrypt_note now does ECDH + AES-256-GCM under the wallet's viewing
        // key. On a junk ciphertext + bogus ephemeral pubkey the auth tag
        // verification fails and the daemon returns Ok(None) — never an
        // error. The byte-equality success-path test lives in the
        // railgun::wallet module against engine-generated vectors.
        let ciphertext = RailgunNoteCiphertext {
            ephemeral_pubkey_hex: "22".repeat(32),
            iv_hex: "33".repeat(16),
            tag_hex: "44".repeat(16),
            data_chunks_hex: vec!["55".repeat(32), "66".repeat(32), "77".repeat(32)],
        };
        let decrypt_result = backend
            .railgun_decrypt_note(vault_key.id, &ciphertext)
            .await
            .expect("decrypt_note must not error on auth failure — only return None");
        assert!(
            decrypt_result.is_none(),
            "junk ciphertext must auth-fail rather than decrypt to garbage; got {decrypt_result:?}",
        );

        let path = RailgunMerklePath {
            tree_number: RailgunTreeNumber::Utxo,
            leaf_index: 0,
            path_elements_hex: vec!["55".repeat(32)],
            root_hex: "66".repeat(32),
        };

        // witness_inputs requires a 32-byte pre-hashed Poseidon digest. Empty
        // input must fail loudly so a sidecar bug never silently produces
        // garbage signatures.
        let bad_payload = backend
            .railgun_witness_inputs(vault_key.id, &[note.clone()], &[path.clone()], "")
            .await
            .unwrap_err();
        assert!(
            matches!(
                &bad_payload,
                SignerError::RailgunCrypto(msg) if msg.contains("32 bytes")
            ),
            "empty payload must trigger the 32-byte-digest precondition; got {bad_payload:?}",
        );

        // With a valid 32-byte digest the call succeeds and produces a bundle
        // shaped per the trait contract (one nullifier per note, one
        // unpacked-96-byte signature per transaction).
        let digest_hex = "ab".repeat(32);
        let bundle = backend
            .railgun_witness_inputs(vault_key.id, &[note.clone()], &[path.clone()], &digest_hex)
            .await
            .expect("witness inputs succeed with a valid digest");
        assert_eq!(
            bundle.nullifiers_hex.len(),
            1,
            "one nullifier per spent note",
        );
        assert_eq!(
            bundle.nullifiers_hex[0].len(),
            64,
            "nullifier is a 32-byte hex string",
        );
        assert_eq!(
            bundle.spending_signatures_hex.len(),
            1,
            "one transaction signature per witness call",
        );
        assert_eq!(
            bundle.spending_signatures_hex[0].len(),
            96 * 2,
            "unpacked signature is R8.x || R8.y || S = 96 bytes hex",
        );
        assert_eq!(
            bundle.spend_authority_pubkey_hex.len(),
            64,
            "packed spend authority pubkey is 32 bytes hex",
        );

        // Same key + same digest must produce a byte-identical bundle — the
        // EdDSA-Poseidon signature is deterministic for fixed (priv, msg).
        let bundle2 = backend
            .railgun_witness_inputs(vault_key.id, &[note], &[path], &digest_hex)
            .await
            .expect("witness inputs repeat");
        assert_eq!(
            bundle, bundle2,
            "EdDSA-Poseidon signature must be deterministic"
        );
    }

    #[tokio::test]
    async fn trait_default_railgun_methods_return_unsupported_for_dummy_backend() {
        use vault_domain::{RailgunNoteCiphertext, RailgunNoteInput, RailgunTreeNumber};

        let backend = DummyTeeBackend;
        let id = Uuid::new_v4();
        let note = RailgunNoteInput {
            chain_id: 1,
            tree_number: RailgunTreeNumber::LegacyUtxo,
            leaf_index: 7,
            commitment_hex: "ab".repeat(32),
            random_hex: "cd".repeat(32),
            token: "0x2222222222222222222222222222222222222222"
                .parse()
                .unwrap(),
            value_wei: 100,
        };
        let ciphertext = RailgunNoteCiphertext {
            ephemeral_pubkey_hex: "11".repeat(32),
            iv_hex: "22".repeat(16),
            tag_hex: "33".repeat(16),
            data_chunks_hex: vec!["44".repeat(32), "55".repeat(32), "66".repeat(32)],
        };

        assert!(matches!(
            backend.railgun_master_public_key(id).await,
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            backend.railgun_viewing_public_key(id).await,
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            backend.railgun_compute_nullifier(id, &note).await,
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            backend.railgun_decrypt_note(id, &ciphertext).await,
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            backend.railgun_witness_inputs(id, &[], &[], "").await,
            Err(SignerError::Unsupported(_))
        ));
    }
}
