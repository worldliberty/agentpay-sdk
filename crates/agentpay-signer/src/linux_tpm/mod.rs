//! Linux TPM 2.0 signer backend using Seal/Unseal for secp256k1 key protection.
//!
//! # Architecture: Why Seal/Unseal Instead of Direct TPM Signing
//!
//! TPM 2.0 does **not** support the secp256k1 curve required by Ethereum. The
//! TPM's built-in ECDSA only works with NIST curves (P-256, P-384). Using the
//! TPM directly for signing would produce P-256 signatures that yield incorrect
//! Ethereum addresses.
//!
//! Instead, this backend uses the TPM as a **key-protection vault**:
//!
//! 1. **Key generation**: A secp256k1 private key is generated in software
//!    using a cryptographically secure RNG.
//!
//! 2. **Sealing**: The raw 32-byte private key is encrypted (sealed) by the TPM
//!    under a Storage Root Key (SRK). The sealed blob can only be decrypted by
//!    the same TPM chip. The sealed blob is the only thing persisted to disk.
//!
//! 3. **Signing**: At signing time the daemon unseals the private key, performs
//!    secp256k1 ECDSA signing in software via the `k256` crate, and immediately
//!    zeroizes the plaintext key material.
//!
//! 4. **Platform binding**: Because the sealed blob is bound to the TPM's SRK,
//!    stealing the file alone is useless without physical access to the same
//!    TPM chip.
//!
//! On Linux the TPM is accessed via `/dev/tpmrm0` (the kernel TPM Resource
//! Manager) using raw TPM2 command buffers (see [`tpm2`]). All blocking TPM I/O
//! is offloaded to `tokio::task::spawn_blocking` to avoid stalling the async
//! runtime.

mod tpm2;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use agentpay_domain::{KeyAlgorithm, KeySource, Signature, VaultKey};
use async_trait::async_trait;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use k256::elliptic_curve::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::software::SoftwareSignerBackend;
use crate::{BackendKind, KeyCreateRequest, SignerError, VaultSignerBackend};

/// Current version of the sealed blob serialization format.
///
/// Increment this when the blob layout changes so older daemons can detect
/// incompatible blobs instead of silently producing corrupt keys.
const SEALED_BLOB_VERSION: u32 = 1;

/// Persistable representation of a TPM-sealed secp256k1 private key.
///
/// The `sealed_private_key` field holds the opaque TPM sealed data object.
/// It can only be unsealed by the same TPM chip that created it.
#[derive(Clone, Serialize, Deserialize)]
pub struct LinuxTpmKeyBlob {
    /// Format version for forward-compatible deserialization.
    pub version: u32,

    /// Opaque TPM sealed data bytes (TPM2B_PRIVATE + TPM2B_PUBLIC).
    ///
    /// This is the concatenation of:
    ///   - 4 bytes (u32 LE): length of TPM2B_PRIVATE
    ///   - TPM2B_PRIVATE bytes
    ///   - 4 bytes (u32 LE): length of TPM2B_PUBLIC
    ///   - TPM2B_PUBLIC bytes
    pub sealed_private_key: Vec<u8>,

    /// Uncompressed SEC1 public key bytes (65 bytes) for address derivation
    /// without needing to unseal.
    pub public_key_uncompressed: Vec<u8>,
}

// C6 fix: Manual Debug impl to avoid leaking sealed_private_key in logs.
impl std::fmt::Debug for LinuxTpmKeyBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxTpmKeyBlob")
            .field("version", &self.version)
            .field("sealed_private_key", &"<redacted>")
            .field(
                "public_key_uncompressed",
                &hex::encode(&self.public_key_uncompressed),
            )
            .finish()
    }
}

impl LinuxTpmKeyBlob {
    /// Checks the blob version and that the stored public key is an
    /// uncompressed secp256k1 point (C19 fix), without touching the TPM.
    fn validate(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
        if self.version > SEALED_BLOB_VERSION {
            return Err(SignerError::Internal(format!(
                "sealed blob version {} is newer than supported version \
                 {SEALED_BLOB_VERSION}; upgrade the daemon to load this key",
                self.version
            )));
        }
        if self.public_key_uncompressed.len() != 65 || self.public_key_uncompressed[0] != 0x04 {
            return Err(SignerError::Internal(format!(
                "key {vault_key_id}: invalid public key length or prefix"
            )));
        }
        VerifyingKey::from_sec1_bytes(&self.public_key_uncompressed).map_err(|_| {
            SignerError::Internal(format!(
                "key {vault_key_id}: public key is not a valid secp256k1 point"
            ))
        })?;
        Ok(())
    }
}

/// In-memory representation of a loaded key.
///
/// Holds the sealed blob (for persistence) and, when the key is "hot", the
/// unsealed signing key. The unsealed key is populated on first sign and
/// kept in memory for the lifetime of the backend (matching the
/// `SoftwareSignerBackend` behavior). `SigningKey` zeroizes itself on drop.
struct LoadedKey {
    blob: LinuxTpmKeyBlob,
    /// Cached unsealed signing key. Populated lazily on first sign.
    signing_key: Option<SigningKey>,
}

/// Linux TPM 2.0 signer backend.
///
/// Uses TPM Seal/Unseal to protect secp256k1 private keys at rest while
/// performing ECDSA signing in software with the `k256` crate. See the
/// module-level documentation for the full architecture rationale.
#[derive(Clone)]
pub struct LinuxTpmSignerBackend {
    device_path: PathBuf,
    keys: Arc<RwLock<HashMap<Uuid, LoadedKey>>>,
}

impl std::fmt::Debug for LinuxTpmSignerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxTpmSignerBackend")
            .field("device_path", &self.device_path)
            .field("keys", &"<locked>")
            .finish()
    }
}

impl Default for LinuxTpmSignerBackend {
    fn default() -> Self {
        Self::new("/dev/tpmrm0")
    }
}

fn poisoned() -> SignerError {
    SignerError::Internal("poisoned lock".into())
}

fn join_failed(err: tokio::task::JoinError) -> SignerError {
    SignerError::Internal(format!("spawn_blocking join failed: {err}"))
}

impl LinuxTpmSignerBackend {
    /// Creates a new Linux TPM signer backend with the given device path.
    #[must_use]
    pub fn new(device_path: impl Into<PathBuf>) -> Self {
        Self {
            device_path: device_path.into(),
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Ensures the signing key for `vault_key_id` is cached (unsealed),
    /// then calls `f` with a reference to it while holding the lock.
    ///
    /// This avoids cloning the `SigningKey` out of the lock, which would
    /// create untracked copies of the private key in memory.
    async fn with_signing_key<F, R>(&self, vault_key_id: Uuid, f: F) -> Result<R, SignerError>
    where
        F: FnOnce(&SigningKey) -> Result<R, SignerError>,
    {
        // Fast path: key already unsealed — sign within read lock. Otherwise
        // copy the sealed blob out so the TPM I/O runs without holding the lock.
        let sealed_blob = {
            let keys = self.keys.read().map_err(|_| poisoned())?;
            let loaded = keys
                .get(&vault_key_id)
                .ok_or(SignerError::UnknownKey(vault_key_id))?;
            if let Some(signing_key) = &loaded.signing_key {
                return f(signing_key);
            }
            loaded.blob.sealed_private_key.clone()
        };

        // Slow path: unseal via TPM (blocking I/O).
        let device_path = self.device_path.clone();
        let plaintext =
            tokio::task::spawn_blocking(move || tpm2::unseal(&device_path, &sealed_blob))
                .await
                .map_err(join_failed)??;
        let signing_key =
            SigningKey::from_slice(&plaintext).map_err(|_| SignerError::InvalidPrivateKey)?;

        // Cache the unsealed key, then sign with the cached reference — no clone.
        let mut keys = self.keys.write().map_err(|_| poisoned())?;
        let loaded = keys
            .get_mut(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        f(loaded.signing_key.insert(signing_key))
    }

    /// Unseals one restored key to verify the TPM can still decrypt our blobs
    /// and that the unsealed key matches the stored public key (C5 fix). If
    /// `tpm2_clear` was run this fails fast at startup instead of on the first
    /// sign request.
    fn probe_unseal(&self, vault_key_id: Uuid, blob: &LinuxTpmKeyBlob) -> Result<(), SignerError> {
        // Synchronous TPM I/O: restore is a sync fn and the caller is
        // responsible for running it in an appropriate context.
        let plaintext =
            tpm2::unseal(&self.device_path, &blob.sealed_private_key).map_err(|err| {
                SignerError::Internal(format!(
                    "key {vault_key_id}: TPM probe unseal failed (was tpm2_clear run?): {err}"
                ))
            })?;
        let signing_key = SigningKey::from_slice(&plaintext).map_err(|_| {
            SignerError::Internal(format!(
                "key {vault_key_id}: probe unseal returned invalid secp256k1 key"
            ))
        })?;
        let derived_public_key = signing_key.verifying_key().to_encoded_point(false);
        if derived_public_key.as_bytes() != blob.public_key_uncompressed.as_slice() {
            return Err(SignerError::Internal(format!(
                "key {vault_key_id}: unsealed key does not match stored public key \
                 (TPM state may have been tampered with)"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl VaultSignerBackend for LinuxTpmSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Tpm
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        let (signing_key, source) = match request {
            KeyCreateRequest::Generate
            | KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
            } => (SigningKey::random(&mut OsRng), KeySource::Generated),
            KeyCreateRequest::Import { private_key_hex }
            | KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
                private_key_hex,
            } => (
                SoftwareSignerBackend::parse_import_secp256k1_key(&private_key_hex)?,
                KeySource::Imported,
            ),
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            }
            | KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
                ..
            } => {
                return Err(SignerError::Unsupported(
                    "TPM backend does not support Ed25519 keys".to_string(),
                ));
            }
        };

        let key_id = Uuid::new_v4();
        let public_key_hex = SoftwareSignerBackend::secp256k1_public_key_hex(&signing_key);
        let public_key_uncompressed = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let created_at = OffsetDateTime::now_utc();

        // Seal the private key via TPM (blocking I/O).
        let private_key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());
        let device_path = self.device_path.clone();
        let sealed_private_key =
            tokio::task::spawn_blocking(move || tpm2::seal(&device_path, &private_key_bytes))
                .await
                .map_err(join_failed)??;

        let blob = LinuxTpmKeyBlob {
            version: SEALED_BLOB_VERSION,
            sealed_private_key,
            public_key_uncompressed,
        };

        self.keys.write().map_err(|_| poisoned())?.insert(
            key_id,
            LoadedKey {
                blob,
                // Cache the signing key so first sign does not need to unseal.
                signing_key: Some(signing_key),
            },
        );

        Ok(VaultKey {
            id: key_id,
            source,
            algorithm: KeyAlgorithm::Secp256k1,
            public_key_hex,
            created_at,
            name: None,
        })
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        self.with_signing_key(vault_key_id, |signing_key| {
            let signature: EcdsaSignature = signing_key.sign(payload);
            Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
        })
        .await
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        self.with_signing_key(vault_key_id, |signing_key| {
            SoftwareSignerBackend::map_recoverable_digest_signature(
                signing_key.sign_prehash_recoverable(&digest),
            )
        })
        .await
    }

    fn export_persistable_key_material(
        &self,
        vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        let keys = self.keys.read().map_err(|_| poisoned())?;
        let mut exported = HashMap::with_capacity(vault_key_ids.len());
        for vault_key_id in vault_key_ids {
            let loaded = keys
                .get(vault_key_id)
                .ok_or(SignerError::UnknownKey(*vault_key_id))?;
            // Serialize the full blob (version + sealed data + public key)
            // as JSON for the string-valued persistence map.
            let json = serde_json::to_string(&loaded.blob).map_err(|err| {
                SignerError::Internal(format!("blob serialization failed: {err}"))
            })?;
            exported.insert(*vault_key_id, Zeroizing::new(json));
        }
        Ok(exported)
    }

    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        let mut restored = HashMap::with_capacity(persisted.len());
        for (vault_key_id, serialized) in persisted {
            let blob: LinuxTpmKeyBlob = serde_json::from_str(serialized).map_err(|err| {
                SignerError::Internal(format!("blob deserialization failed: {err}"))
            })?;
            blob.validate(*vault_key_id)?;
            restored.insert(
                *vault_key_id,
                LoadedKey {
                    blob,
                    signing_key: None, // Unsealed lazily on first sign.
                },
            );
        }

        if let Some((probe_id, probe)) = restored.iter().next() {
            self.probe_unseal(*probe_id, &probe.blob)?;
        }

        *self.keys.write().map_err(|_| poisoned())? = restored;
        Ok(())
    }

    fn delete_vault_key_if_present(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
        self.keys
            .write()
            .map_err(|_| poisoned())?
            .remove(&vault_key_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
