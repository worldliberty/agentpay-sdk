//! In-process software signer. Key material lives in memory and is persisted (encrypted) by the
//! daemon through [`VaultSignerBackend::export_persistable_key_material`].

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use agentpay_domain::{KeyAlgorithm, KeySource, Signature, VaultKey};
use async_trait::async_trait;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use k256::elliptic_curve::rand_core::OsRng;
use rand::random;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backend::{BackendKind, KeyCreateRequest, SignerError, VaultSignerBackend};

/// Pure software signer backend.
#[derive(Debug, Clone, Default)]
pub struct SoftwareSignerBackend {
    pub(crate) keys: Arc<RwLock<HashMap<Uuid, SoftwareSigningKey>>>,
}

#[derive(Debug, Clone)]
pub(crate) enum SoftwareSigningKey {
    Secp256k1(SigningKey),
    Ed25519(Ed25519SigningKey),
}

impl SoftwareSignerBackend {
    pub(crate) fn secp256k1_public_key_hex(signing_key: &SigningKey) -> String {
        hex::encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        )
    }

    pub(crate) fn ed25519_public_key_hex(signing_key: &Ed25519SigningKey) -> String {
        hex::encode(signing_key.verifying_key().to_bytes())
    }

    /// Solana signers are derived deterministically from the secp256k1 key bytes so one wallet
    /// key yields both an EVM and a Solana address.
    fn solana_signing_key(signing_key: &SoftwareSigningKey) -> Ed25519SigningKey {
        match signing_key {
            SoftwareSigningKey::Secp256k1(signing_key) => {
                let seed = Zeroizing::new(<[u8; 32]>::from(signing_key.to_bytes()));
                Ed25519SigningKey::from_bytes(&seed)
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

    pub(crate) fn map_recoverable_digest_signature<T, E>(
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

    fn decode_private_key_hex(private_key_hex: &str) -> Result<Zeroizing<[u8; 32]>, SignerError> {
        let raw = Zeroizing::new(
            hex::decode(
                private_key_hex
                    .strip_prefix("0x")
                    .unwrap_or(private_key_hex),
            )
            .map_err(|_| SignerError::InvalidPrivateKey)?,
        );
        Ok(Zeroizing::new(
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| SignerError::InvalidPrivateKey)?,
        ))
    }

    pub(crate) fn parse_import_secp256k1_key(
        private_key_hex: &str,
    ) -> Result<SigningKey, SignerError> {
        let bytes = Self::decode_private_key_hex(private_key_hex)?;
        SigningKey::from_slice(bytes.as_slice()).map_err(|_| SignerError::InvalidPrivateKey)
    }

    fn parse_import_ed25519_key(private_key_hex: &str) -> Result<Ed25519SigningKey, SignerError> {
        let bytes = Self::decode_private_key_hex(private_key_hex)?;
        Ok(Ed25519SigningKey::from_bytes(&bytes))
    }

    fn secp256k1(
        key: SigningKey,
        source: KeySource,
    ) -> (SoftwareSigningKey, KeySource, KeyAlgorithm, String) {
        let public_key_hex = Self::secp256k1_public_key_hex(&key);
        (
            SoftwareSigningKey::Secp256k1(key),
            source,
            KeyAlgorithm::Secp256k1,
            public_key_hex,
        )
    }

    fn ed25519(
        key: Ed25519SigningKey,
        source: KeySource,
    ) -> (SoftwareSigningKey, KeySource, KeyAlgorithm, String) {
        let public_key_hex = Self::ed25519_public_key_hex(&key);
        (
            SoftwareSigningKey::Ed25519(key),
            source,
            KeyAlgorithm::Ed25519,
            public_key_hex,
        )
    }

    /// Runs `operation` against the stored key for `vault_key_id`.
    fn with_key<T>(
        &self,
        vault_key_id: Uuid,
        operation: impl FnOnce(&SoftwareSigningKey) -> Result<T, SignerError>,
    ) -> Result<T, SignerError> {
        let keys = self.keys.read().map_err(|_| poisoned())?;
        let signing_key = keys
            .get(&vault_key_id)
            .ok_or(SignerError::UnknownKey(vault_key_id))?;
        operation(signing_key)
    }
}

fn poisoned() -> SignerError {
    SignerError::Internal("poisoned lock".into())
}

#[async_trait]
impl VaultSignerBackend for SoftwareSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Software
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        let (signing_key, source, algorithm, public_key_hex) = match request {
            KeyCreateRequest::Generate
            | KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
            } => Self::secp256k1(SigningKey::random(&mut OsRng), KeySource::Generated),
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            } => {
                let seed = Zeroizing::new(random::<[u8; 32]>());
                Self::ed25519(Ed25519SigningKey::from_bytes(&seed), KeySource::Generated)
            }
            KeyCreateRequest::Import { private_key_hex }
            | KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Secp256k1,
                private_key_hex,
            } => Self::secp256k1(
                Self::parse_import_secp256k1_key(&private_key_hex)?,
                KeySource::Imported,
            ),
            KeyCreateRequest::ImportWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
                private_key_hex,
            } => Self::ed25519(
                Self::parse_import_ed25519_key(&private_key_hex)?,
                KeySource::Imported,
            ),
        };

        let key_id = Uuid::new_v4();
        self.keys
            .write()
            .map_err(|_| poisoned())?
            .insert(key_id, signing_key);

        Ok(VaultKey {
            id: key_id,
            source,
            algorithm,
            public_key_hex,
            created_at: OffsetDateTime::now_utc(),
            name: None,
        })
    }

    async fn sign_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        self.with_key(vault_key_id, |signing_key| match signing_key {
            SoftwareSigningKey::Secp256k1(signing_key) => {
                let signature: EcdsaSignature = signing_key.sign(payload);
                Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
            }
            SoftwareSigningKey::Ed25519(signing_key) => {
                Ok(Self::ed25519_signature(payload, signing_key))
            }
        })
    }

    fn solana_public_key_hex(&self, vault_key_id: Uuid) -> Result<String, SignerError> {
        self.with_key(vault_key_id, |signing_key| {
            Ok(Self::ed25519_public_key_hex(&Self::solana_signing_key(
                signing_key,
            )))
        })
    }

    async fn sign_solana_payload(
        &self,
        vault_key_id: Uuid,
        payload: &[u8],
    ) -> Result<Signature, SignerError> {
        self.with_key(vault_key_id, |signing_key| {
            Ok(Self::ed25519_signature(
                payload,
                &Self::solana_signing_key(signing_key),
            ))
        })
    }

    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError> {
        self.with_key(vault_key_id, |signing_key| match signing_key {
            SoftwareSigningKey::Secp256k1(signing_key) => Self::map_recoverable_digest_signature(
                signing_key.sign_prehash_recoverable(&digest),
            ),
            SoftwareSigningKey::Ed25519(_) => Err(SignerError::Unsupported(
                "ed25519 keys do not support prehashed digest signing".to_string(),
            )),
        })
    }

    fn export_persistable_key_material(
        &self,
        vault_key_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
        let keys = self.keys.read().map_err(|_| poisoned())?;
        let mut exported = HashMap::with_capacity(vault_key_ids.len());
        for vault_key_id in vault_key_ids {
            let signing_key = keys
                .get(vault_key_id)
                .ok_or(SignerError::UnknownKey(*vault_key_id))?;
            let material = match signing_key {
                SoftwareSigningKey::Secp256k1(signing_key) => {
                    let bytes = Zeroizing::new(signing_key.to_bytes());
                    format!("secp256k1:{}", hex::encode(*bytes))
                }
                SoftwareSigningKey::Ed25519(signing_key) => {
                    let bytes = Zeroizing::new(signing_key.to_bytes());
                    format!("ed25519:{}", hex::encode(*bytes))
                }
            };
            exported.insert(*vault_key_id, Zeroizing::new(material));
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
