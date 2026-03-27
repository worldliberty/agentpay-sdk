//! Signer backends for vault keys.
//!
//! The daemon depends on [`VaultSignerBackend`] so hardware-backed (Secure
//! Enclave), software-backed, and future TEE-backed implementations can be
//! swapped without changing policy logic.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey};
use k256::elliptic_curve::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use vault_domain::{KeySource, Signature, VaultKey};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyCreateRequest {
    /// Generate a fresh private key.
    Generate,
    /// Import an existing hex-encoded 32-byte secp256k1 private key.
    Import { private_key_hex: String },
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

    /// Signs a prehashed 32-byte digest with key `vault_key_id`.
    ///
    /// Digest format is caller-defined; for Ethereum transactions this must be
    /// Keccak-256 transaction-signing prehash.
    async fn sign_digest(
        &self,
        vault_key_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Signature, SignerError>;

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
    keys: Arc<RwLock<HashMap<Uuid, SigningKey>>>,
}

impl SoftwareSignerBackend {
    fn public_key_hex(signing_key: &SigningKey) -> String {
        let verifying_key = signing_key.verifying_key();
        hex::encode(verifying_key.to_encoded_point(false).as_bytes())
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

    fn parse_import_key(private_key_hex: &str) -> Result<SigningKey, SignerError> {
        let raw = hex::decode(
            private_key_hex
                .strip_prefix("0x")
                .unwrap_or(private_key_hex),
        )
        .map_err(|_| SignerError::InvalidPrivateKey)?;
        if raw.len() != 32 {
            return Err(SignerError::InvalidPrivateKey);
        }
        SigningKey::from_slice(&raw).map_err(|_| SignerError::InvalidPrivateKey)
    }
}

#[async_trait]
impl VaultSignerBackend for SoftwareSignerBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Software
    }

    async fn create_vault_key(&self, request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
        let (signing_key, source) = match request {
            KeyCreateRequest::Generate => (SigningKey::random(&mut OsRng), KeySource::Generated),
            KeyCreateRequest::Import { private_key_hex } => {
                let key = Self::parse_import_key(&private_key_hex)?;
                (key, KeySource::Imported)
            }
        };

        let key_id = Uuid::new_v4();
        let public_key_hex = Self::public_key_hex(&signing_key);
        let created_at = OffsetDateTime::now_utc();

        self.keys
            .write()
            .map_err(|_| SignerError::Internal("poisoned lock".into()))?
            .insert(key_id, signing_key);

        Ok(VaultKey {
            id: key_id,
            source,
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

        let signature: EcdsaSignature = signing_key.sign(payload);
        Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
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

        Self::map_recoverable_digest_signature(signing_key.sign_prehash_recoverable(&digest))
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
            let private_key_bytes = Zeroizing::new(signing_key.to_bytes());
            exported.insert(
                *vault_key_id,
                Zeroizing::new(hex::encode(&*private_key_bytes)),
            );
        }
        Ok(exported)
    }

    fn restore_persistable_key_material(
        &self,
        persisted: &HashMap<Uuid, Zeroizing<String>>,
    ) -> Result<(), SignerError> {
        let mut restored = HashMap::with_capacity(persisted.len());
        for (vault_key_id, private_key_hex) in persisted {
            let signing_key = Self::parse_import_key(private_key_hex)?;
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
                KeyCreateRequest::Generate => {
                    Self::require_root()?;
                    let key_id = Uuid::new_v4();
                    let private_key = self.generate_secure_enclave_key(key_id)?;
                    let public_key_hex = Self::public_key_hex(&private_key)?;
                    Ok(VaultKey {
                        id: key_id,
                        source: KeySource::Generated,
                        public_key_hex,
                        created_at: OffsetDateTime::now_utc(),
                    })
                }
                KeyCreateRequest::Import { .. } => Err(SignerError::Unsupported(
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

    #[tokio::test]
    async fn import_path_marks_keys_as_imported_and_accepts_prefixed_hex() {
        let backend = SoftwareSignerBackend::default();
        let key = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: format!("0x{}", "11".repeat(32)),
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
                private_key_hex: "0x1234".to_string(),
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
        assert_eq!(
            SoftwareSignerBackend::public_key_hex(signing_key),
            key.public_key_hex
        );
        drop(stored);

        let imported = SoftwareSignerBackend::parse_import_key(&format!("0x{}", "22".repeat(32)))
            .expect("must parse prefixed import key");
        assert_eq!(imported.to_bytes().len(), 32);
        assert!(matches!(
            SoftwareSignerBackend::parse_import_key("not-hex"),
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
                    private_key_hex: "11".repeat(32)
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
                private_key_hex: "0x11".repeat(32),
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
}
