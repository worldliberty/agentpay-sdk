use std::collections::HashMap;

use agentpay_domain::{KeyAlgorithm, KeySource, Signature, VaultKey};
use async_trait::async_trait;
use uuid::Uuid;

use crate::software::SoftwareSigningKey;
use crate::{
    BackendKind, KeyCreateRequest, SignerError, SoftwareSignerBackend, VaultSignerBackend,
};

/// Backend that only implements the required trait methods, so every default
/// method can be exercised.
struct MinimalBackend;

#[async_trait]
impl VaultSignerBackend for MinimalBackend {
    fn backend_kind(&self) -> BackendKind {
        BackendKind::Tpm
    }

    async fn create_vault_key(&self, _request: KeyCreateRequest) -> Result<VaultKey, SignerError> {
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

fn poison_backend_lock(backend: &SoftwareSignerBackend) {
    let clone = backend.clone();
    let _ = std::thread::spawn(move || {
        let _guard = clone.keys.write().expect("write lock");
        panic!("poison signer backend lock");
    })
    .join();
}

#[tokio::test]
async fn trait_defaults_report_unsupported_solana_and_persistence() {
    let backend = MinimalBackend;
    assert_eq!(backend.backend_kind(), BackendKind::Tpm);
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
        SoftwareSignerBackend::default().backend_kind(),
        BackendKind::Software
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

    assert_eq!(key.source, KeySource::Imported);
    assert_eq!(key.algorithm, KeyAlgorithm::Secp256k1);
    assert!(!key.public_key_hex.is_empty());
}

#[tokio::test]
async fn import_rejects_bad_key() {
    let backend = SoftwareSignerBackend::default();
    for private_key_hex in ["0x1234", "not-hex"] {
        let result = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: private_key_hex.to_string().into(),
            })
            .await;
        assert!(matches!(result, Err(SignerError::InvalidPrivateKey)));
    }
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
        backend.solana_public_key_hex(unknown),
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
    assert!(matches!(
        poisoned.delete_vault_key_if_present(Uuid::new_v4()),
        Err(SignerError::Internal(_))
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
    assert_eq!(key.source, KeySource::Generated);

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
async fn ed25519_key_signs_payloads_but_rejects_prehashed_digests() {
    use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};

    let backend = SoftwareSignerBackend::default();
    let key = backend
        .create_vault_key(KeyCreateRequest::GenerateWithAlgorithm {
            algorithm: KeyAlgorithm::Ed25519,
        })
        .await
        .expect("must create ed25519 key");
    assert_eq!(key.algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(
        backend.solana_public_key_hex(key.id).expect("solana key"),
        key.public_key_hex,
        "an ed25519 key is its own Solana signer"
    );

    let signature = backend
        .sign_payload(key.id, b"payload")
        .await
        .expect("must sign");
    let public_key_bytes = <[u8; 32]>::try_from(
        hex::decode(&key.public_key_hex)
            .expect("public key hex")
            .as_slice(),
    )
    .expect("public key bytes");
    VerifyingKey::from_bytes(&public_key_bytes)
        .expect("verifying key")
        .verify(
            b"payload",
            &Ed25519Signature::from_slice(&signature.bytes).expect("ed25519 signature"),
        )
        .expect("valid ed25519 signature");
    assert!(matches!(
        backend.sign_digest(key.id, [0x42; 32]).await,
        Err(SignerError::Unsupported(_))
    ));
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
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("verifying key");
    let recovery_id = RecoveryId::trial_recovery_from_prehash(&verifying_key, &digest, &parsed)
        .expect("must derive recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed, recovery_id)
        .expect("must recover verifying key");
    assert_eq!(recovered, verifying_key);
}

#[tokio::test]
async fn software_backend_can_export_restore_and_delete_key_material() {
    let backend = SoftwareSignerBackend::default();
    let secp256k1 = backend
        .create_vault_key(KeyCreateRequest::Generate)
        .await
        .expect("must create key");
    let ed25519 = backend
        .create_vault_key(KeyCreateRequest::ImportWithAlgorithm {
            algorithm: KeyAlgorithm::Ed25519,
            private_key_hex: "33".repeat(32).into(),
        })
        .await
        .expect("must import ed25519 key");

    let exported = backend
        .export_persistable_key_material(&[secp256k1.id, ed25519.id])
        .expect("must export key material");
    assert!(exported[&secp256k1.id].starts_with("secp256k1:"));
    assert!(exported[&ed25519.id].starts_with("ed25519:"));

    let restored_backend = SoftwareSignerBackend::default();
    restored_backend
        .restore_persistable_key_material(&exported)
        .expect("must restore key material");
    for key in [&secp256k1, &ed25519] {
        let sig = restored_backend
            .sign_payload(key.id, b"payload")
            .await
            .expect("must sign with restored key");
        assert!(!sig.bytes.is_empty());
    }
    assert_eq!(
        restored_backend
            .solana_public_key_hex(ed25519.id)
            .expect("solana key"),
        ed25519.public_key_hex
    );

    restored_backend
        .delete_vault_key_if_present(secp256k1.id)
        .expect("delete");
    assert!(matches!(
        restored_backend
            .sign_payload(secp256k1.id, b"payload")
            .await,
        Err(SignerError::UnknownKey(_))
    ));
}

#[tokio::test]
async fn software_restore_accepts_legacy_unprefixed_keys_and_rejects_bad_material() {
    let backend = SoftwareSignerBackend::default();
    let key_id = Uuid::new_v4();
    backend
        .restore_persistable_key_material(&HashMap::from([(key_id, "22".repeat(32).into())]))
        .expect("legacy unprefixed secp256k1 material");
    assert!(backend.sign_digest(key_id, [0x01; 32]).await.is_ok());

    assert!(matches!(
        backend.restore_persistable_key_material(&HashMap::from([(
            Uuid::new_v4(),
            "not-hex".to_string().into()
        )])),
        Err(SignerError::InvalidPrivateKey)
    ));
    assert!(matches!(
        backend.restore_persistable_key_material(&HashMap::from([(
            Uuid::new_v4(),
            format!("railgun_spending:{}", "22".repeat(32)).into()
        )])),
        Err(SignerError::Internal(message)) if message.contains("railgun_spending")
    ));
}

#[tokio::test]
async fn software_signer_public_key_helpers_match_created_keys() {
    let backend = SoftwareSignerBackend::default();
    let key = backend
        .create_vault_key(KeyCreateRequest::Generate)
        .await
        .expect("must create key");

    let stored = backend.keys.read().expect("read keys");
    match stored.get(&key.id).expect("stored signing key") {
        SoftwareSigningKey::Secp256k1(signing_key) => assert_eq!(
            SoftwareSignerBackend::secp256k1_public_key_hex(signing_key),
            key.public_key_hex
        ),
        SoftwareSigningKey::Ed25519(signing_key) => assert_eq!(
            SoftwareSignerBackend::ed25519_public_key_hex(signing_key),
            key.public_key_hex
        ),
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

    let result =
        SoftwareSignerBackend::map_recoverable_digest_signature::<(), _>(Err(TestRecoverableError));

    assert!(matches!(
        result,
        Err(SignerError::Internal(message))
            if message
                == "recoverable digest signature creation failed: injected recoverable signing failure"
    ));
}
