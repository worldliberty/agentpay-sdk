//! Tests that exercise the real backend and command encoding without TPM
//! hardware: every path here fails or succeeds before `/dev/tpmrm0` is opened.

use std::collections::HashMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use super::tpm2::{
    pack_sealed_blob, parse_response_header, unpack_sealed_blob, CmdBuilder, RespReader,
};
use super::*;

const MISSING_DEVICE: &str = "/nonexistent/agentpay-test-tpm";

fn backend() -> LinuxTpmSignerBackend {
    LinuxTpmSignerBackend::new(MISSING_DEVICE)
}

fn valid_public_key() -> Vec<u8> {
    SigningKey::random(&mut OsRng)
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn persisted_blob(
    version: u32,
    public_key_uncompressed: Vec<u8>,
) -> HashMap<Uuid, Zeroizing<String>> {
    let blob = LinuxTpmKeyBlob {
        version,
        sealed_private_key: pack_sealed_blob(&[1, 2], &[3]),
        public_key_uncompressed,
    };
    HashMap::from([(
        Uuid::new_v4(),
        Zeroizing::new(serde_json::to_string(&blob).expect("serialize blob")),
    )])
}

fn internal_message(result: Result<(), SignerError>) -> String {
    match result {
        Err(SignerError::Internal(message)) => message,
        other => panic!("expected internal error, got {other:?}"),
    }
}

#[test]
fn blob_and_backend_debug_output_redacts_secrets() {
    let blob = LinuxTpmKeyBlob {
        version: SEALED_BLOB_VERSION,
        sealed_private_key: vec![0xde, 0xad, 0xbe, 0xef],
        public_key_uncompressed: vec![0x04; 65],
    };
    let rendered = format!("{blob:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("deadbeef"), "{rendered}");

    let rendered = format!("{:?}", backend());
    assert!(rendered.contains(MISSING_DEVICE), "{rendered}");
    assert!(rendered.contains("<locked>"), "{rendered}");
}

#[test]
fn restore_validates_blobs_before_touching_the_tpm() {
    let backend = backend();
    assert!(backend
        .restore_persistable_key_material(&HashMap::new())
        .is_ok());

    let message = internal_message(backend.restore_persistable_key_material(&persisted_blob(
        SEALED_BLOB_VERSION + 1,
        valid_public_key(),
    )));
    assert!(message.contains("newer than supported"), "{message}");

    for public_key in [vec![0x04; 33], vec![0x05; 65]] {
        let message = internal_message(
            backend
                .restore_persistable_key_material(&persisted_blob(SEALED_BLOB_VERSION, public_key)),
        );
        assert!(
            message.contains("invalid public key length or prefix"),
            "{message}"
        );
    }

    let message = internal_message(
        backend
            .restore_persistable_key_material(&persisted_blob(SEALED_BLOB_VERSION, vec![0x04; 65])),
    );
    assert!(message.contains("not a valid secp256k1 point"), "{message}");

    let message = internal_message(backend.restore_persistable_key_material(&HashMap::from([(
        Uuid::new_v4(),
        Zeroizing::new("not-json".to_string()),
    )])));
    assert!(message.contains("blob deserialization failed"), "{message}");
}

#[test]
fn restore_probes_the_tpm_for_valid_blobs() {
    let message = internal_message(backend().restore_persistable_key_material(&persisted_blob(
        SEALED_BLOB_VERSION,
        valid_public_key(),
    )));
    assert!(message.contains("TPM probe unseal failed"), "{message}");
    assert!(message.contains(MISSING_DEVICE), "{message}");
}

#[tokio::test]
async fn create_rejects_unsupported_requests_before_sealing() {
    let backend = backend();
    assert_eq!(backend.backend_kind(), BackendKind::Tpm);
    assert!(matches!(
        backend
            .create_vault_key(KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            })
            .await,
        Err(SignerError::Unsupported(_))
    ));
    assert!(matches!(
        backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: "0x1234".to_string().into(),
            })
            .await,
        Err(SignerError::InvalidPrivateKey)
    ));
    match backend.create_vault_key(KeyCreateRequest::Generate).await {
        Err(SignerError::Internal(message)) => {
            assert!(message.contains("failed to open TPM device"), "{message}");
        }
        other => panic!("expected TPM open failure, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_keys_are_rejected() {
    let backend = backend();
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
    backend
        .delete_vault_key_if_present(unknown)
        .expect("deleting an unknown key is a no-op");
}

#[test]
fn sealed_blob_packing_round_trips_and_rejects_truncation() {
    let packed = pack_sealed_blob(&[0xaa, 0xbb, 0xcc], &[0xdd]);
    assert_eq!(&packed[..4], &3u32.to_le_bytes());
    let (private, public) = unpack_sealed_blob(&packed).expect("unpack");
    assert_eq!(private, &[0xaa, 0xbb, 0xcc]);
    assert_eq!(public, &[0xdd]);

    for truncated in [
        &packed[..2],
        &packed[..5],
        &packed[..8],
        &packed[..packed.len() - 1],
    ] {
        assert!(matches!(
            unpack_sealed_blob(truncated),
            Err(SignerError::Internal(_))
        ));
    }
}

#[test]
fn command_builder_patches_size_and_reader_rejects_truncation() {
    let mut cmd = CmdBuilder::command(0x8001, 0x0000_0165);
    cmd.push_tpm2b(&[0xab, 0xcd]);
    assert_eq!(
        cmd.finalize().to_vec(),
        vec![0x80, 0x01, 0, 0, 0, 14, 0, 0, 0x01, 0x65, 0, 2, 0xab, 0xcd]
    );

    assert_eq!(
        parse_response_header(&[0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01]).expect("header"),
        (0x8001, 10, 0x0101)
    );
    assert!(parse_response_header(&[0x80, 0x01]).is_err());

    let mut reader = RespReader::new(&[0, 2, 0xaa, 0xbb, 0, 5, 0xcc]);
    assert_eq!(reader.read_tpm2b().expect("tpm2b"), &[0xaa, 0xbb]);
    assert!(
        reader.read_tpm2b().is_err(),
        "declared length exceeds buffer"
    );
    let mut reader = RespReader::new(&[0, 0, 0]);
    assert!(reader.read_u32().is_err());
    assert_eq!(reader.read_u16().expect("u16"), 0);
    assert!(reader.skip(2).is_err());
    assert!(reader.read_bytes(1).is_ok());
}
