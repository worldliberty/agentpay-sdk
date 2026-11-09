//! Backup format tests, including vectors written by the TypeScript CLI
//! (`src/lib/wallet-backup.ts`, Node's `crypto.scryptSync` and AES-256-GCM).

use zeroize::Zeroizing;

use super::{decrypt, encrypt_with_cost, BackupError, BackupSource};

/// The example wallet of the API docs.
const EXAMPLE_PRIVATE_KEY_HEX: &str =
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const EXAMPLE_ADDRESS: &str = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";
const EXAMPLE_PUBLIC_KEY_HEX: &str = "044e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e47fd35c4215d1edf53e6f83de344615ce719bdb0fd878f6ed76f06dd277956de";

/// Format v2 (N = 2^15) written by the TypeScript CLI's code path.
const TS_V2: &str = include_str!("../../fixtures/wallet-backups/ts-cli-v2.json");
const TS_V2_PASSPHRASE: &str = "legacy-ts-cli-passphrase";
/// Format v1 (no additional authenticated data), as early CLIs wrote it.
const TS_V1: &str = include_str!("../../fixtures/wallet-backups/ts-cli-v1.json");
const TS_V1_PASSPHRASE: &str = "short";

fn example_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(EXAMPLE_PRIVATE_KEY_HEX, &mut *key).expect("example key");
    key
}

/// The quoted keys of a pretty-printed JSON document, in order.
fn keys_in_order(document: &str) -> Vec<String> {
    document
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix('"')?;
            let (key, after) = rest.split_once('"')?;
            after.starts_with(':').then(|| key.to_string())
        })
        .collect()
}

#[test]
fn reads_version_2_backups_written_by_the_typescript_cli() {
    let contents = decrypt(TS_V2, TS_V2_PASSPHRASE).expect("decrypt");
    assert_eq!(contents.version, 2);
    assert_eq!(contents.created_at, "2025-06-01T09:30:00.000Z");
    assert_eq!(contents.private_key_hex.as_str(), EXAMPLE_PRIVATE_KEY_HEX);
    assert_eq!(contents.address, EXAMPLE_ADDRESS);
    assert_eq!(contents.public_key_hex, EXAMPLE_PUBLIC_KEY_HEX);
    assert_eq!(contents.source_vault_key_id, None);
}

#[test]
fn reads_version_1_backups_written_by_early_clis() {
    let contents = decrypt(TS_V1, TS_V1_PASSPHRASE).expect("decrypt");
    assert_eq!(contents.version, 1);
    assert_eq!(contents.private_key_hex.as_str(), EXAMPLE_PRIVATE_KEY_HEX);
    assert_eq!(contents.address, EXAMPLE_ADDRESS);
}

#[test]
fn round_trips_and_writes_the_typescript_layout() {
    let source = Some("5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d".to_string());
    let key = example_key();
    let backup = encrypt_with_cost(
        BackupSource {
            private_key: &key,
            source_vault_key_id: source.clone(),
            name: Some("Trading bot".into()),
        },
        "a long passphrase",
        15,
    )
    .expect("encrypt");
    assert!(
        !backup.backup_json.contains("Trading bot"),
        "the name is only in the encrypted payload"
    );
    assert_eq!(backup.address, EXAMPLE_ADDRESS);
    assert_eq!(backup.public_key_hex, EXAMPLE_PUBLIC_KEY_HEX);
    assert!(backup.backup_json.ends_with("}\n"));
    assert!(
        backup
            .backup_json
            .contains("\"address\": \"0x2c7536E3605D9C16a7a3D7b1898e529396a65c23\""),
        "the address is written in EIP-55 form"
    );
    assert!(backup.backup_json.contains(&format!(
        "\"vaultPublicKey\": \"0x{EXAMPLE_PUBLIC_KEY_HEX}\""
    )));
    assert!(!backup.backup_json.contains(EXAMPLE_PRIVATE_KEY_HEX));
    // Same keys in the same order as the TypeScript CLI's files (which add
    // `sourceVaultKeyId` only when known).
    let mut expected = keys_in_order(TS_V2);
    expected.insert(
        expected
            .iter()
            .position(|key| key == "vaultPublicKey")
            .expect("key")
            + 1,
        "sourceVaultKeyId".to_string(),
    );
    assert_eq!(keys_in_order(&backup.backup_json), expected);

    let contents = decrypt(&backup.backup_json, "a long passphrase").expect("decrypt");
    assert_eq!(contents.version, 2);
    assert_eq!(contents.created_at, backup.created_at);
    assert_eq!(contents.private_key_hex.as_str(), EXAMPLE_PRIVATE_KEY_HEX);
    assert_eq!(contents.source_vault_key_id, source);
    assert_eq!(contents.name.as_deref(), Some("Trading bot"));
}

#[test]
fn backups_without_a_name_still_restore() {
    // Written by the TypeScript CLI: no `name` in the payload.
    let contents = decrypt(TS_V2, TS_V2_PASSPHRASE).expect("decrypt");
    assert_eq!(contents.name, None);
}

#[test]
fn new_backups_use_the_v2_cost() {
    let key = example_key();
    let backup = super::encrypt(
        BackupSource {
            private_key: &key,
            source_vault_key_id: None,
            name: None,
        },
        "a long passphrase",
    )
    .expect("encrypt");
    let document: serde_json::Value = serde_json::from_str(&backup.backup_json).expect("json");
    assert_eq!(document["version"], 2);
    assert_eq!(document["encryption"]["n"], 262_144);
    assert_eq!(document["encryption"]["r"], 8);
    assert_eq!(document["encryption"]["p"], 1);
    assert!(document["wallet"].get("sourceVaultKeyId").is_none());
}

#[test]
fn a_wrong_passphrase_fails_to_decrypt() {
    assert_eq!(
        decrypt(TS_V2, "not the passphrase").err(),
        Some(BackupError::DecryptionFailed)
    );
    assert!(matches!(
        decrypt(TS_V2, "   "),
        Err(BackupError::Invalid(_))
    ));
}

#[test]
fn version_2_headers_are_authenticated() {
    for (from, to) in [
        ("2025-06-01T09:30:00.000Z", "2025-06-02T09:30:00.000Z"),
        ("\"n\": 32768", "\"n\": 65536"),
    ] {
        let tampered = TS_V2.replace(from, to);
        assert_ne!(tampered, TS_V2);
        assert_eq!(
            decrypt(&tampered, TS_V2_PASSPHRASE).err(),
            Some(BackupError::DecryptionFailed),
            "changing {from} must break the tag"
        );
    }
}

#[test]
fn version_1_metadata_must_match_the_encrypted_key() {
    let tampered = TS_V1.replace(
        "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
        "0x0000000000000000000000000000000000000001",
    );
    assert!(matches!(
        decrypt(&tampered, TS_V1_PASSPHRASE),
        Err(BackupError::Invalid(reason)) if reason.contains("metadata")
    ));
}

#[test]
fn rejects_malformed_documents_and_unsupported_parameters() {
    let cases = [
        ("not json", "not valid JSON"),
        ("[]", "JSON object"),
        (r#"{"kind": "other"}"#, "kind"),
        (
            r#"{"kind": "agentpay-wallet-backup", "version": 3}"#,
            "version",
        ),
    ];
    for (document, reason_part) in cases {
        assert!(
            matches!(decrypt(document, "pw"), Err(BackupError::Invalid(reason)) if reason.contains(reason_part)),
            "{document}"
        );
    }
    for (from, to) in [
        ("\"n\": 32768", "\"n\": 16384"),
        ("\"n\": 32768", "\"n\": 2097152"),
        ("\"n\": 32768", "\"n\": 30000"),
        ("\"r\": 8", "\"r\": 16"),
        ("\"p\": 1", "\"p\": 2"),
        ("\"kdf\": \"scrypt\"", "\"kdf\": \"pbkdf2\""),
        (
            "\"algorithm\": \"aes-256-gcm\"",
            "\"algorithm\": \"aes-128-gcm\"",
        ),
    ] {
        let tampered = TS_V2.replace(from, to);
        assert!(
            matches!(
                decrypt(&tampered, TS_V2_PASSPHRASE),
                Err(BackupError::Invalid(_))
            ),
            "{to} must be rejected before any key derivation"
        );
    }
    let oversized = format!("{TS_V2}{}", " ".repeat(64 * 1024));
    assert!(matches!(
        decrypt(&oversized, TS_V2_PASSPHRASE),
        Err(BackupError::Invalid(_))
    ));
}
