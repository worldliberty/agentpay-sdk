//! The wallet backup document (format v2, reading v1 too): parsing with the
//! same validation as the TypeScript CLI that introduced it, the header bound
//! as AES-GCM additional data, and the encrypted plaintext.
//!
//! Field order matters twice: the additional authenticated data is the
//! compact JSON of [`AadHeader`] in exactly the TypeScript key order, and the
//! written document follows the order `JSON.stringify` produced, so files
//! written here and by the TypeScript CLI look the same.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::BackupError;

/// `kind` of every backup document.
pub(super) const BACKUP_KIND: &str = "agentpay-wallet-backup";
/// Version written by this daemon.
pub(super) const BACKUP_VERSION: u8 = 2;
/// Version written by early CLIs (no additional authenticated data).
pub(super) const LEGACY_BACKUP_VERSION: u8 = 1;
/// scrypt cost of new backups: N = 2^18 (256 MiB with r = 8).
pub(super) const SCRYPT_LOG_N: u8 = 18;
/// Smallest accepted N (older CLIs used 2^15).
const SCRYPT_MIN_LOG_N: u8 = 15;
/// Largest accepted N, so a crafted file cannot request unbounded work (1 GiB).
const SCRYPT_MAX_LOG_N: u8 = 20;
/// scrypt block size.
pub(super) const SCRYPT_R: u32 = 8;
/// scrypt parallelism.
pub(super) const SCRYPT_P: u32 = 1;
/// Salt length in bytes.
pub(super) const SALT_BYTES: usize = 16;
/// AES-GCM IV length in bytes.
pub(super) const IV_BYTES: usize = 12;
/// AES-GCM tag length in bytes.
pub(super) const TAG_BYTES: usize = 16;
/// Largest accepted ciphertext (the plaintext is a few hundred bytes).
const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024;
const ALGORITHM: &str = "aes-256-gcm";
const KDF: &str = "scrypt";

/// A parsed, validated backup document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackupFile {
    pub(super) version: u8,
    pub(super) created_at: String,
    pub(super) wallet: WalletHeader,
    pub(super) encryption: EncryptionHeader,
    pub(super) ciphertext: Vec<u8>,
}

/// The cleartext wallet metadata of a backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct WalletHeader {
    pub(super) address: String,
    #[serde(rename = "vaultPublicKey")]
    pub(super) vault_public_key: String,
    #[serde(rename = "sourceVaultKeyId", skip_serializing_if = "Option::is_none")]
    pub(super) source_vault_key_id: Option<String>,
}

/// The key-derivation and cipher parameters of a backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EncryptionHeader {
    pub(super) salt: [u8; SALT_BYTES],
    pub(super) iv: [u8; IV_BYTES],
    pub(super) tag: [u8; TAG_BYTES],
    pub(super) log_n: u8,
}

/// The header bound as additional authenticated data (version 2).
#[derive(Serialize)]
struct AadHeader<'a> {
    kind: &'static str,
    version: u8,
    #[serde(rename = "createdAt")]
    created_at: &'a str,
    wallet: &'a WalletHeader,
    encryption: AadEncryption,
}

#[derive(Serialize)]
struct AadEncryption {
    algorithm: &'static str,
    kdf: &'static str,
    #[serde(rename = "saltHex")]
    salt_hex: String,
    #[serde(rename = "ivHex")]
    iv_hex: String,
    n: u64,
    r: u32,
    p: u32,
}

/// The written document, in `JSON.stringify` key order.
#[derive(Serialize)]
struct FileOut<'a> {
    kind: &'static str,
    version: u8,
    #[serde(rename = "createdAt")]
    created_at: &'a str,
    wallet: &'a WalletHeader,
    encryption: EncryptionOut,
    #[serde(rename = "ciphertextHex")]
    ciphertext_hex: String,
}

#[derive(Serialize)]
struct EncryptionOut {
    algorithm: &'static str,
    kdf: &'static str,
    #[serde(rename = "saltHex")]
    salt_hex: String,
    #[serde(rename = "ivHex")]
    iv_hex: String,
    n: u64,
    r: u32,
    p: u32,
    #[serde(rename = "authTagHex")]
    auth_tag_hex: String,
}

/// The encrypted payload.
#[derive(Serialize, Deserialize)]
pub(super) struct Plaintext {
    #[serde(rename = "createdAt")]
    pub(super) created_at: String,
    #[serde(
        rename = "privateKeyHex",
        with = "agentpay_domain::serde_helpers::zeroizing_string"
    )]
    pub(super) private_key_hex: Zeroizing<String>,
    pub(super) address: String,
    #[serde(rename = "vaultPublicKey")]
    pub(super) vault_public_key: String,
    #[serde(
        rename = "sourceVaultKeyId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) source_vault_key_id: Option<String>,
    /// The wallet's display name (API 1.1); absent in older backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
}

impl BackupFile {
    /// The additional authenticated data: the header for version 2, none for version 1.
    pub(super) fn aad(&self) -> Result<Vec<u8>, BackupError> {
        if self.version < BACKUP_VERSION {
            return Ok(Vec::new());
        }
        let header = AadHeader {
            kind: BACKUP_KIND,
            version: self.version,
            created_at: &self.created_at,
            wallet: &self.wallet,
            encryption: AadEncryption {
                algorithm: ALGORITHM,
                kdf: KDF,
                salt_hex: hex::encode(self.encryption.salt),
                iv_hex: hex::encode(self.encryption.iv),
                n: 1u64 << self.encryption.log_n,
                r: SCRYPT_R,
                p: SCRYPT_P,
            },
        };
        serde_json::to_vec(&header)
            .map_err(|err| BackupError::Internal(format!("failed to encode backup header: {err}")))
    }

    /// The document as pretty-printed JSON with a trailing newline.
    pub(super) fn render(&self) -> Result<String, BackupError> {
        let out = FileOut {
            kind: BACKUP_KIND,
            version: self.version,
            created_at: &self.created_at,
            wallet: &self.wallet,
            encryption: EncryptionOut {
                algorithm: ALGORITHM,
                kdf: KDF,
                salt_hex: hex::encode(self.encryption.salt),
                iv_hex: hex::encode(self.encryption.iv),
                n: 1u64 << self.encryption.log_n,
                r: SCRYPT_R,
                p: SCRYPT_P,
                auth_tag_hex: hex::encode(self.encryption.tag),
            },
            ciphertext_hex: hex::encode(&self.ciphertext),
        };
        let mut rendered = serde_json::to_string_pretty(&out)
            .map_err(|err| BackupError::Internal(format!("failed to encode backup: {err}")))?;
        rendered.push('\n');
        Ok(rendered)
    }

    /// Parses and validates a backup document.
    pub(super) fn parse(raw: &str) -> Result<Self, BackupError> {
        let payload: Value = serde_json::from_str(raw)
            .map_err(|_| invalid("the backup is not valid JSON".to_string()))?;
        let payload = object(&payload, "wallet backup")?;
        if payload.get("kind").and_then(Value::as_str) != Some(BACKUP_KIND) {
            return Err(invalid("wallet backup kind is invalid".to_string()));
        }
        let version = match payload.get("version").and_then(Value::as_u64) {
            Some(2) => BACKUP_VERSION,
            Some(1) => LEGACY_BACKUP_VERSION,
            _ => {
                return Err(invalid(format!(
                    "wallet backup version must be {LEGACY_BACKUP_VERSION} or {BACKUP_VERSION}"
                )))
            }
        };
        let created_at = payload
            .get("createdAt")
            .and_then(Value::as_str)
            .filter(|value| OffsetDateTime::parse(value, &Rfc3339).is_ok())
            .ok_or_else(|| {
                invalid("wallet backup createdAt must be a valid ISO-8601 time".to_string())
            })?
            .to_string();

        let wallet = object(payload.get("wallet").unwrap_or(&Value::Null), "wallet")?;
        let wallet = WalletHeader {
            address: optional_string(wallet, "address")?
                .ok_or_else(|| invalid("wallet backup wallet.address is required".to_string()))?,
            vault_public_key: optional_string(wallet, "vaultPublicKey")?.ok_or_else(|| {
                invalid("wallet backup wallet.vaultPublicKey is required".to_string())
            })?,
            source_vault_key_id: optional_string(wallet, "sourceVaultKeyId")?,
        };

        let encryption = object(
            payload.get("encryption").unwrap_or(&Value::Null),
            "encryption",
        )?;
        if encryption.get("algorithm").and_then(Value::as_str) != Some(ALGORITHM) {
            return Err(invalid(format!(
                "wallet backup encryption.algorithm must be {ALGORITHM}"
            )));
        }
        if encryption.get("kdf").and_then(Value::as_str) != Some(KDF) {
            return Err(invalid(format!(
                "wallet backup encryption.kdf must be {KDF}"
            )));
        }
        let log_n = scrypt_log_n(encryption)?;
        let encryption = EncryptionHeader {
            salt: fixed_hex(encryption, "saltHex")?,
            iv: fixed_hex(encryption, "ivHex")?,
            tag: fixed_hex(encryption, "authTagHex")?,
            log_n,
        };
        let ciphertext = hex_field(payload, "ciphertextHex")?;
        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(invalid("wallet backup ciphertext is too large".to_string()));
        }
        Ok(Self {
            version,
            created_at,
            wallet,
            encryption,
            ciphertext,
        })
    }
}

/// `createdAt` for a backup made now, as JavaScript's `toISOString` writes it.
pub(super) fn created_at_now() -> Result<String, BackupError> {
    let format = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    OffsetDateTime::now_utc()
        .format(&format)
        .map_err(|err| BackupError::Internal(format!("failed to format the backup time: {err}")))
}

fn invalid(reason: String) -> BackupError {
    BackupError::Invalid(reason)
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>, BackupError> {
    value
        .as_object()
        .ok_or_else(|| invalid(format!("{label} must be a JSON object")))
}

/// A trimmed, non-empty string field; `None` when absent, `null`, or blank.
fn optional_string(
    record: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, BackupError> {
    match record.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Some(_) => Err(invalid(format!(
            "{field} must be a string in wallet backup"
        ))),
    }
}

fn hex_field(record: &Map<String, Value>, field: &str) -> Result<Vec<u8>, BackupError> {
    let value = record
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| invalid(format!("{field} must be a hex string in wallet backup")))?;
    hex::decode(value).map_err(|_| {
        invalid(format!(
            "{field} must contain an even number of hex characters in wallet backup"
        ))
    })
}

fn fixed_hex<const N: usize>(
    record: &Map<String, Value>,
    field: &str,
) -> Result<[u8; N], BackupError> {
    <[u8; N]>::try_from(hex_field(record, field)?)
        .map_err(|_| invalid(format!("{field} must be {N} bytes in wallet backup")))
}

/// `log2(N)` of the scrypt parameters, which must be N = 2^15..=2^20, r = 8, p = 1.
fn scrypt_log_n(encryption: &Map<String, Value>) -> Result<u8, BackupError> {
    let unsupported = || invalid("wallet backup encryption parameters are unsupported".to_string());
    let n = encryption
        .get("n")
        .and_then(Value::as_u64)
        .ok_or_else(unsupported)?;
    let r = encryption.get("r").and_then(Value::as_u64);
    let p = encryption.get("p").and_then(Value::as_u64);
    if !n.is_power_of_two() || r != Some(u64::from(SCRYPT_R)) || p != Some(u64::from(SCRYPT_P)) {
        return Err(unsupported());
    }
    let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| unsupported())?;
    if !(SCRYPT_MIN_LOG_N..=SCRYPT_MAX_LOG_N).contains(&log_n) {
        return Err(unsupported());
    }
    Ok(log_n)
}
