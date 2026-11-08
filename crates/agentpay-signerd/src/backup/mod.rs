//! Encrypted offline wallet backups (format v2; v1 is read too), compatible
//! with the files the TypeScript CLI wrote.
//!
//! The private key is encrypted and decrypted here, inside the signer daemon:
//! scrypt (N = 2^18, r = 8, p = 1) derives an AES-256-GCM key from the
//! passphrase, and version 2 binds the cleartext header as additional
//! authenticated data. The wire contract documents the format
//! (`agentpay_api::rpc::wallet`). Key derivation is CPU- and memory-heavy
//! (about a second and 256 MiB), so callers run it on a blocking thread.

mod format;
#[cfg(test)]
mod tests;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use agentpay_api::rpc::wallet::{MAX_BACKUP_JSON_BYTES, MAX_BACKUP_PASSPHRASE_BYTES};
use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;

use self::format::{
    created_at_now, BackupFile, EncryptionHeader, Plaintext, WalletHeader, BACKUP_VERSION,
    IV_BYTES, SALT_BYTES, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R,
};

/// Why a backup could not be made or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackupError {
    /// The document is not a valid backup. Human-readable reason.
    Invalid(String),
    /// The passphrase is wrong or the document was altered.
    DecryptionFailed,
    /// An unexpected internal failure. Human-readable reason.
    Internal(String),
}

/// What a decrypted backup holds.
pub(crate) struct BackupContents {
    /// Format version (1 or 2).
    pub(crate) version: u8,
    /// `createdAt` as written in the document.
    pub(crate) created_at: String,
    /// Uncompressed SEC1 public key, lowercase hex without `0x`.
    pub(crate) public_key_hex: String,
    /// Lowercase `0x` address.
    pub(crate) address: String,
    /// `sourceVaultKeyId` as written, if any.
    pub(crate) source_vault_key_id: Option<String>,
    /// The wallet name from the encrypted payload, as written (unvalidated).
    pub(crate) name: Option<String>,
    /// The private key, 64 lowercase hex characters.
    pub(crate) private_key_hex: Zeroizing<String>,
}

/// A freshly encrypted backup.
pub(crate) struct EncryptedBackup {
    /// The document, ready to be written to a file.
    pub(crate) backup_json: String,
    /// What it holds (no private key).
    pub(crate) created_at: String,
    /// Uncompressed SEC1 public key, lowercase hex without `0x`.
    pub(crate) public_key_hex: String,
    /// Lowercase `0x` address.
    pub(crate) address: String,
}

/// The wallet a backup is made of: its private key (a secp256k1 scalar),
/// the vault key id it came from, and its name.
pub(crate) struct BackupSource<'a> {
    pub(crate) private_key: &'a Zeroizing<[u8; 32]>,
    pub(crate) source_vault_key_id: Option<String>,
    pub(crate) name: Option<String>,
}

/// Encrypts `source` under `passphrase`. The name travels inside the
/// encrypted payload only.
///
/// The passphrase strength rule is the caller's; this only bounds its size.
pub(crate) fn encrypt(
    source: BackupSource<'_>,
    passphrase: &str,
) -> Result<EncryptedBackup, BackupError> {
    encrypt_with_cost(source, passphrase, SCRYPT_LOG_N)
}

fn encrypt_with_cost(
    source: BackupSource<'_>,
    passphrase: &str,
    log_n: u8,
) -> Result<EncryptedBackup, BackupError> {
    let BackupSource {
        private_key,
        source_vault_key_id,
        name,
    } = source;
    check_passphrase_size(passphrase)?;
    let identity = KeyIdentity::from_private_key(private_key)?;
    let created_at = created_at_now()?;
    let wallet = WalletHeader {
        address: identity.checksum_address.clone(),
        vault_public_key: format!("0x{}", identity.public_key_hex),
        source_vault_key_id: source_vault_key_id.clone(),
    };
    let private_key_hex = Zeroizing::new(hex::encode(private_key.as_slice()));
    let plaintext = Plaintext {
        created_at: created_at.clone(),
        private_key_hex,
        address: wallet.address.clone(),
        vault_public_key: wallet.vault_public_key.clone(),
        source_vault_key_id,
        name,
    };
    // Pre-sized so the buffer holding the key is never reallocated (and left behind).
    let mut buffer = Zeroizing::new(Vec::with_capacity(1024));
    serde_json::to_writer(&mut *buffer, &plaintext)
        .map_err(|err| BackupError::Internal(format!("failed to encode backup payload: {err}")))?;

    let mut file = BackupFile {
        version: BACKUP_VERSION,
        created_at: created_at.clone(),
        wallet,
        encryption: EncryptionHeader {
            salt: rand::random::<[u8; SALT_BYTES]>(),
            iv: rand::random::<[u8; IV_BYTES]>(),
            tag: [0; 16],
            log_n,
        },
        ciphertext: Vec::new(),
    };
    let key = derive_key(passphrase, &file.encryption)?;
    let aad = file.aad()?;
    let tag = cipher(&key)?
        .encrypt_in_place_detached(&Nonce::from(file.encryption.iv), &aad, &mut buffer)
        .map_err(|_| BackupError::Internal("failed to encrypt the backup".to_string()))?;
    file.encryption.tag.copy_from_slice(&tag);
    file.ciphertext = buffer.to_vec();
    Ok(EncryptedBackup {
        backup_json: file.render()?,
        created_at,
        public_key_hex: identity.public_key_hex,
        address: identity.lowercase_address,
    })
}

/// Decrypts a backup document with `passphrase` and checks its metadata
/// against the key it holds.
pub(crate) fn decrypt(backup_json: &str, passphrase: &str) -> Result<BackupContents, BackupError> {
    if backup_json.len() > MAX_BACKUP_JSON_BYTES {
        return Err(BackupError::Invalid(format!(
            "the backup must not exceed {MAX_BACKUP_JSON_BYTES} bytes"
        )));
    }
    check_passphrase_size(passphrase)?;
    let file = BackupFile::parse(backup_json)?;
    let key = derive_key(passphrase, &file.encryption)?;
    let aad = file.aad()?;
    let mut buffer = Zeroizing::new(file.ciphertext.clone());
    cipher(&key)?
        .decrypt_in_place_detached(
            &Nonce::from(file.encryption.iv),
            &aad,
            &mut buffer,
            &Tag::from(file.encryption.tag),
        )
        .map_err(|_| BackupError::DecryptionFailed)?;
    let plaintext: Plaintext = serde_json::from_slice(&buffer).map_err(|_| {
        BackupError::Invalid("the encrypted wallet backup payload is malformed".to_string())
    })?;

    let private_key = parse_private_key_hex(&plaintext.private_key_hex)?;
    let identity = KeyIdentity::from_private_key(&private_key)?;
    let matches = |claimed: &str, actual: &str| claimed.eq_ignore_ascii_case(actual);
    let public_key_matches = |claimed: &str| {
        matches(
            claimed.strip_prefix("0x").unwrap_or(claimed),
            &identity.public_key_hex,
        )
    };
    if !matches(plaintext.address.trim(), &identity.lowercase_address)
        || !public_key_matches(plaintext.vault_public_key.trim())
    {
        return Err(BackupError::Invalid(
            "the encrypted wallet backup payload does not match its private key".to_string(),
        ));
    }
    if !matches(&file.wallet.address, &identity.lowercase_address)
        || !public_key_matches(&file.wallet.vault_public_key)
    {
        return Err(BackupError::Invalid(
            "the wallet backup metadata does not match the encrypted key".to_string(),
        ));
    }
    let payload_source = plaintext
        .source_vault_key_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if payload_source != file.wallet.source_vault_key_id.as_deref() {
        return Err(BackupError::Invalid(
            "the wallet backup metadata sourceVaultKeyId does not match the encrypted payload"
                .to_string(),
        ));
    }
    Ok(BackupContents {
        version: file.version,
        created_at: file.created_at,
        public_key_hex: identity.public_key_hex,
        address: identity.lowercase_address,
        source_vault_key_id: file.wallet.source_vault_key_id,
        name: plaintext.name,
        private_key_hex: Zeroizing::new(hex::encode(private_key.as_slice())),
    })
}

/// Rejects an empty, whitespace-only, or oversized passphrase (as the TypeScript CLI did).
fn check_passphrase_size(passphrase: &str) -> Result<(), BackupError> {
    if passphrase.trim().is_empty() {
        return Err(BackupError::Invalid(
            "the backup passphrase must not be empty or whitespace".to_string(),
        ));
    }
    if passphrase.len() > MAX_BACKUP_PASSPHRASE_BYTES {
        return Err(BackupError::Invalid(format!(
            "the backup passphrase must not exceed {MAX_BACKUP_PASSPHRASE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn cipher(key: &Zeroizing<[u8; 32]>) -> Result<Aes256Gcm, BackupError> {
    Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| BackupError::Internal("invalid AES-256-GCM key length".to_string()))
}

fn derive_key(
    passphrase: &str,
    encryption: &EncryptionHeader,
) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let params = scrypt::Params::new(encryption.log_n, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|_| BackupError::Invalid("unsupported scrypt parameters".to_string()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase.as_bytes(), &encryption.salt, &params, &mut *key)
        .map_err(|_| BackupError::Internal("scrypt key derivation failed".to_string()))?;
    Ok(key)
}

/// A private key as written in backups: 64 hex characters, optional `0x`.
fn parse_private_key_hex(value: &str) -> Result<Zeroizing<[u8; 32]>, BackupError> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(digits, &mut *key).map_err(|_| {
        BackupError::Invalid("the encrypted private key is not a 32-byte hex string".to_string())
    })?;
    Ok(key)
}

/// The public identity of a secp256k1 private key.
struct KeyIdentity {
    /// Uncompressed SEC1 public key, lowercase hex without `0x`.
    public_key_hex: String,
    /// EIP-55 address.
    checksum_address: String,
    /// Lowercase `0x` address.
    lowercase_address: String,
}

impl KeyIdentity {
    fn from_private_key(private_key: &Zeroizing<[u8; 32]>) -> Result<Self, BackupError> {
        let signing_key = SigningKey::from_slice(private_key.as_slice()).map_err(|_| {
            BackupError::Invalid("the private key is not a valid secp256k1 key".to_string())
        })?;
        let point = signing_key.verifying_key().to_encoded_point(false);
        let public_key = point.as_bytes();
        let digest = alloy_primitives::keccak256(&public_key[1..]);
        let address = alloy_primitives::Address::from_slice(&digest[12..]);
        Ok(Self {
            public_key_hex: hex::encode(public_key),
            checksum_address: address.to_checksum(None),
            lowercase_address: format!("0x{}", hex::encode(address.as_slice())),
        })
    }
}
