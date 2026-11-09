//! `ExportWalletBackup` and `VerifyWalletBackup`: encrypted offline backups of
//! the wallet key. The key is encrypted and decrypted here; it never leaves
//! the daemon in the clear.

use agentpay_api::rpc::wallet::{
    WalletBackupExport, WalletBackupSummary, MAX_BACKUP_PASSPHRASE_BYTES,
    MIN_BACKUP_PASSPHRASE_CHARS,
};
use agentpay_domain::{AdminAuth, EvmAddress, KeyAlgorithm, VaultKey};
use agentpay_signer::{SignerError, VaultSignerBackend};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::super::signing::parse_verifying_key;
use super::wallet_name;
use crate::backup::{self, BackupContents, BackupError, BackupSource};
use crate::{DaemonError, InMemoryDaemon, RequestContext};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn export_wallet_backup_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        vault_key_id: Option<Uuid>,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupExport, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        check_new_passphrase(&passphrase)?;
        let vault_key = self.resolve_wallet(vault_key_id)?;
        if vault_key.algorithm != KeyAlgorithm::Secp256k1 {
            return Err(DaemonError::InvalidWalletRequest(
                "only secp256k1 wallets can be backed up".to_string(),
            ));
        }
        let private_key = self.wallet_private_key(vault_key.id)?;
        let source = vault_key.id.to_string();
        let name = vault_key.name.clone();
        let _kdf_guard = self.backup_kdf_guard.lock().await;
        let encrypted = tokio::task::spawn_blocking(move || {
            backup::encrypt(
                BackupSource {
                    private_key: &private_key,
                    source_vault_key_id: Some(source),
                    name,
                },
                &passphrase,
            )
        })
        .await
        .map_err(|_| internal("backup encryption task failed"))?
        .map_err(map_backup_error)?;
        Ok(WalletBackupExport {
            backup_json: encrypted.backup_json,
            summary: WalletBackupSummary {
                version: 2,
                created_at: encrypted.created_at,
                address: parse_address(&encrypted.address)?,
                public_key_hex: encrypted.public_key_hex,
                source_vault_key_id: Some(vault_key.id.to_string()),
                matching_vault_key_id: Some(vault_key.id),
                name: vault_key.name,
            },
        })
    }

    pub(crate) async fn verify_wallet_backup_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        backup_json: String,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupSummary, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let contents = self.decrypt_backup(backup_json, passphrase).await?;
        let matching_vault_key_id = self.vault_key_holding(&contents.public_key_hex)?;
        Ok(WalletBackupSummary {
            version: contents.version,
            address: parse_address(&contents.address)?,
            created_at: contents.created_at,
            public_key_hex: contents.public_key_hex,
            source_vault_key_id: contents.source_vault_key_id,
            matching_vault_key_id,
            name: backup_name(contents.name),
        })
    }

    /// Decrypts a backup on a blocking thread, one key derivation at a time.
    pub(super) async fn decrypt_backup(
        &self,
        backup_json: String,
        passphrase: Zeroizing<String>,
    ) -> Result<BackupContents, DaemonError> {
        let _kdf_guard = self.backup_kdf_guard.lock().await;
        tokio::task::spawn_blocking(move || backup::decrypt(&backup_json, &passphrase))
            .await
            .map_err(|_| internal("backup decryption task failed"))?
            .map_err(map_backup_error)
    }

    /// The vault key holding the secp256k1 key with this (uncompressed, hex) public key.
    pub(super) fn vault_key_holding(
        &self,
        public_key_hex: &str,
    ) -> Result<Option<Uuid>, DaemonError> {
        let wanted = parse_verifying_key(public_key_hex)?;
        let vault_keys = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let mut matching = vault_keys
            .values()
            .filter(|key| key.algorithm == KeyAlgorithm::Secp256k1)
            .filter(|key| parse_verifying_key(&key.public_key_hex).ok() == Some(wanted))
            .map(|key| key.id)
            .collect::<Vec<_>>();
        matching.sort_unstable();
        Ok(matching.into_iter().next())
    }

    /// The wallet: `vault_key_id`, or the only vault key.
    pub(super) fn resolve_wallet(
        &self,
        vault_key_id: Option<Uuid>,
    ) -> Result<VaultKey, DaemonError> {
        let vault_keys = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        match vault_key_id {
            Some(id) => vault_keys
                .get(&id)
                .cloned()
                .ok_or(DaemonError::UnknownVaultKey(id)),
            None => match vault_keys.len() {
                0 => Err(DaemonError::WalletNotFound),
                1 => vault_keys
                    .values()
                    .next()
                    .cloned()
                    .ok_or(DaemonError::WalletNotFound),
                count => Err(DaemonError::InvalidWalletRequest(format!(
                    "the daemon holds {count} vault keys; pass vault_key_id"
                ))),
            },
        }
    }

    /// The wallet's secp256k1 private key, from the signer backend.
    fn wallet_private_key(&self, vault_key_id: Uuid) -> Result<Zeroizing<[u8; 32]>, DaemonError> {
        let not_exportable = || {
            DaemonError::Signer(SignerError::Unsupported(
                "the signer backend keeps this wallet key non-exportable".to_string(),
            ))
        };
        let mut exported = self
            .signer_backend
            .export_persistable_key_material(&[vault_key_id])
            .map_err(DaemonError::Signer)?;
        let material = exported.remove(&vault_key_id).ok_or_else(not_exportable)?;
        let digits = material
            .strip_prefix("secp256k1:")
            .ok_or_else(not_exportable)?;
        let mut private_key = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(digits, &mut *private_key)
            .map_err(|_| internal("the signer backend returned malformed key material"))?;
        Ok(private_key)
    }
}

/// A new backup's passphrase: at least [`MIN_BACKUP_PASSPHRASE_CHARS`]
/// characters, not only whitespace, at most [`MAX_BACKUP_PASSPHRASE_BYTES`] bytes.
fn check_new_passphrase(passphrase: &str) -> Result<(), DaemonError> {
    if passphrase.len() > MAX_BACKUP_PASSPHRASE_BYTES {
        return Err(DaemonError::InvalidWalletRequest(format!(
            "the backup passphrase must not exceed {MAX_BACKUP_PASSPHRASE_BYTES} bytes"
        )));
    }
    if passphrase.chars().count() < MIN_BACKUP_PASSPHRASE_CHARS || passphrase.trim().is_empty() {
        return Err(DaemonError::WeakBackupPassphrase {
            min_chars: MIN_BACKUP_PASSPHRASE_CHARS,
        });
    }
    Ok(())
}

/// The name a backup carries, if it is a valid wallet name; a crafted or
/// damaged one is dropped rather than blocking a restore.
pub(super) fn backup_name(name: Option<String>) -> Option<String> {
    wallet_name(name).ok().flatten()
}

pub(super) fn map_backup_error(error: BackupError) -> DaemonError {
    match error {
        BackupError::Invalid(reason) => DaemonError::InvalidWalletBackup(reason),
        BackupError::DecryptionFailed => DaemonError::WalletBackupDecryptionFailed,
        BackupError::Internal(reason) => DaemonError::Signer(SignerError::Internal(reason)),
    }
}

fn parse_address(address: &str) -> Result<EvmAddress, DaemonError> {
    address
        .parse()
        .map_err(|_| internal("derived EVM address is not valid"))
}

fn internal(reason: &str) -> DaemonError {
    DaemonError::Signer(SignerError::Internal(reason.to_string()))
}
