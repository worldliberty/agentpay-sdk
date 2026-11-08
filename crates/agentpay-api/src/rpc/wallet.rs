//! Wallet lifecycle: one-call setup (`BootstrapWallet`), the wallets on the
//! machine (`ListWallets`, `RenameWallet`), and encrypted offline backups
//! (`ExportWalletBackup`, `VerifyWalletBackup`).
//!
//! # Wallet names
//!
//! A wallet may carry an operator-chosen display name (API 1.1), set by
//! `BootstrapWallet` (`create`, `restore_from_backup`) or `RenameWallet`:
//! surrounding whitespace is trimmed, the result is 1 to
//! [`MAX_WALLET_NAME_CHARS`] characters without control characters
//! (`InvalidWalletRequest` otherwise). Names are labels only: nothing
//! addresses a wallet by name, and two wallets may share one. A backup keeps
//! the name inside its encrypted payload (see below).
//!
//! The **wallet** is the daemon's `secp256k1` vault key: it signs EVM and
//! Tempo transactions, and its Solana (Ed25519) key is derived from it. A
//! daemon set up through `BootstrapWallet` holds exactly one; `ListWallets`
//! shows every vault key, so a client can tell several apart (by address,
//! age, and agent keys) before it reuses or backs up one of them.
//!
//! # Encrypted backups (format v2)
//!
//! A backup is a JSON document that holds the wallet's private key encrypted
//! under a passphrase. It is the same format the TypeScript CLI wrote
//! (`agentpay admin wallet-backup export`), so backups made by earlier
//! releases restore unchanged:
//!
//! ```json
//! {
//!   "kind": "agentpay-wallet-backup",
//!   "version": 2,
//!   "createdAt": "2026-11-05T12:00:00.000Z",
//!   "wallet": {"address": "0x<EIP-55>", "vaultPublicKey": "0x04<128 hex>", "sourceVaultKeyId": "<uuid, optional>"},
//!   "encryption": {"algorithm": "aes-256-gcm", "kdf": "scrypt", "saltHex": "<16 bytes>", "ivHex": "<12 bytes>", "n": 262144, "r": 8, "p": 1, "authTagHex": "<16 bytes>"},
//!   "ciphertextHex": "<hex>"
//! }
//! ```
//!
//! - **Key derivation:** scrypt(passphrase as UTF-8, salt, N, r = 8, p = 1,
//!   32 bytes). New backups use N = 2^18 (256 MiB of memory); backups with N
//!   from 2^15 to 2^20 are read.
//! - **Encryption:** AES-256-GCM with the 12-byte IV and a 16-byte tag.
//!   Version 2 binds the header as additional authenticated data: the compact
//!   JSON `{"kind", "version", "createdAt", "wallet": {"address",
//!   "vaultPublicKey"[, "sourceVaultKeyId"]}, "encryption": {"algorithm",
//!   "kdf", "saltHex", "ivHex", "n", "r", "p"}}` in exactly that key order, so
//!   editing any header field breaks the tag. Version 1 (older CLIs) has no
//!   additional data and is still read.
//! - **Plaintext:** the compact JSON `{"createdAt", "privateKeyHex" (64 hex,
//!   no `0x`), "address", "vaultPublicKey"[, "sourceVaultKeyId"][, "name"]}`.
//!   `name` (API 1.1) is the wallet's name when it had one; it is encrypted
//!   and authenticated with the key, and readers that do not know it ignore
//!   it, so the format stays version 2 and older backups (without it) restore
//!   unchanged. On
//!   decryption the daemon re-derives the address and public key from the
//!   private key and requires both copies of the metadata to match.
//!
//! The private key is encrypted and decrypted inside the signer daemon; it
//! never crosses the socket in the clear. Passphrases do (inside the request,
//! over the local socket), so treat requests carrying one as secrets.
//!
//! # Passphrases
//!
//! A new backup's passphrase must have at least
//! [`MIN_BACKUP_PASSPHRASE_CHARS`] characters (Unicode scalar values,
//! counted as given: surrounding whitespace counts) and at most
//! [`MAX_BACKUP_PASSPHRASE_BYTES`] bytes of UTF-8. Reading a backup accepts any
//! non-empty passphrase up to that size, because earlier CLIs had no minimum.
//! There is no recovery: a forgotten passphrase makes the backup useless.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{AdminAuth, AgentCredentials};
use crate::rpc::limits::{SpendingLimit, SpendingLimitsReport};
use crate::types::{EvmAddress, KeyAlgorithm, KeySource, SolanaAddress, Timestamp, VaultKey};

/// Minimum length of a new backup passphrase, in characters.
pub const MIN_BACKUP_PASSPHRASE_CHARS: usize = 12;

/// Maximum size of a backup passphrase, in bytes of UTF-8.
pub const MAX_BACKUP_PASSPHRASE_BYTES: usize = 16 * 1024;

/// Maximum size of a backup document (`backup_json`), in bytes.
pub const MAX_BACKUP_JSON_BYTES: usize = 64 * 1024;

/// Maximum length of a wallet name, in characters (Unicode scalar values).
pub const MAX_WALLET_NAME_CHARS: usize = 32;

/// How `BootstrapWallet` obtains the wallet key.
///
/// JSON (internally tagged by `kind`): `{"kind": "create", "replace_existing":
/// false}`, `{"kind": "reuse"}`, or `{"kind": "restore_from_backup",
/// "backup_json": "...", "passphrase": "...", "replace_existing": false}`
/// (`replace_existing` defaults to `false`; the `reuse` ids and the `name`
/// of `create` and `restore_from_backup` are optional).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WalletBootstrapMode {
    /// Generate a new wallet key.
    ///
    /// Fails with `WalletAlreadyExists` when the daemon holds any vault key,
    /// unless `replace_existing` is `true`.
    Create {
        /// Destroy the existing wallet(s) (see `BootstrapWallet`); default `false`.
        #[serde(default)]
        replace_existing: bool,
        /// The new wallet's name (API 1.1; see the [module docs](self)).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        name: Option<String>,
    },
    /// Keep the existing wallet key and (re)issue its agent key.
    ///
    /// The wallet is `vault_key_id`, or the only vault key when absent. The
    /// agent key is `agent_key_id`, or the wallet's only agent key when
    /// absent (one is created when the wallet has none); its token is
    /// rotated, and its spend history is kept.
    Reuse {
        /// The wallet to reuse; required when the daemon holds several vault keys.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        vault_key_id: Option<Uuid>,
        /// The agent key to keep; required when the wallet has several.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        agent_key_id: Option<Uuid>,
    },
    /// Import the wallet key from an encrypted backup (see the [module docs](self)).
    ///
    /// Fails with `WalletAlreadyExists` when the daemon holds any vault key,
    /// unless `replace_existing` is `true`; when the daemon already holds this
    /// very key, use `reuse` instead (`InvalidWalletRequest`).
    RestoreFromBackup {
        /// The backup document, verbatim (at most [`MAX_BACKUP_JSON_BYTES`]).
        backup_json: String,
        /// The backup's passphrase. Secret.
        #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
        #[schemars(with = "String")]
        #[ts(as = "String")]
        passphrase: Zeroizing<String>,
        /// Destroy the existing wallet(s) (see `BootstrapWallet`); default `false`.
        #[serde(default)]
        replace_existing: bool,
        /// The restored wallet's name (API 1.1); absent: the name stored in
        /// the backup, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        name: Option<String>,
    },
}

impl WalletBootstrapMode {
    /// Wipes the backup passphrase in place.
    pub fn zeroize_secrets(&mut self) {
        if let Self::RestoreFromBackup { passphrase, .. } = self {
            passphrase.zeroize();
        }
    }
}

impl fmt::Debug for WalletBootstrapMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create {
                replace_existing,
                name,
            } => f
                .debug_struct("Create")
                .field("replace_existing", replace_existing)
                .field("name", name)
                .finish(),
            Self::Reuse {
                vault_key_id,
                agent_key_id,
            } => f
                .debug_struct("Reuse")
                .field("vault_key_id", vault_key_id)
                .field("agent_key_id", agent_key_id)
                .finish(),
            Self::RestoreFromBackup {
                backup_json,
                replace_existing,
                name,
                ..
            } => f
                .debug_struct("RestoreFromBackup")
                .field("backup_json_bytes", &backup_json.len())
                .field("passphrase", &"<redacted>")
                .field("replace_existing", replace_existing)
                .field("name", name)
                .finish(),
        }
    }
}

/// `BootstrapWallet`: sets up the wallet, its agent key, and the agent's
/// spending limits in one atomic step.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::WalletBootstrap`](crate::DaemonRpcResponse::WalletBootstrap) |
/// | Side effects | creates, keeps, or imports the wallet key; creates or refreshes its agent key (new token); replaces the agent's spending limits; with `replace_existing`, destroys the previous wallet(s); persists |
/// | Idempotent | no: every call issues a new agent token, and `create` makes a new key |
///
/// Steps, all applied together or not at all:
///
/// 1. **Wallet** per `mode` ([`WalletBootstrapMode`]).
/// 2. **Agent key**: a new one for `create` and `restore_from_backup`; for
///    `reuse`, the existing one is refreshed. Its token is returned once.
/// 3. **Limits**: exactly as `SetSpendingLimits` with `limits`. Deny by
///    default: the agent can spend only the listed network and asset pairs.
///
/// **Replacing a wallet** (`replace_existing: true`) deletes every existing
/// vault key with its private key, every agent key of those vault keys
/// (tokens, spend history, nonce state, approval requests), and disables
/// their spending policies. Funds held by a replaced wallet are reachable
/// only through a backup of it: export one first.
///
/// **Wallet name:** `create` stores `name`; `restore_from_backup` stores
/// `name`, else the name the backup carries; `reuse` keeps the wallet's name
/// (rename it with `RenameWallet`).
///
/// **Errors:** admin-auth kinds, `WalletAlreadyExists`, `WalletNotFound`
/// (`reuse` without a wallet), `InvalidWalletRequest` (ambiguous or
/// inconsistent ids, restoring a key the daemon already holds, an invalid
/// `name`),
/// `InvalidSpendingLimits`, `InvalidWalletBackup`,
/// `WalletBackupDecryptionFailed`, `UnknownVaultKey`, `UnknownAgentKey`,
/// `Signer`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/BootstrapWallet.request.json")]
/// ```
///
/// Response (`auth_token` is shown once; store it securely):
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/BootstrapWallet.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BootstrapWalletParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// How to obtain the wallet key.
    pub mode: WalletBootstrapMode,
    /// The agent's spending limits: 1 to 64 rows (see `SetSpendingLimits`).
    pub limits: Vec<SpendingLimit>,
}

/// What `BootstrapWallet` did with the wallet key. JSON: `"created"`,
/// `"reused"`, or `"restored"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum WalletBootstrapOutcome {
    /// A new key was generated.
    Created,
    /// The existing key was kept.
    Reused,
    /// The key was imported from a backup.
    Restored,
}

/// Result of `BootstrapWallet`.
///
/// `Debug` redacts the agent token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletBootstrap {
    /// What happened to the wallet key.
    pub outcome: WalletBootstrapOutcome,
    /// Public metadata of the wallet key.
    pub vault_key: VaultKey,
    /// The wallet's EVM address (lower case).
    pub evm_address: Option<EvmAddress>,
    /// The wallet's Solana address; `null` when the signer backend cannot
    /// sign for Solana (the Linux TPM).
    pub solana_address: Option<SolanaAddress>,
    /// The agent key and its new bearer token (shown only here).
    pub agent_credentials: AgentCredentials,
    /// The agent's spending limits with usage (carried over for `reuse`).
    pub spending_limits: SpendingLimitsReport,
    /// Vault keys destroyed by `replace_existing`, ascending; empty otherwise.
    pub replaced_vault_key_ids: Vec<Uuid>,
}

impl WalletBootstrap {
    /// Wipes the agent token in place.
    pub fn zeroize_secrets(&mut self) {
        self.agent_credentials.zeroize_secrets();
    }
}

/// `ExportWalletBackup`: encrypts the wallet's private key under a
/// passphrase and returns the backup document.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::WalletBackup`](crate::DaemonRpcResponse::WalletBackup) |
/// | Side effects | none (the daemon does not store the backup) |
/// | Idempotent | yes in effect: every call makes a new document (fresh salt and IV) for the same key |
///
/// The key is encrypted inside the daemon (format v2, N = 2^18; see the
/// [module docs](self)), which takes about a second and 256 MiB of memory;
/// the daemon runs one backup key derivation at a time. Write `backup_json`
/// to a file only the user can read and keep it offline.
///
/// **Errors:** admin-auth kinds, `WeakBackupPassphrase`, `WalletNotFound`,
/// `InvalidWalletRequest` (several vault keys and no `vault_key_id`, or an
/// `ed25519` key), `UnknownVaultKey`, `Signer` (`Unsupported` when the
/// backend keeps keys non-exportable, as the Linux TPM does).
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ExportWalletBackup.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ExportWalletBackup.response.json")]
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ExportWalletBackupParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// The wallet to back up; required when the daemon holds several vault keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub vault_key_id: Option<Uuid>,
    /// The new backup's passphrase: at least [`MIN_BACKUP_PASSPHRASE_CHARS`]
    /// characters. Secret.
    #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub passphrase: Zeroizing<String>,
}

impl ExportWalletBackupParams {
    /// Wipes the lease secret and the passphrase in place.
    pub fn zeroize_secrets(&mut self) {
        self.auth.zeroize_secrets();
        self.passphrase.zeroize();
    }
}

impl fmt::Debug for ExportWalletBackupParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportWalletBackupParams")
            .field("auth", &self.auth)
            .field("vault_key_id", &self.vault_key_id)
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// `VerifyWalletBackup`: decrypts a backup with its passphrase and reports
/// what it holds, without changing anything.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::WalletBackupSummary`](crate::DaemonRpcResponse::WalletBackupSummary) |
/// | Side effects | none |
/// | Idempotent | yes |
///
/// Use it right after `ExportWalletBackup` (on the file as written) to prove
/// the backup and passphrase work. A wrong passphrase and a tampered document
/// are indistinguishable (`WalletBackupDecryptionFailed`).
///
/// **Errors:** admin-auth kinds, `InvalidWalletBackup` (not a backup,
/// unsupported version or parameters, metadata that does not match the key),
/// `WalletBackupDecryptionFailed`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/VerifyWalletBackup.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/VerifyWalletBackup.response.json")]
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct VerifyWalletBackupParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// The backup document, verbatim (at most [`MAX_BACKUP_JSON_BYTES`]).
    pub backup_json: String,
    /// The backup's passphrase. Secret.
    #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub passphrase: Zeroizing<String>,
}

impl VerifyWalletBackupParams {
    /// Wipes the lease secret and the passphrase in place.
    pub fn zeroize_secrets(&mut self) {
        self.auth.zeroize_secrets();
        self.passphrase.zeroize();
    }
}

impl fmt::Debug for VerifyWalletBackupParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyWalletBackupParams")
            .field("auth", &self.auth)
            .field("backup_json_bytes", &self.backup_json.len())
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// What a backup holds, from its authenticated contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletBackupSummary {
    /// Backup format version (1 or 2).
    pub version: u8,
    /// When the backup was made, as written in it (ISO-8601, for example
    /// `"2026-11-05T12:00:00.000Z"`).
    pub created_at: String,
    /// The wallet's EVM address (lower case).
    pub address: EvmAddress,
    /// The wallet's uncompressed `secp256k1` public key, 130 lowercase hex
    /// characters without `0x` (the encoding of `VaultKey.public_key_hex`).
    pub public_key_hex: String,
    /// The vault key id the backup was made from, if it recorded one.
    pub source_vault_key_id: Option<String>,
    /// The vault key in this daemon that holds the same private key, if any.
    pub matching_vault_key_id: Option<Uuid>,
    /// The wallet name stored in the backup (API 1.1); `null` when it has
    /// none (unnamed wallets and backups made before names existed).
    pub name: Option<String>,
}

/// Result of `ExportWalletBackup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletBackupExport {
    /// The backup document: pretty-printed JSON with a trailing newline,
    /// ready to be written to a file as is.
    pub backup_json: String,
    /// What the backup holds.
    pub summary: WalletBackupSummary,
}

/// `ListWallets`: lists the wallets (vault keys) on this machine with their
/// addresses and agent keys, oldest first.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::Wallets`](crate::DaemonRpcResponse::Wallets) |
/// | Side effects | none; idempotent |
///
/// Read-only and secret-free: the response carries public metadata only (no
/// key material, agent tokens, or token hashes). Clients use it to show which
/// wallet `BootstrapWallet` `reuse` or `ExportWalletBackup` would act on, and
/// to name one by `vault_key_id` when the daemon holds several. An empty list
/// means no wallet is set up.
///
/// **Errors:** admin-auth kinds, `Signer` (the backend failed to derive a
/// Solana address).
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListWallets.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListWallets.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListWalletsParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
}

/// One wallet in the `ListWallets` response: a vault key's public metadata,
/// its addresses, and the agent keys that sign with it. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct WalletInfo {
    /// The vault key id (`vault_key_id` in `BootstrapWallet` and `ExportWalletBackup`).
    pub vault_key_id: Uuid,
    /// The key's signing algorithm; wallets set up by `BootstrapWallet` are `"secp256k1"`.
    pub algorithm: KeyAlgorithm,
    /// The EVM (and Tempo) address, lower case; `null` for an `ed25519` key.
    pub evm_address: Option<EvmAddress>,
    /// The Solana address (base58); `null` when the signer backend cannot
    /// sign for Solana (the Linux TPM).
    pub solana_address: Option<SolanaAddress>,
    /// When the key was created or imported (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub created_at: OffsetDateTime,
    /// `"Generated"` by the signer backend or `"Imported"` (a restored backup
    /// or an imported private key).
    pub source: KeySource,
    /// The wallet's display name (API 1.1); `null` when unnamed.
    pub name: Option<String>,
    /// The agent keys bound to this wallet, ascending; empty when it has none.
    pub agent_key_ids: Vec<Uuid>,
}

/// `RenameWallet` (API 1.1): sets or clears a wallet's display name.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::Wallet`](crate::DaemonRpcResponse::Wallet) (the renamed wallet) |
/// | Side effects | changes the vault key's name; persists |
/// | Idempotent | yes |
///
/// `name` is trimmed and must then be 1 to [`MAX_WALLET_NAME_CHARS`]
/// characters without control characters; `null` clears the name. The name
/// is a label only (see the [module docs](self)); it changes nothing about
/// keys, agents, or policies.
///
/// **Errors:** admin-auth kinds, `UnknownVaultKey`, `InvalidWalletRequest`
/// (invalid name), `Signer` (the backend failed to derive a Solana address),
/// `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RenameWallet.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RenameWallet.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RenameWalletParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// The wallet to rename.
    pub vault_key_id: Uuid,
    /// The new name, or `null` to clear it.
    pub name: Option<String>,
}
