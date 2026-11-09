//! [`ConfigStore`]: the configuration file in paymentd's state directory.
//!
//! The file is `<state dir>/config.json`, written as
//! `{"schema": 1, "config": {...}}` with mode `0600`. paymentd refuses to load
//! a file that is a symlink, is owned by another uid, or is accessible to
//! group or others, so only the service account (and root) can change where
//! payments go. Writes go to a temporary file in the same directory, which is
//! synced and then renamed over the old file.
//!
//! A missing file means "built-in defaults"; nothing is written until the
//! first `SetConfig`. A stored chain that still uses a retired built-in
//! default RPC URL is moved to the current defaults when the file is loaded
//! ([`upgrade_retired_defaults`]). Seeded chains added to the built-in
//! defaults since the file was written are added to it, with their built-in
//! token deployments ([`add_missing_builtin_networks`]), and a built-in token
//! deployment that named the wrong contract is corrected
//! ([`upgrade_retired_deployments`]); the file records
//! which seeded chains it has been offered, so one an operator removed stays
//! removed. Either change rewrites the file once.

use std::io::Write;
use std::path::{Path, PathBuf};

use agentpay_api::payments::PaymentsConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::{
    add_missing_builtin_deployments, add_missing_builtin_networks, default_config,
    seeded_deployment_keys, upgrade_retired_defaults, upgrade_retired_deployments, validate,
    NEW_SEEDED_DEPLOYMENTS, ORIGINAL_SEEDED_CHAINS, SEEDED_CHAINS,
};
use crate::error::PaymentsError;

/// File name of the configuration inside the state directory.
pub const CONFIG_FILE_NAME: &str = "config.json";
/// Current on-disk schema version.
pub const CONFIG_SCHEMA: u32 = 1;
/// Largest configuration file paymentd reads.
const MAX_CONFIG_FILE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct StoredConfig {
    schema: u32,
    config: PaymentsConfig,
    /// Seeded chain keys ([`SEEDED_CHAINS`]) this file has been offered. A
    /// file without it has been offered [`ORIGINAL_SEEDED_CHAINS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seeded_networks: Option<Vec<String>>,
    /// Built-in token deployments (`token@network`) this file has been
    /// offered. A file without it has been offered all but
    /// [`NEW_SEEDED_DEPLOYMENTS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seeded_deployments: Option<Vec<String>>,
}

/// The current configuration, loaded at startup and replaced by `SetConfig`.
#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    current: RwLock<PaymentsConfig>,
}

impl ConfigStore {
    /// Loads `<state_dir>/config.json`, or the built-in defaults when it does
    /// not exist. Fails on an untrusted, unreadable, or invalid file rather
    /// than silently falling back to defaults. Retired built-in RPC defaults
    /// are upgraded, seeded chains the file has not been offered are added,
    /// and the file is rewritten; if that write fails the changes still apply
    /// in memory and are retried at the next start.
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        let path = state_dir.join(CONFIG_FILE_NAME);
        let (mut current, offered, offered_deployments) = match read_trusted(&path)? {
            None => (
                default_config(),
                seeded_chain_keys(),
                seeded_deployment_keys(),
            ),
            Some(bytes) => {
                let stored: StoredConfig = serde_json::from_slice(&bytes)
                    .map_err(|err| format!("{} is not valid: {err}", path.display()))?;
                if stored.schema != CONFIG_SCHEMA {
                    return Err(format!(
                        "{} has schema {}, expected {CONFIG_SCHEMA}",
                        path.display(),
                        stored.schema
                    ));
                }
                let config = validate(&stored.config)
                    .map_err(|reason| format!("{} is invalid: {reason}", path.display()))?;
                let offered = stored.seeded_networks.unwrap_or_else(|| {
                    ORIGINAL_SEEDED_CHAINS
                        .iter()
                        .map(|key| (*key).to_string())
                        .collect()
                });
                let offered_deployments = stored.seeded_deployments.unwrap_or_else(|| {
                    let new: Vec<String> = NEW_SEEDED_DEPLOYMENTS
                        .iter()
                        .map(|(token, network)| format!("{token}@{network}"))
                        .collect();
                    seeded_deployment_keys()
                        .into_iter()
                        .filter(|key| !new.contains(key))
                        .collect()
                });
                (config, offered, offered_deployments)
            }
        };
        let upgraded = upgrade_retired_defaults(&mut current);
        if !upgraded.is_empty() {
            // Network keys only: URLs may embed API keys.
            tracing::info!(
                networks = %upgraded.join(","),
                "upgraded retired default RPC URLs to the current defaults with backups"
            );
            current = validate(&current).map_err(|reason| {
                format!("{} is invalid after upgrade: {reason}", path.display())
            })?;
        }
        let corrected = upgrade_retired_deployments(&mut current);
        if !corrected.is_empty() {
            tracing::info!(
                deployments = %corrected.join(","),
                "moved retired built-in token deployments to the current contracts"
            );
            current = validate(&current).map_err(|reason| {
                format!("{} is invalid after upgrade: {reason}", path.display())
            })?;
        }
        let added = add_new_seeded_chains(&mut current, &offered);
        let deployments = add_new_deployments(&mut current, &offered_deployments);
        let changed = [&upgraded, &corrected, &added, &deployments];
        if changed.iter().any(|keys| !keys.is_empty()) {
            if let Err(error) = persist(&path, &current) {
                tracing::warn!(error = %error.kind(), "could not save the upgraded configuration");
            }
        }
        Ok(Self {
            path,
            current: RwLock::new(current),
        })
    }

    /// Path of the configuration file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current configuration.
    pub async fn get(&self) -> PaymentsConfig {
        self.current.read().await.clone()
    }

    /// Validates `config`, persists it, and makes it current. Storing the
    /// current configuration again writes nothing.
    pub async fn set(&self, config: PaymentsConfig) -> Result<PaymentsConfig, PaymentsError> {
        self.update(|_| Ok((config, ())))
            .await
            .map(|(config, ())| config)
    }

    /// Read-modify-write: `change` derives a new configuration (and a value
    /// to return with it) from the current one, which is then validated,
    /// persisted, and made current exactly as by [`set`](Self::set). The
    /// configuration stays locked throughout, so concurrent changes are never
    /// lost; `change` must not block. An error from `change` changes nothing.
    pub async fn update<T>(
        &self,
        change: impl FnOnce(&PaymentsConfig) -> Result<(PaymentsConfig, T), PaymentsError>,
    ) -> Result<(PaymentsConfig, T), PaymentsError> {
        let mut current = self.current.write().await;
        let (config, value) = change(&current)?;
        let normalized = validate(&config).map_err(PaymentsError::InvalidConfig)?;
        if *current == normalized {
            return Ok((normalized, value));
        }
        persist(&self.path, &normalized)?;
        *current = normalized;
        Ok((current.clone(), value))
    }
}

/// Adds the seeded chains missing from `config` that it has not been offered
/// ([`add_missing_builtin_networks`]) and returns their keys. A result that
/// does not validate (too many chains, say) is dropped with a warning, so
/// new built-in networks never stop paymentd from starting.
fn add_new_seeded_chains(config: &mut PaymentsConfig, offered: &[String]) -> Vec<String> {
    let mut extended = config.clone();
    let added = add_missing_builtin_networks(&mut extended, offered);
    if added.is_empty() {
        return added;
    }
    match validate(&extended) {
        Ok(extended) => {
            tracing::info!(
                networks = %added.join(","),
                "added built-in networks missing from the stored configuration"
            );
            *config = extended;
            added
        }
        Err(reason) => {
            tracing::warn!(
                networks = %added.join(","),
                %reason,
                "could not add the new built-in networks"
            );
            Vec::new()
        }
    }
}

/// Adds the built-in token deployments `config` has not been offered
/// ([`add_missing_builtin_deployments`]), like [`add_new_seeded_chains`].
fn add_new_deployments(config: &mut PaymentsConfig, offered: &[String]) -> Vec<String> {
    let mut extended = config.clone();
    let added = add_missing_builtin_deployments(&mut extended, offered);
    if added.is_empty() {
        return added;
    }
    match validate(&extended) {
        Ok(extended) => {
            tracing::info!(
                deployments = %added.join(","),
                "added built-in token deployments missing from the stored configuration"
            );
            *config = extended;
            added
        }
        Err(reason) => {
            tracing::warn!(
                deployments = %added.join(","),
                %reason,
                "could not add the new built-in token deployments"
            );
            Vec::new()
        }
    }
}

/// Keys of every seeded chain ([`SEEDED_CHAINS`]).
fn seeded_chain_keys() -> Vec<String> {
    SEEDED_CHAINS
        .iter()
        .map(|(key, _)| (*key).to_string())
        .collect()
}

/// Writes `config` to `path` atomically in the stored format. The file
/// records that it has been offered every seeded chain: `config` either came
/// from the defaults or has been through [`add_new_seeded_chains`].
fn persist(path: &Path, config: &PaymentsConfig) -> Result<(), PaymentsError> {
    let stored = StoredConfig {
        schema: CONFIG_SCHEMA,
        config: config.clone(),
        seeded_networks: Some(seeded_chain_keys()),
        seeded_deployments: Some(seeded_deployment_keys()),
    };
    let mut bytes = serde_json::to_vec_pretty(&stored)
        .map_err(|err| PaymentsError::Internal(format!("failed to encode config: {err}")))?;
    bytes.push(b'\n');
    write_atomically(path, &bytes)
        .map_err(|err| PaymentsError::Persistence(format!("failed to write config: {err}")))
}

/// Reads `path` if it exists, after checking it is a private regular file of this uid.
pub(crate) fn read_trusted(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to inspect {}: {err}", path.display())),
    };
    if !metadata.file_type().is_file() {
        return Err(format!("{} must be a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let euid = nix::unistd::geteuid().as_raw();
        if metadata.uid() != euid {
            return Err(format!(
                "{} must be owned by uid {euid} (found uid {})",
                path.display(),
                metadata.uid()
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(format!(
                "{} must not be accessible to group or others (chmod 600)",
                path.display()
            ));
        }
    }
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(format!(
            "{} is larger than {MAX_CONFIG_FILE_BYTES} bytes",
            path.display()
        ));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))
}

/// Writes `bytes` to a fresh `0600` temporary file next to `path`, syncs it,
/// renames it over `path`, and syncs the directory.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        file_name.as_deref().unwrap_or(CONFIG_FILE_NAME),
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
