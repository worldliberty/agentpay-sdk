//! [`PendingStore`]: actions waiting for an operator, kept so that
//! `ResumeApproved` resends exactly what was submitted.
//!
//! The signer daemon matches a resent request to its approval by the SHA-256
//! of the payload bytes, so the resumed action must be identical: same
//! nonce, fees, and calldata. Rebuilding it would create a new approval
//! request. Each record is `<state dir>/evm-pending/<approval id>.json`
//! (directory `0700`, files `0600`), written to a temporary file that is
//! synced and renamed into place. Reads refuse symlinks, files of other
//! owners, and files readable by group or others, like the configuration.
//! Records hold no secrets: the agent key id, the action, and how to deliver
//! it. Records older than the signer daemon's approval lifetime (24 hours)
//! are deleted whenever a new one is saved.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use agentpay_api::payments::EvmPayment;
use agentpay_domain::AgentAction;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::PaymentsError;

/// Directory of the records inside the state directory.
pub(super) const PENDING_DIR_NAME: &str = "evm-pending";
/// On-disk schema version.
pub(super) const RECORD_SCHEMA: u32 = 1;
/// Largest record read.
const MAX_RECORD_BYTES: u64 = 64 * 1024;
/// Records older than this are pruned (the signer daemon expires pending and
/// approved requests after 24 hours).
const RECORD_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// How a transaction is delivered once signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Delivery {
    /// Send the transaction after verifying it.
    pub(super) broadcast: bool,
    /// Wait for the receipt after sending.
    pub(super) wait_for_receipt: bool,
    /// Receipt wait, in seconds.
    pub(super) receipt_timeout_secs: u64,
}

/// One action waiting for an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PendingRecord {
    /// [`RECORD_SCHEMA`].
    pub(super) schema: u32,
    /// The signer daemon's approval request.
    pub(super) approval_request_id: Uuid,
    /// The agent that submitted it; only that agent may resume it.
    pub(super) agent_key_id: Uuid,
    /// The method that was called.
    pub(super) method: String,
    /// Chain key; `None` for typed data.
    pub(super) network: Option<String>,
    /// Chain id.
    pub(super) chain_id: u64,
    /// What a transfer or approval moves.
    pub(super) payment: Option<EvmPayment>,
    /// The exact action submitted for signing.
    pub(super) action: AgentAction,
    /// For a `BroadcastTx`, how to deliver it.
    pub(super) delivery: Option<Delivery>,
}

/// The pending-approval records of one state directory.
pub(super) struct PendingStore {
    dir: PathBuf,
}

impl PendingStore {
    /// The store under `state_dir`.
    pub(super) fn new(state_dir: &Path) -> Self {
        Self {
            dir: state_dir.join(PENDING_DIR_NAME),
        }
    }

    fn path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Writes `record`, replacing any record with the same approval id.
    pub(super) fn save(&self, record: &PendingRecord) -> Result<(), PaymentsError> {
        self.ensure_dir()?;
        self.prune_expired();
        let bytes = serde_json::to_vec(record)
            .map_err(|_| persistence("failed to encode a pending approval"))?;
        let path = self.path(record.approval_request_id);
        let temp = self.dir.join(format!(
            ".{}.tmp-{}",
            record.approval_request_id,
            Uuid::new_v4().simple()
        ));
        let written = write_new(&temp, &bytes).and_then(|()| {
            fs::rename(&temp, &path)?;
            fs::File::open(&self.dir)?.sync_all()
        });
        if written.is_err() {
            let _ = fs::remove_file(&temp);
            return Err(persistence("failed to write a pending approval"));
        }
        Ok(())
    }

    /// The record for `id` if it exists and belongs to `agent_key_id`.
    pub(super) fn load(
        &self,
        id: Uuid,
        agent_key_id: Uuid,
    ) -> Result<PendingRecord, PaymentsError> {
        let path = self.path(id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(PaymentsError::UnknownPendingApproval(id));
            }
            Err(_) => return Err(persistence("failed to read a pending approval")),
        };
        let trusted = metadata.file_type().is_file()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0
            && metadata.len() <= MAX_RECORD_BYTES;
        if !trusted {
            return Err(persistence("a pending approval file is not trusted"));
        }
        let bytes =
            fs::read(&path).map_err(|_| persistence("failed to read a pending approval"))?;
        let record: PendingRecord = serde_json::from_slice(&bytes)
            .map_err(|_| persistence("a pending approval file is invalid"))?;
        if record.schema != RECORD_SCHEMA || record.approval_request_id != id {
            return Err(persistence("a pending approval file is invalid"));
        }
        // Another agent's record is reported exactly like a missing one.
        if record.agent_key_id != agent_key_id {
            return Err(PaymentsError::UnknownPendingApproval(id));
        }
        Ok(record)
    }

    /// Deletes the record for `id`, if any.
    pub(super) fn remove(&self, id: Uuid) -> Result<(), PaymentsError> {
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(persistence("failed to delete a pending approval")),
        }
    }

    fn ensure_dir(&self) -> Result<(), PaymentsError> {
        match fs::symlink_metadata(&self.dir) {
            Ok(metadata)
                if metadata.is_dir() && metadata.uid() == nix::unistd::geteuid().as_raw() =>
            {
                if metadata.mode() & 0o077 != 0 {
                    fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700)).map_err(
                        |_| persistence("failed to secure the pending approvals directory"),
                    )?;
                }
                Ok(())
            }
            Ok(_) => Err(persistence(
                "the pending approvals directory is not trusted",
            )),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
                .mode(0o700)
                .create(&self.dir)
                .map_err(|_| persistence("failed to create the pending approvals directory")),
            Err(_) => Err(persistence(
                "failed to read the pending approvals directory",
            )),
        }
    }

    /// Deletes records older than [`RECORD_LIFETIME`]; best effort.
    fn prune_expired(&self) {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let now = SystemTime::now();
        for entry in entries.flatten() {
            let expired = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age > RECORD_LIFETIME);
            if expired {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Creates `path` (which must not exist) with mode `0600` and syncs `bytes` to it.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn persistence(reason: &str) -> PaymentsError {
    PaymentsError::Persistence(reason.to_string())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use agentpay_domain::EvmAddress;

    use super::*;
    use crate::test_support::{set_mode, TempDir};

    fn record(agent: Uuid) -> PendingRecord {
        PendingRecord {
            schema: RECORD_SCHEMA,
            approval_request_id: Uuid::new_v4(),
            agent_key_id: agent,
            method: "TransferNative".into(),
            network: Some("bsc".into()),
            chain_id: 56,
            payment: None,
            action: AgentAction::TransferNative {
                chain_id: 56,
                to: EvmAddress::from_str("0x5aeda56215b167893e80b4fe645ba6d5bab767de").unwrap(),
                amount_wei: 1,
            },
            delivery: None,
        }
    }

    #[test]
    fn records_round_trip_privately_and_only_for_their_agent() {
        let dir = TempDir::new("pending");
        let store = PendingStore::new(dir.path());
        let agent = Uuid::new_v4();
        let record = record(agent);
        let id = record.approval_request_id;
        store.save(&record).expect("save");

        let path = dir.path().join(PENDING_DIR_NAME).join(format!("{id}.json"));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(dir.path().join(PENDING_DIR_NAME))
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(store.load(id, agent).expect("load"), record);
        assert_eq!(
            store.load(id, Uuid::new_v4()),
            Err(PaymentsError::UnknownPendingApproval(id))
        );

        store.save(&record).expect("overwrite");
        store.remove(id).expect("remove");
        store.remove(id).expect("remove twice");
        assert_eq!(
            store.load(id, agent),
            Err(PaymentsError::UnknownPendingApproval(id))
        );
    }

    #[test]
    fn untrusted_files_are_refused() {
        let dir = TempDir::new("pending");
        let store = PendingStore::new(dir.path());
        let agent = Uuid::new_v4();
        let record = record(agent);
        let id = record.approval_request_id;
        store.save(&record).expect("save");
        let path = dir.path().join(PENDING_DIR_NAME).join(format!("{id}.json"));
        set_mode(&path, 0o644);
        assert!(matches!(
            store.load(id, agent),
            Err(PaymentsError::Persistence(_))
        ));

        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &path).unwrap();
        assert!(matches!(
            store.load(id, agent),
            Err(PaymentsError::Persistence(_))
        ));
    }
}
