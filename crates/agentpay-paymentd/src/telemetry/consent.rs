//! The stored telemetry consent: `telemetry.json` in the service's state
//! directory (mode `0600`), holding the opt-out and the random install id.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{read_trusted, write_atomically};
use crate::error::PaymentsError;

/// File name inside the state directory.
pub const TELEMETRY_FILE_NAME: &str = "telemetry.json";

/// What `telemetry.json` holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consent {
    /// Whether telemetry may be sent.
    pub enabled: bool,
    /// The random id events carry; fixed for the life of the file.
    pub install_id: Uuid,
}

/// The state of `telemetry.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// No file yet: telemetry is on by default.
    Missing,
    /// The file cannot be trusted or parsed. Treated as an opt-out, because
    /// it may be a damaged one.
    Unreadable,
    /// A valid file.
    Present(Consent),
}

/// Reads and writes `telemetry.json`.
#[derive(Debug, Clone)]
pub struct ConsentStore {
    path: PathBuf,
}

impl ConsentStore {
    /// The store in `state_dir`.
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(TELEMETRY_FILE_NAME),
        }
    }

    /// The file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current state of the file.
    #[must_use]
    pub fn read(&self) -> Stored {
        match read_trusted(&self.path) {
            Ok(None) => Stored::Missing,
            Ok(Some(bytes)) => serde_json::from_slice::<Consent>(&bytes)
                .ok()
                .filter(|consent| !consent.install_id.is_nil())
                .map_or(Stored::Unreadable, Stored::Present),
            Err(_) => Stored::Unreadable,
        }
    }

    /// The stored consent, creating the file (on, with a new install id)
    /// when there is none. `None` when the file is unreadable or cannot be
    /// created: without durable state there is no install id, so telemetry
    /// stays off.
    #[must_use]
    pub fn ensure(&self) -> Option<Consent> {
        match self.read() {
            Stored::Present(consent) => Some(consent),
            Stored::Unreadable => None,
            Stored::Missing => {
                let consent = Consent {
                    enabled: true,
                    install_id: Uuid::new_v4(),
                };
                self.write(&consent).ok().map(|()| consent)
            }
        }
    }

    /// Stores `enabled`, keeping the install id of a valid file; a missing
    /// or damaged file is replaced with a fresh one.
    pub fn set(&self, enabled: bool) -> Result<Consent, PaymentsError> {
        let install_id = match self.read() {
            Stored::Present(consent) => consent.install_id,
            Stored::Missing | Stored::Unreadable => Uuid::new_v4(),
        };
        let consent = Consent {
            enabled,
            install_id,
        };
        self.write(&consent).map_err(|err| {
            PaymentsError::Persistence(format!("failed to write telemetry.json: {err}"))
        })?;
        Ok(consent)
    }

    fn write(&self, consent: &Consent) -> std::io::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(consent).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        write_atomically(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{set_mode, TempDir};

    #[test]
    fn the_file_is_created_on_first_use_and_keeps_its_install_id() {
        let dir = TempDir::new("consent");
        let store = ConsentStore::new(dir.path());
        assert_eq!(store.read(), Stored::Missing);
        let first = store.ensure().expect("created");
        assert!(first.enabled);
        assert_eq!(store.ensure(), Some(first));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(store.path())
            .expect("file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let off = store.set(false).expect("opt out");
        assert_eq!(off.install_id, first.install_id);
        assert_eq!(store.read(), Stored::Present(off));
    }

    #[test]
    fn a_damaged_file_is_an_opt_out_until_rewritten() {
        let dir = TempDir::new("consent");
        let store = ConsentStore::new(dir.path());
        std::fs::write(store.path(), b"{not json").expect("write");
        set_mode(store.path(), 0o600);
        assert_eq!(store.read(), Stored::Unreadable);
        assert_eq!(store.ensure(), None);
        let rewritten = store.set(true).expect("rewrite");
        assert_eq!(store.read(), Stored::Present(rewritten));

        // A file others can read is not trusted either.
        set_mode(store.path(), 0o644);
        assert_eq!(store.read(), Stored::Unreadable);
    }
}
