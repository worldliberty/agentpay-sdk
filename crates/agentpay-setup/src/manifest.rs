//! The install manifest: a small root-owned JSON record of what install configured.
//!
//! `status` and `uninstall` read it to report the installed version and to find the
//! installing user (whose name keys the legacy macOS keychain item).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::layout::Layout;
use crate::system::System;

/// Current manifest schema version.
pub const SCHEMA: u32 = 1;

/// Contents of `install.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Schema version ([`SCHEMA`]).
    pub schema: u32,
    /// `agentpay-setup` version that performed the install.
    pub version: String,
    /// Login name of the user the daemon was installed for.
    pub user: String,
    /// That user's uid (admin and agent peer).
    pub uid: u32,
    /// Payments service account name.
    pub service_user: String,
    /// Payments service account uid (agent peer).
    pub service_uid: u32,
}

impl Manifest {
    /// Serialized form written to disk.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Reads the manifest, if present.
pub fn read(sys: &dyn System, layout: &Layout) -> Result<Option<Manifest>> {
    if sys.lstat(&layout.manifest)?.is_none() {
        return Ok(None);
    }
    let bytes = sys.read_file(&layout.manifest)?;
    serde_json::from_slice(&bytes).map(Some).with_context(|| {
        format!(
            "{} is not a valid install manifest",
            layout.manifest.display()
        )
    })
}
