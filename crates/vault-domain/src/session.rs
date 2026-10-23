use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Admin lease issued by the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    /// Lease identifier.
    pub lease_id: Uuid,
    /// Issuance timestamp.
    pub issued_at: OffsetDateTime,
    /// Expiration timestamp.
    pub expires_at: OffsetDateTime,
}

impl Lease {
    /// Returns whether lease is valid at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.issued_at && now <= self.expires_at
    }
}

/// Admin authentication material supplied to privileged APIs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSession {
    /// Vault password.
    ///
    /// Wrapped in [`Zeroizing`] so the secret is wiped on drop even when a
    /// caller returns early with `?` before an explicit zeroize call.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    pub vault_password: Zeroizing<String>,
    /// Active lease.
    pub lease: Lease,
}

impl fmt::Debug for AdminSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminSession")
            .field("vault_password", &"<redacted>")
            .field("lease", &self.lease)
            .finish()
    }
}

impl AdminSession {
    pub fn zeroize_secrets(&mut self) {
        self.vault_password.zeroize();
    }
}
