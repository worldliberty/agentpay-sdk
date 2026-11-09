//! Admin authentication types.
//!
//! There is no vault password. A privileged (admin) call is authorized in one of
//! two ways:
//!
//! - **Root peer**: the caller connects over the local socket as root (euid 0),
//!   which the daemon learns from the kernel, not from the request. Such callers
//!   send [`AdminAuth::PeerCredentials`].
//! - **Admin lease**: the caller proves possession of an enrolled
//!   [`AdminCredential`] (a Secure Enclave P-256 key on macOS) by signing an
//!   [`AdminChallenge`], and receives a short-lived [`AdminLease`]. It then sends
//!   [`AdminAuth::Lease`] with the lease's [`AdminSession`].

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::schema::Timestamp;

/// Bearer credential for an admin lease: the lease id plus its secret.
///
/// The secret is wrapped in [`Zeroizing`] so it is wiped on drop, and it is
/// redacted from `Debug` output.
///
/// JSON: `{"lease_id": "<uuid>", "lease_secret": "<64 lowercase hex chars>"}`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AdminSession {
    /// Lease identifier returned by the daemon in [`AdminLease::lease_id`].
    pub lease_id: Uuid,
    /// Lease secret returned by the daemon in [`AdminLease::lease_secret`]
    /// (lowercase hex, 64 characters). A bearer secret: never log it.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub lease_secret: Zeroizing<String>,
}

impl fmt::Debug for AdminSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminSession")
            .field("lease_id", &self.lease_id)
            .field("lease_secret", &"<redacted>")
            .finish()
    }
}

impl AdminSession {
    /// Wipes the lease secret in place.
    pub fn zeroize_secrets(&mut self) {
        self.lease_secret.zeroize();
    }
}

/// How the caller of a privileged daemon API proves admin authority.
///
/// JSON: `"peer_credentials"` or `{"lease": {"lease_id": "...", "lease_secret": "..."}}`.
/// Every admin RPC treats a missing `auth` field as `"peer_credentials"`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(rename_all = "snake_case")]
pub enum AdminAuth {
    /// Rely on the transport-verified identity of the calling process.
    ///
    /// Only root peers (euid 0) and in-process callers are authorized this way;
    /// the daemon never trusts an identity claimed inside the request.
    #[default]
    PeerCredentials,
    /// Present an admin lease obtained through the challenge flow.
    ///
    /// The lease must be unexpired, and the connection must come from the same
    /// peer euid that completed the challenge. A presented lease is verified
    /// even for root peers.
    Lease(AdminSession),
}

impl AdminAuth {
    /// Wipes any secret material in place.
    pub fn zeroize_secrets(&mut self) {
        if let Self::Lease(session) = self {
            session.zeroize_secrets();
        }
    }
}

/// Short-lived admin lease issued after a successful admin challenge.
///
/// Leases live only in daemon memory (a restart forgets them) and are bound to
/// the peer euid that completed the challenge. The default lifetime is 5 minutes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AdminLease {
    /// Lease identifier.
    pub lease_id: Uuid,
    /// Lease secret (lowercase hex, 64 characters). Only returned once; the
    /// daemon keeps a SHA-256 hash. A bearer secret: never log it.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub lease_secret: Zeroizing<String>,
    /// Issuance timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub issued_at: OffsetDateTime,
    /// Expiration timestamp (UTC); the lease is valid while `now <= expires_at`.
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for AdminLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminLease")
            .field("lease_id", &self.lease_id)
            .field("lease_secret", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AdminLease {
    /// Returns the bearer session to present with privileged calls.
    #[must_use]
    pub fn session(&self) -> AdminSession {
        AdminSession {
            lease_id: self.lease_id,
            lease_secret: self.lease_secret.clone(),
        }
    }

    /// Returns [`AdminAuth::Lease`] for this lease.
    #[must_use]
    pub fn auth(&self) -> AdminAuth {
        AdminAuth::Lease(self.session())
    }

    /// Returns whether the lease is valid at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.issued_at && now <= self.expires_at
    }

    /// Wipes the lease secret in place.
    pub fn zeroize_secrets(&mut self) {
        self.lease_secret.zeroize();
    }
}

/// Enrolled admin credential: a P-256 public key whose holder may obtain leases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AdminCredential {
    /// Credential identifier, used with `BeginAdminChallenge`.
    pub id: Uuid,
    /// SEC1-encoded P-256 public key, lowercase hex without `0x`. The daemon
    /// stores the canonical uncompressed form (`04` + 64 bytes, 130 hex chars)
    /// whatever encoding was enrolled.
    pub public_key_sec1_hex: String,
    /// Human-readable label, for example the device name (at most 64 characters).
    pub label: String,
    /// Enrollment timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub created_at: OffsetDateTime,
}

/// Admin challenge to be signed by an enrolled credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AdminChallenge {
    /// Challenge identifier, passed back with the signature.
    pub challenge_id: Uuid,
    /// Exact bytes to sign, lowercase hex without `0x` (the
    /// `agentpay-admin-challenge-v1` message documented in `docs/daemon-api.md`).
    /// The signature is ECDSA P-256 over SHA-256 of these bytes, DER encoded
    /// (CryptoKit `signature(for:)`). Clients sign the bytes as given and never
    /// rebuild them.
    pub message_hex: String,
    /// Expiration timestamp (UTC, 2 minutes after issuance by default); the
    /// challenge is single use.
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}
