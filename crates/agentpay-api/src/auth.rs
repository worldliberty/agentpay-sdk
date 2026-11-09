//! Who may call what: peer allowlists, agent bearer tokens, and admin authority.
//!
//! Authorization happens in two independent layers.
//!
//! # 1. Transport: peer-euid allowlists
//!
//! The daemon learns the caller's effective uid from the kernel
//! (`SO_PEERCRED` / `getpeereid`), never from the request. It keeps two
//! allowlists, both of which always contain root (`0`):
//!
//! - the **admin allowlist** (`--allow-admin-euid`), which gates every method
//!   whose [`AccessLevel`] is [`AccessLevel::Admin`];
//! - the **agent allowlist** (`--allow-agent-euid`), which gates
//!   [`AccessLevel::Agent`] methods.
//!
//! A peer on neither list is disconnected before its request is read. A peer
//! calling a method outside its list is disconnected without a response.
//! [`AccessLevel::Any`] methods (the `Hello` handshake) are open to every peer
//! on either list.
//!
//! # 2. Daemon: credentials inside the request
//!
//! - **Agent methods** carry an `agent_key_id` plus `agent_auth_token` (the
//!   bearer token from [`AgentCredentials`]). Wrong or unknown tokens fail with
//!   `AgentAuthenticationFailed`.
//! - **Admin methods** carry an `auth` field ([`AdminAuth`]); a missing field
//!   means [`AdminAuth::PeerCredentials`]:
//!   - `"peer_credentials"` succeeds only for **root peers** (euid 0), for
//!     example the CLI run under `sudo`. Others get
//!     `AdminAuthenticationRequired`.
//!   - `{"lease": {...}}` presents an **admin lease** obtained through the
//!     challenge flow below. It must be unexpired and come from the same peer
//!     euid that completed the challenge.
//!
//! # Admin challenge flow (`agentpay-admin-challenge-v1`)
//!
//! 1. A root peer enrolls a P-256 public key once (`EnrollAdminCredential`);
//!    on macOS the private key lives in the Secure Enclave behind Touch ID or
//!    the login password.
//! 2. The client calls `BeginAdminChallenge` with the credential id and a
//!    short `purpose` and receives an [`AdminChallenge`] (single use, 2-minute
//!    TTL, bound to the caller's peer euid).
//! 3. The client signs the bytes of `message_hex` exactly as given: ECDSA
//!    P-256 over SHA-256 of the message, DER-encoded (CryptoKit
//!    `P256.Signing.PrivateKey.signature(for:)` / `ecdsa-with-SHA256`).
//! 4. The client calls `CompleteAdminChallenge` with the DER signature as hex
//!    and receives an [`AdminLease`] (5-minute TTL). The challenge is consumed
//!    whether or not the signature verifies; 5 consecutive failures lock the
//!    credential for 30 seconds (`AdminCredentialLocked`).
//!
//! The message bytes are the concatenation of:
//!
//! | Field | Encoding |
//! |---|---|
//! | domain tag | ASCII [`ADMIN_CHALLENGE_DOMAIN_TAG`] then one `0x00` byte |
//! | daemon instance id | 16 bytes (UUID, random per daemon process) |
//! | credential id | 16 bytes (UUID) |
//! | challenge id | 16 bytes (UUID) |
//! | nonce | [`ADMIN_CHALLENGE_NONCE_BYTES`] random bytes |
//! | purpose | big-endian `u16` byte length, then the UTF-8 bytes |
//! | expiry | big-endian `i64` Unix timestamp in seconds |
//!
//! Clients may parse the message to show the purpose and expiry to the user,
//! but must sign the bytes they received rather than a rebuilt message.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub use agentpay_domain::{
    AdminAuth, AdminChallenge, AdminCredential, AdminLease, AdminSession, AgentCredentials,
};

/// Agent credentials presented by methods that are not tied to one signing
/// request: signerd's `AuthenticateAgent` and every authenticated payments
/// service method.
///
/// JSON: `{"agent_key_id": "<uuid>", "agent_auth_token": "<token>"}`.
///
/// The token is a bearer secret (from [`AgentCredentials::auth_token`]): send it
/// only over the local socket, keep it out of logs, and wipe it after use.
/// `Debug` redacts it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct AgentAuth {
    /// The agent key id (`AgentCredentials.agent_key.id`).
    pub agent_key_id: Uuid,
    /// The agent's bearer token (`AgentCredentials.auth_token`), at most 16 KiB.
    #[serde(with = "agentpay_domain::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub agent_auth_token: Zeroizing<String>,
}

impl AgentAuth {
    /// Wipes the bearer token in place.
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
    }
}

impl fmt::Debug for AgentAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentAuth")
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .finish()
    }
}

/// Domain-separation tag at the start of every admin challenge message.
pub const ADMIN_CHALLENGE_DOMAIN_TAG: &[u8] = b"agentpay-admin-challenge-v1";

/// Number of random nonce bytes in an admin challenge message.
pub const ADMIN_CHALLENGE_NONCE_BYTES: usize = 32;

/// Maximum length of an admin challenge `purpose`, in bytes.
///
/// A purpose is 1 to 128 characters of `[A-Za-z0-9._:/-]`, for example
/// `admin-session` or `approve:<uuid>`.
pub const MAX_ADMIN_CHALLENGE_PURPOSE_BYTES: usize = 128;

/// Returns whether `purpose` is a valid admin challenge purpose.
#[must_use]
pub fn is_valid_admin_challenge_purpose(purpose: &str) -> bool {
    let valid_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/');
    !purpose.is_empty()
        && purpose.len() <= MAX_ADMIN_CHALLENGE_PURPOSE_BYTES
        && purpose.chars().all(valid_char)
}

/// Which peer-euid allowlist governs a method.
///
/// The allowlist only decides who may *reach* a method; admin methods still
/// require a root peer or a valid admin lease inside the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessLevel {
    /// Vault administration: admin credentials, challenges and leases,
    /// policies, keys, and manual approvals. Gated by the admin allowlist.
    Admin,
    /// Agent signing, evaluation, and nonce management. Gated by the agent
    /// allowlist.
    Agent,
    /// Open to every peer on either allowlist (the `Hello` handshake).
    Any,
}
