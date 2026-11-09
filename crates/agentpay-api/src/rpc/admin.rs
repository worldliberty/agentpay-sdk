//! Admin authentication methods: credential enrollment, challenges, and leases.
//!
//! See [`crate::auth`] for the end-to-end challenge flow and message format.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::auth::AdminAuth;

/// `EnrollAdminCredential`: enrolls a P-256 public key whose holder may
/// obtain admin leases through the challenge flow.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | **root peer only** (no `auth` field; leases are not accepted) |
/// | Response | [`DaemonRpcResponse::AdminCredential`](crate::DaemonRpcResponse::AdminCredential) |
/// | Side effects | persists the credential |
/// | Idempotent | no: enrolling the same key again fails |
///
/// The key is stored in canonical uncompressed form, so the same key cannot be
/// enrolled twice under different encodings. At most 8 credentials may exist.
///
/// **Errors:** `RootPeerRequired`, `InvalidAdminCredential` (not hex, not a
/// P-256 point, bad label, already enrolled), `TooManyAdminCredentials`,
/// `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/EnrollAdminCredential.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/EnrollAdminCredential.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct EnrollAdminCredentialParams {
    /// SEC1-encoded P-256 public key, compressed (33 bytes) or uncompressed
    /// (65 bytes), as hex without `0x` (at most 130 characters).
    pub public_key_sec1_hex: String,
    /// Human-readable label, 1 to 64 characters without control characters
    /// (surrounding whitespace is trimmed).
    pub label: String,
}

/// `ListAdminCredentials`: lists enrolled admin credentials, oldest first.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::AdminCredentials`](crate::DaemonRpcResponse::AdminCredentials) |
/// | Side effects | none; idempotent |
///
/// **Errors:** the admin-auth kinds only.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListAdminCredentials.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/ListAdminCredentials.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct ListAdminCredentialsParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
}

/// `RevokeAdminCredential`: removes a credential together with its leases,
/// pending challenges, and lockout state.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease (a lease may revoke its own credential) |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | persists the removal; every lease of the credential stops working immediately |
/// | Idempotent | no: a second call fails with `UnknownAdminCredential` |
///
/// **Errors:** admin-auth kinds, `UnknownAdminCredential`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RevokeAdminCredential.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RevokeAdminCredential.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RevokeAdminCredentialParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Credential to revoke.
    pub id: Uuid,
}

/// `BeginAdminChallenge`: issues a single-use challenge for an enrolled credential.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | none (possession of the credential's private key is proven in step 2) |
/// | Response | [`DaemonRpcResponse::AdminChallenge`](crate::DaemonRpcResponse::AdminChallenge) |
/// | Side effects | stores a pending challenge in memory (2-minute TTL), bound to the caller's peer euid |
/// | Idempotent | no: every call issues a new challenge |
///
/// **Errors:** `InvalidAdminChallengePurpose`, `UnknownAdminCredential`,
/// `AdminCredentialLocked`, `TooManyPendingAdminChallenges`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/BeginAdminChallenge.request.json")]
/// ```
///
/// Response (`message_hex` is the real `agentpay-admin-challenge-v1` encoding
/// of the ids, nonce, purpose, and expiry shown in these examples):
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/BeginAdminChallenge.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct BeginAdminChallengeParams {
    /// Credential that will sign the challenge.
    pub credential_id: Uuid,
    /// Short identifier of the intended operation, embedded in the signed
    /// message so the signing prompt can show it: 1 to 128 characters of
    /// `[A-Za-z0-9._:/-]`, for example `admin-session` or `approve:<uuid>`.
    pub purpose: String,
}

/// `CompleteAdminChallenge`: exchanges a signed challenge for an admin lease.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist; must be the same peer euid that began the challenge |
/// | Auth | the signature itself |
/// | Response | [`DaemonRpcResponse::AdminLease`](crate::DaemonRpcResponse::AdminLease) |
/// | Side effects | consumes the challenge (even on failure); a failure counts toward the credential's lockout (5 failures lock it for 30 s); success resets the counter and stores the lease hash in memory |
/// | Idempotent | no: a challenge can be completed once |
///
/// **Errors:** `InvalidAdminChallenge` (unknown, expired, used, or different
/// peer), `AdminCredentialLocked`, `UnknownAdminCredential`,
/// `AuthenticationFailed` (bad signature), `TooManyActiveLeases`.
///
/// Request (the signature verifies against the example credential's key):
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/CompleteAdminChallenge.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/CompleteAdminChallenge.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CompleteAdminChallengeParams {
    /// Challenge id from `BeginAdminChallenge`.
    pub challenge_id: Uuid,
    /// ASN.1 DER ECDSA P-256 signature over SHA-256 of the challenge message,
    /// as hex without `0x` (at most 160 characters).
    pub signature_der_hex: String,
}

/// `RevokeAdminLease`: revokes an admin lease before it expires.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease (a lease may revoke itself, which is how clients "log out") |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | forgets the lease (in memory) |
/// | Idempotent | no: a second call fails with `UnknownLease` |
///
/// **Errors:** admin-auth kinds, `UnknownLease`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RevokeAdminLease.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RevokeAdminLease.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RevokeAdminLeaseParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Lease to revoke.
    pub lease_id: Uuid,
}
