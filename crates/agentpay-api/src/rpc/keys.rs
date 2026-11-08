//! Vault-key and agent-key methods.
//!
//! A **vault key** is a signing key held by the daemon (software, or sealed by
//! the Linux TPM). An **agent key** is an identity that may ask a vault key
//! to sign within the policies attached to it; it authenticates with a bearer
//! token returned only by `CreateAgentKey`, `RefreshAgentKey`, and
//! `RotateAgentAuthToken`.
//!
//! Private keys never leave the daemon in the clear: back a wallet up with
//! `ExportWalletBackup` ([`wallet`](super::wallet)), which encrypts it inside
//! the daemon.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::auth::AdminAuth;
use crate::types::{KeyCreateRequest, PolicyAttachment};

/// `CreateVaultKey`: generates or imports a vault signing key.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::VaultKey`](crate::DaemonRpcResponse::VaultKey) |
/// | Side effects | creates the key in the signer backend and persists it |
/// | Idempotent | no: every call creates a new key id |
///
/// **Errors:** admin-auth kinds, `Signer` (`InvalidPrivateKey`,
/// `Unsupported`, ...), `Persistence` (the new key is deleted again).
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/CreateVaultKey.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/CreateVaultKey.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateVaultKeyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// What key to create. Import variants carry a private key: send them only
    /// over the local socket and wipe the request afterwards.
    pub request: KeyCreateRequest,
}

impl CreateVaultKeyParams {
    /// Wipes the lease secret and any imported private key in place.
    pub fn zeroize_secrets(&mut self) {
        self.auth.zeroize_secrets();
        if let KeyCreateRequest::Import { private_key_hex }
        | KeyCreateRequest::ImportWithAlgorithm {
            private_key_hex, ..
        } = &mut self.request
        {
            private_key_hex.zeroize();
        }
    }
}

/// `CreateAgentKey`: creates an agent key for a vault key and returns its bearer token.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::AgentCredentials`](crate::DaemonRpcResponse::AgentCredentials) |
/// | Side effects | persists the agent key and the token's SHA-256 hash |
/// | Idempotent | no: every call creates a new agent key |
///
/// `AllPolicies` is dynamic (policies added later apply too); `PolicySet` is
/// a static snapshot and must name existing, enabled policies.
///
/// **Errors:** admin-auth kinds, `UnknownVaultKey`, `UnknownPolicy`,
/// `InvalidPolicyAttachment`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/CreateAgentKey.request.json")]
/// ```
///
/// Response (`auth_token` is shown once; store it securely):
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/CreateAgentKey.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct CreateAgentKeyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Vault key the agent will sign with.
    pub vault_key_id: Uuid,
    /// Policies governing the agent.
    pub attachment: PolicyAttachment,
}

/// `RefreshAgentKey`: replaces an agent key's policy attachment and rotates its token.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::AgentCredentials`](crate::DaemonRpcResponse::AgentCredentials) |
/// | Side effects | persists the new attachment and token hash; the old token stops working |
/// | Idempotent | no: every call issues a new token |
///
/// **Errors:** admin-auth kinds, `UnknownAgentKey`, `InvalidPolicyAttachment`
/// (including an agent that does not belong to `vault_key_id`),
/// `UnknownPolicy`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RefreshAgentKey.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RefreshAgentKey.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RefreshAgentKeyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Agent key to refresh.
    pub agent_key_id: Uuid,
    /// Vault key the agent must already belong to.
    pub vault_key_id: Uuid,
    /// Replacement policy attachment.
    pub attachment: PolicyAttachment,
}

/// `SolanaPublicKey`: returns the Solana (Ed25519) public key of a vault key.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::PublicKey`](crate::DaemonRpcResponse::PublicKey) |
/// | Side effects | none; idempotent |
///
/// The Solana address is the base58 encoding of these 32 bytes.
///
/// **Errors:** admin-auth kinds, `UnknownVaultKey`, `Signer`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/SolanaPublicKey.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/SolanaPublicKey.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SolanaPublicKeyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Vault key whose Solana key to derive.
    pub vault_key_id: Uuid,
}

/// `RotateAgentAuthToken`: issues a new bearer token for an agent key.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::AuthToken`](crate::DaemonRpcResponse::AuthToken) |
/// | Side effects | persists the new token hash; the old token stops working |
/// | Idempotent | no: every call issues a new token |
///
/// **Errors:** admin-auth kinds, `UnknownAgentKey`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RotateAgentAuthToken.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RotateAgentAuthToken.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RotateAgentAuthTokenParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Agent key whose token to rotate.
    pub agent_key_id: Uuid,
}

/// `RevokeAgentKey`: deletes an agent key and everything tied to it.
///
/// | | |
/// |---|---|
/// | Access | admin allowlist |
/// | Auth | root peer or admin lease |
/// | Response | [`DaemonRpcResponse::Unit`](crate::DaemonRpcResponse::Unit) |
/// | Side effects | persists removal of the key, its token, spend history, nonce reservations, manual approval requests, and recoverable results |
/// | Idempotent | no: a second call fails with `UnknownAgentKey` |
///
/// **Errors:** admin-auth kinds, `UnknownAgentKey`, `Persistence`.
///
/// Request:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RevokeAgentKey.request.json")]
/// ```
///
/// Response:
///
/// ```json
#[doc = include_str!("../../fixtures/rpc/RevokeAgentKey.response.json")]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct RevokeAgentKeyParams {
    /// Admin authorization; `"peer_credentials"` when absent.
    #[serde(default)]
    pub auth: AdminAuth,
    /// Agent key to revoke.
    pub agent_key_id: Uuid,
}
