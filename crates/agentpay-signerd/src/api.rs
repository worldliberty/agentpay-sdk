//! The transport-neutral [`KeyManagerDaemonApi`] trait implemented by the daemon and its
//! remote clients.

use agentpay_api::rpc::{
    SpendingLimit, SpendingLimitsReport, WalletBackupExport, WalletBackupSummary, WalletBootstrap,
    WalletBootstrapMode, WalletInfo,
};
use agentpay_api::{AgentAuth, AgentIdentity, PolicySummary};
use agentpay_domain::{
    AdminAuth, AdminChallenge, AdminCredential, AdminLease, AgentCredentials,
    ManualApprovalDecision, ManualApprovalRequest, NonceReleaseRequest, NonceReservation,
    NonceReservationRequest, PolicyAttachment, SignRequest, Signature, SignedNonceReleaseRequest,
    SpendingPolicy, VaultKey,
};
use agentpay_policy::{PolicyEvaluation, PolicyExplanation};
use agentpay_signer::KeyCreateRequest;
use async_trait::async_trait;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::DaemonError;

/// Transport-neutral daemon API.
///
/// Privileged methods take an [`AdminAuth`]: either
/// [`AdminAuth::PeerCredentials`] (honored only for root peers and in-process
/// callers) or an [`AdminAuth::Lease`] obtained through
/// [`begin_admin_challenge`](Self::begin_admin_challenge) and
/// [`complete_admin_challenge`](Self::complete_admin_challenge).
// `async_trait` marks each generated method `#[must_use]` on top of the boxed
// future it returns, which newer clippy reports as `double_must_use`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait KeyManagerDaemonApi: Send + Sync {
    /// Enrolls a P-256 admin credential (SEC1 public key, hex). Root peers only.
    async fn enroll_admin_credential(
        &self,
        public_key_sec1_hex: String,
        label: String,
    ) -> Result<AdminCredential, DaemonError>;

    /// Lists enrolled admin credentials, oldest first.
    async fn list_admin_credentials(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<AdminCredential>, DaemonError>;

    /// Revokes an admin credential and every lease and challenge issued for it.
    async fn revoke_admin_credential(
        &self,
        auth: &AdminAuth,
        credential_id: Uuid,
    ) -> Result<(), DaemonError>;

    /// Issues a single-use challenge (2-minute TTL by default) for `credential_id`.
    ///
    /// `purpose` is a short identifier of the intended operation (for example
    /// `admin-session`) that is embedded in the signed message.
    async fn begin_admin_challenge(
        &self,
        credential_id: Uuid,
        purpose: String,
    ) -> Result<AdminChallenge, DaemonError>;

    /// Exchanges a DER P-256 signature over the challenge message for an admin lease.
    ///
    /// The challenge is consumed whether or not the signature verifies; failed
    /// signatures count toward the credential's temporary lockout.
    async fn complete_admin_challenge(
        &self,
        challenge_id: Uuid,
        signature_der_hex: String,
    ) -> Result<AdminLease, DaemonError>;

    /// Revokes an admin lease before it expires.
    async fn revoke_admin_lease(&self, auth: &AdminAuth, lease_id: Uuid)
        -> Result<(), DaemonError>;

    /// Adds a policy; an existing `policy.id` is rejected with `InvalidPolicy`.
    ///
    /// Existing `PolicyAttachment::PolicySet` agent keys are left unchanged.
    /// New policy ids must be attached explicitly when the agent key is
    /// created.
    async fn add_policy(&self, auth: &AdminAuth, policy: SpendingPolicy)
        -> Result<(), DaemonError>;

    /// Lists all policies ordered by priority for an authenticated admin session.
    async fn list_policies(&self, auth: &AdminAuth) -> Result<Vec<SpendingPolicy>, DaemonError>;

    /// Lists compact policy metadata for callers that only need ids and enabled state.
    async fn list_policy_summaries(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<PolicySummary>, DaemonError>;

    /// Disables a policy by id.
    ///
    /// Disabled policies remain listed but are ignored during evaluation.
    async fn disable_policy(&self, auth: &AdminAuth, policy_id: Uuid) -> Result<(), DaemonError>;

    /// Creates a vault key through configured signer backend.
    async fn create_vault_key(
        &self,
        auth: &AdminAuth,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError>;

    /// Returns the Solana Ed25519 public key derived for a vault key.
    async fn solana_public_key_hex(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError>;

    /// Creates an agent key attached to all policies or a selected subset.
    ///
    /// `PolicyAttachment::PolicySet` is a static attachment snapshot. Later
    /// `add_policy` calls must not change existing `PolicySet` memberships.
    ///
    /// Returns an auth token that must be sent with each agent sign request.
    async fn create_agent_key(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError>;

    /// Replaces policy attachment on an existing agent key and rotates its auth token.
    ///
    /// The target agent key must already belong to `vault_key_id`.
    async fn refresh_agent_key(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError>;

    /// Rotates the bearer token for an existing agent key.
    ///
    /// Returns the newly issued token.
    async fn rotate_agent_auth_token(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError>;

    /// Revokes an agent key and its auth token.
    async fn revoke_agent_key(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError>;

    /// Sets up the wallet key, its agent key, and the agent's spending limits
    /// in one atomic step (`BootstrapWallet`).
    async fn bootstrap_wallet(
        &self,
        auth: &AdminAuth,
        mode: WalletBootstrapMode,
        limits: Vec<SpendingLimit>,
    ) -> Result<WalletBootstrap, DaemonError>;

    /// Lists every wallet (vault key) with its addresses and agent keys,
    /// oldest first (`ListWallets`). Public metadata only.
    async fn list_wallets(&self, auth: &AdminAuth) -> Result<Vec<WalletInfo>, DaemonError>;

    /// Sets or (with `None`) clears a wallet's display name (`RenameWallet`).
    async fn rename_wallet(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        name: Option<String>,
    ) -> Result<WalletInfo, DaemonError>;

    /// Encrypts the wallet key under `passphrase` (at least 12 characters)
    /// and returns the backup document; the key never leaves the daemon in
    /// the clear.
    async fn export_wallet_backup(
        &self,
        auth: &AdminAuth,
        vault_key_id: Option<Uuid>,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupExport, DaemonError>;

    /// Decrypts a backup document and reports what it holds, changing nothing.
    async fn verify_wallet_backup(
        &self,
        auth: &AdminAuth,
        backup_json: String,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupSummary, DaemonError>;

    /// Lists an agent's spending limit rows with their usage.
    async fn list_spending_limits(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<SpendingLimitsReport, DaemonError>;

    /// Replaces an agent's spending limits atomically (deny by default).
    async fn set_spending_limits(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        limits: Vec<SpendingLimit>,
    ) -> Result<SpendingLimitsReport, DaemonError>;

    /// Lists manual approval requests for an authenticated admin session.
    async fn list_manual_approval_requests(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError>;

    /// Applies an approval or rejection decision to a pending approval request.
    async fn decide_manual_approval_request(
        &self,
        auth: &AdminAuth,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError>;

    /// Verifies agent credentials and returns the agent's identity and wallet
    /// addresses. No side effects.
    async fn authenticate_agent(&self, auth: &AgentAuth) -> Result<AgentIdentity, DaemonError>;

    /// Evaluates an agent request against current policy state without signing
    /// or recording spend.
    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError>;

    /// Returns an explanation for policy evaluation without signing or spend mutation.
    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError>;

    /// Reserves a unique nonce for a future broadcast transaction.
    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError>;

    /// Releases a previously reserved nonce lease.
    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError>;

    /// Returns the nonce of a signed `BroadcastTx` whose transaction provably
    /// never reached the network. Only for definitive pre-submission failures.
    async fn release_signed_nonce(
        &self,
        request: SignedNonceReleaseRequest,
    ) -> Result<(), DaemonError>;

    /// Evaluates policy and signs payload on success.
    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError>;
}
