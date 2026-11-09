//! [`InMemoryDaemon::handle_rpc`]: dispatches a decoded [`DaemonRpcRequest`]
//! (the wire contract defined in `agentpay-api`) with the caller's transport
//! context.
//!
//! Secret-bearing request fields ([`agentpay_domain::AdminSession`] lease
//! secrets, agent tokens, imported keys) are [`zeroize::Zeroizing`] wrappers,
//! so they are wiped when each arm drops its bindings.

use agentpay_api::rpc::{
    AddPolicyParams, AgentActivityParams, AgentPolicySummaryParams, AuthenticateAgentParams,
    BeginAdminChallengeParams, BootstrapWalletParams, CompleteAdminChallengeParams,
    CreateAgentKeyParams, CreateVaultKeyParams, DecideManualApprovalRequestParams,
    DisablePolicyParams, EnrollAdminCredentialParams, EvaluateForAgentParams,
    ExplainForAgentParams, ExportWalletBackupParams, ListAdminCredentialsParams,
    ListManualApprovalRequestsParams, ListPoliciesParams, ListPolicySummariesParams,
    ListSpendingLimitsParams, ListWalletsParams, RefreshAgentKeyParams, ReleaseNonceParams,
    ReleaseSignedNonceParams, RenameWalletParams, ReserveNonceParams, RevokeAdminCredentialParams,
    RevokeAdminLeaseParams, RevokeAgentKeyParams, RotateAgentAuthTokenParams,
    SetSpendingLimitsParams, SignForAgentParams, SolanaPublicKeyParams, VerifyWalletBackupParams,
};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, HelloResponse};
use agentpay_signer::VaultSignerBackend;

use crate::{DaemonError, InMemoryDaemon, RequestContext};

/// Release version reported by the `Hello` handshake.
const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Returns the `Hello` handshake payload: API version, daemon release, and capabilities.
    #[must_use]
    pub fn hello(&self) -> HelloResponse {
        HelloResponse::for_daemon(DAEMON_VERSION)
    }

    /// Handles a serialized daemon RPC call on behalf of the caller described by `ctx`.
    ///
    /// Transports must build `ctx` from kernel-verified peer credentials; it
    /// decides whether [`agentpay_domain::AdminAuth::PeerCredentials`] is honored.
    pub async fn handle_rpc(
        &self,
        ctx: &RequestContext,
        request: DaemonRpcRequest,
    ) -> Result<DaemonRpcResponse, DaemonError> {
        use DaemonRpcRequest as Req;
        use DaemonRpcResponse as Res;
        match request {
            Req::Hello => Ok(Res::Hello(self.hello())),
            Req::EnrollAdminCredential(EnrollAdminCredentialParams {
                public_key_sec1_hex,
                label,
            }) => self
                .enroll_admin_credential_impl(ctx, &public_key_sec1_hex, &label)
                .await
                .map(Res::AdminCredential),
            Req::ListAdminCredentials(ListAdminCredentialsParams { auth }) => self
                .list_admin_credentials_impl(ctx, &auth)
                .map(Res::AdminCredentials),
            Req::RevokeAdminCredential(RevokeAdminCredentialParams { auth, id }) => self
                .revoke_admin_credential_impl(ctx, &auth, id)
                .await
                .map(|()| Res::Unit),
            Req::BeginAdminChallenge(BeginAdminChallengeParams {
                credential_id,
                purpose,
            }) => self
                .begin_admin_challenge_impl(ctx, credential_id, &purpose)
                .map(Res::AdminChallenge),
            Req::CompleteAdminChallenge(CompleteAdminChallengeParams {
                challenge_id,
                signature_der_hex,
            }) => self
                .complete_admin_challenge_impl(ctx, challenge_id, &signature_der_hex)
                .map(Res::AdminLease),
            Req::RevokeAdminLease(RevokeAdminLeaseParams { auth, lease_id }) => self
                .revoke_admin_lease_impl(ctx, &auth, lease_id)
                .map(|()| Res::Unit),
            Req::AddPolicy(AddPolicyParams { auth, policy }) => self
                .add_policy_impl(ctx, &auth, policy)
                .await
                .map(|()| Res::Unit),
            Req::ListPolicies(ListPoliciesParams { auth }) => {
                self.list_policies_impl(ctx, &auth).await.map(Res::Policies)
            }
            Req::ListPolicySummaries(ListPolicySummariesParams { auth }) => self
                .list_policy_summaries_impl(ctx, &auth)
                .await
                .map(Res::PolicySummaries),
            Req::DisablePolicy(DisablePolicyParams { auth, policy_id }) => self
                .disable_policy_impl(ctx, &auth, policy_id)
                .await
                .map(|()| Res::Unit),
            Req::CreateVaultKey(CreateVaultKeyParams { auth, request }) => self
                .create_vault_key_impl(ctx, &auth, request)
                .await
                .map(Res::VaultKey),
            Req::CreateAgentKey(CreateAgentKeyParams {
                auth,
                vault_key_id,
                attachment,
            }) => self
                .create_agent_key_impl(ctx, &auth, vault_key_id, attachment)
                .await
                .map(Res::AgentCredentials),
            Req::RefreshAgentKey(RefreshAgentKeyParams {
                auth,
                agent_key_id,
                vault_key_id,
                attachment,
            }) => self
                .refresh_agent_key_impl(ctx, &auth, agent_key_id, vault_key_id, attachment)
                .await
                .map(Res::AgentCredentials),
            Req::SolanaPublicKey(SolanaPublicKeyParams { auth, vault_key_id }) => self
                .solana_public_key_hex_impl(ctx, &auth, vault_key_id)
                .await
                .map(Res::PublicKey),
            Req::RotateAgentAuthToken(RotateAgentAuthTokenParams { auth, agent_key_id }) => self
                .rotate_agent_auth_token_impl(ctx, &auth, agent_key_id)
                .await
                .map(Res::AuthToken),
            Req::RevokeAgentKey(RevokeAgentKeyParams { auth, agent_key_id }) => self
                .revoke_agent_key_impl(ctx, &auth, agent_key_id)
                .await
                .map(|()| Res::Unit),
            Req::BootstrapWallet(BootstrapWalletParams { auth, mode, limits }) => self
                .bootstrap_wallet_impl(ctx, &auth, mode, limits)
                .await
                .map(|bootstrap| Res::WalletBootstrap(Box::new(bootstrap))),
            Req::ListWallets(ListWalletsParams { auth }) => {
                self.list_wallets_impl(ctx, &auth).map(Res::Wallets)
            }
            Req::RenameWallet(RenameWalletParams {
                auth,
                vault_key_id,
                name,
            }) => self
                .rename_wallet_impl(ctx, &auth, vault_key_id, name)
                .await
                .map(Res::Wallet),
            Req::ExportWalletBackup(ExportWalletBackupParams {
                auth,
                vault_key_id,
                passphrase,
            }) => self
                .export_wallet_backup_impl(ctx, &auth, vault_key_id, passphrase)
                .await
                .map(Res::WalletBackup),
            Req::VerifyWalletBackup(VerifyWalletBackupParams {
                auth,
                backup_json,
                passphrase,
            }) => self
                .verify_wallet_backup_impl(ctx, &auth, backup_json, passphrase)
                .await
                .map(Res::WalletBackupSummary),
            Req::ListSpendingLimits(ListSpendingLimitsParams { auth, agent_key_id }) => self
                .list_spending_limits_impl(ctx, &auth, agent_key_id)
                .map(Res::SpendingLimits),
            Req::SetSpendingLimits(SetSpendingLimitsParams {
                auth,
                agent_key_id,
                limits,
            }) => self
                .set_spending_limits_impl(ctx, &auth, agent_key_id, limits)
                .await
                .map(Res::SpendingLimits),
            Req::ListManualApprovalRequests(ListManualApprovalRequestsParams { auth }) => self
                .list_manual_approval_requests_impl(ctx, &auth)
                .await
                .map(Res::ManualApprovalRequests),
            Req::DecideManualApprovalRequest(DecideManualApprovalRequestParams {
                auth,
                approval_request_id,
                decision,
                rejection_reason,
            }) => self
                .decide_manual_approval_request_impl(
                    ctx,
                    &auth,
                    approval_request_id,
                    decision,
                    rejection_reason,
                )
                .await
                .map(|request| Res::ManualApprovalRequest(Box::new(request))),
            Req::AgentActivity(AgentActivityParams { auth, since, limit }) => self
                .agent_activity_impl(&auth, since, limit)
                .map(Res::AgentActivity),
            Req::AuthenticateAgent(AuthenticateAgentParams { auth }) => self
                .authenticate_agent_impl(&auth)
                .map(|identity| Res::AgentIdentity(Box::new(identity))),
            Req::AgentPolicySummary(AgentPolicySummaryParams { auth }) => self
                .agent_policy_summary_impl(&auth)
                .map(Res::AgentPolicySummary),
            Req::EvaluateForAgent(EvaluateForAgentParams { request }) => self
                .evaluate_for_agent_impl(request)
                .await
                .map(Res::PolicyEvaluation),
            Req::ExplainForAgent(ExplainForAgentParams { request }) => self
                .explain_for_agent_impl(request)
                .await
                .map(Res::PolicyExplanation),
            Req::ReserveNonce(ReserveNonceParams { request }) => self
                .reserve_nonce_impl(request)
                .await
                .map(Res::NonceReservation),
            Req::ReleaseNonce(ReleaseNonceParams { request }) => {
                self.release_nonce_impl(request).await.map(|()| Res::Unit)
            }
            Req::ReleaseSignedNonce(ReleaseSignedNonceParams { request }) => self
                .release_signed_nonce_impl(request)
                .await
                .map(|()| Res::Unit),
            Req::SignForAgent(SignForAgentParams { request }) => {
                self.sign_for_agent_impl(request).await.map(Res::Signature)
            }
        }
    }
}
