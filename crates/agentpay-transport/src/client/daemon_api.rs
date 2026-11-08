//! [`KeyManagerDaemonApi`] implementation that forwards each call over the socket.

use agentpay_api::rpc::{
    AddPolicyParams, AuthenticateAgentParams, BeginAdminChallengeParams, BootstrapWalletParams,
    CompleteAdminChallengeParams, CreateAgentKeyParams, CreateVaultKeyParams,
    DecideManualApprovalRequestParams, DisablePolicyParams, EnrollAdminCredentialParams,
    EvaluateForAgentParams, ExplainForAgentParams, ExportWalletBackupParams,
    ListAdminCredentialsParams, ListManualApprovalRequestsParams, ListPoliciesParams,
    ListPolicySummariesParams, ListSpendingLimitsParams, ListWalletsParams, RefreshAgentKeyParams,
    ReleaseNonceParams, ReleaseSignedNonceParams, RenameWalletParams, ReserveNonceParams,
    RevokeAdminCredentialParams, RevokeAdminLeaseParams, RevokeAgentKeyParams,
    RotateAgentAuthTokenParams, SetSpendingLimitsParams, SignForAgentParams, SolanaPublicKeyParams,
    SpendingLimit, SpendingLimitsReport, VerifyWalletBackupParams, WalletBackupExport,
    WalletBackupSummary, WalletBootstrap, WalletBootstrapMode, WalletInfo,
};
use agentpay_api::{AgentAuth, AgentIdentity, DaemonRpcRequest, DaemonRpcResponse, PolicySummary};
use agentpay_domain::{
    AdminAuth, AdminChallenge, AdminCredential, AdminLease, AgentCredentials,
    ManualApprovalDecision, ManualApprovalRequest, NonceReleaseRequest, NonceReservation,
    NonceReservationRequest, PolicyAttachment, SignRequest, Signature, SignedNonceReleaseRequest,
    SpendingPolicy, VaultKey,
};
use agentpay_policy::{PolicyEvaluation, PolicyExplanation};
use agentpay_signer::KeyCreateRequest;
use agentpay_signerd::{DaemonError, KeyManagerDaemonApi};
use async_trait::async_trait;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::UnixDaemonClient;

#[async_trait]
impl KeyManagerDaemonApi for UnixDaemonClient {
    async fn enroll_admin_credential(
        &self,
        public_key_sec1_hex: String,
        label: String,
    ) -> Result<AdminCredential, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::EnrollAdminCredential(EnrollAdminCredentialParams {
                public_key_sec1_hex,
                label,
            }),
            |response| match response {
                DaemonRpcResponse::AdminCredential(credential) => Some(credential),
                _ => None,
            },
        )
        .await
    }

    async fn list_admin_credentials(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<AdminCredential>, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ListAdminCredentials(ListAdminCredentialsParams {
                auth: auth.clone(),
            }),
            |response| match response {
                DaemonRpcResponse::AdminCredentials(credentials) => Some(credentials),
                _ => None,
            },
        )
        .await
    }

    async fn revoke_admin_credential(
        &self,
        auth: &AdminAuth,
        credential_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::RevokeAdminCredential(RevokeAdminCredentialParams {
                auth: auth.clone(),
                id: credential_id,
            }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn begin_admin_challenge(
        &self,
        credential_id: Uuid,
        purpose: String,
    ) -> Result<AdminChallenge, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::BeginAdminChallenge(BeginAdminChallengeParams {
                credential_id,
                purpose,
            }),
            |response| match response {
                DaemonRpcResponse::AdminChallenge(challenge) => Some(challenge),
                _ => None,
            },
        )
        .await
    }

    async fn complete_admin_challenge(
        &self,
        challenge_id: Uuid,
        signature_der_hex: String,
    ) -> Result<AdminLease, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::CompleteAdminChallenge(CompleteAdminChallengeParams {
                challenge_id,
                signature_der_hex,
            }),
            |response| match response {
                DaemonRpcResponse::AdminLease(lease) => Some(lease),
                _ => None,
            },
        )
        .await
    }

    async fn revoke_admin_lease(
        &self,
        auth: &AdminAuth,
        lease_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::RevokeAdminLease(RevokeAdminLeaseParams {
                auth: auth.clone(),
                lease_id,
            }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn add_policy(
        &self,
        auth: &AdminAuth,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::AddPolicy(AddPolicyParams {
                auth: auth.clone(),
                policy,
            }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn list_policies(&self, auth: &AdminAuth) -> Result<Vec<SpendingPolicy>, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ListPolicies(ListPoliciesParams { auth: auth.clone() }),
            |response| match response {
                DaemonRpcResponse::Policies(policies) => Some(policies),
                _ => None,
            },
        )
        .await
    }

    async fn list_policy_summaries(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<PolicySummary>, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ListPolicySummaries(ListPolicySummariesParams { auth: auth.clone() }),
            |response| match response {
                DaemonRpcResponse::PolicySummaries(summaries) => Some(summaries),
                _ => None,
            },
        )
        .await
    }

    async fn disable_policy(&self, auth: &AdminAuth, policy_id: Uuid) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::DisablePolicy(DisablePolicyParams {
                auth: auth.clone(),
                policy_id,
            }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn create_vault_key(
        &self,
        auth: &AdminAuth,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::CreateVaultKey(CreateVaultKeyParams {
                auth: auth.clone(),
                request,
            }),
            |response| match response {
                DaemonRpcResponse::VaultKey(key) => Some(key),
                _ => None,
            },
        )
        .await
    }

    async fn create_agent_key(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::CreateAgentKey(CreateAgentKeyParams {
                auth: auth.clone(),
                vault_key_id,
                attachment,
            }),
            |response| match response {
                DaemonRpcResponse::AgentCredentials(agent_credentials) => Some(agent_credentials),
                _ => None,
            },
        )
        .await
    }

    async fn refresh_agent_key(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::RefreshAgentKey(RefreshAgentKeyParams {
                auth: auth.clone(),
                agent_key_id,
                vault_key_id,
                attachment,
            }),
            |response| match response {
                DaemonRpcResponse::AgentCredentials(agent_credentials) => Some(agent_credentials),
                _ => None,
            },
        )
        .await
    }

    async fn bootstrap_wallet(
        &self,
        auth: &AdminAuth,
        mode: WalletBootstrapMode,
        limits: Vec<SpendingLimit>,
    ) -> Result<WalletBootstrap, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::BootstrapWallet(BootstrapWalletParams {
                auth: auth.clone(),
                mode,
                limits,
            }),
            |response| match response {
                DaemonRpcResponse::WalletBootstrap(bootstrap) => Some(*bootstrap),
                _ => None,
            },
        )
        .await
    }

    async fn list_wallets(&self, auth: &AdminAuth) -> Result<Vec<WalletInfo>, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ListWallets(ListWalletsParams { auth: auth.clone() }),
            |response| match response {
                DaemonRpcResponse::Wallets(wallets) => Some(wallets),
                _ => None,
            },
        )
        .await
    }

    async fn rename_wallet(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
        name: Option<String>,
    ) -> Result<WalletInfo, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::RenameWallet(RenameWalletParams {
                auth: auth.clone(),
                vault_key_id,
                name,
            }),
            |response| match response {
                DaemonRpcResponse::Wallet(wallet) => Some(wallet),
                _ => None,
            },
        )
        .await
    }

    async fn export_wallet_backup(
        &self,
        auth: &AdminAuth,
        vault_key_id: Option<Uuid>,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupExport, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ExportWalletBackup(ExportWalletBackupParams {
                auth: auth.clone(),
                vault_key_id,
                passphrase,
            }),
            |response| match response {
                DaemonRpcResponse::WalletBackup(backup) => Some(backup),
                _ => None,
            },
        )
        .await
    }

    async fn verify_wallet_backup(
        &self,
        auth: &AdminAuth,
        backup_json: String,
        passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupSummary, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::VerifyWalletBackup(VerifyWalletBackupParams {
                auth: auth.clone(),
                backup_json,
                passphrase,
            }),
            |response| match response {
                DaemonRpcResponse::WalletBackupSummary(summary) => Some(summary),
                _ => None,
            },
        )
        .await
    }

    async fn list_spending_limits(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ListSpendingLimits(ListSpendingLimitsParams {
                auth: auth.clone(),
                agent_key_id,
            }),
            |response| match response {
                DaemonRpcResponse::SpendingLimits(report) => Some(report),
                _ => None,
            },
        )
        .await
    }

    async fn set_spending_limits(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        limits: Vec<SpendingLimit>,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::SetSpendingLimits(SetSpendingLimitsParams {
                auth: auth.clone(),
                agent_key_id,
                limits,
            }),
            |response| match response {
                DaemonRpcResponse::SpendingLimits(report) => Some(report),
                _ => None,
            },
        )
        .await
    }

    async fn solana_public_key_hex(
        &self,
        auth: &AdminAuth,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::SolanaPublicKey(SolanaPublicKeyParams {
                auth: auth.clone(),
                vault_key_id,
            }),
            |response| match response {
                DaemonRpcResponse::PublicKey(public_key) => Some(public_key),
                _ => None,
            },
        )
        .await
    }

    async fn rotate_agent_auth_token(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::RotateAgentAuthToken(RotateAgentAuthTokenParams {
                auth: auth.clone(),
                agent_key_id,
            }),
            |response| match response {
                DaemonRpcResponse::AuthToken(token) => Some(token),
                _ => None,
            },
        )
        .await
    }

    async fn revoke_agent_key(
        &self,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::RevokeAgentKey(RevokeAgentKeyParams {
                auth: auth.clone(),
                agent_key_id,
            }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn list_manual_approval_requests(
        &self,
        auth: &AdminAuth,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ListManualApprovalRequests(ListManualApprovalRequestsParams {
                auth: auth.clone(),
            }),
            |response| match response {
                DaemonRpcResponse::ManualApprovalRequests(requests) => Some(requests),
                _ => None,
            },
        )
        .await
    }

    async fn decide_manual_approval_request(
        &self,
        auth: &AdminAuth,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::DecideManualApprovalRequest(DecideManualApprovalRequestParams {
                auth: auth.clone(),
                approval_request_id,
                decision,
                rejection_reason,
            }),
            |response| match response {
                DaemonRpcResponse::ManualApprovalRequest(request) => Some(*request),
                _ => None,
            },
        )
        .await
    }

    async fn authenticate_agent(&self, auth: &AgentAuth) -> Result<AgentIdentity, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::AuthenticateAgent(AuthenticateAgentParams { auth: auth.clone() }),
            |response| match response {
                DaemonRpcResponse::AgentIdentity(identity) => Some(*identity),
                _ => None,
            },
        )
        .await
    }

    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::EvaluateForAgent(EvaluateForAgentParams { request }),
            |response| match response {
                DaemonRpcResponse::PolicyEvaluation(evaluation) => Some(evaluation),
                _ => None,
            },
        )
        .await
    }

    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ExplainForAgent(ExplainForAgentParams { request }),
            |response| match response {
                DaemonRpcResponse::PolicyExplanation(explanation) => Some(explanation),
                _ => None,
            },
        )
        .await
    }

    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ReserveNonce(ReserveNonceParams { request }),
            |response| match response {
                DaemonRpcResponse::NonceReservation(reservation) => Some(reservation),
                _ => None,
            },
        )
        .await
    }

    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ReleaseNonce(ReleaseNonceParams { request }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn release_signed_nonce(
        &self,
        request: SignedNonceReleaseRequest,
    ) -> Result<(), DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::ReleaseSignedNonce(ReleaseSignedNonceParams { request }),
            |response| match response {
                DaemonRpcResponse::Unit => Some(()),
                _ => None,
            },
        )
        .await
    }

    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError> {
        self.call_expecting(
            DaemonRpcRequest::SignForAgent(SignForAgentParams { request }),
            |response| match response {
                DaemonRpcResponse::Signature(sig) => Some(sig),
                _ => None,
            },
        )
        .await
    }
}
