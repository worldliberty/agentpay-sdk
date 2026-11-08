//! `RecordingDaemon`: a `KeyManagerDaemonApi` test double that captures the
//! agent-side requests the SDK sends and fails every admin-only call.

use std::sync::Mutex;

use agentpay_api::rpc::{
    SpendingLimit, SpendingLimitsReport, WalletBackupExport, WalletBackupSummary, WalletBootstrap,
    WalletBootstrapMode, WalletInfo,
};
use agentpay_domain::{
    AdminAuth, AdminChallenge, AdminCredential, AdminLease, AgentAction, AgentCredentials,
    AgentKey, EntityScope, ManualApprovalDecision, ManualApprovalRequest, NonceReleaseRequest,
    NonceReservation, NonceReservationRequest, PolicyAttachment, SignRequest, Signature,
    SignedNonceReleaseRequest, SpendingPolicy, VaultKey,
};
use agentpay_policy::PolicyEvaluation;
use agentpay_signer::KeyCreateRequest;
use agentpay_signerd::{DaemonError, KeyManagerDaemonApi, PolicySummary};
use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct RecordingDaemon {
    pub(super) request: Mutex<Option<SignRequest>>,
    pub(super) nonce_request: Mutex<Option<NonceReservationRequest>>,
    pub(super) released_reservation: Mutex<Option<Uuid>>,
    pub(super) fail_sign: bool,
    pub(super) reserved_nonce_override: Option<u64>,
}

#[async_trait]
impl KeyManagerDaemonApi for RecordingDaemon {
    async fn enroll_admin_credential(
        &self,
        _public_key_sec1_hex: String,
        _label: String,
    ) -> Result<AdminCredential, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn list_admin_credentials(
        &self,
        _auth: &AdminAuth,
    ) -> Result<Vec<AdminCredential>, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn revoke_admin_credential(
        &self,
        _auth: &AdminAuth,
        _credential_id: Uuid,
    ) -> Result<(), DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn begin_admin_challenge(
        &self,
        _credential_id: Uuid,
        _purpose: String,
    ) -> Result<AdminChallenge, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn complete_admin_challenge(
        &self,
        _challenge_id: Uuid,
        _signature_der_hex: String,
    ) -> Result<AdminLease, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn revoke_admin_lease(
        &self,
        _auth: &AdminAuth,
        _lease_id: Uuid,
    ) -> Result<(), DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn add_policy(
        &self,
        _auth: &AdminAuth,
        _policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn list_policies(&self, _auth: &AdminAuth) -> Result<Vec<SpendingPolicy>, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn list_policy_summaries(
        &self,
        _auth: &AdminAuth,
    ) -> Result<Vec<PolicySummary>, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn disable_policy(&self, _auth: &AdminAuth, _policy_id: Uuid) -> Result<(), DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn create_vault_key(
        &self,
        _auth: &AdminAuth,
        _request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn bootstrap_wallet(
        &self,
        _auth: &AdminAuth,
        _mode: WalletBootstrapMode,
        _limits: Vec<SpendingLimit>,
    ) -> Result<WalletBootstrap, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn list_wallets(&self, _auth: &AdminAuth) -> Result<Vec<WalletInfo>, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn rename_wallet(
        &self,
        _auth: &AdminAuth,
        _vault_key_id: Uuid,
        _name: Option<String>,
    ) -> Result<WalletInfo, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn export_wallet_backup(
        &self,
        _auth: &AdminAuth,
        _vault_key_id: Option<Uuid>,
        _passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupExport, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn verify_wallet_backup(
        &self,
        _auth: &AdminAuth,
        _backup_json: String,
        _passphrase: Zeroizing<String>,
    ) -> Result<WalletBackupSummary, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn list_spending_limits(
        &self,
        _auth: &AdminAuth,
        _agent_key_id: Uuid,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn set_spending_limits(
        &self,
        _auth: &AdminAuth,
        _agent_key_id: Uuid,
        _limits: Vec<SpendingLimit>,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn solana_public_key_hex(
        &self,
        _auth: &AdminAuth,
        _vault_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn create_agent_key(
        &self,
        _auth: &AdminAuth,
        _vault_key_id: Uuid,
        _attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn refresh_agent_key(
        &self,
        _auth: &AdminAuth,
        _agent_key_id: Uuid,
        _vault_key_id: Uuid,
        _attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn rotate_agent_auth_token(
        &self,
        _auth: &AdminAuth,
        _agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn revoke_agent_key(
        &self,
        _auth: &AdminAuth,
        _agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn list_manual_approval_requests(
        &self,
        _auth: &AdminAuth,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn decide_manual_approval_request(
        &self,
        _auth: &AdminAuth,
        _approval_request_id: Uuid,
        _decision: ManualApprovalDecision,
        _rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn authenticate_agent(
        &self,
        _auth: &agentpay_signerd::AgentAuth,
    ) -> Result<agentpay_signerd::AgentIdentity, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn evaluate_for_agent(
        &self,
        _request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn explain_for_agent(
        &self,
        _request: SignRequest,
    ) -> Result<agentpay_policy::PolicyExplanation, DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError> {
        *self.nonce_request.lock().expect("lock") = Some(request.clone());
        Ok(NonceReservation {
            reservation_id: Uuid::new_v4(),
            agent_key_id: request.agent_key_id,
            vault_key_id: Uuid::new_v4(),
            chain_id: request.chain_id,
            nonce: self.reserved_nonce_override.unwrap_or(request.min_nonce),
            issued_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
    }

    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError> {
        *self.released_reservation.lock().expect("lock") = Some(request.reservation_id);
        Ok(())
    }

    async fn release_signed_nonce(
        &self,
        _request: SignedNonceReleaseRequest,
    ) -> Result<(), DaemonError> {
        Err(DaemonError::Transport("not used".to_string()))
    }

    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError> {
        *self.request.lock().expect("lock") = Some(request);
        if self.fail_sign {
            return Err(DaemonError::AgentAuthenticationFailed);
        }
        Ok(Signature::from_der(vec![0x11, 0x22]))
    }
}

pub(super) fn test_credentials() -> AgentCredentials {
    AgentCredentials {
        agent_key: AgentKey {
            id: Uuid::new_v4(),
            vault_key_id: Uuid::new_v4(),
            policies: PolicyAttachment::AllPolicies,
            created_at: OffsetDateTime::now_utc(),
        },
        auth_token: "agent-secret-token".to_string().into(),
    }
}

fn sample_admin_session() -> AdminAuth {
    AdminAuth::PeerCredentials
}

fn sample_policy() -> SpendingPolicy {
    SpendingPolicy::new(
        0,
        agentpay_domain::PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

fn sample_sign_request() -> SignRequest {
    SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "agent-secret-token".to_string().into(),
        payload: br#"{"kind":"transfer_native"}"#.to_vec(),
        action: AgentAction::TransferNative {
            chain_id: 1,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("to"),
            amount_wei: 1,
        },
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2),
    }
}

fn sample_nonce_release_request() -> NonceReleaseRequest {
    NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "agent-secret-token".to_string().into(),
        reservation_id: Uuid::new_v4(),
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2),
    }
}

fn sample_nonce_reservation_request() -> NonceReservationRequest {
    NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "agent-secret-token".to_string().into(),
        chain_id: 1,
        min_nonce: 7,
        exact_nonce: false,
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2),
    }
}

#[tokio::test]
async fn recording_daemon_not_used_paths_return_transport_errors() {
    let daemon = RecordingDaemon::default();
    let session = sample_admin_session();
    let policy = sample_policy();
    let request = sample_sign_request();
    let reservation_request = sample_nonce_reservation_request();
    let release_request = sample_nonce_release_request();

    assert!(matches!(
        daemon
            .enroll_admin_credential("02".repeat(33), "Mac".to_string())
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.list_admin_credentials(&session).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.revoke_admin_credential(&session, Uuid::new_v4()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon
            .begin_admin_challenge(Uuid::new_v4(), "admin-session".to_string())
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon
            .complete_admin_challenge(Uuid::new_v4(), "00".to_string())
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.revoke_admin_lease(&session, Uuid::new_v4()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.add_policy(&session, policy.clone()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.list_policies(&session).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.disable_policy(&session, Uuid::new_v4()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon
            .create_vault_key(&session, KeyCreateRequest::Generate)
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon
            .export_wallet_backup(&session, None, String::new().into())
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.list_spending_limits(&session, Uuid::new_v4()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon
            .create_agent_key(&session, Uuid::new_v4(), PolicyAttachment::AllPolicies)
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.rotate_agent_auth_token(&session, Uuid::new_v4()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.revoke_agent_key(&session, Uuid::new_v4()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.list_manual_approval_requests(&session).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon
            .decide_manual_approval_request(
                &session,
                Uuid::new_v4(),
                ManualApprovalDecision::Approve,
                None
            )
            .await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.evaluate_for_agent(request.clone()).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));
    assert!(matches!(
        daemon.explain_for_agent(request).await,
        Err(DaemonError::Transport(message)) if message == "not used"
    ));

    let reservation = daemon
        .reserve_nonce(reservation_request.clone())
        .await
        .expect("reserve nonce");
    assert_eq!(reservation.chain_id, reservation_request.chain_id);
    assert_eq!(reservation.nonce, reservation_request.min_nonce);
    assert_eq!(
        daemon
            .nonce_request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured nonce request")
            .exact_nonce,
        reservation_request.exact_nonce
    );
    daemon
        .release_nonce(release_request)
        .await
        .expect("release nonce");
}
