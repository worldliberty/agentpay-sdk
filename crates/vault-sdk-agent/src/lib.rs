//! Agent-side SDK for daemon-mediated token operations.

#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vault_daemon::{DaemonError, KeyManagerDaemonApi};
use vault_domain::{
    action_from_erc20_calldata, AgentAction, AgentCredentials, BroadcastTx, DomainError,
    Eip3009Transfer, EvmAddress, NonceReleaseRequest, NonceReservation, NonceReservationRequest,
    Permit2Permit, SignRequest, Signature, TempoSessionOpenTransaction,
    TempoSessionTopUpTransaction, TempoSessionVoucher,
};
use zeroize::Zeroizing;

/// Errors returned by the Agentic SDK.
#[derive(Debug, Error)]
pub enum AgentSdkError {
    /// Upstream daemon call failed.
    #[error("daemon call failed: {0}")]
    Daemon(#[from] DaemonError),
    /// Invalid action payload.
    #[error("invalid action: {0}")]
    Domain(#[from] DomainError),
    /// Failed to serialize action payload for daemon verification.
    #[error("failed to serialize action payload: {0}")]
    Serialization(String),
}

/// High-level agent operations.
#[async_trait]
pub trait AgentOperations: Send + Sync {
    /// Requests an ERC-20 `approve` signature.
    async fn approve(
        &self,
        chain_id: u64,
        token: EvmAddress,
        spender: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests an ERC-20 `transfer` signature.
    async fn transfer(
        &self,
        chain_id: u64,
        token: EvmAddress,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a native ETH transfer signature.
    async fn transfer_native(
        &self,
        chain_id: u64,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Permit2 `PermitSingle` signature.
    async fn permit2_permit(&self, permit: Permit2Permit) -> Result<Signature, AgentSdkError>;

    /// Requests an EIP-3009 `transferWithAuthorization` signature.
    async fn eip3009_transfer_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests an EIP-3009 `receiveWithAuthorization` signature.
    async fn eip3009_receive_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo session open-transaction digest signature.
    async fn tempo_session_open_transaction(
        &self,
        authorization: TempoSessionOpenTransaction,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo session top-up transaction digest signature.
    async fn tempo_session_top_up_transaction(
        &self,
        authorization: TempoSessionTopUpTransaction,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests a Tempo session voucher digest signature.
    async fn tempo_session_voucher(
        &self,
        authorization: TempoSessionVoucher,
    ) -> Result<Signature, AgentSdkError>;

    /// Parses ERC-20 calldata and signs derived action (`approve` / `transfer`).
    async fn sign_erc20_calldata(
        &self,
        chain_id: u64,
        token: EvmAddress,
        calldata: Vec<u8>,
    ) -> Result<Signature, AgentSdkError>;

    /// Requests signature authorization for a raw broadcast transaction.
    async fn broadcast_tx(&self, tx: BroadcastTx) -> Result<Signature, AgentSdkError>;

    /// Reserves a nonce lease for a future broadcast transaction.
    async fn reserve_broadcast_nonce(
        &self,
        chain_id: u64,
        nonce: u64,
    ) -> Result<NonceReservation, AgentSdkError>;

    /// Explicitly releases an unused nonce reservation.
    async fn release_broadcast_nonce(
        &self,
        reservation_id: uuid::Uuid,
    ) -> Result<(), AgentSdkError>;
}

/// Default SDK implementation backed by a daemon API client.
pub struct AgentSdk<D>
where
    D: KeyManagerDaemonApi + ?Sized,
{
    daemon: Arc<D>,
    agent_key_id: Uuid,
    agent_auth_token: Zeroizing<String>,
}

impl<D> AgentSdk<D>
where
    D: KeyManagerDaemonApi + ?Sized,
{
    const REQUEST_TTL: Duration = Duration::minutes(2);

    /// Creates SDK bound to agent credentials.
    #[must_use]
    pub fn new(daemon: Arc<D>, agent_credentials: AgentCredentials) -> Self {
        Self {
            daemon,
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
        }
    }

    /// Creates SDK from raw agent key id and auth token.
    ///
    /// This constructor is useful for CLIs and integrations where only the
    /// stable key id + bearer token are persisted.
    #[must_use]
    pub fn new_with_key_id_and_token<T>(
        daemon: Arc<D>,
        agent_key_id: Uuid,
        agent_auth_token: T,
    ) -> Self
    where
        T: Into<Zeroizing<String>>,
    {
        Self {
            daemon,
            agent_key_id,
            agent_auth_token: agent_auth_token.into(),
        }
    }

    async fn sign_action(&self, action: AgentAction) -> Result<Signature, AgentSdkError> {
        action.validate()?;
        let now = OffsetDateTime::now_utc();
        let payload = serde_json::to_vec(&action)
            .map_err(|err| AgentSdkError::Serialization(err.to_string()))?;
        let request = SignRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: self.agent_key_id,
            agent_auth_token: self.agent_auth_token.clone(),
            payload,
            action,
            requested_at: now,
            expires_at: now + Self::REQUEST_TTL,
        };

        Ok(self.daemon.sign_for_agent(request).await?)
    }
}

#[async_trait]
impl<D> AgentOperations for AgentSdk<D>
where
    D: KeyManagerDaemonApi + ?Sized,
{
    async fn approve(
        &self,
        chain_id: u64,
        token: EvmAddress,
        spender: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Approve {
            chain_id,
            token,
            spender,
            amount_wei,
        })
        .await
    }

    async fn transfer(
        &self,
        chain_id: u64,
        token: EvmAddress,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Transfer {
            chain_id,
            token,
            to,
            amount_wei,
        })
        .await
    }

    async fn transfer_native(
        &self,
        chain_id: u64,
        to: EvmAddress,
        amount_wei: u128,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TransferNative {
            chain_id,
            to,
            amount_wei,
        })
        .await
    }

    async fn permit2_permit(&self, permit: Permit2Permit) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Permit2Permit { permit })
            .await
    }

    async fn eip3009_transfer_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Eip3009TransferWithAuthorization { authorization })
            .await
    }

    async fn eip3009_receive_with_authorization(
        &self,
        authorization: Eip3009Transfer,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::Eip3009ReceiveWithAuthorization { authorization })
            .await
    }

    async fn tempo_session_open_transaction(
        &self,
        authorization: TempoSessionOpenTransaction,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionOpenTransaction { authorization })
            .await
    }

    async fn tempo_session_top_up_transaction(
        &self,
        authorization: TempoSessionTopUpTransaction,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionTopUpTransaction { authorization })
            .await
    }

    async fn tempo_session_voucher(
        &self,
        authorization: TempoSessionVoucher,
    ) -> Result<Signature, AgentSdkError> {
        self.sign_action(AgentAction::TempoSessionVoucher { authorization })
            .await
    }

    async fn sign_erc20_calldata(
        &self,
        chain_id: u64,
        token: EvmAddress,
        calldata: Vec<u8>,
    ) -> Result<Signature, AgentSdkError> {
        let action = action_from_erc20_calldata(chain_id, token, &calldata)?;
        self.sign_action(action).await
    }

    async fn broadcast_tx(&self, mut tx: BroadcastTx) -> Result<Signature, AgentSdkError> {
        let requested_nonce = tx.nonce;
        let reservation = self
            .reserve_broadcast_nonce(tx.chain_id, requested_nonce)
            .await?;
        if reservation.nonce != requested_nonce {
            let _ = self
                .release_broadcast_nonce(reservation.reservation_id)
                .await;
            return Err(AgentSdkError::Daemon(DaemonError::InvalidNonceReservation(
                format!(
                    "requested exact nonce {requested_nonce} for chain_id {} but daemon reserved {}",
                    tx.chain_id, reservation.nonce
                ),
            )));
        }
        tx.nonce = reservation.nonce;

        match self.sign_action(AgentAction::BroadcastTx { tx }).await {
            Ok(signature) => Ok(signature),
            Err(err) => {
                let _ = self
                    .release_broadcast_nonce(reservation.reservation_id)
                    .await;
                Err(err)
            }
        }
    }

    async fn reserve_broadcast_nonce(
        &self,
        chain_id: u64,
        nonce: u64,
    ) -> Result<NonceReservation, AgentSdkError> {
        let now = OffsetDateTime::now_utc();
        let request = NonceReservationRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: self.agent_key_id,
            agent_auth_token: self.agent_auth_token.clone(),
            chain_id,
            min_nonce: nonce,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + Self::REQUEST_TTL,
        };
        Ok(self.daemon.reserve_nonce(request).await?)
    }

    async fn release_broadcast_nonce(
        &self,
        reservation_id: uuid::Uuid,
    ) -> Result<(), AgentSdkError> {
        let now = OffsetDateTime::now_utc();
        let request = NonceReleaseRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: self.agent_key_id,
            agent_auth_token: self.agent_auth_token.clone(),
            reservation_id,
            requested_at: now,
            expires_at: now + Self::REQUEST_TTL,
        };
        Ok(self.daemon.release_nonce(request).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use vault_daemon::{DaemonError, KeyManagerDaemonApi};
    use vault_domain::{
        AdminSession, AgentAction, AgentCredentials, AgentKey, BroadcastTx, DomainError,
        EntityScope, EvmAddress, Lease, ManualApprovalDecision, ManualApprovalRequest,
        NonceReleaseRequest, NonceReservation, NonceReservationRequest, PolicyAttachment,
        RelayConfig, SignRequest, Signature, SpendingPolicy, VaultKey,
    };
    use vault_policy::PolicyEvaluation;
    use vault_signer::KeyCreateRequest;

    use super::{AgentOperations, AgentSdk, AgentSdkError};

    #[derive(Default)]
    pub(super) struct RecordingDaemon {
        pub(super) request: Mutex<Option<SignRequest>>,
        pub(super) nonce_request: Mutex<Option<NonceReservationRequest>>,
        pub(super) released_reservation: Mutex<Option<Uuid>>,
        fail_sign: bool,
        reserved_nonce_override: Option<u64>,
    }

    #[async_trait]
    impl KeyManagerDaemonApi for RecordingDaemon {
        async fn issue_lease(&self, _vault_password: &str) -> Result<Lease, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn add_policy(
            &self,
            _session: &AdminSession,
            _policy: SpendingPolicy,
        ) -> Result<(), DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn list_policies(
            &self,
            _session: &AdminSession,
        ) -> Result<Vec<SpendingPolicy>, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn disable_policy(
            &self,
            _session: &AdminSession,
            _policy_id: Uuid,
        ) -> Result<(), DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn create_vault_key(
            &self,
            _session: &AdminSession,
            _request: KeyCreateRequest,
        ) -> Result<VaultKey, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn export_vault_private_key(
            &self,
            _session: &AdminSession,
            _vault_key_id: Uuid,
        ) -> Result<Option<String>, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn create_agent_key(
            &self,
            _session: &AdminSession,
            _vault_key_id: Uuid,
            _attachment: PolicyAttachment,
        ) -> Result<AgentCredentials, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn refresh_agent_key(
            &self,
            _session: &AdminSession,
            _agent_key_id: Uuid,
            _vault_key_id: Uuid,
            _attachment: PolicyAttachment,
        ) -> Result<AgentCredentials, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn rotate_agent_auth_token(
            &self,
            _session: &AdminSession,
            _agent_key_id: Uuid,
        ) -> Result<String, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn revoke_agent_key(
            &self,
            _session: &AdminSession,
            _agent_key_id: Uuid,
        ) -> Result<(), DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn list_manual_approval_requests(
            &self,
            _session: &AdminSession,
        ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn decide_manual_approval_request(
            &self,
            _session: &AdminSession,
            _approval_request_id: Uuid,
            _decision: ManualApprovalDecision,
            _rejection_reason: Option<String>,
        ) -> Result<ManualApprovalRequest, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn set_relay_config(
            &self,
            _session: &AdminSession,
            _relay_url: Option<String>,
            _frontend_url: Option<String>,
        ) -> Result<RelayConfig, DaemonError> {
            Err(DaemonError::Transport("not used".to_string()))
        }

        async fn get_relay_config(
            &self,
            _session: &AdminSession,
        ) -> Result<RelayConfig, DaemonError> {
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
        ) -> Result<vault_policy::PolicyExplanation, DaemonError> {
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

    fn sample_admin_session() -> AdminSession {
        AdminSession {
            vault_password: "vault-password".to_string(),
            lease: Lease {
                lease_id: Uuid::new_v4(),
                issued_at: OffsetDateTime::UNIX_EPOCH,
                expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(5),
            },
        }
    }

    fn sample_policy() -> SpendingPolicy {
        SpendingPolicy::new(
            0,
            vault_domain::PolicyType::PerTxMaxSpending,
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
            daemon.issue_lease("pw").await,
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
                .export_vault_private_key(&session, Uuid::new_v4())
                .await,
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
            daemon
                .set_relay_config(&session, Some("https://relay.example".to_string()), None)
                .await,
            Err(DaemonError::Transport(message)) if message == "not used"
        ));
        assert!(matches!(
            daemon.get_relay_config(&session).await,
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

    #[tokio::test]
    async fn approve_sends_canonical_action_payload_and_auth_token() {
        let daemon = Arc::new(RecordingDaemon::default());
        let credentials = test_credentials();
        let key_id = credentials.agent_key.id;
        let auth_token = credentials.auth_token.clone();
        let sdk = AgentSdk::new(daemon.clone(), credentials);

        let token: EvmAddress = "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token");
        let spender: EvmAddress = "0x2000000000000000000000000000000000000000"
            .parse()
            .expect("spender");

        let signature = sdk
            .approve(1, token.clone(), spender.clone(), 42)
            .await
            .expect("approve");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let captured = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request");
        assert_eq!(captured.agent_key_id, key_id);
        assert_eq!(captured.agent_auth_token, auth_token);
        assert_eq!(
            captured.action,
            AgentAction::Approve {
                chain_id: 1,
                token,
                spender,
                amount_wei: 42
            }
        );
        let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
        assert_eq!(decoded, captured.action);
    }

    #[tokio::test]
    async fn constructors_transfer_native_and_reservation_helpers_use_expected_identity() {
        let daemon = Arc::new(RecordingDaemon::default());
        let key_id = Uuid::new_v4();
        let sdk = AgentSdk::new_with_key_id_and_token(
            daemon.clone(),
            key_id,
            "agent-secret-token".to_string(),
        );

        let recipient: EvmAddress = "0x2100000000000000000000000000000000000000"
            .parse()
            .expect("recipient");
        let signature = sdk
            .transfer_native(1, recipient.clone(), 5)
            .await
            .expect("transfer native");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let captured = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request");
        assert_eq!(captured.agent_key_id, key_id);
        assert_eq!(captured.agent_auth_token.as_str(), "agent-secret-token");
        assert_eq!(
            captured.action,
            AgentAction::TransferNative {
                chain_id: 1,
                to: recipient,
                amount_wei: 5
            }
        );

        let reservation = sdk
            .reserve_broadcast_nonce(56, 99)
            .await
            .expect("reserve nonce");
        assert_eq!(reservation.chain_id, 56);
        assert_eq!(reservation.nonce, 99);
        let captured_reservation = daemon
            .nonce_request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured nonce request");
        assert_eq!(captured_reservation.chain_id, 56);
        assert_eq!(captured_reservation.min_nonce, 99);
        assert!(captured_reservation.exact_nonce);
        sdk.release_broadcast_nonce(reservation.reservation_id)
            .await
            .expect("release nonce");
    }

    #[tokio::test]
    async fn sign_erc20_calldata_and_invalid_actions_propagate_domain_errors() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon.clone(), test_credentials());
        let encoded = vec![
            0x09, 0x5e, 0xa7, 0xb3, // approve(address,uint256)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
            0x44, 0x44, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
        ];

        let signature = sdk
            .sign_erc20_calldata(
                1,
                "0x3300000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                encoded,
            )
            .await
            .expect("sign erc20 calldata");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let err = sdk
            .transfer_native(
                1,
                "0x5500000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                0,
            )
            .await
            .expect_err("invalid action");
        assert!(matches!(
            err,
            AgentSdkError::Domain(DomainError::InvalidAmount)
        ));
    }

    #[tokio::test]
    async fn transfer_propagates_daemon_errors() {
        let daemon = Arc::new(RecordingDaemon {
            request: Mutex::new(None),
            nonce_request: Mutex::new(None),
            released_reservation: Mutex::new(None),
            fail_sign: true,
            reserved_nonce_override: None,
        });
        let sdk = AgentSdk::new(daemon, test_credentials());

        let token: EvmAddress = "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("token");
        let recipient: EvmAddress = "0x4000000000000000000000000000000000000000"
            .parse()
            .expect("recipient");

        let err = sdk
            .transfer(1, token, recipient, 7)
            .await
            .expect_err("must fail");
        assert!(matches!(
            err,
            AgentSdkError::Daemon(DaemonError::AgentAuthenticationFailed)
        ));
    }

    #[tokio::test]
    async fn broadcast_tx_sends_canonical_action_payload() {
        let daemon = Arc::new(RecordingDaemon::default());
        let credentials = test_credentials();
        let sdk = AgentSdk::new(daemon.clone(), credentials);

        let tx = BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            value_wei: 0,
            data_hex: "0xdeadbeef".to_string(),
            gas_limit: 50_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        };

        let signature = sdk.broadcast_tx(tx.clone()).await.expect("broadcast");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let captured = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request");
        assert_eq!(captured.action, AgentAction::BroadcastTx { tx: tx.clone() });
        let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
        assert_eq!(decoded, AgentAction::BroadcastTx { tx });
    }

    #[tokio::test]
    async fn broadcast_tx_rejects_mismatched_reserved_nonce_from_daemon() {
        let daemon = Arc::new(RecordingDaemon {
            request: Mutex::new(None),
            nonce_request: Mutex::new(None),
            released_reservation: Mutex::new(None),
            fail_sign: false,
            reserved_nonce_override: Some(1),
        });
        let sdk = AgentSdk::new(daemon.clone(), test_credentials());

        let tx = BroadcastTx {
            chain_id: 56,
            nonce: 0,
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            value_wei: 0,
            data_hex: "0xdeadbeef".to_string(),
            gas_limit: 50_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        };

        let err = sdk
            .broadcast_tx(tx.clone())
            .await
            .expect_err("mismatched reserved nonce must fail");
        assert!(matches!(
            err,
            AgentSdkError::Daemon(DaemonError::InvalidNonceReservation(message))
            if message.contains("requested exact nonce 0")
                && message.contains("chain_id 56")
                && message.contains("reserved 1")
        ));

        assert!(daemon.request.lock().expect("lock").is_none());
        assert!(daemon.released_reservation.lock().expect("lock").is_some());
        let captured_reservation = daemon
            .nonce_request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured nonce request");
        assert!(captured_reservation.exact_nonce);
        assert_eq!(captured_reservation.min_nonce, tx.nonce);
    }
}

#[cfg(test)]
mod typed_data_tests {
    use std::sync::Arc;

    use super::tests::{test_credentials, RecordingDaemon};
    use super::{AgentOperations, AgentSdk, AgentSdkError};
    use time::OffsetDateTime;
    use vault_domain::{AgentAction, DomainError, Eip3009Transfer, Permit2Permit};

    fn unix_timestamp(value: OffsetDateTime) -> u64 {
        value.unix_timestamp().try_into().expect("unix timestamp")
    }

    fn future_unix_timestamp(offset: time::Duration) -> u64 {
        unix_timestamp(OffsetDateTime::now_utc() + offset)
    }

    #[tokio::test]
    async fn permit2_sends_canonical_action_payload() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon.clone(), test_credentials());
        let sig_deadline = future_unix_timestamp(time::Duration::hours(1));
        let permit = Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration: future_unix_timestamp(time::Duration::hours(2)),
            nonce: 1,
            sig_deadline,
        };

        let signature = sdk.permit2_permit(permit.clone()).await.expect("permit2");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let captured = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request");
        assert_eq!(captured.action, AgentAction::Permit2Permit { permit });
        let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
        assert_eq!(decoded, captured.action);
    }

    #[tokio::test]
    async fn permit2_rejects_expired_signature_deadline() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon, test_credentials());
        let permit = Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration: future_unix_timestamp(time::Duration::hours(2)),
            nonce: 1,
            sig_deadline: unix_timestamp(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
        };

        let err = sdk
            .permit2_permit(permit)
            .await
            .expect_err("expired permit must be rejected");
        assert!(matches!(
            err,
            AgentSdkError::Domain(DomainError::InvalidSignatureDeadline)
        ));
    }

    #[tokio::test]
    async fn permit2_rejects_expired_permit_expiration() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon, test_credentials());
        let permit = Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration: unix_timestamp(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
            nonce: 1,
            sig_deadline: future_unix_timestamp(time::Duration::hours(1)),
        };

        let err = sdk
            .permit2_permit(permit)
            .await
            .expect_err("expired permit must be rejected");
        assert!(matches!(
            err,
            AgentSdkError::Domain(DomainError::InvalidPermitExpiration)
        ));
    }

    #[tokio::test]
    async fn eip3009_receive_sends_canonical_action_payload() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon.clone(), test_credentials());
        let authorization = Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 9,
            valid_after: future_unix_timestamp(time::Duration::minutes(5)),
            valid_before: future_unix_timestamp(time::Duration::minutes(10)),
            nonce_hex: "0x5555555555555555555555555555555555555555555555555555555555555555"
                .to_string(),
        };

        let signature = sdk
            .eip3009_receive_with_authorization(authorization.clone())
            .await
            .expect("eip3009 receive");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let captured = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request");
        assert_eq!(
            captured.action,
            AgentAction::Eip3009ReceiveWithAuthorization { authorization }
        );
        let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
        assert_eq!(decoded, captured.action);
    }

    #[tokio::test]
    async fn eip3009_rejects_expired_valid_before() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon, test_credentials());
        let authorization = Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 9,
            valid_after: unix_timestamp(OffsetDateTime::now_utc() - time::Duration::minutes(2)),
            valid_before: unix_timestamp(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
            nonce_hex: "0x5555555555555555555555555555555555555555555555555555555555555555"
                .to_string(),
        };

        let err = sdk
            .eip3009_transfer_with_authorization(authorization)
            .await
            .expect_err("expired authorization must be rejected");
        assert!(matches!(
            err,
            AgentSdkError::Domain(DomainError::InvalidAuthorizationWindow)
        ));
    }

    #[tokio::test]
    async fn transfer_and_eip3009_transfer_sends_canonical_action_payload() {
        let daemon = Arc::new(RecordingDaemon::default());
        let sdk = AgentSdk::new(daemon.clone(), test_credentials());

        let token = "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("token");
        let to = "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("to");
        let signature = sdk.transfer(1, token, to, 9).await.expect("transfer");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let transfer_action = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request")
            .action;
        assert!(matches!(transfer_action, AgentAction::Transfer { .. }));

        let authorization = Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 9,
            valid_after: future_unix_timestamp(time::Duration::minutes(5)),
            valid_before: future_unix_timestamp(time::Duration::minutes(10)),
            nonce_hex: "0x5555555555555555555555555555555555555555555555555555555555555555"
                .to_string(),
        };

        let signature = sdk
            .eip3009_transfer_with_authorization(authorization.clone())
            .await
            .expect("eip3009 transfer");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);

        let captured = daemon
            .request
            .lock()
            .expect("lock")
            .clone()
            .expect("captured request");
        assert_eq!(
            captured.action,
            AgentAction::Eip3009TransferWithAuthorization { authorization }
        );
        let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
        assert_eq!(decoded, captured.action);

        let erc20_transfer = vec![
            0xa9, 0x05, 0x9c, 0xbb, // transfer(address,uint256)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
            0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        let signature = sdk
            .sign_erc20_calldata(
                1,
                "0x6000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                erc20_transfer,
            )
            .await
            .expect("erc20 transfer");
        assert_eq!(signature.bytes, vec![0x11, 0x22]);
    }
}
