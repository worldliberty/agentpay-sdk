//! [`AgentSigner`]: policy-checked signer daemon operations for one agent.

use std::time::Duration;

use agentpay_api::rpc::{
    AgentActivityParams, AgentActivityReport, AgentPolicySummaryParams, AuthenticateAgentParams,
    ReleaseNonceParams, ReleaseSignedNonceParams, ReserveNonceParams, SignForAgentParams,
};
use agentpay_api::{
    AgentAuth, AgentIdentity, AgentPolicySummary, DaemonRpcRequest, DaemonRpcResponse,
    WireDaemonError,
};
use agentpay_domain::{
    AgentAction, BroadcastTx, NonceReleaseRequest, NonceReservation, NonceReservationRequest,
    SignRequest, Signature, SignedNonceReleaseRequest,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{unexpected, SignerClient, SignerError};
use crate::error::PaymentsError;

/// Lifetime given to every signer request (signerd accepts at most 5 minutes).
const REQUEST_TTL: time::Duration = time::Duration::minutes(2);

/// Upper bound on how long one call may wait for a manual approval. Clients
/// must use a response timeout longer than the wait they ask for.
pub const MAX_APPROVAL_WAIT: Duration = Duration::from_secs(10 * 60);

/// How long [`AgentSigner::sign`] keeps polling while signerd holds a
/// request for an operator, and how often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalWait {
    /// Total time to keep polling; zero returns `ManualApprovalPending` at once.
    pub max_wait: Duration,
    /// Delay before the first poll; doubles after each poll.
    pub initial_interval: Duration,
    /// Longest delay between polls.
    pub max_interval: Duration,
}

impl ApprovalWait {
    /// Do not wait: report `ManualApprovalPending` on the first hold.
    #[must_use]
    pub const fn none() -> Self {
        Self::up_to(Duration::ZERO)
    }

    /// Poll for up to `max_wait` (capped at [`MAX_APPROVAL_WAIT`]), starting
    /// at 1 s and backing off to 15 s between polls.
    #[must_use]
    pub const fn up_to(max_wait: Duration) -> Self {
        let max_wait = if max_wait.as_secs() > MAX_APPROVAL_WAIT.as_secs() {
            MAX_APPROVAL_WAIT
        } else {
            max_wait
        };
        Self {
            max_wait,
            initial_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(15),
        }
    }
}

/// Signer daemon operations on behalf of one authenticated agent.
///
/// Every request carries the agent's credentials and fresh timestamps
/// (2-minute lifetime), so signerd authenticates the agent and applies its
/// policies to each call.
pub struct AgentSigner<'a> {
    signer: &'a dyn SignerClient,
    auth: &'a AgentAuth,
}

impl<'a> AgentSigner<'a> {
    /// Operations for the agent identified by `auth`.
    #[must_use]
    pub fn new(signer: &'a dyn SignerClient, auth: &'a AgentAuth) -> Self {
        Self { signer, auth }
    }

    /// Verifies the credentials and returns the agent's identity and addresses.
    pub async fn identity(&self) -> Result<AgentIdentity, SignerError> {
        let request = DaemonRpcRequest::AuthenticateAgent(AuthenticateAgentParams {
            auth: self.auth.clone(),
        });
        match self.signer.call(request).await? {
            DaemonRpcResponse::AgentIdentity(identity) => Ok(*identity),
            other => Err(unexpected("AuthenticateAgent", &other)),
        }
    }

    /// The enabled policies that govern the agent (read-only).
    pub async fn policy_summary(&self) -> Result<AgentPolicySummary, SignerError> {
        let request = DaemonRpcRequest::AgentPolicySummary(AgentPolicySummaryParams {
            auth: self.auth.clone(),
        });
        match self.signer.call(request).await? {
            DaemonRpcResponse::AgentPolicySummary(summary) => Ok(summary),
            other => Err(unexpected("AgentPolicySummary", &other)),
        }
    }

    /// The agent's recent spends and approval requests (`AgentActivity`).
    pub async fn activity(
        &self,
        since: Option<OffsetDateTime>,
        limit: Option<u16>,
    ) -> Result<AgentActivityReport, SignerError> {
        let request = DaemonRpcRequest::AgentActivity(AgentActivityParams {
            auth: self.auth.clone(),
            since,
            limit,
        });
        match self.signer.call(request).await? {
            DaemonRpcResponse::AgentActivity(report) => Ok(report),
            other => Err(unexpected("AgentActivity", &other)),
        }
    }

    /// Reserves an EVM nonce at or above `min_nonce` (exactly `min_nonce` when
    /// `exact`) for a `BroadcastTx` on `chain_id`. Release it with
    /// [`release_nonce`](Self::release_nonce) if the transaction is abandoned.
    pub async fn reserve_nonce(
        &self,
        chain_id: u64,
        min_nonce: u64,
        exact: bool,
    ) -> Result<NonceReservation, SignerError> {
        let (requested_at, expires_at) = timestamps();
        let request = DaemonRpcRequest::ReserveNonce(ReserveNonceParams {
            request: NonceReservationRequest {
                request_id: Uuid::new_v4(),
                agent_key_id: self.auth.agent_key_id,
                agent_auth_token: self.auth.agent_auth_token.clone(),
                chain_id,
                min_nonce,
                exact_nonce: exact,
                requested_at,
                expires_at,
            },
        });
        match self.signer.call(request).await? {
            DaemonRpcResponse::NonceReservation(reservation) => Ok(reservation),
            other => Err(unexpected("ReserveNonce", &other)),
        }
    }

    /// Returns an unused reservation's nonce to the pool.
    pub async fn release_nonce(&self, reservation_id: Uuid) -> Result<(), SignerError> {
        let (requested_at, expires_at) = timestamps();
        let request = DaemonRpcRequest::ReleaseNonce(ReleaseNonceParams {
            request: NonceReleaseRequest {
                request_id: Uuid::new_v4(),
                agent_key_id: self.auth.agent_key_id,
                agent_auth_token: self.auth.agent_auth_token.clone(),
                reservation_id,
                requested_at,
                expires_at,
            },
        });
        match self.signer.call(request).await? {
            DaemonRpcResponse::Unit => Ok(()),
            other => Err(unexpected("ReleaseNonce", &other)),
        }
    }

    /// Returns the nonce of a signed `BroadcastTx` to the pool.
    ///
    /// Call it **only** when the transaction certainly never reached the
    /// network (see [`SendFailure::not_submitted`](crate::chains::evm::SendFailure)):
    /// a released nonce is handed out again, and a second transaction with
    /// it would replace or race a live one.
    pub async fn release_signed_nonce(
        &self,
        chain_id: u64,
        nonce: u64,
        tx_hash_hex: &str,
    ) -> Result<(), SignerError> {
        let (requested_at, expires_at) = timestamps();
        let request = DaemonRpcRequest::ReleaseSignedNonce(ReleaseSignedNonceParams {
            request: SignedNonceReleaseRequest {
                request_id: Uuid::new_v4(),
                agent_key_id: self.auth.agent_key_id,
                agent_auth_token: self.auth.agent_auth_token.clone(),
                chain_id,
                nonce,
                tx_hash_hex: tx_hash_hex.to_string(),
                requested_at,
                expires_at,
            },
        });
        match self.signer.call(request).await? {
            DaemonRpcResponse::Unit => Ok(()),
            other => Err(unexpected("ReleaseSignedNonce", &other)),
        }
    }

    /// Best-effort [`release_signed_nonce`](Self::release_signed_nonce) for a
    /// signed `tx` that certainly never reached the network, so the next
    /// payment does not wait behind a nonce gap. A failure only leaves the
    /// gap, so it is logged rather than reported; without a hash nothing
    /// can be released.
    pub async fn release_unsent(&self, tx: &BroadcastTx, tx_hash_hex: Option<&str>) {
        let Some(tx_hash_hex) = tx_hash_hex else {
            return;
        };
        if let Err(error) = self
            .release_signed_nonce(tx.chain_id, tx.nonce, tx_hash_hex)
            .await
        {
            tracing::warn!(
                error = PaymentsError::from(error).kind(),
                "failed to release the nonce of an unsent transaction"
            );
        }
    }

    /// Asks signerd to sign `action` under the agent's policies.
    ///
    /// When a policy holds the action for an operator, keeps resending the
    /// identical request (same `request_id` and payload, fresh timestamps)
    /// with exponential backoff until it is approved, rejected
    /// (`Signer(ManualApprovalRejected)`), or `wait.max_wait` has passed
    /// (`ManualApprovalPending`). To resume after `ManualApprovalPending`, a
    /// feature must resend exactly the same `action`: a rebuilt action with
    /// a different nonce or fee creates a new approval request.
    pub async fn sign(
        &self,
        action: AgentAction,
        wait: ApprovalWait,
    ) -> Result<Signature, PaymentsError> {
        let payload = serde_json::to_vec(&action)
            .map_err(|err| PaymentsError::Internal(format!("failed to encode action: {err}")))?;
        let request_id = Uuid::new_v4();
        let deadline = tokio::time::Instant::now() + wait.max_wait;
        let mut interval = wait.initial_interval;
        loop {
            let (requested_at, expires_at) = timestamps();
            let request = DaemonRpcRequest::SignForAgent(SignForAgentParams {
                request: SignRequest {
                    request_id,
                    agent_key_id: self.auth.agent_key_id,
                    agent_auth_token: self.auth.agent_auth_token.clone(),
                    payload: payload.clone(),
                    action: action.clone(),
                    requested_at,
                    expires_at,
                },
            });
            match self.signer.call(request).await {
                Ok(DaemonRpcResponse::Signature(signature)) => return Ok(signature),
                Ok(other) => return Err(unexpected("SignForAgent", &other).into()),
                Err(SignerError::Rejected(WireDaemonError::ManualApprovalRequired {
                    approval_request_id,
                })) => {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        return Err(PaymentsError::ManualApprovalPending {
                            approval_request_id,
                        });
                    }
                    tokio::time::sleep(interval.min(deadline - now)).await;
                    interval = interval.saturating_mul(2).min(wait.max_interval);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// `(requested_at, expires_at)` for a request sent now.
fn timestamps() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now, now + REQUEST_TTL)
}
