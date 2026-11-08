//! Caller authentication, delegated to the signer daemon.
//!
//! paymentd keeps no credential store. For every authenticated method,
//! [`authenticate`] forwards the caller's `AgentAuth` to signerd's
//! `AuthenticateAgent`; the request is served only when signerd accepts it.
//! Nothing is cached, so a rotated or revoked token stops working at once.
//!
//! The credentials stay with the request (as [`AuthenticatedAgent::credentials`])
//! because every later signer call is made as that agent. They are wiped when
//! the request is dropped and never logged.

use agentpay_api::{AgentAuth, AgentIdentity, WireDaemonError};

use crate::error::PaymentsError;
use crate::signer::{AgentSigner, SignerClient, SignerError};

/// A caller whose agent token signerd accepted.
#[derive(Debug, Clone)]
pub struct AuthenticatedAgent {
    /// The verified credentials, used for this agent's signer calls.
    pub credentials: AgentAuth,
    /// The agent's identity and wallet addresses, as reported by signerd.
    pub identity: AgentIdentity,
}

impl AuthenticatedAgent {
    /// Signer daemon operations on behalf of this agent.
    #[must_use]
    pub fn signer<'a>(&'a self, signer: &'a dyn SignerClient) -> AgentSigner<'a> {
        AgentSigner::new(signer, &self.credentials)
    }
}

/// Verifies `credentials` with the signer daemon.
pub async fn authenticate(
    signer: &dyn SignerClient,
    credentials: &AgentAuth,
) -> Result<AuthenticatedAgent, PaymentsError> {
    match AgentSigner::new(signer, credentials).identity().await {
        // Signerd answers for the agent it was asked about; anything else is a bug.
        Ok(identity) if identity.agent_key.id == credentials.agent_key_id => {
            Ok(AuthenticatedAgent {
                credentials: credentials.clone(),
                identity,
            })
        }
        Ok(_) => Err(PaymentsError::AgentAuthenticationFailed),
        Err(SignerError::Rejected(WireDaemonError::AgentAuthenticationFailed)) => {
            Err(PaymentsError::AgentAuthenticationFailed)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use agentpay_api::rpc::AuthenticateAgentParams;
    use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};
    use uuid::Uuid;

    use super::*;
    use crate::signer::testing::{InProcessSigner, ScriptedSigner};

    #[tokio::test]
    async fn valid_credentials_yield_the_agent_identity() {
        let (signer, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let agent = authenticate(&signer, &auth).await.expect("authenticated");
        assert_eq!(agent.identity.agent_key.id, auth.agent_key_id);
        assert!(agent.identity.evm_address.is_some());
        assert_eq!(agent.credentials, auth);
    }

    #[tokio::test]
    async fn wrong_or_unknown_credentials_are_rejected() {
        let (signer, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let wrong_token = AgentAuth {
            agent_key_id: auth.agent_key_id,
            agent_auth_token: "not-the-token".to_string().into(),
        };
        let unknown_agent = AgentAuth {
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: auth.agent_auth_token.clone(),
        };
        for credentials in [wrong_token, unknown_agent] {
            let error = authenticate(&signer, &credentials)
                .await
                .expect_err("rejected");
            assert_eq!(error, PaymentsError::AgentAuthenticationFailed);
        }
    }

    #[tokio::test]
    async fn signer_outages_are_not_reported_as_bad_credentials() {
        let signer = ScriptedSigner::new([Err(SignerError::Unavailable("no socket".into()))]);
        let auth = AgentAuth {
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "token".to_string().into(),
        };
        let error = authenticate(&signer, &auth).await.expect_err("unavailable");
        assert_eq!(error, PaymentsError::SignerUnavailable("no socket".into()));

        // The request forwarded the caller's credentials unchanged.
        let requests = signer.requests();
        let [DaemonRpcRequest::AuthenticateAgent(AuthenticateAgentParams { auth: sent })] =
            requests.as_slice()
        else {
            panic!("expected one AuthenticateAgent call, got {requests:?}");
        };
        assert_eq!(sent, &auth);
    }

    #[tokio::test]
    async fn an_identity_for_another_agent_is_refused() {
        let (real, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let mut identity = AgentSigner::new(&real, &auth)
            .identity()
            .await
            .expect("identity");
        identity.agent_key.id = Uuid::new_v4();
        let signer =
            ScriptedSigner::new([Ok(DaemonRpcResponse::AgentIdentity(Box::new(identity)))]);
        let error = authenticate(&signer, &auth).await.expect_err("mismatch");
        assert_eq!(error, PaymentsError::AgentAuthenticationFailed);
    }
}
