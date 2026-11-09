//! Signer daemon test doubles for paymentd's unit tests.
//!
//! - [`InProcessSigner`]: a real in-memory signerd reached without a socket,
//!   with the same peer semantics as production (paymentd is a non-root agent
//!   peer, so admin methods fail). Use it to test real policy outcomes.
//! - [`ScriptedSigner`]: replays canned responses and records every request,
//!   for transport failures and exact request assertions.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use agentpay_api::{AgentAuth, DaemonRpcRequest, DaemonRpcResponse, WireDaemonError};
use agentpay_domain::{AdminAuth, EntityScope, PolicyAttachment, PolicyType, SpendingPolicy};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use agentpay_signerd::{DaemonConfig, InMemoryDaemon, KeyManagerDaemonApi, RequestContext};
use async_trait::async_trait;

use super::{SignerClient, SignerError};

/// The uid the doubles pretend paymentd runs as.
pub(crate) const PAYMENTD_TEST_UID: u32 = 4242;

/// A real signerd in this process.
pub(crate) struct InProcessSigner {
    pub(crate) daemon: Arc<InMemoryDaemon<SoftwareSignerBackend>>,
}

impl InProcessSigner {
    /// A signerd with one generated vault key, one agent attached to all
    /// policies, and the given policies; returns the agent's credentials.
    pub(crate) async fn with_agent(policies: Vec<SpendingPolicy>) -> (Self, AgentAuth) {
        let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("in-memory signer daemon");
        let admin = AdminAuth::PeerCredentials;
        for policy in policies {
            daemon.add_policy(&admin, policy).await.expect("add policy");
        }
        let vault_key = daemon
            .create_vault_key(&admin, KeyCreateRequest::Generate)
            .await
            .expect("vault key");
        let credentials = daemon
            .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
            .await
            .expect("agent key");
        let auth = AgentAuth {
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
        };
        (
            Self {
                daemon: Arc::new(daemon),
            },
            auth,
        )
    }
}

#[async_trait]
impl SignerClient for InProcessSigner {
    async fn call(&self, request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError> {
        self.daemon
            .handle_rpc(&RequestContext::peer(PAYMENTD_TEST_UID), request)
            .await
            .map_err(|error| SignerError::Rejected(WireDaemonError::from(error)))
    }
}

/// A per-transaction limit on every asset and network.
pub(crate) fn per_tx_limit(max_amount_wei: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        max_amount_wei,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

/// Manual approval for every amount in `[min, max]`.
pub(crate) fn manual_approval(min_amount_wei: u128, max_amount_wei: u128) -> SpendingPolicy {
    SpendingPolicy::new_manual_approval(
        1,
        min_amount_wei,
        max_amount_wei,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy")
}

/// Replays canned responses in order and records the requests it receives.
#[derive(Default)]
pub(crate) struct ScriptedSigner {
    responses: Mutex<VecDeque<Result<DaemonRpcResponse, SignerError>>>,
    requests: Mutex<Vec<DaemonRpcRequest>>,
}

impl ScriptedSigner {
    /// A double that answers with `responses`, in order.
    pub(crate) fn new(
        responses: impl IntoIterator<Item = Result<DaemonRpcResponse, SignerError>>,
    ) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Every request received so far.
    pub(crate) fn requests(&self) -> Vec<DaemonRpcRequest> {
        self.requests.lock().expect("requests lock").clone()
    }
}

#[async_trait]
impl SignerClient for ScriptedSigner {
    async fn call(&self, request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError> {
        self.requests.lock().expect("requests lock").push(request);
        self.responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .unwrap_or_else(|| Err(SignerError::Unavailable("script exhausted".into())))
    }
}
