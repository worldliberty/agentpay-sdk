//! `ProxyStart`, `ProxyStop`, `ProxyStatus`: the local paying proxy
//! ([`crate::proxy`]). The proxy pays as the agent that started it, without
//! waiting for manual approvals (a proxied client cannot wait that long):
//! a payment a policy holds for an operator fails with
//! `ManualApprovalPending` in the proxy's `x-agentpay-proxy-error` header.

use agentpay_api::payments::{PaymentsRpcRequest as Req, PaymentsRpcResponse as Res};

use super::payer::Payer;
use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::state::AppState;

/// Handles the proxy methods.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: Req,
) -> Result<Res, PaymentsError> {
    match request {
        Req::ProxyStart(params) => {
            let payer = Payer::new(state, agent, None).await?;
            state
                .proxy
                .start(payer, &params)
                .await
                .map(Res::ProxyStarted)
        }
        Req::ProxyStop(_) => state
            .proxy
            .stop(agent.credentials.agent_key_id)
            .await
            .map(Res::ProxyStatus),
        Req::ProxyStatus(_) => Ok(Res::ProxyStatus(state.proxy.status().await)),
        other => Err(PaymentsError::Internal(format!(
            "the proxy feature cannot handle {}",
            other.method_name()
        ))),
    }
}
