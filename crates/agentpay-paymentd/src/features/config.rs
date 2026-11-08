//! `GetConfig`, `SetConfig`, `AddToken`, and the unauthenticated
//! `LookupToken`.

#[cfg(test)]
mod lookup_tests;
#[cfg(test)]
mod tests;
mod tokens;

use agentpay_api::payments::{
    GetConfigParams, LookupTokenParams, PaymentsRpcRequest, PaymentsRpcResponse, SetConfigParams,
};

use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::state::AppState;

/// Handles the configuration methods.
pub async fn handle(
    state: &AppState,
    _agent: &AuthenticatedAgent,
    request: PaymentsRpcRequest,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    match request {
        PaymentsRpcRequest::GetConfig(GetConfigParams { .. }) => {
            Ok(PaymentsRpcResponse::Config(state.config.get().await))
        }
        PaymentsRpcRequest::SetConfig(SetConfigParams { config, .. }) => state
            .config
            .set(config)
            .await
            .map(PaymentsRpcResponse::Config),
        PaymentsRpcRequest::AddToken(params) => tokens::add_token(state, params)
            .await
            .map(PaymentsRpcResponse::TokenAdded),
        other => Err(PaymentsError::Internal(format!(
            "the config feature cannot handle {}",
            other.method_name()
        ))),
    }
}

/// Handles `LookupToken`, which has no caller: it reads public chain data
/// through the configured endpoints and changes nothing.
pub async fn lookup_token(
    state: &AppState,
    params: LookupTokenParams,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    tokens::lookup_token(state, params)
        .await
        .map(PaymentsRpcResponse::TokenInfo)
}
