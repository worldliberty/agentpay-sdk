//! Routes a decoded `PaymentsRpcRequest` to its feature module.
//!
//! Authentication happens here, once, before any feature code runs: a request
//! that carries `auth` is served only after the signer daemon accepts the
//! credentials. Adding a method family is one match arm in `route`:
//!
//! ```ignore
//! Req::Transfer(_) | Req::TransferNative(_) => features::evm::handle(state, agent(&caller)?, request).await,
//! ```

use agentpay_api::payments::{PaymentsRpcRequest as Req, PaymentsRpcResponse as Res};
use agentpay_api::HelloResponse;

use crate::auth::{authenticate, AuthenticatedAgent};
use crate::error::PaymentsError;
use crate::features;
use crate::state::{AppState, SERVICE_VERSION};
use crate::telemetry::RequestUsage;

/// Authenticates the caller (unless the method is open) and handles
/// `request`, then records the call in telemetry (method, outcome, and coarse
/// duration and amount only; never blocks).
pub async fn dispatch(state: &AppState, request: Req) -> Result<Res, PaymentsError> {
    let started = std::time::Instant::now();
    let usage = RequestUsage::of(&request);
    let result = authenticate_and_route(state, request).await;
    state
        .telemetry
        .record_request(usage, &result, started.elapsed());
    result
}

async fn authenticate_and_route(state: &AppState, request: Req) -> Result<Res, PaymentsError> {
    let caller = match request.agent_auth() {
        Some(credentials) => Some(authenticate(state.signer.as_ref(), credentials).await?),
        None => None,
    };
    route(state, caller.as_ref(), request).await
}

async fn route(
    state: &AppState,
    caller: Option<&AuthenticatedAgent>,
    request: Req,
) -> Result<Res, PaymentsError> {
    // `ResumeApproved` serves every family: approvals that belong to a stored
    // Solana transfer resume there, all others in the EVM feature below.
    if let Req::ResumeApproved(params) = &request {
        let resumed = features::solana::resume_approved(
            state,
            agent(caller)?,
            params.approval_request_id,
            params.approval_wait_secs,
        )
        .await;
        if let Some(result) = resumed {
            return result;
        }
    }
    match request {
        Req::Hello => Ok(Res::Hello(HelloResponse::for_payments_service(
            SERVICE_VERSION,
        ))),
        // Read-only and unauthenticated, like `Hello`: no caller is needed.
        Req::LookupToken(params) => features::config::lookup_token(state, params).await,
        Req::GetConfig(_) | Req::SetConfig(_) | Req::AddToken(_) => {
            features::config::handle(state, agent(caller)?, request).await
        }
        Req::TransferSol(_) | Req::TransferSpl(_) => {
            features::solana::handle(state, agent(caller)?, request).await
        }
        Req::Transfer(_)
        | Req::TransferNative(_)
        | Req::Approve(_)
        | Req::Broadcast(_)
        | Req::SignTypedData(_)
        | Req::ResumeApproved(_)
        | Req::RpcChainInfo(_)
        | Req::RpcBlockNumber(_)
        | Req::RpcBalance(_)
        | Req::RpcNonce(_)
        | Req::RpcFees(_)
        | Req::RpcGasEstimate(_)
        | Req::RpcTx(_)
        | Req::RpcReceipt(_)
        | Req::RpcCode(_) => features::evm::handle(state, agent(caller)?, request).await,
        Req::WalletSummary(_) | Req::WalletBalance(_) | Req::FundingRequest(_) | Req::Status(_) => {
            features::wallet::handle(state, agent(caller)?, request).await
        }
        Req::X402Fetch(_) => features::x402::handle(state, agent(caller)?, request).await,
        Req::Activity(_) => features::activity::handle(state, agent(caller)?, request).await,
        Req::MppFetch(_) => features::mpp::handle(state, agent(caller)?, request).await,
        Req::ProxyStart(_) | Req::ProxyStop(_) | Req::ProxyStatus(_) => {
            features::proxy::handle(state, agent(caller)?, request).await
        }
        Req::TelemetryStatus(_) | Req::SetTelemetry(_) => {
            features::telemetry::handle(state, agent(caller)?, request).await
        }
    }
}

/// The authenticated caller; every method but `Hello` and `LookupToken` has one.
fn agent(caller: Option<&AuthenticatedAgent>) -> Result<&AuthenticatedAgent, PaymentsError> {
    caller.ok_or(PaymentsError::AgentAuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use agentpay_api::payments::{
        AddTokenParams, GetConfigParams, LookupTokenParams, SetConfigParams,
    };
    use agentpay_api::rpc::AuthenticateAgentParams;
    use agentpay_api::{AgentAuth, DaemonRpcRequest, WireDaemonError};
    use uuid::Uuid;

    use super::*;
    use crate::config::{default_config, ConfigStore};
    use crate::signer::testing::{InProcessSigner, ScriptedSigner};
    use crate::signer::{SignerClient, SignerError};
    use crate::test_support::TempDir;

    fn state(dir: &TempDir, signer: Arc<dyn SignerClient>) -> AppState {
        AppState::new(ConfigStore::open(dir.path()).expect("config"), signer)
    }

    #[tokio::test]
    async fn hello_needs_no_credentials_and_no_signer() {
        let dir = TempDir::new("dispatch");
        let signer = Arc::new(ScriptedSigner::default());
        let state = state(&dir, signer.clone());
        let Res::Hello(hello) = dispatch(&state, Req::Hello).await.expect("hello") else {
            panic!("Hello must answer Hello");
        };
        assert_eq!(hello, HelloResponse::for_payments_service(SERVICE_VERSION));
        assert!(signer.requests().is_empty(), "Hello must not call signerd");
    }

    #[tokio::test]
    async fn config_methods_route_to_the_config_feature_after_authentication() {
        let dir = TempDir::new("dispatch");
        let (signer, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let state = state(&dir, Arc::new(signer));

        let get = Req::GetConfig(GetConfigParams { auth: auth.clone() });
        let Res::Config(config) = dispatch(&state, get).await.expect("get") else {
            panic!("GetConfig must answer Config");
        };
        assert_eq!(config, default_config());

        let mut changed = config.clone();
        changed.default_network = "eth".into();
        let set = Req::SetConfig(SetConfigParams {
            auth,
            config: changed.clone(),
        });
        assert_eq!(
            dispatch(&state, set).await.expect("set"),
            Res::Config(changed.clone())
        );
        assert_eq!(state.config.get().await, changed);
    }

    #[tokio::test]
    async fn bad_credentials_never_reach_a_feature() {
        let dir = TempDir::new("dispatch");
        let (signer, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let state = state(&dir, Arc::new(signer));
        let mut config = default_config();
        config.default_network = "eth".into();
        let set = Req::SetConfig(SetConfigParams {
            auth: AgentAuth {
                agent_key_id: auth.agent_key_id,
                agent_auth_token: "forged".to_string().into(),
            },
            config,
        });
        let err = dispatch(&state, set).await.expect_err("forged token");
        assert_eq!(err, PaymentsError::AgentAuthenticationFailed);
        assert_eq!(state.config.get().await, default_config());
    }

    #[tokio::test]
    async fn add_token_with_bad_credentials_is_refused_like_set_config() {
        let dir = TempDir::new("dispatch");
        let (signer, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let state = state(&dir, Arc::new(signer));
        let add = Req::AddToken(AddTokenParams {
            auth: AgentAuth {
                agent_key_id: auth.agent_key_id,
                agent_auth_token: "forged".to_string().into(),
            },
            network: "bsc".into(),
            address: "0x3333333333333333333333333333333333333333".into(),
            symbol: Some("TKN".into()),
            decimals: Some(6),
        });
        let err = dispatch(&state, add).await.expect_err("forged token");
        assert_eq!(err, PaymentsError::AgentAuthenticationFailed);
        assert_eq!(state.config.get().await, default_config());

        let add = Req::AddToken(AddTokenParams {
            auth: auth.clone(),
            network: "bsc".into(),
            address: "0x3333333333333333333333333333333333333333".into(),
            symbol: None,
            decimals: None,
        });
        let err = route(&state, None, add).await.expect_err("no caller");
        assert_eq!(err, PaymentsError::AgentAuthenticationFailed);
        assert_eq!(state.config.get().await, default_config());
    }

    #[tokio::test]
    async fn lookup_token_needs_no_credentials_and_never_calls_the_signer() {
        let dir = TempDir::new("dispatch");
        let signer = Arc::new(ScriptedSigner::default());
        let state = state(&dir, signer.clone());
        let lookup = Req::LookupToken(LookupTokenParams {
            network: "nope".into(),
            address: "0x3333333333333333333333333333333333333333".into(),
            symbol: None,
            decimals: None,
        });
        assert!(lookup.agent_auth().is_none());
        let err = dispatch(&state, lookup).await.expect_err("unknown network");
        assert!(matches!(err, PaymentsError::InvalidRequest(_)), "{err:?}");
        assert!(
            signer.requests().is_empty(),
            "LookupToken must not call signerd"
        );
        assert_eq!(state.config.get().await, default_config());
    }

    #[tokio::test]
    async fn signer_errors_surface_with_their_kind() {
        let dir = TempDir::new("dispatch");
        let signer = Arc::new(ScriptedSigner::new([
            Err(SignerError::Unavailable("down".into())),
            Err(SignerError::Rejected(WireDaemonError::LockPoisoned)),
        ]));
        let state = state(&dir, signer.clone());
        let auth = AgentAuth {
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "token".to_string().into(),
        };
        let get = || Req::GetConfig(GetConfigParams { auth: auth.clone() });
        assert_eq!(
            dispatch(&state, get()).await,
            Err(PaymentsError::SignerUnavailable("down".into()))
        );
        assert_eq!(
            dispatch(&state, get()).await,
            Err(PaymentsError::Signer(WireDaemonError::LockPoisoned))
        );
        assert!(signer.requests().iter().all(|r| matches!(
            r,
            DaemonRpcRequest::AuthenticateAgent(AuthenticateAgentParams { .. })
        )));
    }

    #[tokio::test]
    async fn a_route_without_a_caller_is_refused() {
        let dir = TempDir::new("dispatch");
        let state = state(&dir, Arc::new(ScriptedSigner::default()));
        let auth = AgentAuth {
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "token".to_string().into(),
        };
        let err = route(&state, None, Req::GetConfig(GetConfigParams { auth }))
            .await
            .expect_err("no caller");
        assert_eq!(err, PaymentsError::AgentAuthenticationFailed);
    }
}
