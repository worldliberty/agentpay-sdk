//! EVM feature tests: every method through [`dispatch`], with a real
//! in-memory signer daemon (policies, nonce reservations, approvals) and the
//! loopback mock JSON-RPC endpoint.

mod approval;
mod examples;
mod nonce_gap;
mod payments;
mod reads;

use std::str::FromStr;
use std::sync::Arc;

use agentpay_api::payments::{
    EvmTxOptions, PaymentsRpcRequest as Req, PaymentsRpcResponse as Res, TransferParams,
};
use agentpay_api::{AgentAuth, DaemonRpcRequest, DaemonRpcResponse};
use agentpay_domain::{AgentAction, EvmAddress, SpendingPolicy};
use async_trait::async_trait;

use crate::chains::evm::mock_rpc::MockRpc;
use crate::config::{default_config, ConfigStore};
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::signer::testing::InProcessSigner;
use crate::signer::{AgentSigner, SignerClient, SignerError};
use crate::state::AppState;
use crate::test_support::TempDir;

/// USD1 on BSC in the built-in configuration (18 decimals).
const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
/// A recipient.
const RECIPIENT: &str = "0x5aeda56215b167893e80b4fe645ba6d5bab767de";
/// 1 USD1 in base units.
const ONE_USD1: u128 = 1_000_000_000_000_000_000;

fn address(value: &str) -> EvmAddress {
    EvmAddress::from_str(value).expect("address")
}

/// paymentd state wired to an in-memory signer daemon and a mock BSC endpoint.
struct Harness {
    _dir: TempDir,
    state: AppState,
    signer: Arc<InProcessSigner>,
    auth: AgentAuth,
    mock: MockRpc,
}

impl Harness {
    /// A harness whose agent is bound by `policies`.
    async fn new(policies: Vec<SpendingPolicy>) -> Self {
        let (signer, auth) = InProcessSigner::with_agent(policies).await;
        Self::with_signer(Arc::new(signer), auth, |signer| signer).await
    }

    /// A harness over `signer`, reached through `wrap(signer)`.
    async fn with_signer(
        signer: Arc<InProcessSigner>,
        auth: AgentAuth,
        wrap: impl FnOnce(Arc<InProcessSigner>) -> Arc<dyn SignerClient>,
    ) -> Self {
        let dir = TempDir::new("evm");
        let mock = MockRpc::start(56).await;
        let state = AppState::new(
            ConfigStore::open(dir.path()).expect("config"),
            wrap(signer.clone()),
        );
        let mut config = default_config();
        let bsc = config.chains.get_mut("bsc").expect("bsc");
        bsc.rpc_url = Some(mock.url().to_string());
        bsc.fallback_rpc_urls.clear();
        state.config.set(config).await.expect("set config");
        Self {
            _dir: dir,
            state,
            signer,
            auth,
            mock,
        }
    }

    async fn call(&self, request: Req) -> Result<Res, PaymentsError> {
        dispatch(&self.state, request).await
    }

    /// A transfer of `amount` USD1 (default network and asset) with `options`.
    fn transfer(&self, amount: &str, options: EvmTxOptions) -> Req {
        Req::Transfer(TransferParams {
            auth: self.auth.clone(),
            network: None,
            asset: None,
            to: address(RECIPIENT),
            amount: amount.into(),
            options,
        })
    }

    /// The agent's wallet address.
    async fn wallet(&self) -> EvmAddress {
        AgentSigner::new(self.signer.as_ref(), &self.auth)
            .identity()
            .await
            .expect("identity")
            .evm_address
            .expect("evm address")
    }

    /// The nonce the signer daemon would reserve next at or above `min`
    /// (the reservation is released again).
    async fn next_free_nonce(&self, min: u64) -> u64 {
        let signer = AgentSigner::new(self.signer.as_ref(), &self.auth);
        let reservation = signer.reserve_nonce(56, min, false).await.expect("reserve");
        signer
            .release_nonce(reservation.reservation_id)
            .await
            .expect("release");
        reservation.nonce
    }
}

/// A policy that allows every payment (the signer daemon refuses agents
/// without policies).
fn open_policy() -> Vec<SpendingPolicy> {
    vec![crate::signer::testing::per_tx_limit(u128::MAX)]
}

/// Options that send the transaction.
fn broadcast() -> EvmTxOptions {
    EvmTxOptions {
        broadcast: true,
        ..EvmTxOptions::default()
    }
}

/// Forwards to a real signer daemon but makes it sign a different
/// transaction than requested (higher gas limit), as a compromised or buggy
/// signer might. The signature is valid; only the contents differ.
struct TamperingSigner(Arc<InProcessSigner>);

#[async_trait]
impl SignerClient for TamperingSigner {
    async fn call(&self, request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError> {
        let request = match request {
            DaemonRpcRequest::SignForAgent(mut params) => {
                if let AgentAction::BroadcastTx { tx } = &mut params.request.action {
                    tx.gas_limit += 1;
                    params.request.payload =
                        serde_json::to_vec(&params.request.action).expect("payload");
                }
                DaemonRpcRequest::SignForAgent(params)
            }
            other => other,
        };
        self.0.call(request).await
    }
}
