//! `MppFetch` end to end against a mock MPP merchant built from `mpp`'s own
//! protocol code: it issues challenges with `PaymentChallenge` and
//! `format_www_authenticate`, parses credentials with `parse_authorization`,
//! and verifies them offline with `mpp`'s verifiers (attribution memos,
//! TIP-1034 channel ids and voucher signatures, the `0x78` fee-payer
//! envelope) plus `tempo-alloy` transaction decoding. Signatures come from a
//! real in-memory signer daemon with policies; chain calls go to the
//! loopback mock RPC.

mod charge;
mod evm;
pub(crate) mod merchant;
mod ranking;
mod session;
mod solana;

use std::sync::Arc;

use agentpay_api::payments::{
    HttpRequest, MppFetchParams, MppFetchResult, PaymentsRpcRequest as Req,
    PaymentsRpcResponse as Res,
};
use agentpay_api::AgentAuth;
use agentpay_domain::SpendingPolicy;
use alloy_primitives::Address;

use crate::chains::evm::mock_rpc::MockRpc;
use crate::config::{default_config, ConfigStore};
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::signer::testing::{per_tx_limit, InProcessSigner};
use crate::signer::AgentSigner;
use crate::state::AppState;
use crate::test_support::TempDir;

/// Tempo Moderato.
pub(crate) const CHAIN_ID: u64 = 42_431;
/// pathUSD.
pub(crate) const PATH_USD: &str = "0x20c0000000000000000000000000000000000000";
/// The merchant.
pub(crate) const RECIPIENT: &str = "0x742d35cc6634c0532925a3b844bc9e7595f8fe00";

/// paymentd state with an in-memory signer daemon and a mock Moderato RPC.
pub(crate) struct Harness {
    dir: TempDir,
    pub(crate) state: AppState,
    pub(crate) auth: AgentAuth,
    pub(crate) wallet: Address,
    pub(crate) rpc: Arc<MockRpc>,
}

impl Harness {
    pub(crate) async fn new(policies: Vec<SpendingPolicy>) -> Self {
        let (signer, auth) = InProcessSigner::with_agent(policies).await;
        let wallet = AgentSigner::new(&signer, &auth)
            .identity()
            .await
            .expect("identity")
            .evm_address
            .expect("evm wallet")
            .to_string()
            .parse()
            .expect("address");
        let dir = TempDir::new("mpp");
        let rpc = Arc::new(MockRpc::start(CHAIN_ID).await);
        let state = AppState::new(
            ConfigStore::open(dir.path()).expect("config"),
            Arc::new(signer),
        );
        let mut config = default_config();
        for chain in config.chains.values_mut() {
            if chain.chain_id == CHAIN_ID {
                chain.rpc_url = Some(rpc.url().to_string());
                chain.fallback_rpc_urls.clear();
            }
        }
        state.config.set(config).await.expect("set config");
        Self {
            dir,
            state,
            auth,
            wallet,
            rpc,
        }
    }

    /// Adds a configured EVM network `key` with `chain_id`, served by a new
    /// mock RPC.
    pub(super) async fn add_evm_chain(&self, key: &str, chain_id: u64) -> Arc<MockRpc> {
        let rpc = Arc::new(MockRpc::start(chain_id).await);
        let mut config = self.state.config.get().await;
        config.chains.insert(
            key.into(),
            agentpay_api::payments::ChainProfile {
                chain_id,
                name: key.into(),
                family: agentpay_api::payments::ChainFamily::Evm,
                rpc_url: Some(rpc.url().to_string()),
                fallback_rpc_urls: Vec::new(),
            },
        );
        self.state.config.set(config).await.expect("set config");
        rpc
    }

    /// The state directory.
    pub(super) fn dir(&self) -> &std::path::Path {
        self.dir.path()
    }

    /// A harness whose agent may spend anything.
    pub(crate) async fn open() -> Self {
        Self::new(vec![per_tx_limit(u128::MAX)]).await
    }

    /// `MppFetch` parameters for `url`.
    pub(super) fn params(&self, url: String) -> MppFetchParams {
        MppFetchParams {
            auth: self.auth.clone(),
            request: HttpRequest {
                url,
                method: None,
                headers: Vec::new(),
                body: None,
            },
            amount: None,
            deposit: None,
            max_deposit: None,
            currency: None,
            network: None,
            session_key: None,
            close_session: false,
            approval_wait_secs: None,
        }
    }

    pub(super) async fn fetch(
        &self,
        params: MppFetchParams,
    ) -> Result<MppFetchResult, PaymentsError> {
        match dispatch(&self.state, Req::MppFetch(params)).await? {
            Res::MppResponse(result) => Ok(result),
            other => panic!("unexpected response {other:?}"),
        }
    }
}
