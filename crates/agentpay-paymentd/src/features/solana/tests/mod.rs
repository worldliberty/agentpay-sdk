//! `TransferSol` / `TransferSpl` end to end inside paymentd: requests go
//! through [`crate::dispatch`], signatures come from a real in-memory signer
//! daemon (with policies and manual approvals), and the chain is a
//! [`FakeCluster`].

mod approval;
mod examples;
mod sol;
mod spl;

use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{
    ManualApprovalPendingResult, PaymentsRpcRequest, PaymentsRpcResponse, SolanaAmount,
    SolanaTransferOptions, SolanaTransferResult, TransferSolParams, TransferSplParams,
};
use agentpay_api::AgentAuth;
use agentpay_domain::{AdminAuth, ManualApprovalDecision, SpendingPolicy, SOLANA_DEVNET_CHAIN_ID};
use agentpay_signerd::KeyManagerDaemonApi;
use base64::Engine as _;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;
use uuid::Uuid;

use crate::auth::{authenticate, AuthenticatedAgent};
use crate::chains::solana::accounts::managed_nonce_account;
use crate::chains::solana::testing::FakeCluster;
use crate::chains::solana::SolanaProvider;
use crate::config::ConfigStore;
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::signer::testing::InProcessSigner;
use crate::signer::{ApprovalWait, SignerClient};
use crate::state::AppState;
use crate::test_support::TempDir;

/// The configured chain key of the fake cluster.
const NETWORK: &str = "solana-devnet";

pub(super) struct Harness {
    pub(super) state: AppState,
    pub(super) cluster: FakeCluster,
    pub(super) signer: Arc<InProcessSigner>,
    pub(super) auth: AgentAuth,
    pub(super) wallet: Pubkey,
    _dir: TempDir,
}

impl Harness {
    /// An agent with `policies` and a devnet fake cluster.
    pub(super) async fn new(policies: Vec<SpendingPolicy>) -> Self {
        Self::with_signer(policies, |signer| signer).await
    }

    /// Like [`new`](Self::new), with paymentd talking to signerd through `wrap`.
    pub(super) async fn with_signer(
        policies: Vec<SpendingPolicy>,
        wrap: impl FnOnce(Arc<InProcessSigner>) -> Arc<dyn SignerClient>,
    ) -> Self {
        let dir = TempDir::new("sol");
        let (signer, auth) = InProcessSigner::with_agent(policies).await;
        let signer = Arc::new(signer);
        let mut state = AppState::new(
            ConfigStore::open(dir.path()).expect("config"),
            wrap(signer.clone()),
        );
        let cluster = FakeCluster::devnet();
        state.chains.register(Arc::new(cluster.provider()));
        state.approval_wait = ApprovalWait {
            max_wait: Duration::ZERO,
            initial_interval: Duration::from_millis(5),
            max_interval: Duration::from_millis(10),
        };
        let identity = authenticate(signer.as_ref(), &auth)
            .await
            .expect("authenticated")
            .identity;
        let wallet = identity
            .solana_address
            .expect("software keys sign for Solana")
            .to_string()
            .parse()
            .expect("pubkey");
        Self {
            state,
            cluster,
            signer,
            auth,
            wallet,
            _dir: dir,
        }
    }

    pub(super) async fn agent(&self) -> AuthenticatedAgent {
        authenticate(self.signer.as_ref(), &self.auth)
            .await
            .expect("authenticated")
    }

    pub(super) fn provider(&self) -> Arc<SolanaProvider> {
        self.state.chains.get::<SolanaProvider>().expect("provider")
    }

    /// The agent's managed nonce account on the fake devnet.
    pub(super) fn managed_nonce(&self) -> Pubkey {
        managed_nonce_account(&self.wallet, SOLANA_DEVNET_CHAIN_ID)
            .expect("derive")
            .address
    }

    pub(super) async fn sol(
        &self,
        to: Pubkey,
        amount: SolanaAmount,
        options: SolanaTransferOptions,
    ) -> Result<PaymentsRpcResponse, PaymentsError> {
        dispatch(
            &self.state,
            PaymentsRpcRequest::TransferSol(TransferSolParams {
                auth: self.auth.clone(),
                network: NETWORK.into(),
                to: address(&to),
                amount,
                options,
            }),
        )
        .await
    }

    pub(super) async fn spl(
        &self,
        mint: Pubkey,
        to: Pubkey,
        amount: SolanaAmount,
        options: SolanaTransferOptions,
    ) -> Result<PaymentsRpcResponse, PaymentsError> {
        dispatch(
            &self.state,
            PaymentsRpcRequest::TransferSpl(TransferSplParams {
                auth: self.auth.clone(),
                network: NETWORK.into(),
                mint: address(&mint),
                to: address(&to),
                amount,
                options,
            }),
        )
        .await
    }

    /// Decides `id` as the operator.
    pub(super) async fn decide(&self, id: Uuid, decision: ManualApprovalDecision) {
        self.signer
            .daemon
            .decide_manual_approval_request(&AdminAuth::PeerCredentials, id, decision, None)
            .await
            .expect("decided");
    }
}

/// A per-transaction limit no test reaches.
pub(super) fn allow_all() -> Vec<SpendingPolicy> {
    vec![crate::signer::testing::per_tx_limit(u128::from(u64::MAX))]
}

pub(super) fn address(pubkey: &Pubkey) -> agentpay_domain::SolanaAddress {
    pubkey.to_string().parse().expect("address")
}

pub(super) fn lamports(amount: u128) -> SolanaAmount {
    SolanaAmount::BaseUnits(amount)
}

pub(super) fn broadcast() -> SolanaTransferOptions {
    SolanaTransferOptions {
        broadcast: true,
        ..SolanaTransferOptions::default()
    }
}

pub(super) fn done(response: Result<PaymentsRpcResponse, PaymentsError>) -> SolanaTransferResult {
    match response {
        Ok(PaymentsRpcResponse::SolanaTransfer(result)) => result,
        other => panic!("expected SolanaTransfer, got {other:?}"),
    }
}

pub(super) fn pending(
    response: Result<PaymentsRpcResponse, PaymentsError>,
) -> ManualApprovalPendingResult {
    match response {
        Ok(PaymentsRpcResponse::ManualApprovalPending(pending)) => pending,
        other => panic!("expected ManualApprovalPending, got {other:?}"),
    }
}

pub(super) fn invalid(response: Result<PaymentsRpcResponse, PaymentsError>) -> String {
    match response {
        Err(PaymentsError::InvalidRequest(reason)) => reason,
        other => panic!("expected InvalidRequest, got {other:?}"),
    }
}

pub(super) fn decode(raw_tx_base64: &str) -> Transaction {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_tx_base64)
        .expect("base64");
    bincode::deserialize(&bytes).expect("transaction")
}
