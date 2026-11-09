//! EVM methods: `Transfer`, `TransferNative`, `Approve`, `Broadcast`,
//! `SignTypedData`, `ResumeApproved`, and the `Rpc*` read helpers.
//!
//! The wire contract (defaults, pipeline, manual approval) is documented on
//! `agentpay_api::payments::evm`. Here:
//!
//! - `resolve`: networks, assets, amounts, and options against the configuration;
//! - `payments`: one function per payment method, plus `ResumeApproved`;
//! - `transaction`: plan → reserve nonce → sign → verify → send → receipt,
//!   and sign-only actions; holds pending approvals;
//! - `pending`: the stored actions `ResumeApproved` resends;
//! - `reads`: the read helpers.
//!
//! Chain access goes through [`EvmProvider`]; signatures through the
//! caller's [`AgentSigner`](crate::signer::AgentSigner), so the signer
//! daemon applies the agent's policies to everything.

mod payments;
mod pending;
mod reads;
mod resolve;
mod transaction;

#[cfg(test)]
mod tests;

use agentpay_api::payments::{
    EvmAsset, PaymentsConfig, PaymentsRpcRequest as Req, PaymentsRpcResponse as Res,
};
use alloy_primitives::Address;
use tokio::sync::OnceCell;

use crate::auth::AuthenticatedAgent;
use crate::chains::evm::{to_alloy_address, EvmProvider, EvmRpc};
use crate::error::PaymentsError;
use crate::state::AppState;
pub(crate) use resolve::{format_units, parse_amount};
use resolve::{AssetChoice, Network};

/// Handles the EVM methods.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: Req,
) -> Result<Res, PaymentsError> {
    match request {
        Req::Transfer(params) => payments::transfer(state, agent, params).await,
        Req::TransferNative(params) => payments::transfer_native(state, agent, params).await,
        Req::Approve(params) => payments::approve(state, agent, params).await,
        Req::Broadcast(params) => payments::broadcast(state, agent, params).await,
        Req::SignTypedData(params) => payments::sign_typed_data(state, agent, params).await,
        Req::ResumeApproved(params) => payments::resume(state, agent, params).await,
        Req::RpcChainInfo(params) | Req::RpcBlockNumber(params) => {
            reads::chain_info(state, agent, params).await
        }
        Req::RpcBalance(params) => reads::balance(state, agent, params).await,
        Req::RpcNonce(params) => reads::nonce(state, agent, params).await,
        Req::RpcFees(params) => reads::fees(state, agent, params).await,
        Req::RpcGasEstimate(params) => reads::gas_estimate(state, agent, params).await,
        Req::RpcTx(params) => reads::transaction(state, agent, params).await,
        Req::RpcReceipt(params) => reads::receipt(state, agent, params).await,
        Req::RpcCode(params) => reads::code(state, agent, params).await,
        other => Err(PaymentsError::Internal(format!(
            "the EVM feature cannot handle {}",
            other.method_name()
        ))),
    }
}

/// One request's view of an EVM network: a configuration snapshot, the
/// resolved network, and a lazily opened, chain-id-checked RPC connection.
struct Session<'a> {
    state: &'a AppState,
    agent: &'a AuthenticatedAgent,
    config: PaymentsConfig,
    network: Network,
    rpc: OnceCell<EvmRpc>,
}

impl<'a> Session<'a> {
    /// Resolves `network` (default: the configured default network).
    async fn open(
        state: &'a AppState,
        agent: &'a AuthenticatedAgent,
        network: Option<&str>,
    ) -> Result<Self, PaymentsError> {
        let config = state.config.get().await;
        let network = resolve::network(&config, network)?;
        Ok(Self {
            state,
            agent,
            config,
            network,
            rpc: OnceCell::new(),
        })
    }

    /// The RPC connection, opened (and its chain id checked) on first use.
    async fn rpc(&self) -> Result<&EvmRpc, PaymentsError> {
        self.rpc
            .get_or_try_init(|| async {
                let evm = self.state.chains.get::<EvmProvider>()?;
                evm.connect(&self.network.key, &self.network.chain).await
            })
            .await
    }

    /// The agent's wallet.
    fn wallet(&self) -> Result<Address, PaymentsError> {
        transaction::wallet(self.agent)
    }

    /// `address`, or the agent's wallet.
    fn account(
        &self,
        address: Option<&agentpay_domain::EvmAddress>,
    ) -> Result<Address, PaymentsError> {
        match address {
            Some(address) => to_alloy_address(address),
            None => self.wallet(),
        }
    }

    /// Resolves an asset; an unconfigured contract's metadata is read from
    /// the chain. The native coin is accepted only when `allow_native`.
    async fn asset(
        &self,
        requested: Option<&str>,
        allow_native: bool,
    ) -> Result<EvmAsset, PaymentsError> {
        match resolve::asset(&self.config, &self.network, requested)? {
            AssetChoice::Known(asset) if asset.token.is_none() && !allow_native => {
                Err(PaymentsError::InvalidRequest(format!(
                    "asset '{}' is the native coin of network '{}'; use TransferNative",
                    asset.key.as_deref().unwrap_or("native"),
                    self.network.key
                )))
            }
            AssetChoice::Known(asset) => Ok(asset),
            AssetChoice::Unconfigured(token) => {
                let rpc = self.rpc().await?;
                let address = to_alloy_address(&token)?;
                let decimals = rpc.erc20_decimals(address).await?;
                let symbol = rpc
                    .erc20_symbol(address)
                    .await
                    .unwrap_or_else(|| token.to_string());
                Ok(EvmAsset {
                    key: None,
                    symbol,
                    decimals,
                    token: Some(token),
                })
            }
        }
    }
}
