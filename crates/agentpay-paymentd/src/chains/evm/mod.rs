//! The EVM chain provider: alloy JSON-RPC clients for configured EVM chains,
//! and verification of signed transactions before they are sent.
//!
//! [`EvmProvider::connect`] turns a configured chain into an [`EvmRpc`]:
//!
//! - the chain must be an EVM chain with an `rpc_url`;
//! - the URL must be safe ([`check_rpc_url`]: `https`, or `http` to a
//!   loopback host, no embedded credentials), checked again here even though
//!   `SetConfig` already validated it;
//! - the HTTP client follows no redirects (a redirect could leave the vetted
//!   host) and times out after 30 seconds;
//! - `eth_chainId` must equal the configured chain id before any other call,
//!   so a misconfigured or hijacked endpoint for another chain is never used
//!   for nonces, fees, or broadcasting (the TypeScript `rpc-guard`);
//! - when that fails, the chain's `fallback_rpc_urls` are tried in order
//!   ([`Failover`]), and the returned [`EvmRpc`] says whether it uses a
//!   backup. Every later request, sends included, goes to that one endpoint.
//!
//! Several balances are read together with [`EvmRpc::balances`]: one
//! Multicall3 `aggregate3` where the chain has the contract, else one
//! JSON-RPC batch, else concurrent single calls (see `batch.rs`).
//!
//! Errors never quote the RPC URL: it may embed a provider API key.

mod batch;
#[cfg(test)]
mod batch_tests;
mod convert;
#[cfg(test)]
pub(crate) mod mock_rpc;
mod rpc;
mod verify;

use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{ChainFamily, ChainProfile};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_client::RpcClient;
use alloy_transport_http::Http;

pub use batch::{BalanceQuery, MULTICALL3_CHAIN_IDS};
pub use convert::{evm_address, hex_prefixed, parse_calldata, parse_tx_hash, to_alloy_address};
pub use rpc::{EvmRpc, FeeEstimate, SendFailure, RECEIPT_POLL_INTERVAL};
pub use verify::{verify_signed_transaction, VerifiedTransaction};

use super::failover::{Clock, Failover};
use super::ChainProvider;
use crate::config::check_rpc_url;
use crate::error::PaymentsError;

/// Timeout of one RPC request, including `eth_sendRawTransaction`.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for establishing the connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// RPC access to the configured EVM chains.
pub struct EvmProvider {
    /// Shared HTTP client (connection pool); `None` if it could not be built.
    http: Option<reqwest::Client>,
    /// Which chains have Multicall3, kept for the service's lifetime.
    multicall: Arc<batch::MulticallSupport>,
    /// Which endpoint of each network is preferred after a failover.
    failover: Failover,
}

impl ChainProvider for EvmProvider {
    const FAMILY: ChainFamily = ChainFamily::Evm;
}

impl Default for EvmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EvmProvider {
    /// A provider with a shared HTTP client. Never fails: if the client
    /// cannot be built, every [`connect`](Self::connect) fails instead.
    #[must_use]
    pub fn new() -> Self {
        Self::with_failover(Failover::default())
    }

    /// A provider whose endpoint preferences expire by `clock` (tests).
    #[must_use]
    pub fn with_clock(clock: Clock) -> Self {
        Self::with_failover(Failover::with_clock(clock))
    }

    fn with_failover(failover: Failover) -> Self {
        let http = reqwest::Client::builder()
            .timeout(RPC_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok();
        Self {
            http,
            multicall: Arc::default(),
            failover,
        }
    }

    /// Connects to the chain `network` (its key in the configuration) and
    /// checks that the endpoint serves `chain.chain_id`: `rpc_url`, else the
    /// first of `fallback_rpc_urls` that does (see [`Failover`]).
    pub async fn connect(
        &self,
        network: &str,
        chain: &ChainProfile,
    ) -> Result<EvmRpc, PaymentsError> {
        if chain.family != ChainFamily::Evm {
            return Err(PaymentsError::InvalidRequest(format!(
                "network '{network}' is not an EVM chain"
            )));
        }
        let primary = chain.rpc_url.clone().ok_or_else(|| {
            PaymentsError::InvalidRequest(format!("network '{network}' has no rpc_url configured"))
        })?;
        let endpoints: Vec<String> = std::iter::once(primary)
            .chain(chain.fallback_rpc_urls.iter().cloned())
            .collect();
        let connected = self
            .failover
            .connect(network, chain.chain_id, &endpoints, |index| {
                self.connect_one(network, chain.chain_id, &endpoints[index], index)
            })
            .await?;
        Ok(connected.value.on_backup(connected.backup))
    }

    /// Connects to one endpoint (`index` 0 is `rpc_url`) and checks its chain id.
    async fn connect_one(
        &self,
        network: &str,
        chain_id: u64,
        url: &str,
        index: usize,
    ) -> Result<EvmRpc, PaymentsError> {
        let field = match index {
            0 => "rpc_url".to_string(),
            n => format!("fallback_rpc_urls[{}]", n - 1),
        };
        check_rpc_url(url).map_err(|reason| {
            PaymentsError::InvalidRequest(format!("network '{network}' {field} {reason}"))
        })?;
        let url = url::Url::parse(url).map_err(|_| {
            PaymentsError::InvalidRequest(format!("network '{network}' {field} is not a valid URL"))
        })?;
        let http = self
            .http
            .clone()
            .ok_or_else(|| PaymentsError::Internal("the HTTP client is unavailable".into()))?;
        let is_local = url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        let client = RpcClient::new(Http::with_client(http, url), is_local);
        let provider = RootProvider::new(client).erased();
        let rpc = EvmRpc::new(provider, network, chain_id, self.multicall.clone());
        rpc.check_chain_id().await?;
        Ok(rpc)
    }
}

#[cfg(test)]
mod tests;
