//! Wallet methods: `WalletSummary`, `WalletBalance`, `FundingRequest`, and
//! `Status` (ported from the TypeScript `wallet-profile`, `wallet-status`,
//! and the `prepare-funding-request` skill script). The wire contract is
//! documented on `agentpay_api::payments::{wallet, status}`.
//!
//! - this module: resolving configured token deployments ([`Target`]) and the
//!   agent's address for each;
//! - `balances`: parallel, time-boxed balance reads over the EVM and Solana
//!   providers;
//! - `funding`: EIP-681 / Solana Pay URIs and the gas hint;
//! - `qr`: the QR code as SVG and terminal text;
//! - `status`: the `Status` health report.
//!
//! Nothing here signs: these methods only read the chains (or, for
//! `FundingRequest`, nothing at all).

mod balances;
mod funding;
mod qr;
mod status;

#[cfg(test)]
mod tests;

use std::time::Duration;

use agentpay_api::payments::{
    ChainFamily, ChainProfile, PaymentsConfig, PaymentsRpcRequest as Req,
    PaymentsRpcResponse as Res, WalletAssetKind,
};

use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::state::AppState;

/// Time budgets for chain reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Connecting to a chain, including the chain id or cluster check.
    pub connect: Duration,
    /// One balance read.
    pub read: Duration,
    /// One `Status` chain check (connect and probe together).
    pub check: Duration,
}

impl Default for Budget {
    /// 10 s to connect, 10 s per balance, 5 s per status check.
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(10),
            check: Duration::from_secs(5),
        }
    }
}

/// Chain reads in flight at once.
const MAX_CONCURRENT_CHAINS: usize = 16;

/// Tempo chain ids: no native gas coin, so no native balance or gas hint.
const TEMPO_CHAIN_IDS: [u64; 2] = [4217, 42_431];

/// Handles the wallet methods.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: Req,
) -> Result<Res, PaymentsError> {
    handle_with(state, agent, request, Budget::default()).await
}

/// [`handle`] with explicit time budgets (tests use short ones).
pub(crate) async fn handle_with(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: Req,
    budget: Budget,
) -> Result<Res, PaymentsError> {
    match request {
        Req::WalletSummary(_) => balances::summary(state, agent, budget)
            .await
            .map(Res::WalletSummary),
        Req::WalletBalance(params) => balances::single(
            state,
            agent,
            params.network.as_deref(),
            params.asset.as_deref(),
            budget,
        )
        .await
        .map(Res::WalletBalance),
        Req::FundingRequest(params) => funding::request(state, agent, &params)
            .await
            .map(Res::FundingRequest),
        Req::Status(_) => Ok(Res::Status(status::report(state, agent, budget).await)),
        other => Err(PaymentsError::Internal(format!(
            "the wallet feature cannot handle {}",
            other.method_name()
        ))),
    }
}

/// One configured token deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// Chain key.
    pub network: String,
    /// The chain's configuration.
    pub chain: ChainProfile,
    /// Token key.
    pub asset: String,
    /// Ticker symbol.
    pub symbol: String,
    /// Contract address or mint; `None` for the native coin.
    pub token: Option<String>,
    /// Decimals.
    pub decimals: u8,
}

impl Target {
    /// The balance kind.
    pub fn kind(&self) -> WalletAssetKind {
        match (self.chain.family, &self.token) {
            (ChainFamily::Evm, None) => WalletAssetKind::Native,
            (ChainFamily::Evm, Some(_)) => WalletAssetKind::Erc20,
            (ChainFamily::Solana, None) => WalletAssetKind::Sol,
            (ChainFamily::Solana, Some(_)) => WalletAssetKind::Spl,
        }
    }

    /// Whether this is a Tempo chain's native "coin", which has no balance.
    fn is_tempo_native(&self) -> bool {
        self.token.is_none() && TEMPO_CHAIN_IDS.contains(&self.chain.chain_id)
    }
}

/// Every configured deployment, sorted by network, then asset.
pub(crate) fn all_targets(config: &PaymentsConfig) -> Vec<Target> {
    let mut targets: Vec<Target> = config
        .tokens
        .iter()
        .flat_map(|(asset, token)| {
            token
                .chains
                .iter()
                .filter_map(move |(network, deployment)| {
                    let chain = config.chains.get(network)?;
                    Some(Target {
                        network: network.clone(),
                        chain: chain.clone(),
                        asset: asset.clone(),
                        symbol: token.symbol.clone(),
                        token: (!deployment.is_native)
                            .then(|| deployment.address.clone())
                            .flatten(),
                        decimals: deployment.decimals,
                    })
                })
        })
        .collect();
    targets.sort_by(|a, b| (&a.network, &a.asset).cmp(&(&b.network, &b.asset)));
    targets
}

/// Resolves `network` (default `default_network`) and `asset` (default
/// `default_asset`): a token key, or the contract address or mint of a
/// configured deployment on that network.
pub(crate) fn resolve(
    config: &PaymentsConfig,
    network: Option<&str>,
    asset: Option<&str>,
) -> Result<Target, PaymentsError> {
    let network = network
        .map(|key| key.trim().to_ascii_lowercase())
        .unwrap_or_else(|| config.default_network.clone());
    if !config.chains.contains_key(&network) {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{}' is not configured",
            network.escape_default()
        )));
    }
    let asset = asset.map_or(config.default_asset.as_str(), str::trim);
    let key = asset.to_ascii_lowercase();
    let on_network = all_targets(config)
        .into_iter()
        .filter(|target| target.network == network);
    let mut matches = on_network.filter(|target| {
        target.asset == key
            || target
                .token
                .as_deref()
                .is_some_and(|token| match target.chain.family {
                    ChainFamily::Evm => token.eq_ignore_ascii_case(asset),
                    ChainFamily::Solana => token == asset,
                })
    });
    matches.next().ok_or_else(|| {
        if config.tokens.contains_key(&key) {
            PaymentsError::InvalidRequest(format!(
                "asset '{key}' has no deployment on network '{network}'"
            ))
        } else {
            PaymentsError::InvalidRequest(format!(
                "asset '{}' is not configured on network '{network}'",
                asset.escape_default()
            ))
        }
    })
}

/// The agent's address for `family`, or why there is none.
pub(crate) fn wallet_address(
    agent: &AuthenticatedAgent,
    family: ChainFamily,
) -> Result<String, PaymentsError> {
    match family {
        ChainFamily::Evm => agent
            .identity
            .evm_address
            .as_ref()
            .map(|address| address.as_str().to_string())
            .ok_or_else(|| {
                PaymentsError::InvalidRequest(
                    "the agent's vault key has no EVM address (it is an ed25519 key)".into(),
                )
            }),
        ChainFamily::Solana => agent
            .identity
            .solana_address
            .as_ref()
            .map(ToString::to_string)
            .ok_or_else(|| {
                PaymentsError::InvalidRequest(
                    "the agent's vault key cannot sign for Solana on this signer backend".into(),
                )
            }),
    }
}
