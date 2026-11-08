//! `Activity`: the calling agent's recent payments and approval requests,
//! from the signer daemon's `AgentActivity`, with the network, symbol,
//! decimals, and a human-readable amount added from the configuration. The
//! wire contract is documented on `agentpay_api::payments::activity`.

use agentpay_api::payments::{
    ActivityApproval, ActivityAsset, ActivityParams, ActivityResult, ActivitySpend, PaymentsConfig,
    PaymentsRpcRequest, PaymentsRpcResponse, TokenChainProfile,
};
use agentpay_domain::{canonical_policy_chain_id, AssetId};
use alloy_primitives::U256;

use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::features::evm::format_units;
use crate::state::AppState;

/// Handles `Activity`.
pub async fn handle(
    state: &AppState,
    agent: &AuthenticatedAgent,
    request: PaymentsRpcRequest,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let PaymentsRpcRequest::Activity(ActivityParams { since, limit, .. }) = request else {
        return Err(PaymentsError::Internal(format!(
            "the activity feature cannot handle {}",
            request.method_name()
        )));
    };
    let report = agent
        .signer(state.signer.as_ref())
        .activity(since, limit)
        .await?;
    let config = state.config.get().await;
    Ok(PaymentsRpcResponse::Activity(ActivityResult {
        agent_key_id: report.agent_key_id,
        spends: report
            .spends
            .into_iter()
            .map(|spend| ActivitySpend {
                labels: labels(&config, spend.chain_id, &spend.asset, spend.amount_wei),
                spend,
            })
            .collect(),
        approvals: report
            .approvals
            .into_iter()
            .map(|request| ActivityApproval {
                labels: labels(
                    &config,
                    request.chain_id,
                    &request.asset,
                    request.amount_wei,
                ),
                request,
            })
            .collect(),
        as_of: report.as_of,
    }))
}

/// The configured network, symbol, decimals, and whole-token amount of an
/// entry.
///
/// Networks are tried in this order: chains with exactly `chain_id`, then
/// chains on the same policy network (every Solana cluster shares
/// `900000001`), each in key order. The first that has the asset configured
/// labels the entry; when none does, the first candidate names the network
/// and the token labels stay `null`.
pub(crate) fn labels(
    config: &PaymentsConfig,
    chain_id: u64,
    asset: &AssetId,
    amount_wei: u128,
) -> ActivityAsset {
    let policy_network = canonical_policy_chain_id(chain_id);
    let exact = config
        .chains
        .iter()
        .filter(|(_, chain)| chain.chain_id == chain_id);
    let same_network = config.chains.iter().filter(|(_, chain)| {
        chain.chain_id != chain_id && canonical_policy_chain_id(chain.chain_id) == policy_network
    });
    let candidates: Vec<&String> = exact.chain(same_network).map(|(key, _)| key).collect();
    for network in &candidates {
        let found = config.tokens.values().find_map(|token| {
            let deployment = token.chains.get(*network)?;
            deploys(deployment, asset).then_some((token.symbol.clone(), deployment.decimals))
        });
        if let Some((symbol, decimals)) = found {
            return ActivityAsset {
                network: Some((*network).clone()),
                symbol: Some(symbol),
                decimals: Some(decimals),
                amount: Some(format_units(U256::from(amount_wei), decimals)),
            };
        }
    }
    ActivityAsset {
        network: candidates.first().map(|network| (*network).clone()),
        ..ActivityAsset::default()
    }
}

/// Whether `deployment` is `asset`.
fn deploys(deployment: &TokenChainProfile, asset: &AssetId) -> bool {
    let address = deployment.address.as_deref();
    match asset {
        AssetId::NativeEth | AssetId::NativeSol => deployment.is_native,
        AssetId::Erc20(token) => {
            !deployment.is_native && address.is_some_and(|a| a.eq_ignore_ascii_case(token.as_str()))
        }
        AssetId::SplToken(mint) => !deployment.is_native && address == Some(mint.as_str()),
    }
}
