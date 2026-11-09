//! `Status`: the service's health as seen by the calling agent (ported from
//! the TypeScript `wallet-status`, minus the checks that moved into
//! `agentpay-setup`: binaries, sockets, and file permissions).

use std::sync::Arc;

use agentpay_api::payments::{
    AgentStatus, ChainStatus, ConfigStatus, PaymentsConfig, ServiceStatus, SignerStatus,
    StatusResult, StatusWarning, StatusWarningCode,
};
use agentpay_api::{
    AgentPolicySummary, ApiVersion, DaemonRpcRequest, DaemonRpcResponse, WirePaymentsError,
    API_VERSION,
};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::balances::{within, Connection, Providers};
use super::{Budget, Target, MAX_CONCURRENT_CHAINS};
use crate::auth::AuthenticatedAgent;
use crate::config::validate;
use crate::error::PaymentsError;
use crate::state::{AppState, SERVICE_VERSION};

/// Builds the report; every failed check becomes a field or a warning.
pub(super) async fn report(
    state: &AppState,
    agent: &AuthenticatedAgent,
    budget: Budget,
) -> StatusResult {
    let config = state.config.get().await;
    let agent_signer = agent.signer(state.signer.as_ref());
    let (signer, policies, chains) = tokio::join!(
        signer_status(state),
        agent_signer.policy_summary(),
        chain_statuses(state, &config, budget),
    );
    let mut warnings = Vec::new();
    let warn = |code, message: String, network: Option<String>| StatusWarning {
        code,
        message,
        network,
    };
    if !signer.reachable {
        warnings.push(warn(
            StatusWarningCode::SignerUnavailable,
            "the signer daemon did not answer Hello".into(),
            None,
        ));
    } else if !signer.compatible {
        warnings.push(warn(
            StatusWarningCode::SignerIncompatible,
            format!(
                "the signer daemon speaks API {}, this service {API_VERSION}",
                signer.api_version.as_deref().unwrap_or("unknown")
            ),
            None,
        ));
    }
    let config_status = config_status(&config);
    if let Some(error) = &config_status.error {
        warnings.push(warn(StatusWarningCode::InvalidConfig, error.clone(), None));
    }
    let policies = policies.ok();
    let can_spend = policies
        .as_ref()
        .is_some_and(|summary: &AgentPolicySummary| summary.spending_policy_count > 0);
    match &policies {
        None => warnings.push(warn(
            StatusWarningCode::PolicyStatusUnavailable,
            "the signer daemon could not report this agent's policies".into(),
            None,
        )),
        Some(_) if !can_spend => warnings.push(warn(
            StatusWarningCode::NoSpendingPolicy,
            "agent cannot spend until limits are set: no spending policy applies to it".into(),
            None,
        )),
        Some(_) => {}
    }
    if config
        .chains
        .get(&config.default_network)
        .is_some_and(|chain| chain.rpc_url.is_none())
    {
        warnings.push(warn(
            StatusWarningCode::DefaultNetworkUnconfigured,
            format!(
                "the default network '{}' has no rpc_url",
                config.default_network
            ),
            Some(config.default_network.clone()),
        ));
    }
    for chain in chains.iter().filter(|chain| chain.reachable == Some(false)) {
        warnings.push(warn(
            StatusWarningCode::ChainUnreachable,
            format!(
                "network '{}' did not answer as the configured chain",
                chain.network
            ),
            Some(chain.network.clone()),
        ));
    }
    let identity = &agent.identity;
    if identity.evm_address.is_none() {
        warnings.push(warn(
            StatusWarningCode::NoEvmAddress,
            "the vault key has no EVM address".into(),
            None,
        ));
    }
    if identity.solana_address.is_none() {
        warnings.push(warn(
            StatusWarningCode::NoSolanaAddress,
            "the signer backend cannot sign for Solana".into(),
            None,
        ));
    }
    StatusResult {
        service: ServiceStatus {
            api_version: API_VERSION.to_string(),
            service_version: SERVICE_VERSION.to_string(),
        },
        signer,
        agent: AgentStatus {
            agent_key_id: identity.agent_key.id,
            vault_key_id: identity.vault_key.id,
            algorithm: identity.vault_key.algorithm,
            evm_address: identity.evm_address.clone(),
            solana_address: identity.solana_address.clone(),
        },
        config: config_status,
        chains,
        policies,
        can_spend,
        telemetry_enabled: state.telemetry.is_enabled(),
        warnings,
    }
}

/// The signer daemon's `Hello`.
async fn signer_status(state: &AppState) -> SignerStatus {
    let hello = match state.signer.call(DaemonRpcRequest::Hello).await {
        Ok(DaemonRpcResponse::Hello(hello)) => Some(hello),
        _ => None,
    };
    let compatible = hello
        .as_ref()
        .and_then(|hello| ApiVersion::parse(&hello.api_version))
        .is_some_and(|theirs| ApiVersion::CURRENT.is_compatible_with(&theirs));
    SignerStatus {
        reachable: hello.is_some(),
        api_version: hello.as_ref().map(|hello| hello.api_version.clone()),
        daemon_version: hello.map(|hello| hello.daemon_version),
        compatible,
    }
}

fn config_status(config: &PaymentsConfig) -> ConfigStatus {
    let error = validate(config).err();
    ConfigStatus {
        valid: error.is_none(),
        error,
        default_network: config.default_network.clone(),
        default_asset: config.default_asset.clone(),
        chain_count: u32::try_from(config.chains.len()).unwrap_or(u32::MAX),
        token_count: u32::try_from(config.tokens.len()).unwrap_or(u32::MAX),
    }
}

/// Checks every configured chain in parallel, each within `budget.check`.
async fn chain_statuses(
    state: &AppState,
    config: &PaymentsConfig,
    budget: Budget,
) -> Vec<ChainStatus> {
    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CHAINS));
    let mut tasks = JoinSet::new();
    let mut statuses = Vec::new();
    for (network, chain) in &config.chains {
        let status = ChainStatus {
            network: network.clone(),
            chain_id: chain.chain_id,
            chain_name: chain.name.clone(),
            family: chain.family,
            rpc_configured: chain.rpc_url.is_some(),
            reachable: None,
            block_number: None,
            using_backup_rpc: false,
            error: None,
        };
        if chain.rpc_url.is_none() {
            statuses.push(status);
            continue;
        }
        let target = Target {
            network: network.clone(),
            chain: chain.clone(),
            asset: String::new(),
            symbol: String::new(),
            token: None,
            decimals: 0,
        };
        let providers = Providers::from_state(state);
        let limit = limit.clone();
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            let probe = within(
                budget.check,
                &target.network,
                probe(&providers, &target, budget),
            );
            let result = probe.await;
            ChainStatus {
                reachable: Some(result.is_ok()),
                block_number: result.as_ref().ok().and_then(|(block, _)| *block),
                using_backup_rpc: result.as_ref().is_ok_and(|(_, backup)| *backup),
                error: result.err().map(WirePaymentsError::from),
                ..status
            }
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok(status) = joined {
            statuses.push(status);
        }
    }
    statuses.sort_by(|a, b| a.network.cmp(&b.network));
    statuses
}

/// Connects (chain id or cluster check, with failover to the chain's
/// backups) and makes one cheap read: the latest block on EVM chains, a
/// recent blockhash on Solana. Also returns whether a backup answered.
async fn probe(
    providers: &Providers,
    target: &Target,
    budget: Budget,
) -> Result<(Option<u64>, bool), PaymentsError> {
    match providers.connect(target, budget.check).await? {
        Connection::Evm(rpc) => {
            let block = rpc.block_number().await?;
            Ok((Some(block), rpc.using_backup()))
        }
        Connection::Solana(rpc) => {
            rpc.latest_blockhash().await?;
            Ok((None, rpc.using_backup()))
        }
    }
}
