//! Balance reads for `WalletSummary` and `WalletBalance`.
//!
//! Every chain is read in its own task (at most
//! [`MAX_CONCURRENT_CHAINS`](super::MAX_CONCURRENT_CHAINS) at once): connect
//! (with the provider's chain id or cluster check) within `budget.connect`,
//! then read all balances of that chain together within `budget.read`:
//!
//! - EVM: [`EvmRpc::balances`], one Multicall3 `eth_call` where the chain
//!   has the contract, else one JSON-RPC batch, else concurrent single calls;
//! - Solana: one `getMultipleAccounts` for the wallet and every mint, then
//!   one for every associated token account.
//!
//! A failure only marks the entries it affects.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{ChainFamily, WalletBalanceEntry, WalletSummaryResult};
use agentpay_api::WirePaymentsError;
use agentpay_domain::EvmAddress;
use alloy_primitives::U256;
use solana_sdk::account::Account;
use solana_sdk::pubkey::Pubkey;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::{all_targets, resolve, wallet_address, Budget, Target, MAX_CONCURRENT_CHAINS};
use crate::auth::AuthenticatedAgent;
use crate::chains::evm::{to_alloy_address, BalanceQuery, EvmProvider, EvmRpc};
use crate::chains::solana::accounts::{associated_token_account, token_program_id};
use crate::chains::solana::{SolanaChain, SolanaProvider, SolanaRpc};
use crate::error::PaymentsError;
use crate::features::evm::format_units;
use crate::state::AppState;
use agentpay_domain::SolanaTokenProgram;

/// Offset and length of `amount` in an SPL Token (and Token-2022) account.
const TOKEN_AMOUNT_RANGE: std::ops::Range<usize> = 64..72;

/// An open connection to one chain.
#[derive(Clone)]
pub(super) enum Connection {
    Evm(Arc<EvmRpc>),
    Solana(SolanaRpc),
}

/// `WalletSummary`.
pub(super) async fn summary(
    state: &AppState,
    agent: &AuthenticatedAgent,
    budget: Budget,
) -> Result<WalletSummaryResult, PaymentsError> {
    let config = state.config.get().await;
    let mut by_network: BTreeMap<String, Vec<(Target, String)>> = BTreeMap::new();
    for target in all_targets(&config) {
        if target.chain.rpc_url.is_none() || target.is_tempo_native() {
            continue;
        }
        let Ok(address) = wallet_address(agent, target.chain.family) else {
            continue;
        };
        by_network
            .entry(target.network.clone())
            .or_default()
            .push((target, address));
    }

    let limit = Arc::new(Semaphore::new(MAX_CONCURRENT_CHAINS));
    let mut tasks = JoinSet::new();
    for (network, targets) in by_network {
        let providers = Providers::from_state(state);
        let limit = limit.clone();
        tasks.spawn(async move {
            let _permit = limit.acquire_owned().await;
            read_network(&providers, &network, targets, budget).await
        });
    }
    let mut balances = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let reads = joined.map_err(|_| PaymentsError::Internal("a balance task failed".into()))?;
        balances.extend(reads.into_iter().map(entry));
    }
    balances.sort_by(|a, b| (&a.network, &a.asset).cmp(&(&b.network, &b.asset)));
    Ok(WalletSummaryResult {
        agent_key_id: agent.identity.agent_key.id,
        evm_address: agent.identity.evm_address.clone(),
        solana_address: agent.identity.solana_address.clone(),
        default_network: config.default_network,
        default_asset: config.default_asset,
        balances,
    })
}

/// `WalletBalance`: one balance; a failed read fails the call.
pub(super) async fn single(
    state: &AppState,
    agent: &AuthenticatedAgent,
    network: Option<&str>,
    asset: Option<&str>,
    budget: Budget,
) -> Result<WalletBalanceEntry, PaymentsError> {
    let config = state.config.get().await;
    let target = resolve(&config, network, asset)?;
    if target.is_tempo_native() {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{}' has no native coin balance; fees are paid in its stablecoins",
            target.network
        )));
    }
    let address = wallet_address(agent, target.chain.family)?;
    let providers = Providers::from_state(state);
    let network = target.network.clone();
    let mut reads = read_network(&providers, &network, vec![(target, address)], budget).await;
    let (target, address, result) = reads
        .pop()
        .ok_or_else(|| PaymentsError::Internal("no balance was read".into()))?;
    Ok(entry((target, address, Ok(result?))))
}

/// The providers a balance task needs, owned so tasks can be spawned.
#[derive(Clone)]
pub(super) struct Providers {
    pub(super) evm: Option<Arc<EvmProvider>>,
    pub(super) solana: Option<Arc<SolanaProvider>>,
}

impl Providers {
    pub(super) fn from_state(state: &AppState) -> Self {
        Self {
            evm: state.chains.get::<EvmProvider>().ok(),
            solana: state.chains.get::<SolanaProvider>().ok(),
        }
    }

    /// Connects to `target`'s chain within `limit`.
    pub(super) async fn connect(
        &self,
        target: &Target,
        limit: Duration,
    ) -> Result<Connection, PaymentsError> {
        let connect = async {
            match target.chain.family {
                ChainFamily::Evm => {
                    let evm = self.evm.as_ref().ok_or_else(no_provider)?;
                    let rpc = evm.connect(&target.network, &target.chain).await?;
                    Ok(Connection::Evm(Arc::new(rpc)))
                }
                ChainFamily::Solana => {
                    let solana = self.solana.as_ref().ok_or_else(no_provider)?;
                    let rpc_url = target.chain.rpc_url.clone().ok_or_else(|| {
                        PaymentsError::InvalidRequest(format!(
                            "network '{}' has no rpc_url configured",
                            target.network
                        ))
                    })?;
                    let chain = SolanaChain {
                        key: target.network.clone(),
                        chain_id: target.chain.chain_id,
                        rpc_url,
                        fallback_rpc_urls: target.chain.fallback_rpc_urls.clone(),
                    };
                    Ok(Connection::Solana(solana.rpc(&chain).await?))
                }
            }
        };
        within(limit, &target.network, connect).await
    }
}

/// One read: the deployment, the wallet address, and the balance in base units.
type Read = (Target, String, Result<U256, PaymentsError>);

/// Reads every balance of one network: connect within `budget.connect`, then
/// read them all together within `budget.read`.
async fn read_network(
    providers: &Providers,
    network: &str,
    targets: Vec<(Target, String)>,
    budget: Budget,
) -> Vec<Read> {
    let Some((first, _)) = targets.first() else {
        return Vec::new();
    };
    let results = match providers.connect(first, budget.connect).await {
        Ok(connection) => {
            let read = async {
                Ok(match &connection {
                    Connection::Evm(rpc) => evm_balances(rpc, &targets).await,
                    Connection::Solana(rpc) => solana_balances(rpc, &targets).await,
                })
            };
            within(budget.read, network, read).await
        }
        Err(error) => Err(error),
    };
    let results = match results {
        Ok(results) if results.len() == targets.len() => results,
        Ok(_) => vec![Err(PaymentsError::Internal("a balance read failed".into())); targets.len()],
        Err(error) => vec![Err(error); targets.len()],
    };
    targets
        .into_iter()
        .zip(results)
        .map(|((target, address), result)| (target, address, result))
        .collect()
}

/// The EVM balances of `targets`, in order, through [`EvmRpc::balances`]
/// (Multicall3, else one JSON-RPC batch, else single calls).
async fn evm_balances(
    rpc: &EvmRpc,
    targets: &[(Target, String)],
) -> Vec<Result<U256, PaymentsError>> {
    let queries: Vec<Result<BalanceQuery, PaymentsError>> = targets
        .iter()
        .map(|(target, address)| {
            let token = target
                .token
                .as_deref()
                .map(|token| {
                    EvmAddress::from_str(token)
                        .map_err(|_| {
                            PaymentsError::InvalidRequest(format!(
                                "asset '{}' has an invalid contract address",
                                target.asset
                            ))
                        })
                        .and_then(|token| to_alloy_address(&token))
                })
                .transpose()?;
            Ok(BalanceQuery {
                owner: evm_account(address)?,
                token,
            })
        })
        .collect();
    let valid: Vec<BalanceQuery> = queries.iter().filter_map(|q| q.clone().ok()).collect();
    let mut read = rpc.balances(&valid).await.into_iter();
    queries
        .into_iter()
        .map(|query| {
            query.and_then(|_| {
                read.next()
                    .unwrap_or_else(|| Err(PaymentsError::Internal("a balance read failed".into())))
            })
        })
        .collect()
}

/// The Solana balances of `targets`, in order: one `getMultipleAccounts`
/// for every wallet and mint, then one for every associated token account.
async fn solana_balances(
    rpc: &SolanaRpc,
    targets: &[(Target, String)],
) -> Vec<Result<U256, PaymentsError>> {
    // What each target needs: its wallet (SOL) or its wallet and mint (SPL).
    let parsed: Vec<Result<(Pubkey, Option<Pubkey>), PaymentsError>> = targets
        .iter()
        .map(|(target, address)| {
            let owner = solana_account(address)?;
            let mint = target.token.as_deref().map(solana_account).transpose()?;
            Ok((owner, mint))
        })
        .collect();
    let first: Vec<Pubkey> = parsed
        .iter()
        .flatten()
        .map(|(owner, mint)| mint.unwrap_or(*owner))
        .collect();
    let first = match fetch(rpc, &first).await {
        Ok(accounts) => accounts,
        Err(error) => return vec![Err(error); targets.len()],
    };

    // SOL balances, and the associated token account of each SPL target.
    let mut token_accounts = Vec::new();
    let staged: Vec<Result<Staged, PaymentsError>> = parsed
        .into_iter()
        .map(|parsed| {
            let (owner, mint) = parsed?;
            match mint {
                None => Ok(Staged::Done(U256::from(
                    first.get(&owner).map_or(0, |account| account.lamports),
                ))),
                Some(mint) => {
                    let program = mint_program(first.get(&mint))?;
                    let account = associated_token_account(&owner, &mint, &program);
                    token_accounts.push(account);
                    Ok(Staged::Token { account, program })
                }
            }
        })
        .collect();
    let second = if token_accounts.is_empty() {
        Ok(HashMap::new())
    } else {
        fetch(rpc, &token_accounts).await
    };
    staged
        .into_iter()
        .map(|staged| match staged? {
            Staged::Done(balance) => Ok(balance),
            Staged::Token { account, program } => match &second {
                Ok(accounts) => token_amount(accounts.get(&account), &program),
                Err(error) => Err(error.clone()),
            },
        })
        .collect()
}

/// A Solana balance after the first request.
enum Staged {
    /// Known (SOL).
    Done(U256),
    /// Held in this token account of this token program.
    Token { account: Pubkey, program: Pubkey },
}

/// The existing accounts among `addresses` (deduplicated), by address.
async fn fetch(
    rpc: &SolanaRpc,
    addresses: &[Pubkey],
) -> Result<HashMap<Pubkey, Account>, PaymentsError> {
    let mut unique = addresses.to_vec();
    unique.sort_unstable();
    unique.dedup();
    let accounts = rpc.accounts(&unique).await?;
    Ok(unique
        .into_iter()
        .zip(accounts)
        .filter_map(|(address, account)| Some((address, account?)))
        .collect())
}

/// The token program that owns a configured mint.
fn mint_program(mint: Option<&Account>) -> Result<Pubkey, PaymentsError> {
    let mint = mint.ok_or_else(|| {
        PaymentsError::ChainRpc("the configured mint does not exist on this cluster".into())
    })?;
    let known = [SolanaTokenProgram::Token, SolanaTokenProgram::Token2022]
        .into_iter()
        .any(|kind| token_program_id(kind) == mint.owner);
    if !known {
        return Err(PaymentsError::ChainRpc(
            "the configured mint is not owned by a token program".into(),
        ));
    }
    Ok(mint.owner)
}

/// The amount in an associated token account of `program`; `0` when the
/// account does not exist.
fn token_amount(account: Option<&Account>, program: &Pubkey) -> Result<U256, PaymentsError> {
    let Some(account) = account else {
        return Ok(U256::ZERO);
    };
    let amount = account
        .data
        .get(TOKEN_AMOUNT_RANGE)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .filter(|_| account.owner == *program)
        .ok_or_else(|| {
            PaymentsError::ChainRpc("the associated token account is not a token account".into())
        })?;
    Ok(U256::from(u64::from_le_bytes(amount)))
}

fn evm_account(address: &str) -> Result<alloy_primitives::Address, PaymentsError> {
    let address = EvmAddress::from_str(address)
        .map_err(|_| PaymentsError::Internal("the wallet address is not an EVM address".into()))?;
    to_alloy_address(&address)
}

fn solana_account(address: &str) -> Result<Pubkey, PaymentsError> {
    Pubkey::from_str(address)
        .map_err(|_| PaymentsError::InvalidRequest("invalid Solana address".into()))
}

/// Runs `work` within `limit`; running out is a `ChainRpc` error naming the network.
pub(super) async fn within<T>(
    limit: Duration,
    network: &str,
    work: impl std::future::Future<Output = Result<T, PaymentsError>>,
) -> Result<T, PaymentsError> {
    tokio::time::timeout(limit, work).await.unwrap_or_else(|_| {
        Err(PaymentsError::ChainRpc(format!(
            "network '{network}' did not answer within {} ms",
            limit.as_millis()
        )))
    })
}

fn no_provider() -> PaymentsError {
    PaymentsError::Internal("no chain provider is registered for this family".into())
}

fn entry((target, address, result): Read) -> WalletBalanceEntry {
    let kind = target.kind();
    let (balance_base_units, balance, error) = match result {
        Ok(value) => (
            Some(value.to_string()),
            Some(format_units(value, target.decimals)),
            None,
        ),
        Err(error) => (None, None, Some(WirePaymentsError::from(error))),
    };
    WalletBalanceEntry {
        chain_id: target.chain.chain_id,
        chain_name: target.chain.name,
        family: target.chain.family,
        network: target.network,
        asset: target.asset,
        symbol: target.symbol,
        kind,
        token: target.token,
        decimals: target.decimals,
        address,
        balance_base_units,
        balance,
        error,
    }
}
