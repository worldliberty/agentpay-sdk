//! Batched balance reads on one EVM chain ([`EvmRpc::balances`]).
//!
//! Several balances are read in as few requests as the endpoint allows:
//!
//! 1. **Multicall3** `aggregate3` at [`MULTICALL3_ADDRESS`]: one `eth_call`
//!    with `getEthBalance(owner)` for native balances and `balanceOf(owner)`
//!    for tokens, every sub-call with `allowFailure`, so a failing token only
//!    fails its own entry. Used on chains known to have the contract
//!    ([`MULTICALL3_CHAIN_IDS`]); on any other chain the address is probed
//!    once with `eth_getCode` and the answer kept per network and chain id
//!    for the service's lifetime ([`MulticallSupport`]).
//! 2. **JSON-RPC batch**: when the multicall `eth_call` fails as a whole (no
//!    contract, RPC error, unreadable answer), one batch of `eth_getBalance`
//!    and `eth_call balanceOf` requests.
//! 3. **Single calls**: when the endpoint rejects the batch (some public
//!    endpoints refuse batches) or no entry of it succeeded, the balances are
//!    read with concurrent single calls, as before batching existed.
//!
//! A single balance is always read with a single call.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::bindings::IMulticall3::getEthBalanceCall;
use alloy_provider::{CallItem, Provider, MULTICALL3_ADDRESS};
use alloy_rpc_client::{BatchRequest, Waiter};
use alloy_rpc_types_eth::{BlockNumberOrTag, TransactionRequest};
use alloy_sol_types::SolCall;
use tokio::task::JoinSet;

use super::rpc::{balanceOfCall, rpc_error, EvmRpc};
use crate::error::PaymentsError;

/// Chain ids with Multicall3 at [`MULTICALL3_ADDRESS`]: Ethereum, BSC, Tempo
/// (a system predeploy), Tempo Moderato, Base, Sepolia, BSC testnet, Base
/// Sepolia, Arbitrum, Arbitrum Sepolia, Optimism, and Polygon. Other chains
/// are probed.
pub const MULTICALL3_CHAIN_IDS: &[u64] = &[
    1, 56, 4217, 42431, 8453, 11_155_111, 97, 84532, 42_161, 421_614, 10, 137,
];

/// One balance to read: the native coin (`token: None`) or an ERC-20 token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalanceQuery {
    /// The account whose balance is read.
    pub owner: Address,
    /// The ERC-20 contract; `None` for the native coin.
    pub token: Option<Address>,
}

/// Which chains outside [`MULTICALL3_CHAIN_IDS`] have Multicall3, by network
/// key and chain id. Probe failures are not recorded, so they are retried.
#[derive(Debug, Default)]
pub struct MulticallSupport {
    probed: Mutex<HashMap<(String, u64), bool>>,
}

impl MulticallSupport {
    fn get(&self, key: &(String, u64)) -> Option<bool> {
        self.probed.lock().ok()?.get(key).copied()
    }

    fn insert(&self, key: (String, u64), present: bool) {
        if let Ok(mut probed) = self.probed.lock() {
            probed.insert(key, present);
        }
    }
}

/// A request in a JSON-RPC batch.
enum Pending {
    Native(Waiter<U256>),
    Token(Waiter<Bytes>),
}

impl EvmRpc {
    /// The balances of `queries`, in order, in base units. Each entry fails
    /// on its own; see the [module documentation](self) for how they are read.
    pub async fn balances(&self, queries: &[BalanceQuery]) -> Vec<Result<U256, PaymentsError>> {
        if queries.len() > 1 {
            if self.has_multicall().await {
                if let Some(results) = self.multicall_balances(queries).await {
                    return results;
                }
            }
            if let Some(results) = self.batch_balances(queries).await {
                return results;
            }
        }
        self.single_balances(queries).await
    }

    /// Whether Multicall3 is deployed on this chain: known, cached, or probed now.
    async fn has_multicall(&self) -> bool {
        if MULTICALL3_CHAIN_IDS.contains(&self.chain_id()) {
            return true;
        }
        let key = (self.network().to_string(), self.chain_id());
        if let Some(present) = self.multicall_support().get(&key) {
            return present;
        }
        let Ok(code) = self.code(MULTICALL3_ADDRESS).await else {
            return false;
        };
        let present = !code.is_empty();
        self.multicall_support().insert(key, present);
        present
    }

    /// One `aggregate3` call; `None` when it fails as a whole.
    async fn multicall_balances(
        &self,
        queries: &[BalanceQuery],
    ) -> Option<Vec<Result<U256, PaymentsError>>> {
        let calls = queries.iter().map(|query| {
            let call = match query.token {
                None => CallItem::<balanceOfCall>::new(
                    MULTICALL3_ADDRESS,
                    getEthBalanceCall { addr: query.owner }.abi_encode().into(),
                ),
                // `getEthBalance` also returns one uint256, so one decoder serves both.
                Some(token) => CallItem::<balanceOfCall>::new(
                    token,
                    balanceOfCall { owner: query.owner }.abi_encode().into(),
                ),
            };
            call.allow_failure(true)
        });
        let results = self
            .provider()
            .multicall()
            .dynamic::<balanceOfCall>()
            .extend_calls(calls)
            .aggregate3()
            .await
            .ok()?;
        if results.len() != queries.len() {
            return None;
        }
        Some(
            queries
                .iter()
                .zip(results)
                .map(|(query, result)| {
                    result.map_err(|_| {
                        PaymentsError::ChainRpc(match query.token {
                            None => "getEthBalance failed in the Multicall3 call".into(),
                            Some(_) => "balanceOf reverted or returned an invalid value".into(),
                        })
                    })
                })
                .collect(),
        )
    }

    /// One JSON-RPC batch; `None` when the endpoint rejects it or no entry
    /// of it succeeded.
    async fn batch_balances(
        &self,
        queries: &[BalanceQuery],
    ) -> Option<Vec<Result<U256, PaymentsError>>> {
        let mut batch = BatchRequest::new(self.provider().client());
        let mut pending = Vec::with_capacity(queries.len());
        for query in queries {
            let request = match query.token {
                None => batch
                    .add_call("eth_getBalance", &(query.owner, BlockNumberOrTag::Latest))
                    .map(Pending::Native),
                Some(token) => {
                    let call = TransactionRequest::default()
                        .with_to(token)
                        .with_input(balanceOfCall { owner: query.owner }.abi_encode());
                    batch
                        .add_call("eth_call", &(call, BlockNumberOrTag::Latest))
                        .map(Pending::Token)
                }
            };
            pending.push(request.ok()?);
        }
        batch.send().await.ok()?;
        let mut results = Vec::with_capacity(pending.len());
        for request in pending {
            results.push(match request {
                Pending::Native(waiter) => waiter
                    .await
                    .map_err(|err| rpc_error("eth_getBalance", &err)),
                Pending::Token(waiter) => match waiter.await {
                    Ok(output) => balanceOfCall::abi_decode_returns(&output).map_err(|_| {
                        PaymentsError::ChainRpc("balanceOf returned an invalid value".into())
                    }),
                    Err(err) => Err(rpc_error("eth_call", &err)),
                },
            });
        }
        results.iter().any(Result::is_ok).then_some(results)
    }

    /// One call per balance, all at once.
    async fn single_balances(&self, queries: &[BalanceQuery]) -> Vec<Result<U256, PaymentsError>> {
        let mut reads = JoinSet::new();
        for (index, query) in queries.iter().copied().enumerate() {
            let rpc = self.clone();
            reads.spawn(async move {
                let result = match query.token {
                    None => rpc.native_balance(query.owner).await,
                    Some(token) => rpc.erc20_balance(token, query.owner).await,
                };
                (index, result)
            });
        }
        let mut results: Vec<Option<Result<U256, PaymentsError>>> = vec![None; queries.len()];
        while let Some(joined) = reads.join_next().await {
            if let Ok((index, result)) = joined {
                if let Some(slot) = results.get_mut(index) {
                    *slot = Some(result);
                }
            }
        }
        results
            .into_iter()
            .map(|result| {
                result
                    .unwrap_or_else(|| Err(PaymentsError::Internal("a balance read failed".into())))
            })
            .collect()
    }
}
