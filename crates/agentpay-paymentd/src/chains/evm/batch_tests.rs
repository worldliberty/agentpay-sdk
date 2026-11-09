//! [`EvmRpc::balances`] against the loopback mock endpoint: Multicall3 first,
//! then one JSON-RPC batch, then single calls.

use agentpay_api::payments::{ChainFamily, ChainProfile};
use alloy_primitives::{Address, U256};

use super::mock_rpc::MockRpc;
use super::*;

/// A chain id outside [`MULTICALL3_CHAIN_IDS`], so Multicall3 is probed.
const UNKNOWN_CHAIN_ID: u64 = 777;

fn owner() -> Address {
    Address::repeat_byte(0x11)
}

fn token(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

/// The native balance and two token balances of [`owner`].
fn queries() -> Vec<BalanceQuery> {
    [None, Some(token(0x22)), Some(token(0x33))]
        .into_iter()
        .map(|token| BalanceQuery {
            owner: owner(),
            token,
        })
        .collect()
}

async fn connect(provider: &EvmProvider, mock: &MockRpc, network: &str) -> EvmRpc {
    let chain_id = mock.chain().chain_id;
    let chain = ChainProfile {
        chain_id,
        name: network.to_uppercase(),
        family: ChainFamily::Evm,
        rpc_url: Some(mock.url().to_string()),
        fallback_rpc_urls: Vec::new(),
    };
    provider.connect(network, &chain).await.expect("connect")
}

fn count(mock: &MockRpc, method: &str) -> usize {
    mock.calls().iter().filter(|call| *call == method).count()
}

/// The expected balances of [`queries`], all successful.
fn expected(mock: &MockRpc) -> Vec<Result<U256, PaymentsError>> {
    let chain = mock.chain();
    vec![
        Ok(chain.balance),
        Ok(chain.token_balance),
        Ok(chain.token_balance),
    ]
}

#[tokio::test]
async fn a_known_chain_reads_every_balance_in_one_multicall() {
    let mock = MockRpc::start(56).await;
    let rpc = connect(&EvmProvider::new(), &mock, "bsc").await;
    assert_eq!(rpc.balances(&queries()).await, expected(&mock));
    assert_eq!(count(&mock, "eth_call"), 1);
    assert_eq!(count(&mock, "eth_getBalance"), 0);
    assert_eq!(
        count(&mock, "eth_getCode"),
        0,
        "known chains are not probed"
    );
    assert_eq!(mock.chain().batches, 0);
}

#[tokio::test]
async fn a_failing_sub_call_only_fails_its_entry() {
    let mock = MockRpc::start(56).await;
    mock.chain().reverting_tokens.push(token(0x22));
    let rpc = connect(&EvmProvider::new(), &mock, "bsc").await;
    let results = rpc.balances(&queries()).await;
    let expected = expected(&mock);
    assert_eq!(results[0], expected[0]);
    assert!(
        matches!(&results[1], Err(PaymentsError::ChainRpc(reason)) if reason.contains("balanceOf")),
        "{:?}",
        results[1]
    );
    assert_eq!(results[2], expected[2]);
    assert_eq!(count(&mock, "eth_call"), 1);
}

#[tokio::test]
async fn without_multicall3_the_balances_are_read_in_one_batch() {
    let mock = MockRpc::start(UNKNOWN_CHAIN_ID).await;
    mock.chain().multicall = false;
    let rpc = connect(&EvmProvider::new(), &mock, "other").await;
    assert_eq!(rpc.balances(&queries()).await, expected(&mock));
    assert_eq!(count(&mock, "eth_getCode"), 1, "probed");
    assert_eq!(mock.chain().batches, 1);
    assert_eq!(count(&mock, "eth_getBalance"), 1);
    assert_eq!(
        count(&mock, "eth_call"),
        2,
        "the two balanceOf calls of the batch"
    );
}

#[tokio::test]
async fn a_failed_multicall_on_a_known_chain_falls_back_to_a_batch() {
    let mock = MockRpc::start(56).await;
    mock.chain().multicall = false;
    let rpc = connect(&EvmProvider::new(), &mock, "bsc").await;
    assert_eq!(rpc.balances(&queries()).await, expected(&mock));
    assert_eq!(mock.chain().batches, 1);
}

#[tokio::test]
async fn a_rejected_batch_falls_back_to_single_calls() {
    let mock = MockRpc::start(UNKNOWN_CHAIN_ID).await;
    {
        let mut chain = mock.chain();
        chain.multicall = false;
        chain.reject_batches = true;
    }
    let rpc = connect(&EvmProvider::new(), &mock, "other").await;
    let mut queries = queries();
    queries.push(BalanceQuery {
        owner: owner(),
        token: Some(token(0x44)),
    });
    mock.chain().reverting_tokens.push(token(0x44));
    let results = rpc.balances(&queries).await;
    assert_eq!(results[..3], expected(&mock)[..]);
    assert!(matches!(results[3], Err(PaymentsError::ChainRpc(_))));
    assert_eq!(mock.chain().batches, 1);
    assert_eq!(count(&mock, "eth_getBalance"), 1);
    assert_eq!(count(&mock, "eth_call"), 3);
}

#[tokio::test]
async fn an_unknown_chain_is_probed_once_per_provider() {
    let mock = MockRpc::start(UNKNOWN_CHAIN_ID).await;
    let provider = EvmProvider::new();
    for _ in 0..2 {
        let rpc = connect(&provider, &mock, "other").await;
        assert_eq!(rpc.balances(&queries()).await, expected(&mock));
    }
    assert_eq!(
        count(&mock, "eth_getCode"),
        1,
        "cached after the first probe"
    );
    assert_eq!(count(&mock, "eth_call"), 2, "one aggregate3 per read");
    assert_eq!(mock.chain().batches, 0);

    // The answer is kept per network: another key for the same chain probes again.
    let rpc = connect(&provider, &mock, "other-alias").await;
    rpc.balances(&queries()).await;
    assert_eq!(count(&mock, "eth_getCode"), 2);
}

#[tokio::test]
async fn a_single_balance_is_read_with_a_single_call() {
    let mock = MockRpc::start(56).await;
    let rpc = connect(&EvmProvider::new(), &mock, "bsc").await;
    let native = queries().remove(0);
    assert_eq!(
        rpc.balances(&[native]).await,
        vec![Ok(mock.chain().balance)]
    );
    assert_eq!(count(&mock, "eth_getBalance"), 1);
    assert_eq!(count(&mock, "eth_call"), 0);
    assert_eq!(mock.chain().batches, 0);
}
