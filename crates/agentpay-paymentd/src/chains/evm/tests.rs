//! EVM chain provider tests: signed-transaction verification against a real
//! signed transaction, and RPC behaviour against the loopback mock endpoint.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{ChainFamily, ChainProfile};
use agentpay_domain::{BroadcastTx, EvmAddress};
use alloy_primitives::{keccak256, Address, U256};
use serde_json::Value;

use super::mock_rpc::MockRpc;
use super::*;

/// The signer daemon's `SignForAgent` example: a real 1 USD1 transfer on BSC
/// signed by the example key, whose address is the `AuthenticateAgent` example's.
const SIGN_FOR_AGENT_EXAMPLE: &str =
    include_str!("../../../../agentpay-api/fixtures/rpc/SignForAgent.response.json");
const SIGN_FOR_AGENT_REQUEST: &str =
    include_str!("../../../../agentpay-api/fixtures/rpc/SignForAgent.request.json");
const EXAMPLE_WALLET: &str = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";

fn example() -> (BroadcastTx, String, String) {
    let request: Value = serde_json::from_str(SIGN_FOR_AGENT_REQUEST).expect("request");
    let tx: BroadcastTx =
        serde_json::from_value(request["params"]["request"]["action"]["tx"].clone()).expect("tx");
    let response: Value = serde_json::from_str(SIGN_FOR_AGENT_EXAMPLE).expect("response");
    let raw = response["data"]["raw_tx_hex"]
        .as_str()
        .expect("raw")
        .to_string();
    let hash = response["data"]["tx_hash_hex"]
        .as_str()
        .expect("hash")
        .to_string();
    (tx, raw, hash)
}

fn wallet() -> Address {
    Address::from_str(EXAMPLE_WALLET).expect("wallet")
}

#[test]
fn the_real_signed_example_verifies() {
    let (tx, raw, hash) = example();
    let verified = verify_signed_transaction(&raw, Some(&hash), &tx, wallet()).expect("verified");
    assert_eq!(hex_prefixed(verified.hash.as_slice()), hash);
    assert_eq!(hex_prefixed(&verified.raw), raw);
    // Without a reported hash the envelope still verifies.
    verify_signed_transaction(&raw, None, &tx, wallet()).expect("no reported hash");
}

fn assert_mismatch(result: Result<VerifiedTransaction, PaymentsError>, field: &str) {
    match result {
        Err(PaymentsError::SignedTransactionMismatch(message)) => {
            assert!(message.contains(field), "{message} should name {field}");
            assert!(!message.contains("0x"), "{message} must not quote values");
        }
        other => panic!("expected a {field} mismatch, got {other:?}"),
    }
}

/// A change to an expected transaction.
type Change = dyn Fn(&mut BroadcastTx);

#[test]
fn every_field_that_changes_the_transaction_is_checked() {
    let (tx, raw, hash) = example();
    let other = EvmAddress::from_str("0x1111111111111111111111111111111111111111").unwrap();
    let cases: Vec<(&str, Box<Change>)> = vec![
        ("chain id", Box::new(|tx| tx.chain_id = 1)),
        ("nonce", Box::new(|tx| tx.nonce += 1)),
        ("recipient", Box::new(move |tx| tx.to = other.clone())),
        ("value", Box::new(|tx| tx.value_wei = 1)),
        ("calldata", Box::new(|tx| tx.data_hex = "0x".into())),
        ("gas limit", Box::new(|tx| tx.gas_limit += 1)),
        (
            "max fee per gas",
            Box::new(|tx| tx.max_fee_per_gas_wei += 1),
        ),
        (
            "max priority fee per gas",
            Box::new(|tx| tx.max_priority_fee_per_gas_wei -= 1),
        ),
        ("transaction type", Box::new(|tx| tx.tx_type = 4)),
    ];
    for (field, change) in cases {
        let mut expected = tx.clone();
        change(&mut expected);
        assert_mismatch(
            verify_signed_transaction(&raw, Some(&hash), &expected, wallet()),
            field,
        );
    }
    let stranger = Address::repeat_byte(0x22);
    assert_mismatch(
        verify_signed_transaction(&raw, Some(&hash), &tx, stranger),
        "signer",
    );
    let wrong_hash = hex_prefixed(keccak256(b"other").as_slice());
    assert_mismatch(
        verify_signed_transaction(&raw, Some(&wrong_hash), &tx, wallet()),
        "reported hash",
    );
}

#[test]
fn malformed_or_tampered_envelopes_are_rejected() {
    let (tx, raw, _) = example();
    assert_mismatch(
        verify_signed_transaction(&raw[2..], None, &tx, wallet()),
        "encoding",
    );
    assert_mismatch(
        verify_signed_transaction(&format!("{raw}00"), None, &tx, wallet()),
        "encoding",
    );
    assert_mismatch(
        verify_signed_transaction("0x02", None, &tx, wallet()),
        "encoding",
    );
    // Flipping a byte of `s` keeps the envelope decodable but changes the
    // recovered signer (or makes recovery fail).
    let mut bytes = alloy_primitives::hex::decode(&raw[2..]).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = hex_prefixed(&bytes);
    let result = verify_signed_transaction(&tampered, None, &tx, wallet());
    assert!(
        matches!(&result, Err(PaymentsError::SignedTransactionMismatch(m)) if m.contains("signer") || m.contains("signature")),
        "{result:?}"
    );
}

fn chain(chain_id: u64, rpc_url: Option<&str>) -> ChainProfile {
    ChainProfile {
        chain_id,
        name: "Test".into(),
        family: ChainFamily::Evm,
        rpc_url: rpc_url.map(str::to_string),
        fallback_rpc_urls: Vec::new(),
    }
}

#[tokio::test]
async fn connect_refuses_unusable_chains_before_any_request() {
    let evm = EvmProvider::new();
    let mut solana = chain(900_000_001, Some("https://api.mainnet-beta.solana.com"));
    solana.family = ChainFamily::Solana;
    for (profile, reason) in [
        (solana, "not an EVM chain"),
        (chain(56, None), "no rpc_url"),
        (chain(56, Some("http://example.com")), "rpc_url"),
        (
            chain(56, Some("https://user:secret@example.com")),
            "rpc_url",
        ),
        (chain(56, Some("ftp://127.0.0.1")), "rpc_url"),
    ] {
        match evm.connect("test", &profile).await {
            Err(PaymentsError::InvalidRequest(message)) => {
                assert!(message.contains(reason), "{message}");
                assert!(!message.contains("secret"), "{message} leaks the URL");
            }
            Err(other) => panic!("expected InvalidRequest, got {other:?}"),
            Ok(_) => panic!("expected InvalidRequest, got a connection"),
        }
    }
}

#[tokio::test]
async fn an_endpoint_for_another_chain_is_never_used() {
    let mock = MockRpc::start(1).await;
    let error = EvmProvider::new()
        .connect("bsc", &chain(56, Some(mock.url())))
        .await
        .err()
        .expect("chain id mismatch");
    let PaymentsError::ChainRpc(message) = error else {
        panic!("expected ChainRpc, got {error:?}");
    };
    assert!(
        message.contains("chain id 1") && message.contains("expected 56"),
        "{message}"
    );
    assert_eq!(mock.calls(), ["eth_chainId"]);
}

#[tokio::test]
async fn rpc_failures_never_quote_the_endpoint() {
    // Bind and drop a listener so the port is closed.
    let url = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let error = EvmProvider::new()
        .connect("local", &chain(31337, Some(&url)))
        .await
        .err()
        .expect("unreachable");
    let PaymentsError::ChainRpc(message) = error else {
        panic!("expected ChainRpc, got {error:?}");
    };
    assert!(!message.contains("127.0.0.1"), "{message} quotes the URL");
    assert!(message.contains("eth_chainId"), "{message}");
}

#[tokio::test]
async fn reads_map_to_typed_values() {
    let mock = MockRpc::start(56).await;
    mock.chain().code = vec![0x60, 0x80];
    let rpc = EvmProvider::new()
        .connect("bsc", &chain(56, Some(mock.url())))
        .await
        .expect("connect");
    assert_eq!((rpc.network(), rpc.chain_id()), ("bsc", 56));
    assert_eq!(rpc.block_number().await.unwrap(), 45_000_123);
    assert_eq!(rpc.pending_nonce(wallet()).await.unwrap(), 7);
    assert_eq!(
        rpc.native_balance(wallet()).await.unwrap(),
        U256::from(2_000_000_000_000_000_000_u128)
    );
    let token = Address::repeat_byte(0x33);
    assert_eq!(rpc.erc20_decimals(token).await.unwrap(), 6);
    assert_eq!(rpc.erc20_symbol(token).await.as_deref(), Some("TKN"));
    assert_eq!(
        rpc.erc20_balance(token, wallet()).await.unwrap(),
        U256::from(25_500_000_u64)
    );
    assert_eq!(rpc.code(wallet()).await.unwrap().as_ref(), [0x60, 0x80]);
    assert_eq!(rpc.gas_price().await.unwrap(), 1_000_000_000);
    let fees = rpc.fees().await.unwrap();
    assert!(fees.max_fee_per_gas >= 1_000_000_000 && fees.max_priority_fee_per_gas > 0);
    assert!(fees.max_priority_fee_per_gas <= fees.max_fee_per_gas);
}

#[tokio::test]
async fn chains_without_base_fees_use_the_gas_price() {
    let mock = MockRpc::start(56).await;
    mock.chain().base_fee = 0;
    mock.chain().gas_price = 3_000_000_000;
    let rpc = EvmProvider::new()
        .connect("bsc", &chain(56, Some(mock.url())))
        .await
        .expect("connect");
    assert!(rpc.eip1559_fees().await.is_err());
    let fees = rpc.fees().await.unwrap();
    assert_eq!(
        fees,
        FeeEstimate {
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 3_000_000_000
        }
    );
}

#[tokio::test]
async fn broadcasts_are_sent_once_and_already_known_counts_as_sent() {
    let (_, raw, hash) = example();
    let raw = alloy_primitives::hex::decode(&raw[2..]).unwrap();
    let mock = MockRpc::start(56).await;
    let rpc = EvmProvider::new()
        .connect("bsc", &chain(56, Some(mock.url())))
        .await
        .expect("connect");

    let sent = rpc.send_raw_transaction(&raw).await.expect("sent");
    assert_eq!(hex_prefixed(sent.as_slice()), hash);
    let receipt = rpc
        .wait_for_receipt(sent, Duration::ZERO)
        .await
        .unwrap()
        .expect("mined");
    assert!(receipt.success);
    assert_eq!(receipt.tx_hash, hash);
    let transaction = rpc.transaction(sent).await.unwrap().expect("known");
    assert_eq!(
        (transaction.nonce, transaction.tx_type, transaction.chain_id),
        (7, 2, Some(56))
    );
    assert_eq!(transaction.from.as_str(), EXAMPLE_WALLET);

    mock.chain().send_error = Some("already known".into());
    assert_eq!(rpc.send_raw_transaction(&raw).await.unwrap(), sent);
    mock.chain().send_error = Some("insufficient funds for gas * price + value".into());
    let error = rpc.send_raw_transaction(&raw).await.expect_err("rejected");
    assert!(
        matches!(&error, PaymentsError::ChainRpc(m) if m.contains("insufficient funds")),
        "{error:?}"
    );
    let sends = mock
        .calls()
        .iter()
        .filter(|m| *m == "eth_sendRawTransaction")
        .count();
    assert_eq!(sends, 3, "every send is a single request");
}

#[tokio::test]
async fn receipt_waits_give_up_after_the_timeout() {
    let mock = MockRpc::start(56).await;
    mock.chain().mined = false;
    let rpc = EvmProvider::new()
        .connect("bsc", &chain(56, Some(mock.url())))
        .await
        .expect("connect");
    let hash = keccak256(b"unknown");
    assert_eq!(rpc.receipt(hash).await.unwrap(), None);
    assert_eq!(rpc.transaction(hash).await.unwrap(), None);
    let started = std::time::Instant::now();
    assert_eq!(
        rpc.wait_for_receipt(hash, Duration::from_millis(50))
            .await
            .unwrap(),
        None
    );
    assert!(started.elapsed() < RECEIPT_POLL_INTERVAL);
}

#[tokio::test]
async fn send_failures_say_whether_the_transaction_certainly_never_left() {
    let (_, raw, _) = example();
    let raw = alloy_primitives::hex::decode(&raw[2..]).expect("raw");
    let mock = MockRpc::start(56).await;
    let rpc = EvmProvider::new()
        .connect("bsc", &chain(56, Some(mock.url())))
        .await
        .expect("connect");

    // The node answered with a JSON-RPC error: it rejected the transaction.
    mock.chain().send_error = Some("nonce too low".into());
    let failure = rpc
        .try_send_raw_transaction(&raw)
        .await
        .expect_err("rejected");
    assert!(failure.not_submitted);
    assert!(matches!(failure.error, PaymentsError::ChainRpc(_)));

    // A proxy error after the request was delivered is ambiguous.
    mock.chain().send_error = None;
    mock.chain().send_http_status = Some(502);
    let failure = rpc.try_send_raw_transaction(&raw).await.expect_err("502");
    assert!(!failure.not_submitted, "the node may have the transaction");

    // Nobody is listening any more: the request was never sent.
    let addr = mock.url().trim_start_matches("http://").to_string();
    drop(mock);
    // The server task is aborted asynchronously; wait until the port really refuses.
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(&addr).await.is_err() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let failure = rpc
        .try_send_raw_transaction(&raw)
        .await
        .expect_err("connection refused");
    assert!(failure.not_submitted, "{:?}", failure.error);
}

/// A chain whose `rpc_url` and backups are the given mocks' URLs.
fn with_backups(chain_id: u64, urls: &[&str]) -> ChainProfile {
    let mut profile = chain(chain_id, urls.first().copied());
    profile.fallback_rpc_urls = urls.iter().skip(1).map(|url| (*url).to_string()).collect();
    profile
}

/// A closed loopback port.
async fn dead_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    format!("http://{}", listener.local_addr().expect("addr"))
}

#[tokio::test]
async fn connect_fails_over_to_the_first_backup_serving_the_chain() {
    let wrong_chain = MockRpc::start(1).await;
    let dead = dead_url().await;
    let backup = MockRpc::start(56).await;
    let profile = with_backups(56, &[wrong_chain.url(), &dead, backup.url()]);
    let rpc = EvmProvider::new()
        .connect("bsc", &profile)
        .await
        .expect("backup");
    assert!(rpc.using_backup());
    assert_eq!(rpc.block_number().await.expect("block"), 45_000_123);
    assert_eq!(wrong_chain.calls(), ["eth_chainId"]);
    assert_eq!(backup.calls(), ["eth_chainId", "eth_blockNumber"]);

    let primary = EvmProvider::new()
        .connect("bsc", &with_backups(56, &[backup.url(), wrong_chain.url()]))
        .await
        .expect("primary");
    assert!(!primary.using_backup());
}

#[tokio::test]
async fn a_working_backup_is_preferred_for_ten_minutes() {
    let now = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let clock = {
        let now = now.clone();
        Arc::new(move || *now.lock().expect("clock")) as crate::chains::failover::Clock
    };
    let evm = EvmProvider::with_clock(clock);
    let primary = MockRpc::start(1).await;
    let backup = MockRpc::start(56).await;
    let profile = with_backups(56, &[primary.url(), backup.url()]);

    assert!(evm
        .connect("bsc", &profile)
        .await
        .expect("backup")
        .using_backup());
    // The primary serves the right chain again, but is not asked yet.
    primary.chain().chain_id = 56;
    assert!(evm
        .connect("bsc", &profile)
        .await
        .expect("sticky")
        .using_backup());
    assert_eq!(primary.calls().len(), 1, "the primary is not re-probed");

    *now.lock().expect("clock") += Duration::from_secs(600);
    let rpc = evm.connect("bsc", &profile).await.expect("primary again");
    assert!(!rpc.using_backup());
    assert_eq!(primary.calls().len(), 2);
}

#[tokio::test]
async fn when_every_endpoint_fails_the_primary_error_counts_the_backups() {
    let primary = MockRpc::start(1).await;
    let dead = dead_url().await;
    let other = MockRpc::start(97).await;
    let profile = with_backups(56, &[primary.url(), &dead, other.url()]);
    let error = EvmProvider::new()
        .connect("bsc", &profile)
        .await
        .err()
        .expect("all fail");
    let PaymentsError::ChainRpc(message) = error else {
        panic!("expected ChainRpc, got {error:?}");
    };
    assert!(
        message.contains("chain id 1") && message.ends_with("(2 backup RPCs also failed)"),
        "{message}"
    );
    assert!(!message.contains("127.0.0.1"), "{message} leaks a URL");
}

#[tokio::test]
async fn sends_go_only_to_the_chosen_endpoint() {
    let primary = MockRpc::start(1).await;
    let backup = MockRpc::start(56).await;
    let rpc = EvmProvider::new()
        .connect("bsc", &with_backups(56, &[primary.url(), backup.url()]))
        .await
        .expect("backup");
    backup.chain().send_error = Some("nonce too low".into());
    let failure = rpc
        .try_send_raw_transaction(&[0x02, 0xc0])
        .await
        .expect_err("rejected");
    assert!(failure.not_submitted);
    assert_eq!(
        primary.calls(),
        ["eth_chainId"],
        "never sent to the primary"
    );
}
