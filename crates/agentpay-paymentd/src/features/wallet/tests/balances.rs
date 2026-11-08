//! `WalletSummary` and `WalletBalance`.

use std::time::{Duration, Instant};

use agentpay_api::payments::{
    ChainFamily, ChainProfile, TokenChainProfile, TokenProfile, WalletAssetKind,
    WalletBalanceEntry, WalletBalanceParams, WalletSummaryParams,
};
use agentpay_api::WirePaymentsError;
use tokio::net::TcpListener;

use super::*;

fn summary_request(h: &Harness) -> Req {
    Req::WalletSummary(WalletSummaryParams {
        auth: h.auth.clone(),
    })
}

fn balance_request(h: &Harness, network: Option<&str>, asset: Option<&str>) -> Req {
    Req::WalletBalance(WalletBalanceParams {
        auth: h.auth.clone(),
        network: network.map(str::to_string),
        asset: asset.map(str::to_string),
    })
}

fn row(entries: &[WalletBalanceEntry], network: &str, asset: &str) -> WalletBalanceEntry {
    entries
        .iter()
        .find(|entry| entry.network == network && entry.asset == asset)
        .cloned()
        .unwrap_or_else(|| panic!("no {asset} on {network}"))
}

#[tokio::test]
async fn the_summary_reads_every_balance_and_reports_failures_per_entry() {
    let h = Harness::new(Vec::new()).await;
    let Res::WalletSummary(summary) = h.call(summary_request(&h)).await.expect("summary") else {
        panic!("WalletSummary must answer WalletSummary");
    };
    assert_eq!(summary.agent_key_id, h.auth.agent_key_id);
    assert_eq!(
        summary.evm_address.as_ref().map(|a| a.as_str()),
        Some(EVM_WALLET)
    );
    assert_eq!(
        summary
            .solana_address
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(SOLANA_WALLET)
    );
    assert_eq!(
        (
            summary.default_network.as_str(),
            summary.default_asset.as_str()
        ),
        ("bsc", "usd1")
    );
    let order: Vec<(&str, &str)> = summary
        .balances
        .iter()
        .map(|entry| (entry.network.as_str(), entry.asset.as_str()))
        .collect();
    assert_eq!(
        order,
        [
            ("bsc", "bnb"),
            ("bsc", "usd1"),
            ("eth", "eth"),
            ("eth", "usd1"),
            ("solana-devnet", "sol"),
            ("solana-devnet", "usdc"),
        ]
    );

    let bnb = row(&summary.balances, "bsc", "bnb");
    assert_eq!(bnb.kind, WalletAssetKind::Native);
    assert_eq!(bnb.balance.as_deref(), Some("2"));
    assert_eq!(bnb.address, EVM_WALLET);
    let usd1 = row(&summary.balances, "bsc", "usd1");
    assert_eq!(usd1.kind, WalletAssetKind::Erc20);
    assert_eq!(usd1.token.as_deref(), Some(USD1));
    assert_eq!(usd1.balance.as_deref(), Some("25.5"));
    assert_eq!(
        usd1.balance_base_units.as_deref(),
        Some("25500000000000000000")
    );

    let sol = row(&summary.balances, "solana-devnet", "sol");
    assert_eq!(
        (sol.kind, sol.balance.as_deref()),
        (WalletAssetKind::Sol, Some("0.001"))
    );
    assert_eq!(sol.address, SOLANA_WALLET);
    let usdc = row(&summary.balances, "solana-devnet", "usdc");
    assert_eq!(
        (usdc.kind, usdc.balance.as_deref()),
        (WalletAssetKind::Spl, Some("12.5"))
    );

    // Ethereum is down: both of its rows carry the error, nothing else fails.
    for asset in ["eth", "usd1"] {
        let entry = row(&summary.balances, "eth", asset);
        assert_eq!(entry.balance, None);
        let Some(WirePaymentsError::ChainRpc(reason)) = &entry.error else {
            panic!("expected ChainRpc for {asset}, got {:?}", entry.error);
        };
        assert!(
            !reason.contains("127.0.0.1"),
            "the URL must not leak: {reason}"
        );
    }
    assert_eq!(
        summary
            .balances
            .iter()
            .filter(|e| e.error.is_none())
            .count(),
        4
    );
}

#[tokio::test]
async fn a_hanging_chain_times_out_without_holding_up_the_others() {
    let h = Harness::new(Vec::new()).await;
    // Accepts connections and never answers.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let _keep = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    h.edit_config(|config| {
        config.chains.get_mut("eth").expect("eth").rpc_url = Some(url);
    })
    .await;

    let started = Instant::now();
    let Res::WalletSummary(summary) = h
        .call_with(summary_request(&h), FAST)
        .await
        .expect("summary")
    else {
        panic!("WalletSummary must answer WalletSummary");
    };
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let eth = row(&summary.balances, "eth", "eth");
    let Some(WirePaymentsError::ChainRpc(reason)) = eth.error else {
        panic!("expected a timeout");
    };
    assert!(reason.contains("did not answer within 500 ms"), "{reason}");
    assert_eq!(
        row(&summary.balances, "bsc", "usd1").balance.as_deref(),
        Some("25.5")
    );
}

#[tokio::test]
async fn chains_without_rpc_tempo_natives_and_missing_addresses_are_skipped() {
    let h = Harness::new(Vec::new()).await;
    h.edit_config(|config| {
        config.chains.insert(
            "tempo".into(),
            ChainProfile {
                chain_id: 4217,
                name: "Tempo".into(),
                family: ChainFamily::Evm,
                rpc_url: Some(DEAD_RPC.into()),
                fallback_rpc_urls: Vec::new(),
            },
        );
        config.chains.get_mut("eth").expect("eth").rpc_url = None;
        config.tokens.insert(
            "usd".into(),
            TokenProfile {
                name: "USD".into(),
                symbol: "USD".into(),
                recommended_limits: None,
                chains: BTreeMap::from([(
                    "tempo".into(),
                    TokenChainProfile {
                        chain_id: 4217,
                        is_native: true,
                        address: None,
                        decimals: 6,
                    },
                )]),
            },
        );
    })
    .await;
    let Res::WalletSummary(summary) = h.call(summary_request(&h)).await.expect("summary") else {
        panic!("WalletSummary must answer WalletSummary");
    };
    assert!(summary
        .balances
        .iter()
        .all(|e| e.network != "eth" && e.network != "tempo"));
    assert_eq!(summary.balances.len(), 4);

    let err = h
        .call(balance_request(&h, Some("tempo"), Some("usd")))
        .await
        .expect_err("tempo native");
    assert!(matches!(err, PaymentsError::InvalidRequest(_)), "{err:?}");
}

#[tokio::test]
async fn a_single_balance_defaults_to_usd1_on_bsc_and_fails_when_its_read_fails() {
    let h = Harness::new(Vec::new()).await;
    let Res::WalletBalance(usd1) = h
        .call(balance_request(&h, None, None))
        .await
        .expect("default")
    else {
        panic!("WalletBalance must answer WalletBalance");
    };
    assert_eq!(
        (usd1.network.as_str(), usd1.asset.as_str()),
        ("bsc", "usd1")
    );
    assert_eq!(usd1.balance.as_deref(), Some("25.5"));
    assert!(usd1.error.is_none());

    // By contract address (any case) and by mint.
    let by_address = h
        .call(balance_request(
            &h,
            Some("BSC"),
            Some(&USD1.to_ascii_uppercase().replace("0X", "0x")),
        ))
        .await
        .expect("by address");
    assert_eq!(by_address, Res::WalletBalance(usd1));
    let Res::WalletBalance(usdc) = h
        .call(balance_request(
            &h,
            Some("solana-devnet"),
            Some(DEVNET_USDC),
        ))
        .await
        .expect("by mint")
    else {
        panic!("WalletBalance must answer WalletBalance");
    };
    assert_eq!(usdc.balance.as_deref(), Some("12.5"));

    let err = h
        .call(balance_request(&h, Some("eth"), None))
        .await
        .expect_err("unreachable");
    assert!(matches!(err, PaymentsError::ChainRpc(_)), "{err:?}");
    for (network, asset) in [
        (Some("polygon"), None),
        (None, Some("doge")),
        (Some("bsc"), Some("sol")),
    ] {
        let err = h
            .call(balance_request(&h, network, asset))
            .await
            .expect_err("unknown");
        assert!(matches!(err, PaymentsError::InvalidRequest(_)), "{err:?}");
    }
}

#[tokio::test]
async fn a_missing_token_account_is_a_zero_balance() {
    let h = Harness::new(Vec::new()).await;
    let wallet: Pubkey = SOLANA_WALLET.parse().expect("wallet");
    let mint: Pubkey = DEVNET_USDC.parse().expect("mint");
    h.cluster.with(|state| {
        state
            .accounts
            .remove(&associated_token_account(&wallet, &mint, &spl_token::ID))
    });
    let Res::WalletBalance(usdc) = h
        .call(balance_request(&h, Some("solana-devnet"), Some("usdc")))
        .await
        .expect("balance")
    else {
        panic!("WalletBalance must answer WalletBalance");
    };
    assert_eq!(usdc.balance.as_deref(), Some("0"));
    assert_eq!(usdc.balance_base_units.as_deref(), Some("0"));
}

#[tokio::test]
async fn the_summary_batches_the_reads_of_each_chain() {
    let h = Harness::new(Vec::new()).await;
    let count = |method: &str| h.bsc.calls().iter().filter(|call| *call == method).count();
    let (calls_before, multiple_before) =
        (count("eth_call"), h.cluster.calls("getMultipleAccounts"));
    let single_before = h.cluster.calls("getAccountInfo");
    let Res::WalletSummary(summary) = h.call(summary_request(&h)).await.expect("summary") else {
        panic!("WalletSummary must answer WalletSummary");
    };
    assert_eq!(
        row(&summary.balances, "bsc", "usd1").balance.as_deref(),
        Some("25.5")
    );
    // BSC has Multicall3: BNB and USD1 in one eth_call, no eth_getBalance.
    assert_eq!(count("eth_call") - calls_before, 1);
    assert_eq!(count("eth_getBalance"), 0);
    // Solana: wallet and mint, then the token account.
    assert_eq!(h.cluster.calls("getMultipleAccounts") - multiple_before, 2);
    assert_eq!(h.cluster.calls("getAccountInfo"), single_before);
}
