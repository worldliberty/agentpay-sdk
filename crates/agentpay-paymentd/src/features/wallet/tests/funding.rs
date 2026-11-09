//! `FundingRequest`.

use agentpay_api::payments::{FundingRequestParams, FundingRequestResult, WalletAssetKind};

use super::*;

fn funding(h: &Harness, network: Option<&str>, asset: Option<&str>, amount: Option<&str>) -> Req {
    Req::FundingRequest(FundingRequestParams {
        auth: h.auth.clone(),
        network: network.map(str::to_string),
        asset: asset.map(str::to_string),
        amount: amount.map(str::to_string),
        qr: None,
    })
}

async fn request(h: &Harness, req: Req) -> FundingRequestResult {
    match h.call(req).await.expect("funding request") {
        Res::FundingRequest(result) => result,
        other => panic!("FundingRequest must answer FundingRequest, got {other:?}"),
    }
}

#[tokio::test]
async fn usd1_on_bsc_by_default_with_an_eip681_uri_a_qr_and_a_bnb_hint() {
    let h = Harness::new(Vec::new()).await;
    let result = request(&h, funding(&h, None, None, Some("25.50"))).await;
    assert_eq!(
        (result.network.as_str(), result.asset.as_str()),
        ("bsc", "usd1")
    );
    assert_eq!(result.kind, WalletAssetKind::Erc20);
    assert_eq!(result.address, EVM_WALLET);
    assert_eq!(result.amount.as_deref(), Some("25.5"));
    assert_eq!(
        result.amount_base_units.as_deref(),
        Some("25500000000000000000")
    );
    assert_eq!(
        result.uri,
        format!("ethereum:{USD1}@56/transfer?address={EVM_WALLET}&uint256=25500000000000000000")
    );
    let qr = result.qr.as_ref().expect("qr by default");
    assert!(qr.modules >= 21 && qr.svg.starts_with("<svg") && !qr.terminal.is_empty());
    let gas = result.gas.as_ref().expect("gas hint");
    assert_eq!(
        (gas.asset.as_deref(), gas.symbol.as_str()),
        (Some("bnb"), "BNB")
    );
    assert!(result.instructions.contains("at least 25.5 USD1"));
    assert!(result.instructions.contains("BNB for network fees"));
    assert!(result.instructions.contains(EVM_WALLET));
    // Funding reads no chain.
    assert!(h.bsc.calls().is_empty());
}

#[tokio::test]
async fn native_coins_and_solana_assets_use_their_own_uris() {
    let h = Harness::new(Vec::new()).await;
    let bnb = request(&h, funding(&h, None, Some("bnb"), Some("0.05"))).await;
    assert_eq!(bnb.kind, WalletAssetKind::Native);
    assert_eq!(
        bnb.uri,
        format!("ethereum:{EVM_WALLET}@56?value=50000000000000000")
    );
    assert_eq!(bnb.gas, None, "the native coin pays its own fees");

    let plain = request(&h, funding(&h, Some("bsc"), Some("bnb"), None)).await;
    assert_eq!(plain.uri, format!("ethereum:{EVM_WALLET}@56"));
    assert_eq!(plain.amount, None);

    let sol = request(
        &h,
        funding(&h, Some("solana-devnet"), Some("sol"), Some("1.5")),
    )
    .await;
    assert_eq!(sol.kind, WalletAssetKind::Sol);
    assert_eq!(sol.address, SOLANA_WALLET);
    assert_eq!(sol.uri, format!("solana:{SOLANA_WALLET}?amount=1.5"));
    assert_eq!(sol.amount_base_units.as_deref(), Some("1500000000"));

    let usdc = request(&h, funding(&h, Some("solana-devnet"), Some("usdc"), None)).await;
    assert_eq!(
        usdc.uri,
        format!("solana:{SOLANA_WALLET}?spl-token={DEVNET_USDC}")
    );
    let gas = usdc.gas.expect("SOL hint");
    assert_eq!(
        (gas.asset.as_deref(), gas.symbol.as_str()),
        (Some("sol"), "SOL")
    );
}

#[tokio::test]
async fn the_qr_can_be_left_out_and_bad_amounts_are_refused() {
    let h = Harness::new(Vec::new()).await;
    let mut req = funding(&h, None, None, None);
    if let Req::FundingRequest(params) = &mut req {
        params.qr = Some(false);
    }
    assert_eq!(request(&h, req).await.qr, None);

    for amount in ["0", "-1", "1e3", "abc", "0.0000001"] {
        let err = h
            .call(funding(
                &h,
                Some("solana-devnet"),
                Some("usdc"),
                Some(amount),
            ))
            .await
            .expect_err(amount);
        assert!(
            matches!(err, PaymentsError::InvalidRequest(_)),
            "{amount}: {err:?}"
        );
    }
}

#[tokio::test]
async fn a_token_without_a_configured_native_coin_falls_back_to_the_chain_id_symbol() {
    let h = Harness::new(Vec::new()).await;
    h.edit_config(|config| {
        config.tokens.remove("eth");
    })
    .await;
    let result = request(&h, funding(&h, Some("eth"), Some("usd1"), None)).await;
    let gas = result.gas.expect("hint");
    assert_eq!((gas.asset, gas.symbol.as_str()), (None, "ETH"));
}
