//! The `Rpc*` read helpers through dispatch.

use agentpay_api::payments::{
    EvmAccountParams, EvmBalanceParams, EvmGasEstimateParams, EvmNetworkParams, EvmTxHashParams,
    PaymentsRpcRequest as Req, PaymentsRpcResponse as Res,
};

use super::*;

fn network(h: &Harness) -> EvmNetworkParams {
    EvmNetworkParams {
        auth: h.auth.clone(),
        network: None,
    }
}

#[tokio::test]
async fn chain_info_block_number_nonce_fees_and_code() {
    let h = Harness::new(open_policy()).await;
    h.mock.chain().code = vec![0xfe];
    for request in [
        Req::RpcChainInfo(network(&h)),
        Req::RpcBlockNumber(network(&h)),
    ] {
        let Res::EvmChainInfo(info) = h.call(request).await.expect("info") else {
            panic!("expected EvmChainInfo");
        };
        assert_eq!(
            (info.network.as_str(), info.chain_id, info.block_number),
            ("bsc", 56, 45_000_123)
        );
    }
    let account = EvmAccountParams {
        auth: h.auth.clone(),
        network: Some("bsc".into()),
        address: None,
    };
    let Res::EvmNonce(nonce) = h.call(Req::RpcNonce(account.clone())).await.expect("nonce") else {
        panic!("expected EvmNonce");
    };
    assert_eq!((nonce.address, nonce.nonce), (h.wallet().await, 7));
    let Res::EvmCode(code) = h.call(Req::RpcCode(account)).await.expect("code") else {
        panic!("expected EvmCode");
    };
    assert_eq!(code.code_hex, "0xfe");

    let Res::EvmFees(fees) = h.call(Req::RpcFees(network(&h))).await.expect("fees") else {
        panic!("expected EvmFees");
    };
    assert_eq!(fees.gas_price_wei, 1_000_000_000);
    assert!(fees.max_fee_per_gas_wei.is_some() && fees.max_priority_fee_per_gas_wei.is_some());
    h.mock.chain().base_fee = 0;
    let Res::EvmFees(fees) = h.call(Req::RpcFees(network(&h))).await.expect("fees") else {
        panic!("expected EvmFees");
    };
    assert_eq!(
        (fees.max_fee_per_gas_wei, fees.max_priority_fee_per_gas_wei),
        (None, None)
    );
}

#[tokio::test]
async fn balances_of_the_native_coin_and_of_tokens() {
    let h = Harness::new(open_policy()).await;
    let balance = |asset: Option<&str>| {
        Req::RpcBalance(EvmBalanceParams {
            auth: h.auth.clone(),
            network: None,
            address: Some(address(RECIPIENT)),
            asset: asset.map(str::to_string),
        })
    };
    let Res::EvmBalance(native) = h.call(balance(None)).await.expect("native") else {
        panic!("expected EvmBalance");
    };
    assert_eq!(native.asset.symbol, "BNB");
    assert_eq!(
        (native.balance_wei.as_str(), native.balance.as_str()),
        ("2000000000000000000", "2")
    );
    assert_eq!(native.address, address(RECIPIENT));

    let Res::EvmBalance(token) = h
        .call(balance(Some("0x3333333333333333333333333333333333333333")))
        .await
        .expect("token")
    else {
        panic!("expected EvmBalance");
    };
    assert_eq!(
        (token.asset.symbol.as_str(), token.balance.as_str()),
        ("TKN", "25.5")
    );
    let Res::EvmBalance(usd1) = h.call(balance(Some("usd1"))).await.expect("usd1") else {
        panic!("expected EvmBalance");
    };
    assert_eq!(
        (usd1.asset.decimals, usd1.balance_wei.as_str()),
        (18, "25500000")
    );
}

#[tokio::test]
async fn gas_estimates_transactions_and_receipts() {
    let h = Harness::new(open_policy()).await;
    let estimate = Req::RpcGasEstimate(EvmGasEstimateParams {
        auth: h.auth.clone(),
        network: None,
        from: None,
        to: address(USD1),
        value_wei: 0,
        data_hex: "0x".into(),
    });
    let Res::EvmGasEstimate(gas) = h.call(estimate).await.expect("estimate") else {
        panic!("expected EvmGasEstimate");
    };
    assert_eq!(gas.gas_limit, 34_512);

    let Res::EvmTransaction(sent) = h.call(h.transfer("1", broadcast())).await.expect("sent")
    else {
        panic!("expected EvmTransaction");
    };
    let by_hash = |hash: &str| EvmTxHashParams {
        auth: h.auth.clone(),
        network: None,
        tx_hash: hash.to_string(),
    };
    let Res::EvmTransactionLookup(lookup) = h
        .call(Req::RpcTx(by_hash(&sent.tx_hash)))
        .await
        .expect("tx")
    else {
        panic!("expected EvmTransactionLookup");
    };
    let tx = lookup.transaction.expect("known");
    assert_eq!(
        (tx.tx_hash.as_str(), tx.nonce, tx.input_hex.as_str()),
        (sent.tx_hash.as_str(), 7, sent.data_hex.as_str())
    );
    assert_eq!(tx.from, sent.from);
    let Res::EvmReceiptLookup(lookup) = h
        .call(Req::RpcReceipt(by_hash(&sent.tx_hash)))
        .await
        .expect("receipt")
    else {
        panic!("expected EvmReceiptLookup");
    };
    assert!(lookup.receipt.expect("mined").success);

    let unknown = format!("0x{}", "ab".repeat(32));
    let Res::EvmReceiptLookup(lookup) = h
        .call(Req::RpcReceipt(by_hash(&unknown)))
        .await
        .expect("receipt")
    else {
        panic!("expected EvmReceiptLookup");
    };
    assert_eq!(lookup.receipt, None);
    let error = h
        .call(Req::RpcTx(by_hash("0x1234")))
        .await
        .expect_err("bad hash");
    assert!(matches!(error, PaymentsError::InvalidRequest(_)));
}

#[tokio::test]
async fn reads_refuse_non_evm_networks() {
    let h = Harness::new(open_policy()).await;
    let request = Req::RpcChainInfo(EvmNetworkParams {
        auth: h.auth.clone(),
        network: Some("solana-mainnet".into()),
    });
    assert!(matches!(
        h.call(request).await,
        Err(PaymentsError::InvalidRequest(_))
    ));
    assert!(h.mock.calls().is_empty());
}
