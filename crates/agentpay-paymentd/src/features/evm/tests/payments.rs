//! `Transfer`, `TransferNative`, `Approve`, and `Broadcast`: sign-only and
//! broadcast flows, verification, policy denial, and nonce release.

use std::sync::Arc;

use agentpay_api::payments::{
    ApproveParams, BroadcastParams, EvmTxOptions, PaymentsRpcRequest as Req,
    PaymentsRpcResponse as Res, TransferNativeParams, TransferParams,
};
use agentpay_api::types::PolicyError;
use agentpay_api::WireDaemonError;
use agentpay_domain::AgentAction;
use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, Address, U256};

use super::*;
use crate::chains::evm::hex_prefixed;
use crate::signer::testing::per_tx_limit;

fn decode(raw: &[u8]) -> TxEnvelope {
    TxEnvelope::decode_2718_exact(raw).expect("signed envelope")
}

#[tokio::test]
async fn a_sign_only_transfer_uses_the_defaults_and_needs_no_rpc() {
    let h = Harness::new(open_policy()).await;
    let response = h
        .call(h.transfer("1.5", EvmTxOptions::default()))
        .await
        .expect("signed");
    let Res::EvmSignature(signed) = response else {
        panic!("expected EvmSignature, got {response:?}");
    };
    assert_eq!(
        (signed.network.as_deref(), signed.chain_id),
        (Some("bsc"), 56)
    );
    let payment = signed.payment.expect("payment");
    assert_eq!(payment.asset.key.as_deref(), Some("usd1"));
    assert_eq!(
        (payment.amount.as_str(), payment.amount_wei),
        ("1.5", ONE_USD1 * 3 / 2)
    );
    assert_eq!(
        signed.action,
        AgentAction::Transfer {
            chain_id: 56,
            token: address(USD1),
            to: address(RECIPIENT),
            amount_wei: ONE_USD1 * 3 / 2,
        }
    );
    assert!(signed.signature_hex.starts_with("0x30"), "a DER signature");
    assert!(
        h.mock.calls().is_empty(),
        "sign-only transfers of configured tokens make no RPC calls"
    );
}

#[tokio::test]
async fn a_broadcast_transfer_is_planned_signed_verified_sent_and_confirmed() {
    let h = Harness::new(open_policy()).await;
    let options = EvmTxOptions {
        wait_for_receipt: true,
        ..broadcast()
    };
    let response = h.call(h.transfer("1", options)).await.expect("sent");
    let Res::EvmTransaction(tx) = response else {
        panic!("expected EvmTransaction, got {response:?}");
    };
    let sent = h.mock.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(tx.raw_tx_hex, hex_prefixed(&sent[0]));
    assert_eq!(tx.tx_hash, hex_prefixed(keccak256(&sent[0]).as_slice()));
    assert!(tx.broadcast && !tx.receipt_timed_out);
    let receipt = tx.receipt.expect("receipt");
    assert!(receipt.success);
    assert_eq!(receipt.tx_hash, tx.tx_hash);

    // The envelope is the ERC-20 call to the token contract, signed by the wallet.
    let envelope = decode(&sent[0]);
    assert_eq!(envelope.to(), Some(USD1.parse::<Address>().unwrap()));
    assert_eq!(envelope.value(), U256::ZERO);
    assert_eq!(hex_prefixed(envelope.input()), tx.data_hex);
    assert!(tx.data_hex.starts_with("0xa9059cbb"));
    assert_eq!(
        (tx.nonce, envelope.nonce()),
        (7, 7),
        "the account's pending nonce"
    );
    assert_eq!(tx.gas_limit, 34_512, "estimated");
    assert_eq!(tx.from, h.wallet().await);
    assert!(tx.max_priority_fee_per_gas_wei <= tx.max_fee_per_gas_wei);

    let calls = h.mock.calls();
    assert_eq!(calls[0], "eth_chainId", "the chain id is checked first");
    for method in [
        "eth_getTransactionCount",
        "eth_estimateGas",
        "eth_sendRawTransaction",
    ] {
        assert!(calls.iter().any(|c| c == method), "{method} in {calls:?}");
    }
    // The signer daemon consumed nonce 7.
    assert_eq!(h.next_free_nonce(7).await, 8);
}

#[tokio::test]
async fn explicit_nonce_gas_and_fees_are_used_verbatim() {
    let h = Harness::new(open_policy()).await;
    let options = EvmTxOptions {
        nonce: Some(12),
        gas_limit: Some(70_000),
        max_fee_per_gas_wei: Some(2_000_000_000),
        max_priority_fee_per_gas_wei: Some(1_000_000_000),
        ..broadcast()
    };
    let Res::EvmTransaction(tx) = h.call(h.transfer("1", options)).await.expect("sent") else {
        panic!("expected EvmTransaction");
    };
    assert_eq!(
        (
            tx.nonce,
            tx.gas_limit,
            tx.max_fee_per_gas_wei,
            tx.max_priority_fee_per_gas_wei
        ),
        (12, 70_000, 2_000_000_000, 1_000_000_000)
    );
    let envelope = decode(&h.mock.sent()[0]);
    assert_eq!((envelope.nonce(), envelope.gas_limit()), (12, 70_000));
    let calls = h.mock.calls();
    for method in [
        "eth_getTransactionCount",
        "eth_estimateGas",
        "eth_feeHistory",
        "eth_gasPrice",
    ] {
        assert!(
            !calls.iter().any(|c| c == method),
            "{method} must not be called: {calls:?}"
        );
    }
    assert!(
        !tx.receipt_timed_out && tx.receipt.is_none(),
        "no receipt wait was asked for"
    );
}

#[tokio::test]
async fn native_transfers_and_approvals_build_the_right_transactions() {
    let h = Harness::new(open_policy()).await;
    let native = Req::TransferNative(TransferNativeParams {
        auth: h.auth.clone(),
        network: Some("bsc".into()),
        to: address(RECIPIENT),
        amount: "0.25".into(),
        options: broadcast(),
    });
    let Res::EvmTransaction(tx) = h.call(native).await.expect("native") else {
        panic!("expected EvmTransaction");
    };
    assert_eq!(
        tx.payment.as_ref().map(|p| p.asset.symbol.as_str()),
        Some("BNB")
    );
    assert_eq!(
        (tx.to.as_str(), tx.value_wei, tx.data_hex.as_str()),
        (RECIPIENT, ONE_USD1 / 4, "0x")
    );

    let approve = Req::Approve(ApproveParams {
        auth: h.auth.clone(),
        network: None,
        asset: Some("USD1".into()),
        spender: address(RECIPIENT),
        amount: "100".into(),
        options: broadcast(),
    });
    let Res::EvmTransaction(tx) = h.call(approve).await.expect("approve") else {
        panic!("expected EvmTransaction");
    };
    assert_eq!(tx.to.as_str(), USD1);
    assert!(
        tx.data_hex.starts_with("0x095ea7b3"),
        "approve(spender, amount)"
    );
    assert_eq!(tx.nonce, 8, "the next free nonce after the native transfer");
    let sent = h.mock.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(decode(&sent[1]).nonce(), 8);
}

#[tokio::test]
async fn a_broadcast_request_without_sending_returns_the_signed_transaction() {
    let h = Harness::new(open_policy()).await;
    let request = Req::Broadcast(BroadcastParams {
        auth: h.auth.clone(),
        network: None,
        to: address(RECIPIENT),
        value_wei: 5,
        data_hex: "0x".into(),
        options: EvmTxOptions::default(),
    });
    let Res::EvmTransaction(tx) = h.call(request).await.expect("signed") else {
        panic!("expected EvmTransaction");
    };
    assert!(!tx.broadcast && tx.payment.is_none());
    assert!(h.mock.sent().is_empty());
    let raw = alloy_primitives::hex::decode(&tx.raw_tx_hex[2..]).unwrap();
    assert_eq!(decode(&raw).value(), U256::from(5));
    assert_eq!(
        h.next_free_nonce(tx.nonce).await,
        tx.nonce + 1,
        "the caller holds the signed transaction, so its nonce stays used"
    );
}

#[tokio::test]
async fn a_policy_denial_is_structured_and_releases_the_nonce() {
    let h = Harness::new(vec![per_tx_limit(ONE_USD1)]).await;
    let error = h
        .call(h.transfer("2", broadcast()))
        .await
        .expect_err("denied");
    let PaymentsError::Signer(WireDaemonError::Policy(PolicyError::PerTxLimitExceeded {
        max_amount_wei,
        requested_amount_wei,
        ..
    })) = error
    else {
        panic!("expected a per-transaction limit denial, got {error:?}");
    };
    assert_eq!(
        (max_amount_wei, requested_amount_wei),
        (ONE_USD1, 2 * ONE_USD1)
    );
    assert!(h.mock.sent().is_empty());
    assert_eq!(
        h.next_free_nonce(7).await,
        7,
        "the reservation was released"
    );

    // Within the limit the same flow goes through.
    assert!(matches!(
        h.call(h.transfer("1", broadcast())).await,
        Ok(Res::EvmTransaction(_))
    ));
}

#[tokio::test]
async fn a_signed_transaction_that_differs_from_the_request_is_never_sent() {
    let (signer, auth) = InProcessSigner::with_agent(open_policy()).await;
    let h = Harness::with_signer(Arc::new(signer), auth, |signer| {
        Arc::new(TamperingSigner(signer))
    })
    .await;
    let error = h
        .call(h.transfer("1", broadcast()))
        .await
        .expect_err("tampered");
    assert!(
        matches!(&error, PaymentsError::SignedTransactionMismatch(m) if m.contains("gas limit")),
        "{error:?}"
    );
    assert!(h.mock.sent().is_empty(), "nothing is broadcast");
    assert!(!h.mock.calls().iter().any(|c| c == "eth_sendRawTransaction"));
}

#[tokio::test]
async fn unconfigured_token_metadata_comes_from_the_chain() {
    let h = Harness::new(open_policy()).await;
    let request = Req::Transfer(TransferParams {
        auth: h.auth.clone(),
        network: Some("bsc".into()),
        asset: Some("0x3333333333333333333333333333333333333333".into()),
        to: address(RECIPIENT),
        amount: "1.5".into(),
        options: EvmTxOptions::default(),
    });
    let Res::EvmSignature(signed) = h.call(request).await.expect("signed") else {
        panic!("expected EvmSignature");
    };
    let payment = signed.payment.expect("payment");
    assert_eq!(
        (payment.asset.symbol.as_str(), payment.asset.decimals),
        ("TKN", 6)
    );
    assert_eq!((payment.asset.key, payment.amount_wei), (None, 1_500_000));
}

#[tokio::test]
async fn invalid_requests_fail_before_anything_is_signed() {
    let h = Harness::new(open_policy()).await;
    let with = |network: Option<&str>, asset: Option<&str>, amount: &str, options: EvmTxOptions| {
        Req::Transfer(TransferParams {
            auth: h.auth.clone(),
            network: network.map(str::to_string),
            asset: asset.map(str::to_string),
            to: address(RECIPIENT),
            amount: amount.into(),
            options,
        })
    };
    let nonce_without_broadcast = EvmTxOptions {
        nonce: Some(1),
        ..EvmTxOptions::default()
    };
    let cases = [
        with(None, None, "0", EvmTxOptions::default()),
        with(None, None, "1.0000000000000000001", EvmTxOptions::default()),
        with(Some("nowhere"), None, "1", EvmTxOptions::default()),
        with(Some("solana-mainnet"), None, "1", EvmTxOptions::default()),
        with(None, Some("bnb"), "1", EvmTxOptions::default()),
        with(None, Some("0x12"), "1", EvmTxOptions::default()),
        with(None, None, "1", nonce_without_broadcast),
    ];
    for request in cases {
        let error = h.call(request).await.expect_err("invalid");
        assert!(
            matches!(error, PaymentsError::InvalidRequest(_)),
            "{error:?}"
        );
    }
    assert!(h.mock.sent().is_empty());
    assert_eq!(h.next_free_nonce(7).await, 7);
}

#[tokio::test]
async fn an_endpoint_for_another_chain_stops_the_payment_before_signing() {
    let h = Harness::new(open_policy()).await;
    h.mock.chain().chain_id = 1;
    let error = h
        .call(h.transfer("1", broadcast()))
        .await
        .expect_err("wrong chain");
    assert!(
        matches!(&error, PaymentsError::ChainRpc(m) if m.contains("chain id")),
        "{error:?}"
    );
    assert_eq!(h.mock.calls(), ["eth_chainId"]);
    assert_eq!(h.next_free_nonce(7).await, 7, "no nonce was reserved");
}

#[tokio::test]
async fn a_rejected_broadcast_is_reported_and_a_lost_receipt_is_not_an_error() {
    let h = Harness::new(open_policy()).await;
    h.mock.chain().send_error = Some("insufficient funds for gas * price + value".into());
    let error = h
        .call(h.transfer("1", broadcast()))
        .await
        .expect_err("rejected");
    assert!(
        matches!(&error, PaymentsError::ChainRpc(m) if m.contains("insufficient funds")),
        "{error:?}"
    );

    let h = Harness::new(open_policy()).await;
    h.mock.chain().mined = false;
    let options = EvmTxOptions {
        wait_for_receipt: true,
        receipt_timeout_secs: Some(0),
        ..broadcast()
    };
    let Res::EvmTransaction(tx) = h.call(h.transfer("1", options)).await.expect("sent") else {
        panic!("expected EvmTransaction");
    };
    assert!(tx.broadcast && tx.receipt.is_none() && tx.receipt_timed_out);
}
