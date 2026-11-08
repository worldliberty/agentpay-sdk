//! A signed transaction that never reached the network gives its nonce back
//! (`ReleaseSignedNonce`), so the next payment does not wait behind a gap;
//! one that may have reached it keeps the nonce.

use std::sync::Arc;

use agentpay_api::payments::PaymentsRpcResponse as Res;
use alloy_consensus::Transaction as _;

use super::*;

/// The mock chain's pending nonce for the wallet.
const PENDING_NONCE: u64 = 7;

fn sent_nonce(h: &Harness, index: usize) -> u64 {
    use alloy_eips::eip2718::Decodable2718;
    alloy_consensus::TxEnvelope::decode_2718_exact(&h.mock.sent()[index])
        .expect("signed envelope")
        .nonce()
}

#[tokio::test]
async fn a_send_the_node_rejected_returns_its_nonce() {
    let h = Harness::new(open_policy()).await;
    h.mock.chain().send_error = Some("insufficient funds for gas * price + value".into());
    let error = h
        .call(h.transfer("1", broadcast()))
        .await
        .expect_err("rejected by the node");
    assert!(matches!(error, PaymentsError::ChainRpc(_)), "{error:?}");
    assert_eq!(
        h.next_free_nonce(PENDING_NONCE).await,
        PENDING_NONCE,
        "the rejected transaction's nonce is free again"
    );

    // The retry (the chain still reports nonce 7) uses 7, not 8.
    h.mock.chain().send_error = None;
    let Res::EvmTransaction(tx) = h.call(h.transfer("1", broadcast())).await.expect("sent") else {
        panic!("expected EvmTransaction");
    };
    assert_eq!(tx.nonce, PENDING_NONCE);
    assert_eq!(sent_nonce(&h, 0), PENDING_NONCE);
}

#[tokio::test]
async fn an_ambiguous_send_keeps_its_nonce() {
    let h = Harness::new(open_policy()).await;
    // A proxy fails after the node may have accepted the transaction.
    h.mock.chain().send_http_status = Some(502);
    let error = h
        .call(h.transfer("1", broadcast()))
        .await
        .expect_err("HTTP 502");
    assert!(matches!(error, PaymentsError::ChainRpc(_)), "{error:?}");
    assert_eq!(h.mock.sent().len(), 1, "the node may have it");
    assert_eq!(
        h.next_free_nonce(PENDING_NONCE).await,
        PENDING_NONCE + 1,
        "the nonce stays used: reusing it could replace a live transaction"
    );
}

#[tokio::test]
async fn a_signed_transaction_that_fails_verification_returns_its_nonce() {
    let (signer, auth) = InProcessSigner::with_agent(open_policy()).await;
    let h = Harness::with_signer(Arc::new(signer), auth, |signer| {
        Arc::new(TamperingSigner(signer))
    })
    .await;
    let error = h
        .call(h.transfer("1", broadcast()))
        .await
        .expect_err("tampered");
    assert!(matches!(error, PaymentsError::SignedTransactionMismatch(_)));
    assert!(h.mock.sent().is_empty());
    assert_eq!(h.next_free_nonce(PENDING_NONCE).await, PENDING_NONCE);
}
