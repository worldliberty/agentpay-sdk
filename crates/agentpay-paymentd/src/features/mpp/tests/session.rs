//! TIP-1034 sessions: open, persisted reuse, top-up, close, deposit caps,
//! v1 rejection, selection by the persisted channel, and event streams.

use agentpay_api::payments::HttpBody;
use serde_json::json;

use super::merchant::{MppMerchant, Terms};
use super::Harness;
use crate::error::PaymentsError;
use crate::features::mpp::store::{SessionLocks, SessionStore};

const AMOUNT: u128 = 25_000;

#[tokio::test]
async fn a_persisted_channel_is_reused_topped_up_and_closed() {
    let harness = Harness::open().await;
    let merchant = MppMerchant::start(
        Terms::session(AMOUNT, Some(2 * AMOUNT)),
        harness.rpc.clone(),
    )
    .await;
    let url = merchant.url("/v1/complete");
    let call = |close: bool| {
        let mut params = harness.params(url.clone());
        params.session_key = Some("llm".into());
        params.close_session = close;
        params
    };

    // 1: open with the suggested deposit and a first voucher.
    let first = harness.fetch(call(false)).await.expect("open");
    let session = first
        .payment
        .as_ref()
        .and_then(|p| p.session.clone())
        .expect("session");
    assert!(session.opened && !session.closed);
    assert_eq!(
        (session.deposit, session.cumulative_amount),
        (2 * AMOUNT, AMOUNT)
    );
    assert_eq!(
        first
            .payment
            .as_ref()
            .and_then(|p| p.session_protocol.clone())
            .as_deref(),
        Some("v2")
    );
    let receipt = first.payment.and_then(|p| p.receipt).expect("receipt");
    assert_eq!(receipt["channelId"], session.channel_id.as_str());
    let persisted = SessionStore::new(harness.dir(), &SessionLocks::default())
        .load(harness.auth.agent_key_id, "llm")
        .expect("load")
        .expect("persisted");
    assert_eq!(persisted.cumulative, AMOUNT);

    // 2: the same channel pays with a voucher.
    let second = harness.fetch(call(false)).await.expect("voucher");
    let reused = second.payment.and_then(|p| p.session).expect("session");
    assert_eq!(reused.channel_id, session.channel_id);
    assert!(!reused.opened);
    assert_eq!(
        (reused.cumulative_amount, reused.topped_up),
        (2 * AMOUNT, 0)
    );

    // 3: the deposit is exhausted, so the channel is topped up first.
    let third = harness.fetch(call(false)).await.expect("top-up");
    let topped = third.payment.and_then(|p| p.session).expect("session");
    assert_eq!(topped.topped_up, AMOUNT);
    assert_eq!(
        (topped.deposit, topped.cumulative_amount),
        (3 * AMOUNT, 3 * AMOUNT)
    );

    // 4: close after the paid response.
    let fourth = harness.fetch(call(true)).await.expect("close");
    let closed = fourth.payment.and_then(|p| p.session).expect("session");
    assert!(closed.closed);
    assert!(closed.close_receipt.is_some());
    assert_eq!(
        merchant.log(),
        ["open", "voucher", "top-up", "voucher", "top-up", "voucher", "close"]
    );
    let channel = merchant.channel();
    assert_eq!(channel.payer, harness.wallet);
    assert!(channel.closed);
    assert_eq!(
        (channel.deposit, channel.accepted),
        (4 * AMOUNT, 4 * AMOUNT)
    );
    assert!(SessionStore::new(harness.dir(), &SessionLocks::default())
        .load(harness.auth.agent_key_id, "llm")
        .expect("load")
        .is_none());
}

#[tokio::test]
async fn a_one_call_session_without_a_key_is_closed_and_self_paid_opens_estimate_gas() {
    let harness = Harness::open().await;
    let mut terms = Terms::session(AMOUNT, None);
    terms.fee_payer = false;
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let result = harness
        .fetch(harness.params(merchant.url("/once")))
        .await
        .expect("paid");
    let session = result.payment.and_then(|p| p.session).expect("session");
    assert!(session.opened && session.closed && session.session_key.is_none());
    assert_eq!(session.deposit, AMOUNT);
    assert_eq!(merchant.log(), ["open", "close"]);
    assert!(harness
        .rpc
        .calls()
        .iter()
        .any(|call| call == "eth_estimateGas"));
}

#[tokio::test]
async fn deposits_respect_max_deposit() {
    let harness = Harness::open().await;
    let merchant = MppMerchant::start(
        Terms::session(AMOUNT, Some(10 * AMOUNT)),
        harness.rpc.clone(),
    )
    .await;
    let mut explicit = harness.params(merchant.url("/x"));
    explicit.deposit = Some(5 * AMOUNT);
    explicit.max_deposit = Some(2 * AMOUNT);
    let error = harness.fetch(explicit).await.expect_err("above the cap");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("max_deposit")),
        "{error:?}"
    );
    assert!(merchant.log().is_empty());

    let mut capped = harness.params(merchant.url("/x"));
    capped.max_deposit = Some(2 * AMOUNT);
    capped.session_key = Some("capped".into());
    let result = harness.fetch(capped.clone()).await.expect("capped deposit");
    let session = result.payment.and_then(|p| p.session).expect("session");
    assert_eq!(
        session.deposit,
        2 * AMOUNT,
        "the suggested deposit is lowered to the cap"
    );
    harness.fetch(capped.clone()).await.expect("second voucher");
    let error = harness
        .fetch(capped)
        .await
        .expect_err("top-up above the cap");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("max_deposit")),
        "{error:?}"
    );
}

#[tokio::test]
async fn legacy_v1_sessions_are_rejected() {
    let harness = Harness::open().await;
    for details in [
        json!({"sessionProtocol": "v1"}),
        json!({"escrowContract": "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"}),
    ] {
        let mut terms = Terms::session(AMOUNT, None);
        terms.details = details;
        let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
        let error = harness
            .fetch(harness.params(merchant.url("/x")))
            .await
            .expect_err("v1");
        assert!(
            matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("sessions v1")),
            "{error:?}"
        );
        assert!(merchant.log().is_empty());
    }
}

#[tokio::test]
async fn a_persisted_channel_filters_challenges_before_selection() {
    let harness = Harness::open().await;
    let merchant = MppMerchant::start(Terms::session(AMOUNT, None), harness.rpc.clone()).await;
    let call = || {
        let mut params = harness.params(merchant.url("/x"));
        params.session_key = Some("shop".into());
        params
    };
    harness.fetch(call()).await.expect("open");

    // The merchant now asks to pay another recipient: the persisted channel
    // cannot pay it, and no new channel is opened behind the caller's back.
    let mut terms = Terms::session(AMOUNT, None);
    terms.recipient = "0x1111111111111111111111111111111111111111";
    merchant.set_terms(terms);
    let error = harness.fetch(call()).await.expect_err("other recipient");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("persisted channel")),
        "{error:?}"
    );
    assert_eq!(merchant.log(), ["open"]);

    // A different origin cannot use the key either.
    let other = MppMerchant::start(Terms::session(AMOUNT, None), harness.rpc.clone()).await;
    let mut params = harness.params(other.url("/x"));
    params.session_key = Some("shop".into());
    let error = harness.fetch(params).await.expect_err("other origin");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("another origin")),
        "{error:?}"
    );
}

#[tokio::test]
async fn event_streams_are_collected_and_need_voucher_events_answered() {
    let harness = Harness::open().await;
    let mut terms = Terms::session(AMOUNT, Some(AMOUNT));
    terms.stream = true;
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let mut params = harness.params(merchant.url("/stream"));
    params.session_key = Some("stream".into());
    let result = harness.fetch(params).await.expect("stream");
    let HttpBody::Text(body) = &result.response.body else {
        panic!("a text body");
    };
    assert!(body.contains("data: hello") && body.contains("data: world"));
    let payment = result.payment.expect("payment");
    let session = payment.session.expect("session");
    assert_eq!(
        session.vouchers, 2,
        "the stream's need-voucher was answered"
    );
    assert_eq!(
        (session.cumulative_amount, session.topped_up),
        (2 * AMOUNT, AMOUNT)
    );
    assert_eq!(merchant.log(), ["open", "top-up", "voucher"]);
    assert_eq!(
        payment.receipt.expect("stream receipt")["acceptedCumulative"],
        (2 * AMOUNT).to_string()
    );
}

#[tokio::test]
async fn a_gone_channel_is_forgotten_and_a_new_one_opened() {
    let harness = Harness::open().await;
    let merchant = MppMerchant::start(
        Terms::session(AMOUNT, Some(4 * AMOUNT)),
        harness.rpc.clone(),
    )
    .await;
    let call = || {
        let mut params = harness.params(merchant.url("/x"));
        params.session_key = Some("gone".into());
        params
    };
    let first = harness.fetch(call()).await.expect("open");
    let first = first.payment.and_then(|p| p.session).expect("session");
    merchant.forget_channels();
    let second = harness.fetch(call()).await.expect("reopened");
    let second = second.payment.and_then(|p| p.session).expect("session");
    assert!(second.opened);
    assert_ne!(second.channel_id, first.channel_id);
    assert_eq!(merchant.log(), ["open", "open"]);
    let persisted = SessionStore::new(harness.dir(), &SessionLocks::default())
        .load(harness.auth.agent_key_id, "gone")
        .expect("load")
        .expect("persisted");
    assert_eq!(persisted.channel_id_hex, second.channel_id);
}
