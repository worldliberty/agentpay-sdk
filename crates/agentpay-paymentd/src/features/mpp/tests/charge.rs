//! Tempo charges, selection rules, and header handling.

use agentpay_api::payments::HttpBody;
use agentpay_api::WireDaemonError;
use serde_json::json;

use super::merchant::{MppMerchant, Terms};
use super::{Harness, PATH_USD};
use crate::error::PaymentsError;
use crate::signer::testing::per_tx_limit;

#[tokio::test]
async fn a_charge_is_paid_with_a_memo_bound_transfer_and_a_hash_credential() {
    let harness = Harness::open().await;
    let mut terms = Terms::charge(25_000);
    terms.opaque = Some(json!({"order": "A-17", "nonce": 3}));
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let mut params = harness.params(merchant.url("/v1/answer"));
    params.amount = Some(25_000);
    let result = harness.fetch(params).await.expect("paid");

    assert_eq!(result.response.status, 200);
    assert_eq!(
        result.response.body,
        HttpBody::Text("{\"answer\":42}".into())
    );
    let payment = result.payment.expect("payment");
    assert_eq!(
        (payment.intent.as_str(), payment.amount),
        ("charge", 25_000)
    );
    assert_eq!(payment.session_protocol, None);
    assert_eq!(payment.currency.to_string(), PATH_USD);
    let charge = payment.charge.expect("charge");
    assert_eq!(merchant.log(), ["charge"]);
    assert_eq!(
        payment.receipt.expect("receipt")["reference"],
        charge.tx_hash.as_deref().expect("hash")
    );
    assert_eq!(charge.credential_type, "hash");
    assert_eq!(payment.network, "tempo-testnet");
    assert_eq!(harness.rpc.sent().len(), 1);
}

#[tokio::test]
async fn a_policy_denial_sends_nothing() {
    let harness = Harness::new(vec![per_tx_limit(24_999)]).await;
    let merchant = MppMerchant::start(Terms::charge(25_000), harness.rpc.clone()).await;
    let error = harness
        .fetch(harness.params(merchant.url("/v1/answer")))
        .await
        .expect_err("denied");
    assert!(
        matches!(error, PaymentsError::Signer(WireDaemonError::Policy(_))),
        "{error:?}"
    );
    assert!(harness.rpc.sent().is_empty());
    assert!(merchant.log().is_empty());
}

#[tokio::test]
async fn the_challenge_header_parameter_is_honored() {
    let harness = Harness::open().await;
    let mut terms = Terms::charge(1_000);
    terms.payment_authorization = true;
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let result = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid");
    assert_eq!(result.response.status, 200);
    let paid = merchant.http.seen();
    assert!(paid[1].header("payment-authorization").is_some());
}

#[tokio::test]
async fn amount_and_currency_filters_refuse_before_signing() {
    let harness = Harness::open().await;
    let merchant = MppMerchant::start(Terms::charge(25_000), harness.rpc.clone()).await;
    let mut wrong_amount = harness.params(merchant.url("/x"));
    wrong_amount.amount = Some(1);
    let mut wrong_currency = harness.params(merchant.url("/x"));
    wrong_currency.currency = Some("0x20c0000000000000000000000000000000000001".into());
    for params in [wrong_amount, wrong_currency] {
        let error = harness.fetch(params).await.expect_err("refused");
        assert!(
            matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("nothing was signed")),
            "{error:?}"
        );
    }
    assert!(harness.rpc.sent().is_empty());
}

#[tokio::test]
async fn split_and_unsupported_charges_are_refused() {
    let harness = Harness::open().await;
    let mut terms = Terms::charge(1_000);
    terms.details = json!({"splits": [{"recipient": PATH_USD, "amount": "10"}]});
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let error = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect_err("splits");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("split")),
        "{error:?}"
    );

    let mut terms = Terms::charge(1_000);
    terms.details = json!({"chainId": 1});
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let error = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect_err("not tempo");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("not a Tempo chain")),
        "{error:?}"
    );
}

#[tokio::test]
async fn unpaid_responses_pass_through() {
    let harness = Harness::open().await;
    let merchant = crate::features::http::merchant::Merchant::start(|_| {
        crate::features::http::merchant::Reply::new(200, "free")
    })
    .await;
    let result = harness
        .fetch(harness.params(format!("{}/free", merchant.url())))
        .await
        .expect("free");
    assert!(result.payment.is_none());
    assert_eq!(result.response.body, HttpBody::Text("free".into()));
}

#[tokio::test]
async fn a_tempo_charge_in_a_token_that_is_not_tip20_is_never_paid() {
    // A plain ERC-20 on Tempo (USD1's CCIP contract), without `transferWithMemo`.
    const ERC20: &str = "0x111111d2bf19e43c34263401e0cad979ed1cdb61";
    let harness = Harness::open().await;
    let mut terms = Terms::charge(1_000);
    terms.other_currencies = vec![ERC20];
    let merchant = MppMerchant::start(terms, harness.rpc.clone()).await;
    let mut params = harness.params(merchant.url("/x"));
    params.currency = Some(ERC20.into());
    let error = harness.fetch(params).await.expect_err("not TIP-20");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("not a TIP-20 token")),
        "{error:?}"
    );
    assert!(harness.rpc.sent().is_empty());

    // Without the filter, the pathUSD challenge next to it is paid.
    let result = harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid");
    assert_eq!(result.payment.expect("payment").currency, PATH_USD);
}

#[tokio::test]
async fn a_tempo_charge_needs_no_native_coin() {
    // Tempo fees are paid in the stablecoin: the gas check skips Tempo.
    let harness = Harness::open().await;
    harness.rpc.chain().balance = alloy_primitives::U256::ZERO;
    let merchant = MppMerchant::start(Terms::charge(1_000), harness.rpc.clone()).await;
    harness
        .fetch(harness.params(merchant.url("/x")))
        .await
        .expect("paid");
    assert_eq!(merchant.log(), ["charge"]);
}
