//! Ranking with the wallet's funds: a challenge the wallet cannot pay is
//! never preferred over one it can.

use std::sync::{Arc, Mutex};

use alloy_primitives::U256;
use mpp::protocol::core::{
    format_www_authenticate, parse_authorization, Base64UrlJson, PaymentChallenge, Receipt,
};
use serde_json::json;

use super::{Harness, RECIPIENT};
use crate::features::http::merchant::{Merchant, Reply, Seen};

const TOKEN: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const SETTLEMENT: &str = "0x5e771e5e771e5e771e5e771e5e771e5e771e5e77";

fn evm_challenge(id: &str, chain_id: u64, types: &[&str]) -> PaymentChallenge {
    let request = json!({
        "amount": "1000",
        "currency": TOKEN,
        "recipient": RECIPIENT,
        "methodDetails": {
            "chainId": chain_id,
            "credentialTypes": types,
            "permit2Spender": SETTLEMENT,
        },
    });
    PaymentChallenge::new(
        id,
        "api.example.com",
        "evm",
        "charge",
        Base64UrlJson::from_value(&request).expect("request"),
    )
}

/// Offers a gasless permit2 on Base and a `hash` on Optimism; accepts any
/// credential and logs `<challenge id> <type>`.
async fn two_chain_merchant(log: Arc<Mutex<Vec<String>>>) -> Merchant {
    Merchant::start(move |seen: &Seen| {
        let Some(header) = seen.header("authorization") else {
            let offered = [
                evm_challenge("base-permit2", 8_453, &["permit2"]),
                evm_challenge("optimism-hash", 10, &["hash"]),
            ]
            .iter()
            .map(|challenge| format_www_authenticate(challenge).expect("challenge"))
            .collect::<Vec<_>>()
            .join(", ");
            return Reply::new(402, "payment required").header("WWW-Authenticate", offered);
        };
        let credential = parse_authorization(header).expect("credential");
        let kind = credential.payload["type"].as_str().unwrap_or_default();
        log.lock()
            .expect("log")
            .push(format!("{} {kind}", credential.challenge.id));
        let receipt = Receipt::success("evm", "0xreference");
        Reply::new(200, "{}")
            .header("content-type", "application/json")
            .header("Payment-Receipt", receipt.to_header().expect("receipt"))
    })
    .await
}

#[tokio::test]
async fn a_gasless_challenge_the_wallet_cannot_fund_loses_to_one_it_can() {
    let harness = Harness::open().await;
    let base = harness.add_evm_chain("base", 8_453).await;
    let optimism = harness.add_evm_chain("optimism", 10).await;
    let log = Arc::new(Mutex::new(Vec::new()));
    let merchant = two_chain_merchant(log.clone()).await;

    // Funded on both chains: the gasless permit2 wins.
    base.chain().token_allowance = U256::MAX;
    harness
        .fetch(harness.params(format!("{}/x", merchant.url())))
        .await
        .expect("paid");
    // No tokens on Base: the payable hash on Optimism is chosen instead.
    base.chain().token_balance = U256::ZERO;
    let payment = harness
        .fetch(harness.params(format!("{}/x", merchant.url())))
        .await
        .expect("paid")
        .payment
        .expect("payment");
    assert_eq!(payment.network, "optimism");
    assert_eq!(
        *log.lock().expect("log"),
        ["base-permit2 permit2", "optimism-hash hash"]
    );
    assert_eq!(optimism.sent().len(), 1);
}
