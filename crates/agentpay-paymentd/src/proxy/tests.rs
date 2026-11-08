//! The paying proxy over real sockets: lifecycle, authentication, allowed
//! hosts, paying x402 and MPP `402`s for an unaware HTTP client, and TLS
//! interception with the per-run CA.

use agentpay_api::payments::{
    PaymentsRpcRequest as Req, PaymentsRpcResponse as Res, ProxyParams, ProxyStartParams,
    ProxyStartResult, ProxyStatusResult,
};
use base64::Engine;
use serde_json::json;
use uuid::Uuid;

use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::features::http::merchant::{Merchant, Reply, Seen};
use crate::features::mpp::tests::merchant::{MppMerchant, Terms};
use crate::features::mpp::tests::{Harness, PATH_USD};

async fn start(
    harness: &Harness,
    allowed_hosts: Option<Vec<String>>,
    max_amount: Option<u128>,
) -> Result<ProxyStartResult, PaymentsError> {
    start_with(
        harness,
        ProxyStartParams {
            auth: harness.auth.clone(),
            port: None,
            allowed_hosts,
            max_amount,
            currency: None,
            network: None,
            deposit: None,
            max_deposit: None,
        },
    )
    .await
}

async fn start_with(
    harness: &Harness,
    params: ProxyStartParams,
) -> Result<ProxyStartResult, PaymentsError> {
    match dispatch(&harness.state, Req::ProxyStart(params)).await? {
        Res::ProxyStarted(started) => Ok(started),
        other => panic!("unexpected response {other:?}"),
    }
}

async fn status(harness: &Harness, stop: bool) -> ProxyStatusResult {
    let params = ProxyParams {
        auth: harness.auth.clone(),
    };
    let request = if stop {
        Req::ProxyStop(params)
    } else {
        Req::ProxyStatus(params)
    };
    match dispatch(&harness.state, request).await.expect("status") {
        Res::ProxyStatus(status) => status,
        other => panic!("unexpected response {other:?}"),
    }
}

fn client(started: &ProxyStartResult) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(started.proxy_url.as_str()).expect("proxy"))
        .build()
        .expect("client")
}

/// A merchant charging 1000 base units of USDC with x402 v2 (checked
/// structurally; the x402 tests verify the signature itself).
async fn x402_merchant() -> Merchant {
    Merchant::start(|seen: &Seen| {
        if seen.header("payment-signature").is_some() {
            assert_eq!(seen.method, "POST");
            assert_eq!(seen.body, b"{\"q\":1}");
            return Reply::new(200, "paid content");
        }
        let required = json!({
            "x402Version": 2,
            "resource": {"url": "http://127.0.0.1/data"},
            "accepts": [{
                "scheme": "exact", "network": "eip155:84532", "amount": "1000",
                "payTo": "0x209693bc6afc0c5328ba36faf03c514ef312287c", "maxTimeoutSeconds": 60,
                "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
                "extra": {"name": "USDC", "version": "2"}
            }]
        });
        Reply::new(402, "").header(
            "PAYMENT-REQUIRED",
            base64::engine::general_purpose::STANDARD.encode(required.to_string()),
        )
    })
    .await
}

#[tokio::test]
async fn the_proxy_starts_once_reports_status_and_stops() {
    let harness = Harness::open().await;
    assert!(!status(&harness, false).await.running);
    let started = start(
        &harness,
        Some(vec!["LOCALHOST".into(), "127.0.0.1".into()]),
        Some(5),
    )
    .await
    .expect("start");
    assert!(started.status.running);
    assert_eq!(started.status.allowed_hosts, ["localhost", "127.0.0.1"]);
    assert_eq!(started.token.len(), 64);
    let address = started.status.address.clone().expect("address");
    assert!(address.starts_with("127.0.0.1:"));
    assert_eq!(
        started.proxy_url.as_str(),
        format!("http://agentpay:{}@{address}", started.token.as_str())
    );
    assert!(started
        .ca_certificate_pem
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(!format!("{started:?}").contains(started.token.as_str()));

    let again = start(&harness, None, None)
        .await
        .expect_err("already running");
    assert!(
        matches!(again, PaymentsError::InvalidRequest(_)),
        "{again:?}"
    );
    let other = harness
        .state
        .proxy
        .stop(Uuid::new_v4())
        .await
        .expect_err("not the owner");
    assert!(
        matches!(other, PaymentsError::InvalidRequest(_)),
        "{other:?}"
    );

    let running = status(&harness, false).await;
    assert!(running.running && running.agent_key_id == Some(harness.auth.agent_key_id));
    let stopped = status(&harness, true).await;
    assert!(!stopped.running && stopped.address.is_none());
    assert!(!status(&harness, false).await.running);
    // The listener is gone.
    assert!(tokio::net::TcpStream::connect(&address).await.is_err());
    // Bad hosts are refused.
    let bad = start(&harness, Some(vec!["https://x.example".into()]), None)
        .await
        .expect_err("bad host");
    assert!(matches!(bad, PaymentsError::InvalidRequest(_)), "{bad:?}");
}

#[tokio::test]
async fn requests_without_the_token_are_refused_and_never_forwarded() {
    let harness = Harness::open().await;
    let merchant = x402_merchant().await;
    let started = start(&harness, None, None).await.expect("start");
    let address = started.status.address.clone().expect("address");
    let target = format!("{}/data", merchant.url());
    for proxy in [
        format!("http://{address}"),
        format!("http://agentpay:{}@{address}", "0".repeat(64)),
    ] {
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(proxy).expect("proxy"))
            .build()
            .expect("client");
        let response = client.get(&target).send().await.expect("response");
        assert_eq!(response.status(), 407);
        assert!(response.headers().contains_key("proxy-authenticate"));
    }
    assert!(merchant.seen().is_empty(), "nothing reached the merchant");
    // A bearer token works too.
    let raw = format!(
        "POST {target} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Bearer {}\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{{\"q\":1}}",
        started.token.as_str()
    );
    let mut stream = tokio::net::TcpStream::connect(&address)
        .await
        .expect("connect");
    tokio::io::AsyncWriteExt::write_all(&mut stream, raw.as_bytes())
        .await
        .expect("write");
    let mut answer = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut answer)
        .await
        .expect("read");
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200"));
    status(&harness, true).await;
}

#[tokio::test]
async fn the_proxy_pays_x402_and_mpp_402s_for_an_unaware_client() {
    let harness = Harness::open().await;
    let x402 = x402_merchant().await;
    let mpp = MppMerchant::start(Terms::charge(25_000), harness.rpc.clone()).await;
    let started = start(&harness, Some(vec!["127.0.0.1".into()]), Some(100_000))
        .await
        .expect("start");
    let client = client(&started);

    let paid = client
        .post(format!("{}/data", x402.url()))
        .body("{\"q\":1}")
        .send()
        .await
        .expect("x402 response");
    assert_eq!(paid.status(), 200);
    assert_eq!(paid.text().await.expect("body"), "paid content");

    let paid = client
        .get(mpp.url("/v1/answer"))
        .send()
        .await
        .expect("mpp response");
    assert_eq!(paid.status(), 200);
    assert!(paid.headers().contains_key("payment-receipt"));
    assert_eq!(mpp.log(), ["charge"]);

    let counters = status(&harness, false).await;
    assert_eq!((counters.payments, counters.failed_payments), (2, 0));
    status(&harness, true).await;
}

#[tokio::test]
async fn caps_and_allowed_hosts_are_enforced() {
    let harness = Harness::open().await;
    let x402 = x402_merchant().await;
    let started = start(&harness, Some(vec!["127.0.0.1".into()]), Some(999))
        .await
        .expect("start");
    let client = client(&started);
    let refused = client
        .post(format!("{}/data", x402.url()))
        .body("{\"q\":1}")
        .send()
        .await
        .expect("response");
    assert_eq!(refused.status(), 402);
    assert_eq!(
        refused
            .headers()
            .get("x-agentpay-proxy-error")
            .and_then(|v| v.to_str().ok()),
        Some("InvalidRequest")
    );
    let localhost = x402.url().replace("127.0.0.1", "localhost");
    let forbidden = client
        .get(format!("{localhost}/data"))
        .send()
        .await
        .expect("response");
    assert_eq!(forbidden.status(), 403);
    assert_eq!(status(&harness, false).await.failed_payments, 1);
    status(&harness, true).await;
}

#[tokio::test]
async fn https_is_intercepted_with_the_per_run_ca() {
    let harness = Harness::open().await;
    // A plain-HTTP server stands in for the upstream host: the proxy's own
    // TLS handshake succeeds with its CA, then its upstream TLS fails.
    let upstream = Merchant::start(|_| Reply::new(200, "plain")).await;
    let started = start(&harness, None, None).await.expect("start");
    let target = upstream.url().replace("http://", "https://");

    let trusting = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(started.proxy_url.as_str()).expect("proxy"))
        .add_root_certificate(
            reqwest::Certificate::from_pem(started.ca_certificate_pem.as_bytes()).expect("ca"),
        )
        .build()
        .expect("client");
    let response = trusting.get(&target).send().await.expect("intercepted");
    assert_eq!(
        response.status(),
        502,
        "answered inside the intercepted tunnel"
    );

    let untrusting = client(&started);
    assert!(
        untrusting.get(&target).send().await.is_err(),
        "the CA is required"
    );
    status(&harness, true).await;
}

/// A Tempo token AgentPay has no configuration for (OUSD on mainnet; unknown on Moderato).
const UNKNOWN_TOKEN: &str = "0x20c0000000000000000000006a37da5c996874be";

/// MPP settings for the proxy, as a merchant like `openai.mpp.tempo.xyz` needs them.
fn mpp_params(
    harness: &Harness,
    currency: Option<&str>,
    deposit: Option<u128>,
    max_deposit: Option<u128>,
) -> ProxyStartParams {
    ProxyStartParams {
        auth: harness.auth.clone(),
        port: None,
        allowed_hosts: Some(vec!["127.0.0.1".into()]),
        max_amount: Some(100_000),
        currency: currency.map(str::to_string),
        network: None,
        deposit,
        max_deposit,
    }
}

#[tokio::test]
async fn the_deposit_sizes_the_channel_and_a_known_token_is_preferred() {
    let harness = Harness::open().await;
    // The merchant offers an unknown token first, then pathUSD, with no suggested deposit.
    let mut terms = Terms::session(25_000, None);
    terms.other_currencies = vec![UNKNOWN_TOKEN];
    let mpp = MppMerchant::start(terms, harness.rpc.clone()).await;
    let started = start_with(
        &harness,
        mpp_params(&harness, None, Some(100_000), Some(500_000)),
    )
    .await
    .expect("start");
    assert_eq!(
        (started.status.deposit, started.status.max_deposit),
        (Some(100_000), Some(500_000))
    );
    let client = client(&started);
    for _ in 0..2 {
        let paid = client
            .get(mpp.url("/v1/chat/completions"))
            .send()
            .await
            .expect("response");
        assert_eq!(paid.status(), 200);
    }
    // One channel in pathUSD with the asked deposit; the second request needed no top-up.
    assert_eq!(mpp.log(), ["open", "voucher"]);
    let channel = mpp.channel();
    assert_eq!(
        channel.token,
        PATH_USD
            .parse::<alloy_primitives::Address>()
            .expect("token")
    );
    assert_eq!((channel.deposit, channel.accepted), (100_000, 50_000));
    status(&harness, true).await;
}

#[tokio::test]
async fn currency_limits_what_the_proxy_pays_and_deposits_are_checked() {
    let harness = Harness::open().await;
    let mpp = MppMerchant::start(Terms::session(25_000, None), harness.rpc.clone()).await;
    let started = start_with(
        &harness,
        mpp_params(&harness, Some(UNKNOWN_TOKEN), None, None),
    )
    .await
    .expect("start");
    assert_eq!(
        started.status.currency.clone(),
        Some(UNKNOWN_TOKEN.to_string())
    );
    let refused = client(&started)
        .get(mpp.url("/x"))
        .send()
        .await
        .expect("response");
    assert_eq!(refused.status(), 402);
    assert_eq!(
        refused
            .headers()
            .get("x-agentpay-proxy-error")
            .and_then(|v| v.to_str().ok()),
        Some("InvalidRequest")
    );
    assert!(mpp.log().is_empty(), "nothing was paid");
    status(&harness, true).await;

    let error = start_with(
        &harness,
        mpp_params(&harness, Some(PATH_USD), Some(10), Some(5)),
    )
    .await
    .expect_err("deposit above max_deposit");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("max_deposit")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_paid_stream_passes_through_and_its_voucher_requests_are_answered() {
    let harness = Harness::open().await;
    let mut terms = Terms::session(25_000, None);
    terms.stream = true;
    let mpp = MppMerchant::start(terms, harness.rpc.clone()).await;
    let started = start_with(
        &harness,
        mpp_params(&harness, Some(PATH_USD), Some(100_000), None),
    )
    .await
    .expect("start");
    let response = client(&started)
        .get(mpp.url("/v1/chat/completions"))
        .send()
        .await
        .expect("response");
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("payment-receipt"));
    let body = response.text().await.expect("body");
    // The client sees the merchant's stream as sent, payment events included.
    assert!(body.contains("data: hello") && body.contains("data: world"));
    assert!(
        body.contains("event: payment-need-voucher") && body.contains("event: payment-receipt")
    );
    // The proxy answered the mid-stream voucher request in the background, within the deposit.
    for _ in 0..50 {
        if mpp.log().len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(mpp.log(), ["open", "voucher"]);
    assert_eq!(mpp.channel().accepted, 50_000);
    status(&harness, true).await;
}
