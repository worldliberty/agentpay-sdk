//! `X402Fetch` end to end: a mock merchant issuing x402 v1 and v2 `402`s,
//! a real in-memory signer daemon with policies, and the merchant checking
//! the payment the way a facilitator does (typed `x402-types` decoding, the
//! echoed requirement, and the EIP-3009 signature recomputed with alloy).

use std::sync::Arc;

use agentpay_api::payments::{
    HttpBody, HttpHeader, HttpRequest, PaymentsRpcRequest as Req, PaymentsRpcResponse as Res,
    X402FetchParams, X402FetchResult,
};
use agentpay_api::{AgentAuth, WireDaemonError};
use agentpay_domain::SpendingPolicy;
use alloy_primitives::{hex, Address, Signature, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use x402_types::chain::ChainId;
use x402_types::proto::{v1, v2};

use crate::config::ConfigStore;
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::features::http::merchant::{Merchant, Reply, Seen};
use crate::signer::testing::{manual_approval, per_tx_limit, InProcessSigner};
use crate::signer::AgentSigner;
use crate::state::AppState;
use crate::test_support::TempDir;

const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const PAY_TO: &str = "0x209693bc6afc0c5328ba36faf03c514ef312287c";
const SETTLED: &str = "0x9d4f3b2a1c0e8d7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f";

sol! {
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authorization {
    from: String,
    to: String,
    value: String,
    valid_after: String,
    valid_before: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct ExactPayload {
    signature: String,
    authorization: Authorization,
}

struct Harness {
    _dir: TempDir,
    state: AppState,
    auth: AgentAuth,
    wallet: Address,
}

impl Harness {
    async fn new(policies: Vec<SpendingPolicy>) -> Self {
        let (signer, auth) = InProcessSigner::with_agent(policies).await;
        let wallet = AgentSigner::new(&signer, &auth)
            .identity()
            .await
            .expect("identity")
            .evm_address
            .expect("evm wallet")
            .to_string()
            .parse()
            .expect("address");
        let dir = TempDir::new("x402");
        let state = AppState::new(
            ConfigStore::open(dir.path()).expect("config"),
            Arc::new(signer),
        );
        Self {
            _dir: dir,
            state,
            auth,
            wallet,
        }
    }

    async fn fetch(
        &self,
        url: String,
        limits: (Option<u128>, Option<u128>),
    ) -> Result<X402FetchResult, PaymentsError> {
        let request = Req::X402Fetch(X402FetchParams {
            auth: self.auth.clone(),
            request: HttpRequest {
                url,
                method: None,
                headers: vec![HttpHeader {
                    name: "Accept".into(),
                    value: "application/json".into(),
                }],
                body: None,
            },
            expected_amount: limits.0,
            max_amount: limits.1,
            approval_wait_secs: None,
        });
        match dispatch(&self.state, request).await? {
            Res::X402Response(result) => Ok(result),
            other => panic!("unexpected response {other:?}"),
        }
    }
}

fn requirement_v2(amount: &str) -> v2::PaymentRequirements {
    v2::PaymentRequirements {
        scheme: "exact".into(),
        network: ChainId::new("eip155", "84532"),
        amount: amount.into(),
        pay_to: PAY_TO.into(),
        max_timeout_seconds: 300,
        asset: USDC.into(),
        extra: Some(json!({"name": "USDC", "version": "2"})),
    }
}

/// Checks an EIP-3009 payload as a facilitator would; returns the payer.
fn verify_exact(payload: &ExactPayload, amount: &str) -> Address {
    let authorization = &payload.authorization;
    assert_eq!(authorization.to.to_lowercase(), PAY_TO);
    assert_eq!(authorization.value, amount);
    let now = crate::features::payer::unix_now();
    let valid_before: u64 = authorization.valid_before.parse().expect("validBefore");
    let valid_after: u64 = authorization.valid_after.parse().expect("validAfter");
    assert!(valid_after <= now && valid_before > now && valid_before <= now + 300);
    let message = TransferWithAuthorization {
        from: authorization.from.parse().expect("from"),
        to: authorization.to.parse().expect("to"),
        value: U256::from_str_radix(&authorization.value, 10).expect("value"),
        validAfter: U256::from(valid_after),
        validBefore: U256::from(valid_before),
        nonce: authorization.nonce.parse::<B256>().expect("nonce"),
    };
    let domain = eip712_domain! {
        name: "USDC",
        version: "2",
        chain_id: 84532,
        verifying_contract: USDC.parse::<Address>().expect("usdc"),
    };
    let bytes = hex::decode(payload.signature.trim_start_matches("0x")).expect("signature hex");
    assert_eq!(bytes.len(), 65);
    assert!(bytes[64] == 27 || bytes[64] == 28, "v must be 27 or 28");
    let signature = Signature::from_raw(&bytes).expect("signature");
    let signer = signature
        .recover_address_from_prehash(&message.eip712_signing_hash(&domain))
        .expect("recover");
    assert_eq!(signer, authorization.from.parse::<Address>().expect("from"));
    signer
}

fn settle_response(payer: Address, network: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(
        json!({"success": true, "transaction": SETTLED, "network": network, "payer": format!("{payer:#x}")})
            .to_string(),
    )
}

/// A v2 merchant charging `amount` for `/weather`.
async fn v2_merchant(amount: &'static str) -> Merchant {
    Merchant::start(move |seen: &Seen| {
        let required = v2::PaymentRequired {
            x402_version: v2::X402Version2,
            error: None,
            resource: Some(v2::ResourceInfo {
                url: "https://api.example.com/weather".into(),
                description: Some("weather".into()),
                mime_type: None,
            }),
            accepts: vec![requirement_v2(amount)],
            extensions: Default::default(),
        };
        let Some(header) = seen.header("payment-signature") else {
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&required).expect("required"));
            return Reply::new(402, "{}").header("PAYMENT-REQUIRED", encoded);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(header)
            .expect("base64 payload");
        let payment: v2::PaymentPayload<v2::PaymentRequirements, ExactPayload> =
            serde_json::from_slice(&bytes).expect("typed v2 payment payload");
        assert_eq!(
            payment.accepted,
            requirement_v2(amount),
            "accepted is echoed"
        );
        assert_eq!(
            payment.resource.map(|resource| resource.url).as_deref(),
            Some("https://api.example.com/weather")
        );
        let payer = verify_exact(&payment.payload, amount);
        Reply::new(200, "{\"city\":\"Lisbon\"}")
            .header("content-type", "application/json")
            .header("PAYMENT-RESPONSE", settle_response(payer, "eip155:84532"))
    })
    .await
}

#[tokio::test]
async fn v2_requirements_are_paid_with_a_daemon_signed_authorization() {
    let harness = Harness::new(vec![per_tx_limit(1_000_000)]).await;
    let merchant = v2_merchant("1000").await;
    let result = harness
        .fetch(
            format!("{}/weather", merchant.url()),
            (Some(1000), Some(5000)),
        )
        .await
        .expect("paid");
    assert_eq!(result.response.status, 200);
    assert_eq!(
        result.response.body,
        HttpBody::Text("{\"city\":\"Lisbon\"}".into())
    );
    let payment = result.payment.expect("payment");
    assert_eq!(
        (payment.x402_version, payment.chain_id, payment.amount),
        (2, 84532, 1000)
    );
    assert_eq!(payment.network, "eip155:84532");
    assert_eq!(
        payment.from.to_string().parse::<Address>().ok(),
        Some(harness.wallet)
    );
    assert_eq!(
        payment.payment_response.expect("settlement")["transaction"],
        SETTLED
    );
    let seen = merchant.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].header("accept"), Some("application/json"));
}

#[tokio::test]
async fn v1_bodies_are_paid_with_x_payment() {
    let harness = Harness::new(vec![per_tx_limit(1_000_000)]).await;
    let merchant = Merchant::start(|seen: &Seen| {
        let Some(header) = seen.header("x-payment") else {
            let body = json!({
                "x402Version": 1,
                "error": "X-PAYMENT header is required",
                "accepts": [{
                    "scheme": "exact", "network": "base-sepolia", "maxAmountRequired": "2500",
                    "resource": "https://api.example.com/v1", "description": "", "mimeType": "",
                    "payTo": PAY_TO, "maxTimeoutSeconds": 120, "asset": USDC,
                    "extra": {"name": "USDC", "version": "2"}
                }]
            });
            return Reply::new(402, body.to_string()).header("content-type", "application/json");
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(header)
            .expect("base64 payload");
        let payment: v1::PaymentPayload<String, ExactPayload> =
            serde_json::from_slice(&bytes).expect("typed v1 payment payload");
        assert_eq!(
            (payment.scheme.as_str(), payment.network.as_str()),
            ("exact", "base-sepolia")
        );
        let payer = verify_exact(&payment.payload, "2500");
        Reply::new(200, "ok").header("X-PAYMENT-RESPONSE", settle_response(payer, "base-sepolia"))
    })
    .await;
    let result = harness
        .fetch(format!("{}/v1", merchant.url()), (None, None))
        .await
        .expect("paid");
    assert_eq!(result.response.status, 200);
    let payment = result.payment.expect("payment");
    assert_eq!((payment.x402_version, payment.amount), (1, 2500));
    assert_eq!(payment.network, "base-sepolia");
    assert_eq!(
        payment.payment_response.expect("settlement")["success"],
        true
    );
}

#[tokio::test]
async fn a_policy_denial_signs_nothing_and_sends_no_payment() {
    let harness = Harness::new(vec![per_tx_limit(999)]).await;
    let merchant = v2_merchant("1000").await;
    let error = harness
        .fetch(format!("{}/weather", merchant.url()), (None, None))
        .await
        .expect_err("denied");
    assert!(
        matches!(error, PaymentsError::Signer(WireDaemonError::Policy(_))),
        "{error:?}"
    );
    assert_eq!(merchant.seen().len(), 1, "no paid retry");
}

#[tokio::test]
async fn amount_limits_are_enforced_before_signing() {
    let harness = Harness::new(vec![per_tx_limit(u128::MAX)]).await;
    let merchant = v2_merchant("1000").await;
    let url = format!("{}/weather", merchant.url());
    for limits in [(None, Some(999)), (Some(1001), None)] {
        let error = harness
            .fetch(url.clone(), limits)
            .await
            .expect_err("refused");
        assert!(
            matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("nothing was signed")),
            "{error:?}"
        );
    }
    assert!(merchant
        .seen()
        .iter()
        .all(|seen| seen.header("payment-signature").is_none()));
}

#[tokio::test]
async fn unpaid_and_unpayable_answers() {
    let harness = Harness::new(vec![per_tx_limit(u128::MAX)]).await;
    let merchant = Merchant::start(|seen: &Seen| match seen.path.as_str() {
        "/free" => Reply::new(200, vec![0_u8, 159]),
        "/permit2" => {
            let mut requirement = serde_json::to_value(requirement_v2("1")).expect("json");
            requirement["extra"]["assetTransferMethod"] = Value::from("permit2");
            let required = json!({"x402Version": 2, "resource": null, "accepts": [requirement]});
            Reply::new(402, "").header(
                "PAYMENT-REQUIRED",
                base64::engine::general_purpose::STANDARD.encode(required.to_string()),
            )
        }
        _ => Reply::new(402, "pay me"),
    })
    .await;
    let free = harness
        .fetch(format!("{}/free", merchant.url()), (None, None))
        .await
        .expect("free");
    assert!(free.payment.is_none());
    assert_eq!(free.response.body, HttpBody::Base64("AJ8=".into()));

    let error = harness
        .fetch(format!("{}/other", merchant.url()), (None, None))
        .await
        .expect_err("not x402");
    assert!(matches!(error, PaymentsError::Merchant(_)), "{error:?}");

    let error = harness
        .fetch(format!("{}/permit2", merchant.url()), (None, None))
        .await
        .expect_err("permit2");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(reason) if reason.contains("permit2")),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_held_payment_reports_manual_approval_pending() {
    let harness = Harness::new(vec![per_tx_limit(u128::MAX), manual_approval(1, u128::MAX)]).await;
    let merchant = v2_merchant("1000").await;
    let error = harness
        .fetch(format!("{}/weather", merchant.url()), (None, None))
        .await
        .expect_err("held");
    assert!(
        matches!(error, PaymentsError::ManualApprovalPending { .. }),
        "{error:?}"
    );
    assert_eq!(merchant.seen().len(), 1, "no paid retry while held");
}
