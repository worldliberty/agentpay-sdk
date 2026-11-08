//! The wallet and telemetry examples in
//! `crates/agentpay-api/fixtures/payments/{wallet,telemetry}/` (and so in
//! `docs/daemon-api.md`) are real: this test sends every example request
//! through paymentd, with the example key, the mock chains, and an active
//! (recording, never sending) telemetry instance, and compares the responses.
//! Random ids are replaced with the documented ones.
//!
//! Run with `AGENTPAY_UPDATE_EXAMPLES=1` to rewrite the response files from
//! the actual responses instead of comparing.

use std::path::PathBuf;

use agentpay_api::rpc::AddPolicyParams;
use agentpay_api::DaemonRpcRequest;
use serde_json::Value;

use super::*;
use crate::telemetry::settings::Settings;
use crate::telemetry::tests::Recorder;
use crate::telemetry::Telemetry;

/// The ids the examples show.
const EXAMPLE_AGENT_KEY_ID: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
pub(super) const EXAMPLE_VAULT_KEY_ID: &str = "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d";
const EXAMPLE_INSTALL_ID: &str = "3f6c2a9e-8b1d-4e7f-a5c0-9d2b4e6f8a1c";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../agentpay-api/fixtures")
}

pub(super) fn fixture_path(family: &str, name: &str) -> PathBuf {
    fixtures()
        .join("payments")
        .join(family)
        .join(format!("{name}.json"))
}

pub(super) fn fixture(family: &str, name: &str) -> Value {
    let text = std::fs::read_to_string(fixture_path(family, name)).expect("fixture");
    serde_json::from_str(&text).expect("fixture JSON")
}

/// The example request for `method`, sent with the harness's credentials.
fn example_request(h: &Harness, family: &str, method: &str) -> Req {
    let mut request = fixture(family, &format!("{method}.request"));
    request["params"]["auth"] = serde_json::to_value(&h.auth).expect("auth");
    serde_json::from_value(request).expect("example request")
}

/// Compares `actual` (with random ids replaced) with the example response,
/// or rewrites it in update mode.
fn check(h: &Harness, family: &str, method: &str, actual: &Res, ids: &[(String, &str)]) {
    let mut text = serde_json::to_string_pretty(actual).expect("encode") + "\n";
    text = text.replace(&h.auth.agent_key_id.to_string(), EXAMPLE_AGENT_KEY_ID);
    for (random, documented) in ids {
        text = text.replace(random, documented);
    }
    let name = format!("{method}.response");
    if std::env::var_os("AGENTPAY_UPDATE_EXAMPLES").is_some() {
        std::fs::write(fixture_path(family, &name), text).expect("write example");
        return;
    }
    let actual: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        actual,
        fixture(family, &name),
        "{family}/{name} differs from the real response"
    );
}

/// The `AddPolicy` example policy (per transaction, USD1 on BSC).
pub(super) fn example_policy() -> SpendingPolicy {
    let text = std::fs::read_to_string(fixtures().join("rpc/AddPolicy.request.json"))
        .expect("AddPolicy example");
    let DaemonRpcRequest::AddPolicy(AddPolicyParams { policy, .. }) =
        serde_json::from_str(&text).expect("AddPolicy request")
    else {
        panic!("wrong AddPolicy example");
    };
    policy
}

async fn example_harness() -> (Harness, Arc<Recorder>) {
    let mut h = Harness::new(vec![example_policy()]).await;
    let recorder = Arc::new(Recorder::default());
    h.state.telemetry =
        Telemetry::with_sink(h.dir.path(), Settings::defaults(), Some(recorder.clone()));
    (h, recorder)
}

#[tokio::test]
async fn the_documented_wallet_and_telemetry_examples_are_real() {
    let (h, recorder) = example_harness().await;
    let vault_key_id = h.agent().await.identity.vault_key.id.to_string();
    let ids = [(vault_key_id, EXAMPLE_VAULT_KEY_ID)];
    for method in ["WalletSummary", "WalletBalance", "FundingRequest", "Status"] {
        let response = h
            .call(example_request(&h, "wallet", method))
            .await
            .unwrap_or_else(|err| panic!("{method}: {err:?}"));
        check(&h, "wallet", method, &response, &ids);
    }

    let install_id = h
        .state
        .telemetry
        .status()
        .install_id
        .expect("install id")
        .to_string();
    let ids = [(install_id, EXAMPLE_INSTALL_ID)];
    for method in ["TelemetryStatus", "SetTelemetry"] {
        let response = h
            .call(example_request(&h, "telemetry", method))
            .await
            .unwrap_or_else(|err| panic!("{method}: {err:?}"));
        check(&h, "telemetry", method, &response, &ids);
    }
    // Every call so far was recorded (until `SetTelemetry` opted out), and
    // none of the events carries an address.
    let events = recorder.events.lock().expect("events").clone();
    assert_eq!(events.len(), 5);
    let rendered = serde_json::to_string(&events).expect("encode");
    assert!(!rendered.contains("0x") && !rendered.contains(SOLANA_WALLET));
    assert!(!h.state.telemetry.is_enabled());
}
