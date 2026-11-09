//! The EVM examples in `crates/agentpay-api/fixtures/payments/evm/` (and so
//! in `docs/daemon-api.md`) are real: this test sends every example request
//! through paymentd, with the example vault key (the signer daemon's example
//! wallet, held by the `ExportWalletBackup` example backup) and the mock
//! endpoint, and compares the
//! responses. Signatures are deterministic (RFC 6979), so they must match
//! byte for byte; the Transfer example is the signer daemon's own
//! `SignForAgent` example transaction.
//!
//! Run with `AGENTPAY_UPDATE_EXAMPLES=1` to rewrite the response files from
//! the actual responses instead of comparing.

use std::path::PathBuf;
use std::sync::Arc;

use agentpay_api::payments::{PaymentsRpcRequest as Req, PaymentsRpcResponse as Res};
use agentpay_domain::{AdminAuth, ManualApprovalDecision, PolicyAttachment};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use agentpay_signerd::{DaemonConfig, InMemoryDaemon, KeyManagerDaemonApi};
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::signer::testing::manual_approval;

/// The signer daemon's example wallet key (held by the `ExportWalletBackup` example backup).
const EXAMPLE_KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
/// The approval request id the examples show.
const EXAMPLE_APPROVAL_ID: &str = "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/payments/evm")
        .join(format!("{name}.json"))
}

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(fixture_path(name)).expect("fixture");
    serde_json::from_str(&text).expect("fixture JSON")
}

/// The example request for `method`, sent with the harness's credentials.
fn example_request(h: &Harness, method: &str, edit: impl FnOnce(&mut Value)) -> Req {
    let mut request = fixture(&format!("{method}.request"));
    request["params"]["auth"] = serde_json::to_value(&h.auth).expect("auth");
    edit(&mut request["params"]);
    serde_json::from_value(request).expect("example request")
}

/// Compares `actual` with the example response (or rewrites it in update mode).
fn check(method: &str, actual: &Res, approval_id: Option<Uuid>) {
    let mut text = serde_json::to_string_pretty(actual).expect("encode") + "\n";
    if let Some(id) = approval_id {
        // Approval ids are random; the example shows a fixed one.
        text = text.replace(&id.to_string(), EXAMPLE_APPROVAL_ID);
    }
    let name = format!("{method}.response");
    if std::env::var_os("AGENTPAY_UPDATE_EXAMPLES").is_some() {
        std::fs::write(fixture_path(&name), text).expect("write example");
        return;
    }
    let actual: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(
        actual,
        fixture(&name),
        "{name} differs from the real response"
    );
}

/// A harness whose agent signs with the example key.
async fn example_harness() -> Harness {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let admin = AdminAuth::PeerCredentials;
    // Approvals above 50 USD1 need an operator (the Approve example).
    daemon
        .add_policy(&admin, manual_approval(50 * ONE_USD1, u128::MAX))
        .await
        .expect("policy");
    let vault_key = daemon
        .create_vault_key(
            &admin,
            KeyCreateRequest::Import {
                private_key_hex: EXAMPLE_KEY.to_string().into(),
            },
        )
        .await
        .expect("vault key");
    let credentials = daemon
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let auth = AgentAuth {
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
    };
    let signer = Arc::new(InProcessSigner {
        daemon: Arc::new(daemon),
    });
    Harness::with_signer(signer, auth, |signer| signer).await
}

async fn approve(h: &Harness, id: Uuid) {
    h.signer
        .daemon
        .decide_manual_approval_request(
            &AdminAuth::PeerCredentials,
            id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve");
}

fn approval_id(response: &Res) -> Uuid {
    match response {
        Res::ManualApprovalPending(pending) => pending.approval_request_id,
        other => panic!("expected ManualApprovalPending, got {other:?}"),
    }
}

fn resume_request(h: &Harness, id: Uuid) -> Req {
    example_request(h, "ResumeApproved", |params| {
        params["approval_request_id"] = Value::String(id.to_string());
    })
}

#[tokio::test]
async fn the_documented_evm_examples_are_real() {
    let h = example_harness().await;
    assert_eq!(
        h.wallet().await.as_str(),
        "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
    );
    {
        let mut chain = h.mock.chain();
        chain.base_fee = 0; // fees fall back to eth_gasPrice: 1 gwei
        chain.gas_estimate = 60_000;
    }

    // Transfer (nonce 7, sent, confirmed), then look it up.
    let response = h
        .call(example_request(&h, "Transfer", |_| {}))
        .await
        .expect("Transfer");
    check("Transfer", &response, None);
    for method in ["RpcTx", "RpcReceipt"] {
        let response = h
            .call(example_request(&h, method, |_| {}))
            .await
            .expect(method);
        check(method, &response, None);
    }

    // TransferNative, signed only.
    let response = h
        .call(example_request(&h, "TransferNative", |_| {}))
        .await
        .expect("native");
    check("TransferNative", &response, None);

    // Approve is held for an operator; ResumeApproved sends it (nonce 8).
    h.mock.chain().nonce = 8;
    let no_wait = |params: &mut Value| {
        params["approval_wait_secs"] = Value::Null;
    };
    let response = h
        .call(example_request(&h, "Approve", no_wait))
        .await
        .expect("Approve");
    let id = approval_id(&response);
    check("Approve", &response, Some(id));
    approve(&h, id).await;
    let response = h
        .call(resume_request(&h, id))
        .await
        .expect("ResumeApproved");
    check("ResumeApproved", &response, None);

    // Broadcast with an explicit nonce, signed but not sent.
    let response = h
        .call(example_request(&h, "Broadcast", |_| {}))
        .await
        .expect("Broadcast");
    check("Broadcast", &response, None);

    // Typed data needs an operator by default; the example shows the result.
    let response = h
        .call(example_request(&h, "SignTypedData", no_wait))
        .await
        .expect("SignTypedData");
    let id = approval_id(&response);
    approve(&h, id).await;
    let response = h
        .call(resume_request(&h, id))
        .await
        .expect("resumed typed data");
    check("SignTypedData", &response, None);

    // Read helpers.
    {
        let mut chain = h.mock.chain();
        chain.base_fee = 1_000_000_000;
        chain.priority_fee = 1_000_000_000;
        chain.gas_estimate = 34_512;
        chain.token_balance = alloy_primitives::U256::from(25_500_000_000_000_000_000_u128);
        chain.code = alloy_primitives::hex::decode("363d3d373d3d3d363d73").expect("code");
    }
    for method in [
        "RpcChainInfo",
        "RpcBlockNumber",
        "RpcBalance",
        "RpcNonce",
        "RpcFees",
        "RpcGasEstimate",
        "RpcCode",
    ] {
        let response = h
            .call(example_request(&h, method, |_| {}))
            .await
            .expect(method);
        check(method, &response, None);
    }
}
