//! The payments service contract: every documented example round-trips, every
//! method and error kind is documented, and secrets never survive zeroization
//! or `Debug`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::fixtures::{daemon_api_markdown, json_blocks};
use crate::payments::{PaymentsRpcRequest, PaymentsRpcResponse, WirePaymentsError};
use crate::version::{payments_capabilities, PAYMENTS_FEATURE_CAPABILITIES};
use crate::{AccessLevel, HelloResponse};

/// Every payments method with the response variant (`type`) it documents.
const EXPECTED_RESPONSES: &[(&str, &str)] = &[
    ("Hello", "Hello"),
    ("GetConfig", "Config"),
    ("SetConfig", "Config"),
    ("TransferSol", "SolanaTransfer"),
    ("TransferSpl", "SolanaTransfer"),
    ("Transfer", "EvmTransaction"),
    ("TransferNative", "EvmSignature"),
    ("Approve", "ManualApprovalPending"),
    ("Broadcast", "EvmTransaction"),
    ("SignTypedData", "EvmSignature"),
    ("ResumeApproved", "EvmTransaction"),
    ("RpcChainInfo", "EvmChainInfo"),
    ("RpcBlockNumber", "EvmChainInfo"),
    ("RpcBalance", "EvmBalance"),
    ("RpcNonce", "EvmNonce"),
    ("RpcFees", "EvmFees"),
    ("RpcGasEstimate", "EvmGasEstimate"),
    ("RpcTx", "EvmTransactionLookup"),
    ("RpcReceipt", "EvmReceiptLookup"),
    ("RpcCode", "EvmCode"),
    ("X402Fetch", "X402Response"),
    ("MppFetch", "MppResponse"),
    ("ProxyStart", "ProxyStarted"),
    ("ProxyStop", "ProxyStatus"),
    ("ProxyStatus", "ProxyStatus"),
    ("WalletSummary", "WalletSummary"),
    ("WalletBalance", "WalletBalance"),
    ("FundingRequest", "FundingRequest"),
    ("Status", "Status"),
    ("TelemetryStatus", "TelemetryStatus"),
    ("SetTelemetry", "TelemetryStatus"),
    ("AddToken", "TokenAdded"),
    ("LookupToken", "TokenInfo"),
    ("Activity", "Activity"),
];

/// The agent token used by the examples.
const EXAMPLE_TOKEN: &str = "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7";

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/payments")
}

/// Every example file by name: directly in `fixtures/payments`, or in one
/// method-family subdirectory (`evm/`, `solana/`).
fn example_paths() -> BTreeMap<String, PathBuf> {
    let mut paths = BTreeMap::new();
    let mut dirs = vec![fixtures_dir()];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("fixtures dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                assert_eq!(dir, fixtures_dir(), "one level of subdirectories at most");
                dirs.push(path);
                continue;
            }
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            let previous = paths.insert(name.clone(), path);
            assert!(previous.is_none(), "{name} exists twice");
        }
    }
    paths
}

/// Loads `fixtures/payments/[<family>/]<method>.<kind>.json`.
pub(super) fn load(method: &str, kind: &str) -> Value {
    let name = format!("{method}.{kind}.json");
    let path = example_paths()
        .remove(&name)
        .unwrap_or_else(|| panic!("missing example {name}"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing example {}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn error_examples() -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/payments_errors.json");
    let text = std::fs::read_to_string(&path).expect("fixtures/payments_errors.json");
    serde_json::from_str(&text).expect("payments_errors.json is a JSON array")
}

fn request(method: &str) -> PaymentsRpcRequest {
    serde_json::from_value(load(method, "request")).expect("request example")
}

fn response(method: &str) -> PaymentsRpcResponse {
    serde_json::from_value(load(method, "response")).expect("response example")
}

#[test]
fn every_payments_method_has_exactly_one_request_and_response_example() {
    let documented: Vec<&str> = EXPECTED_RESPONSES.iter().map(|(m, _)| *m).collect();
    assert_eq!(documented, PaymentsRpcRequest::METHOD_NAMES);
    let expected: BTreeSet<String> = EXPECTED_RESPONSES
        .iter()
        .flat_map(|(method, _)| ["request", "response"].map(|k| format!("{method}.{k}.json")))
        .collect();
    let on_disk: BTreeSet<String> = example_paths().into_keys().collect();
    assert_eq!(on_disk, expected);
}

#[test]
fn payments_examples_round_trip_through_the_wire_types() {
    for (method, response_type) in EXPECTED_RESPONSES {
        let example = load(method, "request");
        let decoded = request(method);
        assert_eq!(decoded.method_name(), *method);
        assert_eq!(serde_json::to_value(&decoded).expect("encode"), example);

        let example = load(method, "response");
        assert_eq!(example["type"], *response_type, "{method} response variant");
        let decoded = response(method);
        assert_eq!(serde_json::to_value(&decoded).expect("encode"), example);
    }
}

#[test]
fn hello_example_is_what_the_service_advertises() {
    let PaymentsRpcResponse::Hello(hello) = response("Hello") else {
        panic!("Hello example must be a Hello response");
    };
    assert_eq!(hello, HelloResponse::for_payments_service("1.0.0"));
    assert_eq!(hello.capabilities, payments_capabilities());
    for capability in PaymentsRpcRequest::METHOD_NAMES
        .iter()
        .chain(PAYMENTS_FEATURE_CAPABILITIES)
    {
        assert!(
            hello.supports(capability),
            "missing capability {capability}"
        );
    }
}

#[test]
fn only_hello_and_lookup_token_are_unauthenticated() {
    for (method, _) in EXPECTED_RESPONSES {
        let request = request(method);
        let open = matches!(*method, "Hello" | "LookupToken");
        let expected = if open {
            AccessLevel::Any
        } else {
            AccessLevel::Agent
        };
        assert_eq!(request.access_level(), expected, "{method}");
        assert_eq!(request.agent_auth().is_some(), !open);
    }
}

#[test]
fn payments_secrets_are_zeroized_and_redacted() {
    for (method, _) in EXPECTED_RESPONSES {
        let original = request(method);
        assert!(
            !format!("{original:?}").contains(EXAMPLE_TOKEN),
            "{method} leaks the token through Debug"
        );
        let mut wiped = original;
        wiped.zeroize_secrets();
        let rendered = serde_json::to_string(&wiped).expect("encode");
        assert!(
            !rendered.contains(EXAMPLE_TOKEN),
            "{method} keeps the token"
        );
    }
}

/// Every `kind` the generated JSON Schema allows for `WirePaymentsError`.
fn schema_kinds() -> BTreeSet<String> {
    crate::codegen::json_schema()["$defs"]["WirePaymentsError"]["oneOf"]
        .as_array()
        .expect("WirePaymentsError is a oneOf")
        .iter()
        .map(|variant| {
            variant["properties"]["kind"]["const"]
                .as_str()
                .expect("each variant has a constant kind")
                .to_string()
        })
        .collect()
}

#[test]
fn payments_error_examples_round_trip_and_cover_every_kind() {
    let mut kinds = BTreeSet::new();
    for example in error_examples() {
        let error: WirePaymentsError = serde_json::from_value(example.clone())
            .unwrap_or_else(|err| panic!("error example {example} does not decode: {err}"));
        assert_eq!(serde_json::to_value(&error).expect("encode"), example);
        assert!(kinds.insert(example["kind"].as_str().expect("kind").to_string()));
    }
    assert_eq!(kinds, schema_kinds());
}

#[test]
fn daemon_api_markdown_documents_the_payments_service() {
    let markdown = daemon_api_markdown();
    let blocks = json_blocks(&markdown);
    for (method, _) in EXPECTED_RESPONSES {
        for kind in ["request", "response"] {
            assert!(
                blocks.contains(&load(method, kind)),
                "docs/daemon-api.md is missing the payments {method}.{kind}.json example"
            );
        }
    }
    for kind in schema_kinds() {
        assert!(
            markdown.contains(&format!("| `{kind}` |")),
            "docs/daemon-api.md has no payments error-table row for {kind}"
        );
    }
    assert!(
        blocks.contains(&Value::Array(error_examples())),
        "docs/daemon-api.md must show the full payments error example list"
    );
}
