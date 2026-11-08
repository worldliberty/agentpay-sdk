//! Round-trips every documented request/response example through the wire
//! types, so the rustdoc and `docs/daemon-api.md` examples cannot drift from
//! the real encoding.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::rpc::{EvaluateForAgentParams, ExplainForAgentParams, SignForAgentParams};
use crate::{DaemonRpcRequest, DaemonRpcResponse};

/// Every method with the response variant (`type`) it documents.
const EXPECTED_RESPONSES: &[(&str, &str)] = &[
    ("Hello", "Hello"),
    ("EnrollAdminCredential", "AdminCredential"),
    ("ListAdminCredentials", "AdminCredentials"),
    ("RevokeAdminCredential", "Unit"),
    ("BeginAdminChallenge", "AdminChallenge"),
    ("CompleteAdminChallenge", "AdminLease"),
    ("RevokeAdminLease", "Unit"),
    ("AddPolicy", "Unit"),
    ("ListPolicies", "Policies"),
    ("ListPolicySummaries", "PolicySummaries"),
    ("DisablePolicy", "Unit"),
    ("CreateVaultKey", "VaultKey"),
    ("CreateAgentKey", "AgentCredentials"),
    ("RefreshAgentKey", "AgentCredentials"),
    ("SolanaPublicKey", "PublicKey"),
    ("RotateAgentAuthToken", "AuthToken"),
    ("RevokeAgentKey", "Unit"),
    ("BootstrapWallet", "WalletBootstrap"),
    ("ListWallets", "Wallets"),
    ("ExportWalletBackup", "WalletBackup"),
    ("VerifyWalletBackup", "WalletBackupSummary"),
    ("ListSpendingLimits", "SpendingLimits"),
    ("SetSpendingLimits", "SpendingLimits"),
    ("ListManualApprovalRequests", "ManualApprovalRequests"),
    ("DecideManualApprovalRequest", "ManualApprovalRequest"),
    ("AuthenticateAgent", "AgentIdentity"),
    ("AgentPolicySummary", "AgentPolicySummary"),
    ("EvaluateForAgent", "PolicyEvaluation"),
    ("ExplainForAgent", "PolicyExplanation"),
    ("ReserveNonce", "NonceReservation"),
    ("ReleaseNonce", "Unit"),
    ("ReleaseSignedNonce", "Unit"),
    ("SignForAgent", "Signature"),
    ("RenameWallet", "Wallet"),
    ("AgentActivity", "AgentActivity"),
];

/// Secrets that appear in the examples and must never survive zeroization or `Debug`.
const EXAMPLE_SECRETS: &[&str] = &[
    "3f9a6c1e8b2d47f0a5c3e9b1d7f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8",
    "8c1e5f0b2a7d4e3c9b6a1f8e2d7c4b0a.f3e2d1c0b9a8476594a3b2c1d0e9f8a7",
    "2b7e1f9c4a6d48e0b3c5a7f1e9d2c4b6.0e1d2c3b4a5948f7a6b5c4d3e2f1a0b9",
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
    "correct horse battery staple",
];

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/rpc")
}

/// Loads `fixtures/rpc/<method>.<kind>.json`, where `kind` is `request` or `response`.
pub(super) fn load(method: &str, kind: &str) -> Value {
    let path = fixtures_dir().join(format!("{method}.{kind}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("missing example {}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// Every example as `(file name, JSON value)`.
pub(super) fn all_examples() -> Vec<(String, Value)> {
    EXPECTED_RESPONSES
        .iter()
        .flat_map(|(method, _)| {
            ["request", "response"]
                .map(|kind| (format!("{method}.{kind}.json"), load(method, kind)))
        })
        .collect()
}

#[test]
fn every_method_has_exactly_one_request_and_response_example() {
    let documented: Vec<&str> = EXPECTED_RESPONSES
        .iter()
        .map(|(method, _)| *method)
        .collect();
    assert_eq!(documented, DaemonRpcRequest::METHOD_NAMES);

    let expected: BTreeSet<String> = all_examples().into_iter().map(|(name, _)| name).collect();
    let on_disk: BTreeSet<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(
        on_disk, expected,
        "fixtures/rpc must hold exactly one pair per method"
    );
}

#[test]
fn request_examples_round_trip_through_the_wire_types() {
    for (method, _) in EXPECTED_RESPONSES {
        let example = load(method, "request");
        let request: DaemonRpcRequest = serde_json::from_value(example.clone())
            .unwrap_or_else(|err| panic!("{method} request example does not decode: {err}"));
        assert_eq!(request.method_name(), *method);
        let encoded = serde_json::to_value(&request).expect("encode request");
        assert_eq!(
            encoded, example,
            "{method} request example is not canonical"
        );
    }
}

#[test]
fn response_examples_round_trip_and_use_the_documented_variant() {
    for (method, response_type) in EXPECTED_RESPONSES {
        let example = load(method, "response");
        assert_eq!(example["type"], *response_type, "{method} response variant");
        let response: DaemonRpcResponse = serde_json::from_value(example.clone())
            .unwrap_or_else(|err| panic!("{method} response example does not decode: {err}"));
        let encoded = serde_json::to_value(&response).expect("encode response");
        assert_eq!(
            encoded, example,
            "{method} response example is not canonical"
        );
    }
}

#[test]
fn sign_request_examples_carry_the_canonical_payload_of_their_action() {
    for method in ["EvaluateForAgent", "ExplainForAgent", "SignForAgent"] {
        let request: DaemonRpcRequest =
            serde_json::from_value(load(method, "request")).expect("request");
        let (DaemonRpcRequest::EvaluateForAgent(EvaluateForAgentParams { request })
        | DaemonRpcRequest::ExplainForAgent(ExplainForAgentParams { request })
        | DaemonRpcRequest::SignForAgent(SignForAgentParams { request })) = request
        else {
            panic!("{method} example has the wrong method");
        };
        let canonical = serde_json::to_vec(&request.action).expect("canonical action");
        assert_eq!(
            request.payload, canonical,
            "{method} payload is not canonical"
        );
        request.action.validate().expect("example action is valid");
    }
}

#[test]
fn zeroize_secrets_wipes_every_secret_in_the_examples() {
    for (method, _) in EXPECTED_RESPONSES {
        let mut request: DaemonRpcRequest =
            serde_json::from_value(load(method, "request")).expect("request");
        request.zeroize_secrets();
        let mut response: DaemonRpcResponse =
            serde_json::from_value(load(method, "response")).expect("response");
        response.zeroize_secrets();
        let rendered = format!(
            "{}{}",
            serde_json::to_string(&request).expect("request"),
            serde_json::to_string(&response).expect("response")
        );
        for secret in EXAMPLE_SECRETS {
            assert!(
                !rendered.contains(secret),
                "{method} keeps a secret after zeroize"
            );
        }
    }
}

#[test]
fn debug_output_redacts_every_secret_in_the_examples() {
    for (method, _) in EXPECTED_RESPONSES {
        let request: DaemonRpcRequest =
            serde_json::from_value(load(method, "request")).expect("request");
        let response: DaemonRpcResponse =
            serde_json::from_value(load(method, "response")).expect("response");
        let rendered = format!("{request:?}{response:?}");
        for secret in EXAMPLE_SECRETS {
            assert!(
                !rendered.contains(secret),
                "{method} leaks a secret through Debug"
            );
        }
    }
}

/// Parses every fenced ```json block of `markdown`.
pub(super) fn json_blocks(markdown: &str) -> Vec<Value> {
    let mut blocks = Vec::new();
    let mut lines = markdown.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "```json" {
            continue;
        }
        let body: Vec<&str> = lines.by_ref().take_while(|l| l.trim() != "```").collect();
        let text = body.join("\n");
        let value = serde_json::from_str(&text)
            .unwrap_or_else(|err| panic!("invalid ```json block in daemon-api.md: {err}\n{text}"));
        blocks.push(value);
    }
    blocks
}

pub(super) fn daemon_api_markdown() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/daemon-api.md");
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

#[test]
fn daemon_api_markdown_shows_every_example_verbatim() {
    let blocks = json_blocks(&daemon_api_markdown());
    for (name, example) in all_examples() {
        assert!(
            blocks.contains(&example),
            "docs/daemon-api.md is missing the {name} example (run the fixtures through it again)"
        );
    }
}
