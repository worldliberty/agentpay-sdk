//! The documented error examples cover every `WireDaemonError` kind and round-trip.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

use super::fixtures::{daemon_api_markdown, json_blocks};
use crate::WireDaemonError;

fn error_examples() -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/errors.json");
    let text = std::fs::read_to_string(&path).expect("fixtures/errors.json");
    serde_json::from_str(&text).expect("errors.json is a JSON array")
}

/// Every `kind` the generated JSON Schema allows for `WireDaemonError`.
fn schema_kinds() -> BTreeSet<String> {
    let schema = crate::codegen::json_schema();
    schema["$defs"]["WireDaemonError"]["oneOf"]
        .as_array()
        .expect("WireDaemonError is a oneOf")
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
fn error_examples_round_trip_and_cover_every_kind() {
    let mut kinds = BTreeSet::new();
    for example in error_examples() {
        let error: WireDaemonError = serde_json::from_value(example.clone())
            .unwrap_or_else(|err| panic!("error example {example} does not decode: {err}"));
        assert_eq!(serde_json::to_value(&error).expect("encode"), example);
        let kind = example["kind"].as_str().expect("kind").to_string();
        assert!(kinds.insert(kind.clone()), "duplicate example for {kind}");
    }
    assert_eq!(kinds, schema_kinds());
}

#[test]
fn daemon_api_markdown_documents_every_error_kind_with_its_example() {
    let markdown = daemon_api_markdown();
    for kind in schema_kinds() {
        assert!(
            markdown.contains(&format!("| `{kind}` |")),
            "docs/daemon-api.md has no error-table row for {kind}"
        );
    }
    let blocks = json_blocks(&markdown);
    let documented = blocks
        .iter()
        .find(|block| block.is_array() && block[0]["kind"].is_string())
        .expect("docs/daemon-api.md shows the full error example list");
    assert_eq!(documented, &Value::Array(error_examples()));
}

#[test]
fn policy_amounts_in_errors_are_decimal_strings() {
    let error: WireDaemonError = serde_json::from_value(serde_json::json!({
        "kind": "Policy",
        "data": {"WindowLimitExceeded": {
            "policy_id": "a1b2c3d4-0000-4000-8000-000000000001",
            "used_amount_wei": "340282366920938463463374607431768211455",
            "requested_amount_wei": "1",
            "max_amount_wei": "2"
        }}
    }))
    .expect("u128::MAX survives as a decimal string");
    let encoded = serde_json::to_value(&error).expect("encode");
    assert_eq!(
        encoded["data"]["WindowLimitExceeded"]["used_amount_wei"],
        "340282366920938463463374607431768211455"
    );
}
