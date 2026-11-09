//! The generated JSON Schema and TypeScript bindings are complete and documented.

use serde_json::Value;

use crate::codegen::{json_schema, typescript_bindings, GENERATED_TS_HEADER};
use crate::{DaemonRpcRequest, PaymentsRpcRequest, API_VERSION};

/// Property names that serde generates for tagged enums rather than declaring as fields.
const TAG_PROPERTIES: &[&str] = &[
    "kind", "method", "params", "type", "data", "value", "mode", "values", "decision", "reason",
];

/// Collects every property and union variant under `node` that lacks a description.
fn undocumented(node: &Value, path: &str, in_variant: bool, missing: &mut Vec<String>) {
    let Some(object) = node.as_object() else {
        return;
    };
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        // An externally tagged variant is a one-property wrapper named after the variant.
        let wrapper = in_variant && properties.len() == 1;
        for (name, property) in properties {
            if property.get("description").is_none()
                && !TAG_PROPERTIES.contains(&name.as_str())
                && !wrapper
            {
                missing.push(format!("{path}.{name}"));
            }
            undocumented(property, &format!("{path}.{name}"), false, missing);
        }
    }
    for key in ["oneOf", "anyOf"] {
        for (index, variant) in object
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let is_null = variant.get("type") == Some(&Value::from("null"));
            if variant.get("description").is_none() && variant.get("$ref").is_none() && !is_null {
                missing.push(format!("{path}.{key}[{index}]"));
            }
            undocumented(variant, &format!("{path}.{key}[{index}]"), true, missing);
        }
    }
}

#[test]
fn every_schema_definition_field_and_variant_is_documented() {
    let schema = json_schema();
    let definitions = schema["$defs"].as_object().expect("$defs");
    let mut missing = Vec::new();
    for (name, definition) in definitions {
        if definition.get("description").is_none() {
            missing.push(format!("definition {name}"));
        }
        undocumented(definition, name, false, &mut missing);
    }
    assert!(
        missing.is_empty(),
        "undocumented schema nodes: {missing:#?}"
    );
}

#[test]
fn schema_declares_the_api_version_and_roots() {
    let schema = json_schema();
    assert_eq!(schema["x-api-version"], API_VERSION);
    for root in [
        "WireRequest",
        "WireResponse",
        "DaemonRpcRequest",
        "DaemonRpcResponse",
        "WireDaemonError",
        "HelloResponse",
        "PaymentsRpcRequest",
        "PaymentsRpcResponse",
        "WirePaymentsError",
    ] {
        assert!(schema["$defs"].get(root).is_some(), "missing root {root}");
    }
    let methods = schema["$defs"]["DaemonRpcRequest"]["oneOf"]
        .as_array()
        .expect("request union")
        .len();
    assert_eq!(methods, DaemonRpcRequest::METHOD_NAMES.len());
    let payments_methods = schema["$defs"]["PaymentsRpcRequest"]["oneOf"]
        .as_array()
        .expect("payments request union")
        .len();
    assert_eq!(payments_methods, PaymentsRpcRequest::METHOD_NAMES.len());
}

#[test]
fn typescript_bindings_cover_the_roots_and_index() {
    let files = typescript_bindings().expect("bindings");
    for root in [
        "WireRequest",
        "WireResponse",
        "DaemonRpcRequest",
        "DaemonRpcResponse",
        "PaymentsRpcRequest",
        "PaymentsRpcResponse",
        "WirePaymentsError",
    ] {
        let contents = &files[&format!("{root}.ts")];
        assert!(contents.starts_with(GENERATED_TS_HEADER));
        assert!(contents.contains(&format!("export type {root} =")));
    }
    let index = &files["index.ts"];
    assert!(index.contains(&format!("export const API_VERSION = \"{API_VERSION}\";")));
    for method in DaemonRpcRequest::METHOD_NAMES {
        assert!(
            index.contains(&format!("  \"{method}\",")),
            "index lacks {method}"
        );
    }
    assert!(index.contains("export const PAYMENTS_METHOD_NAMES = ["));
    // Large integers must be plain numbers: u128 values travel as DecimalU128 strings.
    assert!(files.values().all(|contents| !contents.contains("bigint")));
}
