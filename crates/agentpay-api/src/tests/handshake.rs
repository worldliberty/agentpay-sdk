//! The `Hello` handshake and version compatibility rules.

use serde_json::json;

use crate::version::{daemon_capabilities, FEATURE_CAPABILITIES};
use crate::{ApiVersion, DaemonRpcRequest, DaemonRpcResponse, HelloResponse, API_VERSION};

#[test]
fn api_version_constant_parses_to_current() {
    assert_eq!(ApiVersion::parse(API_VERSION), Some(ApiVersion::CURRENT));
    assert_eq!(ApiVersion::CURRENT.to_string(), API_VERSION);
}

#[test]
fn hello_request_has_no_params() {
    let encoded = serde_json::to_value(DaemonRpcRequest::Hello).expect("encode");
    assert_eq!(encoded, json!({"method": "Hello"}));
    let decoded: DaemonRpcRequest =
        serde_json::from_value(json!({"method": "Hello"})).expect("decode");
    assert!(matches!(decoded, DaemonRpcRequest::Hello));
}

#[test]
fn hello_response_advertises_every_method_and_feature() {
    let hello = HelloResponse::for_daemon("9.9.9");
    assert_eq!(hello.api_version, API_VERSION);
    assert_eq!(hello.daemon_version, "9.9.9");
    assert_eq!(hello.capabilities, daemon_capabilities());
    for method in DaemonRpcRequest::METHOD_NAMES {
        assert!(hello.supports(method), "missing capability {method}");
    }
    for feature in FEATURE_CAPABILITIES {
        assert!(hello.supports(feature), "missing capability {feature}");
    }
    assert!(!hello.supports("NoSuchMethod"));

    let encoded = serde_json::to_value(DaemonRpcResponse::Hello(hello.clone())).expect("encode");
    assert_eq!(encoded["type"], "Hello");
    let decoded: DaemonRpcResponse = serde_json::from_value(encoded).expect("decode");
    let DaemonRpcResponse::Hello(decoded) = decoded else {
        panic!("expected a Hello response");
    };
    assert_eq!(decoded, hello);
}

#[test]
fn method_names_match_the_serialized_method_tags() {
    let names: Vec<&str> = DaemonRpcRequest::METHOD_NAMES.to_vec();
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "method names must be unique");
    for method in names {
        let request: DaemonRpcRequest =
            serde_json::from_value(super::fixtures::load(method, "request")).expect("request");
        assert_eq!(
            serde_json::to_value(&request).expect("encode")["method"],
            method
        );
    }
}

#[test]
fn compatibility_requires_the_same_major_version() {
    let client = ApiVersion::parse("1.2.0").expect("version");
    assert!(client.is_compatible_with(&ApiVersion::parse("1.0.0").expect("older minor")));
    assert!(client.is_compatible_with(&ApiVersion::parse("1.9.3").expect("newer minor")));
    assert!(!client.is_compatible_with(&ApiVersion::parse("2.0.0").expect("next major")));
    assert!(!client.is_compatible_with(&ApiVersion::parse("0.9.0").expect("older major")));
}

#[test]
fn version_parsing_rejects_malformed_values() {
    for value in [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "1.0.x",
        "v1.0.0",
        "1.0.0-beta",
        "-1.0.0",
    ] {
        assert_eq!(ApiVersion::parse(value), None, "{value:?} must not parse");
    }
    assert_eq!(
        ApiVersion::parse(" 10.20.30 "),
        Some(ApiVersion {
            major: 10,
            minor: 20,
            patch: 30
        })
    );
}
