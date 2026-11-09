use super::*;

#[test]
fn address_parser_validates_prefix_and_length() {
    let valid = "0x1111111111111111111111111111111111111111"
        .parse::<EvmAddress>()
        .expect("must parse");
    assert_eq!(valid.as_str(), "0x1111111111111111111111111111111111111111");

    let missing_prefix = "1111111111111111111111111111111111111111".parse::<EvmAddress>();
    assert!(missing_prefix.is_err());

    let too_short = "0x1234".parse::<EvmAddress>();
    assert!(too_short.is_err());
}

#[test]
fn address_parser_accepts_valid_mixed_case_checksum() {
    let checksummed = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        .parse::<Address>()
        .expect("alloy address")
        .to_checksum(None);

    let parsed = checksummed.parse::<EvmAddress>().expect("must parse");

    assert_eq!(
        parsed.as_str(),
        "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
    );
}

#[test]
fn address_parser_rejects_invalid_mixed_case_checksum() {
    let checksummed = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        .parse::<Address>()
        .expect("alloy address")
        .to_checksum(None);
    let invalid = mutate_checksum_case(&checksummed);

    let err = invalid
        .parse::<EvmAddress>()
        .expect_err("must reject invalid checksum");

    assert!(matches!(err, DomainError::InvalidAddress));
}

#[test]
fn address_deserialize_rejects_invalid_values() {
    let invalid =
        serde_json::from_str::<EvmAddress>(r#""not-an-address""#).expect_err("must reject");
    assert!(invalid.to_string().contains("address"));
}

#[test]
fn address_deserialize_normalizes_case() {
    let parsed =
        serde_json::from_str::<EvmAddress>(r#""0xABCD000000000000000000000000000000000000""#)
            .expect("must deserialize");
    assert_eq!(
        parsed.as_str(),
        "0xabcd000000000000000000000000000000000000"
    );
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct U128Wrapper {
    #[serde(with = "super::u128_as_decimal_string")]
    value: u128,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct OptionalU128Wrapper {
    #[serde(with = "super::u128_as_decimal_string::option")]
    value: Option<u128>,
}

#[test]
fn u128_decimal_string_helpers_roundtrip_and_reject_invalid_values() {
    let encoded = serde_json::to_string(&U128Wrapper { value: 42 }).expect("encode");
    assert_eq!(encoded, r#"{"value":"42"}"#);
    let decoded: U128Wrapper = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(decoded, U128Wrapper { value: 42 });

    let some = serde_json::to_string(&OptionalU128Wrapper { value: Some(7) }).expect("encode");
    assert_eq!(some, r#"{"value":"7"}"#);
    let decoded: OptionalU128Wrapper = serde_json::from_str(&some).expect("decode");
    assert_eq!(decoded, OptionalU128Wrapper { value: Some(7) });

    let none = serde_json::to_string(&OptionalU128Wrapper { value: None }).expect("encode");
    assert_eq!(none, r#"{"value":null}"#);
    let decoded: OptionalU128Wrapper = serde_json::from_str(&none).expect("decode");
    assert_eq!(decoded, OptionalU128Wrapper { value: None });

    let err = serde_json::from_str::<U128Wrapper>(r#"{"value":"nope"}"#).expect_err("invalid u128");
    assert!(err.to_string().contains("invalid digit"));

    let err = serde_json::from_str::<OptionalU128Wrapper>(r#"{"value":"bad"}"#)
        .expect_err("invalid option u128");
    assert!(err.to_string().contains("invalid digit"));
}

#[test]
fn debug_output_redacts_secret_fields() {
    let lease = AdminLease {
        lease_id: Uuid::nil(),
        lease_secret: "lease-secret".to_string().into(),
        issued_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(5),
    };
    let session = AdminAuth::Lease(lease.session());
    let credentials = AgentCredentials {
        agent_key: AgentKey {
            id: Uuid::nil(),
            vault_key_id: Uuid::nil(),
            policies: PolicyAttachment::AllPolicies,
            created_at: OffsetDateTime::UNIX_EPOCH,
        },
        auth_token: "agent-secret".to_string().into(),
    };
    let request = SignRequest {
        request_id: Uuid::nil(),
        agent_key_id: Uuid::nil(),
        agent_auth_token: "agent-secret".to_string().into(),
        payload: vec![1, 2, 3],
        action: AgentAction::TransferNative {
            chain_id: 1,
            to: "0x2222222222222222222222222222222222222222"
                .parse()
                .expect("to"),
            amount_wei: 1,
        },
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(1),
    };

    let lease_debug = format!("{lease:?}");
    let session_debug = format!("{session:?}");
    let credentials_debug = format!("{credentials:?}");
    let request_debug = format!("{request:?}");

    assert!(!lease_debug.contains("lease-secret"));
    assert!(lease_debug.contains("<redacted>"));
    assert!(!session_debug.contains("lease-secret"));
    assert!(session_debug.contains("<redacted>"));
    assert!(!credentials_debug.contains("agent-secret"));
    assert!(credentials_debug.contains("<redacted>"));
    assert!(!request_debug.contains("agent-secret"));
    assert!(request_debug.contains("<redacted>"));
}

#[test]
fn nonce_reservation_request_debug_redacts_agent_auth_token() {
    let request = NonceReservationRequest {
        request_id: Uuid::nil(),
        agent_key_id: Uuid::nil(),
        agent_auth_token: "super-secret-token".to_string().into(),
        chain_id: 1,
        min_nonce: 7,
        exact_nonce: false,
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2),
    };

    let rendered = format!("{request:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-token"));
}

#[test]
fn nonce_release_request_debug_redacts_agent_auth_token() {
    let request = NonceReleaseRequest {
        request_id: Uuid::nil(),
        agent_key_id: Uuid::nil(),
        agent_auth_token: "super-secret-token".to_string().into(),
        reservation_id: Uuid::nil(),
        requested_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(2),
    };

    let rendered = format!("{request:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-token"));
}

#[test]
fn admin_auth_defaults_to_peer_credentials_and_round_trips_leases() {
    assert_eq!(AdminAuth::default(), AdminAuth::PeerCredentials);
    let json = serde_json::to_string(&AdminAuth::PeerCredentials).expect("serialize");
    assert_eq!(json, r#""peer_credentials""#);

    let mut auth = AdminAuth::Lease(AdminSession {
        lease_id: Uuid::nil(),
        lease_secret: "ab".repeat(32).into(),
    });
    let json = serde_json::to_string(&auth).expect("serialize");
    assert!(json.starts_with(r#"{"lease":{"lease_id":"#));
    assert_eq!(
        serde_json::from_str::<AdminAuth>(&json).expect("deserialize"),
        auth
    );
    auth.zeroize_secrets();
    let AdminAuth::Lease(session) = auth else {
        panic!("lease variant");
    };
    assert!(session.lease_secret.is_empty());
}

#[test]
fn vault_keys_stored_before_names_existed_decode_unnamed() {
    let key = VaultKey {
        id: Uuid::new_v4(),
        source: KeySource::Generated,
        algorithm: KeyAlgorithm::Secp256k1,
        public_key_hex: "04".to_string() + &"11".repeat(64),
        created_at: OffsetDateTime::UNIX_EPOCH,
        name: None,
    };
    let legacy = serde_json::to_value(&key).expect("encode");
    assert!(
        legacy.get("name").is_none(),
        "an unnamed key looks as before"
    );
    let decoded: VaultKey = serde_json::from_value(legacy).expect("legacy decode");
    assert_eq!(decoded, key);
    let named = VaultKey {
        name: Some("Trading bot".into()),
        ..key
    };
    let encoded = serde_json::to_value(&named).expect("encode");
    assert_eq!(encoded["name"], "Trading bot");
}
