use super::*;

#[derive(Debug, Deserialize)]
struct TempoVectorCall {
    to: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct TempoV2VectorFile {
    vectors: Vec<TempoV2Vector>,
}

#[derive(Debug, Deserialize)]
struct TempoV2Vector {
    name: String,
    open: TempoSessionV2OpenTransaction,
    top_up: TempoSessionV2TopUpTransaction,
    voucher: TempoSessionV2Voucher,
    expected: TempoV2VectorExpected,
}

#[derive(Debug, Deserialize)]
struct TempoV2VectorExpected {
    expiring_nonce_hash_hex: String,
    channel_id_hex: String,
    open_calls: Vec<TempoVectorCall>,
    top_up_calls: Vec<TempoVectorCall>,
    open_signing_hash_hex: String,
    top_up_signing_hash_hex: String,
    voucher_signing_hash_hex: String,
    close_authorization_signing_hash_hex: String,
}

fn load_tempo_v2_vectors() -> Vec<TempoV2Vector> {
    let raw = include_str!("../../tests/fixtures/tempo_session_v2_vectors.json");
    serde_json::from_str::<TempoV2VectorFile>(raw)
        .expect("tempo v2 fixture parses")
        .vectors
}

fn sample_tempo_v2_vector() -> TempoV2Vector {
    load_tempo_v2_vectors()
        .into_iter()
        .find(|vector| vector.name == "4217-unsponsored")
        .expect("sample v2 vector")
}

fn assert_vector_calls(
    name: &str,
    label: &str,
    calls: &[(EvmAddress, Vec<u8>)],
    expected: &[TempoVectorCall],
) {
    assert_eq!(calls.len(), expected.len(), "{name}: {label} call count");
    for ((to, data), expected) in calls.iter().zip(expected) {
        assert_eq!(to.as_str(), expected.to, "{name}: {label} call target");
        assert_eq!(hex0x(data), expected.data, "{name}: {label} calldata");
    }
}

#[test]
fn tempo_session_v2_digests_match_viem_reference_vectors() {
    let vectors = load_tempo_v2_vectors();
    assert_eq!(vectors.len(), 4, "2 chains x 2 fee modes");
    for vector in vectors {
        let name = &vector.name;
        assert_eq!(
            hex0x(
                &vector
                    .open
                    .expiring_nonce_hash()
                    .expect("expiring nonce hash")
            ),
            vector.expected.expiring_nonce_hash_hex,
            "{name}: expiring nonce hash"
        );
        assert_eq!(
            hex0x(&vector.open.channel_id().expect("channel id")),
            vector.expected.channel_id_hex,
            "{name}: channel id"
        );
        assert_vector_calls(
            name,
            "open",
            &vector.open.encoded_calls().expect("open calls"),
            &vector.expected.open_calls,
        );
        assert_vector_calls(
            name,
            "topUp",
            &vector.top_up.encoded_calls().expect("topUp calls"),
            &vector.expected.top_up_calls,
        );
        assert_eq!(
            hex0x(&vector.open.signing_hash().expect("open digest")),
            vector.expected.open_signing_hash_hex,
            "{name}: open digest"
        );
        assert_eq!(
            hex0x(&vector.top_up.signing_hash().expect("topUp digest")),
            vector.expected.top_up_signing_hash_hex,
            "{name}: topUp digest"
        );
        assert_eq!(
            hex0x(&vector.voucher.signing_hash().expect("voucher digest")),
            vector.expected.voucher_signing_hash_hex,
            "{name}: voucher digest"
        );
        let close = TempoSessionV2CloseAuthorization {
            voucher: vector.voucher.clone(),
        };
        assert_eq!(
            hex0x(&close.signing_hash().expect("close digest")),
            vector.expected.close_authorization_signing_hash_hex,
            "{name}: close authorization digest"
        );
    }
}

#[test]
fn tempo_session_v2_open_requires_expiring_nonce() {
    let open = sample_tempo_v2_vector().open;
    let mut tx = open.tx.clone();
    tx.nonce_key = None;
    assert!(matches!(
        TempoSessionV2OpenTransaction { tx, ..open.clone() }.validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
    let mut tx = open.tx.clone();
    tx.nonce = 1;
    assert!(matches!(
        TempoSessionV2OpenTransaction { tx, ..open.clone() }.validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
    let mut tx = open.tx.clone();
    tx.valid_before = None;
    assert!(matches!(
        TempoSessionV2OpenTransaction { tx, ..open }.validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
}

#[test]
fn tempo_session_v2_expiring_nonce_hash_binds_the_open_transaction() {
    let open = sample_tempo_v2_vector().open;
    let base = open.channel_id().expect("channel id");
    let mut tx = open.tx.clone();
    tx.valid_before = tx.valid_before.map(|value| value + 1);
    assert_ne!(
        TempoSessionV2OpenTransaction { tx, ..open.clone() }
            .channel_id()
            .expect("channel id"),
        base,
        "a different open transaction yields a different channel"
    );
    assert_ne!(
        TempoSessionV2OpenTransaction {
            deposit_wei: open.deposit_wei + 1,
            ..open
        }
        .channel_id()
        .expect("channel id"),
        base
    );
}

#[test]
fn tempo_session_v2_rejects_mismatched_channel_and_bad_amounts() {
    let vector = sample_tempo_v2_vector();
    assert!(matches!(
        TempoSessionV2Voucher {
            recipient: "0x8888888888888888888888888888888888888888"
                .parse()
                .expect("recipient"),
            ..vector.voucher.clone()
        }
        .signing_hash(),
        Err(DomainError::TempoChannelIdMismatch)
    ));
    assert!(matches!(
        TempoSessionV2Voucher {
            expiring_nonce_hash_hex: format!("0x{}", hex::encode([0x42u8; 32])),
            ..vector.voucher.clone()
        }
        .validate(),
        Err(DomainError::TempoChannelIdMismatch)
    ));
    assert!(matches!(
        TempoSessionV2TopUpTransaction {
            operator: "0x6666666666666666666666666666666666666666"
                .parse()
                .expect("operator"),
            ..vector.top_up.clone()
        }
        .validate(),
        Err(DomainError::TempoChannelIdMismatch)
    ));
    assert!(matches!(
        TempoSessionV2Voucher {
            cumulative_amount_wei: 1u128 << 96,
            ..vector.voucher.clone()
        }
        .validate(),
        Err(DomainError::TempoAmountOverflow)
    ));
    assert!(matches!(
        TempoSessionV2OpenTransaction {
            deposit_wei: 1u128 << 96,
            ..vector.open.clone()
        }
        .validate(),
        Err(DomainError::TempoAmountOverflow)
    ));
    assert!(matches!(
        TempoSessionV2Voucher {
            cumulative_amount_wei: 0,
            ..vector.voucher.clone()
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
    assert!(matches!(
        TempoSessionV2OpenTransaction {
            chain_id: 1,
            ..vector.open.clone()
        }
        .validate(),
        Err(DomainError::UnsupportedTempoChain(1))
    ));
    assert!(matches!(
        TempoSessionV2OpenTransaction {
            authorized_signer: "0x9999999999999999999999999999999999999999"
                .parse()
                .expect("signer"),
            ..vector.open
        }
        .validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
}

#[test]
fn tempo_session_v2_rejects_bad_salt_and_transaction_params() {
    let open = sample_tempo_v2_vector().open;
    assert!(matches!(
        TempoSessionV2OpenTransaction {
            salt_hex: "0x12".to_string(),
            ..open.clone()
        }
        .validate(),
        Err(DomainError::InvalidTypedDataDomain(_))
    ));
    type Mutation = fn(&mut TempoTxParams);
    let invalid_params: [(&str, Mutation); 6] = [
        ("zero gas limit", |tx| tx.gas_limit = 0),
        ("priority fee above max fee", |tx| {
            tx.max_priority_fee_per_gas_wei = tx.max_fee_per_gas_wei + 1;
        }),
        ("sponsored tx naming a fee token", |tx| tx.fee_payer = true),
        ("non-numeric nonce key", |tx| {
            tx.nonce_key = Some("not-a-number".to_string());
        }),
        ("zero valid_before", |tx| tx.valid_before = Some(0)),
        ("empty validity window", |tx| {
            tx.valid_after = tx.valid_before
        }),
    ];
    for (label, mutate) in invalid_params {
        let mut tx = open.tx.clone();
        mutate(&mut tx);
        assert!(
            matches!(
                TempoSessionV2OpenTransaction { tx, ..open.clone() }.validate(),
                Err(DomainError::InvalidTempoTransactionParams(_))
            ),
            "{label}"
        );
    }
}

#[test]
fn tempo_session_v2_policy_semantics() {
    let vector = sample_tempo_v2_vector();
    let cumulative = vector.voucher.cumulative_amount_wei;
    let open = AgentAction::TempoSessionV2OpenTransaction {
        authorization: vector.open,
    };
    let top_up = AgentAction::TempoSessionV2TopUpTransaction {
        authorization: vector.top_up,
    };
    let close = AgentAction::TempoSessionV2CloseAuthorization {
        authorization: TempoSessionV2CloseAuthorization {
            voucher: vector.voucher.clone(),
        },
    };
    let voucher = AgentAction::TempoSessionV2Voucher {
        authorization: vector.voucher,
    };
    assert_eq!(open.amount_wei(), 2_500_000);
    assert_eq!(top_up.amount_wei(), 750_000);
    assert_eq!(voucher.amount_wei(), cumulative);
    assert_eq!(close.amount_wei(), cumulative);
    assert!(open.records_spend_event());
    assert!(top_up.records_spend_event());
    for action in [&voucher, &close] {
        assert!(!action.records_spend_event());
        assert!(action.is_escrow_redistribution());
    }
    assert!(!open.is_escrow_redistribution());
    assert!(!top_up.is_escrow_redistribution());
    assert_ne!(
        voucher.signing_hash().expect("voucher"),
        close.signing_hash().expect("close"),
        "voucher and close authorization use distinct EIP-712 types"
    );
}
