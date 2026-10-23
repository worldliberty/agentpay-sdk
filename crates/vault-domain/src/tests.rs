use std::collections::BTreeSet;

use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::*;

sol! {
    function approve(address spender, uint256 value);
    function transfer(address to, uint256 value);
    function increaseAllowance(address spender, uint256 addedValue);
    function setApprovalForAll(address operator, bool approved);
}

fn broadcast_tx_with_calldata(data_hex: String, value_wei: u128) -> BroadcastTx {
    BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("to"),
        value_wei,
        data_hex,
        gas_limit: 60_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    }
}

fn unix_timestamp(value: OffsetDateTime) -> u64 {
    value.unix_timestamp().try_into().expect("unix timestamp")
}

fn future_unix_timestamp(offset: time::Duration) -> u64 {
    unix_timestamp(OffsetDateTime::now_utc() + offset)
}

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
fn manual_approval_capability_token_is_deterministic_per_request() {
    let approval_request_id =
        Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("uuid");
    let relay_private_key_hex = "11".repeat(32);

    let first = manual_approval_capability_token(&relay_private_key_hex, approval_request_id)
        .expect("must derive token");
    let second = manual_approval_capability_token(&relay_private_key_hex, approval_request_id)
        .expect("must derive token");

    assert_eq!(first, second);
    assert_eq!(first.len(), 64);

    let capability_hash = manual_approval_capability_hash(&first).expect("must hash token");
    assert_eq!(capability_hash.len(), 64);
    assert_ne!(capability_hash, first);
}

#[test]
fn manual_approval_capability_token_rejects_invalid_secret() {
    let approval_request_id = Uuid::new_v4();
    let err = manual_approval_capability_token("not-hex", approval_request_id)
        .expect_err("must reject invalid secret");
    assert!(matches!(err, DomainError::InvalidRelayCapabilitySecret));
}

#[test]
fn manual_approval_capability_helpers_reject_blank_and_short_inputs() {
    let approval_request_id = Uuid::new_v4();
    let err = manual_approval_capability_token("  ", approval_request_id)
        .expect_err("must reject blank secret");
    assert!(matches!(err, DomainError::InvalidRelayCapabilitySecret));

    let err = manual_approval_capability_token("11", approval_request_id)
        .expect_err("must reject short secret");
    assert!(matches!(err, DomainError::InvalidRelayCapabilitySecret));

    let err =
        manual_approval_capability_hash("   ").expect_err("must reject blank capability token");
    assert!(matches!(err, DomainError::InvalidRelayCapabilityToken));
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

#[test]
fn solana_chain_ids_are_canonicalized_for_policy() {
    let action = AgentAction::SolanaSplTransfer {
        transfer: SolanaSplTransfer {
            chain_id: SOLANA_DEVNET_CHAIN_ID,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
            durable_nonce_account: None,
            fee_payer: "11111111111111111111111111111111"
                .parse()
                .expect("fee payer"),
            mint: "So11111111111111111111111111111111111111112"
                .parse()
                .expect("mint"),
            recipient_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
            decimals: 9,
            token_program: SolanaTokenProgram::Token,
            transfer_fee_wei: None,
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
        },
    };

    action.validate().expect("solana transfer validates");
    assert_eq!(action.chain_id(), SOLANA_POLICY_CHAIN_ID);
    assert_eq!(
        canonical_policy_chain_id(SOLANA_TESTNET_CHAIN_ID),
        SOLANA_POLICY_CHAIN_ID
    );
}

#[test]
fn solana_native_transfer_projects_to_native_sol_policy_asset() {
    let action = AgentAction::SolanaSolTransfer {
        transfer: SolanaSolTransfer {
            chain_id: SOLANA_DEVNET_CHAIN_ID,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
            durable_nonce_account: None,
            fee_payer: "11111111111111111111111111111111"
                .parse()
                .expect("fee payer"),
            to: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                .parse()
                .expect("recipient"),
            amount_wei: 5_000,
            compute_unit_limit: Some(5_000),
            compute_unit_price_micro_lamports: Some(1),
        },
    };

    action.validate().expect("solana native transfer validates");
    assert_eq!(action.chain_id(), SOLANA_POLICY_CHAIN_ID);
    assert_eq!(action.asset(), AssetId::NativeSol);
}

#[test]
fn solana_nonce_account_create_is_validated_as_wallet_maintenance() {
    let create = SolanaNonceAccountCreate {
        chain_id: SOLANA_DEVNET_CHAIN_ID,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
        fee_payer: "11111111111111111111111111111111"
            .parse()
            .expect("fee payer"),
        nonce_account: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            .parse()
            .expect("nonce account"),
        seed: "agentpay-900000002-nonce".to_string(),
        rent_lamports: 1_500_000,
    };
    let action = AgentAction::SolanaNonceAccountCreate {
        create: create.clone(),
    };

    action.validate().expect("nonce account create validates");
    assert!(action.is_wallet_maintenance());
    assert!(!action.records_spend_event());
    assert_eq!(action.chain_id(), SOLANA_POLICY_CHAIN_ID);
    assert_eq!(action.asset(), AssetId::NativeSol);
    assert_eq!(action.recipient(), create.nonce_account.clone());

    let mut invalid_seed = create.clone();
    invalid_seed.seed = "x".repeat(33);
    assert!(matches!(
        invalid_seed.validate(),
        Err(DomainError::InvalidSolanaNonceSeed)
    ));
}

#[test]
fn solana_nonce_account_rent_constants_follow_rent_formula() {
    // (ACCOUNT_STORAGE_OVERHEAD 128 + 80 data bytes) * 3480 lamports/byte-year * 2 years.
    assert_eq!(SOLANA_NONCE_ACCOUNT_DATA_LEN_BYTES, 80);
    assert_eq!(SOLANA_NONCE_ACCOUNT_RENT_EXEMPT_MINIMUM_LAMPORTS, 1_447_680);
    assert_eq!(SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS, 2_895_360);
}

#[test]
fn solana_nonce_account_create_caps_rent_at_twice_rent_exempt_minimum() {
    let base = SolanaNonceAccountCreate {
        chain_id: SOLANA_DEVNET_CHAIN_ID,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
        fee_payer: "11111111111111111111111111111111"
            .parse()
            .expect("fee payer"),
        nonce_account: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            .parse()
            .expect("nonce account"),
        seed: "agentpay-900000002-nonce".to_string(),
        rent_lamports: SOLANA_NONCE_ACCOUNT_RENT_EXEMPT_MINIMUM_LAMPORTS,
    };
    base.validate().expect("rent-exempt minimum is accepted");

    let at_cap = SolanaNonceAccountCreate {
        rent_lamports: SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS,
        ..base.clone()
    };
    at_cap
        .validate()
        .expect("rent exactly at the cap is accepted");

    let above_cap = SolanaNonceAccountCreate {
        rent_lamports: SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS + 1,
        ..base.clone()
    };
    assert!(matches!(
        above_cap.validate(),
        Err(DomainError::SolanaNonceRentTooHigh { max_lamports })
            if max_lamports == SOLANA_NONCE_ACCOUNT_MAX_RENT_LAMPORTS
    ));
    assert!(matches!(
        AgentAction::SolanaNonceAccountCreate { create: above_cap }.validate(),
        Err(DomainError::SolanaNonceRentTooHigh { .. })
    ));

    let drain_attempt = SolanaNonceAccountCreate {
        rent_lamports: u128::from(u64::MAX),
        ..base
    };
    assert!(matches!(
        drain_attempt.validate(),
        Err(DomainError::SolanaNonceRentTooHigh { .. })
    ));
}

#[test]
fn token2022_transfer_fee_requires_token2022_program() {
    let mut transfer = SolanaSplTransfer {
        chain_id: SOLANA_DEVNET_CHAIN_ID,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
        durable_nonce_account: None,
        fee_payer: "11111111111111111111111111111111"
            .parse()
            .expect("fee payer"),
        mint: "So11111111111111111111111111111111111111112"
            .parse()
            .expect("mint"),
        recipient_owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            .parse()
            .expect("recipient"),
        amount_wei: 100,
        decimals: 6,
        token_program: SolanaTokenProgram::Token,
        transfer_fee_wei: Some(1),
        compute_unit_limit: None,
        compute_unit_price_micro_lamports: None,
    };

    assert!(matches!(
        transfer.validate(),
        Err(DomainError::InvalidSolanaTokenProgram)
    ));
    transfer.token_program = SolanaTokenProgram::Token2022;
    transfer
        .validate()
        .expect("token-2022 transfer fee validates");
}

fn mutate_checksum_case(checksummed: &str) -> String {
    let mut invalid = checksummed.to_owned();
    let (index, ch) = invalid
        .char_indices()
        .skip(2)
        .find(|(_, ch)| ch.is_ascii_alphabetic())
        .expect("checksummed address should contain alphabetic characters");
    let flipped = if ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase()
    } else {
        ch.to_ascii_lowercase()
    };
    invalid.replace_range(index..index + ch.len_utf8(), &flipped.to_string());
    assert_ne!(invalid, checksummed);

    invalid
}

#[test]
fn all_scope_allows_any_value() {
    let addr = "0x2222222222222222222222222222222222222222"
        .parse::<EvmAddress>()
        .expect("must parse");
    let scope: EntityScope<EvmAddress> = EntityScope::All;

    assert!(scope.allows(&addr));
}

#[test]
fn policy_set_cannot_be_empty() {
    let empty = BTreeSet::new();
    let result = PolicyAttachment::policy_set(empty);
    assert!(matches!(result, Err(DomainError::EmptyPolicySet)));
}

#[test]
fn policy_attachment_applies_to_all_and_selected_ids() {
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let attachment = PolicyAttachment::policy_set(BTreeSet::from([first])).expect("policy set");

    assert!(PolicyAttachment::AllPolicies.applies_to(first));
    assert!(attachment.applies_to(first));
    assert!(!attachment.applies_to(second));
}

#[test]
fn spending_policy_rejects_invalid_ranges_and_network_sets() {
    let recipient: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("recipient");
    let asset = AssetId::Erc20(
        "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("token"),
    );

    let err = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        0,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect_err("zero max amount");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new_manual_approval(
        1,
        0,
        10,
        EntityScope::Set(BTreeSet::from([recipient.clone()])),
        EntityScope::Set(BTreeSet::from([asset.clone()])),
        EntityScope::Set(BTreeSet::from([1])),
    )
    .expect_err("zero min amount");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new_manual_approval(
        1,
        11,
        10,
        EntityScope::Set(BTreeSet::from([recipient.clone()])),
        EntityScope::Set(BTreeSet::from([asset.clone()])),
        EntityScope::Set(BTreeSet::from([1])),
    )
    .expect_err("min greater than max");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::Set(BTreeSet::from([recipient])),
        EntityScope::Set(BTreeSet::from([asset])),
        EntityScope::Set(BTreeSet::from([0])),
    )
    .expect_err("zero chain id");
    assert!(matches!(err, DomainError::InvalidChainId));

    let err = SpendingPolicy::new_calldata_limit(
        1,
        0,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect_err("zero calldata bytes");
    assert!(matches!(err, DomainError::InvalidAmount));

    let err = SpendingPolicy::new_with_range(
        1,
        PolicyType::PerTxMaxCalldataBytes,
        Some(1),
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect_err("calldata policies must not accept amount ranges");
    assert!(matches!(err, DomainError::InvalidAmount));
}

#[test]
fn specialized_policies_use_dedicated_limits_and_support_legacy_deserialization() {
    fn assert_specialized_limit_round_trip(
        policy: SpendingPolicy,
        dedicated_field: &str,
        expected_limit: u128,
        legacy_limit: u128,
        accessor: fn(&SpendingPolicy) -> Option<u128>,
    ) {
        assert_eq!(policy.max_amount_wei, 0);
        assert_eq!(accessor(&policy), Some(expected_limit));

        let dedicated_json = serde_json::to_value(&policy).expect("serialize policy");
        let serde_json::Value::Object(mut dedicated_fields) = dedicated_json else {
            panic!("policy must serialize as an object");
        };
        assert_eq!(
            dedicated_fields.get("max_amount_wei"),
            Some(&serde_json::Value::String(expected_limit.to_string()))
        );
        assert_eq!(
            dedicated_fields.get(dedicated_field),
            Some(&serde_json::Value::String(expected_limit.to_string()))
        );

        let dedicated: SpendingPolicy =
            serde_json::from_value(serde_json::Value::Object(dedicated_fields.clone()))
                .expect("dedicated policy");
        assert_eq!(dedicated.max_amount_wei, 0);
        assert_eq!(accessor(&dedicated), Some(expected_limit));

        dedicated_fields.remove(dedicated_field);
        dedicated_fields.insert(
            "max_amount_wei".to_string(),
            serde_json::Value::String(legacy_limit.to_string()),
        );

        let legacy: SpendingPolicy =
            serde_json::from_value(serde_json::Value::Object(dedicated_fields))
                .expect("legacy policy");
        assert_eq!(legacy.max_amount_wei, 0);
        assert_eq!(accessor(&legacy), Some(legacy_limit));
    }

    let calldata_policy = SpendingPolicy::new_calldata_limit(
        1,
        32,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    assert_eq!(calldata_policy.max_calldata_bytes, Some(32));
    assert_specialized_limit_round_trip(
        calldata_policy,
        "max_calldata_bytes",
        32,
        64,
        SpendingPolicy::calldata_bytes_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_tx_count_limit(
            1,
            3,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_tx_count",
        3,
        4,
        SpendingPolicy::tx_count_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_fee_per_gas_limit(
            1,
            5,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_fee_per_gas_wei",
        5,
        6,
        SpendingPolicy::fee_per_gas_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_priority_fee_per_gas_limit(
            1,
            7,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_priority_fee_per_gas_wei",
        7,
        8,
        SpendingPolicy::priority_fee_per_gas_limit,
    );

    assert_specialized_limit_round_trip(
        SpendingPolicy::new_gas_spend_limit(
            1,
            9,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy"),
        "max_gas_spend_wei",
        9,
        10,
        SpendingPolicy::gas_spend_limit_wei,
    );

    let non_calldata = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut non_calldata_json = serde_json::to_value(&non_calldata).expect("serialize policy");
    let serde_json::Value::Object(ref mut fields) = non_calldata_json else {
        panic!("policy must serialize as an object");
    };
    fields.remove("max_amount_wei");

    let err = serde_json::from_value::<SpendingPolicy>(non_calldata_json)
        .expect_err("missing max_amount_wei must fail for non-calldata policies");
    assert!(err.to_string().contains("missing field `max_amount_wei`"));
}

#[test]
fn specialized_policy_deserialization_requires_dedicated_or_legacy_limit_field() {
    let policy = SpendingPolicy::new_calldata_limit(
        1,
        32,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");

    let mut missing_limit_json = serde_json::to_value(&policy).expect("serialize policy");
    let serde_json::Value::Object(ref mut fields) = missing_limit_json else {
        panic!("policy must serialize as an object");
    };
    fields.remove("max_calldata_bytes");
    fields.remove("max_amount_wei");

    let err = serde_json::from_value::<SpendingPolicy>(missing_limit_json)
        .expect_err("missing specialized limit must fail");
    assert!(err
        .to_string()
        .contains("missing field `max_calldata_bytes` or legacy `max_amount_wei`"));
}

#[test]
fn spending_policy_deserialization_rejects_zero_and_inverted_amount_limits() {
    let policy = SpendingPolicy::new_manual_approval(
        1,
        5,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let base = serde_json::to_value(&policy).expect("serialize policy");
    serde_json::from_value::<SpendingPolicy>(base.clone()).expect("valid policy round-trips");

    let mut zero_max = base.clone();
    zero_max["max_amount_wei"] = serde_json::json!("0");
    let err = serde_json::from_value::<SpendingPolicy>(zero_max)
        .expect_err("zero max_amount_wei must fail");
    assert!(err
        .to_string()
        .contains("max_amount_wei must be greater than zero"));

    let mut inverted_range = base.clone();
    inverted_range["min_amount_wei"] = serde_json::json!("11");
    let err = serde_json::from_value::<SpendingPolicy>(inverted_range)
        .expect_err("min above max must fail");
    assert!(err
        .to_string()
        .contains("min_amount_wei must not exceed max_amount_wei"));

    let mut equal_range = base;
    equal_range["min_amount_wei"] = serde_json::json!("10");
    let equal = serde_json::from_value::<SpendingPolicy>(equal_range).expect("min == max is valid");
    assert_eq!(equal.min_amount_wei, Some(10));

    let per_tx = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut zero_per_tx = serde_json::to_value(&per_tx).expect("serialize policy");
    zero_per_tx["max_amount_wei"] = serde_json::json!("0");
    assert!(serde_json::from_value::<SpendingPolicy>(zero_per_tx).is_err());
}

#[test]
fn spending_policy_deserialization_rejects_zero_specialized_limits() {
    let calldata_policy = SpendingPolicy::new_calldata_limit(
        1,
        4,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut zero_dedicated = serde_json::to_value(&calldata_policy).expect("serialize policy");
    zero_dedicated["max_calldata_bytes"] = serde_json::json!("0");
    zero_dedicated["max_amount_wei"] = serde_json::json!("0");
    let err = serde_json::from_value::<SpendingPolicy>(zero_dedicated)
        .expect_err("zero calldata limit must fail");
    assert!(err
        .to_string()
        .contains("policy limit must be greater than zero"));

    let tx_count_policy = SpendingPolicy::new_tx_count_limit(
        1,
        3,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    let mut zero_legacy = serde_json::to_value(&tx_count_policy).expect("serialize policy");
    let serde_json::Value::Object(ref mut fields) = zero_legacy else {
        panic!("policy must serialize as an object");
    };
    fields.remove("max_tx_count");
    fields.insert("max_amount_wei".to_string(), serde_json::json!("0"));
    assert!(serde_json::from_value::<SpendingPolicy>(zero_legacy).is_err());
}

#[test]
fn spending_policy_deserialization_validates_network_scope() {
    let policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([1_u64])),
    )
    .expect("policy");
    let base = serde_json::to_value(&policy).expect("serialize policy");

    let mut zero_chain = base.clone();
    zero_chain["networks"] =
        serde_json::to_value(EntityScope::Set(BTreeSet::from([0_u64]))).expect("scope");
    let err =
        serde_json::from_value::<SpendingPolicy>(zero_chain).expect_err("chain id 0 must fail");
    assert!(err
        .to_string()
        .contains("network set must not contain chain_id 0"));

    let mut empty_networks = base;
    empty_networks["networks"] =
        serde_json::to_value(EntityScope::<u64>::Set(BTreeSet::new())).expect("scope");
    let err = serde_json::from_value::<SpendingPolicy>(empty_networks)
        .expect_err("empty network set must fail");
    assert!(err
        .to_string()
        .contains("network set scope must not be empty"));

    let eip712 = SpendingPolicy::new_eip712_signing(1, ApprovalType::Allow, EntityScope::All)
        .expect("policy");
    let mut eip712_zero_chain = serde_json::to_value(&eip712).expect("serialize policy");
    eip712_zero_chain["networks"] =
        serde_json::to_value(EntityScope::Set(BTreeSet::from([0_u64]))).expect("scope");
    let err = serde_json::from_value::<SpendingPolicy>(eip712_zero_chain)
        .expect_err("eip712 policy with chain id 0 must fail");
    assert!(err
        .to_string()
        .contains("network set must not contain chain_id 0"));
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
fn parse_erc20_transfer_call_succeeds() {
    let to = alloy_primitives::Address::from([0x11; 20]);
    let amount = U256::from(42_u64);
    let calldata = transferCall { to, value: amount }.abi_encode();

    let parsed = parse_erc20_call(&calldata).expect("decode");
    assert_eq!(
        parsed,
        Erc20Call::Transfer {
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("address"),
            amount_wei: 42,
        }
    );
}

#[test]
fn parse_erc20_approve_call_succeeds() {
    let spender = alloy_primitives::Address::from([0x22; 20]);
    let amount = U256::from(1337_u64);
    let calldata = approveCall {
        spender,
        value: amount,
    }
    .abi_encode();

    let action = action_from_erc20_calldata(
        1,
        "0x3333333333333333333333333333333333333333"
            .parse()
            .expect("token"),
        &calldata,
    )
    .expect("action");

    assert_eq!(
        action,
        AgentAction::Approve {
            chain_id: 1,
            token: "0x3333333333333333333333333333333333333333"
                .parse()
                .expect("token"),
            spender: "0x2222222222222222222222222222222222222222"
                .parse()
                .expect("spender"),
            amount_wei: 1337,
        }
    );
}

#[test]
fn parse_erc20_call_rejects_unknown_selector() {
    let err = parse_erc20_call(&[0xde, 0xad, 0xbe, 0xef, 0x00]).expect_err("must fail");
    assert!(matches!(err, DomainError::InvalidErc20Calldata(_)));
}

#[test]
fn broadcast_tx_rejects_delegation() {
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0x1234000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: true,
    };

    let err = tx.validate().expect_err("must reject delegation");
    assert!(matches!(err, DomainError::DelegationNotAllowed));
}

#[test]
fn broadcast_tx_rejects_delegation_for_eip7702() {
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0x1234000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: EIP7702_TX_TYPE,
        delegation_enabled: true,
    };

    let err = tx.validate().expect_err("must reject delegation");
    assert!(matches!(err, DomainError::DelegationNotAllowed));
}

#[test]
fn broadcast_tx_rejects_erc20_call_with_native_value() {
    let to = alloy_primitives::Address::from([0x11; 20]);
    let amount = U256::from(7_u64);
    let calldata = transferCall { to, value: amount }.abi_encode();

    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        value_wei: 1,
        data_hex: format!("0x{}", hex::encode(calldata)),
        gas_limit: 60_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    let err = tx.validate().expect_err("must reject mixed erc20/native");
    assert!(matches!(err, DomainError::Erc20CallWithNativeValue));
}

#[test]
fn broadcast_action_derives_erc20_scope_from_calldata() {
    let to = alloy_primitives::Address::from([0x33; 20]);
    let calldata = transferCall {
        to,
        value: U256::from(77_u64),
    }
    .abi_encode();
    let token: EvmAddress = "0x4444000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: token.clone(),
        value_wei: 0,
        data_hex: format!("0x{}", hex::encode(calldata)),
        gas_limit: 60_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    let action = AgentAction::BroadcastTx { tx };

    assert_eq!(action.asset(), AssetId::Erc20(token));
    assert_eq!(action.amount_wei(), 77);
    assert_eq!(
        action.recipient(),
        "0x3333333333333333333333333333333333333333"
            .parse::<EvmAddress>()
            .expect("recipient")
    );
}

#[test]
fn broadcast_tx_rejects_unknown_calldata_selector() {
    let tx = broadcast_tx_with_calldata("0xdeadbeef".to_string(), 123);

    assert!(matches!(
        tx.validate(),
        Err(DomainError::UnrecognizedCalldata)
    ));
    assert!(matches!(
        tx.eip1559_signing_message(),
        Err(DomainError::UnrecognizedCalldata)
    ));
    assert!(matches!(
        tx.eip1559_signed_raw_transaction(0, [0x11; 32], [0x22; 32]),
        Err(DomainError::UnrecognizedCalldata)
    ));
    assert!(matches!(
        AgentAction::BroadcastTx { tx }.validate(),
        Err(DomainError::UnrecognizedCalldata)
    ));
}

#[test]
fn broadcast_tx_with_empty_calldata_stays_a_native_transfer() {
    for data_hex in ["", "0x"] {
        let tx = broadcast_tx_with_calldata(data_hex.to_string(), 123);
        tx.validate().expect("plain native transfer validates");

        let action = AgentAction::BroadcastTx { tx: tx.clone() };
        assert_eq!(action.asset(), AssetId::NativeEth);
        assert_eq!(action.amount_wei(), 123);
        assert_eq!(action.recipient(), tx.to);
    }
}

#[test]
fn broadcast_tx_rejects_increase_allowance_calldata() {
    let calldata = increaseAllowanceCall {
        spender: alloy_primitives::Address::from([0x33; 20]),
        addedValue: U256::from(1_u64),
    }
    .abi_encode();
    let tx = broadcast_tx_with_calldata(format!("0x{}", hex::encode(calldata)), 0);

    assert!(matches!(
        tx.validate(),
        Err(DomainError::UnrecognizedCalldata)
    ));
}

#[test]
fn broadcast_tx_rejects_set_approval_for_all_calldata() {
    let calldata = setApprovalForAllCall {
        operator: alloy_primitives::Address::from([0x33; 20]),
        approved: true,
    }
    .abi_encode();
    let tx = broadcast_tx_with_calldata(format!("0x{}", hex::encode(calldata)), 0);

    assert!(matches!(
        tx.validate(),
        Err(DomainError::UnrecognizedCalldata)
    ));
}

#[test]
fn broadcast_tx_rejects_truncated_selector_calldata() {
    // Fewer than 4 bytes can never be a recognized call; must not be treated
    // as a native transfer either.
    let tx = broadcast_tx_with_calldata("0xdead".to_string(), 0);

    assert!(matches!(
        tx.validate(),
        Err(DomainError::UnrecognizedCalldata)
    ));
}

#[test]
fn debug_output_redacts_secret_fields() {
    let lease = Lease {
        lease_id: Uuid::nil(),
        issued_at: OffsetDateTime::UNIX_EPOCH,
        expires_at: OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(5),
    };
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease: lease.clone(),
    };
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

    let session_debug = format!("{session:?}");
    let credentials_debug = format!("{credentials:?}");
    let request_debug = format!("{request:?}");

    assert!(!session_debug.contains("vault-password"));
    assert!(session_debug.contains("<redacted>"));
    assert!(!credentials_debug.contains("agent-secret"));
    assert!(credentials_debug.contains("<redacted>"));
    assert!(!request_debug.contains("agent-secret"));
    assert!(request_debug.contains("<redacted>"));
}

#[test]
fn broadcast_action_exposes_gas_and_calldata_metadata() {
    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .expect("to"),
            value_wei: 0,
            data_hex: "0xdeadbeef".to_string(),
            gas_limit: 21_000,
            max_fee_per_gas_wei: 2_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };

    assert_eq!(action.max_fee_per_gas_wei(), Some(2_000_000_000));
    assert_eq!(action.max_priority_fee_per_gas_wei(), Some(1_000_000_000));
    assert_eq!(action.calldata_len_bytes(), Some(4));
}

#[test]
fn eip1559_signing_message_is_typed_and_non_empty() {
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xf0109fc8df283027b6285cc889f5aa624eac1f55"
            .parse()
            .expect("to"),
        value_wei: 1_000_000_000,
        data_hex: "0x".to_string(),
        gas_limit: 2_000_000,
        max_fee_per_gas_wei: 21_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    let signing_message = tx.eip1559_signing_message().expect("signing message");
    assert_eq!(signing_message.first().copied(), Some(0x02));
    assert!(!signing_message.is_empty());
}

#[test]
fn eip1559_signed_raw_transaction_includes_signature_components() {
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xf0109fc8df283027b6285cc889f5aa624eac1f55"
            .parse()
            .expect("to"),
        value_wei: 1_000_000_000,
        data_hex: "0x".to_string(),
        gas_limit: 2_000_000,
        max_fee_per_gas_wei: 21_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    let r = [0x11u8; 32];
    let s = [0x22u8; 32];
    let raw = tx
        .eip1559_signed_raw_transaction(1, r, s)
        .expect("signed raw tx");
    assert_eq!(raw.first().copied(), Some(0x02));
    assert!(!raw.is_empty());
}

#[test]
fn eip1559_helpers_reject_unsupported_tx_type() {
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: EIP7702_TX_TYPE,
        delegation_enabled: false,
    };
    let err = tx
        .eip1559_signing_message()
        .expect_err("must reject non-eip-1559 tx type");
    assert!(matches!(err, DomainError::UnsupportedTransactionType(_)));
}

sol! {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    function permit(address owner, PermitSingle permitSingle, bytes signature);
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);
}

#[test]
fn asset_id_display_formats_native_and_erc20_variants() {
    let token: EvmAddress = "0x1234000000000000000000000000000000000000"
        .parse()
        .expect("token");

    assert_eq!(AssetId::NativeEth.to_string(), "native_eth");
    assert_eq!(AssetId::NativeSol.to_string(), "native_sol");
    assert_eq!(
        AssetId::Erc20(token).to_string(),
        "erc20:0x1234000000000000000000000000000000000000"
    );
}

#[test]
fn spending_policy_rejects_empty_network_sets() {
    let err = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(BTreeSet::new()),
    )
    .expect_err("empty network set must fail");

    assert!(matches!(
        &err,
        DomainError::EmptyScope { scope } if *scope == "network set"
    ));
    assert_eq!(err.to_string(), "network set scope must not be empty");
}

#[test]
fn broadcast_tx_rejects_permit2_call_with_native_value() {
    let permit_single = PermitSingle {
        details: PermitDetails {
            token: alloy_primitives::Address::from([0x44; 20]),
            amount: alloy_primitives::U160::from_be_slice(&42u128.to_be_bytes()),
            expiration: alloy_primitives::aliases::U48::from_be_slice(&100u64.to_be_bytes()[2..]),
            nonce: alloy_primitives::aliases::U48::from_be_slice(&7u64.to_be_bytes()[2..]),
        },
        spender: alloy_primitives::Address::from([0x55; 20]),
        sigDeadline: U256::from(1234u64),
    };
    let calldata = permitCall {
        owner: alloy_primitives::Address::from([0x66; 20]),
        permitSingle: permit_single,
        signature: vec![0x12, 0x34].into(),
    }
    .abi_encode();

    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0x9999000000000000000000000000000000000000"
            .parse()
            .expect("permit2 contract"),
        value_wei: 1,
        data_hex: format!("0x{}", hex::encode(calldata)),
        gas_limit: 60_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    let err = tx.validate().expect_err("must reject mixed permit2/native");
    assert!(matches!(err, DomainError::Erc20CallWithNativeValue));
}

#[test]
fn broadcast_action_derives_permit2_scope_from_calldata() {
    let token: EvmAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        .parse()
        .expect("token");
    let spender: EvmAddress = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        .parse()
        .expect("spender");
    let permit2_contract: EvmAddress = "0xcccccccccccccccccccccccccccccccccccccccc"
        .parse()
        .expect("permit2 contract");
    let permit_single = PermitSingle {
        details: PermitDetails {
            token: alloy_primitives::Address::from([0xaa; 20]),
            amount: alloy_primitives::U160::from_be_slice(&77u128.to_be_bytes()),
            expiration: alloy_primitives::aliases::U48::from_be_slice(&100u64.to_be_bytes()[2..]),
            nonce: alloy_primitives::aliases::U48::from_be_slice(&5u64.to_be_bytes()[2..]),
        },
        spender: alloy_primitives::Address::from([0xbb; 20]),
        sigDeadline: U256::from(200u64),
    };
    let calldata = permitCall {
        owner: alloy_primitives::Address::from([0xdd; 20]),
        permitSingle: permit_single,
        signature: vec![0xab, 0xcd].into(),
    }
    .abi_encode();
    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: permit2_contract,
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(calldata)),
            gas_limit: 120_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };

    assert_eq!(action.asset(), AssetId::Erc20(token));
    assert_eq!(action.recipient(), spender);
    assert_eq!(action.amount_wei(), 77);
}

#[test]
fn broadcast_action_derives_eip3009_scope_from_calldata() {
    let token: EvmAddress = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0xffffffffffffffffffffffffffffffffffffffff"
        .parse()
        .expect("recipient");
    let calldata = transferWithAuthorizationCall {
        from: alloy_primitives::Address::from([0x11; 20]),
        to: alloy_primitives::Address::from([0xff; 20]),
        value: U256::from(91u64),
        validAfter: U256::from(1u64),
        validBefore: U256::from(2u64),
        nonce: [0x55; 32].into(),
        signature: vec![0xde, 0xad].into(),
    }
    .abi_encode();
    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: token.clone(),
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(calldata)),
            gas_limit: 120_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };

    assert_eq!(action.asset(), AssetId::Erc20(token));
    assert_eq!(action.recipient(), recipient);
    assert_eq!(action.amount_wei(), 91);
}

#[test]
fn permit2_and_eip3009_actions_produce_signing_hashes() {
    let expiration = future_unix_timestamp(time::Duration::hours(2));
    let sig_deadline = future_unix_timestamp(time::Duration::hours(1));
    let valid_after = future_unix_timestamp(time::Duration::minutes(5));
    let valid_before = future_unix_timestamp(time::Duration::minutes(10));
    let permit = Permit2Permit {
        chain_id: 1,
        permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
            .parse()
            .expect("permit2"),
        token: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("token"),
        spender: "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("spender"),
        amount_wei: 123,
        expiration,
        nonce: 7,
        sig_deadline,
    };
    let eip3009 = Eip3009Transfer {
        chain_id: 1,
        token: "0x3333333333333333333333333333333333333333"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4444444444444444444444444444444444444444"
            .parse()
            .expect("from"),
        to: "0x5555555555555555555555555555555555555555"
            .parse()
            .expect("to"),
        amount_wei: 456,
        valid_after,
        valid_before,
        nonce_hex: format!("0x{}", hex::encode([0xabu8; 32])),
    };

    let permit_hash = AgentAction::Permit2Permit {
        permit: permit.clone(),
    }
    .signing_hash()
    .expect("permit2 hash")
    .expect("permit2 typed hash");
    let transfer_hash = AgentAction::Eip3009TransferWithAuthorization {
        authorization: eip3009.clone(),
    }
    .signing_hash()
    .expect("eip3009 transfer hash")
    .expect("transfer typed hash");
    let receive_hash = AgentAction::Eip3009ReceiveWithAuthorization {
        authorization: eip3009,
    }
    .signing_hash()
    .expect("eip3009 receive hash")
    .expect("receive typed hash");
    let tempo_open_hash = AgentAction::TempoSessionOpenTransaction {
        authorization: sample_tempo_open(),
    }
    .signing_hash()
    .expect("tempo open hash")
    .expect("tempo open typed hash");
    let tempo_voucher_hash = AgentAction::TempoSessionVoucher {
        authorization: sample_tempo_voucher(),
    }
    .signing_hash()
    .expect("tempo voucher hash")
    .expect("tempo voucher typed hash");

    assert_ne!(permit_hash, [0u8; 32]);
    assert_ne!(transfer_hash, [0u8; 32]);
    assert_ne!(receive_hash, [0u8; 32]);
    assert_ne!(tempo_open_hash, [0u8; 32]);
    assert_ne!(tempo_voucher_hash, [0u8; 32]);
    assert_ne!(transfer_hash, receive_hash);
    assert_ne!(tempo_open_hash, tempo_voucher_hash);
}

#[test]
fn generic_eip712_actions_produce_signing_hashes() {
    let typed_data = Eip712TypedData {
        typed_data_json: r#"{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "verifyingContract", "type": "address" }
    ],
    "Mail": [
      { "name": "contents", "type": "string" }
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "AgentPay Test",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x1111111111111111111111111111111111111111"
  },
  "message": {
    "contents": "hello"
  }
}"#
        .to_string(),
    };

    let action = AgentAction::Eip712TypedData {
        typed_data: typed_data.clone(),
    };
    let signing_hash = action
        .signing_hash()
        .expect("eip712 hash")
        .expect("typed hash");

    assert_ne!(signing_hash, [0u8; 32]);
    assert_eq!(action.chain_id(), 1);
    assert_eq!(
        action
            .eip712_primary_type()
            .expect("primary type")
            .expect("eip712 action"),
        "Mail"
    );
    assert_eq!(
        action
            .eip712_verifying_contract()
            .expect("verifying contract")
            .expect("verifying contract"),
        "0x1111111111111111111111111111111111111111"
            .parse::<EvmAddress>()
            .expect("contract")
    );
}

#[test]
fn generic_eip712_validation_requires_chain_id() {
    let typed_data = Eip712TypedData {
        typed_data_json: r#"{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" }
    ],
    "Mail": [
      { "name": "contents", "type": "string" }
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "AgentPay Test"
  },
  "message": {
    "contents": "hello"
  }
}"#
        .to_string(),
    };

    let err = AgentAction::Eip712TypedData { typed_data }
        .validate()
        .expect_err("missing chainId must fail");
    assert!(
        matches!(err, DomainError::InvalidTypedDataDomain(message) if message.contains("chainId"))
    );
}

#[test]
fn permit2_and_eip3009_validation_reject_invalid_inputs() {
    let now = OffsetDateTime::now_utc();
    let base_permit = Permit2Permit {
        chain_id: 1,
        permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
            .parse()
            .expect("permit2"),
        token: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("token"),
        spender: "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("spender"),
        amount_wei: 123,
        expiration: unix_timestamp(now + time::Duration::hours(2)),
        nonce: 7,
        sig_deadline: unix_timestamp(now + time::Duration::hours(1)),
    };
    assert!(matches!(
        Permit2Permit {
            chain_id: 0,
            ..base_permit.clone()
        }
        .validate(),
        Err(DomainError::InvalidChainId)
    ));
    assert!(matches!(
        Permit2Permit {
            amount_wei: 0,
            ..base_permit.clone()
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
    let expiration_err = Permit2Permit {
        expiration: (1u64 << 48),
        ..base_permit.clone()
    }
    .validate()
    .expect_err("must reject expiration values above uint48");
    assert!(matches!(
        &expiration_err,
        DomainError::Permit2FieldOutOfRange { field } if *field == "expiration"
    ));
    assert_eq!(
        expiration_err.to_string(),
        "permit2 expiration exceeds uint48 range"
    );

    let nonce_err = Permit2Permit {
        nonce: (1u64 << 48),
        ..base_permit.clone()
    }
    .validate()
    .expect_err("must reject nonce values above uint48");
    assert!(matches!(
        &nonce_err,
        DomainError::Permit2FieldOutOfRange { field } if *field == "nonce"
    ));
    assert_eq!(nonce_err.to_string(), "permit2 nonce exceeds uint48 range");
    assert!(matches!(
        Permit2Permit {
            expiration: unix_timestamp(now - time::Duration::seconds(1)),
            ..base_permit.clone()
        }
        .validate_at(now),
        Err(DomainError::InvalidPermitExpiration)
    ));
    assert!(matches!(
        Permit2Permit {
            sig_deadline: 0,
            ..base_permit.clone()
        }
        .validate_at(now),
        Err(DomainError::InvalidSignatureDeadline)
    ));
    let expired_permit = Permit2Permit {
        expiration: unix_timestamp(now - time::Duration::seconds(1)),
        sig_deadline: unix_timestamp(now - time::Duration::seconds(1)),
        ..base_permit.clone()
    };
    assert!(matches!(
        expired_permit.validate_at(now),
        Err(DomainError::InvalidPermitExpiration | DomainError::InvalidSignatureDeadline)
    ));
    assert!(AgentAction::Permit2Permit {
        permit: expired_permit
    }
    .signing_hash()
    .expect("expired permit digest should remain reproducible")
    .is_some());
    assert!(matches!(
        Permit2Permit {
            sig_deadline: u64::try_from((now - time::Duration::seconds(1)).unix_timestamp())
                .expect("past unix timestamp"),
            ..base_permit
        }
        .validate_at(now),
        Err(DomainError::InvalidSignatureDeadline)
    ));

    let base_eip3009 = Eip3009Transfer {
        chain_id: 1,
        token: "0x3333333333333333333333333333333333333333"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some(String::new()),
        from: "0x4444444444444444444444444444444444444444"
            .parse()
            .expect("from"),
        to: "0x5555555555555555555555555555555555555555"
            .parse()
            .expect("to"),
        amount_wei: 456,
        valid_after: unix_timestamp(now + time::Duration::minutes(5)),
        valid_before: unix_timestamp(now + time::Duration::minutes(10)),
        nonce_hex: format!("0x{}", hex::encode([0xabu8; 32])),
    };
    let _ = base_eip3009
        .transfer_signing_hash()
        .expect("empty version should be ignored");
    assert!(matches!(
        Eip3009Transfer {
            chain_id: 0,
            ..base_eip3009.clone()
        }
        .validate(),
        Err(DomainError::InvalidChainId)
    ));
    assert!(matches!(
        Eip3009Transfer {
            amount_wei: 0,
            ..base_eip3009.clone()
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
    assert!(matches!(
        Eip3009Transfer {
            token_name: "   ".to_string(),
            ..base_eip3009.clone()
        }
        .validate(),
        Err(DomainError::InvalidTypedDataDomain(_))
    ));
    assert!(matches!(
        Eip3009Transfer {
            valid_before: 10,
            ..base_eip3009.clone()
        }
        .validate(),
        Err(DomainError::InvalidAuthorizationWindow)
    ));
    assert!(matches!(
        Eip3009Transfer {
            valid_after: unix_timestamp(now - time::Duration::minutes(2)),
            valid_before: unix_timestamp(now - time::Duration::seconds(1)),
            ..base_eip3009.clone()
        }
        .validate_at(now),
        Err(DomainError::InvalidAuthorizationWindow)
    ));
    let expired_eip3009 = Eip3009Transfer {
        valid_after: unix_timestamp(now - time::Duration::minutes(2)),
        valid_before: unix_timestamp(now - time::Duration::seconds(1)),
        ..base_eip3009.clone()
    };
    assert!(matches!(
        expired_eip3009.validate_at(now),
        Err(DomainError::InvalidAuthorizationWindow)
    ));
    assert!(AgentAction::Eip3009TransferWithAuthorization {
        authorization: expired_eip3009
    }
    .signing_hash()
    .expect("expired authorization digest should remain reproducible")
    .is_some());
    assert!(matches!(
        Eip3009Transfer {
            nonce_hex: "0x1234".to_string(),
            ..base_eip3009
        }
        .validate(),
        Err(DomainError::InvalidTypedDataDomain(_))
    ));
    assert!(matches!(
        TempoSessionOpenTransaction {
            deposit_wei: 0,
            ..sample_tempo_open()
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
    assert!(matches!(
        TempoSessionVoucher {
            channel_id_hex: "0x1234".to_string(),
            ..sample_tempo_voucher()
        }
        .validate(),
        Err(DomainError::InvalidTypedDataDomain(_))
    ));
}

#[test]
fn typed_data_actions_reject_alloy_incompatible_addresses_without_panicking() {
    let invalid = EvmAddress::new_unchecked(format!("0x{}", "zz".repeat(20)));

    let permit = Permit2Permit {
        chain_id: 1,
        permit2_contract: invalid.clone(),
        token: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("token"),
        spender: "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("spender"),
        amount_wei: 123,
        expiration: 100,
        nonce: 7,
        sig_deadline: 200,
    };
    assert!(matches!(
        permit.validate(),
        Err(DomainError::InvalidAddress)
    ));
    assert!(matches!(
        permit.eip712_domain(),
        Err(DomainError::InvalidAddress)
    ));
    assert!(matches!(
        permit.signing_hash(),
        Err(DomainError::InvalidAddress)
    ));

    let authorization = Eip3009Transfer {
        chain_id: 1,
        token: invalid.clone(),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4444444444444444444444444444444444444444"
            .parse()
            .expect("from"),
        to: "0x5555555555555555555555555555555555555555"
            .parse()
            .expect("to"),
        amount_wei: 456,
        valid_after: 10,
        valid_before: 20,
        nonce_hex: format!("0x{}", hex::encode([0xabu8; 32])),
    };
    assert!(matches!(
        authorization.validate(),
        Err(DomainError::InvalidAddress)
    ));
    assert!(matches!(
        authorization.eip712_domain(),
        Err(DomainError::InvalidAddress)
    ));
    assert!(matches!(
        authorization.transfer_signing_hash(),
        Err(DomainError::InvalidAddress)
    ));
    assert!(matches!(
        authorization.receive_signing_hash(),
        Err(DomainError::InvalidAddress)
    ));
}

#[test]
fn broadcast_tx_validation_covers_remaining_error_paths() {
    let base_tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xf0109fc8df283027b6285cc889f5aa624eac1f55"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    assert!(matches!(
        BroadcastTx {
            chain_id: 0,
            ..base_tx.clone()
        }
        .validate(),
        Err(DomainError::InvalidChainId)
    ));
    assert!(matches!(
        BroadcastTx {
            gas_limit: 0,
            ..base_tx.clone()
        }
        .validate(),
        Err(DomainError::InvalidGasConfiguration)
    ));
    assert!(matches!(
        BroadcastTx {
            max_priority_fee_per_gas_wei: 2_000_000_000,
            ..base_tx.clone()
        }
        .validate(),
        Err(DomainError::InvalidGasConfiguration)
    ));
    assert!(matches!(
        BroadcastTx {
            gas_limit: u64::MAX,
            max_fee_per_gas_wei: u128::MAX,
            ..base_tx.clone()
        }
        .validate(),
        Err(DomainError::InvalidGasConfiguration)
    ));
    assert!(matches!(
        base_tx
            .clone()
            .eip1559_signed_raw_transaction(2, [0u8; 32], [0u8; 32]),
        Err(DomainError::InvalidSignatureParity)
    ));
    assert!(matches!(
        BroadcastTx {
            tx_type: EIP7702_TX_TYPE,
            ..base_tx
        }
        .eip1559_signed_raw_transaction(1, [0u8; 32], [0u8; 32]),
        Err(DomainError::UnsupportedTransactionType(_))
    ));
}

#[test]
fn agent_action_helpers_cover_remaining_variants_and_none_paths() {
    let approve = AgentAction::Approve {
        chain_id: 1,
        token: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("token"),
        spender: "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("spender"),
        amount_wei: 12,
    };
    assert_eq!(
        approve.recipient(),
        "0x2222222222222222222222222222222222222222"
            .parse::<EvmAddress>()
            .expect("spender")
    );
    assert_eq!(approve.max_fee_per_gas_wei(), None);
    assert_eq!(approve.max_priority_fee_per_gas_wei(), None);
    assert_eq!(approve.calldata_len_bytes(), None);
    assert_eq!(approve.signing_hash().expect("non-typed action"), None);

    let receive_authorization = Eip3009Transfer {
        chain_id: 1,
        token: "0x3333333333333333333333333333333333333333"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4444444444444444444444444444444444444444"
            .parse()
            .expect("from"),
        to: "0x5555555555555555555555555555555555555555"
            .parse()
            .expect("to"),
        amount_wei: 34,
        valid_after: future_unix_timestamp(time::Duration::minutes(5)),
        valid_before: future_unix_timestamp(time::Duration::minutes(10)),
        nonce_hex: format!("0x{}", hex::encode([0xceu8; 32])),
    };
    let receive = AgentAction::Eip3009ReceiveWithAuthorization {
        authorization: receive_authorization,
    };
    assert_eq!(
        receive.asset(),
        AssetId::Erc20(
            "0x3333333333333333333333333333333333333333"
                .parse()
                .expect("token")
        )
    );
    assert_eq!(
        receive.recipient(),
        "0x5555555555555555555555555555555555555555"
            .parse::<EvmAddress>()
            .expect("to")
    );

    assert!(matches!(
        AgentAction::TransferNative {
            chain_id: 1,
            to: "0x6666666666666666666666666666666666666666"
                .parse()
                .expect("to"),
            amount_wei: 0,
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
    assert!(matches!(
        AgentAction::TransferNative {
            chain_id: 0,
            to: "0x6666666666666666666666666666666666666666"
                .parse()
                .expect("to"),
            amount_wei: 1,
        }
        .validate(),
        Err(DomainError::InvalidChainId)
    ));
}

#[test]
fn action_from_erc20_calldata_covers_transfer_and_zero_chain_guard() {
    let to = alloy_primitives::Address::from([0x11; 20]);
    let calldata = transferCall {
        to,
        value: U256::from(42_u64),
    }
    .abi_encode();
    let token: EvmAddress = "0x3333333333333333333333333333333333333333"
        .parse()
        .expect("token");

    assert!(matches!(
        action_from_erc20_calldata(0, token.clone(), &calldata),
        Err(DomainError::InvalidChainId)
    ));
    assert_eq!(
        action_from_erc20_calldata(1, token.clone(), &calldata).expect("transfer action"),
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("to"),
            amount_wei: 42,
        }
    );
}

#[test]
fn broadcast_action_derives_approve_and_receive_with_authorization_scope() {
    let approve_calldata = approveCall {
        spender: alloy_primitives::Address::from([0x77; 20]),
        value: U256::from(88_u64),
    }
    .abi_encode();
    let approve_action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: "0x8888000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(approve_calldata)),
            gas_limit: 80_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    assert_eq!(
        approve_action.recipient(),
        "0x7777777777777777777777777777777777777777"
            .parse::<EvmAddress>()
            .expect("spender")
    );
    assert_eq!(approve_action.amount_wei(), 88);

    let receive_calldata = receiveWithAuthorizationCall {
        from: alloy_primitives::Address::from([0x11; 20]),
        to: alloy_primitives::Address::from([0x22; 20]),
        value: U256::from(99_u64),
        validAfter: U256::from(1_u64),
        validBefore: U256::from(2_u64),
        nonce: [0x44; 32].into(),
        signature: vec![0xaa, 0xbb].into(),
    }
    .abi_encode();
    let receive_action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: "0x9999000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(receive_calldata)),
            gas_limit: 90_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    assert_eq!(
        receive_action.recipient(),
        "0x2222222222222222222222222222222222222222"
            .parse::<EvmAddress>()
            .expect("recipient")
    );
    assert_eq!(receive_action.amount_wei(), 99);
}

#[test]
fn broadcast_tx_supports_long_rlp_payloads_and_rejects_out_of_range_token_amounts() {
    // A 68-byte ERC-20 transfer call exceeds the 55-byte RLP short-string
    // bound, exercising the long-form length prefix with recognized calldata.
    let long_calldata = transferCall {
        to: alloy_primitives::Address::from([0x33; 20]),
        value: U256::from(u128::MAX),
    }
    .abi_encode();
    assert!(long_calldata.len() > 55);
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: format!("0x{}", hex::encode(long_calldata)),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    let raw = tx
        .eip1559_signed_raw_transaction(1, [0x11; 32], [0x22; 32])
        .expect("long payload should encode");
    assert_eq!(raw.first().copied(), Some(0x02));

    let oversized_approve = approveCall {
        spender: alloy_primitives::Address::from([0x33; 20]),
        value: U256::from(u128::MAX) + U256::from(1u8),
    }
    .abi_encode();
    assert!(matches!(
        parse_erc20_call(&oversized_approve),
        Err(DomainError::AmountOutOfRange)
    ));

    let oversized_permit = permitCall {
        owner: alloy_primitives::Address::from([0x66; 20]),
        permitSingle: PermitSingle {
            details: PermitDetails {
                token: alloy_primitives::Address::from([0x44; 20]),
                amount: alloy_primitives::U160::MAX,
                expiration: alloy_primitives::aliases::U48::from_be_slice(
                    &100u64.to_be_bytes()[2..],
                ),
                nonce: alloy_primitives::aliases::U48::from_be_slice(&7u64.to_be_bytes()[2..]),
            },
            spender: alloy_primitives::Address::from([0x55; 20]),
            sigDeadline: U256::from(1234u64),
        },
        signature: vec![0x12, 0x34].into(),
    }
    .abi_encode();
    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: "0x9999000000000000000000000000000000000000"
                .parse()
                .expect("permit2 contract"),
            value_wei: 0,
            data_hex: format!("0x{}", hex::encode(oversized_permit)),
            gas_limit: 60_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    assert_eq!(action.asset(), AssetId::NativeEth);
}

#[test]
fn invalid_hex_payloads_are_rejected_for_transactions_and_typed_nonces() {
    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x123".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    assert!(matches!(
        tx.validate(),
        Err(DomainError::InvalidTransactionDataHex)
    ));

    let authorization = Eip3009Transfer {
        chain_id: 1,
        token: "0x3333333333333333333333333333333333333333"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4444444444444444444444444444444444444444"
            .parse()
            .expect("from"),
        to: "0x5555555555555555555555555555555555555555"
            .parse()
            .expect("to"),
        amount_wei: 456,
        valid_after: future_unix_timestamp(time::Duration::minutes(5)),
        valid_before: future_unix_timestamp(time::Duration::minutes(10)),
        nonce_hex: "0xzz".to_string(),
    };
    assert!(matches!(
        authorization.validate(),
        Err(DomainError::InvalidTypedDataDomain(_))
    ));
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

fn sample_railgun_address() -> RailgunAddress {
    "0zk1qyqqqqqdl645pcpreh6dga7xa0dfwx5ehmkmrkpaczj9cyqr0e0vchcaxfsa6au6f93dvr64skspz"
        .parse::<RailgunAddress>()
        .expect("valid railgun address")
}

#[test]
fn railgun_address_parser_validates_prefix_and_charset() {
    let valid = sample_railgun_address();
    assert!(valid.as_str().starts_with("0zk1"));

    assert!(matches!(
        "0xnot-a-railgun-address".parse::<RailgunAddress>(),
        Err(DomainError::InvalidRailgunAddress)
    ));
    assert!(matches!(
        "0zk1".parse::<RailgunAddress>(),
        Err(DomainError::InvalidRailgunAddress)
    ));
    assert!(matches!(
        "0zk1qyqqq!!!invalid-chars".parse::<RailgunAddress>(),
        Err(DomainError::InvalidRailgunAddress)
    ));

    // Characters outside the bech32 alphabet (`b`, `i`, `o`, `1`) and the
    // previously tolerated `_` are rejected even when otherwise well-formed.
    let canonical = sample_railgun_address().as_str().to_string();
    for forbidden in ['b', 'i', 'o', '1', '_', '-'] {
        let mut mutated = canonical.clone();
        mutated.replace_range(canonical.len() - 1.., &forbidden.to_string());
        assert!(
            matches!(
                mutated.parse::<RailgunAddress>(),
                Err(DomainError::InvalidRailgunAddress)
            ),
            "{forbidden:?} must be rejected"
        );
    }
}

#[test]
fn railgun_address_parser_normalizes_case_to_lowercase() {
    let canonical = sample_railgun_address();
    let upper = canonical.as_str().to_ascii_uppercase();
    assert_ne!(upper, canonical.as_str());

    let from_upper = upper
        .parse::<RailgunAddress>()
        .expect("upper-case input parses");
    assert_eq!(from_upper, canonical);
    assert_eq!(from_upper.as_str(), canonical.as_str());

    let mut mixed = String::new();
    for (index, ch) in canonical.as_str().chars().enumerate() {
        if index % 2 == 0 {
            mixed.extend(ch.to_uppercase());
        } else {
            mixed.push(ch);
        }
    }
    let from_mixed = format!("  {mixed}  ")
        .parse::<RailgunAddress>()
        .expect("mixed-case input with padding parses");
    assert_eq!(from_mixed, canonical);

    // Scope matching relies on one canonical spelling: both spellings must
    // deserialize to the same RecipientId.
    let recipient_upper: RecipientId =
        serde_json::from_value(serde_json::json!(upper)).expect("deserialize upper");
    assert_eq!(recipient_upper, RecipientId::Railgun(canonical));
}

#[test]
fn recipient_id_round_trips_railgun_variant_via_json() {
    let recipient: RecipientId = sample_railgun_address().into();
    let json = serde_json::to_string(&recipient).expect("serialize");
    let decoded: RecipientId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recipient, decoded);
}

#[test]
fn shield_action_reports_railgun_recipient_and_erc20_asset() {
    let token: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("token");
    let action = AgentAction::Shield {
        chain_id: 56,
        token: token.clone(),
        to_railgun_address: sample_railgun_address(),
        amount_wei: 1_000,
    };
    assert_eq!(action.amount_wei(), 1_000);
    assert_eq!(action.chain_id(), 56);
    assert_eq!(action.asset(), AssetId::Erc20(token));
    assert!(matches!(action.recipient(), RecipientId::Railgun(_)));
    assert_eq!(action.action_kind(), ActionKind::Shield);
    assert!(action.records_spend_event());
    action.validate().expect("shield is valid");
}

#[test]
fn unshield_action_uses_evm_recipient_and_unshield_kind() {
    let token: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("token");
    let to: EvmAddress = "0x2222222222222222222222222222222222222222"
        .parse()
        .expect("recipient");
    let action = AgentAction::Unshield {
        chain_id: 1,
        token,
        to: to.clone(),
        amount_wei: 500,
        via_broadcaster: false,
    };
    assert_eq!(action.recipient(), RecipientId::Evm(to));
    assert_eq!(action.action_kind(), ActionKind::Unshield);
}

#[test]
fn private_transfer_action_is_classified_as_private_transfer_kind() {
    let token: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("token");
    let action = AgentAction::PrivateTransfer {
        chain_id: 137,
        token,
        to_railgun_address: sample_railgun_address(),
        amount_wei: 42,
        via_broadcaster: true,
    };
    assert_eq!(action.action_kind(), ActionKind::PrivateTransfer);
    assert!(matches!(action.recipient(), RecipientId::Railgun(_)));
}

#[test]
fn shield_action_rejects_zero_amount() {
    let token: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("token");
    let action = AgentAction::Shield {
        chain_id: 1,
        token,
        to_railgun_address: sample_railgun_address(),
        amount_wei: 0,
    };
    assert!(matches!(action.validate(), Err(DomainError::InvalidAmount)));
}

#[test]
fn shield_action_rejects_zero_chain_id() {
    let token: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("token");
    let action = AgentAction::Shield {
        chain_id: 0,
        token,
        to_railgun_address: sample_railgun_address(),
        amount_wei: 1,
    };
    assert!(matches!(
        action.validate(),
        Err(DomainError::InvalidChainId)
    ));
}

#[test]
fn railgun_domain_types_round_trip_via_json() {
    use crate::railgun::{
        RailgunDecryptedNote, RailgunMerklePath, RailgunNoteCiphertext, RailgunNoteInput,
        RailgunNullifier, RailgunTreeNumber, RailgunViewingPublicKeys, RailgunWitnessBundle,
    };

    let token: EvmAddress = "0x1111111111111111111111111111111111111111"
        .parse()
        .expect("token");

    let note = RailgunNoteInput {
        chain_id: 56,
        tree_number: RailgunTreeNumber::Utxo,
        leaf_index: 42,
        commitment_hex: "00".repeat(32),
        random_hex: "11".repeat(32),
        token: token.clone(),
        value_wei: 1_000,
    };
    let decoded: RailgunNoteInput =
        serde_json::from_str(&serde_json::to_string(&note).expect("ser")).expect("de");
    assert_eq!(note, decoded);

    let ciphertext = RailgunNoteCiphertext {
        ephemeral_pubkey_hex: "22".repeat(32),
        iv_hex: "33".repeat(16),
        tag_hex: "44".repeat(16),
        data_chunks_hex: vec!["55".repeat(32), "66".repeat(32), "77".repeat(32)],
    };
    let decoded: RailgunNoteCiphertext =
        serde_json::from_str(&serde_json::to_string(&ciphertext).expect("ser")).expect("de");
    assert_eq!(ciphertext, decoded);

    let decrypted = RailgunDecryptedNote {
        chunks_hex: vec!["88".repeat(32), "99".repeat(32), "aa".repeat(32)],
    };
    let decoded: RailgunDecryptedNote =
        serde_json::from_str(&serde_json::to_string(&decrypted).expect("ser")).expect("de");
    assert_eq!(decrypted, decoded);

    let pubkeys = RailgunViewingPublicKeys {
        viewing_pubkey_hex: "77".repeat(32),
        master_pubkey_hex: "88".repeat(32),
    };
    let decoded: RailgunViewingPublicKeys =
        serde_json::from_str(&serde_json::to_string(&pubkeys).expect("ser")).expect("de");
    assert_eq!(pubkeys, decoded);

    let path = RailgunMerklePath {
        tree_number: RailgunTreeNumber::LegacyUtxo,
        leaf_index: 42,
        path_elements_hex: vec!["aa".repeat(32), "bb".repeat(32)],
        root_hex: "cc".repeat(32),
    };
    let decoded: RailgunMerklePath =
        serde_json::from_str(&serde_json::to_string(&path).expect("ser")).expect("de");
    assert_eq!(path, decoded);

    let bundle = RailgunWitnessBundle {
        nullifiers_hex: vec!["dd".repeat(32)],
        spending_signatures_hex: vec!["ee".repeat(64)],
        spend_authority_pubkey_hex: "ff".repeat(32),
    };
    let decoded: RailgunWitnessBundle =
        serde_json::from_str(&serde_json::to_string(&bundle).expect("ser")).expect("de");
    assert_eq!(bundle, decoded);

    let nullifier = RailgunNullifier {
        nullifier_hex: "01".repeat(32),
    };
    let decoded: RailgunNullifier =
        serde_json::from_str(&serde_json::to_string(&nullifier).expect("ser")).expect("de");
    assert_eq!(nullifier, decoded);
}

#[test]
fn key_algorithm_serializes_railgun_variants_in_snake_case() {
    let spending: KeyAlgorithm = serde_json::from_str("\"railgun_spending\"").expect("de");
    assert_eq!(spending, KeyAlgorithm::RailgunSpending);
    assert_eq!(
        serde_json::to_string(&KeyAlgorithm::RailgunSpending).expect("ser"),
        "\"railgun_spending\"",
    );

    let viewing: KeyAlgorithm = serde_json::from_str("\"railgun_viewing\"").expect("de");
    assert_eq!(viewing, KeyAlgorithm::RailgunViewing);
    assert_eq!(
        serde_json::to_string(&KeyAlgorithm::RailgunViewing).expect("ser"),
        "\"railgun_viewing\"",
    );
}

#[test]
fn spend_event_default_action_kind_is_other_for_legacy_payloads() {
    let original = SpendEvent {
        agent_key_id: Uuid::nil(),
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: RecipientId::Evm(
            "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("addr"),
        ),
        amount_wei: 1,
        at: OffsetDateTime::UNIX_EPOCH,
        action_kind: ActionKind::Shield,
    };
    let mut value =
        serde_json::to_value(&original).expect("serialize spend event for legacy round-trip");
    // Drop the action_kind field to simulate persisted state from before the
    // Railgun migration. Deserialization must default it to `Other` instead
    // of failing.
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("action_kind");
    }
    let legacy: SpendEvent =
        serde_json::from_value(value).expect("legacy spend event deserialises");
    assert_eq!(legacy.action_kind, ActionKind::Other);
}

#[derive(Debug, Deserialize)]
struct TempoVectorFile {
    vectors: Vec<TempoVector>,
}

#[derive(Debug, Deserialize)]
struct TempoVector {
    name: String,
    open: TempoSessionOpenTransaction,
    top_up: TempoSessionTopUpTransaction,
    voucher: TempoSessionVoucher,
    expected: TempoVectorExpected,
}

#[derive(Debug, Deserialize)]
struct TempoVectorCall {
    to: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct TempoVectorExpected {
    channel_id_hex: String,
    open_calls: Vec<TempoVectorCall>,
    top_up_calls: Vec<TempoVectorCall>,
    open_signing_hash_hex: String,
    top_up_signing_hash_hex: String,
    voucher_signing_hash_hex: String,
}

fn load_tempo_vectors() -> Vec<TempoVector> {
    let raw = include_str!("../tests/fixtures/tempo_session_vectors.json");
    serde_json::from_str::<TempoVectorFile>(raw)
        .expect("tempo fixture parses")
        .vectors
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn sample_tempo_vector() -> TempoVector {
    load_tempo_vectors()
        .into_iter()
        .find(|vector| vector.name == "4217-unsponsored-expiring-nonce")
        .expect("sample vector")
}

fn sample_tempo_open() -> TempoSessionOpenTransaction {
    sample_tempo_vector().open
}

fn sample_tempo_top_up() -> TempoSessionTopUpTransaction {
    sample_tempo_vector().top_up
}

fn sample_tempo_voucher() -> TempoSessionVoucher {
    sample_tempo_vector().voucher
}

#[test]
fn tempo_session_digests_match_viem_reference_vectors() {
    let vectors = load_tempo_vectors();
    assert_eq!(vectors.len(), 8, "2 chains x 2 fee modes x 2 nonce modes");
    for vector in vectors {
        let name = &vector.name;
        assert_eq!(
            hex0x(&vector.open.channel_id().expect("channel id")),
            vector.expected.channel_id_hex,
            "{name}: channel id"
        );
        let open_calls = vector.open.encoded_calls().expect("open calls");
        assert_eq!(open_calls.len(), vector.expected.open_calls.len(), "{name}");
        for ((to, data), expected) in open_calls.iter().zip(&vector.expected.open_calls) {
            assert_eq!(to.as_str(), expected.to, "{name}: open call target");
            assert_eq!(hex0x(data), expected.data, "{name}: open calldata");
        }
        let top_up_calls = vector.top_up.encoded_calls().expect("topUp calls");
        for ((to, data), expected) in top_up_calls.iter().zip(&vector.expected.top_up_calls) {
            assert_eq!(to.as_str(), expected.to, "{name}: topUp call target");
            assert_eq!(hex0x(data), expected.data, "{name}: topUp calldata");
        }
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
    }
}

#[test]
fn tempo_session_rejects_unpinned_escrow_and_unsupported_chain() {
    let wrong_escrow: EvmAddress = "0x3333333333333333333333333333333333333333"
        .parse()
        .expect("escrow");
    assert!(matches!(
        TempoSessionOpenTransaction {
            escrow_contract: wrong_escrow.clone(),
            ..sample_tempo_open()
        }
        .signing_hash(),
        Err(DomainError::InvalidTempoEscrowContract)
    ));
    assert!(matches!(
        TempoSessionVoucher {
            escrow_contract: wrong_escrow,
            ..sample_tempo_voucher()
        }
        .signing_hash(),
        Err(DomainError::InvalidTempoEscrowContract)
    ));
    // Mainnet escrow on the testnet chain id is still rejected.
    assert!(matches!(
        TempoSessionTopUpTransaction {
            chain_id: TEMPO_TESTNET_CHAIN_ID,
            ..sample_tempo_top_up()
        }
        .validate(),
        Err(DomainError::InvalidTempoEscrowContract)
    ));
    assert!(matches!(
        TempoSessionOpenTransaction {
            chain_id: 1,
            ..sample_tempo_open()
        }
        .validate(),
        Err(DomainError::UnsupportedTempoChain(1))
    ));
}

#[test]
fn tempo_session_rejects_channel_id_that_does_not_match_fields() {
    let other_recipient: EvmAddress = "0x8888888888888888888888888888888888888888"
        .parse()
        .expect("recipient");
    // Claimed channel id stays the same while the payee is swapped: the
    // recomputed id no longer matches, so the voucher cannot be mislabeled.
    assert!(matches!(
        TempoSessionVoucher {
            recipient: other_recipient.clone(),
            ..sample_tempo_voucher()
        }
        .signing_hash(),
        Err(DomainError::TempoChannelIdMismatch)
    ));
    assert!(matches!(
        TempoSessionTopUpTransaction {
            recipient: other_recipient,
            ..sample_tempo_top_up()
        }
        .signing_hash(),
        Err(DomainError::TempoChannelIdMismatch)
    ));
    assert!(matches!(
        TempoSessionTopUpTransaction {
            channel_id_hex: format!("0x{}", hex::encode([0x55u8; 32])),
            ..sample_tempo_top_up()
        }
        .validate(),
        Err(DomainError::TempoChannelIdMismatch)
    ));
}

#[test]
fn tempo_session_rejects_foreign_authorized_signer_and_bad_params() {
    let open = sample_tempo_open();
    assert!(matches!(
        TempoSessionOpenTransaction {
            authorized_signer: "0x9999999999999999999999999999999999999999"
                .parse()
                .expect("signer"),
            ..open.clone()
        }
        .validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
    assert!(matches!(
        TempoSessionOpenTransaction {
            salt_hex: "0x12".to_string(),
            ..open.clone()
        }
        .validate(),
        Err(DomainError::InvalidTypedDataDomain(_))
    ));
    let mut tx = open.tx.clone();
    tx.max_priority_fee_per_gas_wei = tx.max_fee_per_gas_wei + 1;
    assert!(matches!(
        TempoSessionOpenTransaction { tx, ..open.clone() }.validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
    let mut tx = open.tx.clone();
    tx.fee_payer = true;
    assert!(
        matches!(
            TempoSessionOpenTransaction { tx, ..open.clone() }.validate(),
            Err(DomainError::InvalidTempoTransactionParams(_))
        ),
        "sponsored transactions must not name a fee token"
    );
    let mut tx = open.tx.clone();
    tx.nonce_key = Some("not-a-number".to_string());
    assert!(matches!(
        TempoSessionOpenTransaction { tx, ..open.clone() }.validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
    let mut tx = open.tx.clone();
    tx.valid_before = Some(0);
    assert!(matches!(
        TempoSessionOpenTransaction { tx, ..open }.validate(),
        Err(DomainError::InvalidTempoTransactionParams(_))
    ));
    assert!(matches!(
        TempoSessionVoucher {
            cumulative_amount_wei: 0,
            ..sample_tempo_voucher()
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
    assert!(matches!(
        TempoSessionTopUpTransaction {
            additional_deposit_wei: 0,
            ..sample_tempo_top_up()
        }
        .validate(),
        Err(DomainError::InvalidAmount)
    ));
}

#[test]
fn tempo_session_sponsored_and_unsponsored_digests_differ() {
    let open = sample_tempo_open();
    let mut sponsored_tx = open.tx.clone();
    sponsored_tx.fee_payer = true;
    sponsored_tx.fee_token = None;
    let sponsored = TempoSessionOpenTransaction {
        tx: sponsored_tx,
        ..open.clone()
    };
    assert_ne!(
        open.signing_hash().expect("unsponsored"),
        sponsored.signing_hash().expect("sponsored")
    );
}

#[test]
fn tempo_session_digest_binds_every_policy_field() {
    let open = sample_tempo_open();
    let base = open.signing_hash().expect("digest");
    assert_ne!(
        TempoSessionOpenTransaction {
            deposit_wei: open.deposit_wei + 1,
            ..open.clone()
        }
        .signing_hash()
        .expect("digest"),
        base
    );
    assert_ne!(
        TempoSessionOpenTransaction {
            recipient: "0x8888888888888888888888888888888888888888"
                .parse()
                .expect("recipient"),
            ..open.clone()
        }
        .signing_hash()
        .expect("digest"),
        base
    );
    assert_ne!(
        TempoSessionOpenTransaction {
            token: "0x20c0000000000000000000000000000000000002"
                .parse()
                .expect("token"),
            ..open.clone()
        }
        .signing_hash()
        .expect("digest"),
        base
    );
}

#[test]
fn tempo_session_policy_semantics() {
    let open = AgentAction::TempoSessionOpenTransaction {
        authorization: sample_tempo_open(),
    };
    let top_up = AgentAction::TempoSessionTopUpTransaction {
        authorization: sample_tempo_top_up(),
    };
    let voucher_auth = sample_tempo_voucher();
    let cumulative = voucher_auth.cumulative_amount_wei;
    let voucher = AgentAction::TempoSessionVoucher {
        authorization: voucher_auth,
    };
    assert_eq!(open.amount_wei(), 2_500_000);
    assert_eq!(top_up.amount_wei(), 750_000);
    assert_eq!(voucher.amount_wei(), cumulative);
    assert!(open.records_spend_event());
    assert!(top_up.records_spend_event());
    assert!(!voucher.records_spend_event());
    assert!(voucher.is_escrow_redistribution());
    assert!(!open.is_escrow_redistribution());
}
