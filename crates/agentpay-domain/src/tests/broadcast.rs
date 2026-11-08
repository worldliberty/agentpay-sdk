use super::*;

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

/// Calldata must be the canonical ABI encoding: no trailing bytes and no dirty
/// padding in address words. Pins the strict decoder across alloy upgrades.
#[test]
fn parse_erc20_call_rejects_non_canonical_calldata() {
    let calldata = transferCall {
        to: alloy_primitives::Address::from([0x11; 20]),
        value: U256::from(42_u64),
    }
    .abi_encode();

    let mut trailing = calldata.clone();
    trailing.push(0x00);
    parse_erc20_call(&trailing).expect_err("trailing bytes must fail");

    let mut dirty_address = calldata.clone();
    // Byte 4 starts the first argument word; an address uses only its last 20 bytes.
    dirty_address[4] = 0x01;
    parse_erc20_call(&dirty_address).expect_err("dirty address padding must fail");

    parse_erc20_call(&calldata[..calldata.len() - 1]).expect_err("truncated calldata must fail");
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
fn broadcast_action_derives_tip20_transfer_with_memo_scope_from_calldata() {
    let token: EvmAddress = "0x20c0000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0xffffffffffffffffffffffffffffffffffffffff"
        .parse()
        .expect("recipient");
    let calldata = transferWithMemoCall {
        to: alloy_primitives::Address::from([0xff; 20]),
        amount: U256::from(250_000u64),
        memo: [0x42; 32].into(),
    }
    .abi_encode();
    let mut tx = broadcast_tx_with_calldata(hex0x(&calldata), 0);
    tx.to = token.clone();
    let action = AgentAction::BroadcastTx { tx: tx.clone() };
    action
        .validate()
        .expect("transferWithMemo is a recognized token call");
    assert_eq!(action.asset(), AssetId::Erc20(token));
    assert_eq!(action.recipient(), recipient);
    assert_eq!(action.amount_wei(), 250_000);

    // A memo transfer with native value or a truncated memo is refused.
    let mut valued = tx.clone();
    valued.value_wei = 1;
    assert!(valued.validate().is_err());
    let truncated = broadcast_tx_with_calldata(hex0x(&calldata[..calldata.len() - 1]), 0);
    assert!(truncated.validate().is_err());
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
