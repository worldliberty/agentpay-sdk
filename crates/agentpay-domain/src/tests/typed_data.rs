use super::*;

#[test]
fn eip3009_actions_produce_signing_hashes() {
    let valid_after = future_unix_timestamp(time::Duration::minutes(5));
    let valid_before = future_unix_timestamp(time::Duration::minutes(10));
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
    assert_ne!(transfer_hash, [0u8; 32]);
    assert_ne!(receive_hash, [0u8; 32]);
    assert_ne!(transfer_hash, receive_hash);
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
fn eip3009_validation_rejects_invalid_inputs() {
    let now = OffsetDateTime::now_utc();
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
}

#[test]
fn typed_data_actions_reject_alloy_incompatible_addresses_without_panicking() {
    let invalid = EvmAddress::new_unchecked(format!("0x{}", "zz".repeat(20)));

    let authorization = Eip3009Transfer {
        chain_id: 1,
        token: invalid,
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
