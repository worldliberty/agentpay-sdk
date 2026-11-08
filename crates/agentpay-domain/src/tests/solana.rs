use super::*;

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
