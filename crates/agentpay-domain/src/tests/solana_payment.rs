use super::*;

const MINT: &str = "So11111111111111111111111111111111111111112";
const PRIMARY: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPLIT: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

fn leg(recipient: &str, amount_wei: u128) -> SolanaPaymentLeg {
    SolanaPaymentLeg {
        recipient_owner: recipient.parse().expect("recipient"),
        amount_wei,
        create_ata: false,
        memo: None,
    }
}

fn spl_payment() -> SolanaPaymentTransaction {
    SolanaPaymentTransaction {
        chain_id: SOLANA_DEVNET_CHAIN_ID,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
        fee_payer: "11111111111111111111111111111111"
            .parse()
            .expect("fee payer"),
        asset: SolanaPaymentAsset::SplToken {
            mint: MINT.parse().expect("mint"),
            decimals: 6,
            token_program: SolanaTokenProgram::Token2022,
        },
        transfers: vec![
            leg(PRIMARY, 1_000),
            SolanaPaymentLeg {
                create_ata: true,
                memo: Some("platform fee".to_string()),
                ..leg(SPLIT, 50)
            },
        ],
        memo: Some("order-42".to_string()),
        compute_unit_limit: Some(200_000),
        compute_unit_price_micro_lamports: Some(1),
    }
}

fn sol_payment() -> SolanaPaymentTransaction {
    SolanaPaymentTransaction {
        asset: SolanaPaymentAsset::NativeSol,
        transfers: vec![leg(PRIMARY, 5_000), leg(SPLIT, 7)],
        ..spl_payment()
    }
}

fn invalid_reason(payment: SolanaPaymentTransaction) -> DomainError {
    let action = AgentAction::SolanaPaymentTransaction { payment };
    action.validate().expect_err("payment must be rejected")
}

#[test]
fn solana_payment_projects_sum_of_legs_onto_the_policy_network() {
    let payment = spl_payment();
    let action = AgentAction::SolanaPaymentTransaction {
        payment: payment.clone(),
    };

    action.validate().expect("spl payment validates");
    assert_eq!(action.amount_wei(), 1_050);
    assert_eq!(action.chain_id(), SOLANA_POLICY_CHAIN_ID);
    assert_eq!(
        action.asset(),
        AssetId::SplToken(MINT.parse().expect("mint"))
    );
    assert_eq!(
        action.recipient(),
        RecipientId::Solana(PRIMARY.parse().expect("primary"))
    );
    assert_eq!(
        action.recipients(),
        vec![
            RecipientId::Solana(PRIMARY.parse().expect("primary")),
            RecipientId::Solana(SPLIT.parse().expect("split")),
        ]
    );
    assert!(action.records_spend_event());
    assert!(!action.is_escrow_redistribution());
    assert!(!action.is_wallet_maintenance());
    assert!(action.signing_hash().expect("no digest").is_none());

    let sol = AgentAction::SolanaPaymentTransaction {
        payment: sol_payment(),
    };
    sol.validate().expect("sol payment validates");
    assert_eq!(sol.asset(), AssetId::NativeSol);
    assert_eq!(sol.amount_wei(), 5_007);
}

#[test]
fn single_recipient_actions_report_one_recipient() {
    let action = AgentAction::TransferNative {
        chain_id: 1,
        to: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        amount_wei: 1,
    };
    assert_eq!(action.recipients(), vec![action.recipient()]);
}

#[test]
fn solana_payment_json_shape() {
    let action = AgentAction::SolanaPaymentTransaction {
        payment: spl_payment(),
    };
    let json = serde_json::to_value(&action).expect("serialize");
    assert_eq!(
        json,
        serde_json::json!({
            "kind": "SolanaPaymentTransaction",
            "payment": {
                "chain_id": 900000002,
                "recent_blockhash": "11111111111111111111111111111111",
                "fee_payer": "11111111111111111111111111111111",
                "asset": {
                    "kind": "spl_token",
                    "mint": MINT,
                    "decimals": 6,
                    "token_program": "token2022"
                },
                "transfers": [
                    {"recipient_owner": PRIMARY, "amount_wei": "1000", "create_ata": false},
                    {
                        "recipient_owner": SPLIT,
                        "amount_wei": "50",
                        "create_ata": true,
                        "memo": "platform fee"
                    }
                ],
                "memo": "order-42",
                "compute_unit_limit": 200000,
                "compute_unit_price_micro_lamports": 1
            }
        })
    );
    let decoded: AgentAction = serde_json::from_value(json).expect("deserialize");
    assert_eq!(decoded, action);

    let sol: AgentAction = serde_json::from_value(serde_json::json!({
        "kind": "SolanaPaymentTransaction",
        "payment": {
            "chain_id": 900000001,
            "recent_blockhash": "11111111111111111111111111111111",
            "fee_payer": "11111111111111111111111111111111",
            "asset": {"kind": "native_sol"},
            "transfers": [{"recipient_owner": PRIMARY, "amount_wei": "1"}]
        }
    }))
    .expect("minimal sol payment");
    sol.validate().expect("minimal sol payment validates");
}

#[test]
fn solana_payment_rejects_invalid_legs() {
    let mut zero = spl_payment();
    zero.transfers[1].amount_wei = 0;
    assert!(matches!(invalid_reason(zero), DomainError::InvalidAmount));

    let mut no_legs = spl_payment();
    no_legs.transfers.clear();
    assert!(matches!(
        invalid_reason(no_legs),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut nine = sol_payment();
    nine.transfers = (0..SOLANA_PAYMENT_MAX_LEGS)
        .map(|_| leg(SPLIT, 1))
        .collect();
    nine.validate().expect("nine legs are allowed");
    let mut ten = nine.clone();
    ten.transfers.push(leg(SPLIT, 1));
    assert!(matches!(
        invalid_reason(ten),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut ata_on_sol = sol_payment();
    ata_on_sol.transfers[1].create_ata = true;
    assert!(matches!(
        invalid_reason(ata_on_sol),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut primary_ata = spl_payment();
    primary_ata.transfers[0].create_ata = true;
    assert!(matches!(
        invalid_reason(primary_ata),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut primary_leg_memo = spl_payment();
    primary_leg_memo.transfers[0].memo = Some("x".to_string());
    assert!(matches!(
        invalid_reason(primary_leg_memo),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut overflow = sol_payment();
    overflow.transfers = vec![leg(PRIMARY, u128::from(u64::MAX)), leg(SPLIT, 1)];
    assert!(matches!(
        invalid_reason(overflow),
        DomainError::AmountOutOfRange
    ));

    let mut too_large = sol_payment();
    too_large.transfers[0].amount_wei = u128::from(u64::MAX) + 1;
    assert!(matches!(
        invalid_reason(too_large),
        DomainError::AmountOutOfRange
    ));
}

#[test]
fn solana_payment_bounds_memos_and_compute_budget() {
    let mut at_limit = spl_payment();
    at_limit.memo = Some("é".repeat(SOLANA_PAYMENT_MAX_MEMO_BYTES / 2));
    at_limit.transfers[1].memo = Some("m".repeat(SOLANA_PAYMENT_MAX_MEMO_BYTES));
    at_limit.validate().expect("566-byte memos are allowed");

    let mut long_memo = spl_payment();
    long_memo.memo = Some("m".repeat(SOLANA_PAYMENT_MAX_MEMO_BYTES + 1));
    assert!(matches!(
        invalid_reason(long_memo),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut long_split_memo = spl_payment();
    // 2-byte characters: 284 of them are 568 bytes.
    long_split_memo.transfers[1].memo = Some("é".repeat(284));
    assert!(matches!(
        invalid_reason(long_split_memo),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut empty_memo = spl_payment();
    empty_memo.memo = Some(String::new());
    assert!(matches!(
        invalid_reason(empty_memo),
        DomainError::InvalidSolanaPaymentTransaction(_)
    ));

    let mut high_limit = spl_payment();
    high_limit.compute_unit_limit = Some(SOLANA_PAYMENT_MAX_COMPUTE_UNIT_LIMIT + 1);
    assert!(matches!(
        invalid_reason(high_limit),
        DomainError::InvalidSolanaComputeBudget
    ));

    let mut zero_price = spl_payment();
    zero_price.compute_unit_price_micro_lamports = Some(0);
    assert!(matches!(
        invalid_reason(zero_price),
        DomainError::InvalidSolanaComputeBudget
    ));

    let mut evm_chain = spl_payment();
    evm_chain.chain_id = 1;
    assert!(matches!(
        invalid_reason(evm_chain),
        DomainError::InvalidChainId
    ));

    let mut bad_blockhash = spl_payment();
    bad_blockhash.recent_blockhash = "not-base58!".to_string();
    assert!(matches!(
        invalid_reason(bad_blockhash),
        DomainError::InvalidSolanaRecentBlockhash
    ));
}
