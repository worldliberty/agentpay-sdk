//! [`verify`] against transactions signed by a real in-memory signer
//! daemon: the exact request passes, every deviation is refused.

use agentpay_domain::{
    AgentAction, SolanaNonceAccountCreate, SolanaSolTransfer, SolanaSplTransfer,
    SolanaTokenProgram, SOLANA_DEVNET_CHAIN_ID,
};
use base64::Engine as _;
use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;

use super::accounts::{associated_token_account, managed_nonce_account, token_program_id};
use super::budget::ComputeBudget;
use super::verify::{verify, Expected, ExpectedOperation};
use crate::error::PaymentsError;
use crate::signer::testing::{per_tx_limit, InProcessSigner};
use crate::signer::{AgentSigner, ApprovalWait};

const BLOCKHASH: Hash = Hash::new_from_array([7; 32]);

struct Fixture {
    signer: InProcessSigner,
    auth: agentpay_api::AgentAuth,
    wallet: Pubkey,
}

impl Fixture {
    async fn new() -> Self {
        let (signer, auth) =
            InProcessSigner::with_agent(vec![per_tx_limit(u128::from(u64::MAX))]).await;
        let identity = AgentSigner::new(&signer, &auth)
            .identity()
            .await
            .expect("identity");
        let wallet = identity
            .solana_address
            .expect("software keys sign for Solana")
            .to_string()
            .parse()
            .expect("pubkey");
        Self {
            signer,
            auth,
            wallet,
        }
    }

    async fn sign(&self, action: AgentAction) -> String {
        AgentSigner::new(&self.signer, &self.auth)
            .sign(action, ApprovalWait::none())
            .await
            .expect("signed")
            .raw_tx_base64
            .expect("raw transaction")
    }

    fn sol(
        &self,
        to: Pubkey,
        lamports: u128,
        nonce: Option<Pubkey>,
        budget: ComputeBudget,
    ) -> AgentAction {
        AgentAction::SolanaSolTransfer {
            transfer: SolanaSolTransfer {
                chain_id: SOLANA_DEVNET_CHAIN_ID,
                recent_blockhash: BLOCKHASH.to_string(),
                durable_nonce_account: nonce.map(|n| n.to_string().parse().expect("address")),
                fee_payer: self.wallet.to_string().parse().expect("address"),
                to: to.to_string().parse().expect("address"),
                amount_wei: lamports,
                compute_unit_limit: budget.unit_limit,
                compute_unit_price_micro_lamports: budget.unit_price,
            },
        }
    }

    fn expected_sol(
        &self,
        to: Pubkey,
        lamports: u64,
        nonce: Option<Pubkey>,
        budget: ComputeBudget,
    ) -> Expected {
        Expected {
            fee_payer: self.wallet,
            recent_blockhash: BLOCKHASH,
            durable_nonce_account: nonce,
            compute_budget: budget,
            operation: ExpectedOperation::SolTransfer { to, lamports },
        }
    }
}

fn budget(unit_limit: u32, unit_price: Option<u64>) -> ComputeBudget {
    ComputeBudget {
        unit_limit: Some(unit_limit),
        unit_price,
    }
}

fn mismatch(result: Result<impl std::fmt::Debug, PaymentsError>) -> String {
    match result {
        Err(PaymentsError::SignedTransactionMismatch(reason)) => reason,
        other => panic!("expected SignedTransactionMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn the_exact_sol_transfer_verifies() {
    let f = Fixture::new().await;
    let (to, nonce) = (Pubkey::new_unique(), Pubkey::new_unique());
    let b = budget(5_000, Some(2_000));
    let raw = f.sign(f.sol(to, 1_500_000, Some(nonce), b)).await;
    let verified = verify(&raw, &f.expected_sol(to, 1_500_000, Some(nonce), b)).expect("verified");
    assert_eq!(verified.compute_budget, b);
    assert_eq!(verified.transaction.message.account_keys[0], f.wallet);
}

#[tokio::test]
async fn any_deviation_from_the_sol_request_is_refused() {
    let f = Fixture::new().await;
    let (to, nonce) = (Pubkey::new_unique(), Pubkey::new_unique());
    let b = budget(5_000, None);
    let raw = f.sign(f.sol(to, 1_500_000, Some(nonce), b)).await;
    let cases = [
        (
            f.expected_sol(to, 1_400_000, Some(nonce), b),
            "SOL amount 1500000 lamports",
        ),
        (
            f.expected_sol(Pubkey::new_unique(), 1_500_000, Some(nonce), b),
            "SOL transfer recipient",
        ),
        (
            f.expected_sol(to, 1_500_000, Some(Pubkey::new_unique()), b),
            "durable nonce account",
        ),
        (
            f.expected_sol(to, 1_500_000, None, b),
            "no nonce account was requested",
        ),
        (
            f.expected_sol(to, 1_500_000, Some(nonce), budget(6_000, None)),
            "compute budget",
        ),
        (
            Expected {
                recent_blockhash: Hash::new_unique(),
                ..f.expected_sol(to, 1_500_000, Some(nonce), b)
            },
            "recent blockhash",
        ),
        (
            Expected {
                fee_payer: Pubkey::new_unique(),
                ..f.expected_sol(to, 1_500_000, Some(nonce), b)
            },
            "fee payer",
        ),
    ];
    for (expected, needle) in cases {
        let reason = mismatch(verify(&raw, &expected));
        assert!(
            reason.contains(needle),
            "{reason:?} should mention {needle:?}"
        );
        assert!(
            !reason.contains(&to.to_string()),
            "addresses stay out of errors"
        );
    }

    // A transaction without the nonce advance when one was requested.
    let plain = f.sign(f.sol(to, 1_500_000, None, b)).await;
    let reason = mismatch(verify(
        &plain,
        &f.expected_sol(to, 1_500_000, Some(nonce), b),
    ));
    assert!(
        reason.contains("missing the expected durable nonce advance"),
        "{reason}"
    );

    // A token transfer where SOL was expected.
    let mint = Pubkey::new_unique();
    let spl = f.sign(spl_action(&f, mint, to, None)).await;
    let reason = mismatch(verify(
        &spl,
        &f.expected_sol(to, 1_500_000, None, budget(20_000, None)),
    ));
    assert!(reason.contains("unexpected program"), "{reason}");
}

#[tokio::test]
async fn broken_encodings_and_signatures_are_refused() {
    let f = Fixture::new().await;
    let to = Pubkey::new_unique();
    let b = budget(5_000, None);
    let expected = f.expected_sol(to, 10, None, b);
    let raw = f.sign(f.sol(to, 10, None, b)).await;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(&raw)
        .expect("base64");

    assert!(mismatch(verify("not base64!", &expected)).contains("base64"));
    let mut trailing = bytes.clone();
    trailing.push(0);
    let trailing = base64::engine::general_purpose::STANDARD.encode(trailing);
    assert!(mismatch(verify(&trailing, &expected)).contains("non-canonical"));

    // Flip one bit of the signature (byte 1 is its first byte).
    bytes[1] ^= 1;
    let forged = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(mismatch(verify(&forged, &expected)).contains("signature does not verify"));
}

#[tokio::test]
async fn priority_fees_above_the_caps_are_refused_even_when_requested() {
    let f = Fixture::new().await;
    let to = Pubkey::new_unique();
    let expensive = budget(1_400_000, Some(10_000_000));
    let raw = f.sign(f.sol(to, 10, None, expensive)).await;
    let reason = mismatch(verify(&raw, &f.expected_sol(to, 10, None, expensive)));
    assert!(reason.contains("priority fee"), "{reason}");
}

fn spl_action(f: &Fixture, mint: Pubkey, owner: Pubkey, fee: Option<u128>) -> AgentAction {
    AgentAction::SolanaSplTransfer {
        transfer: SolanaSplTransfer {
            chain_id: SOLANA_DEVNET_CHAIN_ID,
            recent_blockhash: BLOCKHASH.to_string(),
            durable_nonce_account: None,
            fee_payer: f.wallet.to_string().parse().expect("address"),
            mint: mint.to_string().parse().expect("address"),
            recipient_owner: owner.to_string().parse().expect("address"),
            amount_wei: 1_000_000,
            decimals: 6,
            token_program: if fee.is_some() {
                SolanaTokenProgram::Token2022
            } else {
                SolanaTokenProgram::Token
            },
            transfer_fee_wei: fee,
            compute_unit_limit: Some(20_000),
            compute_unit_price_micro_lamports: None,
        },
    }
}

fn expected_spl(
    f: &Fixture,
    mint: Pubkey,
    owner: Pubkey,
    program: SolanaTokenProgram,
    fee: Option<u64>,
) -> Expected {
    let program = token_program_id(program);
    Expected {
        fee_payer: f.wallet,
        recent_blockhash: BLOCKHASH,
        durable_nonce_account: None,
        compute_budget: budget(20_000, None),
        operation: ExpectedOperation::SplTransfer {
            program,
            mint,
            source: associated_token_account(&f.wallet, &mint, &program),
            destination: associated_token_account(&owner, &mint, &program),
            amount: 1_000_000,
            decimals: 6,
            fee,
        },
    }
}

#[tokio::test]
async fn token_transfers_check_accounts_amount_decimals_and_fee() {
    let f = Fixture::new().await;
    let (mint, owner) = (Pubkey::new_unique(), Pubkey::new_unique());
    let classic = f.sign(spl_action(&f, mint, owner, None)).await;
    verify(
        &classic,
        &expected_spl(&f, mint, owner, SolanaTokenProgram::Token, None),
    )
    .expect("ok");
    let reason = mismatch(verify(
        &classic,
        &expected_spl(
            &f,
            mint,
            Pubkey::new_unique(),
            SolanaTokenProgram::Token,
            None,
        ),
    ));
    assert!(reason.contains("destination token account"), "{reason}");
    let reason = mismatch(verify(
        &classic,
        &expected_spl(&f, mint, owner, SolanaTokenProgram::Token, Some(1)),
    ));
    assert!(
        reason.contains("transfer fee none does not match expected 1"),
        "{reason}"
    );
    let reason = mismatch(verify(
        &classic,
        &expected_spl(&f, mint, owner, SolanaTokenProgram::Token2022, None),
    ));
    assert!(reason.contains("program does not match"), "{reason}");
    let mut wrong_decimals = expected_spl(&f, mint, owner, SolanaTokenProgram::Token, None);
    if let ExpectedOperation::SplTransfer { decimals, .. } = &mut wrong_decimals.operation {
        *decimals = 9;
    }
    assert!(mismatch(verify(&classic, &wrong_decimals)).contains("token decimals 6"));

    let with_fee = f.sign(spl_action(&f, mint, owner, Some(10_000))).await;
    verify(
        &with_fee,
        &expected_spl(&f, mint, owner, SolanaTokenProgram::Token2022, Some(10_000)),
    )
    .expect("fee transfer");
    let reason = mismatch(verify(
        &with_fee,
        &expected_spl(&f, mint, owner, SolanaTokenProgram::Token2022, Some(9_999)),
    ));
    assert!(
        reason.contains("transfer fee 10000 does not match expected 9999"),
        "{reason}"
    );
    let reason = mismatch(verify(
        &with_fee,
        &expected_spl(&f, mint, owner, SolanaTokenProgram::Token2022, None),
    ));
    assert!(
        reason.contains("includes a transfer fee but none was expected"),
        "{reason}"
    );
}

#[tokio::test]
async fn nonce_account_creation_must_match_exactly() {
    let f = Fixture::new().await;
    let managed = managed_nonce_account(&f.wallet, SOLANA_DEVNET_CHAIN_ID).expect("derive");
    let action = AgentAction::SolanaNonceAccountCreate {
        create: SolanaNonceAccountCreate {
            chain_id: SOLANA_DEVNET_CHAIN_ID,
            recent_blockhash: BLOCKHASH.to_string(),
            fee_payer: f.wallet.to_string().parse().expect("address"),
            nonce_account: managed.address.to_string().parse().expect("address"),
            seed: managed.seed.clone(),
            rent_lamports: 1_447_680,
        },
    };
    let raw = f.sign(action).await;
    let expected = |rent_lamports| Expected {
        fee_payer: f.wallet,
        recent_blockhash: BLOCKHASH,
        durable_nonce_account: None,
        compute_budget: ComputeBudget {
            unit_limit: None,
            unit_price: None,
        },
        operation: ExpectedOperation::NonceAccountCreate {
            nonce_account: managed.address,
            seed: managed.seed.clone(),
            rent_lamports,
        },
    };
    verify(&raw, &expected(1_447_680)).expect("creation verifies");
    assert!(mismatch(verify(&raw, &expected(1))).contains("seed, rent, or size"));

    let to = Pubkey::new_unique();
    let transfer = f.sign(f.sol(to, 10, None, budget(5_000, Some(1)))).await;
    assert!(mismatch(verify(&transfer, &expected(1_447_680))).contains("exactly the two"));
}
