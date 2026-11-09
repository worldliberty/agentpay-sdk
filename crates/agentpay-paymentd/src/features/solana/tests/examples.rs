//! The documented `TransferSol` / `TransferSpl` examples are consistent with
//! what the service derives: the managed nonce account and the associated
//! token accounts.

use std::path::Path;

use agentpay_api::payments::{PaymentsRpcResponse, SolanaTransferDetails, SolanaTransferResult};

use super::*;
use crate::chains::solana::accounts::{associated_token_account, token_program_id};
use crate::features::solana::pubkey;

fn example(name: &str) -> SolanaTransferResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/payments/solana")
        .join(name);
    let text = std::fs::read_to_string(&path).expect("example");
    match serde_json::from_str(&text).expect("response example") {
        PaymentsRpcResponse::SolanaTransfer(result) => result,
        other => panic!("{name} is not a SolanaTransfer response: {other:?}"),
    }
}

#[test]
fn the_sol_example_uses_the_wallets_managed_nonce_account() {
    let result = example("TransferSol.response.json");
    let wallet = pubkey(&result.fee_payer).expect("wallet");
    let managed = managed_nonce_account(&wallet, result.chain_id).expect("derive");
    let nonce = result.durable_nonce.expect("durable nonce");
    assert!(nonce.managed);
    assert_eq!(nonce.account, address(&managed.address));
}

#[test]
fn the_spl_example_names_the_derived_token_accounts() {
    let result = example("TransferSpl.response.json");
    let SolanaTransferDetails::Spl {
        mint,
        recipient_owner,
        source_token_account,
        destination_token_account,
        token_program,
        ..
    } = result.transfer
    else {
        panic!("an SPL example");
    };
    let program = token_program_id(token_program);
    let mint = pubkey(&mint).expect("mint");
    let wallet = pubkey(&result.fee_payer).expect("wallet");
    let owner = pubkey(&recipient_owner).expect("owner");
    assert_eq!(
        source_token_account,
        address(&associated_token_account(&wallet, &mint, &program))
    );
    assert_eq!(
        destination_token_account,
        address(&associated_token_account(&owner, &mint, &program))
    );
}
