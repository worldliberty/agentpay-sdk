//! `TransferSpl`: SPL Token and Token-2022 (transfer fee, transfer hook),
//! associated token account checks, and broadcast.

use agentpay_api::payments::{
    SolanaAmount, SolanaTransferDetails, SolanaTransferOptions, SolanaTxStatus,
};
use agentpay_domain::SolanaTokenProgram;
use solana_sdk::pubkey::Pubkey;

use super::*;
use crate::chains::solana::accounts::{associated_token_account, system_program_id};

/// A mint of `program` with both associated token accounts in place.
fn funded_mint(h: &Harness, program: Pubkey, fee: Option<(u16, u64)>, to: &Pubkey) -> Pubkey {
    let mint = h.cluster.add_mint(program, 6, fee, false);
    h.cluster.add_token_account(&h.wallet, &mint, program);
    h.cluster.add_token_account(to, &mint, program);
    mint
}

#[tokio::test]
async fn a_classic_token_transfer_names_both_associated_token_accounts() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let mint = funded_mint(&h, spl_token::ID, None, &to);
    let result = done(
        h.spl(
            mint,
            to,
            SolanaAmount::Decimal("1.5".into()),
            SolanaTransferOptions::default(),
        )
        .await,
    );
    assert_eq!(
        result.transfer,
        SolanaTransferDetails::Spl {
            mint: address(&mint),
            recipient_owner: address(&to),
            source_token_account: address(&associated_token_account(
                &h.wallet,
                &mint,
                &spl_token::ID
            )),
            destination_token_account: address(&associated_token_account(
                &to,
                &mint,
                &spl_token::ID
            )),
            token_program: SolanaTokenProgram::Token,
            decimals: 6,
            amount_wei: 1_500_000,
            transfer_fee_wei: None,
        }
    );
    assert_eq!(result.compute_unit_limit, Some(20_000));
    let tx = decode(result.raw_tx_base64.as_deref().expect("raw"));
    assert!(tx.message.account_keys.contains(&spl_token::ID));
    assert_eq!(
        h.cluster.calls("getEpochInfo"),
        0,
        "no fee lookup without a fee config"
    );
}

#[tokio::test]
async fn token_2022_transfer_fees_use_transfer_checked_with_fee() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let program = spl_token_2022_interface::id();
    // 1% capped at 5,000 base units.
    let mint = funded_mint(&h, program, Some((100, 5_000)), &to);
    let small = done(
        h.spl(
            mint,
            to,
            lamports(100_000),
            SolanaTransferOptions::default(),
        )
        .await,
    );
    let SolanaTransferDetails::Spl {
        token_program,
        transfer_fee_wei,
        ..
    } = small.transfer
    else {
        panic!("spl details");
    };
    assert_eq!(token_program, SolanaTokenProgram::Token2022);
    assert_eq!(transfer_fee_wei, Some(1_000));
    let large = done(
        h.spl(
            mint,
            to,
            lamports(10_000_000),
            SolanaTransferOptions::default(),
        )
        .await,
    );
    assert!(matches!(
        large.transfer,
        SolanaTransferDetails::Spl {
            transfer_fee_wei: Some(5_000),
            ..
        }
    ));
    // TransferFeeExtension (26) / TransferCheckedWithFee (1).
    let tx = decode(large.raw_tx_base64.as_deref().expect("raw"));
    let transfer = tx.message.instructions.last().expect("transfer");
    assert_eq!(&transfer.data[..2], &[26, 1]);

    // A Token-2022 mint without extensions uses plain transfer_checked.
    let plain = funded_mint(&h, program, None, &to);
    let result = done(
        h.spl(plain, to, lamports(10), SolanaTransferOptions::default())
            .await,
    );
    assert!(matches!(
        result.transfer,
        SolanaTransferDetails::Spl {
            transfer_fee_wei: None,
            token_program: SolanaTokenProgram::Token2022,
            ..
        }
    ));
}

#[tokio::test]
async fn unsupported_mints_and_missing_token_accounts_are_refused() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let options = SolanaTransferOptions::default;

    let hooked = h
        .cluster
        .add_mint(spl_token_2022_interface::id(), 6, None, true);
    let reason = invalid(h.spl(hooked, to, lamports(1), options()).await);
    assert!(reason.contains("transfer hook"), "{reason}");

    let not_a_mint = Pubkey::new_unique();
    h.cluster
        .put_account(not_a_mint, system_program_id(), vec![0; 82]);
    let reason = invalid(h.spl(not_a_mint, to, lamports(1), options()).await);
    assert!(reason.contains("not owned by the SPL Token"), "{reason}");
    let reason = invalid(
        h.spl(Pubkey::new_unique(), to, lamports(1), options())
            .await,
    );
    assert!(reason.contains("mint account does not exist"), "{reason}");

    let mint = h.cluster.add_mint(spl_token::ID, 6, None, false);
    let reason = invalid(h.spl(mint, to, lamports(1), options()).await);
    assert!(
        reason.contains("the wallet's associated token account"),
        "{reason}"
    );
    h.cluster.add_token_account(&h.wallet, &mint, spl_token::ID);
    let reason = invalid(h.spl(mint, to, lamports(1), options()).await);
    assert!(
        reason.contains("the recipient's associated token account"),
        "{reason}"
    );
    assert!(reason.contains("create it before sending"), "{reason}");
    // Created as the wrong kind of account.
    let destination = associated_token_account(&to, &mint, &spl_token::ID);
    h.cluster
        .put_account(destination, system_program_id(), vec![0; 165]);
    let reason = invalid(h.spl(mint, to, lamports(1), options()).await);
    assert!(
        reason.contains("not owned by the mint's token program"),
        "{reason}"
    );

    h.cluster.add_token_account(&to, &mint, spl_token::ID);
    let reason = invalid(
        h.spl(
            mint,
            to,
            SolanaAmount::Decimal("0.0000001".into()),
            options(),
        )
        .await,
    );
    assert!(reason.contains("more than 6 decimal places"), "{reason}");
    assert!(h.cluster.sent().is_empty());
}

#[tokio::test]
async fn token_transfers_broadcast_with_the_managed_nonce() {
    let h = Harness::new(allow_all()).await;
    let to = Pubkey::new_unique();
    let mint = funded_mint(&h, spl_token::ID, None, &to);
    let result = done(h.spl(mint, to, lamports(7), broadcast()).await);
    assert_eq!(
        h.cluster.sent().len(),
        2,
        "nonce creation, then the transfer"
    );
    assert!(result.durable_nonce.is_some_and(|n| n.managed));
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Finalized)
    );
}
