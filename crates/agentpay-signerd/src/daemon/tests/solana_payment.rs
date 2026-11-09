//! `SolanaPaymentTransaction`: v0 payment transactions with splits, memos,
//! and a foreign fee payer, and how policies see them.

use agentpay_domain::{
    AdminAuth, AgentAction, AgentCredentials, AssetId, EntityScope, KeyAlgorithm,
    ManualApprovalDecision, ManualApprovalStatus, OverLimit, PolicyAttachment, PolicyType,
    RecipientId, Signature, SolanaPaymentAsset, SolanaPaymentLeg, SolanaPaymentTransaction,
    SolanaTokenProgram, SpendingPolicy, VaultKey, SOLANA_DEVNET_CHAIN_ID, SOLANA_POLICY_CHAIN_ID,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SignerError, SoftwareSignerBackend};
use solana_sdk::bs58;
use solana_sdk::message::VersionedMessage;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::VersionedTransaction;

use super::support::{
    policy_all_per_tx, sample_solana_sol_transfer_action, sample_solana_spl_transfer_action,
    sign_request,
};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// An instruction resolved against the message's account keys.
#[derive(Debug, PartialEq, Eq)]
struct Decoded {
    program: Pubkey,
    accounts: Vec<Pubkey>,
    data: Vec<u8>,
}

fn pk(value: &str) -> Pubkey {
    value.parse().expect("pubkey")
}

fn pk_of(byte: u8) -> Pubkey {
    Pubkey::new_from_array([byte; 32])
}

fn address(key: &Pubkey) -> agentpay_domain::SolanaAddress {
    key.to_string().parse().expect("solana address")
}

fn agent_pubkey(key: &VaultKey) -> Pubkey {
    let bytes = hex::decode(&key.public_key_hex).expect("ed25519 public key hex");
    Pubkey::new_from_array(<[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes"))
}

fn ata(owner: &Pubkey, mint: &Pubkey, program: &str) -> Pubkey {
    spl_associated_token_account::get_associated_token_address_with_program_id(
        owner,
        mint,
        &pk(program),
    )
}

fn leg(recipient: Pubkey, amount_wei: u128) -> SolanaPaymentLeg {
    SolanaPaymentLeg {
        recipient_owner: address(&recipient),
        amount_wei,
        create_ata: false,
        memo: None,
    }
}

fn payment(
    fee_payer: &Pubkey,
    asset: SolanaPaymentAsset,
    transfers: Vec<SolanaPaymentLeg>,
) -> SolanaPaymentTransaction {
    SolanaPaymentTransaction {
        chain_id: SOLANA_DEVNET_CHAIN_ID,
        recent_blockhash: bs58::encode([1u8; 32]).into_string(),
        fee_payer: address(fee_payer),
        asset,
        transfers,
        memo: Some("order-42".to_string()),
        compute_unit_limit: Some(50_000),
        compute_unit_price_micro_lamports: Some(7),
    }
}

fn spl_asset(mint: &Pubkey, token_program: SolanaTokenProgram) -> SolanaPaymentAsset {
    SolanaPaymentAsset::SplToken {
        mint: address(mint),
        decimals: 6,
        token_program,
    }
}

async fn solana_daemon(
    policies: Vec<SpendingPolicy>,
) -> (
    InMemoryDaemon<SoftwareSignerBackend>,
    AdminAuth,
    VaultKey,
    AgentCredentials,
) {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    for policy in policies {
        daemon
            .add_policy(&session, policy)
            .await
            .expect("add policy");
    }
    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    (daemon, session, key, credentials)
}

fn decode_transaction(signature: &Signature) -> VersionedTransaction {
    let raw = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        signature.raw_tx_base64.as_ref().expect("raw transaction"),
    )
    .expect("base64");
    bincode::deserialize(&raw).expect("versioned transaction")
}

fn decoded_instructions(tx: &VersionedTransaction) -> Vec<Decoded> {
    let VersionedMessage::V0(message) = &tx.message else {
        panic!("expected a v0 message, got {:?}", tx.message);
    };
    assert!(message.address_table_lookups.is_empty());
    message
        .instructions
        .iter()
        .map(|instruction| Decoded {
            program: message.account_keys[usize::from(instruction.program_id_index)],
            accounts: instruction
                .accounts
                .iter()
                .map(|index| message.account_keys[usize::from(*index)])
                .collect(),
            data: instruction.data.clone(),
        })
        .collect()
}

fn compute_unit_price(price: u64) -> Decoded {
    let mut data = vec![3u8];
    data.extend_from_slice(&price.to_le_bytes());
    Decoded {
        program: pk(COMPUTE_BUDGET_PROGRAM),
        accounts: vec![],
        data,
    }
}

fn compute_unit_limit(limit: u32) -> Decoded {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    Decoded {
        program: pk(COMPUTE_BUDGET_PROGRAM),
        accounts: vec![],
        data,
    }
}

fn system_transfer(from: Pubkey, to: Pubkey, lamports: u64) -> Decoded {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Decoded {
        program: pk(SYSTEM_PROGRAM),
        accounts: vec![from, to],
        data,
    }
}

fn transfer_checked(
    program: &str,
    authority: Pubkey,
    mint: Pubkey,
    recipient: Pubkey,
    amount: u64,
) -> Decoded {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6);
    Decoded {
        program: pk(program),
        accounts: vec![
            ata(&authority, &mint, program),
            mint,
            ata(&recipient, &mint, program),
            authority,
        ],
        data,
    }
}

fn memo(text: &str) -> Decoded {
    Decoded {
        program: pk(MEMO_PROGRAM),
        accounts: vec![],
        data: text.as_bytes().to_vec(),
    }
}

fn create_ata_idempotent(payer: Pubkey, wallet: Pubkey, mint: Pubkey, program: &str) -> Decoded {
    Decoded {
        program: pk(ATA_PROGRAM),
        accounts: vec![
            payer,
            ata(&wallet, &mint, program),
            wallet,
            mint,
            pk(SYSTEM_PROGRAM),
            pk(program),
        ],
        data: vec![1],
    }
}

fn assert_signed_by(tx: &VersionedTransaction, signer: &Pubkey, signature: &Signature) {
    let index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| key == signer)
        .expect("signer is an account");
    assert!(index < usize::from(tx.message.header().num_required_signatures));
    let tx_signature = tx.signatures[index];
    assert!(tx_signature.verify(signer.as_ref(), &tx.message.serialize()));
    assert_eq!(tx_signature.as_ref(), signature.bytes.as_slice());
    assert_eq!(
        signature.signature_base58.as_deref(),
        Some(tx_signature.to_string().as_str())
    );
}

#[tokio::test]
async fn sol_payment_with_agent_fee_payer_is_fully_signed_in_reference_order() {
    let (daemon, _, key, credentials) = solana_daemon(vec![policy_all_per_tx(10_000)]).await;
    let agent = agent_pubkey(&key);
    let (primary, split_a, split_b) = (pk_of(9), pk_of(10), pk_of(11));
    let mut sol = payment(
        &agent,
        SolanaPaymentAsset::NativeSol,
        vec![leg(primary, 5_000), leg(split_a, 300), leg(split_b, 2)],
    );
    sol.transfers[1].memo = Some("platform".to_string());

    let signature = daemon
        .sign_for_agent(sign_request(
            &credentials,
            AgentAction::SolanaPaymentTransaction { payment: sol },
        ))
        .await
        .expect("sol payment signs");
    let tx = decode_transaction(&signature);

    assert_eq!(
        decoded_instructions(&tx),
        vec![
            compute_unit_price(7),
            compute_unit_limit(50_000),
            system_transfer(agent, primary, 5_000),
            memo("order-42"),
            system_transfer(agent, split_a, 300),
            memo("platform"),
            system_transfer(agent, split_b, 2),
        ]
    );
    assert_eq!(tx.message.static_account_keys()[0], agent);
    assert_eq!(tx.message.header().num_required_signatures, 1);
    assert_eq!(tx.signatures.len(), 1);
    assert_eq!(
        tx.message.recent_blockhash().to_bytes(),
        [1u8; 32],
        "the payment's blockhash"
    );
    assert_signed_by(&tx, &agent, &signature);
    assert_eq!(signature.tx_id, signature.signature_base58);
    assert!(tx.verify_with_results().iter().all(|valid| *valid));
}

#[tokio::test]
async fn spl_payment_with_foreign_fee_payer_is_partially_signed() {
    let (daemon, _, key, credentials) = solana_daemon(vec![policy_all_per_tx(10_000)]).await;
    let agent = agent_pubkey(&key);
    let (fee_payer, mint, primary, split) = (pk_of(5), pk_of(7), pk_of(9), pk_of(10));
    let mut spl = payment(
        &fee_payer,
        spl_asset(&mint, SolanaTokenProgram::Token),
        vec![leg(primary, 1_000), leg(split, 25)],
    );
    spl.transfers[1].create_ata = true;
    spl.transfers[1].memo = Some("split memo".to_string());

    let signature = daemon
        .sign_for_agent(sign_request(
            &credentials,
            AgentAction::SolanaPaymentTransaction { payment: spl },
        ))
        .await
        .expect("spl payment signs");
    let tx = decode_transaction(&signature);

    assert_eq!(
        decoded_instructions(&tx),
        vec![
            compute_unit_price(7),
            compute_unit_limit(50_000),
            transfer_checked(TOKEN_PROGRAM, agent, mint, primary, 1_000),
            memo("order-42"),
            create_ata_idempotent(fee_payer, split, mint, TOKEN_PROGRAM),
            transfer_checked(TOKEN_PROGRAM, agent, mint, split, 25),
            memo("split memo"),
        ]
    );
    assert_eq!(tx.message.static_account_keys()[0], fee_payer);
    assert_eq!(tx.message.header().num_required_signatures, 2);
    assert_eq!(tx.signatures.len(), 2);
    assert_eq!(
        tx.signatures[0],
        solana_sdk::signature::Signature::default(),
        "the fee payer's slot stays empty"
    );
    assert_signed_by(&tx, &agent, &signature);
    assert_eq!(signature.tx_id, None);
}

#[tokio::test]
async fn token_2022_payment_uses_token_2022_accounts_and_no_memo_when_unset() {
    let (daemon, _, key, credentials) = solana_daemon(vec![policy_all_per_tx(10_000)]).await;
    let agent = agent_pubkey(&key);
    let (fee_payer, mint, primary, split) = (pk_of(5), pk_of(7), pk_of(9), pk_of(10));
    let mut spl = payment(
        &fee_payer,
        spl_asset(&mint, SolanaTokenProgram::Token2022),
        vec![leg(primary, 40), leg(split, 2)],
    );
    spl.transfers[1].create_ata = true;
    spl.memo = None;
    spl.compute_unit_limit = None;
    spl.compute_unit_price_micro_lamports = None;

    let signature = daemon
        .sign_for_agent(sign_request(
            &credentials,
            AgentAction::SolanaPaymentTransaction { payment: spl },
        ))
        .await
        .expect("token-2022 payment signs");
    let tx = decode_transaction(&signature);

    assert_eq!(
        decoded_instructions(&tx),
        vec![
            transfer_checked(TOKEN_2022_PROGRAM, agent, mint, primary, 40),
            create_ata_idempotent(fee_payer, split, mint, TOKEN_2022_PROGRAM),
            transfer_checked(TOKEN_2022_PROGRAM, agent, mint, split, 2),
        ]
    );
    assert_signed_by(&tx, &agent, &signature);
}

#[tokio::test]
async fn payment_records_the_sum_of_legs_as_one_spend() {
    let (daemon, _, key, credentials) = solana_daemon(vec![policy_all_per_tx(100)]).await;
    let mint = pk_of(7);
    let primary = pk_of(9);
    let action = AgentAction::SolanaPaymentTransaction {
        payment: payment(
            &pk_of(5),
            spl_asset(&mint, SolanaTokenProgram::Token),
            vec![leg(primary, 60), leg(pk_of(10), 40)],
        ),
    };
    daemon
        .sign_for_agent(sign_request(&credentials, action))
        .await
        .expect("a total at the per-payment limit signs");

    {
        let spend_log = daemon.spend_log.read().expect("spend log");
        assert_eq!(spend_log.len(), 1);
        let event = &spend_log[0];
        assert_eq!(event.amount_wei, 100);
        assert_eq!(event.chain_id, SOLANA_POLICY_CHAIN_ID);
        assert_eq!(event.asset, AssetId::SplToken(address(&mint)));
        assert_eq!(event.recipient, RecipientId::Solana(address(&primary)));
        assert_eq!(event.approval_request_id, None);
    }

    let over = AgentAction::SolanaPaymentTransaction {
        payment: payment(
            &agent_pubkey(&key),
            spl_asset(&mint, SolanaTokenProgram::Token),
            vec![leg(primary, 60), leg(pk_of(10), 41)],
        ),
    };
    let err = daemon
        .sign_for_agent(sign_request(&credentials, over))
        .await
        .expect_err("a total above the per-payment limit is denied");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::PerTxLimitExceeded {
            max_amount_wei: 100,
            requested_amount_wei: 101,
            ..
        })
    ));
    assert_eq!(daemon.spend_log.read().expect("spend log").len(), 1);
}

#[tokio::test]
async fn payment_over_a_limit_waits_for_manual_approval() {
    let policy = policy_all_per_tx(100)
        .with_over_limit(OverLimit::ManualApproval)
        .expect("over-limit approval");
    let (daemon, session, key, credentials) = solana_daemon(vec![policy]).await;
    let primary = pk_of(9);
    let action = AgentAction::SolanaPaymentTransaction {
        payment: payment(
            &agent_pubkey(&key),
            SolanaPaymentAsset::NativeSol,
            vec![leg(primary, 100), leg(pk_of(10), 5)],
        ),
    };

    let approval_request_id = match daemon
        .sign_for_agent(sign_request(&credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
        }) => approval_request_id,
        other => panic!("expected a manual approval request, got {other:?}"),
    };
    {
        let requests = daemon.manual_approval_requests.read().expect("requests");
        let request = requests.get(&approval_request_id).expect("request");
        assert_eq!(request.amount_wei, 105);
        assert_eq!(request.asset, AssetId::NativeSol);
        assert_eq!(request.recipient, RecipientId::Solana(address(&primary)));
    }
    assert!(daemon.spend_log.read().expect("spend log").is_empty());

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve");
    let signature = daemon
        .sign_for_agent(sign_request(&credentials, action))
        .await
        .expect("the approved payment signs");
    assert!(signature.raw_tx_base64.is_some());

    let requests = daemon.manual_approval_requests.read().expect("requests");
    assert_eq!(
        requests
            .get(&approval_request_id)
            .expect("request retained")
            .status,
        ManualApprovalStatus::Completed
    );
    let spend_log = daemon.spend_log.read().expect("spend log");
    assert_eq!(spend_log.len(), 1);
    assert_eq!(spend_log[0].amount_wei, 105);
    assert_eq!(spend_log[0].approval_request_id, Some(approval_request_id));
}

#[tokio::test]
async fn payment_in_a_blocked_asset_is_denied() {
    let native_only = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::Set([AssetId::NativeSol].into()),
        EntityScope::All,
    )
    .expect("policy");
    let (daemon, _, key, credentials) = solana_daemon(vec![native_only]).await;
    let action = AgentAction::SolanaPaymentTransaction {
        payment: payment(
            &agent_pubkey(&key),
            spl_asset(&pk_of(7), SolanaTokenProgram::Token),
            vec![leg(pk_of(9), 1)],
        ),
    };
    let err = daemon
        .sign_for_agent(sign_request(&credentials, action))
        .await
        .expect_err("an SPL payment outside the asset scope is denied");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::NoApplicablePolicies)
    ));
    assert!(daemon.spend_log.read().expect("spend log").is_empty());
}

#[tokio::test]
async fn invalid_payments_are_rejected_before_policy_evaluation() {
    let (daemon, _, key, credentials) = solana_daemon(vec![policy_all_per_tx(1_000)]).await;
    let agent = agent_pubkey(&key);
    let mint = pk_of(7);

    let mut primary_ata = payment(
        &agent,
        spl_asset(&mint, SolanaTokenProgram::Token),
        vec![leg(pk_of(9), 1)],
    );
    primary_ata.transfers[0].create_ata = true;
    let mut ata_on_sol = payment(
        &agent,
        SolanaPaymentAsset::NativeSol,
        vec![leg(pk_of(9), 1), leg(pk_of(10), 1)],
    );
    ata_on_sol.transfers[1].create_ata = true;
    let mut zero = payment(
        &agent,
        SolanaPaymentAsset::NativeSol,
        vec![leg(pk_of(9), 1), leg(pk_of(10), 0)],
    );
    zero.memo = None;
    let ten_legs = payment(
        &agent,
        SolanaPaymentAsset::NativeSol,
        (0..10).map(|_| leg(pk_of(9), 1)).collect(),
    );
    let mut long_memo = payment(
        &agent,
        SolanaPaymentAsset::NativeSol,
        vec![leg(pk_of(9), 1)],
    );
    long_memo.memo = Some("m".repeat(567));

    for invalid in [primary_ata, ata_on_sol, zero, ten_legs, long_memo] {
        let err = daemon
            .sign_for_agent(sign_request(
                &credentials,
                AgentAction::SolanaPaymentTransaction { payment: invalid },
            ))
            .await
            .expect_err("invalid payment is rejected");
        assert!(
            matches!(err, DaemonError::InvalidAction(_)),
            "unexpected error {err:?}"
        );
    }
    assert!(daemon.spend_log.read().expect("spend log").is_empty());
}

#[tokio::test]
async fn transfer_actions_still_reject_a_foreign_fee_payer() {
    let (daemon, _, key, credentials) = solana_daemon(vec![policy_all_per_tx(1_000)]).await;
    let foreign = address(&pk_of(5));

    let mut spl = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut spl {
        transfer.fee_payer = foreign.clone();
    }
    let mut sol = sample_solana_sol_transfer_action(&key);
    if let AgentAction::SolanaSolTransfer { transfer } = &mut sol {
        transfer.fee_payer = foreign;
    }

    for action in [spl, sol] {
        let err = daemon
            .sign_for_agent(sign_request(&credentials, action))
            .await
            .expect_err("foreign fee payer is rejected");
        assert!(
            matches!(
                &err,
                DaemonError::Signer(SignerError::Unsupported(message))
                    if message.contains("fee payer must match")
            ),
            "unexpected error {err:?}"
        );
    }
}
