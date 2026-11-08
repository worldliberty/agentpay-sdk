//! Solana transfer and durable-nonce signing.

use agentpay_domain::{
    AdminAuth, AgentAction, EntityScope, KeyAlgorithm, ManualApprovalDecision,
    ManualApprovalStatus, PolicyAttachment, Signature, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SignerError, SoftwareSignerBackend};
use solana_sdk::bs58;

use super::support::{
    policy_all_per_tx, sample_solana_nonce_account_create_action,
    sample_solana_sol_transfer_action, sample_solana_spl_transfer_action, sign_request,
};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

fn assert_solana_transaction_starts_with_nonce_advance(signature: &Signature) {
    let raw_tx_base64 = signature
        .raw_tx_base64
        .as_ref()
        .expect("signed solana transaction");
    let raw_tx = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw_tx_base64)
        .expect("decode raw solana tx");
    let tx: solana_sdk::transaction::Transaction =
        bincode::deserialize(&raw_tx).expect("deserialize solana tx");
    let first_instruction = tx
        .message
        .instructions
        .first()
        .expect("nonce advance instruction");
    assert_eq!(first_instruction.data, 4u32.to_le_bytes());
    let program_id = tx.message.account_keys[first_instruction.program_id_index as usize];
    assert_eq!(program_id.to_string(), "11111111111111111111111111111111");
}

fn assert_solana_nonce_account_create_transaction(signature: &Signature) {
    let raw_tx_base64 = signature
        .raw_tx_base64
        .as_ref()
        .expect("signed solana transaction");
    let raw_tx = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, raw_tx_base64)
        .expect("decode raw solana tx");
    let tx: solana_sdk::transaction::Transaction =
        bincode::deserialize(&raw_tx).expect("deserialize solana tx");
    assert_eq!(tx.message.instructions.len(), 2);

    let create_instruction = &tx.message.instructions[0];
    let initialize_instruction = &tx.message.instructions[1];
    assert_eq!(
        &create_instruction.data[..4],
        &3u32.to_le_bytes(),
        "first instruction must be SystemProgram::CreateAccountWithSeed"
    );
    assert_eq!(
        &initialize_instruction.data[..4],
        &6u32.to_le_bytes(),
        "second instruction must be SystemProgram::InitializeNonceAccount"
    );
    for instruction in [create_instruction, initialize_instruction] {
        let program_id = tx.message.account_keys[instruction.program_id_index as usize];
        assert_eq!(program_id.to_string(), "11111111111111111111111111111111");
    }
}

#[tokio::test]
async fn solana_nonce_account_create_bypasses_manual_approval_and_spend_log() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let signature = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_solana_nonce_account_create_action(&key),
        ))
        .await
        .expect("nonce account creation should sign without manual approval");

    assert!(!signature.bytes.is_empty());
    assert_solana_nonce_account_create_transaction(&signature);
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests")
            .is_empty(),
        "internal nonce setup must not enqueue manual approval requests"
    );
    assert!(
        daemon.spend_log.read().expect("spend log").is_empty(),
        "internal nonce setup must not count as user spend"
    );
}

#[tokio::test]
async fn solana_spl_transfer_manual_approval_requires_managed_durable_nonce_setup() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_solana_spl_transfer_action(&key),
        ))
        .await
        .expect_err("direct solana manual approval without nonce setup should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Unsupported(message))
            if message.contains("solana manual approval requires AgentPay-managed durable nonce setup")
    ));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests")
            .is_empty(),
        "direct solana manual-approval attempts without nonce setup must not enqueue requests"
    );
}

#[tokio::test]
async fn solana_spl_transfer_manual_approval_signs_with_durable_nonce() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut action = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut action {
        transfer.durable_nonce_account = Some(
            bs58::encode([3u8; 32])
                .into_string()
                .parse()
                .expect("durable nonce account"),
        );
    }
    let approval_request_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected solana manual approval request, got {other:?}"),
    };
    assert_eq!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests")
            .len(),
        1
    );

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve solana request");

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect("approved solana transfer should sign with durable nonce");
    assert!(!signature.bytes.is_empty());
    assert_solana_transaction_starts_with_nonce_advance(&signature);

    let requests = daemon.manual_approval_requests.read().expect("requests");
    let request = requests
        .get(&approval_request_id)
        .expect("approval request retained");
    assert_eq!(request.status, ManualApprovalStatus::Completed);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn solana_sol_transfer_manual_approval_signs_with_durable_nonce() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut action = sample_solana_sol_transfer_action(&key);
    if let AgentAction::SolanaSolTransfer { transfer } = &mut action {
        transfer.durable_nonce_account = Some(
            bs58::encode([3u8; 32])
                .into_string()
                .parse()
                .expect("durable nonce account"),
        );
    }
    let approval_request_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected solana manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve solana request");

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect("approved solana transfer should sign with durable nonce");
    assert!(!signature.bytes.is_empty());
    assert_solana_transaction_starts_with_nonce_advance(&signature);

    let requests = daemon.manual_approval_requests.read().expect("requests");
    let request = requests
        .get(&approval_request_id)
        .expect("approval request retained");
    assert_eq!(request.status, ManualApprovalStatus::Completed);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn solana_spl_transfer_respects_per_tx_spending_policy() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(10))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut allowed_action = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut allowed_action {
        transfer.amount_wei = 5;
    }
    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, allowed_action))
        .await
        .expect("solana action within per-tx limit should sign");
    assert!(!signature.bytes.is_empty());

    let mut denied_action = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut denied_action {
        transfer.amount_wei = 11;
    }
    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, denied_action))
        .await
        .expect_err("solana action above per-tx limit should be denied");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::PerTxLimitExceeded {
            max_amount_wei: 10,
            requested_amount_wei: 11,
            ..
        })
    ));
}
