//! Manual approval: a held durable nonce transfer is stored and resumed with
//! the exact same action, by resending the call or through `ResumeApproved`.

use agentpay_api::payments::{SolanaTransferOptions, SolanaTxStatus};
use agentpay_api::WireDaemonError;
use agentpay_domain::{AgentAction, ManualApprovalDecision};
use solana_sdk::pubkey::Pubkey;

use super::*;
use crate::features::solana::resume_approved;
use crate::signer::testing::manual_approval;

fn price_of(action: &AgentAction) -> Option<u64> {
    match action {
        AgentAction::SolanaSolTransfer { transfer } => transfer.compute_unit_price_micro_lamports,
        _ => None,
    }
}

#[tokio::test]
async fn resending_the_same_call_resumes_the_stored_action() {
    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    let nonce = h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let to = Pubkey::new_unique();

    let first = pending(h.sol(to, lamports(500), broadcast()).await);
    assert_eq!(first.method, "TransferSol");
    assert_eq!(first.network.as_deref(), Some("solana-devnet"));
    assert_eq!(first.chain_id, SOLANA_DEVNET_CHAIN_ID);
    assert_eq!(price_of(&first.action), Some(2_000));
    let AgentAction::SolanaSolTransfer { transfer } = &first.action else {
        panic!("a SOL transfer action");
    };
    assert_eq!(transfer.recent_blockhash, nonce.to_string());
    assert!(h.cluster.sent().is_empty());

    // The fee estimate changes, yet the resent call is the same approval.
    h.cluster.with(|s| s.prioritization_fees = vec![9_000]);
    let again = pending(h.sol(to, lamports(500), broadcast()).await);
    assert_eq!(again.approval_request_id, first.approval_request_id);
    assert_eq!(again.action, first.action);

    h.decide(first.approval_request_id, ManualApprovalDecision::Approve)
        .await;
    let result = done(h.sol(to, lamports(500), broadcast()).await);
    assert_eq!(result.compute_unit_price_micro_lamports, Some(2_000));
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Finalized)
    );
    assert_eq!(h.cluster.sent().len(), 1);
    assert!(h
        .provider()
        .pending
        .find(h.auth.agent_key_id, first.approval_request_id)
        .await
        .is_none());
}

#[tokio::test]
async fn resume_approved_finishes_the_call_as_it_was_asked() {
    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let held = pending(
        h.sol(Pubkey::new_unique(), lamports(500), broadcast())
            .await,
    );
    let agent = h.agent().await;

    assert!(
        resume_approved(&h.state, &agent, Uuid::new_v4(), None)
            .await
            .is_none(),
        "unknown ids are left to other method families"
    );
    let still = resume_approved(&h.state, &agent, held.approval_request_id, None)
        .await
        .expect("a Solana approval");
    assert_eq!(pending(still).approval_request_id, held.approval_request_id);

    h.decide(held.approval_request_id, ManualApprovalDecision::Approve)
        .await;
    let result = done(
        resume_approved(&h.state, &agent, held.approval_request_id, None)
            .await
            .expect("a Solana approval"),
    );
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Finalized)
    );
    assert!(
        resume_approved(&h.state, &agent, held.approval_request_id, None)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn a_rejected_transfer_is_forgotten() {
    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let to = Pubkey::new_unique();
    let held = pending(h.sol(to, lamports(500), broadcast()).await);
    h.decide(held.approval_request_id, ManualApprovalDecision::Reject)
        .await;
    let err = h
        .sol(to, lamports(500), broadcast())
        .await
        .expect_err("rejected");
    assert!(
        matches!(
            err,
            PaymentsError::Signer(WireDaemonError::ManualApprovalRejected { .. })
        ),
        "{err:?}"
    );
    assert!(h
        .provider()
        .pending
        .find(h.auth.agent_key_id, held.approval_request_id)
        .await
        .is_none());
    assert!(h.cluster.sent().is_empty());
}

#[tokio::test]
async fn an_advanced_nonce_makes_the_stored_action_stale() {
    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let to = Pubkey::new_unique();
    let held = pending(h.sol(to, lamports(500), broadcast()).await);
    let agent = h.agent().await;

    // Something else advanced the nonce account.
    h.cluster.advance_nonce(&h.managed_nonce());

    let err = resume_approved(&h.state, &agent, held.approval_request_id, None)
        .await
        .expect("a Solana approval")
        .expect_err("stale");
    assert!(matches!(err, PaymentsError::InvalidRequest(ref r) if r.contains("advanced")));

    // Resending the call builds a new action on the new nonce: a new approval.
    let fresh = pending(h.sol(to, lamports(500), broadcast()).await);
    assert_ne!(fresh.approval_request_id, held.approval_request_id);
}

#[tokio::test]
async fn blockhash_transfers_cannot_wait_for_approval() {
    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    let err = h
        .sol(
            Pubkey::new_unique(),
            lamports(500),
            SolanaTransferOptions::default(),
        )
        .await
        .expect_err("signerd refuses");
    assert!(matches!(err, PaymentsError::Signer(_)), "{err:?}");
    assert!(h.cluster.sent().is_empty());
}

#[tokio::test]
async fn a_short_wait_completes_when_the_operator_approves_in_time() {
    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let daemon = h.signer.daemon.clone();
    let approver = tokio::spawn(async move {
        loop {
            let requests = daemon
                .list_manual_approval_requests(&AdminAuth::PeerCredentials)
                .await
                .expect("list");
            if let Some(request) = requests.first() {
                daemon
                    .decide_manual_approval_request(
                        &AdminAuth::PeerCredentials,
                        request.id,
                        ManualApprovalDecision::Approve,
                        None,
                    )
                    .await
                    .expect("approve");
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    });
    let options = SolanaTransferOptions {
        approval_wait_secs: Some(5),
        ..broadcast()
    };
    let result = done(h.sol(Pubkey::new_unique(), lamports(500), options).await);
    approver.await.expect("approver");
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Finalized)
    );
}

#[tokio::test]
async fn the_resume_approved_method_routes_solana_approvals_here() {
    use agentpay_api::payments::ResumeApprovedParams;

    let h = Harness::new(vec![manual_approval(1, 1_000_000)]).await;
    h.cluster.add_nonce_account(h.managed_nonce(), h.wallet);
    let held = pending(
        h.sol(Pubkey::new_unique(), lamports(500), broadcast())
            .await,
    );
    h.decide(held.approval_request_id, ManualApprovalDecision::Approve)
        .await;
    let resume = |approval_request_id| {
        PaymentsRpcRequest::ResumeApproved(ResumeApprovedParams {
            auth: h.auth.clone(),
            approval_request_id,
            approval_wait_secs: None,
        })
    };
    let result = done(dispatch(&h.state, resume(held.approval_request_id)).await);
    assert_eq!(
        result.broadcast.map(|b| b.status),
        Some(SolanaTxStatus::Finalized)
    );

    // Ids that are not Solana approvals fall through to the EVM store.
    let unknown = Uuid::new_v4();
    assert_eq!(
        dispatch(&h.state, resume(unknown)).await,
        Err(PaymentsError::UnknownPendingApproval(unknown))
    );
}
