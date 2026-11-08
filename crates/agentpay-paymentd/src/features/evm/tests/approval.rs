//! Manual approval: pending results, stored actions, `ResumeApproved`, and
//! waiting within one call.

use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use agentpay_api::payments::{
    EvmTxOptions, PaymentsRpcRequest as Req, PaymentsRpcResponse as Res, ResumeApprovedParams,
    SignTypedDataParams,
};
use agentpay_api::WireDaemonError;
use agentpay_domain::{AdminAuth, AgentAction, ManualApprovalDecision, PolicyAttachment};
use agentpay_signerd::KeyManagerDaemonApi;
use alloy_primitives::{Address, Signature, B256};
use uuid::Uuid;

use super::*;
use crate::features::evm::pending::PENDING_DIR_NAME;
use crate::signer::testing::manual_approval;

const TYPED_DATA: &str = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],"Note":[{"name":"text","type":"string"}]},"primaryType":"Note","domain":{"name":"Test","chainId":56},"message":{"text":"hello"}}"#;

fn resume(h: &Harness, id: Uuid) -> Req {
    Req::ResumeApproved(ResumeApprovedParams {
        auth: h.auth.clone(),
        approval_request_id: id,
        approval_wait_secs: None,
    })
}

async fn decide(h: &Harness, id: Uuid, decision: ManualApprovalDecision) {
    h.signer
        .daemon
        .decide_manual_approval_request(&AdminAuth::PeerCredentials, id, decision, None)
        .await
        .expect("decision");
}

fn record_path(h: &Harness, id: Uuid) -> std::path::PathBuf {
    h._dir
        .path()
        .join(PENDING_DIR_NAME)
        .join(format!("{id}.json"))
}

/// Starts a held broadcast transfer and returns its approval id.
async fn held_transfer(h: &Harness) -> Uuid {
    let response = h.call(h.transfer("1", broadcast())).await.expect("held");
    let Res::ManualApprovalPending(pending) = response else {
        panic!("expected ManualApprovalPending, got {response:?}");
    };
    assert_eq!(
        (pending.method.as_str(), pending.network.as_deref()),
        ("Transfer", Some("bsc"))
    );
    let AgentAction::BroadcastTx { tx } = &pending.action else {
        panic!("a broadcast transfer holds its transaction");
    };
    assert_eq!(tx.nonce, 7);
    pending.approval_request_id
}

#[tokio::test]
async fn a_held_transfer_is_stored_then_resumed_with_the_identical_transaction() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let id = held_transfer(&h).await;
    let path = record_path(&h, id);
    assert_eq!(
        std::fs::metadata(&path).expect("record").mode() & 0o777,
        0o600
    );
    assert!(h.mock.sent().is_empty());
    assert_eq!(
        h.next_free_nonce(7).await,
        7,
        "the reservation was released while pending"
    );

    // Still pending: the same answer, and the record stays.
    let Res::ManualApprovalPending(again) = h.call(resume(&h, id)).await.expect("pending") else {
        panic!("still pending");
    };
    assert_eq!(again.approval_request_id, id);
    assert!(path.exists());

    decide(&h, id, ManualApprovalDecision::Approve).await;
    let Res::EvmTransaction(tx) = h.call(resume(&h, id)).await.expect("resumed") else {
        panic!("expected EvmTransaction");
    };
    assert_eq!((tx.nonce, tx.broadcast), (7, true));
    assert_eq!(tx.payment.expect("payment").amount_wei, ONE_USD1);
    assert_eq!(h.mock.sent().len(), 1);
    assert!(!path.exists(), "a completed resume removes the record");
    assert_eq!(
        h.call(resume(&h, id)).await,
        Err(PaymentsError::UnknownPendingApproval(id))
    );
}

#[tokio::test]
async fn a_rejected_request_fails_and_clears_the_record() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let id = held_transfer(&h).await;
    decide(&h, id, ManualApprovalDecision::Reject).await;
    let error = h.call(resume(&h, id)).await.expect_err("rejected");
    assert_eq!(
        error,
        PaymentsError::Signer(WireDaemonError::ManualApprovalRejected {
            approval_request_id: id
        })
    );
    assert!(!record_path(&h, id).exists());
    assert!(h.mock.sent().is_empty());
    assert_eq!(h.next_free_nonce(7).await, 7);
}

#[tokio::test]
async fn only_the_submitting_agent_can_resume() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let id = held_transfer(&h).await;
    let identity = AgentSigner::new(h.signer.as_ref(), &h.auth)
        .identity()
        .await
        .expect("identity");
    let other = h
        .signer
        .daemon
        .create_agent_key(
            &AdminAuth::PeerCredentials,
            identity.vault_key.id,
            PolicyAttachment::AllPolicies,
        )
        .await
        .expect("second agent");
    let request = Req::ResumeApproved(ResumeApprovedParams {
        auth: AgentAuth {
            agent_key_id: other.agent_key.id,
            agent_auth_token: other.auth_token.clone(),
        },
        approval_request_id: id,
        approval_wait_secs: None,
    });
    assert_eq!(
        h.call(request).await,
        Err(PaymentsError::UnknownPendingApproval(id))
    );
    assert!(
        record_path(&h, id).exists(),
        "the owner's record is untouched"
    );
    let unknown = Uuid::new_v4();
    assert_eq!(
        h.call(resume(&h, unknown)).await,
        Err(PaymentsError::UnknownPendingApproval(unknown))
    );
}

#[tokio::test]
async fn a_nonce_used_while_waiting_makes_the_record_stale() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let id = held_transfer(&h).await;
    decide(&h, id, ManualApprovalDecision::Approve).await;
    h.mock.chain().nonce = 8;
    let error = h.call(resume(&h, id)).await.expect_err("stale");
    assert!(
        matches!(&error, PaymentsError::InvalidRequest(m) if m.contains("nonce 7")),
        "{error:?}"
    );
    assert!(!record_path(&h, id).exists());
    assert!(h.mock.sent().is_empty());
}

#[tokio::test]
async fn an_rpc_outage_during_resume_keeps_the_record_for_a_retry() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let id = held_transfer(&h).await;
    decide(&h, id, ManualApprovalDecision::Approve).await;
    h.mock.chain().chain_id = 1;
    assert!(matches!(
        h.call(resume(&h, id)).await,
        Err(PaymentsError::ChainRpc(_))
    ));
    assert!(record_path(&h, id).exists());
    h.mock.chain().chain_id = 56;
    assert!(matches!(
        h.call(resume(&h, id)).await,
        Ok(Res::EvmTransaction(_))
    ));
}

#[tokio::test]
async fn a_sign_only_transfer_can_be_held_and_resumed() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let response = h
        .call(h.transfer("1", EvmTxOptions::default()))
        .await
        .expect("held");
    let Res::ManualApprovalPending(pending) = response else {
        panic!("expected ManualApprovalPending, got {response:?}");
    };
    assert!(matches!(pending.action, AgentAction::Transfer { .. }));
    decide(
        &h,
        pending.approval_request_id,
        ManualApprovalDecision::Approve,
    )
    .await;
    let response = h
        .call(resume(&h, pending.approval_request_id))
        .await
        .expect("signed");
    let Res::EvmSignature(signed) = response else {
        panic!("expected EvmSignature, got {response:?}");
    };
    assert_eq!(signed.action, pending.action);
    assert_eq!(signed.payment, pending.payment);
}

#[tokio::test]
async fn typed_data_waits_for_an_operator_by_default() {
    let h = Harness::new(open_policy()).await;
    let request = Req::SignTypedData(SignTypedDataParams {
        auth: h.auth.clone(),
        typed_data_json: TYPED_DATA.into(),
        approval_wait_secs: None,
    });
    let Res::ManualApprovalPending(pending) = h.call(request).await.expect("held") else {
        panic!("typed data without an Eip712Signing policy needs approval");
    };
    assert_eq!((pending.network, pending.chain_id), (None, 56));
    decide(
        &h,
        pending.approval_request_id,
        ManualApprovalDecision::Approve,
    )
    .await;
    let Res::EvmSignature(signed) = h
        .call(resume(&h, pending.approval_request_id))
        .await
        .expect("signed")
    else {
        panic!("expected EvmSignature");
    };
    // The 65-byte signature recovers to the wallet over the EIP-712 digest.
    let AgentAction::Eip712TypedData { typed_data } = &signed.action else {
        panic!("typed data action");
    };
    let digest = B256::from(typed_data.signing_hash().expect("digest"));
    let bytes = alloy_primitives::hex::decode(&signed.signature_hex[2..]).expect("hex");
    assert_eq!(bytes.len(), 65);
    assert!(matches!(bytes[64], 27 | 28));
    let signature = Signature::from_raw(&bytes).expect("signature");
    let signer = signature
        .recover_address_from_prehash(&digest)
        .expect("recover");
    assert_eq!(
        signer,
        h.wallet().await.as_str().parse::<Address>().unwrap()
    );

    let invalid = Req::SignTypedData(SignTypedDataParams {
        auth: h.auth.clone(),
        typed_data_json: "{}".into(),
        approval_wait_secs: None,
    });
    assert!(matches!(
        h.call(invalid).await,
        Err(PaymentsError::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn one_call_can_wait_for_the_operator() {
    let h = Harness::new(vec![manual_approval(1, u128::MAX)]).await;
    let daemon = h.signer.daemon.clone();
    let approver = tokio::spawn(async move {
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let pending = daemon
                .list_manual_approval_requests(&AdminAuth::PeerCredentials)
                .await
                .expect("list");
            if let Some(request) = pending.first() {
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
        }
        panic!("no approval request appeared");
    });
    let options = EvmTxOptions {
        approval_wait_secs: Some(30),
        ..broadcast()
    };
    let response = h
        .call(h.transfer("1", options))
        .await
        .expect("approved in time");
    approver.await.expect("approver");
    let Res::EvmTransaction(tx) = response else {
        panic!("expected EvmTransaction, got {response:?}");
    };
    assert_eq!(tx.nonce, 7);
    assert_eq!(h.mock.sent().len(), 1);
    assert!(
        !h._dir.path().join(PENDING_DIR_NAME).exists()
            || std::fs::read_dir(h._dir.path().join(PENDING_DIR_NAME))
                .unwrap()
                .next()
                .is_none()
    );
}
