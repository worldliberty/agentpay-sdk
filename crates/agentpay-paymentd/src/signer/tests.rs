//! [`AgentSigner`] against a real in-process signerd and a scripted double.

use std::time::Duration;

use agentpay_api::rpc::SignForAgentParams;
use agentpay_api::{AgentAuth, DaemonRpcRequest, DaemonRpcResponse, WireDaemonError};
use agentpay_domain::{AdminAuth, AgentAction, ManualApprovalDecision, PolicyType, Signature};
use agentpay_signerd::KeyManagerDaemonApi;
use uuid::Uuid;

use super::testing::{manual_approval, per_tx_limit, InProcessSigner, ScriptedSigner};
use super::{AgentSigner, ApprovalWait, SignerError, MAX_APPROVAL_WAIT};
use crate::error::PaymentsError;

fn transfer(amount_wei: u128) -> AgentAction {
    AgentAction::TransferNative {
        chain_id: 56,
        to: "0x5aeda56215b167893e80b4fe645ba6d5bab767de"
            .parse()
            .expect("recipient"),
        amount_wei,
    }
}

fn some_auth() -> AgentAuth {
    AgentAuth {
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "token".to_string().into(),
    }
}

fn held(approval_request_id: Uuid) -> Result<DaemonRpcResponse, SignerError> {
    Err(SignerError::Rejected(
        WireDaemonError::ManualApprovalRequired {
            approval_request_id,
        },
    ))
}

#[tokio::test]
async fn signing_applies_the_agents_policies() {
    let (signer, auth) = InProcessSigner::with_agent(vec![per_tx_limit(100)]).await;
    let agent = AgentSigner::new(&signer, &auth);

    let signature = agent
        .sign(transfer(100), ApprovalWait::none())
        .await
        .expect("within the limit");
    assert!(!signature.bytes.is_empty());

    let err = agent
        .sign(transfer(101), ApprovalWait::none())
        .await
        .expect_err("over the limit");
    let PaymentsError::Signer(WireDaemonError::Policy(_)) = err else {
        panic!("expected a policy denial, got {err:?}");
    };
}

#[tokio::test]
async fn nonces_are_reserved_and_released_as_the_agent() {
    let (signer, auth) = InProcessSigner::with_agent(vec![per_tx_limit(100)]).await;
    let agent = AgentSigner::new(&signer, &auth);
    let first = agent.reserve_nonce(56, 7, false).await.expect("reserve");
    assert_eq!((first.chain_id, first.nonce), (56, 7));
    assert_eq!(first.agent_key_id, auth.agent_key_id);
    let second = agent.reserve_nonce(56, 7, false).await.expect("reserve");
    assert_eq!(second.nonce, 8, "a reserved nonce is not handed out twice");

    agent
        .release_nonce(first.reservation_id)
        .await
        .expect("release");
    let reused = agent.reserve_nonce(56, 7, false).await.expect("reserve");
    assert_eq!(reused.nonce, 7, "a released nonce returns to the pool");
}

#[tokio::test]
async fn a_held_signature_is_reported_pending_without_waiting() {
    let (signer, auth) = InProcessSigner::with_agent(vec![manual_approval(1, 1_000)]).await;
    let err = AgentSigner::new(&signer, &auth)
        .sign(transfer(10), ApprovalWait::none())
        .await
        .expect_err("held for an operator");
    let PaymentsError::ManualApprovalPending {
        approval_request_id,
    } = err
    else {
        panic!("expected ManualApprovalPending, got {err:?}");
    };
    let requests = signer
        .daemon
        .list_manual_approval_requests(&AdminAuth::PeerCredentials)
        .await
        .expect("list");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].id, approval_request_id);
}

#[tokio::test(start_paused = true)]
async fn waiting_signs_once_an_operator_approves() {
    let (signer, auth) = InProcessSigner::with_agent(vec![manual_approval(1, 1_000)]).await;
    let daemon = signer.daemon.clone();
    let operator = tokio::spawn(async move {
        // Approve while the signer is backing off between polls.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let pending = daemon
            .list_manual_approval_requests(&AdminAuth::PeerCredentials)
            .await
            .expect("list");
        daemon
            .decide_manual_approval_request(
                &AdminAuth::PeerCredentials,
                pending[0].id,
                ManualApprovalDecision::Approve,
                None,
            )
            .await
            .expect("approve");
    });
    let signature: Signature = AgentSigner::new(&signer, &auth)
        .sign(transfer(10), ApprovalWait::up_to(Duration::from_secs(60)))
        .await
        .expect("approved and signed");
    operator.await.expect("operator");
    assert!(!signature.bytes.is_empty());
}

#[tokio::test]
async fn a_rejection_ends_the_wait() {
    let id = Uuid::new_v4();
    let signer = ScriptedSigner::new([
        held(id),
        Err(SignerError::Rejected(
            WireDaemonError::ManualApprovalRejected {
                approval_request_id: id,
            },
        )),
    ]);
    let auth = some_auth();
    let err = AgentSigner::new(&signer, &auth)
        .sign(
            transfer(10),
            ApprovalWait {
                max_wait: Duration::from_secs(5),
                initial_interval: Duration::from_millis(1),
                max_interval: Duration::from_millis(1),
            },
        )
        .await
        .expect_err("rejected");
    assert_eq!(
        err,
        PaymentsError::Signer(WireDaemonError::ManualApprovalRejected {
            approval_request_id: id
        })
    );
}

#[tokio::test(start_paused = true)]
async fn polling_is_bounded_backs_off_and_resends_the_identical_request() {
    let id = Uuid::new_v4();
    let signer = ScriptedSigner::new((0..64).map(|_| held(id)));
    let auth = some_auth();
    let started = tokio::time::Instant::now();
    let err = AgentSigner::new(&signer, &auth)
        .sign(transfer(10), ApprovalWait::up_to(Duration::from_secs(60)))
        .await
        .expect_err("still pending");
    assert_eq!(
        err,
        PaymentsError::ManualApprovalPending {
            approval_request_id: id
        }
    );
    assert_eq!(started.elapsed(), Duration::from_secs(60));

    // 1 + 2 + 4 + 8 + 15 + 15 + 15 = 60 s of backoff: 8 attempts in all.
    let requests = signer.requests();
    assert_eq!(requests.len(), 8);
    let signs: Vec<_> = requests
        .iter()
        .map(|request| match request {
            DaemonRpcRequest::SignForAgent(SignForAgentParams { request }) => request,
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    for sign in &signs {
        assert_eq!(sign.request_id, signs[0].request_id, "same request id");
        assert_eq!(sign.payload, signs[0].payload, "identical payload bytes");
        assert_eq!(
            sign.payload,
            serde_json::to_vec(&sign.action).expect("canonical")
        );
        assert!(sign.expires_at - sign.requested_at <= time::Duration::minutes(5));
    }
}

#[test]
fn approval_waits_are_capped() {
    assert_eq!(ApprovalWait::none().max_wait, Duration::ZERO);
    assert_eq!(
        ApprovalWait::up_to(Duration::from_secs(86_400)).max_wait,
        MAX_APPROVAL_WAIT
    );
}

#[tokio::test]
async fn unexpected_response_variants_are_a_signer_failure() {
    let signer = ScriptedSigner::new([Ok(DaemonRpcResponse::Unit)]);
    let auth = some_auth();
    let err = AgentSigner::new(&signer, &auth)
        .sign(transfer(1), ApprovalWait::none())
        .await
        .expect_err("Unit is not a signature");
    let PaymentsError::SignerUnavailable(reason) = err else {
        panic!("expected SignerUnavailable, got {err:?}");
    };
    assert!(reason.contains("unexpected Unit response"), "{reason}");
}

#[test]
fn manual_approval_helper_builds_a_manual_policy() {
    assert_eq!(
        manual_approval(1, 2).policy_type,
        PolicyType::ManualApproval
    );
}
