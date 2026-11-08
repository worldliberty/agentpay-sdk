//! `ReleaseSignedNonce`: returning the nonce of a signed broadcast that never
//! reached the network.

use agentpay_domain::{
    AdminAuth, AgentAction, AgentCredentials, BroadcastTx, NonceReservation,
    NonceReservationRequest, PolicyAttachment, SignRequest, Signature, SignedNonceReleaseRequest,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::support::{
    policy_all_per_tx, policy_per_chain_gas, sign_request, test_state_secret, unique_state_path,
};
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
};

const CHAIN_ID: u64 = 56;

async fn setup(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
) -> (AgentCredentials, AgentCredentials) {
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("per-tx policy");
    daemon
        .add_policy(
            &session,
            policy_per_chain_gas(CHAIN_ID, 1_000_000_000_000_000),
        )
        .await
        .expect("gas policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let first = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let second = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("second agent on the same wallet");
    (first, second)
}

async fn reserve(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    agent: &AgentCredentials,
    min_nonce: u64,
    exact: bool,
) -> Result<NonceReservation, DaemonError> {
    let now = OffsetDateTime::now_utc();
    daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent.agent_key.id,
            agent_auth_token: agent.auth_token.clone(),
            chain_id: CHAIN_ID,
            min_nonce,
            exact_nonce: exact,
            requested_at: now,
            expires_at: now + Duration::minutes(2),
        })
        .await
}

fn broadcast(agent: &AgentCredentials, nonce: u64) -> SignRequest {
    sign_request(
        agent,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: CHAIN_ID,
                nonce,
                to: "0x9300000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 1,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    )
}

/// Reserves `nonce`, signs a transfer with it, and returns the request and signature.
async fn sign_at(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    agent: &AgentCredentials,
    nonce: u64,
) -> (SignRequest, Signature) {
    let reservation = reserve(daemon, agent, nonce, false).await.expect("reserve");
    assert_eq!(reservation.nonce, nonce);
    let request = broadcast(agent, nonce);
    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("sign broadcast");
    (request, signature)
}

fn release(
    agent: &AgentCredentials,
    nonce: u64,
    signature: &Signature,
) -> SignedNonceReleaseRequest {
    let now = OffsetDateTime::now_utc();
    SignedNonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent.agent_key.id,
        agent_auth_token: agent.auth_token.clone(),
        chain_id: CHAIN_ID,
        nonce,
        tx_hash_hex: signature.tx_hash_hex.clone().expect("tx hash"),
        requested_at: now,
        expires_at: now + Duration::minutes(2),
    }
}

#[tokio::test]
async fn a_signed_nonce_is_consumed_until_released() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let (agent, _) = setup(&daemon).await;
    let (_, signature) = sign_at(&daemon, &agent, 7).await;

    // Without the release, the next payment (same on-chain pending nonce) skips 7.
    let skipped = reserve(&daemon, &agent, 7, false).await.expect("reserve");
    assert_eq!(skipped.nonce, 8, "a signed nonce is never handed out again");
    daemon
        .release_nonce(agentpay_domain::NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent.agent_key.id,
            agent_auth_token: agent.auth_token.clone(),
            reservation_id: skipped.reservation_id,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(1),
        })
        .await
        .expect("release unused reservation");

    daemon
        .release_signed_nonce(release(&agent, 7, &signature))
        .await
        .expect("release the never-sent transaction's nonce");
    let reused = reserve(&daemon, &agent, 7, false).await.expect("reserve");
    assert_eq!(reused.nonce, 7, "the gap is closed");
}

#[tokio::test]
async fn release_keeps_the_spend_counted() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let (agent, _) = setup(&daemon).await;
    let (_, signature) = sign_at(&daemon, &agent, 3).await;
    let spends_before = daemon.spend_log.read().expect("spend log").len();
    daemon
        .release_signed_nonce(release(&agent, 3, &signature))
        .await
        .expect("release");
    assert_eq!(
        daemon.spend_log.read().expect("spend log").len(),
        spends_before,
        "the daemon cannot see the network, so the spend stays counted"
    );
}

#[tokio::test]
async fn only_the_signing_agent_can_release_and_only_its_exact_transaction() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let (agent, other) = setup(&daemon).await;
    let (_, signature) = sign_at(&daemon, &agent, 0).await;

    let err = daemon
        .release_signed_nonce(release(&other, 0, &signature))
        .await
        .expect_err("another agent on the same wallet");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    let err = daemon
        .release_signed_nonce(release(&agent, 1, &signature))
        .await
        .expect_err("wrong nonce");
    assert!(matches!(err, DaemonError::InvalidNonceReservation(_)));

    let mut unknown = release(&agent, 0, &signature);
    unknown.tx_hash_hex = format!("0x{}", "ab".repeat(32));
    let err = daemon
        .release_signed_nonce(unknown)
        .await
        .expect_err("never signed");
    assert!(matches!(err, DaemonError::UnknownSignedTransaction(_)));

    let mut malformed = release(&agent, 0, &signature);
    malformed.tx_hash_hex = "0x1234".to_string();
    assert!(matches!(
        daemon.release_signed_nonce(malformed).await,
        Err(DaemonError::InvalidNonceReservation(_))
    ));

    let mut wrong_token = release(&agent, 0, &signature);
    wrong_token.agent_auth_token = "wrong".to_string().into();
    assert!(matches!(
        daemon.release_signed_nonce(wrong_token).await,
        Err(DaemonError::AgentAuthenticationFailed)
    ));

    // The failed attempts left the record alone; upper-case hashes are accepted.
    let mut upper = release(&agent, 0, &signature);
    upper.tx_hash_hex = format!("0x{}", upper.tx_hash_hex[2..].to_ascii_uppercase());
    daemon
        .release_signed_nonce(upper)
        .await
        .expect("the signing agent releases it");
}

#[tokio::test]
async fn release_is_single_use_and_idempotent_per_request_id() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let (agent, _) = setup(&daemon).await;
    let (sign, signature) = sign_at(&daemon, &agent, 4).await;
    let first = release(&agent, 4, &signature);
    daemon
        .release_signed_nonce(first.clone())
        .await
        .expect("release");
    daemon
        .release_signed_nonce(first.clone())
        .await
        .expect("an identical retry succeeds again");

    let err = daemon
        .release_signed_nonce(release(&agent, 4, &signature))
        .await
        .expect_err("a second release of the same transaction");
    assert!(matches!(err, DaemonError::UnknownSignedTransaction(_)));

    let mut different = first;
    different.nonce = 5;
    assert!(matches!(
        daemon.release_signed_nonce(different).await,
        Err(DaemonError::RequestReplayDetected)
    ));

    // A retry of the original signing request cannot fetch the released transaction.
    let err = daemon
        .sign_for_agent(sign)
        .await
        .expect_err("the released signature is not recoverable");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn a_nonce_reserved_again_exactly_is_not_freed_twice() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let (agent, _) = setup(&daemon).await;
    let (_, signature) = sign_at(&daemon, &agent, 9).await;
    // A replacement transaction reserves 9 exactly before the release arrives.
    let replacement = reserve(&daemon, &agent, 9, true).await.expect("exact");
    assert_eq!(replacement.nonce, 9);
    daemon
        .release_signed_nonce(release(&agent, 9, &signature))
        .await
        .expect("release");
    let next = reserve(&daemon, &agent, 9, false).await.expect("reserve");
    assert_eq!(next.nonce, 10, "9 is still held by the replacement");
}

#[tokio::test]
async fn releasable_transactions_survive_a_restart_and_revocation_forgets_them() {
    let path = unique_state_path("signed-nonce-release");
    let open = || {
        InMemoryDaemon::new_with_persistent_store(
            &test_state_secret(),
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
            PersistentStoreConfig::new_test(path.clone()),
        )
        .expect("daemon")
    };
    let daemon = open();
    let (agent, other) = setup(&daemon).await;
    let (_, signature) = sign_at(&daemon, &agent, 2).await;
    let (_, other_signature) = sign_at(&daemon, &other, 3).await;
    drop(daemon);

    let daemon = open();
    daemon
        .release_signed_nonce(release(&agent, 2, &signature))
        .await
        .expect("release after restart");
    daemon
        .revoke_agent_key(&AdminAuth::PeerCredentials, other.agent_key.id)
        .await
        .expect("revoke");
    assert!(daemon
        .signed_broadcasts
        .read()
        .expect("records")
        .values()
        .all(|record| record.agent_key_id != other.agent_key.id));
    let _ = other_signature;
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn records_expire_after_the_release_window() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let (agent, _) = setup(&daemon).await;
    let (_, signature) = sign_at(&daemon, &agent, 1).await;
    for record in daemon
        .signed_broadcasts
        .write()
        .expect("records")
        .values_mut()
    {
        record.signed_at -= Duration::minutes(11);
    }
    let err = daemon
        .release_signed_nonce(release(&agent, 1, &signature))
        .await
        .expect_err("too late");
    assert!(matches!(err, DaemonError::UnknownSignedTransaction(_)));
}
