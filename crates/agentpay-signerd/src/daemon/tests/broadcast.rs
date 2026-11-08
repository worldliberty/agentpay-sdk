//! EIP-1559 broadcast transaction signing.

use agentpay_domain::{AdminAuth, AgentAction, BroadcastTx, PolicyAttachment};
use agentpay_signer::{KeyCreateRequest, SignerError, SoftwareSignerBackend};
use alloy_primitives::keccak256;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use uuid::Uuid;

use super::support::{
    policy_all_per_tx, policy_per_chain_gas, reserve_nonce_for_agent, sign_request,
    FlakySignerBackend,
};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn broadcast_without_nonce_reservation_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x9300000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("broadcast signing requires nonce reservation");
    assert!(matches!(
        err,
        DaemonError::MissingNonceReservation {
            chain_id: 1,
            nonce: 0
        }
    ));
}

#[tokio::test]
async fn broadcast_unknown_selector_is_rejected_even_when_policies_allow_it() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 1,
                data_hex: "0xdeadbeef".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    // Unknown selectors are denied by default: permissive spend policies cannot authorize
    // calldata the policy engine is unable to interpret.
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("unrecognized calldata must be rejected");
    match err {
        DaemonError::InvalidAction(message) => {
            assert!(
                message.contains("unrecognized transaction calldata"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn eip1559_broadcast_signature_artifacts_are_consistent() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 7,
        to: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 123,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 100_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx { tx: tx.clone() },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, tx.chain_id, tx.nonce).await;

    let signature = daemon.sign_for_agent(request).await.expect("must sign");
    let r_hex = signature.r_hex.expect("eip1559 r must be present");
    let s_hex = signature.s_hex.expect("eip1559 s must be present");
    let v = signature.v.expect("eip1559 v must be present");
    let raw_tx_hex = signature
        .raw_tx_hex
        .expect("eip1559 raw tx bytes must be present");
    let tx_hash_hex = signature
        .tx_hash_hex
        .expect("eip1559 tx hash must be present");
    assert!(v <= 1, "typed tx y-parity must be 0 or 1");

    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let compact = parsed_der.to_bytes();
    assert_eq!(r_hex, format!("0x{}", hex::encode(&compact[..32])));
    assert_eq!(s_hex, format!("0x{}", hex::encode(&compact[32..])));

    let raw_tx = hex::decode(
        raw_tx_hex
            .strip_prefix("0x")
            .expect("raw tx must be 0x-prefixed"),
    )
    .expect("raw tx hex");
    assert_eq!(raw_tx.first().copied(), Some(0x02));
    assert_eq!(
        tx_hash_hex,
        format!("0x{}", hex::encode(keccak256(&raw_tx).0))
    );

    let signing_message = tx.eip1559_signing_message().expect("signing message");
    let digest = keccak256(&signing_message).0;
    let recovery_id = RecoveryId::from_byte(v as u8).expect("valid recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
}

#[tokio::test]
async fn non_eip1559_broadcast_is_rejected_for_signing() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x04,
                delegation_enabled: false,
            },
        },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("non-eip1559 broadcast tx must be rejected");
    assert!(matches!(
        err,
        DaemonError::Signer(agentpay_signer::SignerError::Unsupported(message))
            if message.contains("unsupported for signing")
    ));
}

#[tokio::test]
async fn broadcast_signer_failure_preserves_request_id_and_nonce_reservation() {
    let daemon = InMemoryDaemon::new(
        FlakySignerBackend::fail_first_digest(SignerError::Internal(
            "simulated signer timeout".to_string(),
        )),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4100000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );

    let err = daemon
        .sign_for_agent(request.clone())
        .await
        .expect_err("first broadcast signing attempt should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Internal(message))
            if message == "simulated signer timeout"
    ));

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("same request id and reservation should remain retryable after signer failure");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");

    let replay = daemon
        .sign_for_agent(request)
        .await
        .expect("successful broadcast retries should remain idempotent");
    assert_eq!(replay, signature);
}

#[tokio::test]
async fn non_eip1559_broadcast_rejection_preserves_nonce_reservation() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let rejected = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x04,
                delegation_enabled: false,
            },
        },
    );
    let err = daemon
        .sign_for_agent(rejected)
        .await
        .expect_err("non-eip1559 broadcast tx must be rejected");
    assert!(matches!(
        err,
        DaemonError::Signer(agentpay_signer::SignerError::Unsupported(message))
            if message.contains("unsupported for signing")
    ));

    let recovered = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    let signature = daemon
        .sign_for_agent(recovered)
        .await
        .expect("reserved nonce should remain usable after signing rejection");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");
}

#[tokio::test]
async fn signer_backend_failure_preserves_broadcast_nonce_reservation() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let detached_backend_key_id = Uuid::new_v4();
    let mut detached_backend_key = key.clone();
    detached_backend_key.id = detached_backend_key_id;
    daemon
        .vault_keys
        .write()
        .expect("vault keys")
        .insert(detached_backend_key_id, detached_backend_key);
    daemon
        .agent_keys
        .write()
        .expect("agent keys")
        .entry(agent_credentials.agent_key.id)
        .and_modify(|agent_key| agent_key.vault_key_id = detached_backend_key_id);

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x4100000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 1_000_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("backend signing failure must reject the request");
    assert!(matches!(
        err,
        DaemonError::Signer(agentpay_signer::SignerError::UnknownKey(id))
            if id == detached_backend_key_id
    ));

    let reservations = daemon
        .nonce_reservations
        .read()
        .expect("nonce reservations");
    let reservation = reservations
        .values()
        .next()
        .expect("nonce reservation must be preserved after signer failure");
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservation.agent_key_id, agent_credentials.agent_key.id);
    assert_eq!(reservation.vault_key_id, detached_backend_key_id);
    assert_eq!(reservation.chain_id, 1);
    assert_eq!(reservation.nonce, 0);
}

#[tokio::test]
async fn broadcast_with_delegation_is_rejected_even_for_eip7702() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: true,
            },
        },
    );
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("must reject delegation even for eip-7702");
    assert!(matches!(err, DaemonError::InvalidAction(_)));
}
