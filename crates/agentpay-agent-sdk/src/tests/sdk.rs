//! Tests for `AgentSdk` request construction, nonce handling, and error propagation.

use std::sync::{Arc, Mutex};

use agentpay_domain::{AgentAction, BroadcastTx, DomainError, EvmAddress};
use agentpay_signerd::DaemonError;
use uuid::Uuid;

use super::recording_daemon::{test_credentials, RecordingDaemon};
use crate::{AgentOperations, AgentSdk, AgentSdkError};

#[tokio::test]
async fn approve_sends_canonical_action_payload_and_auth_token() {
    let daemon = Arc::new(RecordingDaemon::default());
    let credentials = test_credentials();
    let key_id = credentials.agent_key.id;
    let auth_token = credentials.auth_token.clone();
    let sdk = AgentSdk::new(daemon.clone(), credentials);

    let token: EvmAddress = "0x1000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let spender: EvmAddress = "0x2000000000000000000000000000000000000000"
        .parse()
        .expect("spender");

    let signature = sdk
        .approve(1, token.clone(), spender.clone(), 42)
        .await
        .expect("approve");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let captured = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(captured.agent_key_id, key_id);
    assert_eq!(captured.agent_auth_token, auth_token);
    assert_eq!(
        captured.action,
        AgentAction::Approve {
            chain_id: 1,
            token,
            spender,
            amount_wei: 42
        }
    );
    let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
    assert_eq!(decoded, captured.action);
}

#[tokio::test]
async fn constructors_transfer_native_and_reservation_helpers_use_expected_identity() {
    let daemon = Arc::new(RecordingDaemon::default());
    let key_id = Uuid::new_v4();
    let sdk = AgentSdk::new_with_key_id_and_token(
        daemon.clone(),
        key_id,
        "agent-secret-token".to_string(),
    );

    let recipient: EvmAddress = "0x2100000000000000000000000000000000000000"
        .parse()
        .expect("recipient");
    let signature = sdk
        .transfer_native(1, recipient.clone(), 5)
        .await
        .expect("transfer native");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let captured = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(captured.agent_key_id, key_id);
    assert_eq!(captured.agent_auth_token.as_str(), "agent-secret-token");
    assert_eq!(
        captured.action,
        AgentAction::TransferNative {
            chain_id: 1,
            to: recipient,
            amount_wei: 5
        }
    );

    let reservation = sdk
        .reserve_broadcast_nonce(56, 99)
        .await
        .expect("reserve nonce");
    assert_eq!(reservation.chain_id, 56);
    assert_eq!(reservation.nonce, 99);
    let captured_reservation = daemon
        .nonce_request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured nonce request");
    assert_eq!(captured_reservation.chain_id, 56);
    assert_eq!(captured_reservation.min_nonce, 99);
    assert!(captured_reservation.exact_nonce);
    sdk.release_broadcast_nonce(reservation.reservation_id)
        .await
        .expect("release nonce");
}

#[tokio::test]
async fn sign_erc20_calldata_and_invalid_actions_propagate_domain_errors() {
    let daemon = Arc::new(RecordingDaemon::default());
    let sdk = AgentSdk::new(daemon.clone(), test_credentials());
    let encoded = vec![
        0x09, 0x5e, 0xa7, 0xb3, // approve(address,uint256)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x0c,
    ];

    let signature = sdk
        .sign_erc20_calldata(
            1,
            "0x3300000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            encoded,
        )
        .await
        .expect("sign erc20 calldata");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let err = sdk
        .transfer_native(
            1,
            "0x5500000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            0,
        )
        .await
        .expect_err("invalid action");
    assert!(matches!(
        err,
        AgentSdkError::Domain(DomainError::InvalidAmount)
    ));
}

#[tokio::test]
async fn transfer_propagates_daemon_errors() {
    let daemon = Arc::new(RecordingDaemon {
        request: Mutex::new(None),
        nonce_request: Mutex::new(None),
        released_reservation: Mutex::new(None),
        fail_sign: true,
        reserved_nonce_override: None,
    });
    let sdk = AgentSdk::new(daemon, test_credentials());

    let token: EvmAddress = "0x3000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0x4000000000000000000000000000000000000000"
        .parse()
        .expect("recipient");

    let err = sdk
        .transfer(1, token, recipient, 7)
        .await
        .expect_err("must fail");
    assert!(matches!(
        err,
        AgentSdkError::Daemon(DaemonError::AgentAuthenticationFailed)
    ));
}

#[tokio::test]
async fn broadcast_tx_sends_canonical_action_payload() {
    let daemon = Arc::new(RecordingDaemon::default());
    let credentials = test_credentials();
    let sdk = AgentSdk::new(daemon.clone(), credentials);

    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x".to_string(),
        gas_limit: 50_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    let signature = sdk.broadcast_tx(tx.clone()).await.expect("broadcast");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let captured = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(captured.action, AgentAction::BroadcastTx { tx: tx.clone() });
    let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
    assert_eq!(decoded, AgentAction::BroadcastTx { tx });
}

#[tokio::test]
async fn broadcast_tx_rejects_mismatched_reserved_nonce_from_daemon() {
    let daemon = Arc::new(RecordingDaemon {
        request: Mutex::new(None),
        nonce_request: Mutex::new(None),
        released_reservation: Mutex::new(None),
        fail_sign: false,
        reserved_nonce_override: Some(1),
    });
    let sdk = AgentSdk::new(daemon.clone(), test_credentials());

    let tx = BroadcastTx {
        chain_id: 56,
        nonce: 0,
        to: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 0,
        data_hex: "0x".to_string(),
        gas_limit: 50_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };

    let err = sdk
        .broadcast_tx(tx.clone())
        .await
        .expect_err("mismatched reserved nonce must fail");
    assert!(matches!(
        err,
        AgentSdkError::Daemon(DaemonError::InvalidNonceReservation(message))
        if message.contains("requested exact nonce 0")
            && message.contains("chain_id 56")
            && message.contains("reserved 1")
    ));

    assert!(daemon.request.lock().expect("lock").is_none());
    assert!(daemon.released_reservation.lock().expect("lock").is_some());
    let captured_reservation = daemon
        .nonce_request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured nonce request");
    assert!(captured_reservation.exact_nonce);
    assert_eq!(captured_reservation.min_nonce, tx.nonce);
}
