//! Tests for EIP-3009 authorizations, ERC-20 calldata, and EIP-712 typed-data signing.

use std::sync::Arc;

use agentpay_domain::{AgentAction, DomainError, Eip3009Transfer, Eip712TypedData};
use time::OffsetDateTime;

use super::recording_daemon::{test_credentials, RecordingDaemon};
use crate::{AgentOperations, AgentSdk, AgentSdkError};

fn unix_timestamp(value: OffsetDateTime) -> u64 {
    value.unix_timestamp().try_into().expect("unix timestamp")
}

fn future_unix_timestamp(offset: time::Duration) -> u64 {
    unix_timestamp(OffsetDateTime::now_utc() + offset)
}

#[tokio::test]
async fn eip3009_receive_sends_canonical_action_payload() {
    let daemon = Arc::new(RecordingDaemon::default());
    let sdk = AgentSdk::new(daemon.clone(), test_credentials());
    let authorization = Eip3009Transfer {
        chain_id: 1,
        token: "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4000000000000000000000000000000000000000"
            .parse()
            .expect("from"),
        to: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        amount_wei: 9,
        valid_after: future_unix_timestamp(time::Duration::minutes(5)),
        valid_before: future_unix_timestamp(time::Duration::minutes(10)),
        nonce_hex: "0x5555555555555555555555555555555555555555555555555555555555555555".to_string(),
    };

    let signature = sdk
        .eip3009_receive_with_authorization(authorization.clone())
        .await
        .expect("eip3009 receive");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let captured = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(
        captured.action,
        AgentAction::Eip3009ReceiveWithAuthorization { authorization }
    );
    let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
    assert_eq!(decoded, captured.action);
}

#[tokio::test]
async fn eip3009_rejects_expired_valid_before() {
    let daemon = Arc::new(RecordingDaemon::default());
    let sdk = AgentSdk::new(daemon, test_credentials());
    let authorization = Eip3009Transfer {
        chain_id: 1,
        token: "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4000000000000000000000000000000000000000"
            .parse()
            .expect("from"),
        to: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        amount_wei: 9,
        valid_after: unix_timestamp(OffsetDateTime::now_utc() - time::Duration::minutes(2)),
        valid_before: unix_timestamp(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
        nonce_hex: "0x5555555555555555555555555555555555555555555555555555555555555555".to_string(),
    };

    let err = sdk
        .eip3009_transfer_with_authorization(authorization)
        .await
        .expect_err("expired authorization must be rejected");
    assert!(matches!(
        err,
        AgentSdkError::Domain(DomainError::InvalidAuthorizationWindow)
    ));
}

#[tokio::test]
async fn transfer_and_eip3009_transfer_sends_canonical_action_payload() {
    let daemon = Arc::new(RecordingDaemon::default());
    let sdk = AgentSdk::new(daemon.clone(), test_credentials());

    let token = "0x3000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let to = "0x5000000000000000000000000000000000000000"
        .parse()
        .expect("to");
    let signature = sdk.transfer(1, token, to, 9).await.expect("transfer");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let transfer_action = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request")
        .action;
    assert!(matches!(transfer_action, AgentAction::Transfer { .. }));

    let authorization = Eip3009Transfer {
        chain_id: 1,
        token: "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        token_name: "USD Coin".to_string(),
        token_version: Some("2".to_string()),
        from: "0x4000000000000000000000000000000000000000"
            .parse()
            .expect("from"),
        to: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        amount_wei: 9,
        valid_after: future_unix_timestamp(time::Duration::minutes(5)),
        valid_before: future_unix_timestamp(time::Duration::minutes(10)),
        nonce_hex: "0x5555555555555555555555555555555555555555555555555555555555555555".to_string(),
    };

    let signature = sdk
        .eip3009_transfer_with_authorization(authorization.clone())
        .await
        .expect("eip3009 transfer");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let captured = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(
        captured.action,
        AgentAction::Eip3009TransferWithAuthorization { authorization }
    );
    let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
    assert_eq!(decoded, captured.action);

    let erc20_transfer = vec![
        0xa9, 0x05, 0x9c, 0xbb, // transfer(address,uint256)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07,
    ];
    let signature = sdk
        .sign_erc20_calldata(
            1,
            "0x6000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            erc20_transfer,
        )
        .await
        .expect("erc20 transfer");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);
}

#[tokio::test]
async fn eip712_typed_data_sends_canonical_action_payload() {
    let daemon = Arc::new(RecordingDaemon::default());
    let sdk = AgentSdk::new(daemon.clone(), test_credentials());
    let typed_data = Eip712TypedData {
        typed_data_json: r#"{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" },
      { "name": "version", "type": "string" },
      { "name": "chainId", "type": "uint256" },
      { "name": "verifyingContract", "type": "address" }
    ],
    "Mail": [
      { "name": "contents", "type": "string" }
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "AgentPay Test",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x1111111111111111111111111111111111111111"
  },
  "message": {
    "contents": "hello"
  }
}"#
        .to_string(),
    };

    let signature = sdk
        .eip712_typed_data(typed_data.clone())
        .await
        .expect("eip712 typed data");
    assert_eq!(signature.bytes, vec![0x11, 0x22]);

    let captured = daemon
        .request
        .lock()
        .expect("lock")
        .clone()
        .expect("captured request");
    assert_eq!(
        captured.action,
        AgentAction::Eip712TypedData {
            typed_data: typed_data.clone(),
        }
    );
    let decoded: AgentAction = serde_json::from_slice(&captured.payload).expect("decode");
    assert_eq!(decoded, captured.action);
}

#[tokio::test]
async fn eip712_typed_data_rejects_missing_chain_id() {
    let daemon = Arc::new(RecordingDaemon::default());
    let sdk = AgentSdk::new(daemon, test_credentials());
    let typed_data = Eip712TypedData {
        typed_data_json: r#"{
  "types": {
    "EIP712Domain": [
      { "name": "name", "type": "string" }
    ],
    "Mail": [
      { "name": "contents", "type": "string" }
    ]
  },
  "primaryType": "Mail",
  "domain": {
    "name": "AgentPay Test"
  },
  "message": {
    "contents": "hello"
  }
}"#
        .to_string(),
    };

    let err = sdk
        .eip712_typed_data(typed_data)
        .await
        .expect_err("missing chain id must be rejected");
    assert!(matches!(
        err,
        AgentSdkError::Domain(DomainError::InvalidTypedDataDomain(message))
            if message.contains("chainId")
    ));
}
