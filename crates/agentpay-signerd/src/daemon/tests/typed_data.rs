//! EIP-712 and EIP-3009 typed-data signing.

use agentpay_domain::{
    AdminAuth, AgentAction, EntityScope, ManualApprovalDecision, PolicyAttachment, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

use super::support::{policy_all_per_tx, sign_request};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn eip3009_signature_artifacts_are_recoverable() {
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
    let valid_after = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).unix_timestamp(),
    )
    .expect("future unix timestamp");
    let valid_before = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(10)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: agentpay_domain::Eip3009Transfer {
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
            amount_wei: 77,
            valid_after,
            valid_before,
            nonce_hex: format!("0x{}", hex::encode([0x11u8; 32])),
        },
    };

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("must sign eip3009");
    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let digest = action
        .signing_hash()
        .expect("typed hash")
        .expect("typed action");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
    assert!(signature.raw_tx_hex.is_none());
    assert!(signature.tx_hash_hex.is_none());
    assert!(signature.r_hex.is_some());
    assert!(signature.s_hex.is_some());
}

#[tokio::test]
async fn expired_eip3009_valid_before_is_rejected() {
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

    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: agentpay_domain::Eip3009Transfer {
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
            amount_wei: 77,
            valid_after: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::minutes(2)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            valid_before: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            nonce_hex: format!("0x{}", hex::encode([0x11u8; 32])),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired eip3009 authorization must be rejected");
    assert!(matches!(err, DaemonError::InvalidAction(_)));
}

fn sample_eip712_mail_action(chain_id: u64) -> AgentAction {
    AgentAction::Eip712TypedData {
        typed_data: agentpay_domain::Eip712TypedData {
            typed_data_json: format!(
                r#"{{
  "types": {{
    "EIP712Domain": [
      {{ "name": "name", "type": "string" }},
      {{ "name": "version", "type": "string" }},
      {{ "name": "chainId", "type": "uint256" }},
      {{ "name": "verifyingContract", "type": "address" }}
    ],
    "Mail": [
      {{ "name": "contents", "type": "string" }}
    ]
  }},
  "primaryType": "Mail",
  "domain": {{
    "name": "AgentPay Test",
    "version": "1",
    "chainId": {chain_id},
    "verifyingContract": "0x1111111111111111111111111111111111111111"
  }},
  "message": {{
    "contents": "hello"
  }}
}}"#
            ),
        },
    }
}

#[tokio::test]
async fn eip712_defaults_to_manual_approval_and_does_not_record_spend() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(&agent_credentials, sample_eip712_mail_action(1));
    let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve request");

    daemon
        .sign_for_agent(request)
        .await
        .expect("approved eip712 request should sign");

    assert!(
        daemon.spend_log.read().expect("spend log").is_empty(),
        "generic eip712 signing must not create spend log entries"
    );
}

#[tokio::test]
async fn eip712_allow_policy_signs_without_manual_approval() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let allow_policy = SpendingPolicy::new_eip712_signing(
        1,
        agentpay_domain::ApprovalType::Allow,
        EntityScope::All,
    )
    .expect("policy");
    daemon
        .add_policy(&session, allow_policy)
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

    let signature = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_eip712_mail_action(1),
        ))
        .await
        .expect("allow policy should sign");

    assert!(!signature.bytes.is_empty());
    assert!(daemon
        .manual_approval_requests
        .read()
        .expect("manual approvals")
        .is_empty());
    assert!(daemon.spend_log.read().expect("spend log").is_empty());
}

#[tokio::test]
async fn eip712_deny_policy_rejects_signing() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let deny_policy = SpendingPolicy::new_eip712_signing(
        1,
        agentpay_domain::ApprovalType::Deny,
        EntityScope::All,
    )
    .expect("policy");
    let deny_policy_id = deny_policy.id;
    daemon
        .add_policy(&session, deny_policy)
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

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_eip712_mail_action(1),
        ))
        .await
        .expect_err("deny policy should reject");

    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::Eip712SigningDenied { policy_id })
            if policy_id == deny_policy_id
    ));
}
