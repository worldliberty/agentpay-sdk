//! Sign request validation, payload canonicalization, and request-id replay.

use agentpay_domain::{
    AdminAuth, AgentAction, EvmAddress, NonceReservationRequest, PolicyAttachment,
};
use agentpay_signer::{KeyCreateRequest, SignerError, SoftwareSignerBackend};
use serde_json::to_vec;
use uuid::Uuid;

use super::support::{policy_all_per_tx, sign_request, FlakySignerBackend};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn successful_sign_request_is_idempotent_for_same_request_id() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7100000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8100000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    let first = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("first request should pass");
    let second = daemon
        .sign_for_agent(request)
        .await
        .expect("identical replay should recover the original signature");
    assert_eq!(second, first);
}

#[tokio::test]
async fn sign_request_reuse_with_different_payload_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7100000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8100000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    daemon
        .sign_for_agent(request.clone())
        .await
        .expect("first request should pass");

    let mut replay = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7100000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8100000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 2,
        },
    );
    replay.request_id = request.request_id;

    let err = daemon
        .sign_for_agent(replay)
        .await
        .expect_err("mismatched replay must fail");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn signer_failure_does_not_consume_request_id() {
    let daemon = InMemoryDaemon::new(
        FlakySignerBackend::fail_first_payload(SignerError::Internal(
            "simulated signer timeout".to_string(),
        )),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7400000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8400000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    let err = daemon
        .sign_for_agent(request.clone())
        .await
        .expect_err("first signing attempt should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Internal(message))
            if message == "simulated signer timeout"
    ));

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("same request id should remain retryable after signer failure");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");

    let replay = daemon
        .sign_for_agent(request)
        .await
        .expect("successful request ids should remain idempotent after retry");
    assert_eq!(replay, signature);
}

#[tokio::test]
async fn expired_request_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7200000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8200000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );
    request.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("expired request should fail");
    assert!(matches!(err, DaemonError::RequestExpired));
}

#[tokio::test]
async fn future_requested_at_beyond_allowed_clock_skew_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let now = time::OffsetDateTime::now_utc();
    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7300000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8300000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );
    request.requested_at = now + time::Duration::seconds(31);
    request.expires_at = request.requested_at + time::Duration::minutes(2);

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("future-dated request must fail");
    assert!(matches!(err, DaemonError::InvalidRequestTimestamps));
}

#[tokio::test]
async fn request_ttl_longer_than_max_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let now = time::OffsetDateTime::now_utc();
    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7400000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8400000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );
    request.requested_at = now;
    request.expires_at = now + time::Duration::minutes(6);

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("overlong request ttl must fail");
    assert!(matches!(err, DaemonError::InvalidRequestTimestamps));
}

#[tokio::test]
async fn payload_action_mismatch_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let token = "0x9000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let declared_action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 10,
    };
    let mut request = sign_request(&agent_credentials, declared_action.clone());
    request.payload = to_vec(&AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 99,
    })
    .expect("payload");
    request.action = declared_action;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("mismatched payload/action must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn malformed_payload_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let token = "0x9100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 1,
        },
    );
    request.payload = b"not-json".to_vec();

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("malformed payload must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn payload_with_extra_fields_is_rejected() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let token = "0x9100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 1,
    };
    let mut request = sign_request(&agent_credentials, action.clone());
    request.payload = format!(
        "{{\"kind\":\"Transfer\",\"token\":\"{}\",\"to\":\"{}\",\"amount_wei\":\"1\",\"unexpected\":\"x\"}}",
        token.as_str(),
        recipient.as_str()
    )
    .into_bytes();
    request.action = action;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("non-canonical payload must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn oversized_payload_is_rejected() {
    let config = DaemonConfig {
        max_sign_payload_bytes: 64,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), config).expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let token = "0x9100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 1,
        },
    );
    request.payload = vec![b'a'; 65];

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("oversized payload must fail");
    assert!(matches!(
        err,
        DaemonError::PayloadTooLarge { max_bytes: 64 }
    ));
}

#[tokio::test]
async fn replay_id_tracking_limit_blocks_new_requests_until_expired_entries_are_pruned() {
    let daemon = InMemoryDaemon::new(
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_tracked_replay_ids: 1,
            ..DaemonConfig::default()
        },
    )
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

    let first_request_id = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc();
    daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: first_request_id,
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reserve");

    let next_now = time::OffsetDateTime::now_utc();
    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: next_now,
            expires_at: next_now + time::Duration::minutes(2),
        })
        .await
        .expect_err("second request should exceed replay tracking limit");
    assert!(matches!(
        err,
        DaemonError::TooManyTrackedReplayIds { max_tracked: 1 }
    ));

    daemon.replay_ids.write().expect("replay ids write").insert(
        first_request_id,
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );

    let recovery_now = time::OffsetDateTime::now_utc();
    let recovered = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: recovery_now,
            expires_at: recovery_now + time::Duration::minutes(2),
        })
        .await
        .expect("expired replay entry should free capacity");
    assert_eq!(recovered.nonce, 1);
}
