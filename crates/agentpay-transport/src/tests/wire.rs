//! Tests for frame encoding limits and the daemon error wire mirror.

use std::time::Duration;

use agentpay_domain::ManualApprovalStatus;
use agentpay_policy::PolicyError;
use agentpay_signer::SignerError;
use agentpay_signerd::DaemonError;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::error::UnixTransportError;
use agentpay_api::WireDaemonError;

use crate::wire::{read_frame, write_frame, WireRequest, MAX_WIRE_BODY_BYTES};

#[tokio::test(flavor = "current_thread")]
async fn write_and_read_frame_cover_protocol_and_serialization_errors() {
    let (mut writer, mut reader) = UnixStream::pair().expect("stream pair");
    let message = WireRequest {
        body_json: "{\"ok\":true}".to_string(),
    };
    write_frame(&mut writer, &message, Duration::from_secs(2))
        .await
        .expect("write frame");
    let decoded: WireRequest = read_frame(&mut reader, Duration::from_secs(2))
        .await
        .expect("read frame");
    assert_eq!(decoded.body_json, message.body_json);

    let oversized = WireRequest {
        body_json: "x".repeat(MAX_WIRE_BODY_BYTES + 1),
    };
    let err = write_frame(&mut writer, &oversized, Duration::from_secs(2))
        .await
        .expect_err("oversized write");
    assert!(
        matches!(err, UnixTransportError::Protocol(message) if message.contains("wire body exceeds max bytes"))
    );

    let (mut invalid_writer, mut invalid_reader) = UnixStream::pair().expect("stream pair");
    invalid_writer
        .write_all(&((MAX_WIRE_BODY_BYTES as u32) + 1).to_be_bytes())
        .await
        .expect("write length");
    let err = read_frame::<WireRequest>(&mut invalid_reader, Duration::from_secs(2))
        .await
        .expect_err("oversized read");
    assert!(
        matches!(err, UnixTransportError::Protocol(message) if message.contains("wire frame exceeds max bytes"))
    );

    let (mut malformed_writer, mut malformed_reader) = UnixStream::pair().expect("stream pair");
    malformed_writer
        .write_all(&(4u32).to_be_bytes())
        .await
        .expect("write length");
    malformed_writer
        .write_all(b"nope")
        .await
        .expect("write body");
    let err = read_frame::<WireRequest>(&mut malformed_reader, Duration::from_secs(2))
        .await
        .expect_err("malformed read");
    assert!(matches!(err, UnixTransportError::Serialization(_)));
}

#[test]
fn wire_body_cap_is_256_kib() {
    assert_eq!(MAX_WIRE_BODY_BYTES, 256 * 1024);
}

#[test]
fn wire_daemon_error_roundtrip_covers_all_variants() {
    let manual_approval_id = Uuid::new_v4();
    let unknown_vault_key = Uuid::new_v4();
    let unknown_agent_key = Uuid::new_v4();
    let unknown_policy = Uuid::new_v4();
    let unknown_approval = Uuid::new_v4();
    let unknown_reservation = Uuid::new_v4();

    let cases = vec![
        (
            DaemonError::AuthenticationFailed,
            DaemonError::AuthenticationFailed.to_string(),
        ),
        (
            DaemonError::UnknownLease,
            DaemonError::UnknownLease.to_string(),
        ),
        (
            DaemonError::InvalidLease,
            DaemonError::InvalidLease.to_string(),
        ),
        (
            DaemonError::TooManyActiveLeases,
            DaemonError::TooManyActiveLeases.to_string(),
        ),
        (
            DaemonError::AdminAuthenticationRequired,
            DaemonError::AdminAuthenticationRequired.to_string(),
        ),
        (
            DaemonError::RootPeerRequired,
            DaemonError::RootPeerRequired.to_string(),
        ),
        (
            DaemonError::UnknownAdminCredential(unknown_policy),
            DaemonError::UnknownAdminCredential(unknown_policy).to_string(),
        ),
        (
            DaemonError::InvalidAdminCredential("bad key".to_string()),
            DaemonError::InvalidAdminCredential("bad key".to_string()).to_string(),
        ),
        (
            DaemonError::TooManyAdminCredentials { max: 8 },
            DaemonError::TooManyAdminCredentials { max: 8 }.to_string(),
        ),
        (
            DaemonError::InvalidAdminChallenge,
            DaemonError::InvalidAdminChallenge.to_string(),
        ),
        (
            DaemonError::InvalidAdminChallengePurpose("purpose".to_string()),
            DaemonError::InvalidAdminChallengePurpose("purpose".to_string()).to_string(),
        ),
        (
            DaemonError::TooManyPendingAdminChallenges { max: 64 },
            DaemonError::TooManyPendingAdminChallenges { max: 64 }.to_string(),
        ),
        (
            DaemonError::AdminCredentialLocked {
                credential_id: unknown_policy,
            },
            DaemonError::AdminCredentialLocked {
                credential_id: unknown_policy,
            }
            .to_string(),
        ),
        (
            DaemonError::UnknownVaultKey(unknown_vault_key),
            DaemonError::UnknownVaultKey(unknown_vault_key).to_string(),
        ),
        (
            DaemonError::UnknownAgentKey(unknown_agent_key),
            DaemonError::UnknownAgentKey(unknown_agent_key).to_string(),
        ),
        (
            DaemonError::UnknownPolicy(unknown_policy),
            DaemonError::UnknownPolicy(unknown_policy).to_string(),
        ),
        (
            DaemonError::UnknownManualApprovalRequest(unknown_approval),
            DaemonError::UnknownManualApprovalRequest(unknown_approval).to_string(),
        ),
        (
            DaemonError::AgentAuthenticationFailed,
            DaemonError::AgentAuthenticationFailed.to_string(),
        ),
        (
            DaemonError::PayloadActionMismatch,
            DaemonError::PayloadActionMismatch.to_string(),
        ),
        (
            DaemonError::PayloadTooLarge { max_bytes: 1024 },
            DaemonError::PayloadTooLarge { max_bytes: 1024 }.to_string(),
        ),
        (
            DaemonError::InvalidRequestTimestamps,
            DaemonError::InvalidRequestTimestamps.to_string(),
        ),
        (
            DaemonError::RequestExpired,
            DaemonError::RequestExpired.to_string(),
        ),
        (
            DaemonError::RequestReplayDetected,
            DaemonError::RequestReplayDetected.to_string(),
        ),
        (
            DaemonError::TooManyTrackedReplayIds { max_tracked: 32 },
            DaemonError::TooManyTrackedReplayIds { max_tracked: 32 }.to_string(),
        ),
        (
            DaemonError::InvalidPolicyAttachment("attachment".to_string()),
            DaemonError::InvalidPolicyAttachment("attachment".to_string()).to_string(),
        ),
        (
            DaemonError::InvalidNonceReservation("nonce".to_string()),
            DaemonError::InvalidNonceReservation("nonce".to_string()).to_string(),
        ),
        (
            DaemonError::TooManyActiveNonceReservations { max_active: 64 },
            DaemonError::TooManyActiveNonceReservations { max_active: 64 }.to_string(),
        ),
        (
            DaemonError::NonceSkipTooLarge {
                requested_skip: 4096,
                max_skip: 1024,
            },
            DaemonError::NonceSkipTooLarge {
                requested_skip: 4096,
                max_skip: 1024,
            }
            .to_string(),
        ),
        (
            DaemonError::UnknownNonceReservation(unknown_reservation),
            DaemonError::UnknownNonceReservation(unknown_reservation).to_string(),
        ),
        (
            DaemonError::MissingNonceReservation {
                chain_id: 1,
                nonce: 7,
            },
            DaemonError::MissingNonceReservation {
                chain_id: 1,
                nonce: 7,
            }
            .to_string(),
        ),
        (
            DaemonError::InvalidPolicy("policy".to_string()),
            DaemonError::InvalidPolicy("policy".to_string()).to_string(),
        ),
        (
            DaemonError::InvalidAction("action".to_string()),
            DaemonError::InvalidAction("action".to_string()).to_string(),
        ),
        (
            DaemonError::ManualApprovalRequired {
                approval_request_id: manual_approval_id,
            },
            DaemonError::ManualApprovalRequired {
                approval_request_id: manual_approval_id,
            }
            .to_string(),
        ),
        (
            DaemonError::ManualApprovalRejected {
                approval_request_id: manual_approval_id,
            },
            DaemonError::ManualApprovalRejected {
                approval_request_id: manual_approval_id,
            }
            .to_string(),
        ),
        (
            DaemonError::ManualApprovalRequestNotPending {
                approval_request_id: manual_approval_id,
                status: ManualApprovalStatus::Approved,
            },
            DaemonError::ManualApprovalRequestNotPending {
                approval_request_id: manual_approval_id,
                status: ManualApprovalStatus::Approved,
            }
            .to_string(),
        ),
        (
            DaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id: unknown_agent_key,
                max_pending: 64,
            },
            DaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id: unknown_agent_key,
                max_pending: 64,
            }
            .to_string(),
        ),
        (
            DaemonError::Policy(PolicyError::NoAttachedPolicies),
            DaemonError::Policy(PolicyError::NoAttachedPolicies).to_string(),
        ),
        (
            DaemonError::Signer(SignerError::InvalidPrivateKey),
            DaemonError::Signer(SignerError::InvalidPrivateKey).to_string(),
        ),
        (
            DaemonError::InvalidConfig("config".to_string()),
            DaemonError::InvalidConfig("config".to_string()).to_string(),
        ),
        (
            DaemonError::Transport("transport".to_string()),
            DaemonError::Transport("transport".to_string()).to_string(),
        ),
        (
            DaemonError::Persistence("persistence".to_string()),
            DaemonError::Persistence("persistence".to_string()).to_string(),
        ),
        (
            DaemonError::LockPoisoned,
            DaemonError::LockPoisoned.to_string(),
        ),
    ];

    for (original, expected_message) in cases {
        let wire = WireDaemonError::from(original);
        let recovered = DaemonError::from(wire);
        assert_eq!(recovered.to_string(), expected_message);
    }
}
