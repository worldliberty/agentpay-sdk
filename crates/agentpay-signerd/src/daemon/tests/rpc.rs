//! RPC envelope redaction, zeroization, and dispatch.

use agentpay_api::rpc::{
    AddPolicyParams, BeginAdminChallengeParams, CompleteAdminChallengeParams, CreateAgentKeyParams,
    CreateVaultKeyParams, DecideManualApprovalRequestParams, DisablePolicyParams,
    EnrollAdminCredentialParams, EvaluateForAgentParams, ExplainForAgentParams,
    ExportWalletBackupParams, ListAdminCredentialsParams, ListManualApprovalRequestsParams,
    ListPoliciesParams, ListPolicySummariesParams, ReleaseNonceParams, ReserveNonceParams,
    RevokeAdminCredentialParams, RevokeAdminLeaseParams, RevokeAgentKeyParams,
    RotateAgentAuthTokenParams, SetSpendingLimitsParams, SignForAgentParams,
};
use agentpay_domain::{
    AdminAuth, AdminCredential, AdminSession, AgentAction, AgentCredentials,
    ManualApprovalDecision, NonceReleaseRequest, NonceReservationRequest, PolicyAttachment,
    SignRequest, Signature,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    admin_public_key_hex, policy_all_per_tx, sample_admin_lease, sample_agent_credentials,
    sample_manual_approval_request, sample_nonce_reservation, sample_policy_evaluation,
    sample_policy_explanation, sample_session, sample_vault_key, sign_request,
    test_admin_signing_key,
};
use crate::{DaemonConfig, InMemoryDaemon, PolicySummary, RequestContext};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};

#[test]
fn daemon_rpc_request_debug_redacts_lease_secret() {
    let session = sample_session();
    let AdminAuth::Lease(lease) = &session else {
        panic!("lease session");
    };
    let secret = lease.lease_secret.to_string();
    let rendered = format!(
        "{:?}",
        DaemonRpcRequest::ListPolicies(ListPoliciesParams { auth: session })
    );

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains(&secret));
}

#[test]
fn daemon_rpc_response_debug_redacts_auth_token() {
    let rendered = format!(
        "{:?}",
        DaemonRpcResponse::AuthToken("super-secret-token".to_string())
    );

    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-token"));
}

#[test]
fn daemon_rpc_request_zeroize_secrets_clears_nested_secret_material() {
    let now = time::OffsetDateTime::now_utc();
    let mut admin_request = DaemonRpcRequest::CreateAgentKey(CreateAgentKeyParams {
        auth: AdminAuth::Lease(AdminSession {
            lease_id: Uuid::new_v4(),
            lease_secret: "super-secret-lease".to_string().into(),
        }),
        vault_key_id: Uuid::new_v4(),
        attachment: PolicyAttachment::AllPolicies,
    });
    admin_request.zeroize_secrets();
    match &admin_request {
        DaemonRpcRequest::CreateAgentKey(CreateAgentKeyParams {
            auth: AdminAuth::Lease(session),
            ..
        }) => {
            assert!(session
                .lease_secret
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }

    let mut sign_request = DaemonRpcRequest::SignForAgent(SignForAgentParams {
        request: SignRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "agent-secret-token".to_string().into(),
            payload: vec![1, 2, 3, 4],
            action: AgentAction::Approve {
                token: "0x1111111111111111111111111111111111111111"
                    .parse()
                    .expect("token"),
                spender: "0x2222222222222222222222222222222222222222"
                    .parse()
                    .expect("spender"),
                amount_wei: 42,
                chain_id: 1,
            },
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        },
    });
    sign_request.zeroize_secrets();
    match &sign_request {
        DaemonRpcRequest::SignForAgent(SignForAgentParams { request }) => {
            assert!(request
                .agent_auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
            assert!(request.payload.iter().all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }

    let mut reserve_nonce = DaemonRpcRequest::ReserveNonce(ReserveNonceParams {
        request: NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "nonce-secret".to_string().into(),
            chain_id: 1,
            min_nonce: 7,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        },
    });
    reserve_nonce.zeroize_secrets();
    match &reserve_nonce {
        DaemonRpcRequest::ReserveNonce(ReserveNonceParams { request }) => {
            assert!(request
                .agent_auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }
}

#[test]
fn daemon_rpc_response_zeroize_secrets_clears_auth_tokens() {
    let now = time::OffsetDateTime::now_utc();
    let mut response = DaemonRpcResponse::AgentCredentials(AgentCredentials {
        agent_key: agentpay_domain::AgentKey {
            id: Uuid::new_v4(),
            vault_key_id: Uuid::new_v4(),
            policies: PolicyAttachment::AllPolicies,
            created_at: now,
        },
        auth_token: "agent-secret-token".to_string().into(),
    });
    response.zeroize_secrets();
    match &response {
        DaemonRpcResponse::AgentCredentials(credentials) => {
            assert!(credentials
                .auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected response variant: {other:?}"),
    }

    let mut rotated = DaemonRpcResponse::AuthToken("rotated-secret-token".to_string());
    rotated.zeroize_secrets();
    match &rotated {
        DaemonRpcResponse::AuthToken(token) => {
            assert!(token.as_bytes().iter().all(|byte| *byte == 0));
        }
        other => panic!("unexpected response variant: {other:?}"),
    }
}

#[test]
fn daemon_rpc_request_debug_covers_all_variants() {
    let session = sample_session();
    let credentials = sample_agent_credentials();
    let request = sign_request(
        &credentials,
        AgentAction::TransferNative {
            chain_id: 1,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("recipient"),
            amount_wei: 7,
        },
    );
    let nonce_request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce: 9,
        exact_nonce: false,
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
    };
    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        reservation_id: Uuid::new_v4(),
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
    };
    let requests = vec![
        DaemonRpcRequest::EnrollAdminCredential(EnrollAdminCredentialParams {
            public_key_sec1_hex: "02".repeat(33),
            label: "Mac".to_string(),
        }),
        DaemonRpcRequest::ListAdminCredentials(ListAdminCredentialsParams {
            auth: session.clone(),
        }),
        DaemonRpcRequest::RevokeAdminCredential(RevokeAdminCredentialParams {
            auth: session.clone(),
            id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::BeginAdminChallenge(BeginAdminChallengeParams {
            credential_id: Uuid::new_v4(),
            purpose: "admin-session".to_string(),
        }),
        DaemonRpcRequest::CompleteAdminChallenge(CompleteAdminChallengeParams {
            challenge_id: Uuid::new_v4(),
            signature_der_hex: "30".to_string(),
        }),
        DaemonRpcRequest::RevokeAdminLease(RevokeAdminLeaseParams {
            auth: session.clone(),
            lease_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::AddPolicy(AddPolicyParams {
            auth: session.clone(),
            policy: policy_all_per_tx(100),
        }),
        DaemonRpcRequest::ListPolicies(ListPoliciesParams {
            auth: session.clone(),
        }),
        DaemonRpcRequest::ListPolicySummaries(ListPolicySummariesParams {
            auth: session.clone(),
        }),
        DaemonRpcRequest::DisablePolicy(DisablePolicyParams {
            auth: session.clone(),
            policy_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::CreateVaultKey(CreateVaultKeyParams {
            auth: session.clone(),
            request: KeyCreateRequest::Generate,
        }),
        DaemonRpcRequest::CreateAgentKey(CreateAgentKeyParams {
            auth: session.clone(),
            vault_key_id: Uuid::new_v4(),
            attachment: PolicyAttachment::AllPolicies,
        }),
        DaemonRpcRequest::ExportWalletBackup(ExportWalletBackupParams {
            auth: session.clone(),
            vault_key_id: None,
            passphrase: "a long enough passphrase".to_string().into(),
        }),
        DaemonRpcRequest::RotateAgentAuthToken(RotateAgentAuthTokenParams {
            auth: session.clone(),
            agent_key_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::RevokeAgentKey(RevokeAgentKeyParams {
            auth: session.clone(),
            agent_key_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::ListManualApprovalRequests(ListManualApprovalRequestsParams {
            auth: session.clone(),
        }),
        DaemonRpcRequest::DecideManualApprovalRequest(DecideManualApprovalRequestParams {
            auth: session.clone(),
            approval_request_id: Uuid::new_v4(),
            decision: ManualApprovalDecision::Reject,
            rejection_reason: Some("denied".to_string()),
        }),
        DaemonRpcRequest::EvaluateForAgent(EvaluateForAgentParams {
            request: request.clone(),
        }),
        DaemonRpcRequest::ExplainForAgent(ExplainForAgentParams {
            request: request.clone(),
        }),
        DaemonRpcRequest::ReserveNonce(ReserveNonceParams {
            request: nonce_request,
        }),
        DaemonRpcRequest::ReleaseNonce(ReleaseNonceParams {
            request: release_request,
        }),
        DaemonRpcRequest::SignForAgent(SignForAgentParams { request }),
    ];

    for request in requests {
        let rendered = format!("{request:?}");
        assert!(!rendered.is_empty());
    }
}

#[test]
fn daemon_rpc_request_zeroize_covers_remaining_admin_and_agent_variants() {
    let session = sample_session();
    let credentials = sample_agent_credentials();
    let request = sign_request(
        &credentials,
        AgentAction::TransferNative {
            chain_id: 1,
            to: "0x1111111111111111111111111111111111111111"
                .parse()
                .expect("recipient"),
            amount_wei: 7,
        },
    );

    let mut admin_variants = vec![
        DaemonRpcRequest::SetSpendingLimits(SetSpendingLimitsParams {
            auth: session.clone(),
            agent_key_id: Uuid::new_v4(),
            limits: Vec::new(),
        }),
        DaemonRpcRequest::ListManualApprovalRequests(ListManualApprovalRequestsParams {
            auth: session.clone(),
        }),
        DaemonRpcRequest::DecideManualApprovalRequest(DecideManualApprovalRequestParams {
            auth: session.clone(),
            approval_request_id: Uuid::new_v4(),
            decision: ManualApprovalDecision::Approve,
            rejection_reason: None,
        }),
    ];
    for request in &mut admin_variants {
        request.zeroize_secrets();
        match request {
            DaemonRpcRequest::SetSpendingLimits(SetSpendingLimitsParams {
                auth: AdminAuth::Lease(session),
                ..
            })
            | DaemonRpcRequest::ListManualApprovalRequests(ListManualApprovalRequestsParams {
                auth: AdminAuth::Lease(session),
            })
            | DaemonRpcRequest::DecideManualApprovalRequest(DecideManualApprovalRequestParams {
                auth: AdminAuth::Lease(session),
                ..
            }) => {
                assert!(session
                    .lease_secret
                    .as_bytes()
                    .iter()
                    .all(|byte| *byte == 0));
            }
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    let mut explain = DaemonRpcRequest::ExplainForAgent(ExplainForAgentParams { request });
    explain.zeroize_secrets();
    match explain {
        DaemonRpcRequest::ExplainForAgent(ExplainForAgentParams { request }) => {
            assert!(request
                .agent_auth_token
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0));
        }
        other => panic!("unexpected request variant: {other:?}"),
    }
}

#[test]
fn daemon_rpc_response_debug_and_zeroize_cover_remaining_variants() {
    let lease = sample_admin_lease();
    let credential = AdminCredential {
        id: Uuid::new_v4(),
        public_key_sec1_hex: admin_public_key_hex(&test_admin_signing_key()),
        label: "Mac".to_string(),
        created_at: time::OffsetDateTime::now_utc(),
    };
    let manual_request = sample_manual_approval_request();
    let reservation = sample_nonce_reservation();
    let responses = vec![
        DaemonRpcResponse::Unit,
        DaemonRpcResponse::AdminCredential(credential.clone()),
        DaemonRpcResponse::AdminCredentials(vec![credential]),
        DaemonRpcResponse::Policies(vec![policy_all_per_tx(100)]),
        DaemonRpcResponse::PolicySummaries(vec![PolicySummary {
            id: Uuid::new_v4(),
            enabled: true,
        }]),
        DaemonRpcResponse::PolicyEvaluation(sample_policy_evaluation()),
        DaemonRpcResponse::PolicyExplanation(sample_policy_explanation()),
        DaemonRpcResponse::VaultKey(sample_vault_key()),
        DaemonRpcResponse::ManualApprovalRequests(vec![manual_request.clone()]),
        DaemonRpcResponse::ManualApprovalRequest(Box::new(manual_request)),
        DaemonRpcResponse::NonceReservation(reservation),
        DaemonRpcResponse::Signature(Signature::from_der(vec![1, 2, 3])),
    ];

    for response in responses {
        let rendered = format!("{response:?}");
        assert!(!rendered.is_empty());
    }

    let rendered = format!(
        "{:?}",
        DaemonRpcResponse::AgentCredentials(sample_agent_credentials())
    );
    assert!(rendered.contains("AgentCredentials"));

    let secret = lease.lease_secret.to_string();
    let mut lease_response = DaemonRpcResponse::AdminLease(lease);
    assert!(!format!("{lease_response:?}").contains(&secret));
    lease_response.zeroize_secrets();
    match &lease_response {
        DaemonRpcResponse::AdminLease(lease) => assert!(lease.lease_secret.is_empty()),
        other => panic!("unexpected response variant: {other:?}"),
    }
}

#[test]
fn admin_auth_defaults_to_peer_credentials_on_the_wire() {
    let request: DaemonRpcRequest =
        serde_json::from_str(r#"{"method":"ListPolicies","params":{}}"#).expect("parse");
    assert!(matches!(
        request,
        DaemonRpcRequest::ListPolicies(ListPoliciesParams {
            auth: AdminAuth::PeerCredentials
        })
    ));
    let encoded = serde_json::to_value(DaemonRpcRequest::ListPolicies(ListPoliciesParams {
        auth: AdminAuth::PeerCredentials,
    }))
    .expect("encode");
    assert_eq!(
        encoded,
        serde_json::json!({"method": "ListPolicies", "params": {"auth": "peer_credentials"}})
    );
    assert!(serde_json::from_str::<DaemonRpcRequest>(
        r#"{"method":"IssueLease","params":{"vault_password":"pw"}}"#
    )
    .is_err());
}

#[tokio::test]
async fn rpc_roundtrip_for_admin_credential_enrollment() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let public_key_sec1_hex = admin_public_key_hex(&test_admin_signing_key());

    let response = daemon
        .handle_rpc(
            &RequestContext::peer(0),
            DaemonRpcRequest::EnrollAdminCredential(EnrollAdminCredentialParams {
                public_key_sec1_hex,
                label: "Mac".to_string(),
            }),
        )
        .await
        .expect("rpc must succeed");

    let DaemonRpcResponse::AdminCredential(credential) = response else {
        panic!("unexpected rpc response");
    };
    let response = daemon
        .handle_rpc(
            &RequestContext::peer(0),
            DaemonRpcRequest::ListAdminCredentials(ListAdminCredentialsParams {
                auth: AdminAuth::PeerCredentials,
            }),
        )
        .await
        .expect("list");
    assert!(matches!(
        response,
        DaemonRpcResponse::AdminCredentials(credentials) if credentials == vec![credential]
    ));
}
