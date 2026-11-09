//! Agent token authentication and the admin authorization gate (root peer,
//! in-process caller, or admin lease).

use agentpay_api::rpc::{
    AddPolicyParams, CreateAgentKeyParams, CreateVaultKeyParams, DisablePolicyParams,
    ExportWalletBackupParams, ListAdminCredentialsParams, ListManualApprovalRequestsParams,
    ListPoliciesParams, ListPolicySummariesParams, ListSpendingLimitsParams, ListWalletsParams,
    RevokeAdminCredentialParams, RevokeAdminLeaseParams, RevokeAgentKeyParams,
    RotateAgentAuthTokenParams, SolanaPublicKeyParams,
};
use agentpay_domain::{AdminAuth, AgentAction, EvmAddress, PolicyAttachment, SignRequest};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use serde_json::to_vec;
use uuid::Uuid;

use super::support::{
    policy_all_per_tx, sample_session, sign_request, test_state_secret, unique_state_path,
    ExportCountingSignerBackend,
};
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
    RequestContext,
};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};

const NON_ROOT_EUID: u32 = 501;

#[tokio::test]
async fn wrong_agent_auth_token_is_rejected() {
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
    let mut agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    agent_credentials.auth_token = "wrong-token".to_string().into();

    let token = "0x7000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 1,
            },
        ))
        .await
        .expect_err("must reject bad auth token");

    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test]
async fn oversized_agent_auth_token_is_rejected() {
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
    let mut agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    agent_credentials.auth_token = "a".repeat((16 * 1024) + 1).into();

    let token = "0x7000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 1,
            },
        ))
        .await
        .expect_err("must reject oversized auth token");

    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test]
async fn unknown_agent_key_is_not_disclosed_in_sign_api() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let token = "0x7100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let request = SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "random-token".to_string().into(),
        payload: to_vec(&AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 1,
        })
        .expect("payload"),
        action: AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 1,
        },
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("unknown key must not leak key existence");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test]
async fn peer_credentials_are_honored_only_for_root_and_in_process_callers() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let list = || {
        DaemonRpcRequest::ListPolicies(ListPoliciesParams {
            auth: AdminAuth::PeerCredentials,
        })
    };

    let err = daemon
        .handle_rpc(&RequestContext::peer(NON_ROOT_EUID), list())
        .await
        .expect_err("non-root peer without a lease must be rejected");
    assert!(matches!(err, DaemonError::AdminAuthenticationRequired));

    let response = daemon
        .handle_rpc(&RequestContext::peer(0), list())
        .await
        .expect("root peer is authorized by its credentials");
    assert!(matches!(response, DaemonRpcResponse::Policies(policies) if policies.is_empty()));

    let response = daemon
        .handle_rpc(&RequestContext::in_process(), list())
        .await
        .expect("in-process caller is root-equivalent");
    assert!(matches!(response, DaemonRpcResponse::Policies(_)));
    daemon
        .list_policies(&AdminAuth::PeerCredentials)
        .await
        .expect("trait impl runs in-process");
}

#[tokio::test]
async fn privileged_rpcs_reject_non_root_peers_without_a_lease() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let key = daemon
        .create_vault_key(&AdminAuth::PeerCredentials, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let auth = AdminAuth::PeerCredentials;
    let requests = vec![
        DaemonRpcRequest::AddPolicy(AddPolicyParams {
            auth: auth.clone(),
            policy: policy_all_per_tx(1),
        }),
        DaemonRpcRequest::ListPolicySummaries(ListPolicySummariesParams { auth: auth.clone() }),
        DaemonRpcRequest::DisablePolicy(DisablePolicyParams {
            auth: auth.clone(),
            policy_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::CreateVaultKey(CreateVaultKeyParams {
            auth: auth.clone(),
            request: KeyCreateRequest::Generate,
        }),
        DaemonRpcRequest::CreateAgentKey(CreateAgentKeyParams {
            auth: auth.clone(),
            vault_key_id: key.id,
            attachment: PolicyAttachment::AllPolicies,
        }),
        DaemonRpcRequest::ListWallets(ListWalletsParams { auth: auth.clone() }),
        DaemonRpcRequest::ExportWalletBackup(ExportWalletBackupParams {
            auth: auth.clone(),
            vault_key_id: Some(key.id),
            passphrase: "a long enough passphrase".to_string().into(),
        }),
        DaemonRpcRequest::ListSpendingLimits(ListSpendingLimitsParams {
            auth: auth.clone(),
            agent_key_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::SolanaPublicKey(SolanaPublicKeyParams {
            auth: auth.clone(),
            vault_key_id: key.id,
        }),
        DaemonRpcRequest::RotateAgentAuthToken(RotateAgentAuthTokenParams {
            auth: auth.clone(),
            agent_key_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::RevokeAgentKey(RevokeAgentKeyParams {
            auth: auth.clone(),
            agent_key_id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::ListManualApprovalRequests(ListManualApprovalRequestsParams {
            auth: auth.clone(),
        }),
        DaemonRpcRequest::ListAdminCredentials(ListAdminCredentialsParams { auth: auth.clone() }),
        DaemonRpcRequest::RevokeAdminCredential(RevokeAdminCredentialParams {
            auth: auth.clone(),
            id: Uuid::new_v4(),
        }),
        DaemonRpcRequest::RevokeAdminLease(RevokeAdminLeaseParams {
            auth,
            lease_id: Uuid::new_v4(),
        }),
    ];
    for request in requests {
        let rendered = format!("{request:?}");
        let err = daemon
            .handle_rpc(&RequestContext::peer(NON_ROOT_EUID), request)
            .await
            .expect_err("non-root peer must be rejected");
        assert!(
            matches!(err, DaemonError::AdminAuthenticationRequired),
            "{rendered}: {err:?}"
        );
    }
}

#[tokio::test]
async fn privileged_calls_reject_unknown_leases_even_in_process() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let bad_session = sample_session();

    let err = daemon
        .add_policy(&bad_session, policy_all_per_tx(1))
        .await
        .expect_err("unknown lease must be rejected");
    assert!(matches!(err, DaemonError::UnknownLease));
    let err = daemon
        .create_vault_key(&bad_session, KeyCreateRequest::Generate)
        .await
        .expect_err("unknown lease must be rejected");
    assert!(matches!(err, DaemonError::UnknownLease));
    let err = daemon
        .list_manual_approval_requests(&bad_session)
        .await
        .expect_err("unknown lease must be rejected");
    assert!(matches!(err, DaemonError::UnknownLease));
}

#[tokio::test]
async fn failed_admin_authorization_never_snapshots_persistent_state() {
    let state_path = unique_state_path("auth-before-snapshot");
    let backend = ExportCountingSignerBackend::default();
    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        backend.clone(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("persistent daemon");
    let baseline = backend.export_calls();

    for request in [
        DaemonRpcRequest::AddPolicy(AddPolicyParams {
            auth: AdminAuth::PeerCredentials,
            policy: policy_all_per_tx(1),
        }),
        DaemonRpcRequest::CreateVaultKey(CreateVaultKeyParams {
            auth: AdminAuth::PeerCredentials,
            request: KeyCreateRequest::Generate,
        }),
    ] {
        daemon
            .handle_rpc(&RequestContext::peer(NON_ROOT_EUID), request)
            .await
            .expect_err("unauthorized write must fail");
    }
    assert_eq!(
        backend.export_calls(),
        baseline,
        "an unauthorized caller must never trigger a key-material snapshot"
    );

    daemon
        .handle_rpc(
            &RequestContext::peer(0),
            DaemonRpcRequest::AddPolicy(AddPolicyParams {
                auth: AdminAuth::PeerCredentials,
                policy: policy_all_per_tx(1),
            }),
        )
        .await
        .expect("root write succeeds");
    assert!(
        backend.export_calls() > baseline,
        "authorized writes snapshot and persist state"
    );

    let _ = std::fs::remove_file(&state_path);
}
