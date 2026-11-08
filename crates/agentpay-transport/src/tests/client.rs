//! Tests for `UnixDaemonClient`: round trips against a real server and
//! error mapping against fake one-shot servers.

use agentpay_api::rpc::ListPoliciesParams;
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, WireDaemonError};
use agentpay_domain::{AdminAuth, AdminLease, PolicyAttachment};
use agentpay_policy::PolicyDecision;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use agentpay_signerd::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};
use uuid::Uuid;

use super::{
    admin_public_key_hex, admin_signing_key, nonce_release_request, nonce_reservation_request,
    policy_all_per_tx, sign_admin_challenge, sign_request, singleton_allowed_set,
    spawn_one_shot_server, unique_socket_path,
};
use crate::client::UnixDaemonClient;
use crate::error::UnixTransportError;
use crate::server::UnixDaemonServer;
use crate::wire::WireResponse;

/// Starts a real server for `daemon` that admits the current euid as admin and agent.
pub(super) async fn spawn_daemon_server(
    label: &str,
    daemon: Arc<InMemoryDaemon<SoftwareSignerBackend>>,
) -> (
    UnixDaemonClient,
    tokio::task::JoinHandle<Result<(), UnixTransportError>>,
) {
    let socket_path = unique_socket_path(label);
    let server = UnixDaemonServer::bind(
        socket_path.clone(),
        singleton_allowed_set(nix::unistd::geteuid().as_raw()),
    )
    .await
    .expect("server");
    let server_task = tokio::spawn(async move {
        server
            .run_until_shutdown(daemon, std::future::pending::<()>())
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (
        UnixDaemonClient::new(socket_path, Duration::from_secs(2)),
        server_task,
    )
}

/// Enrolls the test key in-process (as setup does under sudo) and runs the
/// challenge flow over the socket, signing like the Secure Enclave helper.
pub(super) async fn lease_over_socket(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    client: &UnixDaemonClient,
) -> AdminLease {
    let key = admin_signing_key();
    let credential = daemon
        .enroll_admin_credential(admin_public_key_hex(&key), "Test Mac".to_string())
        .await
        .expect("enroll");
    let challenge = client
        .begin_admin_challenge(credential.id, "admin-session".to_string())
        .await
        .expect("challenge");
    client
        .complete_admin_challenge(
            challenge.challenge_id,
            sign_admin_challenge(&key, &challenge),
        )
        .await
        .expect("lease")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unix_round_trip_for_secure_enclave_style_admin_challenge() {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let (client, server_task) = spawn_daemon_server("challenge", daemon.clone()).await;

    if nix::unistd::geteuid().as_raw() != 0 {
        let err = client
            .list_policies(&AdminAuth::PeerCredentials)
            .await
            .expect_err("a non-root peer needs a lease");
        assert!(matches!(err, DaemonError::AdminAuthenticationRequired));
        let err = client
            .enroll_admin_credential(
                admin_public_key_hex(&admin_signing_key()),
                "Mac".to_string(),
            )
            .await
            .expect_err("only root peers may enroll");
        assert!(matches!(err, DaemonError::RootPeerRequired));
    }

    let lease = lease_over_socket(&daemon, &client).await;
    assert_eq!(lease.lease_id.get_version_num(), 4);
    let credentials = client
        .list_admin_credentials(&lease.auth())
        .await
        .expect("lease authorizes admin calls over the socket");
    assert_eq!(credentials.len(), 1);

    let challenge = client
        .begin_admin_challenge(credentials[0].id, "admin-session".to_string())
        .await
        .expect("challenge");
    let other_key = p256::ecdsa::SigningKey::from_slice(&[0x24; 32]).expect("key");
    let err = client
        .complete_admin_challenge(
            challenge.challenge_id,
            sign_admin_challenge(&other_key, &challenge),
        )
        .await
        .expect_err("a signature from another key is rejected");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    client
        .revoke_admin_lease(&lease.auth(), lease.lease_id)
        .await
        .expect("revoke lease");
    let err = client
        .list_policies(&lease.auth())
        .await
        .expect_err("revoked lease");
    assert!(matches!(err, DaemonError::UnknownLease));

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unix_round_trip_for_full_key_manager_api_surface() {
    let socket_path = unique_socket_path("full-surface");
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let server = UnixDaemonServer::bind(
        socket_path.clone(),
        singleton_allowed_set(nix::unistd::geteuid().as_raw()),
    )
    .await
    .expect("server");
    let server_task = tokio::spawn({
        let daemon = daemon.clone();
        async move {
            server
                .run_until_shutdown(daemon, async {
                    std::future::pending::<()>().await;
                })
                .await
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));

    let lease = lease_over_socket(&daemon, &client).await;
    let session = lease.auth();

    let policy = policy_all_per_tx(100);
    client
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let policies = client.list_policies(&session).await.expect("list policies");
    assert_eq!(policies.len(), 1);
    assert!(policies[0].enabled);

    let vault_key = client
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("create vault key");
    let backup = client
        .export_wallet_backup(
            &session,
            Some(vault_key.id),
            "a long passphrase".to_string().into(),
        )
        .await
        .expect("export backup");
    let summary = client
        .verify_wallet_backup(
            &session,
            backup.backup_json,
            "a long passphrase".to_string().into(),
        )
        .await
        .expect("verify backup");
    assert_eq!(summary.matching_vault_key_id, Some(vault_key.id));

    let mut credentials = client
        .create_agent_key(&session, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("create agent key");

    let evaluation = client
        .evaluate_for_agent(sign_request(&credentials, 1))
        .await
        .expect("evaluate");
    assert_eq!(evaluation.evaluated_policy_ids, vec![policy.id]);

    let explanation = client
        .explain_for_agent(sign_request(&credentials, 1))
        .await
        .expect("explain");
    assert!(matches!(explanation.decision, PolicyDecision::Allow));

    let signature = client
        .sign_for_agent(sign_request(&credentials, 1))
        .await
        .expect("sign");
    assert!(!signature.bytes.is_empty());

    let reservation = client
        .reserve_nonce(nonce_reservation_request(&credentials, 7))
        .await
        .expect("reserve nonce");
    assert_eq!(reservation.nonce, 7);
    client
        .release_nonce(nonce_release_request(
            &credentials,
            reservation.reservation_id,
        ))
        .await
        .expect("release nonce");

    let rotated_token = client
        .rotate_agent_auth_token(&session, credentials.agent_key.id)
        .await
        .expect("rotate token");
    credentials.auth_token = rotated_token.into();

    let approvals = client
        .list_manual_approval_requests(&session)
        .await
        .expect("list approvals");
    assert!(approvals.is_empty());

    client
        .disable_policy(&session, policy.id)
        .await
        .expect("disable policy");
    let disabled = client.list_policies(&session).await.expect("list disabled");
    assert_eq!(disabled.len(), 1);
    assert!(!disabled[0].enabled);

    client
        .revoke_agent_key(&session, credentials.agent_key.id)
        .await
        .expect("revoke agent");
    let err = client
        .sign_for_agent(sign_request(&credentials, 1))
        .await
        .expect_err("revoked agent must fail");
    assert!(
        matches!(
            err,
            DaemonError::UnknownAgentKey(id) if id == credentials.agent_key.id
        ) || matches!(err, DaemonError::AgentAuthenticationFailed)
    );

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_rejects_unexpected_daemon_euid() {
    let socket_path = unique_socket_path("peer-euid");
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let allowed_euid = nix::unistd::geteuid().as_raw();
    let server = UnixDaemonServer::bind(socket_path.clone(), singleton_allowed_set(allowed_euid))
        .await
        .expect("server");
    let server_task = tokio::spawn({
        let daemon = daemon.clone();
        async move {
            server
                .run_until_shutdown(daemon, async {
                    std::future::pending::<()>().await;
                })
                .await
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let mismatched_expected_euid = allowed_euid.saturating_add(1);
    let client = UnixDaemonClient::new_with_expected_server_euid(
        socket_path.clone(),
        Duration::from_secs(2),
        mismatched_expected_euid,
    );
    let err = client
        .begin_admin_challenge(Uuid::new_v4(), "admin-session".to_string())
        .await
        .expect_err("must fail");
    assert!(
        err.to_string().contains("unauthorized peer euid"),
        "unexpected error: {err}"
    );

    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn call_rpc_surfaces_wire_daemon_errors_and_transport_fallbacks() {
    let socket_path = unique_socket_path("wire-error");
    let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));

    let daemon_task = spawn_one_shot_server(
        socket_path.clone(),
        WireResponse {
            ok: false,
            body_json: serde_json::to_string(&WireDaemonError::UnknownLease)
                .expect("serialize daemon error"),
        },
    )
    .await;
    let err = client
        .call_rpc(DaemonRpcRequest::ListPolicies(ListPoliciesParams {
            auth: AdminAuth::PeerCredentials,
        }))
        .await
        .expect_err("daemon error");
    assert!(matches!(
        err,
        UnixTransportError::Daemon(DaemonError::UnknownLease)
    ));
    daemon_task.await.expect("daemon task");

    let transport_task = spawn_one_shot_server(
        socket_path,
        WireResponse {
            ok: false,
            body_json: "plain transport failure".to_string(),
        },
    )
    .await;
    let err = client
        .call_rpc(DaemonRpcRequest::ListPolicies(ListPoliciesParams {
            auth: AdminAuth::PeerCredentials,
        }))
        .await
        .expect_err("transport fallback");
    assert!(matches!(
        err,
        UnixTransportError::Daemon(DaemonError::Transport(message))
            if message == "plain transport failure"
    ));
    transport_task.await.expect("transport task");
}

#[tokio::test(flavor = "current_thread")]
async fn typed_calls_reject_unexpected_response_types() {
    let socket_path = unique_socket_path("unexpected-response");
    let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));
    let response_task = spawn_one_shot_server(
        socket_path,
        WireResponse {
            ok: true,
            body_json: serde_json::to_string(&DaemonRpcResponse::Unit).expect("serialize response"),
        },
    )
    .await;

    let err = client
        .complete_admin_challenge(Uuid::new_v4(), "00".to_string())
        .await
        .expect_err("wrong response type");
    assert!(
        matches!(err, DaemonError::Transport(message) if message == "unexpected response type")
    );

    response_task.await.expect("response task");
}
