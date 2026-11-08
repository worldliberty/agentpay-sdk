//! Tests for `UnixDaemonServer`: binding, the accept loop, and per-connection authorization.

use agentpay_api::rpc::{EvaluateForAgentParams, ListPoliciesParams};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use agentpay_domain::AdminAuth;
use agentpay_signer::SoftwareSignerBackend;
use agentpay_signerd::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};
use tokio::net::UnixStream;
use uuid::Uuid;

use super::{dummy_agent_request, singleton_allowed_set, socket_mode, unique_socket_path};
use crate::client::UnixDaemonClient;
use crate::error::UnixTransportError;
use crate::server::{
    handle_connection, next_accept_backoff, UnixDaemonServer, ACCEPT_BACKOFF_MAX,
    ACCEPT_BACKOFF_MIN, MAX_CONCURRENT_CONNECTIONS,
};
use crate::service::SignerdService;
use crate::wire::{read_frame, write_frame, WireRequest, WireResponse};

#[tokio::test(flavor = "current_thread")]
async fn bind_rejects_empty_admin_and_agent_allowlists() {
    let socket_path = unique_socket_path("empty-allowlists");
    let err = match UnixDaemonServer::bind_with_allowed_peer_euids(
        socket_path.clone(),
        BTreeSet::new(),
        singleton_allowed_set(nix::unistd::geteuid().as_raw()),
    )
    .await
    {
        Ok(_) => panic!("empty admin allowlist must fail"),
        Err(err) => err,
    };
    assert!(
        matches!(err, UnixTransportError::Protocol(message) if message.contains("allowed admin peer euid set must not be empty"))
    );

    let err = match UnixDaemonServer::bind_with_allowed_peer_euids(
        socket_path,
        singleton_allowed_set(nix::unistd::geteuid().as_raw()),
        BTreeSet::new(),
    )
    .await
    {
        Ok(_) => panic!("empty agent allowlist must fail"),
        Err(err) => err,
    };
    assert!(
        matches!(err, UnixTransportError::Protocol(message) if message.contains("allowed agent peer euid set must not be empty"))
    );
}

#[test]
fn next_accept_backoff_doubles_until_capped() {
    assert_eq!(
        next_accept_backoff(ACCEPT_BACKOFF_MIN),
        Duration::from_millis(100)
    );
    assert_eq!(
        next_accept_backoff(Duration::from_millis(400)),
        Duration::from_millis(800)
    );
    assert_eq!(
        next_accept_backoff(Duration::from_millis(800)),
        ACCEPT_BACKOFF_MAX
    );
    assert_eq!(next_accept_backoff(ACCEPT_BACKOFF_MAX), ACCEPT_BACKOFF_MAX);
    assert_eq!(next_accept_backoff(Duration::MAX), ACCEPT_BACKOFF_MAX);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn run_until_shutdown_serves_more_concurrent_clients_than_connection_permits() {
    let socket_path = unique_socket_path("concurrency");
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
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn({
        let daemon = daemon.clone();
        async move {
            server
                .run_until_shutdown(daemon, async {
                    let _ = shutdown_rx.await;
                })
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Twice as many clients as permits: the surplus must queue and be served
    // once earlier connections finish, never dropped or timed out.
    let client_count = MAX_CONCURRENT_CONNECTIONS * 2;
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..client_count {
        let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(20));
        clients.spawn(async move {
            client
                .complete_admin_challenge(Uuid::new_v4(), "00".to_string())
                .await
        });
    }
    let mut served = 0usize;
    while let Some(result) = clients.join_next().await {
        let outcome = result.expect("client task");
        assert!(
            matches!(outcome, Err(DaemonError::InvalidAdminChallenge)),
            "every client must reach the daemon: {outcome:?}"
        );
        served += 1;
    }
    assert_eq!(served, client_count);

    // The server keeps accepting after the burst.
    let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(5));
    let err = client
        .complete_admin_challenge(Uuid::new_v4(), "00".to_string())
        .await
        .expect_err("still reachable");
    assert!(matches!(err, DaemonError::InvalidAdminChallenge));

    let _ = shutdown_tx.send(());
    server_task
        .await
        .expect("server task")
        .expect("server exits cleanly after shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn run_until_shutdown_honors_ready_shutdown_and_exposes_socket_path() {
    let socket_path = unique_socket_path("ready-shutdown");
    let server = UnixDaemonServer::bind(
        socket_path.clone(),
        singleton_allowed_set(nix::unistd::geteuid().as_raw()),
    )
    .await
    .expect("server");
    assert_eq!(server.socket_path(), socket_path.as_path());

    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    server
        .run_until_shutdown(daemon, async {})
        .await
        .expect("shutdown must succeed");
}

#[tokio::test(flavor = "current_thread")]
async fn handle_connection_rejects_admin_requests_from_agent_only_peers() {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let current_euid = nix::unistd::geteuid().as_raw();
    let (mut client_stream, server_stream) = UnixStream::pair().expect("stream pair");
    let wire_request = WireRequest {
        body_json: serde_json::to_string(&agentpay_api::DaemonRpcRequest::ListPolicies(
            ListPoliciesParams {
                auth: AdminAuth::PeerCredentials,
            },
        ))
        .expect("serialize request"),
    };
    write_frame(&mut client_stream, &wire_request, Duration::from_secs(2))
        .await
        .expect("write request");

    let err = handle_connection(
        server_stream,
        Arc::new(SignerdService::new(daemon)),
        singleton_allowed_set(current_euid.saturating_add(1)),
        singleton_allowed_set(current_euid),
    )
    .await
    .expect_err("must reject admin request");

    assert!(
        matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
    );
    assert!(
        read_frame::<WireResponse>(&mut client_stream, Duration::from_millis(50))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn handle_connection_rejects_globally_unauthorized_peer_without_frame_read() {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let current_euid = nix::unistd::geteuid().as_raw();
    let (_client_stream, server_stream) = UnixStream::pair().expect("stream pair");

    let result = tokio::time::timeout(
        Duration::from_millis(200),
        handle_connection(
            server_stream,
            Arc::new(SignerdService::new(daemon)),
            singleton_allowed_set(current_euid.saturating_add(1)),
            singleton_allowed_set(current_euid.saturating_add(2)),
        ),
    )
    .await
    .expect("globally unauthorized peer should be rejected before read timeout");

    let err = result.expect_err("must reject globally unauthorized peer");
    assert!(
        matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn handle_connection_prioritizes_unauthorized_over_deserialization_for_globally_unauthorized_peer(
) {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let current_euid = nix::unistd::geteuid().as_raw();
    let (mut client_stream, server_stream) = UnixStream::pair().expect("stream pair");
    let wire_request = WireRequest {
        body_json: "{not-json".to_string(),
    };
    write_frame(&mut client_stream, &wire_request, Duration::from_secs(2))
        .await
        .expect("write malformed request");

    let err = handle_connection(
        server_stream,
        Arc::new(SignerdService::new(daemon)),
        singleton_allowed_set(current_euid.saturating_add(1)),
        singleton_allowed_set(current_euid.saturating_add(2)),
    )
    .await
    .expect_err("must reject globally unauthorized peer");

    assert!(
        matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn handle_connection_rejects_agent_requests_from_admin_only_peers() {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let current_euid = nix::unistd::geteuid().as_raw();
    let (mut client_stream, server_stream) = UnixStream::pair().expect("stream pair");
    let wire_request = WireRequest {
        body_json: serde_json::to_string(&agentpay_api::DaemonRpcRequest::EvaluateForAgent(
            EvaluateForAgentParams {
                request: dummy_agent_request(),
            },
        ))
        .expect("serialize request"),
    };
    write_frame(&mut client_stream, &wire_request, Duration::from_secs(2))
        .await
        .expect("write request");

    let err = handle_connection(
        server_stream,
        Arc::new(SignerdService::new(daemon)),
        singleton_allowed_set(current_euid),
        singleton_allowed_set(current_euid.saturating_add(1)),
    )
    .await
    .expect_err("must reject agent request");

    assert!(
        matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
    );
    assert!(
        read_frame::<WireResponse>(&mut client_stream, Duration::from_millis(50))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bind_with_split_allowlists_keeps_root_only_socket_private() {
    let socket_path = unique_socket_path("split-root-only-mode");
    let server = UnixDaemonServer::bind_with_allowed_peer_euids(
        socket_path.clone(),
        singleton_allowed_set(0),
        singleton_allowed_set(0),
    )
    .await
    .expect("server");

    #[cfg(unix)]
    assert_eq!(socket_mode(&socket_path), 0o600);

    drop(server);
}
