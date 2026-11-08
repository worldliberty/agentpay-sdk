//! The `Hello` handshake over a real socket, including the exact frame bytes
//! documented in `docs/daemon-api.md`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::{ApiVersion, DaemonRpcRequest, DaemonRpcResponse, WireResponse, API_VERSION};
use agentpay_signer::SoftwareSignerBackend;
use agentpay_signerd::{DaemonConfig, InMemoryDaemon};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{singleton_allowed_set, unique_socket_path};
use crate::client::UnixDaemonClient;
use crate::server::UnixDaemonServer;

type Daemon = Arc<InMemoryDaemon<SoftwareSignerBackend>>;

fn daemon() -> Daemon {
    Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    )
}

/// Serves `daemon` on a fresh socket with the given admin and agent allowlists.
async fn serve(
    label: &str,
    daemon: Daemon,
    admin: BTreeSet<u32>,
    agent: BTreeSet<u32>,
) -> std::path::PathBuf {
    let socket_path = unique_socket_path(label);
    let server = UnixDaemonServer::bind_with_allowed_peer_euids(socket_path.clone(), admin, agent)
        .await
        .expect("server");
    tokio::spawn(async move {
        let _ = server
            .run_until_shutdown(daemon, std::future::pending::<()>())
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    socket_path
}

fn own_euid() -> BTreeSet<u32> {
    singleton_allowed_set(nix::unistd::geteuid().as_raw())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_hello_reports_the_contract_version_and_capabilities() {
    let daemon = daemon();
    let socket_path = serve("hello", daemon.clone(), own_euid(), own_euid()).await;
    let client = UnixDaemonClient::new(socket_path, Duration::from_secs(2));

    let hello = client.hello().await.expect("hello");
    assert_eq!(hello, daemon.hello());
    assert_eq!(hello.api_version, API_VERSION);
    let version = ApiVersion::parse(&hello.api_version).expect("semver");
    assert!(ApiVersion::CURRENT.is_compatible_with(&version));
    for method in DaemonRpcRequest::METHOD_NAMES {
        assert!(hello.supports(method), "missing capability {method}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn documented_hello_frame_gets_a_hello_response() {
    let socket_path = serve("hello-raw", daemon(), own_euid(), own_euid()).await;
    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    let body = br#"{"body_json":"{\"method\":\"Hello\"}"}"#;
    stream
        .write_all(&[0x00, 0x00, 0x00, 0x26])
        .await
        .expect("length");
    stream.write_all(body).await.expect("body");

    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.expect("response length");
    let mut payload = vec![0u8; u32::from_be_bytes(len) as usize];
    stream
        .read_exact(&mut payload)
        .await
        .expect("response body");
    let envelope: WireResponse = serde_json::from_slice(&payload).expect("envelope");
    assert!(envelope.ok);
    let response: DaemonRpcResponse = serde_json::from_str(&envelope.body_json).expect("response");
    let DaemonRpcResponse::Hello(hello) = response else {
        panic!("expected a Hello response, got {response:?}");
    };
    assert_eq!(hello.api_version, API_VERSION);

    // One request per connection: the daemon closes the stream afterwards.
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("eof");
    assert!(rest.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hello_is_open_to_peers_on_either_allowlist() {
    let root_only = singleton_allowed_set(0);
    for (label, admin, agent) in [
        ("hello-agent", root_only.clone(), own_euid()),
        ("hello-admin", own_euid(), root_only.clone()),
    ] {
        let socket_path = serve(label, daemon(), admin, agent).await;
        let client = UnixDaemonClient::new(socket_path, Duration::from_secs(2));
        let hello = client.hello().await.expect("hello from a single allowlist");
        assert_eq!(hello.api_version, API_VERSION);
    }
}
