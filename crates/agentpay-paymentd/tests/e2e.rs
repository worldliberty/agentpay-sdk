//! End to end over real Unix sockets: client -> paymentd -> signerd, all in a
//! temporary directory, everything run by the current user.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::payments::{
    GetConfigParams, PaymentsRpcRequest, PaymentsRpcResponse, SetConfigParams, WirePaymentsError,
};
use agentpay_api::{AgentAuth, HelloResponse};
use agentpay_domain::{AdminAuth, PolicyAttachment};
use agentpay_paymentd::cli::Options;
use agentpay_paymentd::client::{PaymentsClient, PaymentsClientError};
use agentpay_paymentd::config::default_config;
use agentpay_paymentd::{runtime, server};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use agentpay_signerd::{DaemonConfig, InMemoryDaemon, KeyManagerDaemonApi};
use agentpay_transport::UnixDaemonServer;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// A short private directory (socket paths must stay under ~104 bytes), removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let base = if Path::new("/private/tmp").is_dir() {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let path = Path::new(base).join(format!(
            "pd-e2e-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir(&path).expect("temp dir");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running service and the means to stop it.
struct Running {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl Running {
    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.await.expect("service task");
    }
}

fn me() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Starts a signer daemon with one agent and returns its credentials.
async fn start_signer(socket: PathBuf) -> (Running, AgentAuth) {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let admin = AdminAuth::PeerCredentials;
    let vault_key = daemon
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let credentials = daemon
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent key");
    let allowed = BTreeSet::from([me()]);
    let server = UnixDaemonServer::bind_with_allowed_peer_euids(socket, allowed.clone(), allowed)
        .await
        .expect("bind signer");
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        server
            .run_until_shutdown(Arc::new(daemon), async {
                let _ = stopped.await;
            })
            .await
            .expect("signer loop");
    });
    let auth = AgentAuth {
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
    };
    (
        Running {
            stop: Some(stop),
            task,
        },
        auth,
    )
}

fn options(root: &Path, allowed_clients: BTreeSet<u32>) -> Options {
    Options {
        socket: root.join("paymentd.sock"),
        state_dir: root.join("state"),
        signer_socket: root.join("daemon.sock"),
        signer_euid: me(),
        allowed_client_euids: allowed_clients,
        signer_timeout: Duration::from_secs(5),
    }
}

async fn start_paymentd(options: &Options) -> Running {
    runtime::ensure_not_root(me()).expect("tests do not run as root");
    runtime::prepare_state_dir(&options.state_dir, me()).expect("state dir");
    let state = Arc::new(runtime::build_state(options).expect("state"));
    let bound = server::bind(options.socket.clone(), options.allowed_client_euids.clone())
        .await
        .expect("bind paymentd");
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        server::serve(bound, state, async {
            let _ = stopped.await;
        })
        .await
        .expect("paymentd loop");
    });
    Running {
        stop: Some(stop),
        task,
    }
}

fn client(options: &Options) -> PaymentsClient {
    PaymentsClient::new(options.socket.clone(), me(), Duration::from_secs(5))
}

#[tokio::test]
async fn hello_and_config_work_end_to_end() {
    let dir = TempDir::new();
    let options = options(&dir.0, BTreeSet::from([me()]));
    let (signer, auth) = start_signer(options.signer_socket.clone()).await;
    let paymentd = start_paymentd(&options).await;
    let client = client(&options);

    let hello = client.call(PaymentsRpcRequest::Hello).await.expect("hello");
    assert_eq!(
        hello,
        PaymentsRpcResponse::Hello(HelloResponse::for_payments_service(env!(
            "CARGO_PKG_VERSION"
        )))
    );

    let get = PaymentsRpcRequest::GetConfig(GetConfigParams { auth: auth.clone() });
    assert_eq!(
        client.call(get.clone()).await.expect("get"),
        PaymentsRpcResponse::Config(default_config())
    );

    let mut config = default_config();
    config.default_network = "eth".into();
    let set = PaymentsRpcRequest::SetConfig(SetConfigParams {
        auth: auth.clone(),
        config: config.clone(),
    });
    assert_eq!(
        client.call(set).await.expect("set"),
        PaymentsRpcResponse::Config(config.clone())
    );
    assert_eq!(
        client.call(get).await.expect("get again"),
        PaymentsRpcResponse::Config(config.clone())
    );
    assert!(options.state_dir.join("config.json").is_file());

    let forged = PaymentsRpcRequest::GetConfig(GetConfigParams {
        auth: AgentAuth {
            agent_key_id: auth.agent_key_id,
            agent_auth_token: "forged".to_string().into(),
        },
    });
    assert_eq!(
        client.call(forged).await,
        Err(PaymentsClientError::Rejected(
            WirePaymentsError::AgentAuthenticationFailed
        ))
    );

    // With the signer daemon gone, authenticated calls fail as unavailable,
    // while the handshake keeps working.
    signer.stop().await;
    let err = client
        .call(PaymentsRpcRequest::GetConfig(GetConfigParams { auth }))
        .await
        .expect_err("signer down");
    assert!(
        matches!(
            err,
            PaymentsClientError::Rejected(WirePaymentsError::SignerUnavailable(_))
        ),
        "{err:?}"
    );
    client
        .call(PaymentsRpcRequest::Hello)
        .await
        .expect("hello without signer");

    paymentd.stop().await;
    assert!(
        !options.socket.exists(),
        "the socket is removed on shutdown"
    );
}

#[tokio::test]
async fn peers_off_the_allowlist_get_no_answer() {
    let dir = TempDir::new();
    let options = options(&dir.0, BTreeSet::from([me().wrapping_add(1)]));
    let paymentd = start_paymentd(&options).await;
    let err = client(&options)
        .call(PaymentsRpcRequest::Hello)
        .await
        .expect_err("not allowlisted");
    assert!(matches!(err, PaymentsClientError::Transport(_)), "{err:?}");
    paymentd.stop().await;
}

#[tokio::test]
async fn a_second_service_cannot_share_the_state_directory() {
    let dir = TempDir::new();
    let options = options(&dir.0, BTreeSet::from([me()]));
    runtime::prepare_state_dir(&options.state_dir, me()).expect("state dir");
    let _first = runtime::acquire_instance_lock(&options.state_dir).expect("first");
    assert!(runtime::acquire_instance_lock(&options.state_dir).is_err());
}
