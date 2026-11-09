//! Socket binding and the serve-until-signal run loop.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use agentpay_signerd::InMemoryDaemon;
use agentpay_transport::UnixDaemonServer;
use anyhow::{Context, Result};

use crate::config::peers::{format_allowed_euids, AllowedPeerEuids};

fn print_server_banner(daemon_socket: &Path, allowed_peer_euids: &AllowedPeerEuids) {
    eprintln!(
        "==> daemon listening on {} (allowed admin euid(s): {}; allowed agent euid(s): {})",
        daemon_socket.display(),
        format_allowed_euids(&allowed_peer_euids.admin),
        format_allowed_euids(&allowed_peer_euids.agent)
    );
    eprintln!("==> press Ctrl+C to stop");
}

/// Binds the daemon socket with the configured allowlists and prints the startup banner.
pub(crate) async fn bind_server(
    daemon_socket: PathBuf,
    allowed_peer_euids: &AllowedPeerEuids,
) -> Result<UnixDaemonServer> {
    let server = UnixDaemonServer::bind_with_allowed_peer_euids(
        daemon_socket.clone(),
        allowed_peer_euids.admin.clone(),
        allowed_peer_euids.agent.clone(),
    )
    .await
    .with_context(|| {
        format!(
            "failed to bind daemon socket at {}",
            daemon_socket.display()
        )
    })?;
    print_server_banner(&daemon_socket, allowed_peer_euids);
    Ok(server)
}

/// Serves RPCs for `daemon` on the bound `server` until a shutdown signal arrives.
pub(crate) async fn run_bound_daemon<B>(
    server: UnixDaemonServer,
    daemon: Arc<InMemoryDaemon<B>>,
) -> Result<()>
where
    B: agentpay_signer::VaultSignerBackend + Send + Sync + 'static,
{
    server
        .run_until_shutdown(daemon, wait_for_shutdown_signal())
        .await
        .context("daemon server loop failed")
}

/// Resolves on the first of SIGINT, SIGTERM, or SIGHUP so that launchd/systemd stop requests
/// take the same graceful worker-join path as an interactive Ctrl-C.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(stream) => Some(stream),
            Err(error) => {
                eprintln!("warning: failed to install SIGTERM handler: {error}");
                None
            }
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(stream) => Some(stream),
            Err(error) => {
                eprintln!("warning: failed to install SIGHUP handler: {error}");
                None
            }
        };
        let sigterm_recv = async {
            match sigterm.as_mut() {
                Some(stream) => {
                    stream.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let sighup_recv = async {
            match sighup.as_mut() {
                Some(stream) => {
                    stream.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm_recv => {}
            _ = sighup_recv => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
