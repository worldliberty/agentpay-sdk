//! Server side of the transport: socket binding, the bounded accept loop, and
//! per-connection request handling for any [`RpcService`].
//!
//! Each accepted connection carries exactly one request. The peer euid is
//! checked against the union of the admin and agent allowlists before any
//! bytes are read, and again against the allowlist for the request's access
//! level once the request has been decoded.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agentpay_api::AccessLevel;
use agentpay_signer::VaultSignerBackend;
use agentpay_signerd::InMemoryDaemon;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use zeroize::Zeroize;

use crate::error::UnixTransportError;
use crate::peer_auth::{
    combined_allowed_peer_euids, peer_euid, socket_mode_for_allowed_peer_euids,
    validate_allowed_peer_euids,
};
use crate::service::{RpcService, SignerdService};
use crate::socket_trust::{ensure_socket_parent, remove_existing_socket_file};
use crate::wire::{read_frame, write_frame, WireRequest, MAX_WIRE_BODY_BYTES};

/// Upper bound on concurrently serviced client connections.
pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 64;
/// Initial delay after an `accept()` failure before retrying.
pub(crate) const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
/// Longest delay between `accept()` retries.
pub(crate) const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// Per-frame read/write timeout applied to server-side connections.
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Doubles the accept backoff, saturating at [`ACCEPT_BACKOFF_MAX`].
pub(crate) fn next_accept_backoff(current: Duration) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(ACCEPT_BACKOFF_MAX)
        .min(ACCEPT_BACKOFF_MAX)
}

/// Unix daemon socket server bound to a local path.
pub struct UnixDaemonServer {
    listener: UnixListener,
    socket_path: PathBuf,
    allowed_admin_peer_euids: BTreeSet<u32>,
    allowed_agent_peer_euids: BTreeSet<u32>,
}

impl UnixDaemonServer {
    /// Binds server to `socket_path` and restricts clients to `allowed_peer_euids`.
    pub async fn bind(
        socket_path: PathBuf,
        allowed_peer_euids: BTreeSet<u32>,
    ) -> Result<Self, UnixTransportError> {
        Self::bind_with_allowed_peer_euids(
            socket_path,
            allowed_peer_euids.clone(),
            allowed_peer_euids,
        )
        .await
    }

    /// Binds server to `socket_path` with separate admin and agent peer-euid allowlists.
    pub async fn bind_with_allowed_peer_euids(
        socket_path: PathBuf,
        allowed_admin_peer_euids: BTreeSet<u32>,
        allowed_agent_peer_euids: BTreeSet<u32>,
    ) -> Result<Self, UnixTransportError> {
        validate_allowed_peer_euids("admin", &allowed_admin_peer_euids)?;
        validate_allowed_peer_euids("agent", &allowed_agent_peer_euids)?;

        ensure_socket_parent(&socket_path).map_err(UnixTransportError::Io)?;
        remove_existing_socket_file(&socket_path).map_err(UnixTransportError::Io)?;

        let listener = UnixListener::bind(&socket_path)
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let socket_mode = socket_mode_for_allowed_peer_euids(
                &allowed_admin_peer_euids,
                &allowed_agent_peer_euids,
            );
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(socket_mode))
                .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        }

        Ok(Self {
            listener,
            socket_path,
            allowed_admin_peer_euids,
            allowed_agent_peer_euids,
        })
    }

    /// Serves the signer daemon until `shutdown` resolves; see
    /// [`run_service_until_shutdown`](Self::run_service_until_shutdown).
    pub async fn run_until_shutdown<B, S>(
        self,
        daemon: Arc<InMemoryDaemon<B>>,
        shutdown: S,
    ) -> Result<(), UnixTransportError>
    where
        B: VaultSignerBackend + 'static,
        S: std::future::Future<Output = ()>,
    {
        self.run_service_until_shutdown(Arc::new(SignerdService::new(daemon)), shutdown)
            .await
    }

    /// Runs the accept loop for `service` until `shutdown` resolves, then waits
    /// for in-flight connections to finish.
    ///
    /// Transient `accept()` failures (for example fd exhaustion) are logged and
    /// retried with exponential backoff instead of terminating the daemon. At
    /// most `MAX_CONCURRENT_CONNECTIONS` (64) connections are serviced at once;
    /// additional clients wait in the kernel backlog until a slot frees up.
    pub async fn run_service_until_shutdown<R, S>(
        self,
        service: Arc<R>,
        shutdown: S,
    ) -> Result<(), UnixTransportError>
    where
        R: RpcService,
        S: std::future::Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let mut workers: JoinSet<()> = JoinSet::new();
        let connection_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let mut accept_backoff = ACCEPT_BACKOFF_MIN;
        loop {
            // Reap finished connection tasks so the set never grows without bound.
            while workers.try_join_next().is_some() {}

            let permit = tokio::select! {
                _ = &mut shutdown => break,
                permit = Arc::clone(&connection_permits).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    // The semaphore is never closed; treat it as a shutdown signal if it is.
                    Err(_) => break,
                },
            };

            let accepted = tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.listener.accept() => accepted,
            };

            match accepted {
                Ok((stream, _)) => {
                    accept_backoff = ACCEPT_BACKOFF_MIN;
                    let service = Arc::clone(&service);
                    let allowed_admin_peer_euids = self.allowed_admin_peer_euids.clone();
                    let allowed_agent_peer_euids = self.allowed_agent_peer_euids.clone();
                    workers.spawn(async move {
                        // Hold the permit for the lifetime of the connection.
                        let _permit = permit;
                        let _ = handle_connection(
                            stream,
                            service,
                            allowed_admin_peer_euids,
                            allowed_agent_peer_euids,
                        )
                        .await;
                    });
                }
                Err(err) => {
                    drop(permit);
                    eprintln!(
                        "==> daemon socket accept failed: {err}; retrying in {}ms",
                        accept_backoff.as_millis()
                    );
                    tokio::select! {
                        _ = &mut shutdown => break,
                        _ = tokio::time::sleep(accept_backoff) => {}
                    }
                    accept_backoff = next_accept_backoff(accept_backoff);
                }
            }
        }

        while workers.join_next().await.is_some() {}
        Ok(())
    }

    /// Returns bound socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for UnixDaemonServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Authorizes the peer, decodes one request, dispatches it to `service`, and writes the response.
pub(crate) async fn handle_connection<R>(
    mut stream: UnixStream,
    service: Arc<R>,
    allowed_admin_peer_euids: BTreeSet<u32>,
    allowed_agent_peer_euids: BTreeSet<u32>,
) -> Result<(), UnixTransportError>
where
    R: RpcService,
{
    let peer_euid = peer_euid(&stream).map_err(UnixTransportError::Io)?;
    let globally_allowed_peer_euids =
        combined_allowed_peer_euids(&allowed_admin_peer_euids, &allowed_agent_peer_euids);
    if !globally_allowed_peer_euids.contains(&peer_euid) {
        return Err(UnixTransportError::UnauthorizedPeerEuid {
            allowed: globally_allowed_peer_euids.into_iter().collect(),
            actual: peer_euid,
        });
    }

    let mut request: WireRequest = read_frame(&mut stream, CONNECTION_IO_TIMEOUT).await?;
    if request.body_json.len() > MAX_WIRE_BODY_BYTES {
        request.body_json.zeroize();
        return Err(UnixTransportError::Protocol(format!(
            "wire request body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }

    let decoded = serde_json::from_str(&request.body_json)
        .map_err(|err| UnixTransportError::Serialization(err.to_string()));
    request.body_json.zeroize();
    let mut decoded: R::Request = decoded?;
    let allowed_peer_euids = match R::access_level(&decoded) {
        AccessLevel::Admin => &allowed_admin_peer_euids,
        AccessLevel::Agent => &allowed_agent_peer_euids,
        // Already checked against the union of both allowlists above.
        AccessLevel::Any => &globally_allowed_peer_euids,
    };
    if !allowed_peer_euids.contains(&peer_euid) {
        R::zeroize_request(&mut decoded);
        return Err(UnixTransportError::UnauthorizedPeerEuid {
            allowed: allowed_peer_euids.iter().copied().collect(),
            actual: peer_euid,
        });
    }

    let mut response = service.handle(peer_euid, decoded).await?;
    let write_result = write_frame(&mut stream, &response, CONNECTION_IO_TIMEOUT).await;
    response.body_json.zeroize();
    write_result?;
    Ok(())
}
