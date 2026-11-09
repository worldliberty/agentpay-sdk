//! The payments socket: [`PaymentsService`] plugged into the shared transport.
//!
//! Framing, size limits, timeouts, the bounded accept loop, and peer-euid
//! checks come from `agentpay-transport`, exactly as for the signer daemon.
//! paymentd has one allowlist (its clients), used for both access levels.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use agentpay_api::payments::{PaymentsRpcRequest, WirePaymentsError};
use agentpay_api::{AccessLevel, WireResponse};
use agentpay_transport::{RpcService, UnixDaemonServer, UnixTransportError};
use async_trait::async_trait;

use crate::dispatch::dispatch;
use crate::state::AppState;

/// [`RpcService`] for [`PaymentsRpcRequest`].
pub struct PaymentsService {
    state: Arc<AppState>,
}

impl PaymentsService {
    /// Serves requests against `state`.
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl RpcService for PaymentsService {
    type Request = PaymentsRpcRequest;

    fn access_level(request: &PaymentsRpcRequest) -> AccessLevel {
        request.access_level()
    }

    fn zeroize_request(request: &mut PaymentsRpcRequest) {
        request.zeroize_secrets();
    }

    async fn handle(
        &self,
        peer_euid: u32,
        request: PaymentsRpcRequest,
    ) -> Result<WireResponse, UnixTransportError> {
        let method = request.method_name();
        let started = Instant::now();
        // `request` (and the token inside it) is dropped, and wiped, inside dispatch.
        let result = dispatch(&self.state, request).await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        // Log the method and outcome only: never credentials, addresses, or URLs.
        let (ok, body_json) = match result {
            Ok(response) => {
                tracing::info!(method, peer_euid, elapsed_ms, "request served");
                (true, serde_json::to_string(&response))
            }
            Err(error) => {
                tracing::warn!(
                    method,
                    peer_euid,
                    elapsed_ms,
                    kind = error.kind(),
                    "request failed"
                );
                (
                    false,
                    serde_json::to_string(&WirePaymentsError::from(error)),
                )
            }
        };
        let body_json =
            body_json.map_err(|err| UnixTransportError::Serialization(err.to_string()))?;
        Ok(WireResponse { ok, body_json })
    }
}

/// Binds the payments socket at `socket`, reachable by `allowed_client_euids`.
pub async fn bind(
    socket: PathBuf,
    allowed_client_euids: BTreeSet<u32>,
) -> Result<UnixDaemonServer, UnixTransportError> {
    UnixDaemonServer::bind_with_allowed_peer_euids(
        socket,
        allowed_client_euids.clone(),
        allowed_client_euids,
    )
    .await
}

/// Serves `state` on `server` until `shutdown` resolves, then waits for
/// in-flight requests to finish.
pub async fn serve<S>(
    server: UnixDaemonServer,
    state: Arc<AppState>,
    shutdown: S,
) -> Result<(), UnixTransportError>
where
    S: std::future::Future<Output = ()>,
{
    server
        .run_service_until_shutdown(Arc::new(PaymentsService::new(state)), shutdown)
        .await
}

/// Resolves on SIGINT, SIGTERM, or SIGHUP, so launchd and systemd stops take
/// the same graceful path as Ctrl-C.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    async fn recv(kind: SignalKind, name: &str) {
        match signal(kind) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::warn!(signal = name, %error, "failed to install signal handler");
                std::future::pending::<()>().await;
            }
        }
    }

    tokio::select! {
        _ = recv(SignalKind::interrupt(), "SIGINT") => {}
        _ = recv(SignalKind::terminate(), "SIGTERM") => {}
        _ = recv(SignalKind::hangup(), "SIGHUP") => {}
    }
    tracing::info!("shutting down");
}
