//! Client side of the transport: one RPC per socket connection.

mod daemon_api;

use std::path::PathBuf;
use std::time::Duration;

use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, HelloResponse, WireDaemonError};
use agentpay_signerd::DaemonError;
use tokio::net::UnixStream;
use zeroize::Zeroize;

use crate::error::UnixTransportError;
use crate::peer_auth::peer_euid;
use crate::wire::{read_frame, write_frame, WireRequest, WireResponse, MAX_WIRE_BODY_BYTES};

/// Client adapter backed by unix-domain socket transport.
#[derive(Debug, Clone)]
pub struct UnixDaemonClient {
    socket_path: PathBuf,
    timeout: Duration,
    expected_server_euid: u32,
}

impl UnixDaemonClient {
    /// Creates a unix transport client.
    #[must_use]
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Self {
        Self::new_with_expected_server_euid(socket_path, timeout, nix::unistd::geteuid().as_raw())
    }

    /// Creates a unix transport client with explicit expected daemon euid.
    ///
    /// This allows hardened callers to pin daemon identity (for example `0` for root daemon).
    #[must_use]
    pub fn new_with_expected_server_euid(
        socket_path: PathBuf,
        timeout: Duration,
        expected_server_euid: u32,
    ) -> Self {
        Self {
            socket_path,
            timeout,
            expected_server_euid,
        }
    }

    /// Performs a single daemon RPC call.
    pub async fn call_rpc(
        &self,
        request: DaemonRpcRequest,
    ) -> Result<DaemonRpcResponse, UnixTransportError> {
        let mut request = request;
        let body_json = serde_json::to_string(&request)
            .map_err(|err| UnixTransportError::Serialization(err.to_string()));
        request.zeroize_secrets();
        let mut response = self.exchange(body_json?).await?;
        if response.ok {
            let parsed = serde_json::from_str::<DaemonRpcResponse>(&response.body_json)
                .map_err(|err| UnixTransportError::Serialization(err.to_string()));
            response.body_json.zeroize();
            parsed
        } else {
            let daemon_error = match serde_json::from_str::<WireDaemonError>(&response.body_json) {
                Ok(err) => Err(UnixTransportError::Daemon(DaemonError::from(err))),
                Err(_) => Err(UnixTransportError::Daemon(DaemonError::Transport(
                    response.body_json.clone(),
                ))),
            };
            response.body_json.zeroize();
            daemon_error
        }
    }

    /// Sends one already-serialized request body and returns the response
    /// envelope: connect, verify the server's euid, write one frame, read one
    /// frame. `body_json` is wiped before returning.
    ///
    /// This is the service-neutral exchange behind [`call_rpc`](Self::call_rpc);
    /// clients of other services (the payments service) decode `body_json`
    /// themselves and must wipe it when it may hold secrets.
    pub async fn exchange(&self, body_json: String) -> Result<WireResponse, UnixTransportError> {
        let mut body_json = body_json;
        if body_json.len() > MAX_WIRE_BODY_BYTES {
            body_json.zeroize();
            return Err(UnixTransportError::Protocol(format!(
                "wire request body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
            )));
        }
        let mut wire_request = WireRequest { body_json };
        let result = self.exchange_envelope(&wire_request).await;
        wire_request.body_json.zeroize();
        result
    }

    async fn exchange_envelope(
        &self,
        wire_request: &WireRequest,
    ) -> Result<WireResponse, UnixTransportError> {
        let mut stream = tokio::time::timeout(self.timeout, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        let peer_euid = peer_euid(&stream).map_err(UnixTransportError::Io)?;
        if peer_euid != self.expected_server_euid {
            return Err(UnixTransportError::UnauthorizedPeerEuid {
                allowed: vec![self.expected_server_euid],
                actual: peer_euid,
            });
        }
        write_frame(&mut stream, wire_request, self.timeout).await?;
        read_frame(&mut stream, self.timeout).await
    }

    /// Performs the `Hello` handshake: returns the daemon's API version, release,
    /// and capabilities.
    ///
    /// Callers should check the result with
    /// [`ApiVersion::is_compatible_with`](agentpay_api::ApiVersion::is_compatible_with)
    /// before relying on any other method.
    pub async fn hello(&self) -> Result<HelloResponse, DaemonError> {
        self.call_expecting(DaemonRpcRequest::Hello, |response| match response {
            DaemonRpcResponse::Hello(hello) => Some(hello),
            _ => None,
        })
        .await
    }

    /// Performs `request` and extracts the expected response variant.
    ///
    /// Daemon errors are passed through unchanged; transport failures and
    /// responses for which `extract` returns `None` become
    /// [`DaemonError::Transport`].
    async fn call_expecting<T>(
        &self,
        request: DaemonRpcRequest,
        extract: impl FnOnce(DaemonRpcResponse) -> Option<T>,
    ) -> Result<T, DaemonError> {
        match self.call_rpc(request).await {
            Ok(response) => extract(response)
                .ok_or_else(|| DaemonError::Transport("unexpected response type".to_string())),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }
}
