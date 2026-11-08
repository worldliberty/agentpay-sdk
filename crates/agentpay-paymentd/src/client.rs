//! [`PaymentsClient`]: a Rust client for the payments socket.
//!
//! The bundled client is the TypeScript app; this one serves Rust callers and
//! end-to-end tests. It follows the documented client rules: check the socket
//! (owned by the service account), pin the peer euid, one request per
//! connection, wipe request and response bodies.

use std::path::PathBuf;
use std::time::Duration;

use agentpay_api::payments::{PaymentsRpcRequest, PaymentsRpcResponse, WirePaymentsError};
use agentpay_transport::{assert_service_socket_path, UnixDaemonClient};
use thiserror::Error;
use zeroize::Zeroize;

/// Why a payments call failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaymentsClientError {
    /// The service answered with an error.
    #[error("payments service error: {0:?}")]
    Rejected(WirePaymentsError),
    /// No usable answer: untrusted socket, I/O failure, or an undecodable body.
    #[error("payments transport failure: {0}")]
    Transport(String),
}

/// One-request-per-connection client for `agentpay-paymentd`.
#[derive(Debug, Clone)]
pub struct PaymentsClient {
    socket: PathBuf,
    service_euid: u32,
    inner: UnixDaemonClient,
}

impl PaymentsClient {
    /// A client for the service at `socket`, running as `service_euid`.
    /// `timeout` bounds each frame read and write; calls that wait for a
    /// manual approval need a timeout longer than the wait.
    #[must_use]
    pub fn new(socket: PathBuf, service_euid: u32, timeout: Duration) -> Self {
        let inner =
            UnixDaemonClient::new_with_expected_server_euid(socket.clone(), timeout, service_euid);
        Self {
            socket,
            service_euid,
            inner,
        }
    }

    /// Sends `request` and returns the service's response.
    pub async fn call(
        &self,
        request: PaymentsRpcRequest,
    ) -> Result<PaymentsRpcResponse, PaymentsClientError> {
        let mut request = request;
        let trusted = assert_service_socket_path(&self.socket, self.service_euid);
        let body_json = serde_json::to_string(&request);
        request.zeroize_secrets();
        trusted.map_err(PaymentsClientError::Transport)?;
        let body_json = body_json.map_err(|err| PaymentsClientError::Transport(err.to_string()))?;
        let mut response = self
            .inner
            .exchange(body_json)
            .await
            .map_err(|err| PaymentsClientError::Transport(err.to_string()))?;
        let result = if response.ok {
            serde_json::from_str::<PaymentsRpcResponse>(&response.body_json)
                .map_err(|err| PaymentsClientError::Transport(err.to_string()))
        } else {
            match serde_json::from_str::<WirePaymentsError>(&response.body_json) {
                Ok(error) => Err(PaymentsClientError::Rejected(error)),
                Err(err) => Err(PaymentsClientError::Transport(err.to_string())),
            }
        };
        response.body_json.zeroize();
        result
    }
}
