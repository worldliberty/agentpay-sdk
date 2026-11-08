//! [`UnixSignerClient`]: [`SignerClient`] over signerd's Unix socket.

use std::path::PathBuf;
use std::time::Duration;

use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, WireDaemonError};
use agentpay_transport::{
    assert_root_owned_daemon_socket_path, assert_trusted_daemon_socket_path, UnixDaemonClient,
    UnixTransportError,
};
use async_trait::async_trait;

use super::{SignerClient, SignerError};

/// Hint appended when signerd hangs up without answering.
const ALLOWLIST_HINT: &str =
    "if this persists, check that the payments service uid is on the signer daemon's agent allowlist";

/// Calls the signer daemon over its socket, one connection per call.
///
/// Before every call it checks that the socket is trustworthy: with
/// `expected_euid` 0 (production) the socket and its directories must be
/// root-owned; otherwise (development, signerd running as the same user) they
/// must be owned by root or this user. After connecting, the peer's euid must
/// equal `expected_euid`.
#[derive(Debug, Clone)]
pub struct UnixSignerClient {
    socket: PathBuf,
    expected_euid: u32,
    client: UnixDaemonClient,
}

impl UnixSignerClient {
    /// A client for the signerd socket at `socket`, run by `expected_euid`,
    /// with a per-frame I/O `timeout`.
    #[must_use]
    pub fn new(socket: PathBuf, expected_euid: u32, timeout: Duration) -> Self {
        let client =
            UnixDaemonClient::new_with_expected_server_euid(socket.clone(), timeout, expected_euid);
        Self {
            socket,
            expected_euid,
            client,
        }
    }

    fn check_socket(&self) -> Result<(), SignerError> {
        let checked = if self.expected_euid == 0 {
            assert_root_owned_daemon_socket_path(&self.socket)
        } else {
            assert_trusted_daemon_socket_path(&self.socket)
        };
        checked.map(|_| ()).map_err(|reason| {
            SignerError::Unavailable(format!("untrusted signer socket: {reason}"))
        })
    }
}

#[async_trait]
impl SignerClient for UnixSignerClient {
    async fn call(&self, request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError> {
        let mut request = request;
        if let Err(error) = self.check_socket() {
            request.zeroize_secrets();
            return Err(error);
        }
        match self.client.call_rpc(request).await {
            Ok(response) => Ok(response),
            Err(UnixTransportError::Daemon(error)) => {
                Err(SignerError::Rejected(WireDaemonError::from(error)))
            }
            Err(UnixTransportError::Io(reason)) => Err(SignerError::Unavailable(format!(
                "{reason}; {ALLOWLIST_HINT}"
            ))),
            Err(error) => Err(SignerError::Unavailable(error.to_string())),
        }
    }
}
