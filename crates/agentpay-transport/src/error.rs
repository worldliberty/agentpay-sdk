//! Error type surfaced by the unix socket transport.

use agentpay_signerd::DaemonError;
use thiserror::Error;

/// Errors returned by unix socket transport.
#[derive(Debug, Error)]
pub enum UnixTransportError {
    /// Message serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Protocol-level failure.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Underlying daemon returned an error.
    #[error("daemon error: {0}")]
    Daemon(#[from] DaemonError),
    /// Filesystem/socket operation failed.
    #[error("io error: {0}")]
    Io(String),
    /// Timed out waiting for I/O.
    #[error("transport timeout")]
    Timeout,
    /// Client process is not authorized by daemon peer-euid policy.
    #[error("unauthorized peer euid (allowed {allowed:?}, got {actual})")]
    UnauthorizedPeerEuid { allowed: Vec<u32>, actual: u32 },
}
