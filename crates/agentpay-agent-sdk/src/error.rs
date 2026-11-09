//! Error type returned by SDK operations.

use agentpay_domain::DomainError;
use agentpay_signerd::DaemonError;
use thiserror::Error;

/// Errors returned by the Agentic SDK.
#[derive(Debug, Error)]
pub enum AgentSdkError {
    /// Upstream daemon call failed.
    #[error("daemon call failed: {0}")]
    Daemon(#[from] DaemonError),
    /// Invalid action payload.
    #[error("invalid action: {0}")]
    Domain(#[from] DomainError),
    /// Failed to serialize action payload for daemon verification.
    #[error("failed to serialize action payload: {0}")]
    Serialization(String),
}
