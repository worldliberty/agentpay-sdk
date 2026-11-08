//! Talking to the signer daemon as the calling agent.
//!
//! - [`SignerClient`]: the one-method seam to signerd (`DaemonRpcRequest` in,
//!   `DaemonRpcResponse` out). [`UnixSignerClient`] is the real implementation
//!   over signerd's socket; tests use the doubles in `signer::testing`.
//! - [`AgentSigner`]: typed, policy-checked operations for one authenticated
//!   agent (identity, nonce reservation, signing, waiting for manual approval).
//!   Feature modules use this instead of building `DaemonRpcRequest`s.
//!
//! paymentd holds no credentials of its own. Every call carries the caller's
//! agent key id and token, so signerd applies that agent's policies. Signerd
//! only accepts the calls because paymentd's uid is on its agent allowlist
//! (`--allow-agent-euid`, set by `agentpay-setup`).

mod agent;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
mod unix;

use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, WireDaemonError};
use async_trait::async_trait;
use thiserror::Error;

pub use agent::{AgentSigner, ApprovalWait, MAX_APPROVAL_WAIT};
pub use unix::UnixSignerClient;

/// Why a signer daemon call failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SignerError {
    /// The call never got an answer: the socket is missing or untrusted, the
    /// connection failed or timed out, or signerd closed it without a
    /// response (for example because paymentd's uid is not on its agent
    /// allowlist).
    #[error("signer daemon unavailable: {0}")]
    Unavailable(String),
    /// Signerd answered with an error.
    #[error("signer daemon error: {0:?}")]
    Rejected(WireDaemonError),
}

/// One request/response exchange with the signer daemon.
// `async_trait` marks each generated method `#[must_use]` on top of the boxed
// future it returns, which newer clippy reports as `double_must_use`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait SignerClient: Send + Sync {
    /// Sends `request` and returns signerd's response.
    async fn call(&self, request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError>;
}

/// The error for a response variant the caller did not ask for.
pub(crate) fn unexpected(method: &str, response: &DaemonRpcResponse) -> SignerError {
    let variant = serde_json::to_value(response)
        .ok()
        .and_then(|value| {
            value
                .get("type")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_string());
    SignerError::Unavailable(format!(
        "signer daemon answered {method} with an unexpected {variant} response"
    ))
}
