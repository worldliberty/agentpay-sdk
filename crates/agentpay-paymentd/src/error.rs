//! [`PaymentsError`]: every failure a payments method reports, and its wire
//! form [`WirePaymentsError`].
//!
//! Feature modules return `PaymentsError`; the server turns it into the wire
//! error and logs only its [`kind`](PaymentsError::kind), never the message,
//! because messages may quote request data.

use agentpay_api::{WireDaemonError, WirePaymentsError};
use thiserror::Error;
use uuid::Uuid;

use crate::signer::SignerError;

/// A failed payments method call.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PaymentsError {
    /// The signer daemon rejected the caller's agent credentials.
    #[error("agent authentication failed")]
    AgentAuthenticationFailed,
    /// The signer daemon could not be reached or answered unexpectedly.
    #[error("signer daemon unavailable: {0}")]
    SignerUnavailable(String),
    /// The signer daemon refused a request made on the agent's behalf.
    #[error("signer daemon refused the request ({0:?})")]
    Signer(WireDaemonError),
    /// A signature still waits for an operator decision.
    #[error("manual approval {approval_request_id} is still pending")]
    ManualApprovalPending {
        /// The pending approval request.
        approval_request_id: Uuid,
    },
    /// A configuration failed validation.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// Saving state failed.
    #[error("persistence failed: {0}")]
    Persistence(String),
    /// The request cannot be carried out as asked; nothing was signed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// A chain RPC call failed. The message never includes the RPC URL.
    #[error("chain RPC failed: {0}")]
    ChainRpc(String),
    /// The signer daemon returned a transaction that does not match the request.
    #[error("signed transaction mismatch: {0}")]
    SignedTransactionMismatch(String),
    /// `ResumeApproved` names no pending approval stored for the caller.
    #[error("no pending approval {0} is stored for this agent")]
    UnknownPendingApproval(Uuid),
    /// The paid HTTP endpoint failed or answered unusably. The message
    /// never quotes the URL and says whether anything was signed.
    #[error("merchant request failed: {0}")]
    Merchant(String),
    /// Anything else that should not happen.
    #[error("internal error: {0}")]
    Internal(String),
}

impl PaymentsError {
    /// The wire `kind`, safe to log.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::AgentAuthenticationFailed => "AgentAuthenticationFailed",
            Self::SignerUnavailable(_) => "SignerUnavailable",
            Self::Signer(_) => "Signer",
            Self::ManualApprovalPending { .. } => "ManualApprovalPending",
            Self::InvalidConfig(_) => "InvalidConfig",
            Self::Persistence(_) => "Persistence",
            Self::InvalidRequest(_) => "InvalidRequest",
            Self::ChainRpc(_) => "ChainRpc",
            Self::SignedTransactionMismatch(_) => "SignedTransactionMismatch",
            Self::UnknownPendingApproval(_) => "UnknownPendingApproval",
            Self::Merchant(_) => "Merchant",
            Self::Internal(_) => "Internal",
        }
    }
}

impl From<SignerError> for PaymentsError {
    fn from(error: SignerError) -> Self {
        match error {
            SignerError::Unavailable(reason) => Self::SignerUnavailable(reason),
            SignerError::Rejected(error) => Self::Signer(error),
        }
    }
}

impl From<PaymentsError> for WirePaymentsError {
    fn from(error: PaymentsError) -> Self {
        match error {
            PaymentsError::AgentAuthenticationFailed => Self::AgentAuthenticationFailed,
            PaymentsError::SignerUnavailable(reason) => Self::SignerUnavailable(reason),
            PaymentsError::Signer(error) => Self::Signer(error),
            PaymentsError::ManualApprovalPending {
                approval_request_id,
            } => Self::ManualApprovalPending {
                approval_request_id,
            },
            PaymentsError::InvalidConfig(reason) => Self::InvalidConfig(reason),
            PaymentsError::Persistence(reason) => Self::Persistence(reason),
            PaymentsError::InvalidRequest(reason) => Self::InvalidRequest(reason),
            PaymentsError::ChainRpc(reason) => Self::ChainRpc(reason),
            PaymentsError::SignedTransactionMismatch(reason) => {
                Self::SignedTransactionMismatch(reason)
            }
            PaymentsError::UnknownPendingApproval(id) => Self::UnknownPendingApproval(id),
            PaymentsError::Merchant(reason) => Self::Merchant(reason),
            PaymentsError::Internal(reason) => Self::Internal(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_matches_the_wire_kind() {
        let errors = [
            PaymentsError::AgentAuthenticationFailed,
            PaymentsError::SignerUnavailable("down".into()),
            PaymentsError::Signer(WireDaemonError::RequestExpired),
            PaymentsError::ManualApprovalPending {
                approval_request_id: Uuid::nil(),
            },
            PaymentsError::InvalidConfig("bad".into()),
            PaymentsError::Persistence("disk".into()),
            PaymentsError::InvalidRequest("no such network".into()),
            PaymentsError::ChainRpc("timeout".into()),
            PaymentsError::SignedTransactionMismatch("amount".into()),
            PaymentsError::UnknownPendingApproval(Uuid::nil()),
            PaymentsError::Merchant("unreachable".into()),
            PaymentsError::Internal("bug".into()),
        ];
        for error in errors {
            let kind = error.kind();
            let wire = serde_json::to_value(WirePaymentsError::from(error)).expect("encode");
            assert_eq!(wire["kind"], kind);
        }
    }

    #[test]
    fn signer_errors_keep_the_daemon_error() {
        let rejected = SignerError::Rejected(WireDaemonError::RequestExpired);
        assert_eq!(
            PaymentsError::from(rejected),
            PaymentsError::Signer(WireDaemonError::RequestExpired)
        );
        let down = SignerError::Unavailable("no socket".into());
        assert_eq!(
            PaymentsError::from(down),
            PaymentsError::SignerUnavailable("no socket".into())
        );
    }
}
