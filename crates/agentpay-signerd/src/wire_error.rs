//! Conversions between [`DaemonError`] and its serializable mirror
//! [`WireDaemonError`] (defined by the `agentpay-api` contract).
//!
//! `DaemonError` itself is not `Serialize`, so transports convert it into a
//! `WireDaemonError` before writing a failure response, and clients convert it
//! back. Both `match` blocks are exhaustive, so adding a daemon error variant
//! fails to compile until the wire contract is updated.

use agentpay_api::WireDaemonError;

use crate::DaemonError;

impl From<DaemonError> for WireDaemonError {
    fn from(value: DaemonError) -> Self {
        match value {
            DaemonError::AuthenticationFailed => Self::AuthenticationFailed,
            DaemonError::AdminAuthenticationRequired => Self::AdminAuthenticationRequired,
            DaemonError::RootPeerRequired => Self::RootPeerRequired,
            DaemonError::UnknownLease => Self::UnknownLease,
            DaemonError::InvalidLease => Self::InvalidLease,
            DaemonError::TooManyActiveLeases => Self::TooManyActiveLeases,
            DaemonError::UnknownAdminCredential(id) => Self::UnknownAdminCredential(id),
            DaemonError::InvalidAdminCredential(msg) => Self::InvalidAdminCredential(msg),
            DaemonError::TooManyAdminCredentials { max } => Self::TooManyAdminCredentials { max },
            DaemonError::InvalidAdminChallenge => Self::InvalidAdminChallenge,
            DaemonError::InvalidAdminChallengePurpose(msg) => {
                Self::InvalidAdminChallengePurpose(msg)
            }
            DaemonError::TooManyPendingAdminChallenges { max } => {
                Self::TooManyPendingAdminChallenges { max }
            }
            DaemonError::AdminCredentialLocked { credential_id } => {
                Self::AdminCredentialLocked { credential_id }
            }
            DaemonError::UnknownVaultKey(id) => Self::UnknownVaultKey(id),
            DaemonError::UnknownAgentKey(id) => Self::UnknownAgentKey(id),
            DaemonError::UnknownPolicy(id) => Self::UnknownPolicy(id),
            DaemonError::UnknownManualApprovalRequest(id) => Self::UnknownManualApprovalRequest(id),
            DaemonError::AgentAuthenticationFailed => Self::AgentAuthenticationFailed,
            DaemonError::PayloadActionMismatch => Self::PayloadActionMismatch,
            DaemonError::PayloadTooLarge { max_bytes } => Self::PayloadTooLarge { max_bytes },
            DaemonError::InvalidRequestTimestamps => Self::InvalidRequestTimestamps,
            DaemonError::RequestExpired => Self::RequestExpired,
            DaemonError::RequestReplayDetected => Self::RequestReplayDetected,
            DaemonError::TooManyTrackedReplayIds { max_tracked } => {
                Self::TooManyTrackedReplayIds { max_tracked }
            }
            DaemonError::InvalidPolicyAttachment(msg) => Self::InvalidPolicyAttachment(msg),
            DaemonError::InvalidNonceReservation(msg) => Self::InvalidNonceReservation(msg),
            DaemonError::TooManyActiveNonceReservations { max_active } => {
                Self::TooManyActiveNonceReservations { max_active }
            }
            DaemonError::NonceSkipTooLarge {
                requested_skip,
                max_skip,
            } => Self::NonceSkipTooLarge {
                requested_skip,
                max_skip,
            },
            DaemonError::UnknownNonceReservation(id) => Self::UnknownNonceReservation(id),
            DaemonError::MissingNonceReservation { chain_id, nonce } => {
                Self::MissingNonceReservation { chain_id, nonce }
            }
            DaemonError::InvalidPolicy(msg) => Self::InvalidPolicy(msg),
            DaemonError::InvalidAction(msg) => Self::InvalidAction(msg),
            DaemonError::ManualApprovalRequired {
                approval_request_id,
            } => Self::ManualApprovalRequired {
                approval_request_id,
            },
            DaemonError::ManualApprovalRejected {
                approval_request_id,
            } => Self::ManualApprovalRejected {
                approval_request_id,
            },
            DaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            } => Self::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            },
            DaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id,
                max_pending,
            } => Self::TooManyPendingManualApprovalRequests {
                agent_key_id,
                max_pending,
            },
            DaemonError::WalletAlreadyExists { vault_key_ids } => {
                Self::WalletAlreadyExists { vault_key_ids }
            }
            DaemonError::WalletNotFound => Self::WalletNotFound,
            DaemonError::InvalidWalletRequest(msg) => Self::InvalidWalletRequest(msg),
            DaemonError::InvalidSpendingLimits(msg) => Self::InvalidSpendingLimits(msg),
            DaemonError::InvalidWalletBackup(msg) => Self::InvalidWalletBackup(msg),
            DaemonError::WalletBackupDecryptionFailed => Self::WalletBackupDecryptionFailed,
            DaemonError::WeakBackupPassphrase { min_chars } => {
                Self::WeakBackupPassphrase { min_chars }
            }
            DaemonError::UnknownSignedTransaction(hash) => Self::UnknownSignedTransaction(hash),
            DaemonError::Policy(err) => Self::Policy(err),
            DaemonError::Signer(err) => Self::Signer(err),
            DaemonError::InvalidConfig(msg) => Self::InvalidConfig(msg),
            DaemonError::LockPoisoned => Self::LockPoisoned,
            DaemonError::Transport(msg) => Self::Transport(msg),
            DaemonError::Persistence(msg) => Self::Persistence(msg),
        }
    }
}

impl From<WireDaemonError> for DaemonError {
    fn from(value: WireDaemonError) -> Self {
        match value {
            WireDaemonError::AuthenticationFailed => DaemonError::AuthenticationFailed,
            WireDaemonError::AdminAuthenticationRequired => {
                DaemonError::AdminAuthenticationRequired
            }
            WireDaemonError::RootPeerRequired => DaemonError::RootPeerRequired,
            WireDaemonError::UnknownLease => DaemonError::UnknownLease,
            WireDaemonError::InvalidLease => DaemonError::InvalidLease,
            WireDaemonError::TooManyActiveLeases => DaemonError::TooManyActiveLeases,
            WireDaemonError::UnknownAdminCredential(id) => DaemonError::UnknownAdminCredential(id),
            WireDaemonError::InvalidAdminCredential(msg) => {
                DaemonError::InvalidAdminCredential(msg)
            }
            WireDaemonError::TooManyAdminCredentials { max } => {
                DaemonError::TooManyAdminCredentials { max }
            }
            WireDaemonError::InvalidAdminChallenge => DaemonError::InvalidAdminChallenge,
            WireDaemonError::InvalidAdminChallengePurpose(msg) => {
                DaemonError::InvalidAdminChallengePurpose(msg)
            }
            WireDaemonError::TooManyPendingAdminChallenges { max } => {
                DaemonError::TooManyPendingAdminChallenges { max }
            }
            WireDaemonError::AdminCredentialLocked { credential_id } => {
                DaemonError::AdminCredentialLocked { credential_id }
            }
            WireDaemonError::UnknownVaultKey(id) => DaemonError::UnknownVaultKey(id),
            WireDaemonError::UnknownAgentKey(id) => DaemonError::UnknownAgentKey(id),
            WireDaemonError::UnknownPolicy(id) => DaemonError::UnknownPolicy(id),
            WireDaemonError::UnknownManualApprovalRequest(id) => {
                DaemonError::UnknownManualApprovalRequest(id)
            }
            WireDaemonError::AgentAuthenticationFailed => DaemonError::AgentAuthenticationFailed,
            WireDaemonError::PayloadActionMismatch => DaemonError::PayloadActionMismatch,
            WireDaemonError::PayloadTooLarge { max_bytes } => {
                DaemonError::PayloadTooLarge { max_bytes }
            }
            WireDaemonError::InvalidRequestTimestamps => DaemonError::InvalidRequestTimestamps,
            WireDaemonError::RequestExpired => DaemonError::RequestExpired,
            WireDaemonError::RequestReplayDetected => DaemonError::RequestReplayDetected,
            WireDaemonError::TooManyTrackedReplayIds { max_tracked } => {
                DaemonError::TooManyTrackedReplayIds { max_tracked }
            }
            WireDaemonError::InvalidPolicyAttachment(msg) => {
                DaemonError::InvalidPolicyAttachment(msg)
            }
            WireDaemonError::InvalidNonceReservation(msg) => {
                DaemonError::InvalidNonceReservation(msg)
            }
            WireDaemonError::TooManyActiveNonceReservations { max_active } => {
                DaemonError::TooManyActiveNonceReservations { max_active }
            }
            WireDaemonError::NonceSkipTooLarge {
                requested_skip,
                max_skip,
            } => DaemonError::NonceSkipTooLarge {
                requested_skip,
                max_skip,
            },
            WireDaemonError::UnknownNonceReservation(id) => {
                DaemonError::UnknownNonceReservation(id)
            }
            WireDaemonError::MissingNonceReservation { chain_id, nonce } => {
                DaemonError::MissingNonceReservation { chain_id, nonce }
            }
            WireDaemonError::InvalidPolicy(msg) => DaemonError::InvalidPolicy(msg),
            WireDaemonError::InvalidAction(msg) => DaemonError::InvalidAction(msg),
            WireDaemonError::ManualApprovalRequired {
                approval_request_id,
            } => DaemonError::ManualApprovalRequired {
                approval_request_id,
            },
            WireDaemonError::ManualApprovalRejected {
                approval_request_id,
            } => DaemonError::ManualApprovalRejected {
                approval_request_id,
            },
            WireDaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            } => DaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            },
            WireDaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id,
                max_pending,
            } => DaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id,
                max_pending,
            },
            WireDaemonError::WalletAlreadyExists { vault_key_ids } => {
                DaemonError::WalletAlreadyExists { vault_key_ids }
            }
            WireDaemonError::WalletNotFound => DaemonError::WalletNotFound,
            WireDaemonError::InvalidWalletRequest(msg) => DaemonError::InvalidWalletRequest(msg),
            WireDaemonError::InvalidSpendingLimits(msg) => DaemonError::InvalidSpendingLimits(msg),
            WireDaemonError::InvalidWalletBackup(msg) => DaemonError::InvalidWalletBackup(msg),
            WireDaemonError::WalletBackupDecryptionFailed => {
                DaemonError::WalletBackupDecryptionFailed
            }
            WireDaemonError::WeakBackupPassphrase { min_chars } => {
                DaemonError::WeakBackupPassphrase { min_chars }
            }
            WireDaemonError::UnknownSignedTransaction(hash) => {
                DaemonError::UnknownSignedTransaction(hash)
            }
            WireDaemonError::Policy(err) => DaemonError::Policy(err),
            WireDaemonError::Signer(err) => DaemonError::Signer(err),
            WireDaemonError::InvalidConfig(msg) => DaemonError::InvalidConfig(msg),
            WireDaemonError::LockPoisoned => DaemonError::LockPoisoned,
            WireDaemonError::Transport(msg) => DaemonError::Transport(msg),
            WireDaemonError::Persistence(msg) => DaemonError::Persistence(msg),
        }
    }
}
