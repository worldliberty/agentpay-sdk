//! Error type returned by every daemon operation.

use agentpay_domain::ManualApprovalStatus;
use agentpay_policy::PolicyError;
use agentpay_signer::SignerError;
use thiserror::Error;
use uuid::Uuid;

/// Daemon-level errors.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Admin proof was rejected (bad challenge signature or lease secret).
    #[error("authentication failed")]
    AuthenticationFailed,
    /// A privileged call arrived without a lease from a non-root peer.
    #[error("admin authentication required: connect as root or present an admin lease")]
    AdminAuthenticationRequired,
    /// The operation is reserved for root peers (for example credential enrollment).
    #[error("this operation requires a root peer")]
    RootPeerRequired,
    /// Lease id was not issued by daemon.
    #[error("lease is unknown")]
    UnknownLease,
    /// Lease is expired or not yet valid.
    #[error("lease has expired or is not active yet")]
    InvalidLease,
    /// Lease issuance denied because active lease capacity was reached.
    #[error("too many active leases")]
    TooManyActiveLeases,
    /// Admin credential id not found.
    #[error("unknown admin credential id: {0}")]
    UnknownAdminCredential(Uuid),
    /// Admin credential enrollment payload was invalid.
    #[error("invalid admin credential: {0}")]
    InvalidAdminCredential(String),
    /// Enrollment denied because the credential limit was reached.
    #[error("too many admin credentials (max {max})")]
    TooManyAdminCredentials {
        /// Maximum enrolled credentials.
        max: usize,
    },
    /// Admin challenge is unknown, expired, or already used.
    #[error("admin challenge is unknown, expired, or already used")]
    InvalidAdminChallenge,
    /// Requested challenge purpose was malformed.
    #[error("invalid admin challenge purpose: {0}")]
    InvalidAdminChallengePurpose(String),
    /// Challenge issuance denied because too many challenges are pending.
    #[error("too many pending admin challenges (max {max})")]
    TooManyPendingAdminChallenges {
        /// Maximum pending challenges.
        max: usize,
    },
    /// Credential is temporarily locked after repeated failed signatures.
    #[error("admin credential {credential_id} is temporarily locked after failed attempts")]
    AdminCredentialLocked {
        /// Locked credential.
        credential_id: Uuid,
    },
    /// Vault key id not found.
    #[error("unknown vault key id: {0}")]
    UnknownVaultKey(Uuid),
    /// Agent key id not found.
    #[error("unknown agent key id: {0}")]
    UnknownAgentKey(Uuid),
    /// Policy id not found.
    #[error("unknown policy id: {0}")]
    UnknownPolicy(Uuid),
    /// Manual approval request id not found.
    #[error("unknown manual approval request id: {0}")]
    UnknownManualApprovalRequest(Uuid),
    /// Agent key token did not match provisioned secret.
    #[error("agent authentication failed")]
    AgentAuthenticationFailed,
    /// Request payload did not match declared action.
    #[error("sign request payload/action mismatch")]
    PayloadActionMismatch,
    /// Request payload exceeded configured daemon limit.
    #[error("sign request payload exceeds max bytes ({max_bytes})")]
    PayloadTooLarge {
        /// Maximum allowed payload size in bytes.
        max_bytes: usize,
    },
    /// Request timestamp bounds were invalid.
    #[error("request timestamp bounds are invalid")]
    InvalidRequestTimestamps,
    /// Request has expired.
    #[error("request has expired")]
    RequestExpired,
    /// Request ID was already consumed.
    #[error("request id already used")]
    RequestReplayDetected,
    /// Replay protection table reached configured capacity.
    #[error("too many tracked replay ids (max {max_tracked})")]
    TooManyTrackedReplayIds {
        /// Maximum tracked replay ids allowed at once.
        max_tracked: usize,
    },
    /// Agent-key policy attachment was invalid.
    #[error("invalid agent policy attachment: {0}")]
    InvalidPolicyAttachment(String),
    /// Nonce reservation request was invalid.
    #[error("invalid nonce reservation request: {0}")]
    InvalidNonceReservation(String),
    /// Active nonce reservations reached configured capacity.
    #[error("too many active nonce reservations (max {max_active})")]
    TooManyActiveNonceReservations {
        /// Maximum active nonce reservations allowed at once.
        max_active: usize,
    },
    /// Nonce reservation skipped too far ahead of the tracked chain head.
    #[error(
        "nonce reservation skips {requested_skip} nonces ahead of the chain head (max {max_skip})"
    )]
    NonceSkipTooLarge {
        /// Number of nonces the request would have skipped.
        requested_skip: u64,
        /// Maximum permitted skip.
        max_skip: u64,
    },
    /// Nonce reservation id was not found.
    #[error("unknown nonce reservation id: {0}")]
    UnknownNonceReservation(Uuid),
    /// Signing a broadcast tx requires a matching nonce reservation.
    #[error("missing nonce reservation for chain_id {chain_id} and nonce {nonce}")]
    MissingNonceReservation {
        /// EVM chain id.
        chain_id: u64,
        /// Transaction nonce.
        nonce: u64,
    },
    /// Policy payload was invalid.
    #[error("invalid policy payload: {0}")]
    InvalidPolicy(String),
    /// Sign request action failed domain validation (for example unrecognized calldata).
    #[error("invalid sign request action: {0}")]
    InvalidAction(String),
    /// Request requires explicit manual approval before signing can continue.
    #[error("manual approval required (request {approval_request_id})")]
    ManualApprovalRequired { approval_request_id: Uuid },
    /// Existing manual approval request was rejected.
    #[error("manual approval request {approval_request_id} was rejected")]
    ManualApprovalRejected { approval_request_id: Uuid },
    /// Manual approval request was already resolved and cannot be decided again.
    #[error("manual approval request {approval_request_id} is already {status:?}")]
    ManualApprovalRequestNotPending {
        approval_request_id: Uuid,
        status: ManualApprovalStatus,
    },
    /// Agent key already has the maximum number of pending manual approval requests.
    #[error("agent key {agent_key_id} already has {max_pending} pending manual approval requests; resolve or wait for them to expire before requesting more")]
    TooManyPendingManualApprovalRequests {
        /// Agent key that owns the pending requests.
        agent_key_id: Uuid,
        /// Maximum pending requests allowed per agent key.
        max_pending: usize,
    },
    /// A wallet already exists and the bootstrap did not ask to replace it.
    #[error(
        "a wallet already exists (vault keys {vault_key_ids:?}); reuse it or pass replace_existing"
    )]
    WalletAlreadyExists {
        /// The existing vault keys, ascending.
        vault_key_ids: Vec<Uuid>,
    },
    /// No wallet (vault key) exists.
    #[error("no wallet exists; run BootstrapWallet first")]
    WalletNotFound,
    /// A wallet operation was ambiguous or inconsistent.
    #[error("invalid wallet request: {0}")]
    InvalidWalletRequest(String),
    /// A spending limit row was invalid.
    #[error("invalid spending limits: {0}")]
    InvalidSpendingLimits(String),
    /// A backup document was not a valid wallet backup.
    #[error("invalid wallet backup: {0}")]
    InvalidWalletBackup(String),
    /// A backup could not be decrypted (wrong passphrase or altered document).
    #[error("the wallet backup passphrase is incorrect or the backup was altered")]
    WalletBackupDecryptionFailed,
    /// A new backup's passphrase was too short.
    #[error("the backup passphrase must have at least {min_chars} characters")]
    WeakBackupPassphrase {
        /// Minimum passphrase length in characters.
        min_chars: usize,
    },
    /// `ReleaseSignedNonce` named a transaction that is not releasable.
    #[error("no releasable signed transaction {0}")]
    UnknownSignedTransaction(String),
    /// Policy engine denied request.
    #[error("policy check failed: {0}")]
    Policy(#[from] PolicyError),
    /// Signer backend failed.
    #[error("signer backend error: {0}")]
    Signer(#[from] SignerError),
    /// Daemon configuration is invalid.
    #[error("invalid daemon configuration: {0}")]
    InvalidConfig(String),
    /// Transport or serialization layer failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// Persistent-state storage failed.
    #[error("persistent state error: {0}")]
    Persistence(String),
    /// Internal locking failure.
    #[error("internal lock poisoned")]
    LockPoisoned,
}
