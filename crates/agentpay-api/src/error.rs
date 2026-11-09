//! The error body of a failed call (`WireResponse.ok == false`).
//!
//! JSON: `{"kind": "<Kind>"}` for kinds without data, otherwise
//! `{"kind": "<Kind>", "data": ...}` where `data` is a string, a UUID string, or
//! an object, as documented per variant. Clients must treat an unknown `kind`
//! as a generic failure (new kinds may be added in minor versions).
//!
//! Every admin method can fail with the admin-auth kinds
//! (`AdminAuthenticationRequired`, `UnknownLease`, `InvalidLease`,
//! `AuthenticationFailed`); every agent method with `AgentAuthenticationFailed`
//! and, when it carries timestamps, `InvalidRequestTimestamps` /
//! `RequestExpired`; and every method with `LockPoisoned` and (for methods
//! that persist state) `Persistence`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::types::{ManualApprovalStatus, PolicyError, SignerError};

/// Serializable daemon error, one kind per failure the daemon can report.
///
/// The `kind` names are stable within a major API version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "kind", content = "data")]
pub enum WireDaemonError {
    /// An admin proof was rejected: a challenge signature did not verify, or
    /// a lease secret (or the lease's peer euid) did not match.
    /// `{"kind": "AuthenticationFailed"}`.
    AuthenticationFailed,
    /// An admin method was called by a non-root peer without a lease.
    /// `{"kind": "AdminAuthenticationRequired"}`.
    AdminAuthenticationRequired,
    /// The method is reserved for root peers (`EnrollAdminCredential`).
    /// `{"kind": "RootPeerRequired"}`.
    RootPeerRequired,
    /// The presented lease id is unknown (never issued, revoked, or forgotten
    /// on daemon restart), or `RevokeAdminLease` named an unknown lease.
    UnknownLease,
    /// The presented lease has expired; obtain a new one.
    InvalidLease,
    /// The daemon already holds the maximum number of active leases (64).
    TooManyActiveLeases,
    /// No admin credential has this id. `{"kind": "UnknownAdminCredential", "data": "<uuid>"}`.
    UnknownAdminCredential(Uuid),
    /// The credential payload was invalid (bad SEC1 key, bad label, already
    /// enrolled). `data` is a human-readable reason.
    InvalidAdminCredential(String),
    /// Enrollment refused: the credential limit was reached.
    TooManyAdminCredentials {
        /// Maximum enrolled credentials (8 by default).
        max: usize,
    },
    /// The challenge is unknown, expired, already used, or was begun by a
    /// different peer euid.
    InvalidAdminChallenge,
    /// The challenge `purpose` is not 1-128 characters of `[A-Za-z0-9._:/-]`.
    /// `data` is a human-readable reason.
    InvalidAdminChallengePurpose(String),
    /// Too many unanswered challenges are pending.
    TooManyPendingAdminChallenges {
        /// Maximum pending challenges (64 by default).
        max: usize,
    },
    /// The credential is locked for 30 seconds after 5 failed signatures.
    AdminCredentialLocked {
        /// The locked credential.
        credential_id: Uuid,
    },
    /// No vault key has this id. `data` is the id.
    UnknownVaultKey(Uuid),
    /// No agent key has this id. `data` is the id.
    UnknownAgentKey(Uuid),
    /// No policy has this id. `data` is the id.
    UnknownPolicy(Uuid),
    /// No (retained) manual approval request has this id. `data` is the id.
    UnknownManualApprovalRequest(Uuid),
    /// The agent key id is unknown, the token does not match, or the agent
    /// does not own the referenced reservation.
    AgentAuthenticationFailed,
    /// `payload` is not the canonical JSON encoding of `action`.
    PayloadActionMismatch,
    /// `payload` exceeds the daemon limit.
    PayloadTooLarge {
        /// Maximum payload size in bytes (32 KiB by default).
        max_bytes: usize,
    },
    /// `requested_at`/`expires_at` violate the freshness rules (ordering,
    /// 30-second clock skew, 5-minute maximum lifetime).
    InvalidRequestTimestamps,
    /// `expires_at` is in the past.
    RequestExpired,
    /// The `request_id` was already used for a different request.
    RequestReplayDetected,
    /// The replay-protection table is full; retry later.
    TooManyTrackedReplayIds {
        /// Maximum tracked request ids.
        max_tracked: usize,
    },
    /// The policy attachment is invalid (empty set, disabled policy, or an
    /// agent/vault key mismatch). `data` is a human-readable reason.
    InvalidPolicyAttachment(String),
    /// The nonce reservation request is invalid. `data` is a human-readable reason.
    InvalidNonceReservation(String),
    /// Too many active nonce reservations.
    TooManyActiveNonceReservations {
        /// Maximum active reservations.
        max_active: usize,
    },
    /// The reservation would skip too far past the tracked nonce head.
    NonceSkipTooLarge {
        /// Number of nonces the request would have skipped.
        requested_skip: u64,
        /// Maximum permitted skip (1024).
        max_skip: u64,
    },
    /// No active reservation has this id. `data` is the id.
    UnknownNonceReservation(Uuid),
    /// A `BroadcastTx` was submitted without an active reservation of its nonce.
    MissingNonceReservation {
        /// EVM chain id of the transaction.
        chain_id: u64,
        /// Transaction nonce.
        nonce: u64,
    },
    /// The policy payload is invalid (validation failure or duplicate id).
    /// `data` is a human-readable reason.
    InvalidPolicy(String),
    /// The action failed domain validation (bad address, unrecognized
    /// calldata, inconsistent Tempo channel, ...). `data` is a human-readable reason.
    InvalidAction(String),
    /// The request is held for an operator decision. Not a failure: approve
    /// the request (`DecideManualApprovalRequest`), then resend the same
    /// action (a fresh `request_id` and timestamps are fine).
    ManualApprovalRequired {
        /// The pending approval request.
        approval_request_id: Uuid,
    },
    /// An operator rejected the approval request for this action.
    ManualApprovalRejected {
        /// The rejected approval request.
        approval_request_id: Uuid,
    },
    /// The approval request was already decided or completed.
    ManualApprovalRequestNotPending {
        /// The approval request.
        approval_request_id: Uuid,
        /// Its current status.
        status: ManualApprovalStatus,
    },
    /// The agent already has the maximum number of pending approval requests.
    TooManyPendingManualApprovalRequests {
        /// Agent key that owns the pending requests.
        agent_key_id: Uuid,
        /// Maximum pending requests per agent key (64 by default).
        max_pending: usize,
    },
    /// `BootstrapWallet` would create or restore a wallet, but the daemon
    /// already holds one; pass `replace_existing: true` to destroy it, or use
    /// `reuse`.
    WalletAlreadyExists {
        /// The existing vault keys, ascending.
        vault_key_ids: Vec<Uuid>,
    },
    /// The daemon holds no wallet (vault key) to reuse or back up.
    WalletNotFound,
    /// The wallet operation is ambiguous or inconsistent (for example several
    /// vault keys and no `vault_key_id`). `data` is a human-readable reason.
    InvalidWalletRequest(String),
    /// A spending limit row is invalid. `data` is a human-readable reason.
    InvalidSpendingLimits(String),
    /// The backup document is not a valid wallet backup (malformed, an
    /// unsupported version or KDF parameters, or metadata that does not match
    /// the decrypted key). `data` is a human-readable reason.
    InvalidWalletBackup(String),
    /// The backup could not be decrypted: the passphrase is wrong or the
    /// document was altered (the two are indistinguishable).
    WalletBackupDecryptionFailed,
    /// A new backup's passphrase is too short.
    WeakBackupPassphrase {
        /// Minimum passphrase length in characters (12).
        min_chars: usize,
    },
    /// `ReleaseSignedNonce` named a transaction this daemon did not sign for
    /// the agent, already released, or signed more than 10 minutes ago.
    /// `data` is the transaction hash.
    UnknownSignedTransaction(String),
    /// The policy engine denied the request. `data` is a [`PolicyError`].
    Policy(PolicyError),
    /// The signer backend failed. `data` is a [`SignerError`].
    Signer(SignerError),
    /// The daemon configuration is invalid. `data` is a human-readable reason.
    InvalidConfig(String),
    /// Internal locking failure; the daemon should be restarted.
    LockPoisoned,
    /// A transport or serialization failure inside the daemon. `data` is a
    /// human-readable reason.
    Transport(String),
    /// Persisting daemon state failed; the change was rolled back. `data` is a
    /// human-readable reason.
    Persistence(String),
}
