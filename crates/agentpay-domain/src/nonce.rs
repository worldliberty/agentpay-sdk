use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::schema::Timestamp;

/// Agent request for reserving a unique broadcast nonce.
///
/// Same freshness rules as [`crate::SignRequest`]. Resending an identical
/// request (same `request_id`) returns the recorded reservation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct NonceReservationRequest {
    /// Client-generated unique request identifier for replay protection.
    pub request_id: Uuid,
    /// Agent key used for authorization.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id`.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub agent_auth_token: Zeroizing<String>,
    /// EVM chain id for nonce scope (decimal, for example `56` for BSC).
    pub chain_id: u64,
    /// Minimum nonce the caller is willing to reserve, typically the
    /// account's pending transaction count from RPC.
    pub min_nonce: u64,
    /// When true, reserve exactly `min_nonce` instead of allowing a higher
    /// nonce head; defaults to `false` when absent.
    #[serde(default)]
    pub exact_nonce: bool,
    /// Request timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for NonceReservationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceReservationRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("chain_id", &self.chain_id)
            .field("min_nonce", &self.min_nonce)
            .field("exact_nonce", &self.exact_nonce)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl NonceReservationRequest {
    /// Wipes the auth token in place.
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
    }
}

/// Reserved nonce lease for a specific agent and chain.
///
/// A `BroadcastTx` sign request must carry a nonce reserved this way; signing
/// consumes the reservation. Unused reservations expire (2 minutes by default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct NonceReservation {
    /// Unique reservation identifier.
    pub reservation_id: Uuid,
    /// Agent key that owns this reservation.
    pub agent_key_id: Uuid,
    /// Backing vault key used for signing scope.
    pub vault_key_id: Uuid,
    /// EVM chain id for nonce scope.
    pub chain_id: u64,
    /// Reserved nonce value; use it as the transaction nonce.
    pub nonce: u64,
    /// Lease issuance timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub issued_at: OffsetDateTime,
    /// Lease expiry timestamp (UTC); the reservation is valid while `now < expires_at`.
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}

impl NonceReservation {
    /// Returns whether the reservation is currently active at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.issued_at && now < self.expires_at
    }
}

/// Agent request for explicitly releasing a nonce reservation.
///
/// Same freshness rules as [`crate::SignRequest`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct NonceReleaseRequest {
    /// Client-generated unique request identifier for replay protection.
    pub request_id: Uuid,
    /// Agent key used for authorization.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id`.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub agent_auth_token: Zeroizing<String>,
    /// Reservation id to release (from [`NonceReservation::reservation_id`]).
    pub reservation_id: Uuid,
    /// Request timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for NonceReleaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonceReleaseRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("reservation_id", &self.reservation_id)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl NonceReleaseRequest {
    /// Wipes the auth token in place.
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
    }
}

/// Agent request for returning the nonce of a signed `BroadcastTx` whose
/// transaction provably never reached the network.
///
/// Same freshness rules as [`crate::SignRequest`]. Only send it when the
/// transaction was certainly not submitted (see `ReleaseSignedNonce` in the
/// daemon API): a released nonce is handed out again, so a transaction that
/// did reach a node could be replaced by the next one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SignedNonceReleaseRequest {
    /// Client-generated unique request identifier for replay protection.
    pub request_id: Uuid,
    /// Agent key used for authorization; it must be the agent that signed the transaction.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id`.
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub agent_auth_token: Zeroizing<String>,
    /// EVM chain id of the signed transaction.
    pub chain_id: u64,
    /// Nonce of the signed transaction.
    pub nonce: u64,
    /// Hash of the signed transaction (`tx_hash_hex` from `SignForAgent`):
    /// `0x` + 64 hex characters, any case.
    pub tx_hash_hex: String,
    /// Request timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for SignedNonceReleaseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedNonceReleaseRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("chain_id", &self.chain_id)
            .field("nonce", &self.nonce)
            .field("tx_hash_hex", &self.tx_hash_hex)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SignedNonceReleaseRequest {
    /// Wipes the auth token in place.
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
    }
}
