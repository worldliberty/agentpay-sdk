use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ts_rs::TS;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::schema::Timestamp;
use crate::AgentAction;

/// Request sent by an agent to evaluate, explain, or sign an [`AgentAction`].
///
/// Freshness rules (checked by the daemon): `requested_at < expires_at`,
/// `expires_at` in the future, `requested_at` at most 30 s ahead of the
/// daemon clock, and `expires_at - requested_at` at most 5 minutes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct SignRequest {
    /// Client-generated unique request identifier (UUID v4 recommended).
    ///
    /// A signed request id is consumed: reusing it with a different payload
    /// fails with `RequestReplayDetected`, while resending the identical
    /// request returns the recorded signature (idempotent retry).
    pub request_id: Uuid,
    /// Agent key used for authorization.
    pub agent_key_id: Uuid,
    /// Bearer token bound to `agent_key_id` (from `AgentCredentials.auth_token`).
    #[serde(with = "crate::serde_helpers::zeroizing_string")]
    #[schemars(with = "String")]
    #[ts(as = "String")]
    pub agent_auth_token: Zeroizing<String>,
    /// Payload bytes as a JSON array of byte values (0-255), at most 32 KiB.
    ///
    /// Security contract: payload must be the canonical compact JSON encoding
    /// of `action` (`serde_json::to_vec(&action)`: struct fields in declaration
    /// order, no whitespace); the daemon rejects semantic or byte-level
    /// mismatches with `PayloadActionMismatch`.
    pub payload: Vec<u8>,
    /// Semantic action details used by policy checks.
    pub action: AgentAction,
    /// Request timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub requested_at: OffsetDateTime,
    /// Request expiry timestamp (UTC).
    #[schemars(with = "Timestamp")]
    #[ts(as = "Timestamp")]
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for SignRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignRequest")
            .field("request_id", &self.request_id)
            .field("agent_key_id", &self.agent_key_id)
            .field("agent_auth_token", &"<redacted>")
            .field("payload", &self.payload)
            .field("action", &self.action)
            .field("requested_at", &self.requested_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SignRequest {
    /// Wipes the auth token and payload in place.
    pub fn zeroize_secrets(&mut self) {
        self.agent_auth_token.zeroize();
        self.payload.zeroize();
    }
}
