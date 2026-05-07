use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{AgentAction, AssetId, DomainError, RecipientId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualApprovalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualApprovalRequest {
    pub id: Uuid,
    pub agent_key_id: Uuid,
    pub vault_key_id: Uuid,
    pub request_payload_hash_hex: String,
    pub action: AgentAction,
    pub chain_id: u64,
    pub asset: AssetId,
    pub recipient: RecipientId,
    #[serde(with = "crate::u128_as_decimal_string")]
    pub amount_wei: u128,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub status: ManualApprovalStatus,
    pub triggered_by_policy_ids: Vec<Uuid>,
    pub completed_at: Option<OffsetDateTime>,
    pub rejection_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    pub relay_url: Option<String>,
    pub frontend_url: Option<String>,
    pub daemon_id_hex: String,
    pub daemon_public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayFeedbackStatus {
    pub update_id: String,
    pub status: String,
    pub detail: Option<String>,
}

pub fn manual_approval_capability_token(
    relay_private_key_hex: &str,
    approval_request_id: Uuid,
) -> Result<String, DomainError> {
    let normalized = relay_private_key_hex.trim().trim_start_matches("0x");
    if normalized.is_empty() {
        return Err(DomainError::InvalidRelayCapabilitySecret);
    }

    let secret_bytes =
        hex::decode(normalized).map_err(|_| DomainError::InvalidRelayCapabilitySecret)?;
    if secret_bytes.len() != 32 {
        return Err(DomainError::InvalidRelayCapabilitySecret);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"agentpay:manual-approval-capability:v1");
    hasher.update(secret_bytes);
    hasher.update(approval_request_id.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

pub fn manual_approval_capability_hash(token: &str) -> Result<String, DomainError> {
    let normalized = token.trim();
    if normalized.is_empty() {
        return Err(DomainError::InvalidRelayCapabilityToken);
    }

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}
