//! Admin challenges: issuance, the canonical signed message, and completion.
//!
//! The message format (`agentpay-admin-challenge-v1`) is part of the public
//! daemon API and documented in `agentpay_api::auth`; the constants below come
//! from there so the daemon and the contract cannot diverge. Every challenge
//! is single use: completing it consumes it whether or not the signature
//! verifies, and failures count toward the credential's lockout.

use agentpay_api::auth::{
    is_valid_admin_challenge_purpose, ADMIN_CHALLENGE_DOMAIN_TAG as CHALLENGE_DOMAIN_TAG,
    ADMIN_CHALLENGE_NONCE_BYTES as CHALLENGE_NONCE_LEN,
    MAX_ADMIN_CHALLENGE_PURPOSE_BYTES as MAX_PURPOSE_BYTES,
};
use agentpay_domain::{AdminChallenge, AdminLease};
use agentpay_signer::VaultSignerBackend;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DaemonError, InMemoryDaemon, RequestContext};

/// Maximum DER signature hex length (a P-256 DER signature is at most 72 bytes).
const MAX_SIGNATURE_HEX_CHARS: usize = 160;

/// A challenge waiting for its signature.
#[derive(Debug)]
pub(super) struct PendingChallenge {
    pub(super) credential_id: Uuid,
    peer_euid: Option<u32>,
    message: Vec<u8>,
    expires_at: OffsetDateTime,
}

/// Inputs to the canonical challenge message.
pub(crate) struct ChallengeMessage<'a> {
    pub(crate) instance_id: Uuid,
    pub(crate) credential_id: Uuid,
    pub(crate) challenge_id: Uuid,
    pub(crate) nonce: [u8; CHALLENGE_NONCE_LEN],
    pub(crate) purpose: &'a str,
    pub(crate) expires_at: OffsetDateTime,
}

impl ChallengeMessage<'_> {
    /// Encodes the message bytes described in the module docs.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, DaemonError> {
        let purpose_len = u16::try_from(self.purpose.len())
            .map_err(|_| DaemonError::InvalidAdminChallengePurpose("purpose is too long".into()))?;
        let mut message = Vec::with_capacity(
            CHALLENGE_DOMAIN_TAG.len() + 1 + 48 + CHALLENGE_NONCE_LEN + 2 + self.purpose.len() + 8,
        );
        message.extend_from_slice(CHALLENGE_DOMAIN_TAG);
        message.push(0);
        message.extend_from_slice(self.instance_id.as_bytes());
        message.extend_from_slice(self.credential_id.as_bytes());
        message.extend_from_slice(self.challenge_id.as_bytes());
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&purpose_len.to_be_bytes());
        message.extend_from_slice(self.purpose.as_bytes());
        message.extend_from_slice(&self.expires_at.unix_timestamp().to_be_bytes());
        Ok(message)
    }
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Issues a single-use challenge for `credential_id`, bound to the caller's peer euid.
    pub(crate) fn begin_admin_challenge_impl(
        &self,
        ctx: &RequestContext,
        credential_id: Uuid,
        purpose: &str,
    ) -> Result<AdminChallenge, DaemonError> {
        validate_purpose(purpose)?;
        self.admin_credential(credential_id)?;
        let now = OffsetDateTime::now_utc();
        let expires_at = now
            .checked_add(self.config.admin_challenge_ttl)
            .ok_or_else(|| {
                DaemonError::InvalidConfig("admin_challenge_ttl causes timestamp overflow".into())
            })?;
        let challenge_id = Uuid::new_v4();
        let message = ChallengeMessage {
            instance_id: self.instance_id,
            credential_id,
            challenge_id,
            nonce: rand::random::<[u8; CHALLENGE_NONCE_LEN]>(),
            purpose,
            expires_at,
        }
        .encode()?;

        let mut state = self.lock_admin_auth()?;
        state.ensure_not_locked(credential_id, now)?;
        state
            .challenges
            .retain(|_, pending| pending.expires_at > now);
        if state.challenges.len() >= self.config.max_pending_admin_challenges {
            return Err(DaemonError::TooManyPendingAdminChallenges {
                max: self.config.max_pending_admin_challenges,
            });
        }
        let challenge = AdminChallenge {
            challenge_id,
            message_hex: hex::encode(&message),
            expires_at,
        };
        state.challenges.insert(
            challenge_id,
            PendingChallenge {
                credential_id,
                peer_euid: ctx.peer_euid(),
                message,
                expires_at,
            },
        );
        Ok(challenge)
    }

    /// Consumes a challenge and exchanges a valid signature for an admin lease.
    pub(crate) fn complete_admin_challenge_impl(
        &self,
        ctx: &RequestContext,
        challenge_id: Uuid,
        signature_der_hex: &str,
    ) -> Result<AdminLease, DaemonError> {
        let now = OffsetDateTime::now_utc();
        let pending = {
            let mut state = self.lock_admin_auth()?;
            let pending = state
                .challenges
                .remove(&challenge_id)
                .ok_or(DaemonError::InvalidAdminChallenge)?;
            if pending.expires_at <= now || pending.peer_euid != ctx.peer_euid() {
                return Err(DaemonError::InvalidAdminChallenge);
            }
            state.ensure_not_locked(pending.credential_id, now)?;
            pending
        };
        let credential = self.admin_credential(pending.credential_id)?;

        if verify_signature(
            &credential.public_key_sec1_hex,
            &pending.message,
            signature_der_hex,
        )
        .is_err()
        {
            self.lock_admin_auth()?.record_failure(
                pending.credential_id,
                now,
                self.config.max_failed_admin_auth_attempts,
                self.config.admin_auth_lockout,
            )?;
            return Err(DaemonError::AuthenticationFailed);
        }

        self.lock_admin_auth()?
            .failures
            .remove(&pending.credential_id);
        self.issue_admin_lease(ctx, pending.credential_id, now)
    }
}

/// Verifies a DER ECDSA P-256 signature over SHA-256(`message`).
fn verify_signature(
    public_key_sec1_hex: &str,
    message: &[u8],
    signature_der_hex: &str,
) -> Result<(), DaemonError> {
    let signature_der_hex = signature_der_hex.trim();
    if signature_der_hex.len() > MAX_SIGNATURE_HEX_CHARS {
        return Err(DaemonError::AuthenticationFailed);
    }
    let signature_der =
        hex::decode(signature_der_hex).map_err(|_| DaemonError::AuthenticationFailed)?;
    let signature =
        Signature::from_der(&signature_der).map_err(|_| DaemonError::AuthenticationFailed)?;
    let public_key = hex::decode(public_key_sec1_hex).map_err(|_| {
        DaemonError::InvalidAdminCredential("stored public key is not hex".to_string())
    })?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| {
        DaemonError::InvalidAdminCredential("stored public key is invalid".to_string())
    })?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| DaemonError::AuthenticationFailed)
}

/// Purposes are short printable identifiers such as `admin-session` or `approve:<uuid>`.
fn validate_purpose(purpose: &str) -> Result<(), DaemonError> {
    if !is_valid_admin_challenge_purpose(purpose) {
        return Err(DaemonError::InvalidAdminChallengePurpose(format!(
            "challenge purpose must be 1 to {MAX_PURPOSE_BYTES} characters of [A-Za-z0-9._:/-]"
        )));
    }
    Ok(())
}
