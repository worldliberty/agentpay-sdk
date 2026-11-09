//! Caller authentication: the admin authorization gate (root peer or admin
//! lease), agent bearer tokens, request freshness checks, and request-id replay
//! tracking.
//!
//! Admin credentials, challenges, and leases live in [`super::admin_auth`].

use agentpay_domain::{AdminAuth, AgentKey};
use agentpay_signer::VaultSignerBackend;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DaemonError, InMemoryDaemon, RequestContext};

/// Upper bound on the size of an agent auth token accepted for verification.
const MAX_AUTH_SECRET_BYTES: usize = 16 * 1024;

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Authorizes a privileged call.
    ///
    /// [`AdminAuth::PeerCredentials`] succeeds only for root-equivalent callers
    /// (root peers and in-process callers). A presented lease is always
    /// verified, even for root peers, so a stale lease fails loudly instead of
    /// being silently ignored.
    pub(super) fn authorize_admin(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        match auth {
            AdminAuth::PeerCredentials if ctx.is_root_equivalent() => Ok(()),
            AdminAuth::PeerCredentials => Err(DaemonError::AdminAuthenticationRequired),
            AdminAuth::Lease(session) => self.verify_admin_lease(ctx, session, now),
        }
    }

    pub(super) fn validate_request_timestamps(
        &self,
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        if expires_at <= now {
            return Err(DaemonError::RequestExpired);
        }
        if expires_at <= requested_at {
            return Err(DaemonError::InvalidRequestTimestamps);
        }
        if requested_at > now + self.config.max_request_clock_skew {
            return Err(DaemonError::InvalidRequestTimestamps);
        }
        let ttl = expires_at - requested_at;
        if ttl > self.config.max_request_ttl {
            return Err(DaemonError::InvalidRequestTimestamps);
        }
        Ok(())
    }

    pub(super) fn authenticate_agent(
        &self,
        agent_key_id: Uuid,
        agent_auth_token: &str,
    ) -> Result<AgentKey, DaemonError> {
        if agent_auth_token.len() > MAX_AUTH_SECRET_BYTES {
            return Err(DaemonError::AgentAuthenticationFailed);
        }

        let expected_auth_hash = self
            .agent_auth_tokens
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .copied()
            .ok_or(DaemonError::AgentAuthenticationFailed)?;
        let presented_auth_hash = hash_agent_auth_token(agent_auth_token);
        if !constant_time_eq(&expected_auth_hash, &presented_auth_hash) {
            return Err(DaemonError::AgentAuthenticationFailed);
        }

        self.agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .cloned()
            .ok_or(DaemonError::AgentAuthenticationFailed)
    }

    pub(super) fn prune_replay_ids(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.replay_ids
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, expires_at| *expires_at > now);
        Ok(())
    }

    pub(super) fn ensure_replay_id_available(
        &self,
        request_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_replay_ids(now)?;
        let replay_ids = self
            .replay_ids
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        if replay_ids.contains_key(&request_id) {
            return Err(DaemonError::RequestReplayDetected);
        }
        if replay_ids.len() >= self.config.max_tracked_replay_ids {
            return Err(DaemonError::TooManyTrackedReplayIds {
                max_tracked: self.config.max_tracked_replay_ids,
            });
        }
        Ok(())
    }

    pub(super) fn register_replay_id(
        &self,
        request_id: Uuid,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_replay_ids(now)?;
        let mut replay_ids = self
            .replay_ids
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        if replay_ids.contains_key(&request_id) {
            return Err(DaemonError::RequestReplayDetected);
        }
        if replay_ids.len() >= self.config.max_tracked_replay_ids {
            return Err(DaemonError::TooManyTrackedReplayIds {
                max_tracked: self.config.max_tracked_replay_ids,
            });
        }
        replay_ids.insert(request_id, expires_at);
        Ok(())
    }
}

pub(super) fn generate_agent_auth_token() -> String {
    format!("{}.{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub(super) fn hash_agent_auth_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}
