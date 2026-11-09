//! Passwordless admin authentication: enrolled P-256 credentials, signed
//! challenges, and short-lived admin leases.
//!
//! Flow (see [`agentpay_domain::AdminAuth`] for the caller's view):
//!
//! 1. A root peer enrolls a credential's public key ([`credentials`]).
//! 2. Any admin-allowlisted peer asks for a challenge for that credential and
//!    signs the returned message with the private key, for example in the
//!    Secure Enclave behind Touch ID ([`challenge`]).
//! 3. A valid signature is exchanged for a lease secret (this module). The
//!    daemon keeps only its SHA-256 hash, compares it in constant time, binds
//!    it to the peer euid that completed the challenge, and forgets it on
//!    expiry, revocation, or daemon restart.

mod challenge;
mod credentials;

use std::collections::HashMap;

use agentpay_domain::{AdminAuth, AdminLease, AdminSession};
use agentpay_signer::VaultSignerBackend;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::challenge::PendingChallenge;
use super::auth::constant_time_eq;
use crate::{DaemonError, InMemoryDaemon, RequestContext};

#[cfg(test)]
pub(crate) use self::challenge::ChallengeMessage;
pub(crate) use self::credentials::validate_persisted_admin_credential;

/// Number of random bytes in a lease secret (hex-encoded on the wire).
const LEASE_SECRET_BYTES: usize = 32;

/// Upper bound on a presented lease secret, to bound hashing work.
const MAX_LEASE_SECRET_CHARS: usize = 256;

/// In-memory admin authentication state. Nothing here is persisted.
#[derive(Debug, Default)]
pub(super) struct AdminAuthState {
    leases: HashMap<Uuid, LeaseRecord>,
    challenges: HashMap<Uuid, PendingChallenge>,
    failures: HashMap<Uuid, CredentialFailures>,
}

/// Server-side record of an issued lease.
#[derive(Debug)]
struct LeaseRecord {
    secret_hash: [u8; 32],
    credential_id: Uuid,
    peer_euid: Option<u32>,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

impl LeaseRecord {
    fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.issued_at && now <= self.expires_at
    }
}

/// Failed-signature counter and lockout for one credential.
#[derive(Debug, Default)]
struct CredentialFailures {
    failed_attempts: u32,
    locked_until: Option<OffsetDateTime>,
}

impl AdminAuthState {
    /// Drops every lease, challenge, and failure counter tied to `credential_id`.
    fn forget_credential(&mut self, credential_id: Uuid) {
        self.leases
            .retain(|_, lease| lease.credential_id != credential_id);
        self.challenges
            .retain(|_, challenge| challenge.credential_id != credential_id);
        self.failures.remove(&credential_id);
    }

    /// Returns an error while `credential_id` is locked out; clears an elapsed lockout.
    fn ensure_not_locked(
        &mut self,
        credential_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        if let Some(failures) = self.failures.get_mut(&credential_id) {
            match failures.locked_until {
                Some(locked_until) if locked_until > now => {
                    return Err(DaemonError::AdminCredentialLocked { credential_id });
                }
                Some(_) => *failures = CredentialFailures::default(),
                None => {}
            }
        }
        Ok(())
    }

    /// Counts a failed signature and starts a lockout once `max_attempts` is reached.
    fn record_failure(
        &mut self,
        credential_id: Uuid,
        now: OffsetDateTime,
        max_attempts: u32,
        lockout: time::Duration,
    ) -> Result<(), DaemonError> {
        let failures = self.failures.entry(credential_id).or_default();
        failures.failed_attempts = failures.failed_attempts.saturating_add(1);
        if failures.failed_attempts >= max_attempts {
            failures.failed_attempts = 0;
            failures.locked_until = Some(now.checked_add(lockout).ok_or_else(|| {
                DaemonError::InvalidConfig("admin_auth_lockout causes timestamp overflow".into())
            })?);
        }
        Ok(())
    }
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    fn lock_admin_auth(&self) -> Result<std::sync::MutexGuard<'_, AdminAuthState>, DaemonError> {
        self.admin_auth
            .lock()
            .map_err(|_| DaemonError::LockPoisoned)
    }

    /// Issues a lease for `credential_id`, bound to the caller's peer euid.
    fn issue_admin_lease(
        &self,
        ctx: &RequestContext,
        credential_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<AdminLease, DaemonError> {
        let expires_at = now.checked_add(self.config.lease_ttl).ok_or_else(|| {
            DaemonError::InvalidConfig("lease_ttl causes timestamp overflow".to_string())
        })?;
        let secret_bytes = Zeroizing::new(rand::random::<[u8; LEASE_SECRET_BYTES]>());
        let lease = AdminLease {
            lease_id: Uuid::new_v4(),
            lease_secret: Zeroizing::new(hex::encode(secret_bytes.as_ref())),
            issued_at: now,
            expires_at,
        };
        let mut state = self.lock_admin_auth()?;
        // Retain only currently valid leases so stale entries cannot consume capacity.
        state.leases.retain(|_, existing| existing.is_valid_at(now));
        if state.leases.len() >= self.config.max_active_leases {
            return Err(DaemonError::TooManyActiveLeases);
        }
        state.leases.insert(
            lease.lease_id,
            LeaseRecord {
                secret_hash: hash_lease_secret(&lease.lease_secret),
                credential_id,
                peer_euid: ctx.peer_euid(),
                issued_at: now,
                expires_at,
            },
        );
        Ok(lease)
    }

    /// Verifies a presented lease: known, unexpired, same peer, matching secret.
    pub(super) fn verify_admin_lease(
        &self,
        ctx: &RequestContext,
        session: &AdminSession,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        let mut state = self.lock_admin_auth()?;
        let Some(record) = state.leases.get(&session.lease_id) else {
            return Err(DaemonError::UnknownLease);
        };
        if !record.is_valid_at(now) {
            state.leases.remove(&session.lease_id);
            return Err(DaemonError::InvalidLease);
        }
        if record.peer_euid != ctx.peer_euid()
            || session.lease_secret.len() > MAX_LEASE_SECRET_CHARS
            || !constant_time_eq(
                &record.secret_hash,
                &hash_lease_secret(&session.lease_secret),
            )
        {
            return Err(DaemonError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Revokes one admin lease. Callers may revoke their own lease with it.
    pub(crate) fn revoke_admin_lease_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        lease_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        self.lock_admin_auth()?
            .leases
            .remove(&lease_id)
            .map(|_| ())
            .ok_or(DaemonError::UnknownLease)
    }

    #[cfg(test)]
    pub(super) fn active_admin_lease_count(&self) -> Result<usize, DaemonError> {
        Ok(self.lock_admin_auth()?.leases.len())
    }

    #[cfg(test)]
    pub(super) fn pending_admin_challenge_count(&self) -> Result<usize, DaemonError> {
        Ok(self.lock_admin_auth()?.challenges.len())
    }
}

fn hash_lease_secret(secret: &str) -> [u8; 32] {
    super::auth::hash_agent_auth_token(secret)
}
