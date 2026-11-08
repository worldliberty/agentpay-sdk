//! Runtime limits for the daemon (leases, admin challenges, replay and nonce
//! tracking, legacy-migration KDF bounds), plus their validation.

use time::Duration;

use crate::DaemonError;

/// Daemon runtime configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Admin lease time-to-live.
    pub lease_ttl: Duration,
    /// Maximum number of active admin leases retained in memory.
    pub max_active_leases: usize,
    /// Time-to-live of an issued admin challenge.
    pub admin_challenge_ttl: Duration,
    /// Maximum number of pending (unanswered, unexpired) admin challenges.
    pub max_pending_admin_challenges: usize,
    /// Maximum number of enrolled admin credentials.
    pub max_admin_credentials: usize,
    /// Maximum payload size accepted by `sign_for_agent`.
    pub max_sign_payload_bytes: usize,
    /// Maximum accepted request TTL (`expires_at - requested_at`).
    pub max_request_ttl: Duration,
    /// Maximum accepted future skew for `requested_at`.
    pub max_request_clock_skew: Duration,
    /// Maximum number of live replay ids retained in memory.
    pub max_tracked_replay_ids: usize,
    /// Default nonce reservation lease duration.
    pub nonce_reservation_ttl: Duration,
    /// Maximum number of active nonce reservations retained in memory.
    pub max_active_nonce_reservations: usize,
    /// Expiration window for pending or approved manual approval requests.
    pub manual_approval_active_ttl: Duration,
    /// Retention window for terminal manual approval requests before pruning.
    pub manual_approval_terminal_retention: Duration,
    /// Maximum number of distinct chain nonce heads tracked per vault key.
    pub max_tracked_nonce_chains_per_vault: usize,
    /// Consecutive failed challenge signatures per admin credential before a temporary lockout.
    pub max_failed_admin_auth_attempts: u32,
    /// Temporary per-credential lockout after too many failed challenge signatures.
    pub admin_auth_lockout: Duration,
    /// Maximum number of `Pending` manual approval requests a single agent key may hold.
    pub max_pending_manual_approval_requests_per_agent: usize,
    /// Maximum number of recoverable agent results retained in memory (oldest evicted first).
    pub max_recoverable_agent_results: usize,
    /// Maximum Argon2 memory cost (KiB) accepted from a legacy (v1) state file during migration.
    pub max_persisted_argon2_memory_kib: u32,
    /// Maximum Argon2 time cost accepted from a legacy (v1) state file during migration.
    pub max_persisted_argon2_time_cost: u32,
    /// Maximum Argon2 parallelism accepted from a legacy (v1) state file during migration.
    pub max_persisted_argon2_parallelism: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            lease_ttl: Duration::minutes(5),
            max_active_leases: 64,
            admin_challenge_ttl: Duration::minutes(2),
            max_pending_admin_challenges: 64,
            max_admin_credentials: 8,
            max_sign_payload_bytes: 32 * 1024,
            max_request_ttl: Duration::minutes(5),
            max_request_clock_skew: Duration::seconds(30),
            max_tracked_replay_ids: 65_536,
            nonce_reservation_ttl: Duration::minutes(2),
            max_active_nonce_reservations: 16_384,
            manual_approval_active_ttl: Duration::hours(24),
            manual_approval_terminal_retention: Duration::days(8),
            max_tracked_nonce_chains_per_vault: 256,
            max_failed_admin_auth_attempts: 5,
            admin_auth_lockout: Duration::seconds(30),
            max_pending_manual_approval_requests_per_agent: 64,
            max_recoverable_agent_results: 256,
            max_persisted_argon2_memory_kib: 1_048_576,
            max_persisted_argon2_time_cost: 32,
            max_persisted_argon2_parallelism: 16,
        }
    }
}

pub(crate) fn validate_config(config: &DaemonConfig) -> Result<(), DaemonError> {
    if config.lease_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "lease_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_active_leases == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_active_leases must be greater than zero".to_string(),
        ));
    }
    if config.admin_challenge_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "admin_challenge_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_pending_admin_challenges == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_pending_admin_challenges must be greater than zero".to_string(),
        ));
    }
    if config.max_admin_credentials == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_admin_credentials must be greater than zero".to_string(),
        ));
    }
    if config.max_sign_payload_bytes == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_sign_payload_bytes must be greater than zero".to_string(),
        ));
    }
    if config.max_request_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "max_request_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_request_clock_skew < Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "max_request_clock_skew must be non-negative".to_string(),
        ));
    }
    if config.max_tracked_replay_ids == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_tracked_replay_ids must be greater than zero".to_string(),
        ));
    }
    if config.nonce_reservation_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "nonce_reservation_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_active_nonce_reservations == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_active_nonce_reservations must be greater than zero".to_string(),
        ));
    }
    if config.manual_approval_active_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "manual_approval_active_ttl must be greater than zero".to_string(),
        ));
    }
    if config.manual_approval_terminal_retention < Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "manual_approval_terminal_retention must be non-negative".to_string(),
        ));
    }
    if config.max_tracked_nonce_chains_per_vault == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_tracked_nonce_chains_per_vault must be greater than zero".to_string(),
        ));
    }
    if config.max_failed_admin_auth_attempts == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_failed_admin_auth_attempts must be greater than zero".to_string(),
        ));
    }
    if config.admin_auth_lockout <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "admin_auth_lockout must be greater than zero".to_string(),
        ));
    }
    if config.max_pending_manual_approval_requests_per_agent == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_pending_manual_approval_requests_per_agent must be greater than zero".to_string(),
        ));
    }
    if config.max_recoverable_agent_results == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_recoverable_agent_results must be greater than zero".to_string(),
        ));
    }
    if config.max_persisted_argon2_memory_kib == 0
        || config.max_persisted_argon2_time_cost == 0
        || config.max_persisted_argon2_parallelism == 0
    {
        return Err(DaemonError::InvalidConfig(
            "max_persisted_argon2_* limits must be greater than zero".to_string(),
        ));
    }
    Ok(())
}
