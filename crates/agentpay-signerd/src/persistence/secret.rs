//! Secrets used to unlock the encrypted state file.
//!
//! - [`StateSecret`]: the 32-byte random machine secret generated at setup and
//!   stored root-only (System Keychain on macOS, a root `0600` file on Linux).
//!   The state-file key is derived from it with HKDF-SHA256.
//! - [`LegacyStatePassword`]: the retired vault password, accepted only to
//!   migrate a v1 (Argon2) state file to the v2 envelope.

use std::fmt;

use zeroize::Zeroizing;

use crate::DaemonError;

/// Length of the machine state secret in bytes.
pub const STATE_SECRET_LEN: usize = 32;

/// Upper bound on the legacy vault password accepted for migration.
const MAX_LEGACY_PASSWORD_BYTES: usize = 16 * 1024;

/// 32-byte machine secret from which the state-file encryption key is derived.
///
/// The bytes are zeroized on drop and never printed by `Debug`.
#[derive(Clone)]
pub struct StateSecret(Zeroizing<[u8; STATE_SECRET_LEN]>);

impl StateSecret {
    /// Wraps raw secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::InvalidConfig`] for the all-zero secret, which
    /// indicates an uninitialized buffer rather than random key material.
    pub fn from_bytes(bytes: [u8; STATE_SECRET_LEN]) -> Result<Self, DaemonError> {
        let secret = Self(Zeroizing::new(bytes));
        if secret.0.iter().all(|byte| *byte == 0) {
            return Err(DaemonError::InvalidConfig(
                "state secret must not be all zeros".to_string(),
            ));
        }
        Ok(secret)
    }

    /// Parses the secret from 64 hex characters; surrounding ASCII whitespace is ignored.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::InvalidConfig`] when the input is not exactly 32
    /// hex-encoded bytes or is all zeros. The error never echoes the input.
    pub fn from_hex(value: &str) -> Result<Self, DaemonError> {
        let trimmed = value.trim_matches(|c: char| c.is_ascii_whitespace());
        let mut bytes = Zeroizing::new([0u8; STATE_SECRET_LEN]);
        hex::decode_to_slice(trimmed, bytes.as_mut()).map_err(|_| {
            DaemonError::InvalidConfig(format!(
                "state secret must be exactly {} hex characters",
                STATE_SECRET_LEN * 2
            ))
        })?;
        Self::from_bytes(*bytes)
    }

    /// Generates a fresh random secret (used by tests and setup tooling).
    #[must_use]
    pub fn generate() -> Self {
        loop {
            if let Ok(secret) = Self::from_bytes(rand::random::<[u8; STATE_SECRET_LEN]>()) {
                return secret;
            }
        }
    }

    pub(crate) fn expose(&self) -> &[u8; STATE_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for StateSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StateSecret(<redacted>)")
    }
}

/// Retired vault password, accepted only to migrate a legacy v1 state file.
#[derive(Clone)]
pub struct LegacyStatePassword(Zeroizing<String>);

impl LegacyStatePassword {
    /// Wraps the legacy password.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::InvalidConfig`] when the password is blank or
    /// longer than 16 KiB.
    pub fn new(password: Zeroizing<String>) -> Result<Self, DaemonError> {
        if password.trim().is_empty() {
            return Err(DaemonError::InvalidConfig(
                "legacy vault password must not be empty or whitespace".to_string(),
            ));
        }
        if password.len() > MAX_LEGACY_PASSWORD_BYTES {
            return Err(DaemonError::InvalidConfig(format!(
                "legacy vault password must not exceed {MAX_LEGACY_PASSWORD_BYTES} bytes"
            )));
        }
        Ok(Self(password))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for LegacyStatePassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LegacyStatePassword(<redacted>)")
    }
}
