//! State-unlock input: the machine state secret, and optionally the legacy vault
//! password for a one-time migration, read from stdin.
//!
//! Secrets are never accepted as command-line arguments or prompted for.
//!
//! - `--state-secret-stdin`: stdin is the 32-byte state secret as 64 hex
//!   characters (surrounding whitespace and a trailing newline are ignored).
//! - `--migrate-from-password-stdin`: stdin is two lines, the legacy vault
//!   password and then the hex state secret. A legacy v1 state file is
//!   decrypted with the password and atomically rewritten under the secret.
//!
//! Input is capped at [`MAX_STDIN_BYTES`] and zeroized on every path.

use std::io::Read;

use agentpay_signerd::{LegacyStatePassword, StateSecret};
use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

/// Upper bound on stdin input: a 16 KiB legacy password plus the secret line.
const MAX_STDIN_BYTES: u64 = 16 * 1024 + 256;

/// How the daemon unlocks its state file.
pub(crate) enum StateUnlock {
    /// Open (or create) a v2 state file keyed by the machine secret.
    Secret(StateSecret),
    /// Migrate a legacy v1 file to the machine secret, then open it.
    MigrateFromPassword {
        /// Machine secret for the migrated file.
        secret: StateSecret,
        /// Legacy vault password that encrypted the v1 file.
        legacy_password: LegacyStatePassword,
    },
}

impl StateUnlock {
    /// Whether this run only migrates the state file and then exits.
    pub(crate) fn is_migration(&self) -> bool {
        matches!(self, Self::MigrateFromPassword { .. })
    }
}

/// Reads the unlock input from the process's stdin.
pub(crate) fn read_state_unlock(migrate_from_password: bool) -> Result<StateUnlock> {
    read_state_unlock_from(std::io::stdin(), migrate_from_password)
}

fn read_state_unlock_from(
    mut reader: impl std::io::Read,
    migrate_from_password: bool,
) -> Result<StateUnlock> {
    let mut raw = Zeroizing::new(String::new());
    reader
        .by_ref()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
        .context("failed to read the daemon state secret from stdin")?;
    if raw.len() > MAX_STDIN_BYTES as usize {
        bail!("stdin input must not exceed {MAX_STDIN_BYTES} bytes");
    }

    if !migrate_from_password {
        return Ok(StateUnlock::Secret(parse_secret(&raw)?));
    }

    let (password_line, secret_line) = raw.split_once('\n').ok_or_else(|| {
        anyhow!(
            "--migrate-from-password-stdin expects two lines on stdin: the legacy vault password, then the hex state secret"
        )
    })?;
    let legacy_password = LegacyStatePassword::new(Zeroizing::new(
        password_line.trim_end_matches('\r').to_string(),
    ))
    .map_err(|err| anyhow!("{err}"))?;
    Ok(StateUnlock::MigrateFromPassword {
        secret: parse_secret(secret_line)?,
        legacy_password,
    })
}

fn parse_secret(value: &str) -> Result<StateSecret> {
    StateSecret::from_hex(value).map_err(|err| anyhow!("{err}"))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::{read_state_unlock_from, StateUnlock};

    const SECRET_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
    }

    #[test]
    fn reads_hex_secret_with_trailing_newline() {
        let unlock = read_state_unlock_from(Cursor::new(format!("{SECRET_HEX}\r\n")), false)
            .expect("secret");
        assert!(matches!(unlock, StateUnlock::Secret(_)));
    }

    #[test]
    fn rejects_malformed_secret_without_echoing_it() {
        let err = match read_state_unlock_from(Cursor::new("not-a-secret\n"), false) {
            Ok(_) => panic!("must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("64 hex characters"));
        assert!(!err.contains("not-a-secret"));
    }

    #[test]
    fn migration_reads_password_then_secret() {
        let unlock = read_state_unlock_from(
            Cursor::new(format!("legacy password\r\n{SECRET_HEX}\n")),
            true,
        )
        .expect("migration input");
        let StateUnlock::MigrateFromPassword {
            legacy_password, ..
        } = unlock
        else {
            panic!("expected migration input");
        };
        assert_eq!(
            format!("{legacy_password:?}"),
            "LegacyStatePassword(<redacted>)"
        );
    }

    #[test]
    fn migration_requires_two_lines_and_a_password() {
        let err = match read_state_unlock_from(Cursor::new(SECRET_HEX), true) {
            Ok(_) => panic!("must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("expects two lines"));

        let err = match read_state_unlock_from(Cursor::new(format!(" \n{SECRET_HEX}")), true) {
            Ok(_) => panic!("must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn rejects_oversized_input_and_propagates_io_errors() {
        let err = match read_state_unlock_from(Cursor::new("a".repeat(17 * 1024)), false) {
            Ok(_) => panic!("must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("must not exceed"));

        let err = match read_state_unlock_from(FailingReader, false) {
            Ok(_) => panic!("must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("failed to read the daemon state secret"));
    }
}
