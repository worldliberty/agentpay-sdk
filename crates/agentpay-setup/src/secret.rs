//! The daemon machine secret and the root-only stores that hold it.
//!
//! The machine secret is 32 bytes from the OS CSPRNG, hex encoded (64 lowercase characters).
//! The daemon derives its state-encryption key from it, so it is generated once and must survive
//! reinstalls. It is stored root-only:
//! - macOS: a generic-password item in the System Keychain, written and read through the
//!   `agentpay-system-keychain` helper (the item's ACL trusts only that helper);
//! - Linux: a `0600` root-owned file.
//!
//! Secret bytes only ever travel through child stdin and [`Zeroizing`] buffers; they are never
//! placed in arguments, the environment, error messages or [`std::fmt::Debug`] output.

use std::fmt;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use zeroize::Zeroizing;

use crate::layout::{SecretLocation, SYSTEM_KEYCHAIN};
use crate::system::{run_checked, stderr_suffix, Cmd, FileKind, System};

/// Raw length of the machine secret in bytes.
pub const SECRET_BYTES: usize = 32;

/// Exit status of `security find/delete-generic-password` when the item does not exist.
const SECURITY_ITEM_NOT_FOUND: i32 = 44;

/// Upper bound for a stored legacy vault password (matches the old daemon's stdin cap).
const MAX_LEGACY_SECRET_BYTES: usize = 16 * 1024;

/// The daemon's 32-byte machine secret in hex form. Zeroized on drop; never printed.
pub struct MachineSecret(Zeroizing<String>);

impl MachineSecret {
    /// Generates a fresh secret from the operating system CSPRNG.
    pub fn generate(sys: &dyn System) -> Result<Self> {
        let mut raw = Zeroizing::new([0u8; SECRET_BYTES]);
        sys.fill_random(raw.as_mut())?;
        if raw.iter().all(|byte| *byte == 0) {
            bail!("operating system RNG returned an all-zero secret");
        }
        Ok(Self(Zeroizing::new(hex::encode(raw.as_ref()))))
    }

    /// Validates a stored secret (64 hex characters, surrounding whitespace ignored).
    pub fn parse(text: &str) -> Result<Self> {
        let trimmed = text.trim();
        if trimmed.len() != SECRET_BYTES * 2 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("stored machine secret is malformed (expected {SECRET_BYTES} hex-encoded bytes)");
        }
        Ok(Self(Zeroizing::new(trimmed.to_ascii_lowercase())))
    }

    /// The hex string. Callers must keep it out of argv, env and logs.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The secret followed by a newline, ready to be written to a child's stdin.
    pub fn stdin_line(&self) -> Zeroizing<Vec<u8>> {
        line(&self.0)
    }
}

impl fmt::Debug for MachineSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachineSecret([redacted])")
    }
}

/// `value` plus a trailing newline in a zeroizing buffer.
pub fn line(value: &str) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(b'\n');
    bytes
}

/// Whether a secret exists at `location`.
pub fn is_present(sys: &dyn System, location: &SecretLocation) -> Result<bool> {
    match location {
        SecretLocation::Keychain { service, account } => {
            // Without -g/-w, `security` prints only the item's attributes, never its data.
            let output = sys.run(&keychain_cmd("find-generic-password", service, account))?;
            match output.code {
                0 => Ok(true),
                SECURITY_ITEM_NOT_FOUND => Ok(false),
                code => bail!(
                    "failed to query the System Keychain for '{service}' (exit {code}){}",
                    stderr_suffix(&output.stderr)
                ),
            }
        }
        SecretLocation::File { path } => match sys.lstat(path)? {
            None => Ok(false),
            Some(meta) if meta.kind == FileKind::File => Ok(true),
            Some(_) => bail!("{} exists but is not a regular file", path.display()),
        },
    }
}

/// Reads the secret text at `location`, trimming one trailing newline.
///
/// `helper` is the keychain helper to read through (required for keychain locations).
pub fn read(
    sys: &dyn System,
    location: &SecretLocation,
    helper: Option<&Path>,
) -> Result<Zeroizing<String>> {
    let raw = match location {
        SecretLocation::Keychain { service, account } => {
            let helper = require_helper(helper)?;
            let cmd = Cmd::new(helper.display().to_string())
                .args(["read-generic-password", "--keychain", SYSTEM_KEYCHAIN])
                .args(["--service", service.as_str(), "--account", account.as_str()]);
            let output = sys.run(&cmd)?;
            if !output.success() {
                bail!(
                    "failed to read '{service}' from the System Keychain (exit {}){}",
                    output.code,
                    stderr_suffix(&output.stderr)
                );
            }
            output.stdout
        }
        SecretLocation::File { path } => {
            let meta = sys
                .lstat(path)?
                .ok_or_else(|| anyhow!("{} does not exist", path.display()))?;
            if meta.kind != FileKind::File || meta.uid != 0 || meta.mode & 0o077 != 0 {
                bail!(
                    "{} must be a regular root-owned file with mode 0600",
                    path.display()
                );
            }
            sys.read_file(path)?
        }
    };
    parse_stored(&raw, location)
}

/// Reads a System Keychain item through `/usr/bin/security`, which (unlike the helper) lets
/// macOS ask an administrator to allow the read when the item's ACL does not trust the caller.
///
/// Only for an item whose helper build is gone: the legacy vault password during migration, or
/// the machine secret after a setup stopped between replacing the helper and re-sealing. Needs
/// a logged-in GUI session for the approval dialog; the value arrives on stdout.
pub fn read_with_approval(
    sys: &dyn System,
    location: &SecretLocation,
) -> Result<Zeroizing<String>> {
    let SecretLocation::Keychain { service, account } = location else {
        bail!("{} is not a keychain item", location.describe());
    };
    let cmd = Cmd::new("security").arg("find-generic-password").args([
        "-s",
        service.as_str(),
        "-a",
        account.as_str(),
        "-w",
        SYSTEM_KEYCHAIN,
    ]);
    let output = sys.run(&cmd)?;
    if !output.success() {
        bail!(
            "access to '{service}' was not approved (exit {}){}",
            output.code,
            stderr_suffix(&output.stderr)
        );
    }
    parse_stored(&output.stdout, location)
}

fn parse_stored(raw: &[u8], location: &SecretLocation) -> Result<Zeroizing<String>> {
    if raw.len() > MAX_LEGACY_SECRET_BYTES {
        bail!("stored secret at {} is too large", location.describe());
    }
    let text = std::str::from_utf8(raw)
        .with_context(|| format!("stored secret at {} is not UTF-8", location.describe()))?;
    let value = Zeroizing::new(text.trim_end_matches(['\r', '\n']).to_owned());
    if value.trim().is_empty() {
        bail!("stored secret at {} is empty", location.describe());
    }
    Ok(value)
}

/// Stores `value` at `location`, replacing any existing secret.
pub fn store(
    sys: &dyn System,
    location: &SecretLocation,
    helper: Option<&Path>,
    value: &str,
) -> Result<()> {
    match location {
        SecretLocation::Keychain { service, account } => {
            let helper = require_helper(helper)?;
            let cmd = Cmd::new(helper.display().to_string())
                .args(["replace-generic-password", "--keychain", SYSTEM_KEYCHAIN])
                .args(["--service", service.as_str(), "--account", account.as_str()])
                .arg("--password-stdin")
                .stdin(line(value));
            if sys.run(&cmd)?.success() {
                return Ok(());
            }
            // The existing item's ACL trusts the helper build that wrote it, so a newer helper
            // can neither see nor delete it, and adding a second item fails. Root's `security`
            // deletes it regardless (no dialog); then the new helper stores the same value,
            // which the caller still holds.
            delete(sys, location)?;
            run_checked(sys, &cmd).map(|_| ())
        }
        SecretLocation::File { path } => {
            if let Some(meta) = sys.lstat(path)? {
                if meta.kind != FileKind::File {
                    bail!("{} exists but is not a regular file", path.display());
                }
            }
            sys.write_file(path, value.as_bytes(), 0o600)
        }
    }
}

/// Deletes the secret at `location`. Returns whether something was removed.
pub fn delete(sys: &dyn System, location: &SecretLocation) -> Result<bool> {
    match location {
        SecretLocation::Keychain { service, account } => {
            let output = sys.run(&keychain_cmd("delete-generic-password", service, account))?;
            match output.code {
                0 => Ok(true),
                SECURITY_ITEM_NOT_FOUND => Ok(false),
                code => bail!(
                    "failed to delete '{service}' from the System Keychain (exit {code}){}",
                    stderr_suffix(&output.stderr)
                ),
            }
        }
        SecretLocation::File { path } => sys.remove_file(path),
    }
}

fn keychain_cmd(action: &str, service: &str, account: &str) -> Cmd {
    Cmd::new("security")
        .args([action, "-s", service, "-a", account])
        .arg(SYSTEM_KEYCHAIN)
}

fn require_helper(helper: Option<&Path>) -> Result<&Path> {
    helper.ok_or_else(|| anyhow!("the System Keychain helper is required on macOS"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    #[test]
    fn generated_secret_is_64_hex_chars_and_redacted_in_debug() {
        let sys = FakeSystem::macos();
        let secret = MachineSecret::generate(&sys).unwrap();
        assert_eq!(secret.expose().len(), 64);
        assert!(secret.expose().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(format!("{secret:?}"), "MachineSecret([redacted])");
        assert_eq!(&secret.stdin_line()[..64], secret.expose().as_bytes());
        assert_eq!(secret.stdin_line().last(), Some(&b'\n'));
    }

    #[test]
    fn successive_secrets_differ() {
        let sys = FakeSystem::macos();
        let a = MachineSecret::generate(&sys).unwrap();
        let b = MachineSecret::generate(&sys).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn parse_rejects_malformed_secrets() {
        assert!(MachineSecret::parse(&"ab".repeat(32)).is_ok());
        assert!(MachineSecret::parse(&format!("{}\n", "AB".repeat(32))).is_ok());
        assert!(MachineSecret::parse("short").is_err());
        assert!(MachineSecret::parse(&"zz".repeat(32)).is_err());
        let error = MachineSecret::parse(&"g".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("ggg"), "error must not echo the value");
    }

    #[test]
    fn keychain_store_passes_secret_only_on_stdin() {
        let sys = FakeSystem::macos();
        let location = crate::layout::Layout::for_platform(crate::layout::Platform::Macos).secret;
        let helper = Path::new("/Library/AgentPay/bin/agentpay-system-keychain");
        store(&sys, &location, Some(helper), "top-secret-value").unwrap();
        assert!(is_present(&sys, &location).unwrap());
        assert_eq!(
            read(&sys, &location, Some(helper)).unwrap().as_str(),
            "top-secret-value"
        );
        sys.assert_secret_never_leaked("top-secret-value");
        assert!(delete(&sys, &location).unwrap());
        assert!(!delete(&sys, &location).unwrap());
        assert!(!is_present(&sys, &location).unwrap());
    }

    #[test]
    fn file_store_is_root_only_and_rejects_loose_permissions() {
        let sys = FakeSystem::linux();
        let path = std::path::PathBuf::from("/var/lib/agentpay/daemon-secret");
        let location = SecretLocation::File { path: path.clone() };
        sys.mkdir("/var/lib/agentpay");
        store(&sys, &location, None, "abc").unwrap();
        let meta = sys.lstat(&path).unwrap().unwrap();
        assert_eq!((meta.uid, meta.mode), (0, 0o600));
        assert_eq!(read(&sys, &location, None).unwrap().as_str(), "abc");
        sys.set_mode(&path, 0o644);
        assert!(read(&sys, &location, None).is_err());
    }
}
