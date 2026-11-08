//! Migration from the legacy vault-password install to the machine secret.
//!
//! Older releases encrypted the daemon state with a key derived from the user's vault password
//! and stored that password root-only (macOS System Keychain service `agentpay-daemon-password`,
//! Linux `/var/lib/agentpay/daemon-password`). The daemon's migration mode re-encrypts the state
//! under the new machine secret. Both secrets travel only on its stdin:
//!
//! ```text
//! <legacy vault password>\n
//! <new machine secret>\n
//! ```
//!
//! Install stores the new secret *before* migrating and deletes the legacy password only *after*
//! the daemon reports success, so an interrupted run is retried with the same new secret.

use anyhow::Result;
use zeroize::Zeroizing;

use crate::layout::Layout;
use crate::report::actionable;
use crate::secret::MachineSecret;
use crate::system::{stderr_suffix, Cmd, System};

/// Daemon flag that selects one-shot migration mode: the daemon re-encrypts the state file under
/// the machine secret (a no-op when already migrated) and exits without serving.
pub const MIGRATE_FLAG: &str = "--migrate-from-password-stdin";

/// Builds the daemon invocation that re-encrypts the state. Secrets go only to stdin.
pub fn migration_command(layout: &Layout, legacy_password: &str, secret: &MachineSecret) -> Cmd {
    let mut stdin = Zeroizing::new(Vec::with_capacity(legacy_password.len() + 66));
    stdin.extend_from_slice(legacy_password.as_bytes());
    stdin.push(b'\n');
    stdin.extend_from_slice(&secret.stdin_line());
    Cmd::new(layout.daemon_bin().display().to_string())
        .arg(MIGRATE_FLAG)
        .arg("--state-file")
        .arg(layout.state_file.display().to_string())
        .arg("--daemon-socket")
        .arg(layout.socket.display().to_string())
        .stdin(stdin)
}

/// Runs the daemon migration. The daemon must leave the state untouched on failure and must
/// succeed without changes when the state is already encrypted under `secret`.
pub fn run(
    sys: &dyn System,
    layout: &Layout,
    legacy_password: &str,
    secret: &MachineSecret,
) -> Result<()> {
    let output = sys.run(&migration_command(layout, legacy_password, secret))?;
    if output.success() {
        return Ok(());
    }
    Err(actionable(
        format!(
            "the daemon could not migrate the wallet state (exit {}){}",
            output.code,
            stderr_suffix(&output.stderr)
        ),
        "Your wallet state was not changed and is still protected by the old vault password. \
         Rerun setup; if it keeps failing, restore the wallet from your encrypted backup.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Platform;
    use crate::system::fake::FakeSystem;

    #[test]
    fn migration_passes_both_secrets_on_stdin_only() {
        let sys = FakeSystem::linux();
        let layout = Layout::for_platform(Platform::Linux);
        let secret = MachineSecret::generate(&sys).unwrap();
        let cmd = migration_command(&layout, "old-vault-password", &secret);
        assert_eq!(
            cmd.args,
            [
                MIGRATE_FLAG,
                "--state-file",
                "/var/lib/agentpay/daemon-state.enc",
                "--daemon-socket",
                "/run/agentpay/daemon.sock"
            ]
        );
        let stdin = String::from_utf8(cmd.stdin.as_ref().unwrap().to_vec()).unwrap();
        assert_eq!(stdin, format!("old-vault-password\n{}\n", secret.expose()));
        assert!(!format!("{cmd:?}").contains("old-vault-password"));
    }

    #[test]
    fn migration_failure_is_actionable() {
        let sys = FakeSystem::linux();
        sys.state.borrow_mut().migration_fails = true;
        let layout = Layout::for_platform(Platform::Linux);
        let secret = MachineSecret::generate(&sys).unwrap();
        let error = run(&sys, &layout, "pw", &secret).unwrap_err();
        assert!(error.downcast_ref::<crate::report::Actionable>().is_some());
    }
}
