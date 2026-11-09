//! Startup: refuse root, prepare the private state directory, take the
//! single-instance lock, open the configuration, and serve until a signal.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use nix::fcntl::{Flock, FlockArg};

use crate::cli::{Cli, Options};
use crate::config::ConfigStore;
use crate::server::{bind, serve, shutdown_signal};
use crate::signer::UnixSignerClient;
use crate::state::AppState;
use crate::telemetry::settings::Settings as TelemetrySettings;
use crate::telemetry::{Telemetry, SHUTDOWN_DEADLINE};

/// Name of the lock file inside the state directory.
const LOCK_FILE_NAME: &str = "paymentd.lock";

/// Runs the service until SIGINT, SIGTERM, or SIGHUP.
pub async fn run(cli: Cli) -> Result<()> {
    let euid = nix::unistd::geteuid().as_raw();
    ensure_not_root(euid)?;
    let options = cli.resolve(euid)?;
    prepare_state_dir(&options.state_dir, euid)?;
    let _lock = acquire_instance_lock(&options.state_dir)?;
    let mut state = build_state(&options)?;
    // Only the real service sends telemetry; `build_state` (also used by
    // tests) keeps it inactive.
    state.telemetry = Telemetry::start(&options.state_dir, TelemetrySettings::from_env());
    let state = Arc::new(state);

    let server = bind(options.socket.clone(), options.allowed_client_euids.clone())
        .await
        .with_context(|| format!("failed to bind {}", options.socket.display()))?;
    tracing::info!(
        socket = %options.socket.display(),
        clients = ?options.allowed_client_euids,
        "payments service listening"
    );
    let served = serve(server, state.clone(), shutdown_signal())
        .await
        .context("payments service loop failed");
    state.telemetry.shutdown(SHUTDOWN_DEADLINE).await;
    served
}

/// Builds the request-handling state from resolved options.
pub fn build_state(options: &Options) -> Result<AppState> {
    let config = ConfigStore::open(&options.state_dir).map_err(anyhow::Error::msg)?;
    let signer = UnixSignerClient::new(
        options.signer_socket.clone(),
        options.signer_euid,
        options.signer_timeout,
    );
    Ok(AppState::new(config, Arc::new(signer)))
}

/// paymentd does all network I/O and must never hold root privileges.
pub fn ensure_not_root(euid: u32) -> Result<()> {
    if euid == 0 {
        bail!(
            "agentpay-paymentd must not run as root; run it as the payments service account \
             (installed by `sudo agentpay-setup install`)"
        );
    }
    Ok(())
}

/// Creates `path` (mode `0700`) if needed and checks that it is a real
/// directory owned by `euid` that group and others cannot access.
pub fn prepare_state_dir(path: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    if std::fs::symlink_metadata(path).is_err() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .with_context(|| format!("failed to create state directory {}", path.display()))?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect state directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!(
            "state directory {} must be a directory (not a symlink)",
            path.display()
        );
    }
    if metadata.uid() != euid {
        bail!(
            "state directory {} must be owned by uid {euid} (found uid {})",
            path.display(),
            metadata.uid()
        );
    }
    if metadata.mode() & 0o077 != 0 {
        bail!(
            "state directory {} must not be accessible to group or others (chmod 700)",
            path.display()
        );
    }
    Ok(())
}

/// Held for the process lifetime so two services never share a state directory.
pub struct InstanceLock {
    _lock: Flock<File>,
}

/// Takes an exclusive, non-blocking `flock` on `<state_dir>/paymentd.lock`.
pub fn acquire_instance_lock(state_dir: &Path) -> Result<InstanceLock> {
    use std::os::unix::fs::OpenOptionsExt;

    let path = state_dir.join(LOCK_FILE_NAME);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(InstanceLock { _lock: lock }),
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => bail!(
            "another agentpay-paymentd already uses {}; stop it first",
            state_dir.display()
        ),
        Err((_, errno)) => bail!("failed to lock {}: {errno}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{set_mode, TempDir};

    #[test]
    fn root_is_refused() {
        let err = ensure_not_root(0).expect_err("root");
        assert!(err.to_string().contains("must not run as root"));
        ensure_not_root(301).expect("service account");
    }

    #[test]
    fn state_dir_is_created_private_and_checked() {
        let dir = TempDir::new("state");
        let euid = nix::unistd::geteuid().as_raw();
        let state = dir.path().join("paymentd");
        prepare_state_dir(&state, euid).expect("created");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state).expect("dir").permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        set_mode(&state, 0o755);
        let err = prepare_state_dir(&state, euid).expect_err("too open");
        assert!(err.to_string().contains("chmod 700"));
        set_mode(&state, 0o700);

        let err = prepare_state_dir(&state, euid.wrapping_add(1)).expect_err("other owner");
        assert!(err.to_string().contains("must be owned by uid"));

        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&state, &link).expect("symlink");
        let err = prepare_state_dir(&link, euid).expect_err("symlink");
        assert!(err.to_string().contains("not a symlink"));
    }

    #[test]
    fn a_second_instance_cannot_take_the_lock() {
        let dir = TempDir::new("lock");
        let first = acquire_instance_lock(dir.path()).expect("first");
        let err = acquire_instance_lock(dir.path())
            .err()
            .expect("second instance must fail");
        assert!(err.to_string().contains("already uses"));
        drop(first);
        acquire_instance_lock(dir.path()).expect("free again");
    }
}
