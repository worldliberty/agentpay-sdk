//! Resolution and hardening of the daemon's state file and socket paths.
//!
//! Defaults live under `$AGENTPAY_HOME` (or `~/.agentpay`). Before use, every
//! path's parent directory is created if needed and verified, along with all
//! of its ancestors, to be owned by root or the current user and not writable
//! by group/other (sticky ancestors such as `/tmp` are tolerated). Symlinked
//! files and parent directories are rejected.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Returns the explicit state file path or the default, after hardening its parent directory.
pub(crate) fn resolve_state_file_path(cli_value: Option<PathBuf>) -> Result<PathBuf> {
    let path = match cli_value {
        Some(path) => path,
        None => default_state_file_path()?,
    };
    ensure_file_parent(&path, "state")?;
    Ok(path)
}

/// Returns the explicit socket path or the default, after hardening its parent directory.
pub(crate) fn resolve_socket_path(cli_value: Option<PathBuf>) -> Result<PathBuf> {
    let path = match cli_value {
        Some(path) => path,
        None => default_socket_path()?,
    };
    ensure_file_parent(&path, "socket")?;
    Ok(path)
}

fn default_state_file_path() -> Result<PathBuf> {
    Ok(agentpay_home_dir()?.join("daemon-state.enc"))
}

fn default_socket_path() -> Result<PathBuf> {
    Ok(agentpay_home_dir()?.join("daemon.sock"))
}

fn agentpay_home_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGENTPAY_HOME") {
        let candidate = PathBuf::from(path);
        if candidate.as_os_str().is_empty() {
            bail!("AGENTPAY_HOME must not be empty");
        }
        return Ok(candidate);
    }

    let Some(home) = std::env::var_os("HOME") else {
        bail!("HOME is not set; use AGENTPAY_HOME to choose config directory");
    };
    let mut path = PathBuf::from(home);
    path.push(".agentpay");
    Ok(path)
}

/// Rejects a symlinked `path`, then creates and validates its parent directory chain.
pub(crate) fn ensure_file_parent(path: &Path, label: &str) -> Result<()> {
    if is_symlink(path)? {
        bail!("{label} path '{}' must not be a symlink", path.display());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            // Explicit mode, not the umask: a group-writable umask (002) would otherwise create a
            // directory that the ownership check below then refuses.
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .with_context(|| format!("failed to create directory {}", parent.display()))?;
            }
            if is_symlink(parent)? {
                bail!(
                    "{label} directory '{}' must not be a symlink",
                    parent.display()
                );
            }
            ensure_secure_directory_owner(parent, label)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn assert_allowed_directory_owner(
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
    label: &str,
) -> Result<()> {
    if owner_uid == 0 {
        return Ok(());
    }

    if effective_uid == 0 {
        bail!(
            "{label} directory '{}' must be owned by root; found uid {owner_uid}",
            path.display()
        );
    }

    if owner_uid != effective_uid {
        bail!(
            "{label} directory '{}' must be owned by current user or root; found uid {owner_uid}",
            path.display()
        );
    }

    Ok(())
}

#[cfg(unix)]
fn ensure_secure_directory_owner(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    const STICKY_BIT_MODE: u32 = 0o1000;

    fn validate_directory(
        path: &Path,
        metadata: &std::fs::Metadata,
        effective_uid: u32,
        label: &str,
        allow_sticky_group_other_write: bool,
    ) -> Result<()> {
        if !metadata.is_dir() {
            bail!("{label} directory '{}' is not a directory", path.display());
        }
        assert_allowed_directory_owner(path, metadata.uid(), effective_uid, label)?;
        let mode = metadata.mode() & 0o7777;
        if mode & 0o022 != 0 && !(allow_sticky_group_other_write && mode & STICKY_BIT_MODE != 0) {
            bail!(
                "{label} directory '{}' must not be writable by group/other (current mode {:o})",
                path.display(),
                mode & 0o777
            );
        }
        Ok(())
    }

    let effective_uid = nix::unistd::geteuid().as_raw();
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect {label} directory {}", path.display()))?;
    validate_directory(path, &metadata, effective_uid, label, false)?;

    let canonical = std::fs::canonicalize(path).with_context(|| {
        format!(
            "failed to canonicalize {label} directory {}",
            path.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).with_context(|| {
            format!(
                "failed to inspect ancestor {label} directory {}",
                ancestor.display()
            )
        })?;
        validate_directory(ancestor, &metadata, effective_uid, label, true)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_secure_directory_owner(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

fn is_symlink(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect metadata for {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        agentpay_home_dir, default_socket_path, default_state_file_path, ensure_file_parent,
        is_symlink, resolve_socket_path, resolve_state_file_path,
    };
    use crate::test_support::temp_path;

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(unix)]
    #[test]
    fn ensure_file_parent_accepts_current_user_owned_directory() {
        let parent = temp_path("agentpay-daemon-parent");
        crate::test_support::create_private_dir(&parent);
        let path = parent.join("daemon-state.enc");
        ensure_file_parent(&path, "state").expect("current-user-owned directory should pass");
        std::fs::remove_dir_all(&parent).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_file_parent_rejects_group_writable_ancestor_directory() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "agentpay-daemon-parent-ancestor-{}-{}",
            std::process::id(),
            unique
        ));
        let shared = root.join("shared");
        let nested = shared.join("nested");
        crate::test_support::create_private_dir(&nested);
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777))
            .expect("set insecure ancestor permissions");
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700))
            .expect("set nested permissions");

        let path = nested.join("daemon-state.enc");
        let err = ensure_file_parent(&path, "state").expect_err("must reject");
        assert!(err
            .to_string()
            .contains("must not be writable by group/other"));

        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn agentpay_home_dir_prefers_agentpay_home_and_falls_back_to_home() {
        let _guard = env_lock().lock().expect("env lock");
        let agentpay_home = temp_path("agentpay-home");
        let home = temp_path("home-dir");

        std::env::set_var("AGENTPAY_HOME", &agentpay_home);
        std::env::set_var("HOME", &home);
        assert_eq!(agentpay_home_dir().expect("agentpay home"), agentpay_home);

        std::env::remove_var("AGENTPAY_HOME");
        assert_eq!(
            agentpay_home_dir().expect("home fallback"),
            home.join(".agentpay")
        );

        std::env::remove_var("HOME");
    }

    #[test]
    fn agentpay_home_dir_rejects_empty_and_missing_env() {
        let _guard = env_lock().lock().expect("env lock");

        std::env::set_var("AGENTPAY_HOME", "");
        let err = agentpay_home_dir().expect_err("must reject empty AGENTPAY_HOME");
        assert!(err.to_string().contains("AGENTPAY_HOME must not be empty"));

        std::env::remove_var("AGENTPAY_HOME");
        std::env::remove_var("HOME");
        let err = agentpay_home_dir().expect_err("must reject missing HOME");
        assert!(err
            .to_string()
            .contains("HOME is not set; use AGENTPAY_HOME to choose config directory"));
    }

    #[test]
    fn default_paths_and_resolvers_use_agentpay_home() {
        let _guard = env_lock().lock().expect("env lock");
        let agentpay_home = temp_path("agentpay-daemon-defaults");
        std::env::set_var("AGENTPAY_HOME", &agentpay_home);

        assert_eq!(
            default_state_file_path().expect("default state"),
            agentpay_home.join("daemon-state.enc")
        );
        assert_eq!(
            default_socket_path().expect("default socket"),
            agentpay_home.join("daemon.sock")
        );
        assert_eq!(
            resolve_state_file_path(None).expect("resolved state"),
            agentpay_home.join("daemon-state.enc")
        );
        assert_eq!(
            resolve_socket_path(None).expect("resolved socket"),
            agentpay_home.join("daemon.sock")
        );

        std::env::remove_var("AGENTPAY_HOME");
    }

    #[test]
    fn explicit_state_and_socket_paths_are_preserved() {
        let root = temp_path("agentpay-daemon-explicit");
        let state = root.join("state").join("daemon-state.enc");
        let socket = root.join("sock").join("daemon.sock");

        let resolved_state = resolve_state_file_path(Some(state.clone())).expect("state path");
        let resolved_socket = resolve_socket_path(Some(socket.clone())).expect("socket path");
        assert_eq!(resolved_state, state);
        assert_eq!(resolved_socket, socket);
        assert!(root.join("state").exists());
        assert!(root.join("sock").exists());

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_file_parent_rejects_symlink_path_and_is_symlink_reports_it() {
        use std::os::unix::fs::symlink;

        let root = temp_path("agentpay-daemon-symlink");
        crate::test_support::create_private_dir(&root);
        let target = root.join("real-state.enc");
        let link = root.join("linked-state.enc");
        std::fs::write(&target, "seed").expect("seed");
        symlink(&target, &link).expect("symlink");

        assert!(is_symlink(&link).expect("symlink metadata"));
        let err = ensure_file_parent(&link, "state").expect_err("must reject symlink file");
        assert!(err.to_string().contains("must not be a symlink"));

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn is_symlink_returns_false_for_missing_path() {
        let missing = temp_path("agentpay-daemon-missing");
        assert!(!is_symlink(&missing).expect("missing path is not symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_rejects_non_root_owner_for_root_runtime() {
        let err =
            super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 501, 0, "state")
                .expect_err("root runtime must reject non-root owner");

        assert!(err.to_string().contains("must be owned by root"));
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_allows_root_owner_for_root_runtime() {
        super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 0, 0, "state")
            .expect("root runtime should allow root-owned directories");
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_allows_current_user_for_non_root_runtime() {
        super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 501, 501, "state")
            .expect("non-root runtime should allow current-user-owned directories");
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_rejects_other_user_for_non_root_runtime() {
        let err =
            super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 502, 501, "state")
                .expect_err("non-root runtime must reject another user's directory");

        assert!(err
            .to_string()
            .contains("must be owned by current user or root"));
    }
}
