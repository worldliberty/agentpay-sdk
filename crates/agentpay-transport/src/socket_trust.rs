//! Trust checks for daemon socket paths and their parent directories.
//!
//! Clients verify that the socket they are about to connect to is a real unix
//! socket (not a symlink or regular file), owned by a trusted uid, and located
//! in a directory chain that cannot be rewritten by other users. The server
//! applies the same directory checks before binding and only ever removes a
//! stale path if it is a socket.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Validates that a client daemon socket path is an existing trusted unix socket in a secure directory.
pub fn assert_trusted_daemon_socket_path(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("daemon socket path must not be empty".to_string());
    }

    if is_symlink(path)? {
        return Err(format!(
            "socket path '{}' must not be a symlink",
            path.display()
        ));
    }

    let Some(parent) = path.parent() else {
        return Err(format!(
            "socket path '{}' must have a parent directory",
            path.display()
        ));
    };
    if parent.as_os_str().is_empty() {
        return Err(format!(
            "socket path '{}' must have a parent directory",
            path.display()
        ));
    }
    if is_symlink(parent)? {
        return Err(format!(
            "socket directory '{}' must not be a symlink",
            parent.display()
        ));
    }
    ensure_secure_socket_directory(parent)?;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect socket path '{}': {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if !metadata.file_type().is_socket() {
            return Err(format!(
                "socket path '{}' must be a unix socket",
                path.display()
            ));
        }
        let uid = metadata.uid();
        let allowed = allowed_owner_uids()?;
        if !allowed.contains(&uid) {
            return Err(format!(
                "socket path '{}' must be owned by current user, sudo caller, or root (found uid {uid})",
                path.display(),
            ));
        }
    }

    Ok(path.to_path_buf())
}

/// Validates that a client daemon socket path is an existing root-owned unix socket in a secure directory.
pub fn assert_root_owned_daemon_socket_path(path: &Path) -> Result<PathBuf, String> {
    let resolved = assert_trusted_daemon_socket_path(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(&resolved).map_err(|err| {
            format!(
                "failed to inspect socket path '{}': {err}",
                resolved.display()
            )
        })?;
        if metadata.uid() != 0 {
            return Err(format!(
                "socket path '{}' must be owned by root",
                resolved.display()
            ));
        }
    }

    Ok(resolved)
}

/// Validates the socket of a service that runs as `owner_uid` (the payments
/// service runs as its own service account): the path is an existing unix
/// socket, not a symlink, owned by `owner_uid`, and every directory from `/`
/// down to it is owned by root or `owner_uid` and not writable by group/other
/// (sticky directories such as `/tmp` excepted).
///
/// Clients must also check, after connecting, that the peer euid is `owner_uid`.
pub fn assert_service_socket_path(path: &Path, owner_uid: u32) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("service socket path must not be empty".to_string());
    }
    if is_symlink(path)? {
        return Err(format!(
            "socket path '{}' must not be a symlink",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "socket path '{}' must have a parent directory",
                path.display()
            )
        })?;
    if is_symlink(parent)? {
        return Err(format!(
            "socket directory '{}' must not be a symlink",
            parent.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect socket path '{}': {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if !metadata.file_type().is_socket() {
            return Err(format!(
                "socket path '{}' must be a unix socket",
                path.display()
            ));
        }
        if metadata.uid() != owner_uid {
            return Err(format!(
                "socket path '{}' must be owned by uid {owner_uid} (found uid {})",
                path.display(),
                metadata.uid()
            ));
        }
        let canonical = std::fs::canonicalize(parent).map_err(|err| {
            format!(
                "failed to canonicalize socket directory '{}': {err}",
                parent.display()
            )
        })?;
        for (index, dir) in canonical.ancestors().enumerate() {
            let dir_metadata = std::fs::metadata(dir).map_err(|err| {
                format!(
                    "failed to inspect socket directory '{}': {err}",
                    dir.display()
                )
            })?;
            let mode = dir_metadata.mode() & 0o7777;
            let sticky_tolerated = index > 0 && mode & 0o1000 != 0;
            if ![0, owner_uid].contains(&dir_metadata.uid()) {
                return Err(format!(
                    "socket directory '{}' must be owned by root or uid {owner_uid} (found uid {})",
                    dir.display(),
                    dir_metadata.uid()
                ));
            }
            if mode & 0o022 != 0 && !sticky_tolerated {
                return Err(format!(
                    "socket directory '{}' must not be writable by group/other",
                    dir.display()
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, owner_uid);

    Ok(path.to_path_buf())
}

/// Creates the socket's parent directory if needed and verifies the directory chain is secure.
pub(crate) fn ensure_socket_parent(path: &Path) -> Result<(), String> {
    if is_symlink(path)? {
        return Err(format!(
            "socket path '{}' must not be a symlink",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            // Explicit mode, not the umask: traversable so clients can reach the socket, but never
            // group/other writable, which the check below refuses.
            create_socket_dir(parent).map_err(|err| {
                format!(
                    "failed to create socket directory '{}': {err}",
                    parent.display()
                )
            })?;
            if is_symlink(parent)? {
                return Err(format!(
                    "socket directory '{}' must not be a symlink",
                    parent.display()
                ));
            }
            ensure_secure_socket_directory(parent)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_secure_socket_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    const GROUP_OTHER_WRITE_MODE_MASK: u32 = 0o022;
    const STICKY_BIT_MODE: u32 = 0o1000;

    fn allowed_owner_uids() -> Result<BTreeSet<u32>, String> {
        let mut allowed = BTreeSet::new();
        allowed.insert(nix::unistd::geteuid().as_raw());
        if nix::unistd::geteuid().as_raw() == 0 {
            if let Some(raw) = std::env::var_os("SUDO_UID") {
                let rendered = raw.to_string_lossy();
                let parsed = rendered
                    .parse::<u32>()
                    .map_err(|_| format!("invalid SUDO_UID value '{rendered}'"))?;
                allowed.insert(parsed);
            }
        }
        Ok(allowed)
    }

    fn validate_directory(
        path: &Path,
        metadata: &std::fs::Metadata,
        allow_sticky_group_other_write: bool,
    ) -> Result<(), String> {
        if !metadata.is_dir() {
            return Err(format!(
                "socket directory '{}' must be a directory",
                path.display()
            ));
        }

        let uid = metadata.uid();
        if uid != 0 {
            let allowed = allowed_owner_uids()?;
            if !allowed.contains(&uid) {
                return Err(format!(
                    "socket directory '{}' must be owned by current user, sudo caller, or root (found uid {uid})",
                    path.display()
                ));
            }
        }

        let mode = metadata.mode() & 0o7777;
        if mode & GROUP_OTHER_WRITE_MODE_MASK != 0
            && !(allow_sticky_group_other_write && mode & STICKY_BIT_MODE != 0)
        {
            return Err(format!(
                "socket directory '{}' must not be writable by group/other",
                path.display()
            ));
        }

        Ok(())
    }

    let metadata = std::fs::metadata(path).map_err(|err| {
        format!(
            "failed to inspect socket directory '{}': {err}",
            path.display()
        )
    })?;
    validate_directory(path, &metadata, false)?;

    let canonical = std::fs::canonicalize(path).map_err(|err| {
        format!(
            "failed to canonicalize socket directory '{}': {err}",
            path.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).map_err(|err| {
            format!(
                "failed to inspect ancestor socket directory '{}': {err}",
                ancestor.display()
            )
        })?;
        validate_directory(ancestor, &metadata, true)?;
    }

    Ok(())
}

#[cfg(unix)]
fn allowed_owner_uids() -> Result<BTreeSet<u32>, String> {
    let mut allowed = BTreeSet::new();
    allowed.insert(nix::unistd::geteuid().as_raw());
    allowed.insert(0);
    if nix::unistd::geteuid().as_raw() == 0 {
        if let Some(raw) = std::env::var_os("SUDO_UID") {
            let rendered = raw.to_string_lossy();
            let parsed = rendered
                .parse::<u32>()
                .map_err(|_| format!("invalid SUDO_UID value '{rendered}'"))?;
            allowed.insert(parsed);
        }
    }
    Ok(allowed)
}

#[cfg(not(unix))]
fn ensure_secure_socket_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Removes a stale socket left at `path`, refusing to delete anything that is not a socket.
pub(crate) fn remove_existing_socket_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect socket path '{}': {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "socket path '{}' exists and is not a unix socket",
                path.display()
            ));
        }
    }
    std::fs::remove_file(path)
        .map_err(|err| format!("failed to remove stale socket '{}': {err}", path.display()))
}

fn is_symlink(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "failed to inspect metadata for '{}': {err}",
            path.display()
        )),
    }
}

/// `mkdir -p` for socket directories: mode `0755` for the directories it creates.
fn create_socket_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(path)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)
}
