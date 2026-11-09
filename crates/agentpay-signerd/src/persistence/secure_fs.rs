//! Filesystem hardening for the state file: ownership/permission checks on the
//! file and its ancestor directories, and atomic secure writes.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub(super) fn ensure_secure_path(
    path: &Path,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    if is_symlink(path)? {
        return Err(format!(
            "state path '{}' must not be a symlink",
            path.display()
        ));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            // Explicit mode, not the umask: the directory check below refuses group/other write.
            create_dir_with_mode(parent, 0o700).map_err(|err| {
                format!(
                    "failed to create state directory '{}': {err}",
                    parent.display()
                )
            })?;
            if is_symlink(parent)? {
                return Err(format!(
                    "state directory '{}' must not be a symlink",
                    parent.display()
                ));
            }
            ensure_secure_directory(parent, allow_current_uid_in_tests)?;
        }
    }

    if path.exists() {
        let metadata = std::fs::metadata(path)
            .map_err(|err| format!("failed to inspect state file '{}': {err}", path.display()))?;
        validate_private_state_file(path, &metadata, allow_current_uid_in_tests)?;
    }

    Ok(())
}

#[cfg(unix)]
pub(super) fn ensure_secure_directory(
    path: &Path,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    const STICKY_BIT_MODE: u32 = 0o1000;

    fn validate_directory(
        path: &Path,
        metadata: &std::fs::Metadata,
        allow_sticky_group_other_write: bool,
        allow_current_uid_in_tests: bool,
    ) -> Result<(), String> {
        if !metadata.is_dir() {
            return Err(format!(
                "state directory '{}' is not a directory",
                path.display()
            ));
        }

        validate_root_owned(
            path,
            metadata,
            "state directory",
            allow_current_uid_in_tests,
        )?;
        validate_directory_mode(
            path,
            metadata.mode() & 0o7777,
            STICKY_BIT_MODE,
            allow_sticky_group_other_write,
        )
    }

    let metadata = std::fs::metadata(path).map_err(|err| {
        format!(
            "failed to inspect state directory '{}': {err}",
            path.display()
        )
    })?;
    validate_directory(path, &metadata, false, allow_current_uid_in_tests)?;

    let canonical = std::fs::canonicalize(path).map_err(|err| {
        format!(
            "failed to canonicalize state directory '{}': {err}",
            path.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).map_err(|err| {
            format!(
                "failed to inspect ancestor state directory '{}': {err}",
                ancestor.display()
            )
        })?;
        validate_directory(ancestor, &metadata, true, allow_current_uid_in_tests)?;
    }

    Ok(())
}

#[cfg(not(unix))]
pub(super) fn ensure_secure_directory(
    _path: &Path,
    _allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_root_owned(
    path: &Path,
    metadata: &std::fs::Metadata,
    label: &str,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    validate_root_owned_uid(path, metadata.uid(), label, allow_current_uid_in_tests)
}

#[cfg(not(unix))]
fn validate_root_owned(
    _path: &Path,
    _metadata: &std::fs::Metadata,
    _label: &str,
    _allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    Ok(())
}

pub(super) fn validate_private_state_file(
    path: &Path,
    metadata: &std::fs::Metadata,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "state file '{}' must be a regular file",
            path.display()
        ));
    }

    validate_root_owned(path, metadata, "state file", allow_current_uid_in_tests)?;

    #[cfg(unix)]
    {
        validate_private_state_file_mode(path, metadata.mode() & 0o777)?;
    }

    Ok(())
}

#[cfg(all(unix, any(test, coverage)))]
pub(super) fn validate_root_owned_uid(
    path: &Path,
    uid: u32,
    label: &str,
    allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    let current_uid = nix::unistd::Uid::effective().as_raw();
    #[cfg(coverage)]
    let allow_current_uid = true;
    #[cfg(not(coverage))]
    let allow_current_uid = allow_current_uid_in_tests;

    if uid == 0 || (allow_current_uid && uid == current_uid) {
        return Ok(());
    }

    Err(format!(
        "{label} '{}' must be owned by root; found uid {uid}",
        path.display()
    ))
}

#[cfg(all(unix, not(any(test, coverage))))]
pub(super) fn validate_root_owned_uid(
    path: &Path,
    uid: u32,
    label: &str,
    _allow_current_uid_in_tests: bool,
) -> Result<(), String> {
    if uid == 0 {
        return Ok(());
    }

    Err(format!(
        "{label} '{}' must be owned by root; found uid {uid}",
        path.display()
    ))
}

#[cfg(unix)]
pub(super) fn validate_directory_mode(
    path: &Path,
    mode: u32,
    sticky_bit_mode: u32,
    allow_sticky_group_other_write: bool,
) -> Result<(), String> {
    if mode & 0o022 != 0 && !(allow_sticky_group_other_write && mode & sticky_bit_mode != 0) {
        return Err(format!(
            "state directory '{}' must not be writable by group/other",
            path.display()
        ));
    }

    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_private_state_file_mode(path: &Path, mode: u32) -> Result<(), String> {
    if mode & 0o077 != 0 {
        return Err(format!(
            "state file '{}' must not grant group/other permissions",
            path.display()
        ));
    }

    Ok(())
}

pub(super) fn is_symlink(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "failed to inspect metadata for '{}': {err}",
            path.display()
        )),
    }
}

pub(super) fn read_file_secure(
    path: &Path,
    allow_current_uid_in_tests: bool,
) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("failed to open state file '{}': {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to inspect state file '{}': {err}", path.display()))?;
    validate_private_state_file(path, &metadata, allow_current_uid_in_tests)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read state file '{}': {err}", path.display()))?;
    Ok(bytes)
}

pub(super) fn atomic_write_secure(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("agentpay-state");
    let temp_name = if file_name.starts_with('.') {
        format!("{file_name}.tmp.{}", Uuid::new_v4().simple())
    } else {
        format!(".{file_name}.tmp.{}", Uuid::new_v4().simple())
    };
    let temp_path = path.with_file_name(temp_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = options.open(&temp_path).map_err(|err| {
        format!(
            "failed to create temp state file '{}': {err}",
            temp_path.display()
        )
    })?;
    file.write_all(bytes).map_err(|err| {
        format!(
            "failed to write temp state file '{}': {err}",
            temp_path.display()
        )
    })?;
    file.sync_all().map_err(|err| {
        format!(
            "failed to sync temp state file '{}': {err}",
            temp_path.display()
        )
    })?;
    drop(file);

    #[cfg(unix)]
    {
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |err| {
                format!(
                    "failed to set state file permissions '{}': {err}",
                    temp_path.display()
                )
            },
        )?;
    }

    std::fs::rename(&temp_path, path).map_err(|err| {
        format!(
            "failed to atomically replace state file '{}' from '{}': {err}",
            path.display(),
            temp_path.display()
        )
    })?;
    Ok(())
}

/// `mkdir -p` with an explicit mode for the directories it creates (existing ones are untouched).
fn create_dir_with_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::create_dir_all(path)
    }
}
