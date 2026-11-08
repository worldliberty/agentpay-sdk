//! Helpers shared by paymentd's unit tests.

use std::path::{Path, PathBuf};

/// A private temporary directory, removed on drop.
///
/// It lives directly under `/private/tmp` (or `/tmp`) so socket paths inside
/// it stay well below the 104-byte `sun_path` limit on macOS.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    /// Creates a fresh `0700` directory.
    pub(crate) fn new(label: &str) -> Self {
        let base = if Path::new("/private/tmp").is_dir() {
            Path::new("/private/tmp")
        } else {
            Path::new("/tmp")
        };
        let path = base.join(format!(
            "pd-{label}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir(&path).expect("create temp dir");
        set_mode(&path, 0o700);
        Self(path)
    }

    /// The directory.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sets the permission bits of `path`.
pub(crate) fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}
