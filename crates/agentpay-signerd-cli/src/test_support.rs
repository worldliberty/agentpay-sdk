//! Helpers shared by the daemon binary's unit tests.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh private (`0700`) directory under the system temp directory. Files must not sit
/// directly in the temp directory: on Linux that is the shared `/tmp` (mode `1777`), which the
/// daemons rightly refuse as a state or socket directory.
fn private_temp_dir() -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ap-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .subsec_nanos()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("create private temp dir");
    dir
}

/// Returns a not-yet-created path in a fresh private temp directory, unique per call.
pub(crate) fn temp_path(prefix: &str) -> PathBuf {
    private_temp_dir().join(format!(
        "{prefix}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ))
}

/// `mkdir -p` with mode `0700`, independent of the umask (Ubuntu's default 002 would otherwise
/// make the directories group-writable, which the daemon's checks refuse).
pub(crate) fn create_private_dir(path: &std::path::Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .expect("create private test directory");
}
