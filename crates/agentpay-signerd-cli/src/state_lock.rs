//! Exclusive advisory lock that prevents two daemons from sharing one state file.
//!
//! The lock is a `flock(LOCK_EX | LOCK_NB)` on `<state file>.lock`, opened with
//! `O_NOFOLLOW` and mode `0600`. It is held for the lifetime of the returned
//! [`StateFileLock`] and released on drop.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use crate::config::paths::ensure_file_parent;

/// Guard for the state-file lock; unlocks on drop.
pub(crate) struct StateFileLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: valid fd with best-effort unlock during drop.
            unsafe {
                let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Acquires the lock for `path`, failing fast if another daemon already holds it.
pub(crate) fn acquire_state_file_lock(path: &Path) -> Result<StateFileLock> {
    let lock_path = lock_path(path);
    ensure_file_parent(&lock_path, "state lock")?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&lock_path)
        .with_context(|| format!("failed to open state lock file {}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: valid fd for advisory lock in-process lifetime.
        unsafe {
            if libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(anyhow!(
                        "another agentpay daemon already holds the state lock on {}; stop it before starting a new daemon",
                        lock_path.display()
                    ));
                }
                return Err(anyhow!(
                    "failed to acquire state lock on {}: {error}",
                    lock_path.display()
                ));
            }
        }
    }
    Ok(StateFileLock {
        #[cfg(unix)]
        file,
    })
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{acquire_state_file_lock, lock_path};
    use crate::test_support::temp_path;

    #[test]
    fn lock_path_appends_lock_suffix() {
        assert_eq!(
            lock_path(Path::new("/tmp/agentpay/daemon-state.enc")),
            PathBuf::from("/tmp/agentpay/daemon-state.enc.lock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn acquire_state_file_lock_creates_lock_file() {
        let root = temp_path("agentpay-daemon-lock");
        let state_path = root.join("daemon-state.enc");

        let lock = acquire_state_file_lock(&state_path).expect("lock file");
        let lock_file = lock_path(&state_path);
        assert!(lock_file.exists());
        drop(lock);

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn acquire_state_file_lock_fails_fast_when_already_held() {
        let root = temp_path("agentpay-daemon-lock-held");
        let state_path = root.join("daemon-state.enc");

        let first = acquire_state_file_lock(&state_path).expect("first lock");
        let err = match acquire_state_file_lock(&state_path) {
            Ok(_) => panic!("second lock must not block or succeed"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("already holds the state lock"));
        drop(first);

        let again = acquire_state_file_lock(&state_path).expect("lock after release");
        drop(again);

        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
