//! Ownership and permission checks for paths that root code trusts.
//!
//! - Source binaries copied into the root-owned prefix must be regular, executable files that
//!   only root or the installing user can modify, inside directories only they can modify.
//! - The daemon socket must be a root-owned socket inside root-owned directories that nobody
//!   else can write to, so a client connecting to it really talks to the root daemon. The
//!   payments socket must likewise belong to the payments service account, in directories
//!   owned by root or that account.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::system::{FileKind, FileMeta, System};

const GROUP_OTHER_WRITE: u32 = 0o022;
const STICKY: u32 = 0o1000;
const ANY_EXECUTE: u32 = 0o111;
/// Interval between socket readiness probes.
const SOCKET_POLL: Duration = Duration::from_millis(250);

fn writable_by_others(meta: &FileMeta) -> bool {
    meta.mode & GROUP_OTHER_WRITE != 0 && meta.mode & STICKY == 0
}

/// Checks that every directory from `/` down to `dir` is owned by an allowed uid and not
/// writable by anyone else.
fn check_directory_chain(sys: &dyn System, dir: &Path, allowed_uids: &[u32]) -> Result<()> {
    let resolved = sys.canonicalize(dir)?;
    for ancestor in resolved.ancestors() {
        let Some(meta) = sys.lstat(ancestor)? else {
            bail!("{} does not exist", ancestor.display());
        };
        if meta.kind != FileKind::Dir {
            bail!("{} is not a directory", ancestor.display());
        }
        if !allowed_uids.contains(&meta.uid) {
            bail!(
                "{} is owned by uid {}, expected root or the installing user",
                ancestor.display(),
                meta.uid
            );
        }
        if writable_by_others(&meta) {
            bail!("{} is writable by other users", ancestor.display());
        }
    }
    Ok(())
}

/// Verifies a source binary before root copies it into the managed prefix.
pub fn check_source_binary(sys: &dyn System, path: &Path, user_uid: u32) -> Result<()> {
    let allowed = [0, user_uid];
    let Some(meta) = sys.lstat(path)? else {
        bail!("{} is missing", path.display());
    };
    if meta.kind != FileKind::File {
        bail!("{} must be a regular file (not a symlink)", path.display());
    }
    if meta.mode & ANY_EXECUTE == 0 {
        bail!("{} is not executable", path.display());
    }
    if !allowed.contains(&meta.uid) {
        bail!(
            "{} is owned by uid {}, expected root or the installing user",
            path.display(),
            meta.uid
        );
    }
    if meta.mode & GROUP_OTHER_WRITE != 0 {
        bail!("{} is writable by other users", path.display());
    }
    match path.parent() {
        Some(parent) => check_directory_chain(sys, parent, &allowed),
        None => Ok(()),
    }
}

/// Readiness of the daemon socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketCheck {
    /// Nothing at the socket path.
    Missing,
    /// Something is there but it must not be trusted; the reason is attached.
    Untrusted(String),
    /// A trusted socket exists but nothing accepts connections.
    NotAccepting,
    /// Trusted and accepting connections.
    Ready,
}

impl SocketCheck {
    /// Short human description.
    pub fn describe(&self) -> String {
        match self {
            Self::Missing => "missing".into(),
            Self::Untrusted(reason) => format!("untrusted: {reason}"),
            Self::NotAccepting => "present but not accepting connections".into(),
            Self::Ready => "ready".into(),
        }
    }
}

/// Inspects the root daemon socket without waiting.
pub fn check_socket(sys: &dyn System, socket: &Path) -> Result<SocketCheck> {
    check_socket_owned_by(sys, socket, 0)
}

/// Inspects a socket that must belong to `owner_uid` (root for the signer daemon, the service
/// account for the payments service), inside directories owned by root or `owner_uid`.
pub fn check_socket_owned_by(
    sys: &dyn System,
    socket: &Path,
    owner_uid: u32,
) -> Result<SocketCheck> {
    let Some(meta) = sys.lstat(socket)? else {
        return Ok(SocketCheck::Missing);
    };
    if meta.kind != FileKind::Socket {
        return Ok(SocketCheck::Untrusted(format!(
            "{} is not a socket",
            socket.display()
        )));
    }
    if meta.uid != owner_uid {
        let expected = if owner_uid == 0 {
            "root".to_string()
        } else {
            format!("uid {owner_uid}")
        };
        return Ok(SocketCheck::Untrusted(format!(
            "{} is owned by uid {}, not {expected}",
            socket.display(),
            meta.uid
        )));
    }
    if let Some(parent) = socket.parent() {
        if let Err(error) = check_directory_chain(sys, parent, &[0, owner_uid]) {
            return Ok(SocketCheck::Untrusted(error.to_string()));
        }
    }
    Ok(if sys.socket_accepts(socket) {
        SocketCheck::Ready
    } else {
        SocketCheck::NotAccepting
    })
}

/// Polls until the root daemon socket is trusted and accepting, or `timeout` elapses.
pub fn wait_for_socket(sys: &dyn System, socket: &Path, timeout: Duration) -> Result<()> {
    wait_for_socket_owned_by(sys, socket, 0, timeout)
}

/// Polls until a socket owned by `owner_uid` is trusted and accepting, or `timeout` elapses.
pub fn wait_for_socket_owned_by(
    sys: &dyn System,
    socket: &Path,
    owner_uid: u32,
    timeout: Duration,
) -> Result<()> {
    let attempts = (timeout.as_millis() / SOCKET_POLL.as_millis()).max(1);
    let mut last = SocketCheck::Missing;
    for attempt in 0..attempts {
        last = check_socket_owned_by(sys, socket, owner_uid)?;
        match &last {
            SocketCheck::Ready => return Ok(()),
            // An untrusted socket will not fix itself; fail immediately.
            SocketCheck::Untrusted(reason) => bail!("socket is untrusted: {reason}"),
            _ if attempt + 1 < attempts => sys.sleep(SOCKET_POLL),
            _ => {}
        }
    }
    bail!(
        "socket {} is {} after {}s",
        socket.display(),
        last.describe(),
        timeout.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    #[test]
    fn source_binary_checks_owner_mode_and_directories() {
        let sys = FakeSystem::macos();
        let path = Path::new("/Users/alice/bin/agentpay-daemon");
        sys.put_file(path, b"bin", 501, 0o755);
        sys.ensure_dir(Path::new("/Users/alice"), 0o755).unwrap();
        // Directories created by put_file are root-owned 0755, so this passes.
        check_source_binary(&sys, path, 501).unwrap();
        assert!(check_source_binary(&sys, path, 502).is_err());
        sys.set_mode(path, 0o775);
        assert!(check_source_binary(&sys, path, 501).is_err());
        sys.set_mode(path, 0o644);
        assert!(check_source_binary(&sys, path, 501).is_err());
        sys.set_mode(path, 0o755);
        sys.set_mode(Path::new("/Users/alice/bin"), 0o777);
        let error = check_source_binary(&sys, path, 501).unwrap_err();
        assert!(error.to_string().contains("writable by other users"));
    }

    #[test]
    fn socket_wait_times_out_and_rejects_untrusted_sockets() {
        let sys = FakeSystem::linux();
        let socket = Path::new("/run/agentpay/daemon.sock");
        let error = wait_for_socket(&sys, socket, Duration::from_secs(2)).unwrap_err();
        assert!(error.to_string().contains("missing after 2s"));
        assert_eq!(sys.state.borrow().sleeps, 7);

        sys.put_file(socket, b"", 0, 0o600);
        assert!(matches!(
            check_socket(&sys, socket).unwrap(),
            SocketCheck::Untrusted(_)
        ));
    }

    #[test]
    fn service_sockets_must_belong_to_the_service_account() {
        let sys = FakeSystem::linux();
        sys.state.borrow_mut().payments_running = true;
        let socket = Path::new("/run/agentpay-paymentd/paymentd.sock");
        sys.mkdir("/run/agentpay-paymentd");
        sys.set_owner(Path::new("/run/agentpay-paymentd"), 999, 999)
            .unwrap();
        sys.state.borrow_mut().files.insert(
            socket.into(),
            crate::system::fake::Node {
                meta: FileMeta {
                    kind: FileKind::Socket,
                    uid: 999,
                    gid: 999,
                    mode: 0o666,
                },
                data: Vec::new(),
            },
        );
        assert_eq!(
            check_socket_owned_by(&sys, socket, 999).unwrap(),
            SocketCheck::Ready
        );
        let SocketCheck::Untrusted(reason) = check_socket(&sys, socket).unwrap() else {
            panic!("a service-owned socket is not a root socket");
        };
        assert!(reason.contains("not root"));
        let SocketCheck::Untrusted(reason) = check_socket_owned_by(&sys, socket, 998).unwrap()
        else {
            panic!("wrong owner");
        };
        assert!(reason.contains("not uid 998"));
    }
}
