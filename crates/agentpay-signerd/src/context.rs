//! [`RequestContext`]: transport-verified facts about the caller of a daemon API.

/// Effective uid of the superuser.
const ROOT_EUID: u32 = 0;

/// Facts about the caller that the daemon learns from the transport, never from
/// the request body.
///
/// Transports build one per connection from kernel-reported peer credentials
/// (`SO_PEERCRED` / `getpeereid`) and pass it to
/// [`InMemoryDaemon::handle_rpc`](crate::InMemoryDaemon::handle_rpc). The
/// in-process [`KeyManagerDaemonApi`](crate::KeyManagerDaemonApi) implementation
/// on [`InMemoryDaemon`](crate::InMemoryDaemon) uses [`RequestContext::in_process`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestContext {
    peer_euid: Option<u32>,
}

impl RequestContext {
    /// A caller in the daemon's own process, with no transport boundary.
    ///
    /// It is root-equivalent: code sharing the daemon's address space can
    /// already reach every secret the daemon holds.
    #[must_use]
    pub const fn in_process() -> Self {
        Self { peer_euid: None }
    }

    /// A caller connected over a transport whose kernel-reported effective uid is `peer_euid`.
    #[must_use]
    pub const fn peer(peer_euid: u32) -> Self {
        Self {
            peer_euid: Some(peer_euid),
        }
    }

    /// Returns the transport peer's effective uid, or `None` for in-process callers.
    #[must_use]
    pub const fn peer_euid(&self) -> Option<u32> {
        self.peer_euid
    }

    /// Returns whether the caller is a root peer or an in-process caller.
    #[must_use]
    pub const fn is_root_equivalent(&self) -> bool {
        match self.peer_euid {
            None => true,
            Some(euid) => euid == ROOT_EUID,
        }
    }
}
