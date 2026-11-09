//! Peer-euid authentication for socket connections.
//!
//! Both sides of the socket check the kernel-reported effective uid of the
//! remote peer: the client pins the expected daemon euid, and the server
//! enforces separate admin and agent allowlists. The socket file mode is also
//! derived from those allowlists so that a root-only daemon is not
//! world-connectable.

use std::collections::BTreeSet;

use tokio::net::UnixStream;

use crate::error::UnixTransportError;

/// Returns the effective uid of the process on the other end of `stream`.
pub(crate) fn peer_euid(stream: &UnixStream) -> Result<u32, String> {
    let creds = stream.peer_cred().map_err(|err| err.to_string())?;
    Ok(creds.uid())
}

/// Rejects an empty allowlist, which would make the corresponding RPCs unreachable.
pub(crate) fn validate_allowed_peer_euids(
    label: &str,
    values: &BTreeSet<u32>,
) -> Result<(), UnixTransportError> {
    if values.is_empty() {
        return Err(UnixTransportError::Protocol(format!(
            "allowed {label} peer euid set must not be empty"
        )));
    }

    Ok(())
}

/// Socket file mode: owner-only when both allowlists are exactly `{0}`, otherwise world-connectable.
///
/// Non-root peers are still filtered by euid after connecting.
pub(crate) fn socket_mode_for_allowed_peer_euids(
    allowed_admin_peer_euids: &BTreeSet<u32>,
    allowed_agent_peer_euids: &BTreeSet<u32>,
) -> u32 {
    let only_root_admin =
        allowed_admin_peer_euids.len() == 1 && allowed_admin_peer_euids.contains(&0);
    let only_root_agent =
        allowed_agent_peer_euids.len() == 1 && allowed_agent_peer_euids.contains(&0);

    if only_root_admin && only_root_agent {
        0o600
    } else {
        0o666
    }
}

/// Union of the admin and agent allowlists: the set of peers allowed to connect at all.
pub(crate) fn combined_allowed_peer_euids(
    allowed_admin_peer_euids: &BTreeSet<u32>,
    allowed_agent_peer_euids: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    allowed_admin_peer_euids
        .union(allowed_agent_peer_euids)
        .copied()
        .collect()
}
