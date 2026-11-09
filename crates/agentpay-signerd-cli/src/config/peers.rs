//! Admin and agent peer-euid allowlists for the daemon socket.
//!
//! Root (`0`) is always allowed. `--allow-admin-euid` and `--allow-agent-euid`
//! extend the respective lists; the legacy `--allow-client-euid` extends both.

use std::collections::BTreeSet;

use anyhow::Result;

/// Effective uids allowed to issue admin and agent RPCs, respectively.
#[derive(Debug, Clone)]
pub(crate) struct AllowedPeerEuids {
    pub(crate) admin: BTreeSet<u32>,
    pub(crate) agent: BTreeSet<u32>,
}

/// Builds the allowlists from the configured CLI/environment values.
pub(crate) fn resolve_allowed_peer_euids(
    configured_admin: &[u32],
    configured_agent: &[u32],
    configured_legacy: &[u32],
) -> Result<AllowedPeerEuids> {
    resolve_allowed_peer_euids_with_sudo_uid(
        configured_admin,
        configured_agent,
        configured_legacy,
        None,
    )
}

fn resolve_allowed_peer_euids_with_sudo_uid(
    configured_admin: &[u32],
    configured_agent: &[u32],
    configured_legacy: &[u32],
    _sudo_uid: Option<u32>,
) -> Result<AllowedPeerEuids> {
    let mut admin = BTreeSet::from([0]);
    let mut agent = BTreeSet::from([0]);

    admin.extend(configured_legacy.iter().copied());
    admin.extend(configured_admin.iter().copied());
    agent.extend(configured_legacy.iter().copied());
    agent.extend(configured_agent.iter().copied());

    Ok(AllowedPeerEuids { admin, agent })
}

/// Renders an allowlist as a comma-separated, ascending list of uids.
pub(crate) fn format_allowed_euids(values: &BTreeSet<u32>) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        format_allowed_euids, resolve_allowed_peer_euids, resolve_allowed_peer_euids_with_sudo_uid,
    };

    #[test]
    fn resolve_allowed_peer_euids_keeps_root_only_when_allowlists_are_omitted() {
        let resolved = resolve_allowed_peer_euids_with_sudo_uid(&[], &[], &[], Some(501))
            .expect("allowed peer euids");

        assert_eq!(resolved.admin, BTreeSet::from([0]));
        assert_eq!(resolved.agent, BTreeSet::from([0]));
    }

    #[test]
    fn resolve_allowed_peer_euids_supports_split_admin_and_agent_allowlists() {
        let resolved = resolve_allowed_peer_euids_with_sudo_uid(&[11], &[22], &[33], Some(501))
            .expect("allowed peer euids");

        assert_eq!(resolved.admin, BTreeSet::from([0, 11, 33]));
        assert_eq!(resolved.agent, BTreeSet::from([0, 22, 33]));
    }

    #[test]
    fn resolve_allowed_peer_euids_wrapper_matches_internal_helper() {
        let resolved = resolve_allowed_peer_euids(&[7], &[8], &[9]).expect("allowed peer euids");
        assert_eq!(resolved.admin, BTreeSet::from([0, 7, 9]));
        assert_eq!(resolved.agent, BTreeSet::from([0, 8, 9]));
    }

    #[test]
    fn format_allowed_euids_renders_sorted_csv() {
        assert_eq!(
            format_allowed_euids(&BTreeSet::from([0, 11, 33])),
            "0,11,33"
        );
    }
}
