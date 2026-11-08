//! Tests for RPC access classification and peer-euid allowlist helpers.

use std::collections::BTreeSet;

use agentpay_api::rpc::{
    BeginAdminChallengeParams, CompleteAdminChallengeParams, EnrollAdminCredentialParams,
    EvaluateForAgentParams, ListAdminCredentialsParams, ListPoliciesParams, RevokeAdminLeaseParams,
};
use agentpay_api::{AccessLevel, DaemonRpcRequest};

use super::{dummy_agent_request, singleton_allowed_set};
use crate::peer_auth::{combined_allowed_peer_euids, socket_mode_for_allowed_peer_euids};

#[test]
fn access_level_classifies_admin_agent_and_handshake_requests() {
    use agentpay_domain::AdminAuth;

    let admin_requests = [
        DaemonRpcRequest::EnrollAdminCredential(EnrollAdminCredentialParams {
            public_key_sec1_hex: String::new(),
            label: String::new(),
        }),
        DaemonRpcRequest::BeginAdminChallenge(BeginAdminChallengeParams {
            credential_id: uuid::Uuid::new_v4(),
            purpose: "admin-session".to_string(),
        }),
        DaemonRpcRequest::CompleteAdminChallenge(CompleteAdminChallengeParams {
            challenge_id: uuid::Uuid::new_v4(),
            signature_der_hex: String::new(),
        }),
        DaemonRpcRequest::ListAdminCredentials(ListAdminCredentialsParams {
            auth: AdminAuth::PeerCredentials,
        }),
        DaemonRpcRequest::RevokeAdminLease(RevokeAdminLeaseParams {
            auth: AdminAuth::PeerCredentials,
            lease_id: uuid::Uuid::new_v4(),
        }),
        DaemonRpcRequest::ListPolicies(ListPoliciesParams {
            auth: AdminAuth::PeerCredentials,
        }),
    ];
    let agent_request = DaemonRpcRequest::EvaluateForAgent(EvaluateForAgentParams {
        request: dummy_agent_request(),
    });

    for request in &admin_requests {
        assert_eq!(request.access_level(), AccessLevel::Admin);
    }
    assert_eq!(agent_request.access_level(), AccessLevel::Agent);
    assert_eq!(DaemonRpcRequest::Hello.access_level(), AccessLevel::Any);
}

#[test]
fn socket_mode_is_private_only_when_both_allowlists_are_root_only() {
    assert_eq!(
        socket_mode_for_allowed_peer_euids(&singleton_allowed_set(0), &singleton_allowed_set(0)),
        0o600
    );

    let current_euid = nix::unistd::geteuid().as_raw();
    let non_root_euid = if current_euid == 0 { 1 } else { current_euid };
    assert_eq!(
        socket_mode_for_allowed_peer_euids(
            &singleton_allowed_set(0),
            &singleton_allowed_set(non_root_euid)
        ),
        0o666
    );
}

#[test]
fn combined_allowed_peer_euids_deduplicates_split_allowlists() {
    let current_euid = nix::unistd::geteuid().as_raw();
    let combined = combined_allowed_peer_euids(
        &BTreeSet::from([0, current_euid]),
        &BTreeSet::from([current_euid, current_euid.saturating_add(1)]),
    );

    assert_eq!(
        combined,
        BTreeSet::from([0, current_euid, current_euid.saturating_add(1)])
    );
}
