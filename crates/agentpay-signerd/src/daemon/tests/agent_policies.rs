//! `AgentPolicySummary`: the documented example is what the daemon returns,
//! and the summary follows the policy engine's attachment rules.

use std::collections::BTreeSet;

use agentpay_api::rpc::{AgentPolicySummaryParams, AuthenticateAgentParams};
use agentpay_api::{AgentAuth, AgentPolicySummary, DaemonRpcRequest, DaemonRpcResponse};
use agentpay_domain::{
    AdminAuth, ApprovalType, EntityScope, PolicyAttachment, PolicyType, SpendingPolicy,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::policy_all_per_tx;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, RequestContext};

/// Loads `crates/agentpay-api/fixtures/rpc/<method>.<kind>.json`.
fn example(method: &str, kind: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/rpc")
        .join(format!("{method}.{kind}.json"));
    let text = std::fs::read_to_string(&path).expect("example file");
    serde_json::from_str(&text).expect("example JSON")
}

fn daemon() -> InMemoryDaemon<SoftwareSignerBackend> {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default()).expect("daemon")
}

/// Creates an agent with `attachment` and returns its credentials.
async fn agent(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    attachment: PolicyAttachment,
) -> AgentAuth {
    let admin = AdminAuth::PeerCredentials;
    let vault_key = daemon
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let credentials = daemon
        .create_agent_key(&admin, vault_key.id, attachment)
        .await
        .expect("agent key");
    AgentAuth {
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
    }
}

/// Calls `AgentPolicySummary` over the RPC dispatcher as an agent peer.
async fn summary(
    daemon: &InMemoryDaemon<SoftwareSignerBackend>,
    auth: AgentAuth,
) -> Result<AgentPolicySummary, DaemonError> {
    let request = DaemonRpcRequest::AgentPolicySummary(AgentPolicySummaryParams { auth });
    match daemon
        .handle_rpc(&RequestContext::peer(4242), request)
        .await?
    {
        DaemonRpcResponse::AgentPolicySummary(summary) => Ok(summary),
        other => panic!("unexpected response {other:?}"),
    }
}

#[tokio::test]
async fn the_example_is_reproduced_by_the_daemon() {
    let daemon = daemon();
    let admin = AdminAuth::PeerCredentials;
    // The `ListPolicies` example policies, as the summary example shows them.
    let DaemonRpcResponse::Policies(policies) =
        serde_json::from_value(example("ListPolicies", "response")).expect("policies example")
    else {
        panic!("ListPolicies example must return policies");
    };
    for policy in policies {
        daemon.add_policy(&admin, policy).await.expect("add policy");
    }
    let auth = agent(&daemon, PolicyAttachment::AllPolicies).await;
    let DaemonRpcRequest::AgentPolicySummary(AgentPolicySummaryParams { auth: mut sent }) =
        serde_json::from_value(example("AgentPolicySummary", "request")).expect("request")
    else {
        panic!("wrong AgentPolicySummary request example");
    };
    sent.agent_key_id = auth.agent_key_id;
    sent.agent_auth_token = auth.agent_auth_token.clone();
    let actual = summary(&daemon, sent).await.expect("summary");
    let documented: DaemonRpcResponse =
        serde_json::from_value(example("AgentPolicySummary", "response")).expect("response");
    assert_eq!(
        serde_json::to_value(DaemonRpcResponse::AgentPolicySummary(actual)).expect("encode"),
        serde_json::to_value(documented).expect("encode")
    );
}

#[tokio::test]
async fn an_agent_without_policies_has_no_spending_policy() {
    let daemon = daemon();
    let auth = agent(&daemon, PolicyAttachment::AllPolicies).await;
    let result = summary(&daemon, auth).await.expect("summary");
    assert_eq!(result.attachment, PolicyAttachment::AllPolicies);
    assert!(result.policies.is_empty());
    assert_eq!(result.spending_policy_count, 0);
}

#[tokio::test]
async fn typed_data_and_disabled_policies_do_not_count_as_spending_limits() {
    let daemon = daemon();
    let admin = AdminAuth::PeerCredentials;
    let typed_data =
        SpendingPolicy::new_eip712_signing(5, ApprovalType::Allow, EntityScope::All).expect("712");
    let disabled = policy_all_per_tx(10);
    for policy in [typed_data.clone(), disabled.clone()] {
        daemon.add_policy(&admin, policy).await.expect("add policy");
    }
    daemon
        .disable_policy(&admin, disabled.id)
        .await
        .expect("disable");
    let auth = agent(&daemon, PolicyAttachment::AllPolicies).await;
    let result = summary(&daemon, auth).await.expect("summary");
    let ids: Vec<Uuid> = result.policies.iter().map(|p| p.id).collect();
    assert_eq!(ids, vec![typed_data.id]);
    assert_eq!(result.policies[0].policy_type, PolicyType::Eip712Signing);
    assert_eq!(result.spending_policy_count, 0);
}

#[tokio::test]
async fn a_policy_set_only_reports_its_own_policies_in_priority_order() {
    let daemon = daemon();
    let admin = AdminAuth::PeerCredentials;
    let mut late = policy_all_per_tx(10);
    late.priority = 50;
    let mut early = policy_all_per_tx(20);
    early.priority = 1;
    let other = policy_all_per_tx(30);
    for policy in [late.clone(), early.clone(), other] {
        daemon.add_policy(&admin, policy).await.expect("add policy");
    }
    let set = PolicyAttachment::policy_set(BTreeSet::from([late.id, early.id])).expect("set");
    let auth = agent(&daemon, set.clone()).await;
    let result = summary(&daemon, auth).await.expect("summary");
    assert_eq!(result.attachment, set);
    let ids: Vec<Uuid> = result.policies.iter().map(|p| p.id).collect();
    assert_eq!(ids, vec![early.id, late.id]);
    assert_eq!(result.spending_policy_count, 2);
}

#[tokio::test]
async fn bad_credentials_are_refused() {
    let daemon = daemon();
    let auth = agent(&daemon, PolicyAttachment::AllPolicies).await;
    let forged = AgentAuth {
        agent_key_id: auth.agent_key_id,
        agent_auth_token: "forged".to_string().into(),
    };
    let err = summary(&daemon, forged).await.expect_err("forged token");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
    // The summary is an agent method: the agent allowlist governs it.
    let request = DaemonRpcRequest::AgentPolicySummary(AgentPolicySummaryParams { auth });
    assert_eq!(
        request.access_level(),
        DaemonRpcRequest::AuthenticateAgent(AuthenticateAgentParams {
            auth: AgentAuth {
                agent_key_id: Uuid::nil(),
                agent_auth_token: String::new().into(),
            },
        })
        .access_level()
    );
}
