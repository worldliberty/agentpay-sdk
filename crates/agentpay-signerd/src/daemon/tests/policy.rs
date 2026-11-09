//! Policy administration, policy-set attachments, and evaluation explanations.

use std::collections::BTreeSet;

use agentpay_domain::{
    AdminAuth, AgentAction, EntityScope, PolicyAttachment, PolicyType, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{policy_all_per_tx, sign_request};
use crate::daemon::state::validate_loaded_state;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn new_with_loaded_state_normalizes_disabled_policy_set_members() {
    let config = DaemonConfig::default();
    let daemon =
        InMemoryDaemon::new(SoftwareSignerBackend::default(), config.clone()).expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let credentials = daemon
        .create_agent_key(
            &session,
            key.id,
            PolicyAttachment::PolicySet(BTreeSet::from([policy.id])),
        )
        .await
        .expect("agent");

    let mut state = daemon.snapshot_state().expect("snapshot");
    state
        .policies
        .get_mut(&policy.id)
        .expect("policy in snapshot")
        .enabled = false;

    let loaded = InMemoryDaemon::new_with_loaded_state(
        SoftwareSignerBackend::default(),
        config,
        state,
        None,
    )
    .expect("load normalized state");

    let normalized = loaded.snapshot_state().expect("normalized snapshot");
    let stored_agent = normalized
        .agent_keys
        .get(&credentials.agent_key.id)
        .expect("agent in normalized snapshot");
    assert_eq!(
        stored_agent.policies,
        PolicyAttachment::PolicySet(BTreeSet::new())
    );
    validate_loaded_state(&normalized).expect("normalized state remains valid");
}

#[tokio::test]
async fn create_agent_key_validates_policy_set() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let mut ids = BTreeSet::new();
    ids.insert(Uuid::new_v4());

    let err = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(ids))
        .await
        .expect_err("unknown policy must fail");

    assert!(matches!(err, DaemonError::UnknownPolicy(_)));
}

#[tokio::test]
async fn create_agent_key_rejects_disabled_policy_set_member() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let disabled_policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, disabled_policy.clone())
        .await
        .expect("add policy");
    daemon
        .disable_policy(&session, disabled_policy.id)
        .await
        .expect("disable policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let ids = BTreeSet::from([disabled_policy.id]);
    let err = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(ids))
        .await
        .expect_err("disabled policy must fail");

    assert!(matches!(
        &err,
        DaemonError::InvalidPolicyAttachment(message) if message.contains("disabled")
    ));
}

#[tokio::test]
async fn create_agent_key_accepts_enabled_policy_set_member() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let enabled_policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, enabled_policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let ids = BTreeSet::from([enabled_policy.id]);
    let credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(ids.clone()))
        .await
        .expect("enabled policy set must succeed");

    assert_eq!(credentials.agent_key.vault_key_id, key.id);
    assert_eq!(
        credentials.agent_key.policies,
        PolicyAttachment::PolicySet(ids)
    );
    assert!(!credentials.auth_token.is_empty());
}

#[tokio::test]
async fn create_agent_key_rejects_empty_policy_set() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let empty = std::collections::BTreeSet::new();
    let err = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(empty))
        .await
        .expect_err("empty policy set must fail");

    assert!(matches!(err, DaemonError::InvalidPolicyAttachment(_)));
}

#[tokio::test]
async fn disable_policy_prunes_policy_set_attachments() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let credentials = daemon
        .create_agent_key(
            &session,
            key.id,
            PolicyAttachment::PolicySet(BTreeSet::from([policy.id])),
        )
        .await
        .expect("agent");

    daemon
        .disable_policy(&session, policy.id)
        .await
        .expect("disable policy");

    let snapshot = daemon.snapshot_state().expect("snapshot");
    let stored_agent = snapshot
        .agent_keys
        .get(&credentials.agent_key.id)
        .expect("stored agent");
    assert_eq!(
        stored_agent.policies,
        PolicyAttachment::PolicySet(BTreeSet::new())
    );
    validate_loaded_state(&snapshot).expect("pruned snapshot remains loadable");
}

#[tokio::test]
async fn add_policy_rejects_invalid_policy_payloads() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let zero_max = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 0,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::All,
        assets: EntityScope::All,
        networks: EntityScope::All,
        approval_type: None,
        over_limit: agentpay_domain::OverLimit::Deny,
        enabled: true,
    };
    let err = daemon
        .add_policy(&session, zero_max)
        .await
        .expect_err("zero max amount must be rejected");
    assert!(matches!(err, DaemonError::InvalidPolicy(_)));

    let empty_recipient_scope = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 1,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::Set(BTreeSet::new()),
        assets: EntityScope::All,
        networks: EntityScope::All,
        approval_type: None,
        over_limit: agentpay_domain::OverLimit::Deny,
        enabled: true,
    };
    let err = daemon
        .add_policy(&session, empty_recipient_scope)
        .await
        .expect_err("empty recipient scope must be rejected");
    assert!(matches!(err, DaemonError::InvalidPolicy(_)));

    let empty_asset_scope = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 1,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::All,
        assets: EntityScope::Set(BTreeSet::new()),
        networks: EntityScope::All,
        approval_type: None,
        over_limit: agentpay_domain::OverLimit::Deny,
        enabled: true,
    };
    let err = daemon
        .add_policy(&session, empty_asset_scope)
        .await
        .expect_err("empty asset scope must be rejected");
    assert!(matches!(err, DaemonError::InvalidPolicy(_)));
}

#[tokio::test]
async fn add_policy_rejects_duplicate_policy_ids() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let original = policy_all_per_tx(100);
    let mut duplicate = policy_all_per_tx(200);
    duplicate.id = original.id;

    daemon
        .add_policy(&session, original.clone())
        .await
        .expect("add original");

    let err = daemon
        .add_policy(&session, duplicate)
        .await
        .expect_err("duplicate policy id must be rejected");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message)
            if message.contains("already exists")
                && message.contains(&original.id.to_string())
    ));

    let listed = daemon.list_policies(&session).await.expect("list policies");
    let matching: Vec<SpendingPolicy> = listed
        .into_iter()
        .filter(|policy| policy.id == original.id)
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].max_amount_wei, original.max_amount_wei);
}

#[tokio::test]
async fn list_policies_is_deterministic_for_equal_priority() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let mut high_id = policy_all_per_tx(100);
    high_id.priority = 7;
    high_id.id = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").expect("uuid");

    let mut low_id = policy_all_per_tx(100);
    low_id.priority = 7;
    low_id.id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid");

    daemon
        .add_policy(&session, high_id.clone())
        .await
        .expect("add high id");
    daemon
        .add_policy(&session, low_id.clone())
        .await
        .expect("add low id");

    let listed = daemon.list_policies(&session).await.expect("list policies");
    let equal_priority: Vec<Uuid> = listed
        .into_iter()
        .filter(|p| p.priority == 7)
        .map(|p| p.id)
        .collect();
    assert_eq!(equal_priority, vec![low_id.id, high_id.id]);
}

#[tokio::test]
async fn explain_for_agent_returns_denial_without_error() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    let policy = policy_all_per_tx(10);
    daemon
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7700000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8700000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 11,
        },
    );
    let explanation = daemon
        .explain_for_agent(request)
        .await
        .expect("explain should return payload");
    assert_eq!(explanation.applicable_policy_ids, vec![policy.id]);
    assert_eq!(explanation.evaluated_policy_ids, vec![policy.id]);
    match explanation.decision {
        agentpay_policy::PolicyDecision::Deny(PolicyError::PerTxLimitExceeded { .. }) => {}
        other => panic!("unexpected explanation decision: {other:?}"),
    }
}

#[tokio::test]
async fn disable_policy_stops_enforcement() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let mut strict = policy_all_per_tx(100);
    strict.priority = 0;
    let mut permissive = policy_all_per_tx(1_000);
    permissive.priority = 1;
    daemon
        .add_policy(&session, strict.clone())
        .await
        .expect("add strict policy");
    daemon
        .add_policy(&session, permissive)
        .await
        .expect("add permissive policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let deny_action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 500,
    };
    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, deny_action.clone()))
        .await
        .expect_err("strict policy must deny before disable");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::PerTxLimitExceeded { .. })
    ));

    daemon
        .disable_policy(&session, strict.id)
        .await
        .expect("disable strict policy");

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, deny_action))
        .await
        .expect("request should pass after strict policy disable");
    assert!(!signature.bytes.is_empty());
}

#[tokio::test]
async fn policy_set_agents_do_not_pick_up_policies_added_later() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

    let mut permissive = policy_all_per_tx(1_000);
    permissive.priority = 1;
    daemon
        .add_policy(&session, permissive.clone())
        .await
        .expect("add permissive policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let attached_policy_ids = BTreeSet::from([permissive.id]);
    let agent_credentials = daemon
        .create_agent_key(
            &session,
            key.id,
            PolicyAttachment::policy_set(attached_policy_ids.clone()).expect("policy set"),
        )
        .await
        .expect("agent");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 500,
    };
    let first = daemon
        .evaluate_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("explicit policy set should evaluate the attached policy");
    assert_eq!(first.evaluated_policy_ids, vec![permissive.id]);

    let mut strict = policy_all_per_tx(100);
    strict.priority = 0;
    daemon
        .add_policy(&session, strict)
        .await
        .expect("add later strict policy");

    let stored_attachment = daemon
        .agent_keys
        .read()
        .expect("agent keys")
        .get(&agent_credentials.agent_key.id)
        .map(|agent| agent.policies.clone())
        .expect("stored agent");
    assert_eq!(
        stored_attachment,
        PolicyAttachment::PolicySet(attached_policy_ids)
    );

    let second = daemon
        .evaluate_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect("later policies must not retroactively attach");
    assert_eq!(second.evaluated_policy_ids, vec![permissive.id]);
}
