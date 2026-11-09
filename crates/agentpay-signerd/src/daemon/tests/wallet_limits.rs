//! `ListSpendingLimits` / `SetSpendingLimits`: atomic replacement, deny by
//! default, which old policies are disabled, and usage.

use std::collections::BTreeSet;

use agentpay_api::rpc::{SpendingLimit, WalletBootstrapMode};
use agentpay_api::AgentAuth;
use agentpay_domain::{
    AdminAuth, ApprovalLimit, ApprovalReason, ApprovalType, AssetId, EntityScope,
    ManualApprovalDecision, ManualApprovalRequest, OverLimit, PolicyAttachment, PolicyType,
    SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::policy_all_per_tx;
use super::wallet_bootstrap::{bootstrap, sign, transfer, usd1_limit};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

type Daemon = InMemoryDaemon<SoftwareSignerBackend>;

const ROOT: AdminAuth = AdminAuth::PeerCredentials;
const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
const USDT: &str = "0x55d398326f99059ff775485246999027b3197955";

fn daemon() -> Daemon {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default()).expect("daemon")
}

fn usdt_limit(per_tx: u128) -> SpendingLimit {
    SpendingLimit {
        asset: AssetId::Erc20(USDT.parse().expect("token")),
        max_gas_per_tx_wei: None,
        ..usd1_limit(per_tx)
    }
}

fn enabled(daemon: &Daemon, id: &Uuid) -> bool {
    daemon.policies.read().expect("policies")[id].enabled
}

#[tokio::test]
async fn set_replaces_the_rows_keeps_the_token_and_retires_old_policies() {
    let daemon = daemon();
    let boot = bootstrap(
        &daemon,
        WalletBootstrapMode::Create {
            replace_existing: false,
            name: None,
        },
        vec![usd1_limit(100)],
    )
    .await
    .expect("bootstrap");
    let agent = &boot.agent_credentials;
    let old_ids = boot.spending_limits.limits[0].policy_ids.clone();
    // A generic EIP-712 policy attached to the agent survives the replacement.
    let typed_data = SpendingPolicy::new_eip712_signing(5, ApprovalType::Allow, EntityScope::All)
        .expect("eip712 policy");
    daemon
        .add_policy(&ROOT, typed_data.clone())
        .await
        .expect("add");
    let mut attached: BTreeSet<Uuid> = old_ids.iter().copied().collect();
    attached.insert(typed_data.id);
    // `RefreshAgentKey` rotates the token; keep using the new one.
    let agent = daemon
        .refresh_agent_key(
            &ROOT,
            agent.agent_key.id,
            boot.vault_key.id,
            PolicyAttachment::PolicySet(attached),
        )
        .await
        .expect("refresh");

    let report = daemon
        .set_spending_limits(&ROOT, agent.agent_key.id, vec![usdt_limit(10)])
        .await
        .expect("set");
    assert_eq!(report.limits.len(), 1);
    assert_eq!(report.limits[0].limit, usdt_limit(10));
    assert!(report.other_policy_ids.is_empty());
    for id in &old_ids {
        assert!(!enabled(&daemon, id), "the old row's policies are disabled");
    }
    let stored = daemon.agent_keys.read().expect("agents")[&agent.agent_key.id].clone();
    let PolicyAttachment::PolicySet(now_attached) = stored.policies else {
        panic!("policy set");
    };
    assert!(now_attached.contains(&typed_data.id));
    assert_eq!(now_attached.len(), report.limits[0].policy_ids.len() + 1);

    // Same token; USD1 is no longer spendable, USDT is.
    sign(&daemon, &agent, transfer(USDT, 56, 10))
        .await
        .expect("new row");
    assert!(matches!(
        sign(&daemon, &agent, transfer(USD1, 56, 1)).await,
        Err(DaemonError::Policy(PolicyError::NoApplicablePolicies))
    ));
    let listed = daemon
        .list_spending_limits(&ROOT, agent.agent_key.id)
        .await
        .expect("list");
    assert_eq!(listed.limits[0].usage.spent_24h_wei, 10);
    assert_eq!(listed.limits[0].usage.available_now_wei, 10);
}

#[tokio::test]
async fn policies_another_agent_uses_stay_enabled() {
    let daemon = daemon();
    let key = daemon
        .create_vault_key(&ROOT, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let shared = policy_all_per_tx(1_000);
    daemon.add_policy(&ROOT, shared.clone()).await.expect("add");
    let set = PolicyAttachment::PolicySet(BTreeSet::from([shared.id]));
    let first = daemon
        .create_agent_key(&ROOT, key.id, set.clone())
        .await
        .expect("first");
    let second = daemon
        .create_agent_key(&ROOT, key.id, set.clone())
        .await
        .expect("second");

    let report = daemon
        .set_spending_limits(&ROOT, first.agent_key.id, vec![usd1_limit(100)])
        .await
        .expect("set");
    assert!(
        enabled(&daemon, &shared.id),
        "the second agent still uses it"
    );
    assert_eq!(
        daemon.agent_keys.read().expect("agents")[&second.agent_key.id].policies,
        set
    );
    assert_eq!(report.limits.len(), 1);

    // Before: the broad policy let the first agent spend any token. Now it cannot.
    assert!(matches!(
        sign(&daemon, &first, transfer(USDT, 56, 1)).await,
        Err(DaemonError::Policy(PolicyError::NoApplicablePolicies))
    ));
    sign(&daemon, &second, transfer(USDT, 56, 1))
        .await
        .expect("the second agent is unchanged");
}

#[tokio::test]
async fn an_all_policies_agent_keeps_every_policy_enabled_and_sees_others_as_other() {
    let daemon = daemon();
    let key = daemon
        .create_vault_key(&ROOT, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let broad = policy_all_per_tx(1_000);
    daemon.add_policy(&ROOT, broad.clone()).await.expect("add");
    let target = daemon
        .create_agent_key(&ROOT, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("target");
    let bystander = daemon
        .create_agent_key(&ROOT, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("bystander");

    let before = daemon
        .list_spending_limits(&ROOT, target.agent_key.id)
        .await
        .expect("list");
    assert!(before.limits.is_empty());
    assert_eq!(before.other_policy_ids, vec![broad.id]);

    daemon
        .set_spending_limits(&ROOT, target.agent_key.id, vec![usd1_limit(100)])
        .await
        .expect("set");
    assert!(
        enabled(&daemon, &broad.id),
        "an AllPolicies agent is governed by every enabled policy"
    );
    assert!(matches!(
        daemon.agent_keys.read().expect("agents")[&target.agent_key.id].policies,
        PolicyAttachment::PolicySet(_)
    ));
    let bystander_view = daemon
        .list_spending_limits(&ROOT, bystander.agent_key.id)
        .await
        .expect("list");
    assert_eq!(
        bystander_view.limits.len(),
        1,
        "AllPolicies sees the new row too"
    );
    assert_eq!(bystander_view.other_policy_ids, vec![broad.id]);
}

#[tokio::test]
async fn invalid_limits_and_unknown_agents_change_nothing() {
    let daemon = daemon();
    let boot = bootstrap(
        &daemon,
        WalletBootstrapMode::Create {
            replace_existing: false,
            name: None,
        },
        vec![usd1_limit(100)],
    )
    .await
    .expect("bootstrap");
    let agent_id = boot.agent_credentials.agent_key.id;
    let before = daemon.agent_keys.read().expect("agents")[&agent_id].clone();
    let policy_count = daemon.policies.read().expect("policies").len();

    let mut bad = usdt_limit(10);
    bad.max_fee_per_gas_wei = Some(0);
    assert!(matches!(
        daemon
            .set_spending_limits(&ROOT, agent_id, vec![usd1_limit(5), bad])
            .await,
        Err(DaemonError::InvalidSpendingLimits(_))
    ));
    assert!(matches!(
        daemon
            .set_spending_limits(&ROOT, Uuid::new_v4(), vec![usd1_limit(5)])
            .await,
        Err(DaemonError::UnknownAgentKey(_))
    ));
    assert!(matches!(
        daemon.list_spending_limits(&ROOT, Uuid::new_v4()).await,
        Err(DaemonError::UnknownAgentKey(_))
    ));
    assert_eq!(daemon.agent_keys.read().expect("agents")[&agent_id], before);
    assert_eq!(
        daemon.policies.read().expect("policies").len(),
        policy_count
    );
    let auth = AgentAuth {
        agent_key_id: agent_id,
        agent_auth_token: boot.agent_credentials.auth_token.clone(),
    };
    KeyManagerDaemonApi::authenticate_agent(&daemon, &auth)
        .await
        .expect("token unchanged");
}

/// The pending request `result` asks for, with its stored reasons.
async fn pending_request(
    daemon: &Daemon,
    result: Result<agentpay_domain::Signature, DaemonError>,
) -> ManualApprovalRequest {
    let Err(DaemonError::ManualApprovalRequired {
        approval_request_id,
    }) = result
    else {
        panic!("expected ManualApprovalRequired, got {result:?}");
    };
    daemon
        .list_manual_approval_requests(&ROOT)
        .await
        .expect("list")
        .into_iter()
        .find(|request| request.id == approval_request_id)
        .expect("stored request")
}

fn reason(
    limit: ApprovalLimit,
    policy_id: Uuid,
    max: u128,
    used: Option<u128>,
    requested: u128,
) -> ApprovalReason {
    ApprovalReason {
        limit,
        policy_id: Some(policy_id),
        max: Some(max),
        used,
        requested_amount_wei: Some(requested),
    }
}

#[tokio::test]
async fn payments_beyond_a_rows_limits_wait_for_approval_and_count_once_approved() {
    let daemon = daemon();
    let row = usd1_limit(100);
    let boot = bootstrap(
        &daemon,
        WalletBootstrapMode::Create {
            replace_existing: false,
            name: None,
        },
        vec![row.clone()],
    )
    .await
    .expect("bootstrap");
    assert_eq!(boot.spending_limits.limits[0].limit, row);
    let agent = &boot.agent_credentials;
    let policy_of = |policy_type: PolicyType| {
        let policies = daemon.policies.read().expect("policies");
        let policy = policies
            .values()
            .find(|policy| {
                policy.policy_type == policy_type
                    && boot.spending_limits.limits[0]
                        .policy_ids
                        .contains(&policy.id)
            })
            .expect("row policy")
            .clone();
        policy
    };
    let (per_tx, daily, weekly) = (
        policy_of(PolicyType::PerTxMaxSpending),
        policy_of(PolicyType::DailyMaxSpending),
        policy_of(PolicyType::WeeklyMaxSpending),
    );
    for policy in [&per_tx, &daily, &weekly] {
        assert_eq!(policy.over_limit, OverLimit::ManualApproval);
    }
    assert_eq!(
        policy_of(PolicyType::PerChainMaxGasSpend).over_limit,
        OverLimit::Deny,
        "gas caps stay hard"
    );
    assert!(
        !daemon
            .policies
            .read()
            .expect("policies")
            .values()
            .any(|policy| policy.policy_type == PolicyType::ManualApproval),
        "rows no longer create ManualApproval policies"
    );

    // Within the limits: signed on its own.
    sign(&daemon, agent, transfer(USD1, 56, 100))
        .await
        .expect("within the per-payment limit");

    // Beyond the per-payment limit: one pending request with its reason.
    let request =
        pending_request(&daemon, sign(&daemon, agent, transfer(USD1, 56, 150)).await).await;
    assert_eq!(request.triggered_by_policy_ids, [per_tx.id]);
    assert_eq!(
        request.reasons,
        [reason(ApprovalLimit::PerPayment, per_tx.id, 100, None, 150)]
    );
    daemon
        .decide_manual_approval_request(&ROOT, request.id, ManualApprovalDecision::Approve, None)
        .await
        .expect("approve");
    sign(&daemon, agent, transfer(USD1, 56, 150))
        .await
        .expect("approved payment is signed");
    let report = daemon
        .list_spending_limits(&ROOT, agent.agent_key.id)
        .await
        .expect("limits");
    assert_eq!(
        report.limits[0].usage.spent_24h_wei, 250,
        "approved spend counts"
    );

    // The approval was used up: the same payment asks again.
    let again = pending_request(&daemon, sign(&daemon, agent, transfer(USD1, 56, 150)).await).await;
    assert_ne!(again.id, request.id);

    // Beyond two limits at once: one request listing both.
    let both = pending_request(&daemon, sign(&daemon, agent, transfer(USD1, 56, 300)).await).await;
    let mut expected_ids = vec![per_tx.id, daily.id];
    expected_ids.sort_unstable();
    assert_eq!(both.triggered_by_policy_ids, expected_ids);
    assert_eq!(
        both.reasons,
        [
            reason(ApprovalLimit::PerPayment, per_tx.id, 100, None, 300),
            reason(ApprovalLimit::Daily, daily.id, 500, Some(250), 300),
        ]
    );
    daemon
        .decide_manual_approval_request(
            &ROOT,
            both.id,
            ManualApprovalDecision::Reject,
            Some("too much".into()),
        )
        .await
        .expect("reject");
    assert!(matches!(
        sign(&daemon, agent, transfer(USD1, 56, 300)).await,
        Err(DaemonError::ManualApprovalRejected { approval_request_id }) if approval_request_id == both.id
    ));

    // An asset without a row is still denied outright.
    assert!(matches!(
        sign(&daemon, agent, transfer(USDT, 56, 1)).await,
        Err(DaemonError::Policy(PolicyError::NoApplicablePolicies))
    ));
}
