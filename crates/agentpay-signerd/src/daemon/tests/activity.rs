//! `AgentActivity`: an agent sees only its own spends and approval requests,
//! newest first, with the approval that let a payment through; and the
//! documented example is what the daemon returns (ids and times aside).

use std::path::PathBuf;

use agentpay_api::rpc::{AgentActivityParams, AgentActivityReport, WalletBootstrapMode};
use agentpay_api::{AgentAuth, DaemonRpcRequest, DaemonRpcResponse};
use agentpay_domain::{
    AdminAuth, AgentCredentials, ManualApprovalDecision, ManualApprovalStatus, PolicyAttachment,
};
use agentpay_signer::SoftwareSignerBackend;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use super::wallet_bootstrap::{bootstrap, sign, transfer, usd1_limit};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

type Daemon = InMemoryDaemon<SoftwareSignerBackend>;

const ROOT: AdminAuth = AdminAuth::PeerCredentials;
const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
/// One USD1 in base units.
const ONE: u128 = 1_000_000_000_000_000_000;

fn auth(credentials: &AgentCredentials) -> AgentAuth {
    AgentAuth {
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
    }
}

fn activity(
    daemon: &Daemon,
    credentials: &AgentCredentials,
    since: Option<OffsetDateTime>,
    limit: Option<u16>,
) -> AgentActivityReport {
    daemon
        .agent_activity_impl(&auth(credentials), since, limit)
        .expect("activity")
}

/// Signs `amount` USD1, approving it first when it waits for approval;
/// returns the approval request id, if one was needed.
async fn pay(daemon: &Daemon, agent: &AgentCredentials, amount: u128) -> Option<Uuid> {
    match sign(daemon, agent, transfer(USD1, 56, amount)).await {
        Ok(_) => None,
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
        }) => {
            daemon
                .decide_manual_approval_request(
                    &ROOT,
                    approval_request_id,
                    ManualApprovalDecision::Approve,
                    None,
                )
                .await
                .expect("approve");
            sign(daemon, agent, transfer(USD1, 56, amount))
                .await
                .expect("approved payment");
            Some(approval_request_id)
        }
        Err(other) => panic!("unexpected {other:?}"),
    }
}

/// A wallet whose agent pays up to 100 USD1 on its own.
async fn wallet() -> (Daemon, AgentCredentials, Vec<Uuid>) {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let boot = bootstrap(
        &daemon,
        WalletBootstrapMode::Create {
            replace_existing: false,
            name: None,
        },
        vec![usd1_limit(100 * ONE)],
    )
    .await
    .expect("bootstrap");
    let policy_ids = boot.spending_limits.limits[0].policy_ids.clone();
    (daemon, boot.agent_credentials, policy_ids)
}

#[tokio::test]
async fn an_agent_sees_only_its_own_activity_newest_first() {
    let (daemon, alice, policy_ids) = wallet().await;
    // A second agent on the same wallet, under the same limits.
    let bob = daemon
        .create_agent_key(
            &ROOT,
            alice.agent_key.vault_key_id,
            PolicyAttachment::policy_set(policy_ids.into_iter().collect()).expect("set"),
        )
        .await
        .expect("bob");

    assert_eq!(pay(&daemon, &alice, 40 * ONE).await, None);
    let first_spend_done = OffsetDateTime::now_utc();
    let approval = pay(&daemon, &alice, 150 * ONE).await.expect("approved");
    let pending = match sign(&daemon, &alice, transfer(USD1, 56, 160 * ONE)).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
        }) => approval_request_id,
        other => panic!("expected a pending request, got {other:?}"),
    };
    assert_eq!(pay(&daemon, &bob, 5 * ONE).await, None);
    assert!(sign(&daemon, &bob, transfer(USD1, 56, 170 * ONE))
        .await
        .is_err());

    let report = activity(&daemon, &alice, None, None);
    assert_eq!(report.agent_key_id, alice.agent_key.id);
    let spends: Vec<(u128, Option<Uuid>)> = report
        .spends
        .iter()
        .map(|spend| (spend.amount_wei, spend.approval_request_id))
        .collect();
    assert_eq!(spends, [(150 * ONE, Some(approval)), (40 * ONE, None)]);
    let approvals: Vec<(Uuid, ManualApprovalStatus)> = report
        .approvals
        .iter()
        .map(|request| (request.id, request.status))
        .collect();
    assert_eq!(
        approvals,
        [
            (pending, ManualApprovalStatus::Pending),
            (approval, ManualApprovalStatus::Completed)
        ]
    );
    assert!(report
        .approvals
        .iter()
        .all(|request| request.agent_key_id == alice.agent_key.id && !request.reasons.is_empty()));

    let bobs = activity(&daemon, &bob, None, None);
    assert_eq!(bobs.spends.len(), 1);
    assert_eq!(bobs.spends[0].amount_wei, 5 * ONE);
    assert_eq!(bobs.approvals.len(), 1);
    assert!(bobs
        .approvals
        .iter()
        .all(|r| r.agent_key_id == bob.agent_key.id));

    // `since` keeps pending requests; `limit` caps each list.
    let recent = activity(&daemon, &alice, Some(first_spend_done), None);
    assert_eq!(recent.spends.len(), 1);
    assert_eq!(recent.approvals.len(), 2);
    let future = activity(
        &daemon,
        &alice,
        Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
        None,
    );
    assert!(future.spends.is_empty());
    assert_eq!(future.approvals.len(), 1, "pending requests ignore `since`");
    let one = activity(&daemon, &alice, None, Some(1));
    assert_eq!((one.spends.len(), one.approvals.len()), (1, 1));
    assert_eq!(one.approvals[0].id, pending);
    let none = activity(&daemon, &alice, None, Some(0));
    assert!(none.spends.is_empty() && none.approvals.is_empty());

    let forged = AgentAuth {
        agent_key_id: alice.agent_key.id,
        agent_auth_token: "forged".to_string().into(),
    };
    assert!(matches!(
        daemon.agent_activity_impl(&forged, None, None),
        Err(DaemonError::AgentAuthenticationFailed)
    ));
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/rpc")
        .join(format!("{name}.json"))
}

fn fixture(name: &str) -> Value {
    let text = std::fs::read_to_string(fixture_path(name)).expect("fixture");
    serde_json::from_str(&text).expect("fixture JSON")
}

/// Example times: the 40 USD1 payment, the request, its approval and the
/// approved payment, and the report.
fn example_time(hour: u8, minute: u8) -> Value {
    serde_json::json!([2026, 309, hour, minute, 0, 0, 0, 0, 0])
}

/// The `AgentActivity` example in `crates/agentpay-api/fixtures/rpc/` (and so
/// in `docs/daemon-api.md`) is a real report: a 40 USD1 payment within the
/// limits and a 150 USD1 payment approved beyond the 100 USD1 per-payment
/// limit. Random ids are replaced with the documented ones, and times with
/// fixed ones.
///
/// Run with `AGENTPAY_UPDATE_EXAMPLES=1` to rewrite the response example.
#[tokio::test]
async fn the_agent_activity_example_is_a_real_report() {
    let (daemon, agent, policy_ids) = wallet().await;
    pay(&daemon, &agent, 40 * ONE).await;
    let approval = pay(&daemon, &agent, 150 * ONE).await.expect("approved");

    let DaemonRpcRequest::AgentActivity(AgentActivityParams { since, limit, .. }) =
        serde_json::from_value(fixture("AgentActivity.request")).expect("request")
    else {
        panic!("wrong AgentActivity request example");
    };
    let report = activity(&daemon, &agent, since, limit);
    let mut text =
        serde_json::to_string(&DaemonRpcResponse::AgentActivity(report)).expect("encode");
    let per_tx_policy = policy_ids
        .iter()
        .find(|id| text.contains(&id.to_string()))
        .copied()
        .expect("the per-payment policy appears in the reasons");
    for (random, documented) in [
        (agent.agent_key.id, "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"),
        (
            agent.agent_key.vault_key_id,
            "5e0b7c1a-2d3f-4a5b-9c6d-7e8f9a0b1c2d",
        ),
        (approval, "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090"),
        (per_tx_policy, "b1c2d3e4-0000-4000-8000-000000000001"),
    ] {
        text = text.replace(&random.to_string(), documented);
    }
    let mut actual: Value = serde_json::from_str(&text).expect("json");
    let data = &mut actual["data"];
    data["as_of"] = example_time(13, 0);
    data["spends"][0]["at"] = example_time(12, 5);
    data["spends"][1]["at"] = example_time(12, 0);
    data["approvals"][0]["created_at"] = example_time(12, 1);
    data["approvals"][0]["updated_at"] = example_time(12, 5);
    data["approvals"][0]["completed_at"] = example_time(12, 5);

    if std::env::var_os("AGENTPAY_UPDATE_EXAMPLES").is_some() {
        // Through the wire type, so the file keeps the field order.
        let typed: DaemonRpcResponse = serde_json::from_value(actual).expect("decode");
        let pretty = serde_json::to_string_pretty(&typed).expect("encode") + "\n";
        std::fs::write(fixture_path("AgentActivity.response"), pretty).expect("write");
        return;
    }
    assert_eq!(actual, fixture("AgentActivity.response"));
}
