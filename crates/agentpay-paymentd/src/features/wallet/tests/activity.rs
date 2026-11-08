//! `Activity`: the agent's payments and approval requests from the signer
//! daemon, labelled from the configuration; and the documented example is
//! what paymentd returns (ids and times aside).

use std::time::Duration;

use agentpay_api::payments::{ActivityAsset, ActivityParams, PaymentsConfig};
use agentpay_domain::{AgentAction, AssetId, ManualApprovalDecision, OverLimit};
use serde_json::Value;
use uuid::Uuid;

use super::examples::{fixture, fixture_path, EXAMPLE_VAULT_KEY_ID};
use super::*;
use crate::features::activity::labels;
use crate::signer::ApprovalWait;

/// One USD1 in base units.
const ONE: u128 = 1_000_000_000_000_000_000;
const RECIPIENT: &str = "0x5aeda56215b167893e80b4fe645ba6d5bab767de";
const EXAMPLE_APPROVAL_ID: &str = "e7d6c5b4-a392-4817-b6f5-e4d3c2b1a090";

/// A harness whose agent pays up to 100 USD1 on BSC on its own and asks
/// beyond that (the `AddPolicy` example policy).
async fn harness() -> Harness {
    let policy = super::examples::example_policy()
        .with_over_limit(OverLimit::ManualApproval)
        .expect("per-transaction limit");
    Harness::new(vec![policy]).await
}

/// Pays `amount` USD1 on BSC, approving it as the operator when it waits;
/// returns the approval request id, if one was needed.
async fn pay(h: &Harness, amount: u128) -> Option<Uuid> {
    let agent = h.agent().await;
    let signer = agent.signer(h.state.signer.as_ref());
    let action = AgentAction::Transfer {
        chain_id: 56,
        token: USD1.parse().expect("token"),
        to: RECIPIENT.parse().expect("recipient"),
        amount_wei: amount,
    };
    let no_wait = ApprovalWait {
        max_wait: Duration::ZERO,
        initial_interval: Duration::from_millis(1),
        max_interval: Duration::from_millis(1),
    };
    match signer.sign(action.clone(), no_wait).await {
        Ok(_) => None,
        Err(PaymentsError::ManualApprovalPending {
            approval_request_id,
        }) => {
            h.signer
                .daemon
                .decide_manual_approval_request(
                    &AdminAuth::PeerCredentials,
                    approval_request_id,
                    ManualApprovalDecision::Approve,
                    None,
                )
                .await
                .expect("approve");
            signer
                .sign(action, no_wait)
                .await
                .expect("approved payment");
            Some(approval_request_id)
        }
        Err(other) => panic!("unexpected {other:?}"),
    }
}

fn activity_request(h: &Harness, limit: Option<u16>) -> Req {
    Req::Activity(ActivityParams {
        auth: h.auth.clone(),
        since: None,
        limit,
    })
}

#[tokio::test]
async fn payments_and_approvals_carry_their_configured_labels() {
    let h = harness().await;
    assert_eq!(pay(&h, 40 * ONE).await, None);
    let approval = pay(&h, 150 * ONE).await.expect("approved");
    let Res::Activity(activity) = h.call(activity_request(&h, None)).await.expect("activity")
    else {
        panic!("Activity must answer Activity");
    };
    assert_eq!(activity.agent_key_id, h.auth.agent_key_id);
    let usd1 = |amount: &str| ActivityAsset {
        network: Some("bsc".into()),
        symbol: Some("USD1".into()),
        decimals: Some(18),
        amount: Some(amount.into()),
    };
    let spends: Vec<(&ActivityAsset, Option<Uuid>)> = activity
        .spends
        .iter()
        .map(|spend| (&spend.labels, spend.spend.approval_request_id))
        .collect();
    assert_eq!(
        spends,
        [(&usd1("150"), Some(approval)), (&usd1("40"), None)]
    );
    assert_eq!(activity.approvals.len(), 1);
    assert_eq!(activity.approvals[0].request.id, approval);
    assert_eq!(activity.approvals[0].labels, usd1("150"));

    let Res::Activity(one) = h
        .call(activity_request(&h, Some(1)))
        .await
        .expect("activity")
    else {
        panic!("Activity must answer Activity");
    };
    assert_eq!((one.spends.len(), one.approvals.len()), (1, 1));
}

#[tokio::test]
async fn activity_needs_valid_credentials() {
    let h = harness().await;
    let forged = Req::Activity(ActivityParams {
        auth: agentpay_api::AgentAuth {
            agent_key_id: h.auth.agent_key_id,
            agent_auth_token: "forged".to_string().into(),
        },
        since: None,
        limit: None,
    });
    assert_eq!(
        h.call(forged).await.expect_err("forged"),
        PaymentsError::AgentAuthenticationFailed
    );
}

#[test]
fn labels_come_from_the_configured_asset_on_the_matching_network() {
    let config: PaymentsConfig = example_config("http://127.0.0.1:1");
    let usd1: AssetId = AssetId::Erc20(USD1.parse().expect("token"));
    assert_eq!(
        labels(&config, 56, &usd1, 1_500_000_000_000_000_000)
            .amount
            .as_deref(),
        Some("1.5")
    );
    // Native BNB on BSC.
    let bnb = labels(&config, 56, &AssetId::NativeEth, ONE);
    assert_eq!(
        (bnb.symbol.as_deref(), bnb.decimals),
        (Some("BNB"), Some(18))
    );
    // Solana spends use the shared policy id; the cluster that has the mint wins.
    let usdc = labels(
        &config,
        900_000_001,
        &AssetId::SplToken(DEVNET_USDC.parse().expect("mint")),
        12_500_000,
    );
    assert_eq!(
        (
            usdc.network.as_deref(),
            usdc.symbol.as_deref(),
            usdc.amount.as_deref()
        ),
        (Some("solana-devnet"), Some("USDC"), Some("12.5"))
    );
    // An unconfigured token on a configured chain: network only.
    let other = labels(
        &config,
        56,
        &AssetId::Erc20(
            "0x55d398326f99059ff775485246999027b3197955"
                .parse()
                .expect("t"),
        ),
        7,
    );
    assert_eq!(
        other,
        ActivityAsset {
            network: Some("bsc".into()),
            ..ActivityAsset::default()
        }
    );
    // An unconfigured chain: nothing.
    assert_eq!(labels(&config, 137, &usd1, 7), ActivityAsset::default());
}

fn example_time(hour: u8, minute: u8) -> Value {
    serde_json::json!([2026, 309, hour, minute, 0, 0, 0, 0, 0])
}

/// The `Activity` example in
/// `crates/agentpay-api/fixtures/payments/wallet/` (and so in
/// `docs/daemon-api.md`) is real: a 40 USD1 payment within the limit and a
/// 150 USD1 payment approved beyond it. Random ids are replaced with the
/// documented ones, and times with fixed ones.
///
/// Run with `AGENTPAY_UPDATE_EXAMPLES=1` to rewrite the response example.
#[tokio::test]
async fn the_activity_example_is_real() {
    let h = harness().await;
    pay(&h, 40 * ONE).await;
    let approval = pay(&h, 150 * ONE).await.expect("approved");
    let mut request = fixture("wallet", "Activity.request");
    request["params"]["auth"] = serde_json::to_value(&h.auth).expect("auth");
    let request: Req = serde_json::from_value(request).expect("example request");
    let response = h.call(request).await.expect("activity");
    let vault_key_id = h.agent().await.identity.vault_key.id;
    let mut text = serde_json::to_string(&response).expect("encode");
    for (random, documented) in [
        (h.auth.agent_key_id, "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"),
        (vault_key_id, EXAMPLE_VAULT_KEY_ID),
        (approval, EXAMPLE_APPROVAL_ID),
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
        let typed: Res = serde_json::from_value(actual).expect("decode");
        let pretty = serde_json::to_string_pretty(&typed).expect("encode") + "\n";
        std::fs::write(fixture_path("wallet", "Activity.response"), pretty).expect("write");
        return;
    }
    assert_eq!(actual, fixture("wallet", "Activity.response"));
}
