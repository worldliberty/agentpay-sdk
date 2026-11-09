//! `Status`.

use agentpay_api::payments::{StatusParams, StatusResult, StatusWarningCode};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, WirePaymentsError, API_VERSION};
use async_trait::async_trait;

use super::*;
use crate::signer::testing::per_tx_limit;
use crate::signer::SignerError;

async fn fetch_status(h: &Harness) -> StatusResult {
    let request = Req::Status(StatusParams {
        auth: h.auth.clone(),
    });
    match h.call_with(request, FAST).await.expect("status") {
        Res::Status(status) => status,
        other => panic!("Status must answer Status, got {other:?}"),
    }
}

fn codes(status: &StatusResult) -> Vec<StatusWarningCode> {
    status.warnings.iter().map(|warning| warning.code).collect()
}

#[tokio::test]
async fn an_agent_without_limits_is_told_it_cannot_spend() {
    let h = Harness::new(Vec::new()).await;
    let status = fetch_status(&h).await;
    assert_eq!(status.service.api_version, API_VERSION);
    assert!(status.signer.reachable && status.signer.compatible);
    assert_eq!(status.signer.api_version.as_deref(), Some(API_VERSION));
    assert_eq!(status.agent.agent_key_id, h.auth.agent_key_id);
    assert_eq!(
        status.agent.evm_address.as_ref().map(|a| a.as_str()),
        Some(EVM_WALLET)
    );
    assert!(status.config.valid && status.config.error.is_none());
    assert_eq!(
        (status.config.chain_count, status.config.token_count),
        (3, 5)
    );

    let summary = status.policies.as_ref().expect("policy summary");
    assert_eq!(summary.spending_policy_count, 0);
    assert!(!status.can_spend);
    assert!(!status.telemetry_enabled, "tests never send telemetry");
    assert_eq!(
        codes(&status),
        [
            StatusWarningCode::NoSpendingPolicy,
            StatusWarningCode::ChainUnreachable
        ]
    );
    let no_policy = &status.warnings[0];
    assert!(no_policy
        .message
        .contains("agent cannot spend until limits are set"));
    assert_eq!(status.warnings[1].network.as_deref(), Some("eth"));
}

#[tokio::test]
async fn chains_are_checked_and_failures_never_leak_the_url() {
    let h = Harness::new(vec![per_tx_limit(1_000)]).await;
    let status = fetch_status(&h).await;
    assert!(status.can_spend);
    let networks: Vec<&str> = status.chains.iter().map(|c| c.network.as_str()).collect();
    assert_eq!(networks, ["bsc", "eth", "solana-devnet"]);
    let bsc = &status.chains[0];
    assert_eq!(
        (bsc.reachable, bsc.block_number),
        (Some(true), Some(45_000_123))
    );
    let eth = &status.chains[1];
    assert_eq!(eth.reachable, Some(false));
    let Some(WirePaymentsError::ChainRpc(reason)) = &eth.error else {
        panic!("expected ChainRpc, got {:?}", eth.error);
    };
    assert!(!reason.contains("127.0.0.1"), "{reason}");
    let devnet = &status.chains[2];
    assert_eq!((devnet.reachable, devnet.block_number), (Some(true), None));
    assert_eq!(codes(&status), [StatusWarningCode::ChainUnreachable]);

    // A chain without an RPC URL is listed but not checked; as the default
    // network it is a warning of its own.
    h.edit_config(|config| {
        config.chains.get_mut("bsc").expect("bsc").rpc_url = None;
    })
    .await;
    let status = fetch_status(&h).await;
    assert_eq!(status.chains[0].reachable, None);
    assert!(!status.chains[0].rpc_configured);
    assert!(codes(&status).contains(&StatusWarningCode::DefaultNetworkUnconfigured));
}

/// Answers everything through the in-process signer except `Hello` and
/// `AgentPolicySummary`, which fail as if signerd were an older release.
struct OldSigner(Arc<InProcessSigner>);

#[async_trait]
impl SignerClient for OldSigner {
    async fn call(&self, request: DaemonRpcRequest) -> Result<DaemonRpcResponse, SignerError> {
        match request {
            DaemonRpcRequest::Hello => {
                let mut hello = agentpay_api::HelloResponse::for_daemon("0.1.0");
                hello.api_version = "2.0.0".into();
                Ok(DaemonRpcResponse::Hello(hello))
            }
            DaemonRpcRequest::AgentPolicySummary(_) => {
                Err(SignerError::Unavailable("connection closed".into()))
            }
            other => self.0.call(other).await,
        }
    }
}

#[tokio::test]
async fn an_incompatible_signer_and_missing_policy_status_are_warnings() {
    let reference = Harness::new(Vec::new()).await;
    let signer = reference.signer.clone();
    let h = Harness::with_signer(
        signer.clone(),
        Arc::new(OldSigner(signer)),
        reference.auth.clone(),
    )
    .await;
    let status = fetch_status(&h).await;
    assert!(status.signer.reachable && !status.signer.compatible);
    assert_eq!(status.signer.api_version.as_deref(), Some("2.0.0"));
    assert!(status.policies.is_none() && !status.can_spend);
    assert_eq!(
        codes(&status)[..2],
        [
            StatusWarningCode::SignerIncompatible,
            StatusWarningCode::PolicyStatusUnavailable
        ]
    );
}

#[tokio::test]
async fn a_chain_answered_by_a_backup_says_so_without_naming_it() {
    let h = Harness::new(Vec::new()).await;
    let backup = h.bsc.url().to_string();
    h.edit_config(|config| {
        let eth = config.chains.get_mut("eth").expect("eth");
        eth.chain_id = 56;
        eth.fallback_rpc_urls = vec![backup.clone()];
        let usd1 = config.tokens.get_mut("usd1").expect("usd1");
        usd1.chains.get_mut("eth").expect("usd1 on eth").chain_id = 56;
        config
            .tokens
            .get_mut("eth")
            .and_then(|eth| eth.chains.get_mut("eth"))
            .expect("eth on eth")
            .chain_id = 56;
    })
    .await;
    let status = fetch_status(&h).await;
    let eth = status
        .chains
        .iter()
        .find(|chain| chain.network == "eth")
        .expect("eth");
    assert_eq!(eth.reachable, Some(true));
    assert!(eth.using_backup_rpc);
    assert!(eth.error.is_none());
    let bsc = &status.chains[0];
    assert!(bsc.reachable == Some(true) && !bsc.using_backup_rpc);
    let rendered = serde_json::to_string(&status).expect("encode");
    assert!(
        !rendered.contains(&backup),
        "Status must not report RPC URLs"
    );
}
