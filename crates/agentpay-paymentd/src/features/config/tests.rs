//! `AddToken` through [`dispatch`], with the loopback mock EVM endpoint (as
//! `bsc`) and a [`FakeCluster`] (as `solana-devnet`).

use std::path::Path;
use std::sync::Arc;

use agentpay_api::payments::{
    AddTokenParams, AddTokenResult, PaymentsConfig, PaymentsRpcRequest as Req,
    PaymentsRpcResponse as Res, TokenChainProfile,
};
use agentpay_api::AgentAuth;
use serde_json::Value;
use solana_sdk::pubkey::Pubkey;

use crate::chains::evm::mock_rpc::MockRpc;
use crate::chains::solana::testing::FakeCluster;
use crate::config::{default_config, ConfigStore};
use crate::dispatch::dispatch;
use crate::error::PaymentsError;
use crate::signer::testing::InProcessSigner;
use crate::state::AppState;
use crate::test_support::TempDir;

/// An ERC-20 contract that is not configured.
pub(super) const TOKEN: &str = "0x3333333333333333333333333333333333333333";
/// USD1 on BSC in the built-in configuration.
const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
/// The RPC URL the examples show for BSC.
pub(super) const EXAMPLE_RPC_URL: &str = "https://bsc-rpc.publicnode.com";

pub(super) struct Harness {
    dir: TempDir,
    pub(super) state: AppState,
    auth: AgentAuth,
    pub(super) mock: MockRpc,
    pub(super) cluster: FakeCluster,
}

impl Harness {
    /// The built-in configuration with `bsc` on the mock endpoint, whose
    /// token (`TKN`, 6 decimals) has contract code.
    pub(super) async fn new() -> Self {
        let mut config = default_config();
        Self::with_config(|url| {
            let bsc = config.chains.get_mut("bsc").expect("bsc");
            bsc.rpc_url = Some(url.to_string());
            bsc.fallback_rpc_urls.clear();
            config
        })
        .await
    }

    pub(super) async fn with_config(config: impl FnOnce(&str) -> PaymentsConfig) -> Self {
        let dir = TempDir::new("addtoken");
        let (signer, auth) = InProcessSigner::with_agent(Vec::new()).await;
        let mock = MockRpc::start(56).await;
        mock.chain().code = vec![0x60, 0x80];
        let mut state = AppState::new(
            ConfigStore::open(dir.path()).expect("config"),
            Arc::new(signer),
        );
        let cluster = FakeCluster::devnet();
        state.chains.register(Arc::new(cluster.provider()));
        state
            .config
            .set(config(mock.url()))
            .await
            .expect("set config");
        Self {
            dir,
            state,
            auth,
            mock,
            cluster,
        }
    }

    async fn add(
        &self,
        network: &str,
        address: &str,
        symbol: Option<&str>,
        decimals: Option<u8>,
    ) -> Result<AddTokenResult, PaymentsError> {
        let request = Req::AddToken(AddTokenParams {
            auth: self.auth.clone(),
            network: network.into(),
            address: address.into(),
            symbol: symbol.map(str::to_string),
            decimals,
        });
        match dispatch(&self.state, request).await? {
            Res::TokenAdded(result) => Ok(result),
            other => panic!("expected TokenAdded, got {other:?}"),
        }
    }

    /// Fails unless the call fails with `InvalidRequest` and changes nothing.
    async fn refused(&self, result: Result<AddTokenResult, PaymentsError>) -> String {
        let before = self.state.config.get().await;
        let Err(PaymentsError::InvalidRequest(reason)) = result else {
            panic!("expected InvalidRequest, got {result:?}");
        };
        assert_eq!(self.state.config.get().await, before);
        reason
    }
}

fn deployment(chain_id: u64, address: &str, decimals: u8) -> TokenChainProfile {
    TokenChainProfile {
        chain_id,
        is_native: false,
        address: Some(address.into()),
        decimals,
    }
}

#[tokio::test]
async fn evm_token_metadata_is_read_from_the_chain_and_stored() {
    let h = Harness::new().await;
    let upper = "0xABCDEF0000000000000000000000000000000001";
    let lower = upper.to_ascii_lowercase();
    let added = h.add(" BSC ", upper, None, None).await.expect("added");
    assert_eq!(added.key, "tkn");
    assert_eq!(added.network, "bsc");
    assert_eq!(added.deployment, deployment(56, &lower, 6));
    assert!(added.verified_on_chain && added.added);
    assert_eq!(
        (added.token.name.as_str(), added.token.symbol.as_str()),
        ("TKN", "TKN")
    );
    assert_eq!(added.token.recommended_limits, None);
    assert_eq!(added.config.tokens["tkn"], added.token);
    assert_eq!(added.config, h.state.config.get().await);
    let reopened = ConfigStore::open(h.dir.path()).expect("reopen");
    assert_eq!(reopened.get().await, added.config, "persisted");
    let calls = h.mock.calls();
    for method in ["eth_chainId", "eth_getCode", "eth_call"] {
        assert!(
            calls.iter().any(|call| call == method),
            "{method} in {calls:?}"
        );
    }
}

#[tokio::test]
async fn a_requested_symbol_overrides_the_chain_and_matching_decimals_pass() {
    let h = Harness::new().await;
    let added = h
        .add("bsc", TOKEN, Some(" My Token "), Some(6))
        .await
        .expect("added");
    assert_eq!(added.key, "my-token");
    assert_eq!(added.token.symbol, "My Token");
    assert!(added.verified_on_chain);
}

#[tokio::test]
async fn a_known_symbol_gains_a_deployment_on_a_new_network() {
    let h = Harness::new().await;
    // USDC has no BSC deployment in this configuration.
    let mut config = h.state.config.get().await;
    config
        .tokens
        .get_mut("usdc")
        .expect("usdc")
        .chains
        .remove("bsc");
    h.state.config.set(config).await.expect("set config");
    let before = h.state.config.get().await.tokens["usdc"].clone();
    let added = h
        .add("bsc", TOKEN, Some("USDC"), None)
        .await
        .expect("added");
    assert_eq!(added.key, "usdc");
    assert_eq!(added.token.chains["bsc"], deployment(56, TOKEN, 6));
    assert_eq!(added.token.chains.len(), before.chains.len() + 1);
    assert_eq!(added.token.recommended_limits, before.recommended_limits);
    assert_eq!(added.token.name, before.name);
}

#[tokio::test]
async fn adding_a_configured_deployment_changes_nothing() {
    let h = Harness::new().await;
    let before = h.state.config.get().await;
    let found = h
        .add(
            "bsc",
            &USD1.to_ascii_uppercase().replace("0X", "0x"),
            None,
            Some(6),
        )
        .await
        .expect("found");
    assert_eq!(found.key, "usd1");
    assert!(!found.added && !found.verified_on_chain);
    assert_eq!(found.deployment, deployment(56, USD1, 18));
    assert_eq!(found.config, before);
    assert!(h.mock.calls().is_empty(), "no chain I/O");

    let first = h.add("bsc", TOKEN, None, None).await.expect("first");
    let again = h
        .add("bsc", TOKEN, Some("OTHER"), None)
        .await
        .expect("again");
    assert!(first.added && !again.added);
    assert_eq!((again.key, again.config), (first.key, first.config));
}

#[tokio::test]
async fn a_taken_key_gets_an_address_suffix() {
    let h = Harness::new().await;
    let added = h
        .add("bsc", TOKEN, Some("USD1"), None)
        .await
        .expect("added");
    assert_eq!(added.key, "usd1-333333");
    assert_eq!(added.token.symbol, "USD1");
    assert_eq!(
        added.config.tokens["usd1"].chains["bsc"],
        deployment(56, USD1, 18)
    );

    let reason = h
        .refused(
            h.add(
                "bsc",
                "0x3333334444444444444444444444444444444444",
                Some("USD1"),
                None,
            )
            .await,
        )
        .await;
    assert!(reason.contains("rename one"), "{reason}");
}

#[tokio::test]
async fn an_unreadable_chain_needs_decimals_and_a_symbol() {
    let h = Harness::new().await;
    h.mock.chain().chain_id = 1;
    let err = h
        .add("bsc", TOKEN, None, None)
        .await
        .expect_err("no decimals");
    let PaymentsError::ChainRpc(reason) = err else {
        panic!("expected ChainRpc, got {err:?}");
    };
    assert!(
        reason.contains("agentpay config set chains.bsc.rpc_url <url>")
            && reason.contains("pass decimals"),
        "{reason}"
    );
    assert!(!reason.contains("127.0.0.1"), "the URL must not leak");

    let reason = h.refused(h.add("bsc", TOKEN, None, Some(8)).await).await;
    assert!(reason.contains("pass a symbol"), "{reason}");

    let added = h
        .add("bsc", TOKEN, Some("TKN"), Some(8))
        .await
        .expect("manual");
    assert_eq!(added.deployment, deployment(56, TOKEN, 8));
    assert!(added.added && !added.verified_on_chain);
}

#[tokio::test]
async fn a_chain_without_an_rpc_url_takes_manual_decimals() {
    let h = Harness::with_config(|_| {
        let mut config = default_config();
        let bsc = config.chains.get_mut("bsc").expect("bsc");
        bsc.rpc_url = None;
        bsc.fallback_rpc_urls.clear();
        config
    })
    .await;
    let err = h
        .add("bsc", TOKEN, Some("TKN"), None)
        .await
        .expect_err("no url");
    let PaymentsError::ChainRpc(reason) = err else {
        panic!("expected ChainRpc, got {err:?}");
    };
    assert!(reason.contains("no rpc_url configured"), "{reason}");
    let added = h
        .add("bsc", TOKEN, Some("TKN"), Some(9))
        .await
        .expect("manual");
    assert!(!added.verified_on_chain);
    assert_eq!(added.deployment.decimals, 9);
}

#[tokio::test]
async fn decimals_that_differ_from_the_chain_are_refused() {
    let h = Harness::new().await;
    let reason = h.refused(h.add("bsc", TOKEN, None, Some(18)).await).await;
    assert!(reason.contains("differ from the 6"), "{reason}");
}

#[tokio::test]
async fn an_address_without_code_or_symbol_is_refused() {
    let h = Harness::new().await;
    h.mock.chain().code = Vec::new();
    let reason = h
        .refused(h.add("bsc", TOKEN, Some("TKN"), Some(6)).await)
        .await;
    assert!(reason.contains("no contract"), "{reason}");

    h.mock.chain().code = vec![0x60];
    h.mock.chain().token_symbol = String::new();
    let reason = h.refused(h.add("bsc", TOKEN, None, None).await).await;
    assert!(reason.contains("pass a symbol"), "{reason}");
}

#[tokio::test]
async fn invalid_requests_fail_before_any_chain_io() {
    let h = Harness::new().await;
    let mint = h
        .cluster
        .add_mint(spl_token::ID, 6, None, false)
        .to_string();
    let long = "X".repeat(33);
    let cases: Vec<(&str, &str, Option<&str>, Option<u8>)> = vec![
        ("nope", TOKEN, Some("TKN"), None),
        ("bsc", "0x1234", Some("TKN"), None),
        (
            "bsc",
            "0x0000000000000000000000000000000000000000",
            None,
            None,
        ),
        (
            "bsc",
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            None,
            None,
        ),
        ("bsc", &mint, Some("TKN"), None),
        ("bsc", TOKEN, Some(long.as_str()), None),
        ("bsc", TOKEN, Some("TKN"), Some(37)),
        ("solana-devnet", TOKEN, Some("TKN"), None),
        (
            "solana-devnet",
            "11111111111111111111111111111111",
            Some("SOL"),
            None,
        ),
        ("solana-devnet", &mint, None, Some(6)),
    ];
    for (network, address, symbol, decimals) in cases {
        let reason = h
            .refused(h.add(network, address, symbol, decimals).await)
            .await;
        assert!(!reason.is_empty(), "{network} {address}");
    }
    assert!(h.mock.calls().is_empty());
    assert_eq!(h.cluster.calls("getAccountInfo"), 0);
    let reason = h
        .refused(h.add("solana-devnet", &mint, None, None).await)
        .await;
    assert!(reason.contains("symbol is required for Solana"), "{reason}");
}

#[tokio::test]
async fn solana_mint_decimals_come_from_the_chain() {
    let h = Harness::new().await;
    let mint = h
        .cluster
        .add_mint(spl_token::ID, 9, None, false)
        .to_string();
    let added = h
        .add("solana-devnet", &mint, Some("MINT"), None)
        .await
        .expect("added");
    assert_eq!(added.key, "mint");
    assert_eq!(added.deployment, deployment(900_000_002, &mint, 9));
    assert!(added.verified_on_chain && added.added);

    let found = h
        .add("solana-devnet", &mint, Some("OTHER"), Some(6))
        .await
        .expect("already configured");
    assert!(!found.added);
    assert_eq!((found.key.as_str(), found.deployment.decimals), ("mint", 9));

    let missing = Pubkey::new_unique().to_string();
    let reason = h
        .refused(
            h.add("solana-devnet", &missing, Some("GONE"), Some(6))
                .await,
        )
        .await;
    assert!(reason.contains("does not exist"), "{reason}");
}

#[tokio::test]
async fn an_unreadable_solana_cluster_takes_manual_decimals() {
    let h = Harness::new().await;
    let mint = h
        .cluster
        .add_mint(spl_token::ID, 6, None, false)
        .to_string();
    h.cluster.with(|s| s.failing.push("getAccountInfo".into()));
    let err = h
        .add("solana-devnet", &mint, Some("MINT"), None)
        .await
        .expect_err("unreadable");
    let PaymentsError::ChainRpc(reason) = err else {
        panic!("expected ChainRpc, got {err:?}");
    };
    assert!(reason.contains("chains.solana-devnet.rpc_url"), "{reason}");
    let added = h
        .add("solana-devnet", &mint, Some("MINT"), Some(6))
        .await
        .expect("manual");
    assert!(added.added && !added.verified_on_chain);
}

pub(super) fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/payments")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(path).expect("fixture");
    serde_json::from_str(&text).expect("fixture JSON")
}

/// The `AddToken` example in `crates/agentpay-api/fixtures/payments/` (and
/// so in `docs/daemon-api.md`) is real: starting from the `SetConfig`
/// example configuration, the example request against a chain whose token
/// reports `USDC` with 18 decimals gives the example response.
#[tokio::test]
async fn the_add_token_example_is_real() {
    let h = Harness::with_config(|url| {
        let mut config: PaymentsConfig =
            serde_json::from_value(fixture("SetConfig.request")["params"]["config"].clone())
                .expect("SetConfig example config");
        config.chains.get_mut("bsc").expect("bsc").rpc_url = Some(url.to_string());
        config
    })
    .await;
    {
        let mut chain = h.mock.chain();
        chain.token_symbol = "USDC".into();
        chain.token_decimals = 18;
    }
    let mut request = fixture("AddToken.request");
    request["params"]["auth"] = serde_json::to_value(&h.auth).expect("auth");
    let request: Req = serde_json::from_value(request).expect("example request");
    let response = dispatch(&h.state, request).await.expect("added");
    let text = serde_json::to_string(&response)
        .expect("encode")
        .replace(h.mock.url(), EXAMPLE_RPC_URL);
    let actual: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(actual, fixture("AddToken.response"));
}
