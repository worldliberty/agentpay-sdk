//! `LookupToken` through [`dispatch`]: no credentials, the same reads and
//! checks as `AddToken`, and never a configuration change.

use agentpay_api::payments::{
    LookupTokenParams, PaymentsConfig, PaymentsRpcRequest as Req, PaymentsRpcResponse as Res,
    TokenInfo,
};
use serde_json::Value;

use super::tests::{fixture, Harness, EXAMPLE_RPC_URL, TOKEN};
use crate::dispatch::dispatch;
use crate::error::PaymentsError;

impl Harness {
    /// Sends `LookupToken` (no credentials) and checks the configuration
    /// did not change.
    async fn lookup(
        &self,
        network: &str,
        address: &str,
        symbol: Option<&str>,
        decimals: Option<u8>,
    ) -> Result<TokenInfo, PaymentsError> {
        let before = self.state.config.get().await;
        let request = Req::LookupToken(LookupTokenParams {
            network: network.into(),
            address: address.into(),
            symbol: symbol.map(str::to_string),
            decimals,
        });
        let result = dispatch(&self.state, request).await;
        assert_eq!(self.state.config.get().await, before, "nothing changes");
        match result? {
            Res::TokenInfo(info) => Ok(info),
            other => panic!("expected TokenInfo, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn an_evm_token_is_read_without_credentials() {
    let h = Harness::new().await;
    let upper = "0xABCDEF0000000000000000000000000000000001";
    let info = h.lookup(" BSC ", upper, None, None).await.expect("info");
    assert_eq!(
        info,
        TokenInfo {
            network: "bsc".into(),
            chain_id: 56,
            address: upper.to_ascii_lowercase(),
            symbol: "TKN".into(),
            decimals: 6,
            verified_on_chain: true,
        }
    );
    let overridden = h
        .lookup("bsc", TOKEN, Some("My Token"), Some(6))
        .await
        .expect("override");
    assert_eq!(overridden.symbol, "My Token");
    // A configured token is still read from the chain.
    let usd1 = h
        .lookup(
            "bsc",
            "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d",
            None,
            None,
        )
        .await
        .expect("configured");
    assert_eq!((usd1.decimals, usd1.verified_on_chain), (6, true));
}

#[tokio::test]
async fn lookups_refuse_what_add_token_refuses() {
    let h = Harness::new().await;
    let mismatch = h.lookup("bsc", TOKEN, None, Some(18)).await;
    assert!(
        matches!(&mismatch, Err(PaymentsError::InvalidRequest(r)) if r.contains("differ from the 6")),
        "{mismatch:?}"
    );
    for (network, address, symbol) in [
        ("nope", TOKEN, None),
        ("bsc", "0x0000000000000000000000000000000000000000", None),
        (
            "solana-devnet",
            "11111111111111111111111111111111",
            Some("SOL"),
        ),
    ] {
        let result = h.lookup(network, address, symbol, None).await;
        assert!(
            matches!(result, Err(PaymentsError::InvalidRequest(_))),
            "{result:?}"
        );
    }
    h.mock.chain().code = Vec::new();
    let no_code = h.lookup("bsc", TOKEN, Some("TKN"), Some(6)).await;
    assert!(
        matches!(&no_code, Err(PaymentsError::InvalidRequest(r)) if r.contains("no contract")),
        "{no_code:?}"
    );
}

#[tokio::test]
async fn an_unreadable_chain_takes_decimals_or_explains_how_to_fix_it() {
    let h = Harness::new().await;
    h.mock.chain().chain_id = 1;
    let error = h
        .lookup("bsc", TOKEN, None, None)
        .await
        .expect_err("unreadable");
    let PaymentsError::ChainRpc(reason) = error else {
        panic!("expected ChainRpc, got {error:?}");
    };
    assert!(
        reason.contains("agentpay config set chains.bsc.rpc_url <url>"),
        "{reason}"
    );
    let manual = h
        .lookup("bsc", TOKEN, Some("TKN"), Some(8))
        .await
        .expect("manual");
    assert_eq!((manual.decimals, manual.verified_on_chain), (8, false));
}

#[tokio::test]
async fn solana_mints_need_a_symbol_and_report_their_decimals() {
    let h = Harness::new().await;
    let mint = h
        .cluster
        .add_mint(spl_token::ID, 9, None, false)
        .to_string();
    let missing = h.lookup("solana-devnet", &mint, None, None).await;
    assert!(
        matches!(&missing, Err(PaymentsError::InvalidRequest(r)) if r.contains("symbol is required")),
        "{missing:?}"
    );
    assert_eq!(h.cluster.calls("getAccountInfo"), 0);
    let info = h
        .lookup("solana-devnet", &mint, Some("MINT"), None)
        .await
        .expect("mint");
    assert_eq!(
        (
            info.chain_id,
            info.address,
            info.decimals,
            info.verified_on_chain
        ),
        (900_000_002, mint, 9, true)
    );
}

/// The `LookupToken` example (and so `docs/daemon-api.md`) is real: with
/// the `SetConfig` example configuration and a chain whose token reports
/// `USDC` with 18 decimals, the example request gives the example response.
#[tokio::test]
async fn the_lookup_token_example_is_real() {
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
    let request: Req = serde_json::from_value(fixture("LookupToken.request")).expect("request");
    let response = dispatch(&h.state, request).await.expect("info");
    let text = serde_json::to_string(&response)
        .expect("encode")
        .replace(h.mock.url(), EXAMPLE_RPC_URL);
    let actual: Value = serde_json::from_str(&text).expect("json");
    assert_eq!(actual, fixture("LookupToken.response"));
}
