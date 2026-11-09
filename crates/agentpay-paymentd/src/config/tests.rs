//! Defaults, validation, and storage of the payments configuration.

use std::path::Path;

use agentpay_api::payments::{
    ChainFamily, ChainProfile, PaymentsConfig, PaymentsRpcResponse, TokenChainProfile,
};

use super::*;
use crate::error::PaymentsError;
use crate::test_support::{set_mode, TempDir};

/// The documented `GetConfig` response: the built-in default.
fn documented_default() -> PaymentsConfig {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/payments/GetConfig.response.json");
    let text = std::fs::read_to_string(path).expect("GetConfig example");
    let PaymentsRpcResponse::Config(config) = serde_json::from_str(&text).expect("decode") else {
        panic!("GetConfig example must be a Config response");
    };
    config
}

fn documented_small_config() -> PaymentsConfig {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/payments/SetConfig.response.json");
    let text = std::fs::read_to_string(path).expect("SetConfig example");
    let PaymentsRpcResponse::Config(config) = serde_json::from_str(&text).expect("decode") else {
        panic!("SetConfig example must be a Config response");
    };
    config
}

#[test]
fn default_config_is_the_documented_default_and_valid() {
    let config = default_config();
    assert_eq!(config, documented_default());
    assert_eq!(config.default_network, "bsc");
    assert_eq!(config.default_asset, "usd1");
    assert_eq!(validate(&config).expect("valid"), config);
    let usd1 = &config.tokens["usd1"].chains["bsc"];
    assert_eq!(usd1.chain_id, 56);
    assert_eq!(
        usd1.address.as_deref(),
        Some("0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d")
    );
}

#[test]
fn builtin_tables_are_consistent() {
    for token in BUILTIN_TOKENS {
        for deployment in token.deployments {
            assert!(
                builtin_chain(deployment.chain).is_some(),
                "{} names unknown chain {}",
                token.key,
                deployment.chain
            );
        }
    }
    for chain in BUILTIN_CHAINS {
        assert_eq!(
            chain.family == ChainFamily::Solana,
            agentpay_domain::is_solana_chain_id(chain.chain_id),
            "{}",
            chain.key
        );
        if let Some(url) = chain.rpc_url {
            check_rpc_url(url).expect("builtin RPC URLs are valid");
        }
    }
    assert_eq!(builtin_chain("ethereum").map(|c| c.chain_id), Some(1));
}

#[test]
fn rpc_urls_must_be_https_or_loopback_without_credentials() {
    for ok in [
        "https://bsc.drpc.org",
        "https://eth-mainnet.example/v2/api-key",
        "http://localhost:8545",
        "http://127.0.0.1:8545",
        "http://[::1]:8545",
        "http://node.localhost",
    ] {
        check_rpc_url(ok).unwrap_or_else(|err| panic!("{ok}: {err}"));
    }
    for (bad, reason) in [
        ("http://bsc.drpc.org", "https"),
        ("ftp://bsc.drpc.org", "https"),
        ("https://user:pass@bsc.drpc.org", "credentials"),
        ("not a url", "valid"),
        ("http://10.0.0.1:8545", "loopback"),
    ] {
        let err = check_rpc_url(bad).expect_err(bad);
        assert!(err.contains(reason), "{bad}: {err}");
    }
}

/// A change that makes a valid configuration invalid.
type Mutation = fn(&mut PaymentsConfig);

fn usd1_on_bsc(config: &mut PaymentsConfig) -> &mut TokenChainProfile {
    config
        .tokens
        .get_mut("usd1")
        .and_then(|token| token.chains.get_mut("bsc"))
        .expect("usd1 on bsc")
}

fn bsc(config: &mut PaymentsConfig) -> &mut ChainProfile {
    config.chains.get_mut("bsc").expect("bsc")
}

#[test]
fn validation_rejects_inconsistent_configs_without_echoing_urls() {
    let cases: &[(&str, Mutation)] = &[
        ("[a-z0-9._-]", |c| {
            let chain = c.chains["bsc"].clone();
            c.chains.insert("BSC".into(), chain);
        }),
        ("family must be solana", |c| {
            let solana = ChainProfile {
                chain_id: 900_000_001,
                name: "Solana".into(),
                family: ChainFamily::Evm,
                rpc_url: None,
                fallback_rpc_urls: Vec::new(),
            };
            c.chains.insert("sol".into(), solana);
        }),
        ("chain_id must be between", |c| bsc(c).chain_id = 0),
        ("fallback_rpc_urls[1] must use https", |c| {
            let fallbacks = &mut bsc(c).fallback_rpc_urls;
            fallbacks.push("http://secret-key.example".into());
        }),
        ("fallback_rpc_urls[1] repeats rpc_url", |c| {
            let chain = bsc(c);
            let primary = chain.rpc_url.clone().expect("rpc_url");
            chain.fallback_rpc_urls.push(primary);
        }),
        ("fallback_rpc_urls[1] repeats an earlier fallback", |c| {
            let fallbacks = &mut bsc(c).fallback_rpc_urls;
            fallbacks.push(fallbacks[0].clone());
        }),
        ("fallback_rpc_urls holds at most 4", |c| {
            bsc(c).fallback_rpc_urls = (0..5)
                .map(|i| format!("https://secret-key-{i}.example"))
                .collect();
        }),
        ("fallback_rpc_urls needs an rpc_url", |c| {
            bsc(c).rpc_url = None
        }),
        ("rpc_url must use https", |c| {
            bsc(c).rpc_url = Some("http://secret-key.example".into());
        }),
        ("does not name a configured chain", |c| {
            let deployment = usd1_on_bsc(c).clone();
            let token = c.tokens.get_mut("usd1").expect("usd1");
            token.chains.insert("eth".into(), deployment);
        }),
        ("differs from the chain's", |c| usd1_on_bsc(c).chain_id = 1),
        ("must be an EVM address", |c| {
            usd1_on_bsc(c).address = Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into());
        }),
        ("must not set address", |c| usd1_on_bsc(c).is_native = true),
        ("needs an address", |c| usd1_on_bsc(c).address = None),
        ("decimals must be at most", |c| usd1_on_bsc(c).decimals = 77),
        ("non-negative decimal", |c| {
            if let Some(limits) = &mut c.tokens.get_mut("usd1").expect("usd1").recommended_limits {
                limits.daily = "-1".into();
            }
        }),
        ("default_network 'eth' is not", |c| {
            c.default_network = "eth".into()
        }),
        ("default_asset 'usdc' is not", |c| {
            c.default_asset = "usdc".into()
        }),
    ];
    for (expected, mutate) in cases {
        let mut config = documented_small_config();
        mutate(&mut config);
        let err = validate(&config).expect_err(expected);
        assert!(err.contains(expected), "expected '{expected}', got '{err}'");
        assert!(
            !err.contains("secret-key"),
            "message echoes an RPC URL: {err}"
        );
    }
}

#[test]
fn validation_normalizes_checksummed_evm_addresses() {
    let mut config = documented_small_config();
    let deployment = config
        .tokens
        .get_mut("usd1")
        .and_then(|token| token.chains.get_mut("bsc"))
        .expect("usd1 on bsc");
    deployment.address = Some("0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d".into());
    let normalized = validate(&config).expect("valid checksum");
    assert_eq!(normalized, documented_small_config());
}

#[tokio::test]
async fn store_serves_defaults_until_set_then_persists_privately() {
    let dir = TempDir::new("cfg");
    let store = ConfigStore::open(dir.path()).expect("open");
    assert_eq!(store.get().await, default_config());
    assert!(!store.path().exists(), "defaults are not written");

    let small = documented_small_config();
    assert_eq!(store.set(small.clone()).await.expect("set"), small);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(store.path())
        .expect("file")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let leftovers = std::fs::read_dir(dir.path()).expect("dir").count();
    assert_eq!(leftovers, 1, "no temporary files are left behind");

    let reopened = ConfigStore::open(dir.path()).expect("reopen");
    assert_eq!(reopened.get().await, small);
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.path()).expect("read")).expect("json");
    assert_eq!(stored["schema"], CONFIG_SCHEMA);
}

#[tokio::test]
async fn invalid_set_leaves_the_stored_config_unchanged() {
    let dir = TempDir::new("cfg");
    let store = ConfigStore::open(dir.path()).expect("open");
    let mut bad = documented_small_config();
    bad.default_network = "nowhere".into();
    let err = store.set(bad).await.expect_err("invalid");
    assert!(matches!(err, PaymentsError::InvalidConfig(_)));
    assert_eq!(store.get().await, default_config());
    assert!(!store.path().exists());
}

#[tokio::test]
async fn untrusted_or_corrupt_files_are_refused() {
    let dir = TempDir::new("cfg");
    let path = dir.path().join(CONFIG_FILE_NAME);

    std::fs::write(&path, b"{not json").expect("write");
    set_mode(&path, 0o600);
    let err = ConfigStore::open(dir.path()).expect_err("corrupt");
    assert!(err.contains("not valid"), "{err}");

    let stored = serde_json::json!({"schema": CONFIG_SCHEMA, "config": documented_small_config()});
    std::fs::write(&path, stored.to_string()).expect("write");
    set_mode(&path, 0o644);
    let err = ConfigStore::open(dir.path()).expect_err("readable by others");
    assert!(err.contains("chmod 600"), "{err}");

    set_mode(&path, 0o600);
    ConfigStore::open(dir.path()).expect("private file loads");

    std::fs::remove_file(&path).expect("remove");
    let target = dir.path().join("elsewhere.json");
    std::fs::write(&target, stored.to_string()).expect("write");
    set_mode(&target, 0o600);
    std::os::unix::fs::symlink(&target, &path).expect("symlink");
    let err = ConfigStore::open(dir.path()).expect_err("symlink");
    assert!(err.contains("regular file"), "{err}");

    std::fs::remove_file(&path).expect("remove");
    let wrong_schema = serde_json::json!({"schema": 99, "config": documented_small_config()});
    std::fs::write(&path, wrong_schema.to_string()).expect("write");
    set_mode(&path, 0o600);
    let err = ConfigStore::open(dir.path()).expect_err("schema");
    assert!(err.contains("schema 99"), "{err}");
}

#[test]
fn four_distinct_fallbacks_are_valid() {
    let mut config = documented_small_config();
    bsc(&mut config).fallback_rpc_urls = (0..4)
        .map(|i| format!("https://backup-{i}.example"))
        .collect();
    validate(&config).expect("four backups");
}

#[test]
fn builtin_endpoints_are_valid_and_carry_backups() {
    let config = default_config();
    validate(&config).expect("valid");
    for (key, backups) in [
        ("bsc", 2),
        ("eth", 2),
        ("arbitrum", 2),
        ("arbitrum-sepolia", 2),
        ("base", 2),
        ("base-sepolia", 2),
        ("optimism", 2),
        ("polygon", 2),
        ("tempo", 1),
        ("tempo-testnet", 0),
        ("solana-mainnet", 1),
        ("solana-devnet", 0),
        ("solana-testnet", 0),
    ] {
        assert_eq!(config.chains[key].fallback_rpc_urls.len(), backups, "{key}");
    }
    for (chain_id, retired) in RETIRED_DEFAULT_RPC_URLS {
        assert!(
            config
                .chains
                .values()
                .all(|chain| chain.rpc_url.as_deref() != Some(*retired)),
            "{chain_id}: a retired default is still the default"
        );
    }
}

/// The built-in defaults with `edit` applied to the stored chains.
fn with_chains(edit: impl FnOnce(&mut PaymentsConfig)) -> PaymentsConfig {
    let mut config = default_config();
    edit(&mut config);
    config
}

fn retire(config: &mut PaymentsConfig, key: &str, url: &str) {
    let chain = config.chains.get_mut(key).expect("chain");
    chain.rpc_url = Some(url.into());
    chain.fallback_rpc_urls.clear();
}

#[test]
fn only_exact_retired_defaults_are_upgraded() {
    let mut config = with_chains(|c| {
        retire(c, "bsc", "https://bsc.drpc.org");
        retire(c, "eth", "https://eth.llamarpc.com");
        retire(c, "tempo", "https://rpc.presto.tempo.xyz");
    });
    let upgraded = upgrade_retired_defaults(&mut config);
    assert_eq!(upgraded, ["bsc", "eth", "tempo"]);
    assert_eq!(config, default_config());

    let untouched: [(&str, Mutation); 5] = [
        // An operator-chosen URL.
        ("own url", |c| retire(c, "bsc", "https://my-node.example")),
        // Not byte-for-byte the retired default.
        ("trailing slash", |c| {
            retire(c, "bsc", "https://bsc.drpc.org/")
        }),
        // Backups were set by the operator.
        ("has backups", |c| {
            retire(c, "bsc", "https://bsc.drpc.org");
            bsc(c).fallback_rpc_urls = vec!["https://my-node.example".into()];
        }),
        // Another chain's retired default.
        ("other chain", |c| {
            retire(c, "bsc", "https://eth.llamarpc.com")
        }),
        // A key the service does not know.
        ("custom key", |c| {
            let mut chain = c.chains["bsc"].clone();
            chain.rpc_url = Some("https://bsc.drpc.org".into());
            chain.fallback_rpc_urls.clear();
            c.chains.insert("my-bsc".into(), chain);
        }),
    ];
    for (case, edit) in untouched {
        let mut config = with_chains(edit);
        let before = config.clone();
        assert!(upgrade_retired_defaults(&mut config).is_empty(), "{case}");
        assert_eq!(config, before, "{case}");
    }
}

#[tokio::test]
async fn retired_defaults_are_upgraded_and_saved_when_loaded() {
    let dir = TempDir::new("cfg");
    let store = ConfigStore::open(dir.path()).expect("open");
    let stale = with_chains(|c| {
        retire(c, "bsc", "https://bsc.drpc.org");
        retire(c, "eth", "https://my-node.example");
    });
    store
        .set(stale.clone())
        .await
        .expect("store the stale file");

    let reopened = ConfigStore::open(dir.path()).expect("reopen");
    let mut expected = stale;
    expected
        .chains
        .insert("bsc".into(), default_config().chains["bsc"].clone());
    assert_eq!(reopened.get().await, expected);
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.path()).expect("read")).expect("json");
    let saved: PaymentsConfig =
        serde_json::from_value(stored["config"].clone()).expect("stored config");
    assert_eq!(saved, expected, "the upgrade is persisted");
    let leftovers = std::fs::read_dir(dir.path()).expect("dir").count();
    assert_eq!(leftovers, 1, "written atomically");
}

#[test]
fn stored_configs_without_fallbacks_still_load() {
    let mut value = serde_json::to_value(documented_small_config()).expect("encode");
    value["chains"]["bsc"]
        .as_object_mut()
        .expect("bsc")
        .remove("fallback_rpc_urls");
    let config: PaymentsConfig = serde_json::from_value(value).expect("decode");
    assert!(config.chains["bsc"].fallback_rpc_urls.is_empty());
}

/// Seeded chains added after [`ORIGINAL_SEEDED_CHAINS`], in [`SEEDED_CHAINS`] order.
const NEW_NETWORKS: [&str; 6] = [
    "arbitrum",
    "arbitrum-sepolia",
    "base",
    "base-sepolia",
    "optimism",
    "polygon",
];

#[test]
fn default_config_seeds_the_evm_networks_with_usdc_eth_and_pol() {
    let config = default_config();
    for (key, chain_id, name, usdc) in [
        (
            "arbitrum",
            42_161,
            "Arbitrum",
            "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        ),
        (
            "arbitrum-sepolia",
            421_614,
            "Arbitrum Sepolia",
            "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d",
        ),
        (
            "base",
            8453,
            "Base",
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        ),
        (
            "base-sepolia",
            84_532,
            "Base Sepolia",
            "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        ),
        (
            "optimism",
            10,
            "Optimism",
            "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
        ),
        (
            "polygon",
            137,
            "Polygon",
            "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
        ),
    ] {
        let chain = &config.chains[key];
        assert_eq!(
            (chain.chain_id, chain.name.as_str(), chain.family),
            (chain_id, name, ChainFamily::Evm),
            "{key}"
        );
        assert!(chain.rpc_url.is_some(), "{key}");
        let deployment = &config.tokens["usdc"].chains[key];
        assert_eq!(
            (
                deployment.chain_id,
                deployment.is_native,
                deployment.address.as_deref(),
                deployment.decimals
            ),
            (chain_id, false, Some(usdc), 6),
            "usdc on {key}"
        );
        let native = if key == "polygon" { "pol" } else { "eth" };
        let coin = &config.tokens[native].chains[key];
        assert_eq!(
            (
                coin.chain_id,
                coin.is_native,
                coin.address.as_deref(),
                coin.decimals
            ),
            (chain_id, true, None, 18),
            "{native} on {key}"
        );
    }
    let usdc = &config.tokens["usdc"];
    assert!(
        usdc.chains.contains_key("solana-mainnet"),
        "Solana USDC kept"
    );
    assert!(usdc.recommended_limits.is_some());
    let pol = &config.tokens["pol"];
    assert_eq!((pol.name.as_str(), pol.symbol.as_str()), ("Polygon", "POL"));
    assert_eq!(pol.chains.len(), 1);
    assert!(pol.recommended_limits.is_some());
    assert!(!config.tokens["eth"].chains.contains_key("polygon"));
    for chain_id in [42_161, 421_614, 10, 137] {
        assert!(
            crate::chains::evm::MULTICALL3_CHAIN_IDS.contains(&chain_id),
            "{chain_id} has Multicall3"
        );
    }
}

/// The built-in defaults as stored before the new networks were seeded.
fn original_defaults() -> PaymentsConfig {
    let original = |key: &String| ORIGINAL_SEEDED_CHAINS.contains(&key.as_str());
    let mut config = default_config();
    config.chains.retain(|key, _| original(key));
    for token in config.tokens.values_mut() {
        token.chains.retain(|key, _| original(key));
    }
    config.tokens.retain(|_, token| !token.chains.is_empty());
    validate(&config).expect("valid")
}

#[test]
fn missing_builtin_networks_are_added_once() {
    let mut config = original_defaults();
    let added = add_missing_builtin_networks(&mut config, &[]);
    assert_eq!(added, NEW_NETWORKS);
    assert_eq!(config, default_config());

    let again = add_missing_builtin_networks(&mut config, &[]);
    assert!(again.is_empty(), "idempotent");
    assert_eq!(config, default_config());
}

#[test]
fn adding_builtin_networks_never_changes_existing_entries() {
    let mut config = original_defaults();
    // A user's own Base chain under the built-in key.
    let mut my_base = default_config().chains["base"].clone();
    my_base.name = "My Base".into();
    my_base.rpc_url = Some("https://my-base-node.example".into());
    my_base.fallback_rpc_urls.clear();
    config.chains.insert("base".into(), my_base.clone());
    // Optimism under another key.
    let mut my_op = default_config().chains["optimism"].clone();
    my_op.name = "OP".into();
    config.chains.insert("op".into(), my_op.clone());
    // Edited token profiles and a deployment the user already set.
    let usdc = config.tokens.get_mut("usdc").expect("usdc");
    usdc.name = "My USDC".into();
    usdc.recommended_limits = None;
    let mine = TokenChainProfile {
        chain_id: 137,
        is_native: false,
        address: Some("0x1111111111111111111111111111111111111111".into()),
        decimals: 6,
    };
    usdc.chains.insert("polygon".into(), mine.clone());
    config.tokens.get_mut("eth").expect("eth").symbol = "WETH".into();
    let before = config.clone();

    let added = add_missing_builtin_networks(&mut config, &["arbitrum-sepolia".to_string()]);
    assert_eq!(added, ["arbitrum", "base-sepolia", "polygon"]);
    for (key, chain) in &before.chains {
        assert_eq!(&config.chains[key], chain, "chain {key} unchanged");
    }
    for (key, token) in &before.tokens {
        let now = &config.tokens[key];
        assert_eq!(
            (&now.name, &now.symbol, &now.recommended_limits),
            (&token.name, &token.symbol, &token.recommended_limits),
            "token {key} profile unchanged"
        );
        for (chain, deployment) in &token.chains {
            assert_eq!(&now.chains[chain], deployment, "{key} on {chain}");
        }
    }
    assert!(
        !config.chains.contains_key("optimism"),
        "chain id 10 is 'op'"
    );
    assert!(
        !config.chains.contains_key("arbitrum-sepolia"),
        "offered before"
    );
    let usdc = &config.tokens["usdc"];
    assert_eq!(usdc.chains["polygon"], mine, "deployment kept");
    assert_eq!(
        usdc.chains["arbitrum"],
        default_config().tokens["usdc"].chains["arbitrum"]
    );
    assert!(!usdc.chains.contains_key("base"), "not a new network");
    assert_eq!(config.tokens["eth"].symbol, "WETH");
    assert!(config.tokens["eth"].chains.contains_key("base-sepolia"));
    assert_eq!(config.tokens["pol"], default_config().tokens["pol"]);
}

/// Writes `config` as a file from before seeded networks were recorded.
fn write_original_file(dir: &Path, config: &PaymentsConfig) {
    let path = dir.join(CONFIG_FILE_NAME);
    let stored = serde_json::json!({"schema": CONFIG_SCHEMA, "config": config});
    std::fs::write(&path, stored.to_string()).expect("write");
    set_mode(&path, 0o600);
}

#[tokio::test]
async fn new_builtin_networks_are_added_when_loaded_and_removals_stick() {
    let dir = TempDir::new("cfg");
    // The operator removed Tempo Moderato before the new networks shipped.
    let mut stored = original_defaults();
    stored.chains.remove("tempo-testnet");
    for token in stored.tokens.values_mut() {
        token.chains.remove("tempo-testnet");
    }
    write_original_file(dir.path(), &stored);

    let store = ConfigStore::open(dir.path()).expect("open");
    let mut expected = default_config();
    expected.chains.remove("tempo-testnet");
    for token in expected.tokens.values_mut() {
        token.chains.remove("tempo-testnet");
    }
    assert_eq!(store.get().await, expected, "removed chain stays removed");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.path()).expect("read")).expect("json");
    let saved_config: PaymentsConfig =
        serde_json::from_value(saved["config"].clone()).expect("stored config");
    assert_eq!(saved_config, expected, "the additions are persisted");
    let offered: Vec<String> =
        serde_json::from_value(saved["seeded_networks"].clone()).expect("seeded_networks");
    assert!(NEW_NETWORKS
        .iter()
        .all(|key| offered.iter().any(|o| o == key)));

    let mut without_base = expected.clone();
    without_base.chains.remove("base");
    for token in without_base.tokens.values_mut() {
        token.chains.remove("base");
    }
    store.set(without_base.clone()).await.expect("remove base");
    let reopened = ConfigStore::open(dir.path()).expect("reopen");
    assert_eq!(reopened.get().await, without_base, "base stays removed");
}

#[tokio::test]
async fn new_builtin_deployments_reach_existing_networks_once() {
    let dir = TempDir::new("cfg");
    // A file from the previous release: every seeded network recorded, no
    // USDC on Ethereum or BSC or USD1 on Solana yet, and no record of
    // offered deployments.
    let mut stored = default_config();
    let usdc = stored.tokens.get_mut("usdc").expect("usdc");
    usdc.chains.remove("eth");
    usdc.chains.remove("bsc");
    let usd1 = stored.tokens.get_mut("usd1").expect("usd1");
    usd1.chains.remove("solana-mainnet");
    let path = dir.path().join(CONFIG_FILE_NAME);
    let file = serde_json::json!({
        "schema": CONFIG_SCHEMA,
        "config": stored,
        "seeded_networks": SEEDED_CHAINS.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
    });
    std::fs::write(&path, file.to_string()).expect("write");
    set_mode(&path, 0o600);

    let store = ConfigStore::open(dir.path()).expect("open");
    assert_eq!(
        store.get().await,
        default_config(),
        "USDC added on eth and bsc, USD1 on Solana"
    );

    // The operator removes USDC on BSC: it is not added back.
    let mut without = default_config();
    without
        .tokens
        .get_mut("usdc")
        .expect("usdc")
        .chains
        .remove("bsc");
    store.set(without.clone()).await.expect("remove");
    let reopened = ConfigStore::open(dir.path()).expect("reopen");
    assert_eq!(reopened.get().await, without, "removal sticks");
}

#[tokio::test]
async fn loading_a_current_file_rewrites_nothing() {
    let dir = TempDir::new("cfg");
    write_original_file(dir.path(), &default_config());
    let path = dir.path().join(CONFIG_FILE_NAME);
    let before = std::fs::read(&path).expect("read");
    let store = ConfigStore::open(dir.path()).expect("open");
    assert_eq!(store.get().await, default_config());
    assert_eq!(std::fs::read(&path).expect("read"), before, "not rewritten");
}

#[tokio::test]
async fn a_retired_builtin_deployment_moves_to_the_current_contract() {
    const CCIP_USD1: &str = "0x111111d2bf19e43c34263401e0cad979ed1cdb61";
    let retired = |config: &mut PaymentsConfig, address: &str, decimals: u8| {
        let tempo = config
            .tokens
            .get_mut("usd1")
            .and_then(|token| token.chains.get_mut("tempo"))
            .expect("usd1 on tempo");
        tempo.address = Some(address.into());
        tempo.decimals = decimals;
    };

    // The previous built-in default (any case) is corrected, and saved.
    let dir = TempDir::new("cfg");
    let mut stored = default_config();
    retired(
        &mut stored,
        &CCIP_USD1.to_uppercase().replace("0X", "0x"),
        18,
    );
    write_original_file(dir.path(), &stored);
    let store = ConfigStore::open(dir.path()).expect("open");
    assert_eq!(store.get().await, default_config());
    let tempo = &store.get().await.tokens["usd1"].chains["tempo"];
    assert_eq!(
        (tempo.address.as_deref(), tempo.decimals),
        (Some("0x20c000000000000000000000111111111e910f0f"), 6)
    );
    let reopened = ConfigStore::open(dir.path()).expect("reopen");
    assert_eq!(reopened.get().await, default_config(), "saved");

    // A deployment the operator changed is left alone.
    let dir = TempDir::new("cfg");
    let mut edited = default_config();
    retired(&mut edited, CCIP_USD1, 6);
    write_original_file(dir.path(), &edited);
    let store = ConfigStore::open(dir.path()).expect("open");
    assert_eq!(store.get().await, edited);
}
