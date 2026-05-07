use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const CONFIG_FILENAME: &str = "config.json";
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

const DEFAULT_ETH_RPC_URL: &str = "https://eth.llamarpc.com";
const DEFAULT_BSC_RPC_URL: &str = "https://bsc.drpc.org";
const DEFAULT_USD1_ADDRESS: &str = "0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d";
const DEFAULT_SOLANA_MAINNET_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_SOLANA_DEVNET_RPC_URL: &str = "https://api.devnet.solana.com";
const DEFAULT_SOLANA_TESTNET_RPC_URL: &str = "https://api.testnet.solana.com";
const DEFAULT_SOLANA_USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const DEFAULT_SOLANA_DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct WlfiConfig {
    pub(crate) rpc_url: Option<String>,
    pub(crate) chain_id: Option<u64>,
    pub(crate) chain_name: Option<String>,
    pub(crate) daemon_socket: Option<String>,
    pub(crate) state_file: Option<String>,
    pub(crate) rust_bin_dir: Option<String>,
    pub(crate) agent_key_id: Option<String>,
    pub(crate) agent_auth_token: Option<String>,
    pub(crate) wallet: Option<WalletProfile>,
    pub(crate) chains: BTreeMap<String, ChainProfile>,
    pub(crate) tokens: BTreeMap<String, TokenProfile>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl Default for WlfiConfig {
    fn default() -> Self {
        Self {
            rpc_url: None,
            chain_id: None,
            chain_name: None,
            daemon_socket: None,
            state_file: None,
            rust_bin_dir: None,
            agent_key_id: None,
            agent_auth_token: None,
            wallet: None,
            chains: default_chain_profiles(),
            tokens: default_token_profiles(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct WalletProfile {
    pub(crate) vault_key_id: Option<String>,
    pub(crate) vault_public_key: String,
    pub(crate) address: Option<String>,
    pub(crate) agent_key_id: Option<String>,
    pub(crate) policy_attachment: String,
    pub(crate) attached_policy_ids: Vec<String>,
    pub(crate) policy_note: Option<String>,
    pub(crate) network_scope: Option<String>,
    pub(crate) asset_scope: Option<String>,
    pub(crate) recipient_scope: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct ChainProfile {
    pub(crate) chain_id: u64,
    pub(crate) name: String,
    pub(crate) rpc_url: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct TokenPolicyProfile {
    pub(crate) per_tx_amount: Option<f64>,
    pub(crate) daily_amount: Option<f64>,
    pub(crate) weekly_amount: Option<f64>,
    pub(crate) per_tx_amount_decimal: Option<String>,
    pub(crate) daily_amount_decimal: Option<String>,
    pub(crate) weekly_amount_decimal: Option<String>,
    pub(crate) per_tx_limit: Option<String>,
    pub(crate) daily_limit: Option<String>,
    pub(crate) weekly_limit: Option<String>,
    pub(crate) max_gas_per_chain_wei: Option<String>,
    pub(crate) daily_max_tx_count: Option<String>,
    pub(crate) per_tx_max_fee_per_gas_gwei: Option<String>,
    pub(crate) per_tx_max_fee_per_gas_wei: Option<String>,
    pub(crate) per_tx_max_priority_fee_per_gas_wei: Option<String>,
    pub(crate) per_tx_max_calldata_bytes: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct TokenDestinationOverrideProfile {
    pub(crate) recipient: String,
    #[serde(flatten)]
    pub(crate) limits: TokenPolicyProfile,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct TokenManualApprovalProfile {
    pub(crate) priority: u32,
    pub(crate) recipient: Option<String>,
    pub(crate) min_amount: Option<f64>,
    pub(crate) max_amount: Option<f64>,
    pub(crate) min_amount_decimal: Option<String>,
    pub(crate) max_amount_decimal: Option<String>,
    pub(crate) min_amount_wei: Option<String>,
    pub(crate) max_amount_wei: Option<String>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct TokenChainProfile {
    pub(crate) chain_id: u64,
    pub(crate) is_native: bool,
    pub(crate) address: Option<String>,
    pub(crate) decimals: u8,
    pub(crate) default_policy: Option<TokenPolicyProfile>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct TokenProfile {
    pub(crate) name: Option<String>,
    pub(crate) symbol: String,
    pub(crate) default_policy: Option<TokenPolicyProfile>,
    pub(crate) destination_overrides: Vec<TokenDestinationOverrideProfile>,
    pub(crate) manual_approval_policies: Vec<TokenManualApprovalProfile>,
    pub(crate) chains: BTreeMap<String, TokenChainProfile>,
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

fn default_chain_profiles() -> BTreeMap<String, ChainProfile> {
    BTreeMap::from([
        (
            "bsc".to_string(),
            ChainProfile {
                chain_id: 56,
                name: "BSC".to_string(),
                rpc_url: Some(DEFAULT_BSC_RPC_URL.to_string()),
                extra: BTreeMap::new(),
            },
        ),
        (
            "eth".to_string(),
            ChainProfile {
                chain_id: 1,
                name: "ETH".to_string(),
                rpc_url: Some(DEFAULT_ETH_RPC_URL.to_string()),
                extra: BTreeMap::new(),
            },
        ),
        (
            "solana-mainnet".to_string(),
            ChainProfile {
                chain_id: 900_000_001,
                name: "Solana".to_string(),
                rpc_url: Some(DEFAULT_SOLANA_MAINNET_RPC_URL.to_string()),
                extra: BTreeMap::new(),
            },
        ),
        (
            "solana-devnet".to_string(),
            ChainProfile {
                chain_id: 900_000_002,
                name: "Solana Devnet".to_string(),
                rpc_url: Some(DEFAULT_SOLANA_DEVNET_RPC_URL.to_string()),
                extra: BTreeMap::new(),
            },
        ),
        (
            "solana-testnet".to_string(),
            ChainProfile {
                chain_id: 900_000_003,
                name: "Solana Testnet".to_string(),
                rpc_url: Some(DEFAULT_SOLANA_TESTNET_RPC_URL.to_string()),
                extra: BTreeMap::new(),
            },
        ),
    ])
}

fn default_token_profiles() -> BTreeMap<String, TokenProfile> {
    BTreeMap::from([
        (
            "bnb".to_string(),
            TokenProfile {
                name: Some("BNB".to_string()),
                symbol: "BNB".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([(
                    "bsc".to_string(),
                    TokenChainProfile {
                        chain_id: 56,
                        is_native: true,
                        address: None,
                        decimals: 18,
                        default_policy: None,
                        extra: BTreeMap::new(),
                    },
                )]),
                extra: BTreeMap::new(),
            },
        ),
        (
            "eth".to_string(),
            TokenProfile {
                name: Some("ETH".to_string()),
                symbol: "ETH".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([(
                    "eth".to_string(),
                    TokenChainProfile {
                        chain_id: 1,
                        is_native: true,
                        address: None,
                        decimals: 18,
                        default_policy: None,
                        extra: BTreeMap::new(),
                    },
                )]),
                extra: BTreeMap::new(),
            },
        ),
        (
            "sol".to_string(),
            TokenProfile {
                name: Some("Solana".to_string()),
                symbol: "SOL".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([
                    (
                        "solana-mainnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_001,
                            is_native: true,
                            address: None,
                            decimals: 9,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                    (
                        "solana-devnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_002,
                            is_native: true,
                            address: None,
                            decimals: 9,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                    (
                        "solana-testnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_003,
                            is_native: true,
                            address: None,
                            decimals: 9,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                ]),
                extra: BTreeMap::new(),
            },
        ),
        (
            "usd1".to_string(),
            TokenProfile {
                name: Some("USD1".to_string()),
                symbol: "USD1".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([
                    (
                        "bsc".to_string(),
                        TokenChainProfile {
                            chain_id: 56,
                            is_native: false,
                            address: Some(DEFAULT_USD1_ADDRESS.to_string()),
                            decimals: 18,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                    (
                        "eth".to_string(),
                        TokenChainProfile {
                            chain_id: 1,
                            is_native: false,
                            address: Some(DEFAULT_USD1_ADDRESS.to_string()),
                            decimals: 18,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                ]),
                extra: BTreeMap::new(),
            },
        ),
        (
            "usdc".to_string(),
            TokenProfile {
                name: Some("USDC".to_string()),
                symbol: "USDC".to_string(),
                default_policy: None,
                destination_overrides: Vec::new(),
                manual_approval_policies: Vec::new(),
                chains: BTreeMap::from([
                    (
                        "solana-mainnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_001,
                            is_native: false,
                            address: Some(DEFAULT_SOLANA_USDC_MINT.to_string()),
                            decimals: 6,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                    (
                        "solana-devnet".to_string(),
                        TokenChainProfile {
                            chain_id: 900_000_002,
                            is_native: false,
                            address: Some(DEFAULT_SOLANA_DEVNET_USDC_MINT.to_string()),
                            decimals: 6,
                            default_policy: None,
                            extra: BTreeMap::new(),
                        },
                    ),
                ]),
                extra: BTreeMap::new(),
            },
        ),
    ])
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LoadedConfig {
    pub(crate) path: PathBuf,
    pub(crate) config: WlfiConfig,
}

impl LoadedConfig {
    pub(crate) fn load_default() -> Result<Self> {
        let path = default_config_path()?;
        let config = WlfiConfig::read_from_path(&path)?;
        Ok(Self { path, config })
    }

    pub(crate) fn save(&self) -> Result<()> {
        self.config.write_to_path(&self.path)
    }
}

impl WlfiConfig {
    fn apply_seed_defaults_if_legacy_empty(mut self) -> Self {
        if self.chains.is_empty() && self.tokens.is_empty() {
            self.chains = default_chain_profiles();
            self.tokens = default_token_profiles();
        }
        self
    }

    pub(crate) fn read_from_path(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str::<Self>(&raw)
                .map(Self::apply_seed_defaults_if_legacy_empty)
                .with_context(|| format!("failed to parse config file '{}'", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to read config file '{}'", path.display())),
        }
    }

    pub(crate) fn write_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory '{}'", parent.display())
            })?;
            #[cfg(unix)]
            {
                fs::set_permissions(parent, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
                    .with_context(|| {
                        format!("failed to secure config directory '{}'", parent.display())
                    })?;
            }
        }

        let rendered = serde_json::to_string_pretty(self).context("failed to serialize config")?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(PRIVATE_FILE_MODE);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open config file '{}'", path.display()))?;
        file.write_all(rendered.as_bytes())
            .with_context(|| format!("failed to write config file '{}'", path.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("failed to finalize config file '{}'", path.display()))?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .with_context(|| format!("failed to secure config file '{}'", path.display()))?;
        Ok(())
    }
}

pub(crate) fn default_config_path() -> Result<PathBuf> {
    Ok(agentpay_home_dir()?.join(CONFIG_FILENAME))
}

fn agentpay_home_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGENTPAY_HOME") {
        let candidate = PathBuf::from(path);
        if candidate.as_os_str().is_empty() {
            bail!("AGENTPAY_HOME must not be empty");
        }
        return Ok(candidate);
    }

    let Some(home) = std::env::var_os("HOME") else {
        bail!("HOME is not set; use AGENTPAY_HOME to choose config directory");
    };
    Ok(PathBuf::from(home).join(".agentpay"))
}

#[cfg(test)]
mod tests {
    use super::{
        default_config_path, LoadedConfig, TokenChainProfile, TokenDestinationOverrideProfile,
        TokenManualApprovalProfile, TokenPolicyProfile, TokenProfile, WlfiConfig,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    fn temp_root(label: &str) -> PathBuf {
        let unique = format!(
            "agentpay-admin-shared-config-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("unix time")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn read_from_missing_path_returns_default_config() {
        let root = temp_root("missing");
        let path = root.join("config.json");
        let config = WlfiConfig::read_from_path(&path).expect("missing path should default");
        assert_eq!(config, WlfiConfig::default());
    }

    #[test]
    fn read_from_legacy_empty_config_reseeds_defaults() {
        let root = temp_root("legacy-empty");
        fs::create_dir_all(&root).expect("create root");
        let path = root.join("config.json");
        fs::write(
            &path,
            r#"{
  "chains": {},
  "tokens": {},
  "chainId": 56,
  "chainName": "bsc",
  "rpcUrl": "https://rpc.bsc.example"
}
"#,
        )
        .expect("write legacy config");

        let config = WlfiConfig::read_from_path(&path).expect("read config");
        assert!(config.chains.contains_key("eth"));
        assert!(config.chains.contains_key("bsc"));
        assert!(config.chains.contains_key("solana-mainnet"));
        assert!(config.chains.contains_key("solana-devnet"));
        assert!(config.chains.contains_key("solana-testnet"));
        assert!(config.tokens.contains_key("bnb"));
        assert!(config.tokens.contains_key("eth"));
        assert!(config.tokens.contains_key("sol"));
        assert!(config.tokens.contains_key("usd1"));
        assert!(config.tokens.contains_key("usdc"));
        assert_eq!(config.tokens.len(), 5);
        assert_eq!(config.chain_id, Some(56));
        assert_eq!(config.chain_name.as_deref(), Some("bsc"));
        assert_eq!(config.rpc_url.as_deref(), Some("https://rpc.bsc.example"));

        fs::remove_dir_all(&root).expect("cleanup temp root");
    }

    #[test]
    fn default_config_seeds_eth_bsc_unrestricted_native_assets_and_unrestricted_usd1() {
        let config = WlfiConfig::default();

        assert_eq!(config.chains["eth"].chain_id, 1);
        assert_eq!(
            config.chains["eth"].rpc_url.as_deref(),
            Some("https://eth.llamarpc.com")
        );
        assert_eq!(config.chains["bsc"].chain_id, 56);
        assert_eq!(
            config.chains["bsc"].rpc_url.as_deref(),
            Some("https://bsc.drpc.org")
        );
        assert_eq!(config.chains["solana-mainnet"].chain_id, 900_000_001);
        assert_eq!(
            config.chains["solana-mainnet"].rpc_url.as_deref(),
            Some("https://api.mainnet-beta.solana.com")
        );
        assert_eq!(config.chains["solana-devnet"].chain_id, 900_000_002);
        assert_eq!(config.chains["solana-testnet"].chain_id, 900_000_003);

        let bnb = config.tokens.get("bnb").expect("bnb default");
        assert_eq!(bnb.symbol, "BNB");
        assert!(bnb.default_policy.is_none());
        assert_eq!(bnb.chains["bsc"].chain_id, 56);
        assert!(bnb.chains["bsc"].is_native);
        assert!(bnb.chains["bsc"].address.is_none());
        assert_eq!(bnb.chains["bsc"].decimals, 18);

        let eth = config.tokens.get("eth").expect("eth default");
        assert_eq!(eth.symbol, "ETH");
        assert!(eth.default_policy.is_none());
        assert_eq!(eth.chains["eth"].chain_id, 1);
        assert!(eth.chains["eth"].is_native);
        assert!(eth.chains["eth"].address.is_none());
        assert_eq!(eth.chains["eth"].decimals, 18);

        let sol = config.tokens.get("sol").expect("sol default");
        assert_eq!(sol.symbol, "SOL");
        assert!(sol.default_policy.is_none());
        assert_eq!(sol.chains["solana-mainnet"].chain_id, 900_000_001);
        assert!(sol.chains["solana-mainnet"].is_native);
        assert!(sol.chains["solana-mainnet"].address.is_none());
        assert_eq!(sol.chains["solana-mainnet"].decimals, 9);
        assert_eq!(sol.chains["solana-devnet"].chain_id, 900_000_002);
        assert_eq!(sol.chains["solana-testnet"].chain_id, 900_000_003);

        let usd1 = config.tokens.get("usd1").expect("usd1 default");
        assert_eq!(usd1.symbol, "USD1");
        assert!(usd1.default_policy.is_none());
        assert_eq!(
            usd1.chains["eth"].address.as_deref(),
            Some("0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d")
        );
        assert_eq!(
            usd1.chains["bsc"].address.as_deref(),
            Some("0x8d0D000Ee44948FC98c9B98A4FA4921476f08B0d")
        );
        assert!(usd1.chains["eth"].default_policy.is_none());
        assert!(usd1.chains["bsc"].default_policy.is_none());

        let usdc = config.tokens.get("usdc").expect("usdc default");
        assert_eq!(usdc.symbol, "USDC");
        assert_eq!(
            usdc.chains["solana-mainnet"].address.as_deref(),
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        );
        assert_eq!(usdc.chains["solana-mainnet"].decimals, 6);
        assert_eq!(
            usdc.chains["solana-devnet"].address.as_deref(),
            Some("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        );
        assert_eq!(usdc.chains["solana-devnet"].decimals, 6);
        assert_eq!(config.tokens.len(), 5);
    }

    #[test]
    fn write_and_read_round_trip_preserves_chain_and_token_profiles() {
        let root = temp_root("roundtrip");
        fs::create_dir_all(&root).expect("create root");
        let path = root.join("config.json");

        let mut config = WlfiConfig {
            chain_id: Some(1),
            chain_name: Some("eth".to_string()),
            rpc_url: Some("https://rpc.ethereum.example".to_string()),
            ..WlfiConfig::default()
        };
        config.chains.insert(
            "eth".to_string(),
            super::ChainProfile {
                chain_id: 1,
                name: "eth".to_string(),
                rpc_url: Some("https://rpc.ethereum.example".to_string()),
                extra: BTreeMap::new(),
            },
        );
        config.tokens.insert(
            "usd1".to_string(),
            TokenProfile {
                name: Some("USD1".to_string()),
                symbol: "USD1".to_string(),
                default_policy: Some(TokenPolicyProfile {
                    per_tx_amount: Some(25.0),
                    daily_amount: Some(100.0),
                    weekly_amount: Some(500.0),
                    per_tx_amount_decimal: Some("25".to_string()),
                    daily_amount_decimal: Some("100".to_string()),
                    weekly_amount_decimal: Some("500".to_string()),
                    per_tx_limit: None,
                    daily_limit: None,
                    weekly_limit: None,
                    max_gas_per_chain_wei: Some("1000000000000000".to_string()),
                    daily_max_tx_count: Some("0".to_string()),
                    per_tx_max_fee_per_gas_gwei: Some("25".to_string()),
                    per_tx_max_fee_per_gas_wei: Some("25000000000".to_string()),
                    per_tx_max_priority_fee_per_gas_wei: Some("0".to_string()),
                    per_tx_max_calldata_bytes: Some("0".to_string()),
                    extra: BTreeMap::new(),
                }),
                destination_overrides: vec![TokenDestinationOverrideProfile {
                    recipient: "0x1000000000000000000000000000000000000001".to_string(),
                    limits: TokenPolicyProfile {
                        per_tx_amount: None,
                        daily_amount: None,
                        weekly_amount: None,
                        per_tx_amount_decimal: Some("10".to_string()),
                        daily_amount_decimal: Some("50".to_string()),
                        weekly_amount_decimal: Some("200".to_string()),
                        per_tx_limit: None,
                        daily_limit: None,
                        weekly_limit: None,
                        max_gas_per_chain_wei: Some("100000000000000".to_string()),
                        daily_max_tx_count: Some("0".to_string()),
                        per_tx_max_fee_per_gas_gwei: Some("15".to_string()),
                        per_tx_max_fee_per_gas_wei: Some("15000000000".to_string()),
                        per_tx_max_priority_fee_per_gas_wei: Some("0".to_string()),
                        per_tx_max_calldata_bytes: Some("0".to_string()),
                        extra: BTreeMap::new(),
                    },
                }],
                manual_approval_policies: vec![TokenManualApprovalProfile {
                    priority: 100,
                    recipient: None,
                    min_amount: Some(250.0),
                    max_amount: Some(500.0),
                    min_amount_decimal: Some("250".to_string()),
                    max_amount_decimal: Some("500".to_string()),
                    min_amount_wei: None,
                    max_amount_wei: None,
                    extra: BTreeMap::new(),
                }],
                chains: BTreeMap::from([(
                    "eth".to_string(),
                    TokenChainProfile {
                        chain_id: 1,
                        is_native: false,
                        address: Some("0x1000000000000000000000000000000000000000".to_string()),
                        decimals: 6,
                        default_policy: Some(TokenPolicyProfile {
                            per_tx_amount: Some(25.0),
                            daily_amount: Some(100.0),
                            weekly_amount: Some(500.0),
                            per_tx_amount_decimal: Some("25".to_string()),
                            daily_amount_decimal: Some("100".to_string()),
                            weekly_amount_decimal: Some("500".to_string()),
                            per_tx_limit: Some("25".to_string()),
                            daily_limit: Some("100".to_string()),
                            weekly_limit: Some("500".to_string()),
                            max_gas_per_chain_wei: Some("1000000000000000".to_string()),
                            daily_max_tx_count: Some("0".to_string()),
                            per_tx_max_fee_per_gas_gwei: Some("25".to_string()),
                            per_tx_max_fee_per_gas_wei: Some("0".to_string()),
                            per_tx_max_priority_fee_per_gas_wei: Some("0".to_string()),
                            per_tx_max_calldata_bytes: Some("0".to_string()),
                            extra: BTreeMap::new(),
                        }),
                        extra: BTreeMap::new(),
                    },
                )]),
                extra: BTreeMap::new(),
            },
        );

        config.write_to_path(&path).expect("write config");
        let loaded = WlfiConfig::read_from_path(&path).expect("read config");
        assert_eq!(loaded, config);

        let loaded_document = LoadedConfig {
            path: path.clone(),
            config,
        };
        loaded_document.save().expect("save loaded document");
        assert!(path.exists());

        fs::remove_dir_all(&root).expect("cleanup temp root");
    }

    #[test]
    fn default_config_path_uses_agentpay_home_when_present() {
        let root = temp_root("agentpay-home");
        fs::create_dir_all(&root).expect("create root");
        let previous = std::env::var_os("AGENTPAY_HOME");
        std::env::set_var("AGENTPAY_HOME", &root);

        let path = default_config_path().expect("resolve default config path");
        assert_eq!(path, root.join("config.json"));

        if let Some(value) = previous {
            std::env::set_var("AGENTPAY_HOME", value);
        } else {
            std::env::remove_var("AGENTPAY_HOME");
        }
        fs::remove_dir_all(&root).expect("cleanup temp root");
    }
}
