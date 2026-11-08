//! Built-in chains and tokens, ported from the TypeScript `packages/config`.
//!
//! [`BUILTIN_CHAINS`] lists every chain name the service knows (including
//! aliases such as `ethereum` and `mainnet`); [`SEEDED_CHAINS`] picks the ones
//! a fresh configuration starts with. [`default_config`] derives the seeded
//! configuration from both tables, keying each token deployment by the seeded
//! chain with the same chain id, so the tables cannot drift apart.
//! [`add_missing_builtin_networks`] brings a stored configuration up to date
//! with seeded chains added since it was written.

use std::collections::BTreeMap;

use agentpay_api::payments::{
    ChainFamily, ChainProfile, PaymentsConfig, TokenChainProfile, TokenLimits, TokenProfile,
};

/// A chain name the service knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinChain {
    /// Lookup key, for example `"bsc"` or `"ethereum"`.
    pub key: &'static str,
    /// EVM chain id or internal Solana network id.
    pub chain_id: u64,
    /// Signing and RPC stack.
    pub family: ChainFamily,
    /// Public RPC endpoint, when there is a sensible default.
    pub rpc_url: Option<&'static str>,
    /// Public backup endpoints, tried in order when `rpc_url` fails.
    pub fallback_rpc_urls: &'static [&'static str],
}

/// A chain's default endpoints.
#[derive(Debug, Clone, Copy)]
struct Endpoints {
    primary: Option<&'static str>,
    fallbacks: &'static [&'static str],
}

const fn evm(key: &'static str, chain_id: u64, endpoints: Endpoints) -> BuiltinChain {
    BuiltinChain {
        key,
        chain_id,
        family: ChainFamily::Evm,
        rpc_url: endpoints.primary,
        fallback_rpc_urls: endpoints.fallbacks,
    }
}

const fn solana(key: &'static str, chain_id: u64, endpoints: Endpoints) -> BuiltinChain {
    BuiltinChain {
        key,
        chain_id,
        family: ChainFamily::Solana,
        rpc_url: endpoints.primary,
        fallback_rpc_urls: endpoints.fallbacks,
    }
}

const fn only(primary: &'static str) -> Endpoints {
    Endpoints {
        primary: Some(primary),
        fallbacks: &[],
    }
}

/// No default endpoint.
const NONE: Endpoints = Endpoints {
    primary: None,
    fallbacks: &[],
};

// Public endpoints, checked for `eth_chainId` / `getGenesisHash`, JSON-RPC
// batches, and (EVM) Multicall3 code. Backups come from other operators.
const ETH_RPC: Endpoints = Endpoints {
    primary: Some("https://ethereum-rpc.publicnode.com"),
    fallbacks: &["https://1rpc.io/eth", "https://eth.drpc.org"],
};
const BSC_RPC: Endpoints = Endpoints {
    primary: Some("https://bsc-rpc.publicnode.com"),
    fallbacks: &["https://1rpc.io/bnb", "https://bsc-dataseed.bnbchain.org"],
};
const ARBITRUM_RPC: Endpoints = Endpoints {
    primary: Some("https://arbitrum-one-rpc.publicnode.com"),
    fallbacks: &["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org"],
};
const ARBITRUM_SEPOLIA_RPC: Endpoints = Endpoints {
    primary: Some("https://sepolia-rollup.arbitrum.io/rpc"),
    fallbacks: &[
        "https://arbitrum-sepolia-rpc.publicnode.com",
        "https://arbitrum-sepolia.drpc.org",
    ],
};
const BASE_RPC: Endpoints = Endpoints {
    primary: Some("https://base-rpc.publicnode.com"),
    fallbacks: &["https://mainnet.base.org", "https://base.drpc.org"],
};
const BASE_SEPOLIA_RPC: Endpoints = Endpoints {
    primary: Some("https://base-sepolia-rpc.publicnode.com"),
    fallbacks: &["https://sepolia.base.org", "https://base-sepolia.drpc.org"],
};
const OPTIMISM_RPC: Endpoints = Endpoints {
    primary: Some("https://optimism-rpc.publicnode.com"),
    fallbacks: &["https://mainnet.optimism.io", "https://1rpc.io/op"],
};
const POLYGON_RPC: Endpoints = Endpoints {
    primary: Some("https://polygon-bor-rpc.publicnode.com"),
    fallbacks: &["https://1rpc.io/matic", "https://polygon.drpc.org"],
};
const TEMPO_RPC: Endpoints = Endpoints {
    primary: Some("https://rpc.tempo.xyz"),
    fallbacks: &["https://tempo-mainnet.drpc.org"],
};
const TEMPO_TESTNET_RPC: Endpoints = only("https://rpc.moderato.tempo.xyz");
const SOLANA_MAINNET_RPC: Endpoints = Endpoints {
    primary: Some("https://api.mainnet-beta.solana.com"),
    fallbacks: &["https://solana-rpc.publicnode.com"],
};
const SOLANA_DEVNET_RPC: Endpoints = only("https://api.devnet.solana.com");
const SOLANA_TESTNET_RPC: Endpoints = only("https://api.testnet.solana.com");

/// Built-in default RPC URLs that no longer work, by chain id. A stored
/// chain still using one of them (and no backups) is moved to the current
/// defaults when the configuration is loaded ([`upgrade_retired_defaults`]).
pub const RETIRED_DEFAULT_RPC_URLS: &[(u64, &str)] = &[
    (56, "https://bsc.drpc.org"),
    (1, "https://eth.llamarpc.com"),
    (4217, "https://rpc.presto.tempo.xyz"),
];

/// Built-in token deployments that named the wrong contract, as
/// `(token, network, address, decimals)`. A stored deployment still exactly
/// equal to one of them is moved to the current built-in deployment when the
/// configuration is loaded ([`upgrade_retired_deployments`]).
pub const RETIRED_DEFAULT_DEPLOYMENTS: &[(&str, &str, &str, u8)] = &[
    // USD1's Chainlink CCIP ERC-20 on Tempo, which holds no supply there;
    // USD1 on Tempo is the TIP-20.
    (
        "usd1",
        "tempo",
        "0x111111d2bf19e43c34263401e0cad979ed1cdb61",
        18,
    ),
];

/// Every chain name the service knows, aliases included.
pub const BUILTIN_CHAINS: &[BuiltinChain] = &[
    evm("eth", 1, ETH_RPC),
    evm("ethereum", 1, ETH_RPC),
    evm("mainnet", 1, ETH_RPC),
    evm("sepolia", 11_155_111, NONE),
    evm("base", 8453, BASE_RPC),
    evm("base-sepolia", 84_532, BASE_SEPOLIA_RPC),
    evm("optimism", 10, OPTIMISM_RPC),
    evm("arbitrum", 42_161, ARBITRUM_RPC),
    evm("arbitrum-sepolia", 421_614, ARBITRUM_SEPOLIA_RPC),
    evm("polygon", 137, POLYGON_RPC),
    evm("bsc", 56, BSC_RPC),
    solana("solana", 900_000_001, SOLANA_MAINNET_RPC),
    solana("solana-mainnet", 900_000_001, SOLANA_MAINNET_RPC),
    solana("solana-devnet", 900_000_002, SOLANA_DEVNET_RPC),
    solana("solana-testnet", 900_000_003, SOLANA_TESTNET_RPC),
    evm("tempo", 4217, TEMPO_RPC),
    evm("tempo-mainnet", 4217, TEMPO_RPC),
    evm("tempo-testnet", 42_431, TEMPO_TESTNET_RPC),
    evm("moderato", 42_431, TEMPO_TESTNET_RPC),
    evm("tempo-moderato", 42_431, TEMPO_TESTNET_RPC),
];

/// Chains in a fresh configuration, as `(builtin key, display name)`, in priority
/// order for mapping a chain id back to a seeded key.
pub const SEEDED_CHAINS: &[(&str, &str)] = &[
    ("eth", "ETH"),
    ("bsc", "BSC"),
    ("arbitrum", "Arbitrum"),
    ("arbitrum-sepolia", "Arbitrum Sepolia"),
    ("base", "Base"),
    ("base-sepolia", "Base Sepolia"),
    ("optimism", "Optimism"),
    ("polygon", "Polygon"),
    ("tempo", "Tempo"),
    ("tempo-testnet", "Tempo Testnet (Moderato)"),
    ("solana-mainnet", "Solana"),
    ("solana-devnet", "Solana Devnet"),
    ("solana-testnet", "Solana Testnet"),
];

/// The seeded chains before Arbitrum, Base, Optimism, and Polygon were added.
/// A configuration stored before paymentd recorded which seeded chains it
/// had been offered has seen these, so one missing from it was removed on
/// purpose and is not added back by [`add_missing_builtin_networks`].
pub const ORIGINAL_SEEDED_CHAINS: &[&str] = &[
    "eth",
    "bsc",
    "tempo",
    "tempo-testnet",
    "solana-mainnet",
    "solana-devnet",
    "solana-testnet",
];

/// Built-in token deployments added to chains that were already seeded, as
/// `(token, network)`. A configuration stored before paymentd recorded which
/// built-in deployments it had been offered has seen every other one, so
/// [`add_missing_builtin_deployments`] adds only these to it.
pub const NEW_SEEDED_DEPLOYMENTS: &[(&str, &str)] =
    &[("usdc", "eth"), ("usdc", "bsc"), ("usd1", "solana-mainnet")];

/// Every built-in token deployment on a seeded chain, as `token@network`.
pub fn seeded_deployment_keys() -> Vec<String> {
    let defaults = default_config();
    defaults
        .tokens
        .iter()
        .flat_map(|(token, profile)| {
            profile
                .chains
                .keys()
                .map(move |network| format!("{token}@{network}"))
        })
        .collect()
}

/// Adds the built-in token deployments `config` has not been offered
/// (`offered` holds `token@network` keys) on networks it has, creating the
/// token entry when it is missing. Never changes an existing deployment or
/// token profile. Returns the added `token@network` keys.
pub fn add_missing_builtin_deployments(
    config: &mut PaymentsConfig,
    offered: &[String],
) -> Vec<String> {
    let defaults = default_config();
    let mut added = Vec::new();
    for (token_key, token) in &defaults.tokens {
        for (network, deployment) in &token.chains {
            let key = format!("{token_key}@{network}");
            if offered.contains(&key) || !config.chains.contains_key(network) {
                continue;
            }
            let entry = config
                .tokens
                .entry(token_key.clone())
                .or_insert_with(|| TokenProfile {
                    chains: BTreeMap::new(),
                    ..token.clone()
                });
            if entry.chains.contains_key(network) {
                continue;
            }
            entry.chains.insert(network.clone(), deployment.clone());
            added.push(key);
        }
    }
    added
}

/// Network a payment uses when the caller names none.
pub const DEFAULT_NETWORK: &str = "bsc";
/// Asset a payment uses when the caller names none.
pub const DEFAULT_ASSET: &str = "usd1";

/// A token deployment in [`BUILTIN_TOKENS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinDeployment {
    /// Builtin chain key.
    pub chain: &'static str,
    /// Contract address or mint; `None` for the native coin.
    pub address: Option<&'static str>,
    /// Token decimals.
    pub decimals: u8,
}

/// A token the service knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinToken {
    /// Lookup key, for example `"usd1"`.
    pub key: &'static str,
    /// Display name.
    pub name: &'static str,
    /// Ticker symbol.
    pub symbol: &'static str,
    /// Suggested `(per_tx, daily, weekly)` limits in whole tokens.
    pub limits: Option<(&'static str, &'static str, &'static str)>,
    /// Deployments by builtin chain key.
    pub deployments: &'static [BuiltinDeployment],
}

const fn native(chain: &'static str, decimals: u8) -> BuiltinDeployment {
    BuiltinDeployment {
        chain,
        address: None,
        decimals,
    }
}

const fn contract(chain: &'static str, address: &'static str, decimals: u8) -> BuiltinDeployment {
    BuiltinDeployment {
        chain,
        address: Some(address),
        decimals,
    }
}

const USD_LIMITS: Option<(&str, &str, &str)> = Some(("10", "100", "700"));
const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
const PATHUSD: &str = "0x20c0000000000000000000000000000000000000";
const TEMPO_USD1: &str = "0x20c000000000000000000000111111111e910f0f";

/// Every token the service knows.
pub const BUILTIN_TOKENS: &[BuiltinToken] = &[
    BuiltinToken {
        key: "bnb",
        name: "BNB",
        symbol: "BNB",
        limits: Some(("0.01", "0.2", "1.4")),
        deployments: &[native("bsc", 18)],
    },
    BuiltinToken {
        key: "eth",
        name: "ETH",
        symbol: "ETH",
        limits: None,
        deployments: &[
            native("ethereum", 18),
            native("sepolia", 18),
            native("base", 18),
            native("base-sepolia", 18),
            native("optimism", 18),
            native("arbitrum", 18),
            native("arbitrum-sepolia", 18),
        ],
    },
    BuiltinToken {
        key: "pol",
        name: "Polygon",
        symbol: "POL",
        limits: Some(("20", "400", "2800")),
        deployments: &[native("polygon", 18)],
    },
    BuiltinToken {
        key: "sol",
        name: "Solana",
        symbol: "SOL",
        limits: Some(("0.05", "1", "7")),
        deployments: &[
            native("solana-mainnet", 9),
            native("solana-devnet", 9),
            native("solana-testnet", 9),
        ],
    },
    BuiltinToken {
        key: "usd",
        name: "USD",
        symbol: "USD",
        limits: USD_LIMITS,
        deployments: &[native("tempo", 6)],
    },
    BuiltinToken {
        key: "usd1",
        name: "USD1",
        symbol: "USD1",
        limits: USD_LIMITS,
        deployments: &[
            contract("eth", USD1, 18),
            contract("bsc", USD1, 18),
            // The TIP-20 (`currency()` "USD"), which MPP `tempo` charges pay in.
            contract("tempo", TEMPO_USD1, 6),
            contract(
                "solana-mainnet",
                "USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB",
                6,
            ),
            // USD1 has no deployment on Arbitrum, Base, Optimism, or Polygon.
        ],
    },
    BuiltinToken {
        key: "pathusd",
        name: "PATH/USD",
        symbol: "PATH/USD",
        limits: USD_LIMITS,
        deployments: &[
            contract("tempo", PATHUSD, 6),
            contract("tempo-testnet", PATHUSD, 6),
        ],
    },
    BuiltinToken {
        key: "usdc.e",
        name: "Bridged USDC (Stargate)",
        symbol: "USDC.e",
        limits: USD_LIMITS,
        deployments: &[
            contract("tempo", "0x20c000000000000000000000b9537d11c60e8b50", 6),
            contract(
                "tempo-testnet",
                "0x20c0000000000000000000009e8d7eb59b783726",
                6,
            ),
        ],
    },
    BuiltinToken {
        key: "usdc",
        name: "USDC",
        symbol: "USDC",
        limits: USD_LIMITS,
        deployments: &[
            // Circle's native USDC (EIP-3009, EIP-712 domain "USD Coin" / "2").
            contract("eth", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
            // BSC has no Circle-issued USDC: this is Binance-Peg USD Coin, 18
            // decimals and without EIP-3009 (MPP pays it with hash/transaction).
            contract("bsc", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),
            contract("arbitrum", "0xaf88d065e77c8cc2239327c5edb3a432268e5831", 6),
            contract(
                "arbitrum-sepolia",
                "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d",
                6,
            ),
            contract("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),
            contract(
                "base-sepolia",
                "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
                6,
            ),
            contract("optimism", "0x0b2c639c533813f4aa9d7837caf62653d097ff85", 6),
            contract("polygon", "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", 6),
            contract(
                "solana-mainnet",
                "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                6,
            ),
            contract(
                "solana-devnet",
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                6,
            ),
        ],
    },
];

/// Looks up a builtin chain by key (aliases included).
#[must_use]
pub fn builtin_chain(key: &str) -> Option<&'static BuiltinChain> {
    BUILTIN_CHAINS.iter().find(|chain| chain.key == key)
}

/// The configuration a fresh install starts with.
#[must_use]
pub fn default_config() -> PaymentsConfig {
    let mut chains = BTreeMap::new();
    for (key, name) in SEEDED_CHAINS {
        if let Some(builtin) = builtin_chain(key) {
            chains.insert(
                (*key).to_string(),
                ChainProfile {
                    chain_id: builtin.chain_id,
                    name: (*name).to_string(),
                    family: builtin.family,
                    rpc_url: builtin.rpc_url.map(str::to_string),
                    fallback_rpc_urls: urls(builtin.fallback_rpc_urls),
                },
            );
        }
    }

    let mut tokens = BTreeMap::new();
    for token in BUILTIN_TOKENS {
        let mut deployments = BTreeMap::new();
        for deployment in token.deployments {
            let Some(chain_id) = builtin_chain(deployment.chain).map(|chain| chain.chain_id) else {
                continue;
            };
            let Some(seeded_key) = seeded_key_for_chain_id(chain_id) else {
                continue;
            };
            deployments
                .entry(seeded_key.to_string())
                .or_insert_with(|| TokenChainProfile {
                    chain_id,
                    is_native: deployment.address.is_none(),
                    address: deployment.address.map(str::to_string),
                    decimals: deployment.decimals,
                });
        }
        if deployments.is_empty() {
            continue;
        }
        tokens.insert(
            token.key.to_string(),
            TokenProfile {
                name: token.name.to_string(),
                symbol: token.symbol.to_string(),
                recommended_limits: token.limits.map(|(per_tx, daily, weekly)| TokenLimits {
                    per_tx: per_tx.to_string(),
                    daily: daily.to_string(),
                    weekly: weekly.to_string(),
                }),
                chains: deployments,
            },
        );
    }

    PaymentsConfig {
        default_network: DEFAULT_NETWORK.to_string(),
        default_asset: DEFAULT_ASSET.to_string(),
        chains,
        tokens,
    }
}

/// Moves every chain that still uses a retired built-in default RPC URL
/// ([`RETIRED_DEFAULT_RPC_URLS`]) to the current default endpoints, and
/// returns the keys of the chains it changed.
///
/// Only an exact match is upgraded: a built-in chain key with the built-in
/// chain id, an `rpc_url` equal to that chain's retired default, and no
/// `fallback_rpc_urls`. Anything an operator set is left alone.
pub fn upgrade_retired_defaults(config: &mut PaymentsConfig) -> Vec<String> {
    let mut upgraded = Vec::new();
    for (key, chain) in &mut config.chains {
        let Some(builtin) = builtin_chain(key) else {
            continue;
        };
        let Some(current) = builtin.rpc_url else {
            continue;
        };
        let retired = RETIRED_DEFAULT_RPC_URLS.iter().any(|(chain_id, url)| {
            *chain_id == chain.chain_id && chain.rpc_url.as_deref() == Some(*url)
        });
        if builtin.chain_id != chain.chain_id || !retired || !chain.fallback_rpc_urls.is_empty() {
            continue;
        }
        chain.rpc_url = Some(current.to_string());
        chain.fallback_rpc_urls = urls(builtin.fallback_rpc_urls);
        upgraded.push(key.clone());
    }
    upgraded
}

/// Moves every token deployment that is still a retired built-in default
/// ([`RETIRED_DEFAULT_DEPLOYMENTS`]) to the current built-in deployment, and
/// returns the ones it changed as `token@network`.
///
/// Only an exact match is upgraded (address in any case, decimals, and the
/// network's built-in chain id); anything an operator set is left alone.
pub fn upgrade_retired_deployments(config: &mut PaymentsConfig) -> Vec<String> {
    let defaults = default_config();
    let mut upgraded = Vec::new();
    for (token, network, address, decimals) in RETIRED_DEFAULT_DEPLOYMENTS {
        let Some(current) = defaults
            .tokens
            .get(*token)
            .and_then(|profile| profile.chains.get(*network))
        else {
            continue;
        };
        let Some(stored) = config
            .tokens
            .get_mut(*token)
            .and_then(|profile| profile.chains.get_mut(*network))
        else {
            continue;
        };
        let retired = !stored.is_native
            && stored.chain_id == current.chain_id
            && stored.decimals == *decimals
            && stored
                .address
                .as_deref()
                .is_some_and(|stored| stored.eq_ignore_ascii_case(address));
        if retired {
            *stored = current.clone();
            upgraded.push(format!("{token}@{network}"));
        }
    }
    upgraded
}

/// Adds every seeded chain ([`SEEDED_CHAINS`]) that `config` lacks, with the
/// built-in token deployments on it, and returns the keys of the chains it
/// added.
///
/// A seeded chain is skipped when its key is in `offered` (the configuration
/// had it before, so it was removed on purpose), when `config` has a chain
/// under that key, or when another chain already uses its chain id. A
/// deployment goes under the token's existing entry (created from the
/// built-in profile when the token is missing) and never replaces one.
/// Existing chains, RPC URLs, token profiles, and deployments are never
/// changed.
pub fn add_missing_builtin_networks(
    config: &mut PaymentsConfig,
    offered: &[String],
) -> Vec<String> {
    let defaults = default_config();
    let mut added = Vec::new();
    for (key, _) in SEEDED_CHAINS {
        let Some(chain) = defaults.chains.get(*key) else {
            continue;
        };
        let present = offered.iter().any(|offered| offered == key)
            || config.chains.contains_key(*key)
            || config
                .chains
                .values()
                .any(|existing| existing.chain_id == chain.chain_id);
        if present {
            continue;
        }
        config.chains.insert((*key).to_string(), chain.clone());
        for (token_key, token) in &defaults.tokens {
            let Some(deployment) = token.chains.get(*key) else {
                continue;
            };
            config
                .tokens
                .entry(token_key.clone())
                .or_insert_with(|| TokenProfile {
                    chains: BTreeMap::new(),
                    ..token.clone()
                })
                .chains
                .entry((*key).to_string())
                .or_insert_with(|| deployment.clone());
        }
        added.push((*key).to_string());
    }
    added
}

fn urls(values: &[&str]) -> Vec<String> {
    values.iter().map(|url| (*url).to_string()).collect()
}

fn seeded_key_for_chain_id(chain_id: u64) -> Option<&'static str> {
    SEEDED_CHAINS
        .iter()
        .map(|(key, _)| *key)
        .find(|key| builtin_chain(key).is_some_and(|chain| chain.chain_id == chain_id))
}
