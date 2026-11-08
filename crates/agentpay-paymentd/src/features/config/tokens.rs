//! `AddToken` and `LookupToken`: an ERC-20 token or SPL mint, with its
//! decimals (and on EVM chains its symbol) read from the chain, added to the
//! configuration or just reported.
//!
//! Both share [`resolve`]: checking the request and reading the chain.
//! `LookupToken` stops there and changes nothing. The rules are documented
//! on `agentpay_api::payments::AddTokenParams` and `LookupTokenParams`. For
//! `AddToken` the request is checked against a snapshot of the configuration, the chain is
//! read without holding the configuration lock, and the token is then merged
//! into the current configuration under the lock
//! ([`ConfigStore::update`](crate::config::ConfigStore::update)), so a
//! concurrent `SetConfig` or `AddToken` is never lost. Error messages name
//! the network but never the RPC URL, which may embed an API key.

use std::collections::BTreeMap;
use std::str::FromStr;

use agentpay_api::payments::{
    AddTokenParams, AddTokenResult, ChainFamily, ChainProfile, LookupTokenParams, PaymentsConfig,
    TokenChainProfile, TokenInfo, TokenProfile,
};
use agentpay_domain::{EvmAddress, SolanaAddress};

use crate::chains::evm::{to_alloy_address, EvmProvider};
use crate::chains::solana::accounts::{parse_mint, system_program_id};
use crate::chains::solana::{SolanaChain, SolanaProvider};
use crate::config::MAX_DECIMALS;
use crate::error::PaymentsError;
use crate::features::solana::pubkey;
use crate::state::AppState;

/// Longest accepted symbol, as for symbols read from the chain.
const MAX_SYMBOL_LEN: usize = 32;
/// Characters of the address appended to a token key that is taken.
const KEY_SUFFIX_LEN: usize = 6;
/// Token key for a symbol without any character a key allows.
const FALLBACK_KEY: &str = "token";
/// EVM addresses that stand for the native coin rather than a contract.
const EVM_NATIVE_PLACEHOLDERS: &[&str] = &[
    "0x0000000000000000000000000000000000000000",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
];

/// Handles `AddToken`.
pub(super) async fn add_token(
    state: &AppState,
    params: AddTokenParams,
) -> Result<AddTokenResult, PaymentsError> {
    let snapshot = state.config.get().await;
    let request = Request::parse(
        &snapshot,
        &params.network,
        &params.address,
        params.symbol,
        params.decimals,
    )?;
    if let Some(key) = existing_key(&snapshot, &request.network, &request.address) {
        return result(snapshot, &request.network, key, false, false);
    }
    let Resolved {
        decimals,
        symbol,
        verified,
    } = resolve(state, &request).await?;
    let (config, (key, added)) = state
        .config
        .update(|current| merge(current, &request, &symbol, decimals))
        .await?;
    result(config, &request.network, key, verified, added)
}

/// Handles `LookupToken`: [`resolve`] only; the configuration is read, never
/// changed, and a configured token is read from the chain like any other.
pub(super) async fn lookup_token(
    state: &AppState,
    params: LookupTokenParams,
) -> Result<TokenInfo, PaymentsError> {
    let snapshot = state.config.get().await;
    let request = Request::parse(
        &snapshot,
        &params.network,
        &params.address,
        params.symbol,
        params.decimals,
    )?;
    let Resolved {
        decimals,
        symbol,
        verified,
    } = resolve(state, &request).await?;
    Ok(TokenInfo {
        network: request.network,
        chain_id: request.chain.chain_id,
        address: request.address,
        symbol,
        decimals,
        verified_on_chain: verified,
    })
}

/// A token's metadata, from the chain or (when it cannot be read) the request.
struct Resolved {
    decimals: u8,
    symbol: String,
    /// Whether `decimals` were read from the chain.
    verified: bool,
}

/// Reads the token from the chain and applies the request's `symbol` and
/// `decimals` (the shared half of `AddToken` and `LookupToken`).
async fn resolve(state: &AppState, request: &Request) -> Result<Resolved, PaymentsError> {
    let on_chain = read_chain(state, request).await?;
    let (decimals, symbol, verified) = metadata(request, on_chain)?;
    Ok(Resolved {
        decimals,
        symbol,
        verified,
    })
}

/// A checked `AddToken` or `LookupToken` request.
struct Request {
    /// The chain key, lower case.
    network: String,
    /// Its configuration when the call started.
    chain: ChainProfile,
    /// The contract (lower case) or mint.
    address: String,
    /// The requested symbol, trimmed; `None` when absent or empty.
    symbol: Option<String>,
    /// The requested decimals.
    decimals: Option<u8>,
}

impl Request {
    fn parse(
        config: &PaymentsConfig,
        network: &str,
        address: &str,
        symbol: Option<String>,
        decimals: Option<u8>,
    ) -> Result<Self, PaymentsError> {
        let network = network.trim().to_ascii_lowercase();
        let chain = config.chains.get(&network).cloned().ok_or_else(|| {
            PaymentsError::InvalidRequest(format!(
                "network '{}' is not configured",
                network.escape_default()
            ))
        })?;
        let address = normalized_address(&network, chain.family, address.trim())?;
        let symbol = symbol
            .map(|symbol| symbol.trim().to_string())
            .filter(|symbol| !symbol.is_empty());
        if let Some(symbol) = &symbol {
            if symbol.chars().count() > MAX_SYMBOL_LEN || symbol.chars().any(char::is_control) {
                return Err(PaymentsError::InvalidRequest(format!(
                    "symbol must be 1 to {MAX_SYMBOL_LEN} characters without control characters"
                )));
            }
        }
        if let Some(decimals) = decimals {
            if decimals > MAX_DECIMALS {
                return Err(PaymentsError::InvalidRequest(format!(
                    "decimals must be at most {MAX_DECIMALS}"
                )));
            }
        }
        if chain.family == ChainFamily::Solana && symbol.is_none() {
            return Err(PaymentsError::InvalidRequest(
                "a symbol is required for Solana tokens: SPL mints have no on-chain symbol".into(),
            ));
        }
        Ok(Self {
            network,
            chain,
            address,
            symbol,
            decimals,
        })
    }
}

/// The address in its stored form; native coins are refused.
fn normalized_address(
    network: &str,
    family: ChainFamily,
    address: &str,
) -> Result<String, PaymentsError> {
    let native = || {
        PaymentsError::InvalidRequest(format!(
            "the address stands for the native coin of network '{network}'; AddToken adds \
             token contracts and mints only"
        ))
    };
    match family {
        ChainFamily::Evm => {
            let parsed = EvmAddress::from_str(address).map_err(|_| {
                PaymentsError::InvalidRequest(format!(
                    "address must be an ERC-20 contract address (0x + 40 hex characters) on \
                     network '{network}'"
                ))
            })?;
            if EVM_NATIVE_PLACEHOLDERS.contains(&parsed.as_str()) {
                return Err(native());
            }
            Ok(parsed.as_str().to_string())
        }
        ChainFamily::Solana => {
            let parsed = SolanaAddress::from_str(address).map_err(|_| {
                PaymentsError::InvalidRequest(format!(
                    "address must be a base58 SPL mint on network '{network}'"
                ))
            })?;
            if pubkey(&parsed)? == system_program_id() {
                return Err(native());
            }
            Ok(parsed.as_str().to_string())
        }
    }
}

/// The key of the token that already has a contract deployment on
/// `network` at `address` (both in stored form).
fn existing_key(config: &PaymentsConfig, network: &str, address: &str) -> Option<String> {
    config.tokens.iter().find_map(|(key, token)| {
        let deployment = token.chains.get(network)?;
        (!deployment.is_native && deployment.address.as_deref() == Some(address))
            .then(|| key.clone())
    })
}

/// What the chain says about the token.
enum OnChain {
    /// The chain was read.
    Read {
        /// The token's decimals.
        decimals: u8,
        /// Its on-chain symbol, if it has a usable one (EVM only).
        symbol: Option<String>,
    },
    /// The chain could not be read; the reason never quotes the RPC URL.
    Unreadable(String),
}

/// Reads the token from the chain. `ChainRpc` failures (no `rpc_url`, an
/// unreachable or wrong-chain endpoint, a failing call) mean "unreadable";
/// every other error is final.
async fn read_chain(state: &AppState, request: &Request) -> Result<OnChain, PaymentsError> {
    let read = match request.chain.family {
        ChainFamily::Evm => read_evm(state, request).await,
        ChainFamily::Solana => read_solana(state, request).await,
    };
    match read {
        Err(PaymentsError::ChainRpc(reason)) => Ok(OnChain::Unreadable(reason)),
        other => other,
    }
}

fn no_rpc_url(network: &str) -> PaymentsError {
    PaymentsError::ChainRpc(format!("network '{network}' has no rpc_url configured"))
}

/// `decimals()` and, unless the request names a symbol, `symbol()` of an
/// ERC-20 contract, after checking that the address holds code.
async fn read_evm(state: &AppState, request: &Request) -> Result<OnChain, PaymentsError> {
    if request.chain.rpc_url.is_none() {
        return Err(no_rpc_url(&request.network));
    }
    let token = EvmAddress::from_str(&request.address)
        .map_err(|_| PaymentsError::Internal("a normalized address did not parse".into()))
        .and_then(|address| to_alloy_address(&address))?;
    let evm = state.chains.get::<EvmProvider>()?;
    let rpc = evm.connect(&request.network, &request.chain).await?;
    if rpc.code(token).await?.is_empty() {
        return Err(PaymentsError::InvalidRequest(format!(
            "no contract is deployed at this address on network '{}'",
            request.network
        )));
    }
    let decimals = rpc.erc20_decimals(token).await?;
    let symbol = match request.symbol {
        Some(_) => None,
        None => rpc.erc20_symbol(token).await,
    };
    Ok(OnChain::Read { decimals, symbol })
}

/// The decimals of an SPL Token or Token-2022 mint.
async fn read_solana(state: &AppState, request: &Request) -> Result<OnChain, PaymentsError> {
    let rpc_url = request
        .chain
        .rpc_url
        .clone()
        .ok_or_else(|| no_rpc_url(&request.network))?;
    let mint = SolanaAddress::from_str(&request.address)
        .map_err(|_| PaymentsError::Internal("a normalized mint did not parse".into()))
        .and_then(|address| pubkey(&address))?;
    let provider = state.chains.get::<SolanaProvider>()?;
    let chain = SolanaChain {
        key: request.network.clone(),
        chain_id: request.chain.chain_id,
        rpc_url,
        fallback_rpc_urls: request.chain.fallback_rpc_urls.clone(),
    };
    let rpc = provider.rpc(&chain).await?;
    let account = rpc.account(&mint).await?.ok_or_else(|| {
        PaymentsError::InvalidRequest(format!(
            "the mint account does not exist on network '{}'",
            request.network
        ))
    })?;
    let mint = parse_mint(&account)?;
    Ok(OnChain::Read {
        decimals: mint.decimals,
        symbol: None,
    })
}

/// The decimals, symbol, and whether the decimals were read from the chain.
fn metadata(request: &Request, on_chain: OnChain) -> Result<(u8, String, bool), PaymentsError> {
    let network = &request.network;
    let (decimals, chain_symbol, verified) = match (on_chain, request.decimals) {
        (OnChain::Read { decimals, .. }, Some(given)) if given != decimals => {
            return Err(PaymentsError::InvalidRequest(format!(
                "decimals {given} differ from the {decimals} the token reports on network \
                 '{network}'; omit decimals to use the chain's value"
            )))
        }
        (OnChain::Read { decimals, symbol }, _) => (decimals, symbol, true),
        (OnChain::Unreadable(_), Some(given)) => (given, None, false),
        (OnChain::Unreadable(reason), None) => {
            return Err(PaymentsError::ChainRpc(format!(
                "{reason}; set a working RPC URL with `agentpay config set \
                 chains.{network}.rpc_url <url>`, or pass decimals to add the token without \
                 reading the chain"
            )))
        }
    };
    let symbol = request.symbol.clone().or(chain_symbol).ok_or_else(|| {
        PaymentsError::InvalidRequest(if verified {
            "the token has no readable symbol(); pass a symbol".to_string()
        } else {
            format!("network '{network}' could not be read; pass a symbol along with decimals")
        })
    })?;
    Ok((decimals, symbol, verified))
}

/// `current` with the token added, and its key and whether anything was
/// added. Pure: runs under the configuration lock.
fn merge(
    current: &PaymentsConfig,
    request: &Request,
    symbol: &str,
    decimals: u8,
) -> Result<(PaymentsConfig, (String, bool)), PaymentsError> {
    let network = &request.network;
    if let Some(key) = existing_key(current, network, &request.address) {
        return Ok((current.clone(), (key, false)));
    }
    if current.chains.get(network).map(|chain| chain.chain_id) != Some(request.chain.chain_id) {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{network}' changed while the token was being read; try again"
        )));
    }
    let deployment = TokenChainProfile {
        chain_id: request.chain.chain_id,
        is_native: false,
        address: Some(request.address.clone()),
        decimals,
    };
    let base = token_key(symbol);
    let suffixed = format!("{base}-{}", key_suffix(&request.address));
    let mut config = current.clone();
    for key in [&base, &suffixed] {
        match config.tokens.get_mut(key) {
            None => {
                let token = TokenProfile {
                    name: symbol.to_string(),
                    symbol: symbol.to_string(),
                    recommended_limits: None,
                    chains: BTreeMap::from([(network.clone(), deployment)]),
                };
                config.tokens.insert(key.clone(), token);
                return Ok((config, (key.clone(), true)));
            }
            Some(token) if !token.chains.contains_key(network) => {
                token.chains.insert(network.clone(), deployment);
                return Ok((config, (key.clone(), true)));
            }
            Some(_) => {}
        }
    }
    Err(PaymentsError::InvalidRequest(format!(
        "tokens '{base}' and '{suffixed}' already have other deployments on network \
         '{network}'; rename one with SetConfig"
    )))
}

/// The token key for `symbol`: lower case, with every run of characters
/// outside `[a-z0-9._-]` replaced by `-` (dropped at either end).
fn token_key(symbol: &str) -> String {
    let mut key = String::new();
    let mut gap = false;
    for c in symbol.chars().map(|c| c.to_ascii_lowercase()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
            if gap && !key.is_empty() {
                key.push('-');
            }
            gap = false;
            key.push(c);
        } else {
            gap = true;
        }
    }
    if key.is_empty() {
        FALLBACK_KEY.to_string()
    } else {
        key
    }
}

/// The first characters of the address after `0x` (or of the mint), lower case.
fn key_suffix(address: &str) -> String {
    address
        .strip_prefix("0x")
        .unwrap_or(address)
        .chars()
        .take(KEY_SUFFIX_LEN)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// The result for token `key` in the stored `config`.
fn result(
    config: PaymentsConfig,
    network: &str,
    key: String,
    verified_on_chain: bool,
    added: bool,
) -> Result<AddTokenResult, PaymentsError> {
    let token = config.tokens.get(&key).cloned().ok_or_else(|| {
        PaymentsError::Internal("the added token is missing from the configuration".into())
    })?;
    let deployment = token.chains.get(network).cloned().ok_or_else(|| {
        PaymentsError::Internal("the added deployment is missing from the configuration".into())
    })?;
    Ok(AddTokenResult {
        key,
        token,
        network: network.to_string(),
        deployment,
        verified_on_chain,
        added,
        config,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn token_keys_keep_only_key_characters() {
        assert_eq!(token_key("USDC"), "usdc");
        assert_eq!(token_key("USDC.e"), "usdc.e");
        assert_eq!(token_key("PATH/USD"), "path-usd");
        assert_eq!(token_key(" My  Token! "), "my-token");
        assert_eq!(token_key("USD₮0"), "usd-0");
        assert_eq!(token_key("₮"), FALLBACK_KEY);
    }

    #[test]
    fn key_suffixes_come_from_the_address() {
        assert_eq!(
            key_suffix("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d"),
            "8ac76a"
        );
        assert_eq!(
            key_suffix("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            "epjfwd"
        );
    }
}
