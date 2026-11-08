//! Validation and normalization of a [`PaymentsConfig`].
//!
//! The rules are documented on `agentpay_api::payments::config`. Messages
//! name keys and fields but never echo an RPC URL, which may embed an API key.

use std::collections::BTreeMap;
use std::net::IpAddr;

use agentpay_api::payments::{ChainFamily, ChainProfile, PaymentsConfig, TokenChainProfile};
use agentpay_domain::{is_solana_chain_id, EvmAddress, SolanaAddress};

/// Maximum number of chains and of tokens.
pub const MAX_ENTRIES: usize = 256;
/// Maximum token decimals.
pub const MAX_DECIMALS: u8 = 36;
/// Largest chain id a JSON number holds exactly (2^53 - 1).
const MAX_CHAIN_ID: u64 = (1 << 53) - 1;
/// Maximum length of names, symbols, and limit strings.
const MAX_TEXT_LEN: usize = 128;
/// Maximum length of an RPC URL.
const MAX_URL_LEN: usize = 2048;
/// Maximum number of backup RPC URLs per chain.
pub const MAX_FALLBACK_RPC_URLS: usize = 4;

/// Checks `config` and returns its normalized form (EVM addresses lower case).
pub fn validate(config: &PaymentsConfig) -> Result<PaymentsConfig, String> {
    if config.chains.len() > MAX_ENTRIES || config.tokens.len() > MAX_ENTRIES {
        return Err(format!(
            "at most {MAX_ENTRIES} chains and {MAX_ENTRIES} tokens"
        ));
    }
    let mut normalized = config.clone();
    for (key, chain) in &config.chains {
        check_key("chain", key)?;
        check_chain(key, chain)?;
    }
    for (key, token) in &mut normalized.tokens {
        check_key("token", key)?;
        check_text(&format!("token '{key}' name"), &token.name)?;
        check_text(&format!("token '{key}' symbol"), &token.symbol)?;
        if let Some(limits) = &token.recommended_limits {
            for (field, value) in [
                ("per_tx", &limits.per_tx),
                ("daily", &limits.daily),
                ("weekly", &limits.weekly),
            ] {
                if !is_decimal(value) {
                    return Err(format!(
                        "token '{key}' recommended_limits.{field} must be a non-negative decimal"
                    ));
                }
            }
        }
        for (chain_key, deployment) in &mut token.chains {
            let label = format!("token '{key}' chain '{chain_key}'");
            check_deployment(&label, &config.chains, chain_key, deployment)?;
        }
    }
    check_defaults(&normalized)?;
    Ok(normalized)
}

fn check_key(kind: &str, key: &str) -> Result<(), String> {
    let valid = !key.is_empty()
        && key.len() <= 64
        && key.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{kind} key '{}' must be 1 to 64 characters of [a-z0-9._-]",
            key.escape_default()
        ))
    }
}

fn check_text(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_LEN || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} must be 1 to {MAX_TEXT_LEN} characters without control characters"
        ));
    }
    Ok(())
}

fn check_chain(key: &str, chain: &ChainProfile) -> Result<(), String> {
    if chain.chain_id == 0 || chain.chain_id > MAX_CHAIN_ID {
        return Err(format!(
            "chain '{key}' chain_id must be between 1 and 2^53 - 1"
        ));
    }
    let expected = if is_solana_chain_id(chain.chain_id) {
        ChainFamily::Solana
    } else {
        ChainFamily::Evm
    };
    if chain.family != expected {
        return Err(format!(
            "chain '{key}' family must be {} for chain_id {}",
            family_name(expected),
            chain.chain_id
        ));
    }
    check_text(&format!("chain '{key}' name"), &chain.name)?;
    if let Some(url) = &chain.rpc_url {
        check_rpc_url(url).map_err(|reason| format!("chain '{key}' rpc_url {reason}"))?;
    }
    check_fallback_rpc_urls(key, chain)
}

/// At most [`MAX_FALLBACK_RPC_URLS`], each valid like `rpc_url`, all
/// distinct and different from `rpc_url`, and only alongside an `rpc_url`.
/// Messages name the position, never the URL.
fn check_fallback_rpc_urls(key: &str, chain: &ChainProfile) -> Result<(), String> {
    let fallbacks = &chain.fallback_rpc_urls;
    if fallbacks.is_empty() {
        return Ok(());
    }
    if chain.rpc_url.is_none() {
        return Err(format!(
            "chain '{key}' fallback_rpc_urls needs an rpc_url to fall back from"
        ));
    }
    if fallbacks.len() > MAX_FALLBACK_RPC_URLS {
        return Err(format!(
            "chain '{key}' fallback_rpc_urls holds at most {MAX_FALLBACK_RPC_URLS} URLs"
        ));
    }
    for (index, url) in fallbacks.iter().enumerate() {
        let label = format!("chain '{key}' fallback_rpc_urls[{index}]");
        check_rpc_url(url).map_err(|reason| format!("{label} {reason}"))?;
        if chain.rpc_url.as_deref() == Some(url.as_str()) {
            return Err(format!("{label} repeats rpc_url"));
        }
        if fallbacks[..index].contains(url) {
            return Err(format!("{label} repeats an earlier fallback"));
        }
    }
    Ok(())
}

fn family_name(family: ChainFamily) -> &'static str {
    match family {
        ChainFamily::Evm => "evm",
        ChainFamily::Solana => "solana",
    }
}

/// `https`, or `http` to a loopback host; no embedded credentials.
pub fn check_rpc_url(value: &str) -> Result<(), String> {
    if value.len() > MAX_URL_LEN {
        return Err(format!("must be at most {MAX_URL_LEN} characters"));
    }
    let url = url::Url::parse(value).map_err(|_| "must be a valid http(s) URL".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not include embedded credentials".to_string());
    }
    let host = url.host().ok_or("must include a host")?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&host) => Ok(()),
        "http" => Err("must use https unless it targets a loopback address".to_string()),
        _ => Err("must use https or loopback http".to_string()),
    }
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        url::Host::Ipv4(addr) => IpAddr::V4(*addr).is_loopback(),
        url::Host::Ipv6(addr) => IpAddr::V6(*addr).is_loopback(),
    }
}

fn check_deployment(
    label: &str,
    chains: &BTreeMap<String, ChainProfile>,
    chain_key: &str,
    deployment: &mut TokenChainProfile,
) -> Result<(), String> {
    let chain = chains
        .get(chain_key)
        .ok_or_else(|| format!("{label} does not name a configured chain"))?;
    if deployment.chain_id != chain.chain_id {
        return Err(format!(
            "{label} chain_id {} differs from the chain's {}",
            deployment.chain_id, chain.chain_id
        ));
    }
    if deployment.decimals > MAX_DECIMALS {
        return Err(format!("{label} decimals must be at most {MAX_DECIMALS}"));
    }
    match (deployment.is_native, deployment.address.as_deref()) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err(format!(
            "{label} must not set address when is_native is true"
        )),
        (false, None) => Err(format!("{label} needs an address when is_native is false")),
        (false, Some(address)) => {
            let normalized = match chain.family {
                ChainFamily::Evm => address
                    .parse::<EvmAddress>()
                    .map(|parsed| parsed.to_string())
                    .map_err(|_| format!("{label} address must be an EVM address")),
                ChainFamily::Solana => address
                    .parse::<SolanaAddress>()
                    .map(|parsed| parsed.to_string())
                    .map_err(|_| format!("{label} address must be a base58 Solana address")),
            }?;
            deployment.address = Some(normalized);
            Ok(())
        }
    }
}

fn check_defaults(config: &PaymentsConfig) -> Result<(), String> {
    let network = &config.default_network;
    let asset = &config.default_asset;
    if !config.chains.contains_key(network) {
        return Err(format!(
            "default_network '{}' is not a configured chain",
            network.escape_default()
        ));
    }
    let token = config.tokens.get(asset).ok_or_else(|| {
        format!(
            "default_asset '{}' is not a configured token",
            asset.escape_default()
        )
    })?;
    if !token.chains.contains_key(network) {
        return Err(format!(
            "default_asset '{asset}' has no entry for default_network '{network}'"
        ));
    }
    Ok(())
}

/// A non-negative decimal: digits, optionally `.` and more digits.
fn is_decimal(value: &str) -> bool {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, "0"));
    value.len() <= MAX_TEXT_LEN
        && !whole.is_empty()
        && !fraction.is_empty()
        && whole.bytes().all(|b| b.is_ascii_digit())
        && fraction.bytes().all(|b| b.is_ascii_digit())
}
