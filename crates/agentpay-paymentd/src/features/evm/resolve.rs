//! Resolving request parameters against the configuration: networks, assets,
//! amounts, and transaction options.

use std::str::FromStr;
use std::time::Duration;

use agentpay_api::payments::{ChainFamily, ChainProfile, EvmAsset, EvmTxOptions, PaymentsConfig};
use agentpay_domain::EvmAddress;
use alloy_primitives::U256;

use crate::error::PaymentsError;
use crate::signer::{ApprovalWait, MAX_APPROVAL_WAIT};

/// Default `receipt_timeout_secs`.
pub(super) const DEFAULT_RECEIPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest `receipt_timeout_secs`; larger values are capped.
pub(super) const MAX_RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);
/// Decimals assumed for a native coin the configuration does not describe.
const DEFAULT_NATIVE_DECIMALS: u8 = 18;
/// Largest number of decimals an amount can be parsed with (10^38 < 2^128).
const MAX_PARSE_DECIMALS: u8 = 38;

/// A configured EVM chain.
#[derive(Debug, Clone)]
pub(super) struct Network {
    /// The chain key.
    pub(super) key: String,
    /// Its configuration.
    pub(super) chain: ChainProfile,
}

/// `requested`, or the configured default network; must be an EVM chain.
pub(super) fn network(
    config: &PaymentsConfig,
    requested: Option<&str>,
) -> Result<Network, PaymentsError> {
    let key = requested
        .map(|key| key.trim().to_ascii_lowercase())
        .unwrap_or_else(|| config.default_network.clone());
    let chain = config.chains.get(&key).ok_or_else(|| {
        PaymentsError::InvalidRequest(format!(
            "network '{}' is not configured",
            key.escape_default()
        ))
    })?;
    if chain.family != ChainFamily::Evm {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{key}' is not an EVM chain"
        )));
    }
    Ok(Network {
        key,
        chain: chain.clone(),
    })
}

/// What an `asset` parameter names on a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AssetChoice {
    /// A configured token or native coin, with its metadata.
    Known(EvmAsset),
    /// An ERC-20 contract that is not configured; metadata must come from the chain.
    Unconfigured(EvmAddress),
}

/// Resolves `requested` (a token key or contract address), or the
/// configured default asset, on `network`.
pub(super) fn asset(
    config: &PaymentsConfig,
    network: &Network,
    requested: Option<&str>,
) -> Result<AssetChoice, PaymentsError> {
    let requested = requested
        .map(str::trim)
        .unwrap_or(config.default_asset.as_str());
    if requested.starts_with("0x") || requested.starts_with("0X") {
        let address = EvmAddress::from_str(requested).map_err(|_| {
            PaymentsError::InvalidRequest("asset is not a valid EVM address".into())
        })?;
        return Ok(configured_contract(config, network, &address)
            .map_or(AssetChoice::Unconfigured(address), AssetChoice::Known));
    }
    let key = requested.to_ascii_lowercase();
    let token = config.tokens.get(&key).ok_or_else(|| {
        PaymentsError::InvalidRequest(format!(
            "asset '{}' is not configured",
            key.escape_default()
        ))
    })?;
    let deployment = token.chains.get(&network.key).ok_or_else(|| {
        PaymentsError::InvalidRequest(format!(
            "asset '{key}' has no deployment on network '{}'",
            network.key
        ))
    })?;
    let token_address = match (&deployment.address, deployment.is_native) {
        (_, true) => None,
        (Some(address), false) => Some(EvmAddress::from_str(address).map_err(|_| {
            PaymentsError::InvalidRequest(format!("asset '{key}' has an invalid contract address"))
        })?),
        (None, false) => {
            return Err(PaymentsError::InvalidRequest(format!(
                "asset '{key}' has no contract address on network '{}'",
                network.key
            )))
        }
    };
    Ok(AssetChoice::Known(EvmAsset {
        key: Some(key),
        symbol: token.symbol.clone(),
        decimals: deployment.decimals,
        token: token_address,
    }))
}

/// The configured token whose deployment on `network` is `address`.
fn configured_contract(
    config: &PaymentsConfig,
    network: &Network,
    address: &EvmAddress,
) -> Option<EvmAsset> {
    config.tokens.iter().find_map(|(key, token)| {
        let deployment = token.chains.get(&network.key)?;
        let matches = !deployment.is_native
            && deployment
                .address
                .as_deref()
                .is_some_and(|configured| configured.eq_ignore_ascii_case(address.as_str()));
        matches.then(|| EvmAsset {
            key: Some(key.clone()),
            symbol: token.symbol.clone(),
            decimals: deployment.decimals,
            token: Some(address.clone()),
        })
    })
}

/// The native coin of `network`: the configured native deployment, else 18
/// decimals with the symbol `"native"`.
pub(super) fn native_asset(config: &PaymentsConfig, network: &Network) -> EvmAsset {
    config
        .tokens
        .iter()
        .find_map(|(key, token)| {
            let deployment = token.chains.get(&network.key)?;
            deployment.is_native.then(|| EvmAsset {
                key: Some(key.clone()),
                symbol: token.symbol.clone(),
                decimals: deployment.decimals,
                token: None,
            })
        })
        .unwrap_or_else(|| EvmAsset {
            key: None,
            symbol: "native".into(),
            decimals: DEFAULT_NATIVE_DECIMALS,
            token: None,
        })
}

/// Parses a positive decimal `amount` in whole units into base units
/// (ported from `parseConfiguredAmount`). Returns the trimmed amount too.
pub(crate) fn parse_amount(amount: &str, decimals: u8) -> Result<(String, u128), PaymentsError> {
    let invalid = || {
        PaymentsError::InvalidRequest(format!(
            "amount must be a positive decimal with at most {decimals} fractional digits"
        ))
    };
    let amount = amount.trim();
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    let canonical_whole = whole == "0" || (!whole.is_empty() && !whole.starts_with('0'));
    let digits_only = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !canonical_whole
        || !digits_only(whole)
        || !digits_only(fraction)
        || (amount.contains('.') && fraction.is_empty())
        || fraction.len() > usize::from(decimals)
    {
        return Err(invalid());
    }
    if decimals > MAX_PARSE_DECIMALS {
        return Err(PaymentsError::InvalidRequest(format!(
            "tokens with {decimals} decimals are not supported"
        )));
    }
    let too_large = || PaymentsError::InvalidRequest("amount is too large".into());
    let scale = 10_u128.pow(u32::from(decimals));
    let fraction_scale = 10_u128.pow(u32::from(decimals) - fraction.len() as u32);
    let whole: u128 = whole.parse().map_err(|_| too_large())?;
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().map_err(|_| invalid())?
    };
    let base_units = whole
        .checked_mul(scale)
        .and_then(|value| value.checked_add(fraction * fraction_scale))
        .ok_or_else(too_large)?;
    if base_units == 0 {
        return Err(PaymentsError::InvalidRequest(
            "amount must be greater than zero".into(),
        ));
    }
    Ok((amount.to_string(), base_units))
}

/// Formats `value` base units as whole units without trailing zeros.
pub(crate) fn format_units(value: U256, decimals: u8) -> String {
    if decimals == 0 {
        return value.to_string();
    }
    let digits = value.to_string();
    let decimals = usize::from(decimals);
    let padded = if digits.len() <= decimals {
        format!("{}{digits}", "0".repeat(decimals + 1 - digits.len()))
    } else {
        digits
    };
    let (whole, fraction) = padded.split_at(padded.len() - decimals);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fraction}")
    }
}

/// The approval wait a call asked for, or the service default.
pub(super) fn approval_wait(requested: Option<u64>, default: ApprovalWait) -> ApprovalWait {
    requested.map_or(default, |secs| {
        ApprovalWait::up_to(Duration::from_secs(secs).min(MAX_APPROVAL_WAIT))
    })
}

/// The receipt timeout a call asked for (default 30 s, capped at 120 s).
pub(super) fn receipt_timeout(requested: Option<u64>) -> Duration {
    requested.map_or(DEFAULT_RECEIPT_TIMEOUT, |secs| {
        Duration::from_secs(secs).min(MAX_RECEIPT_TIMEOUT)
    })
}

/// Rejects transaction options that make no sense: zero gas or fees, a
/// priority fee above the fee cap, or (when `transaction` is `false`, a
/// sign-only call) any transaction option at all.
pub(super) fn check_options(
    options: &EvmTxOptions,
    transaction: bool,
) -> Result<(), PaymentsError> {
    if !transaction {
        let tx_only = options.wait_for_receipt
            || options.receipt_timeout_secs.is_some()
            || options.nonce.is_some()
            || options.gas_limit.is_some()
            || options.max_fee_per_gas_wei.is_some()
            || options.max_priority_fee_per_gas_wei.is_some();
        if tx_only {
            return Err(PaymentsError::InvalidRequest(
                "nonce, gas, fee, and receipt options require broadcast: true".into(),
            ));
        }
        return Ok(());
    }
    if options.gas_limit == Some(0) {
        return Err(PaymentsError::InvalidRequest(
            "gas_limit must be positive".into(),
        ));
    }
    if options.max_fee_per_gas_wei == Some(0) {
        return Err(PaymentsError::InvalidRequest(
            "max_fee_per_gas_wei must be positive".into(),
        ));
    }
    if let (Some(max_fee), Some(priority)) = (
        options.max_fee_per_gas_wei,
        options.max_priority_fee_per_gas_wei,
    ) {
        if priority > max_fee {
            return Err(PaymentsError::InvalidRequest(
                "max_priority_fee_per_gas_wei must not exceed max_fee_per_gas_wei".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_config;

    #[test]
    fn amounts_parse_like_the_typescript_cli() {
        assert_eq!(parse_amount("1", 18).unwrap().1, 1_000_000_000_000_000_000);
        assert_eq!(parse_amount(" 1.5 ", 6).unwrap(), ("1.5".into(), 1_500_000));
        assert_eq!(parse_amount("0.000001", 6).unwrap().1, 1);
        assert_eq!(parse_amount("42", 0).unwrap().1, 42);
        for bad in [
            "",
            "0",
            "0.0",
            "01",
            "1.",
            ".5",
            "-1",
            "1e3",
            "1.2345678",
            "abc",
            "1,5",
        ] {
            assert!(parse_amount(bad, 6).is_err(), "{bad:?} must be rejected");
        }
        assert!(parse_amount("340282366920938463463374607431768211456", 0).is_err());
        assert!(parse_amount("1", 39).is_err());
    }

    #[test]
    fn units_format_without_trailing_zeros() {
        assert_eq!(format_units(U256::from(25_500_000_u64), 6), "25.5");
        assert_eq!(format_units(U256::from(1_u64), 6), "0.000001");
        assert_eq!(format_units(U256::ZERO, 18), "0");
        assert_eq!(format_units(U256::from(7_u64), 0), "7");
        assert_eq!(format_units(U256::from(3_000_000_u64), 6), "3");
    }

    #[test]
    fn defaults_resolve_to_usd1_on_bsc() {
        let config = default_config();
        let network = network(&config, None).unwrap();
        assert_eq!((network.key.as_str(), network.chain.chain_id), ("bsc", 56));
        let AssetChoice::Known(asset) = asset(&config, &network, None).unwrap() else {
            panic!("usd1 is configured");
        };
        assert_eq!(asset.key.as_deref(), Some("usd1"));
        assert_eq!(asset.decimals, 18);
        assert!(asset.token.is_some());

        // The same contract given by address resolves to the configured token.
        let by_address = asset
            .token
            .as_ref()
            .unwrap()
            .as_str()
            .to_ascii_uppercase()
            .replacen("0X", "0x", 1);
        assert_eq!(
            super::asset(&config, &network, Some(&by_address)).unwrap(),
            AssetChoice::Known(asset)
        );
        let native = native_asset(&config, &network);
        assert_eq!((native.symbol.as_str(), native.token), ("BNB", None));
    }

    #[test]
    fn unknown_or_unsuitable_networks_and_assets_are_rejected() {
        let config = default_config();
        assert!(matches!(
            network(&config, Some("nope")),
            Err(PaymentsError::InvalidRequest(_))
        ));
        assert!(matches!(
            network(&config, Some("solana-mainnet")),
            Err(PaymentsError::InvalidRequest(_))
        ));
        let bsc = network(&config, Some("BSC")).unwrap();
        assert!(matches!(
            asset(&config, &bsc, Some("nope")),
            Err(PaymentsError::InvalidRequest(_))
        ));
        assert!(matches!(
            asset(&config, &bsc, Some("0x12")),
            Err(PaymentsError::InvalidRequest(_))
        ));
        let other = "0x1111111111111111111111111111111111111111";
        assert_eq!(
            asset(&config, &bsc, Some(other)).unwrap(),
            AssetChoice::Unconfigured(EvmAddress::from_str(other).unwrap())
        );
    }

    #[test]
    fn sign_only_calls_reject_transaction_options() {
        let mut options = EvmTxOptions::default();
        assert!(check_options(&options, false).is_ok());
        options.nonce = Some(1);
        assert!(check_options(&options, false).is_err());
        assert!(check_options(&options, true).is_ok());
        options.max_fee_per_gas_wei = Some(1);
        options.max_priority_fee_per_gas_wei = Some(2);
        assert!(check_options(&options, true).is_err());
        options.max_priority_fee_per_gas_wei = None;
        options.gas_limit = Some(0);
        assert!(check_options(&options, true).is_err());
    }

    #[test]
    fn waits_are_capped() {
        assert_eq!(receipt_timeout(None), DEFAULT_RECEIPT_TIMEOUT);
        assert_eq!(receipt_timeout(Some(10_000)), MAX_RECEIPT_TIMEOUT);
        assert_eq!(
            approval_wait(Some(10_000), ApprovalWait::none()).max_wait,
            MAX_APPROVAL_WAIT
        );
        assert_eq!(
            approval_wait(None, ApprovalWait::none()),
            ApprovalWait::none()
        );
    }
}
