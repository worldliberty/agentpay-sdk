//! `FundingRequest`: the address, payment URI, QR code, and gas hint a
//! person needs to fund the wallet (ported from the skill's
//! `prepare-funding-request` script, which only handled native EVM coins).

use agentpay_api::payments::{
    ChainFamily, FundingGasHint, FundingRequestParams, FundingRequestResult, PaymentsConfig,
};
use alloy_primitives::U256;

use super::{qr, resolve, wallet_address, Target};
use crate::auth::AuthenticatedAgent;
use crate::error::PaymentsError;
use crate::features::evm::{format_units, parse_amount};
use crate::state::AppState;

/// Native gas coin symbols by EVM chain id, for chains whose native coin is
/// not configured (from the TypeScript funding script).
const NATIVE_GAS_SYMBOLS: &[(u64, &str)] = &[
    (1, "ETH"),
    (10, "ETH"),
    (56, "BNB"),
    (137, "POL"),
    (8453, "ETH"),
    (42_161, "ETH"),
    (84_532, "ETH"),
    (421_614, "ETH"),
    (11_155_111, "ETH"),
];

/// `FundingRequest`.
pub(super) async fn request(
    state: &AppState,
    agent: &AuthenticatedAgent,
    params: &FundingRequestParams,
) -> Result<FundingRequestResult, PaymentsError> {
    let config = state.config.get().await;
    let target = resolve(&config, params.network.as_deref(), params.asset.as_deref())?;
    if target.is_tempo_native() {
        return Err(PaymentsError::InvalidRequest(format!(
            "network '{}' has no native coin to fund; fund one of its stablecoins",
            target.network
        )));
    }
    let address = wallet_address(agent, target.chain.family)?;
    let amount = params
        .amount
        .as_deref()
        .map(|amount| parse_amount(amount, target.decimals).map(|(_, base_units)| base_units))
        .transpose()?;
    let amount_display = amount.map(|base| format_units(U256::from(base), target.decimals));
    let uri = payment_uri(&target, &address, amount, amount_display.as_deref());
    let qr = match params.qr {
        Some(false) => None,
        _ => Some(qr::render(&uri)?),
    };
    let gas = gas_hint(&config, &target);
    let instructions = instructions(&target, &address, amount_display.as_deref(), gas.as_ref());
    Ok(FundingRequestResult {
        chain_id: target.chain.chain_id,
        chain_name: target.chain.name.clone(),
        family: target.chain.family,
        kind: target.kind(),
        network: target.network,
        asset: target.asset,
        symbol: target.symbol,
        token: target.token,
        decimals: target.decimals,
        address,
        amount: amount_display,
        amount_base_units: amount.map(|base| base.to_string()),
        uri,
        qr,
        gas,
        instructions,
    })
}

/// The EIP-681 or Solana Pay URI for paying `amount` of `target` to `address`.
pub(super) fn payment_uri(
    target: &Target,
    address: &str,
    base_units: Option<u128>,
    decimal: Option<&str>,
) -> String {
    match (target.chain.family, target.token.as_deref()) {
        (ChainFamily::Evm, None) => {
            let mut uri = format!("ethereum:{address}@{}", target.chain.chain_id);
            if let Some(wei) = base_units {
                uri.push_str(&format!("?value={wei}"));
            }
            uri
        }
        (ChainFamily::Evm, Some(token)) => {
            let mut uri = format!(
                "ethereum:{}@{}/transfer?address={address}",
                token.to_ascii_lowercase(),
                target.chain.chain_id
            );
            if let Some(units) = base_units {
                uri.push_str(&format!("&uint256={units}"));
            }
            uri
        }
        (ChainFamily::Solana, mint) => {
            let mut query = Vec::new();
            if let Some(amount) = decimal {
                query.push(format!("amount={amount}"));
            }
            if let Some(mint) = mint {
                query.push(format!("spl-token={mint}"));
            }
            if query.is_empty() {
                format!("solana:{address}")
            } else {
                format!("solana:{address}?{}", query.join("&"))
            }
        }
    }
}

/// The native coin to send along for fees, when `target` is not it.
pub(super) fn gas_hint(config: &PaymentsConfig, target: &Target) -> Option<FundingGasHint> {
    target.token.as_ref()?;
    if super::TEMPO_CHAIN_IDS.contains(&target.chain.chain_id) {
        return None;
    }
    let configured = config.tokens.iter().find_map(|(key, token)| {
        token
            .chains
            .get(&target.network)
            .filter(|deployment| deployment.is_native)
            .map(|_| (key.clone(), token.symbol.clone()))
    });
    let (asset, symbol) = match (configured, target.chain.family) {
        (Some((key, symbol)), _) => (Some(key), symbol),
        (None, ChainFamily::Solana) => (None, "SOL".to_string()),
        (None, ChainFamily::Evm) => (
            None,
            NATIVE_GAS_SYMBOLS
                .iter()
                .find(|(id, _)| *id == target.chain.chain_id)
                .map_or("the native coin", |(_, symbol)| symbol)
                .to_string(),
        ),
    };
    let note = match target.chain.family {
        ChainFamily::Evm => format!(
            "{} transfers pay network fees in {symbol}; send a little {symbol} on {} too.",
            target.symbol, target.chain.name
        ),
        ChainFamily::Solana => format!(
            "{} transfers pay network fees (and token account rent) in {symbol}; send a little {symbol} too.",
            target.symbol
        ),
    };
    Some(FundingGasHint {
        asset,
        symbol,
        note,
    })
}

/// One sentence for the person funding the wallet.
fn instructions(
    target: &Target,
    address: &str,
    amount: Option<&str>,
    gas: Option<&FundingGasHint>,
) -> String {
    let what = match amount {
        Some(amount) => format!("at least {amount} {}", target.symbol),
        None => target.symbol.clone(),
    };
    let fees = gas.map_or(String::new(), |gas| {
        format!(", plus a little {} for network fees", gas.symbol)
    });
    format!(
        "Please send {what} to {address} on {} (chain {}){fees}, then say when the transfer is confirmed.",
        target.chain.name, target.chain.chain_id
    )
}
