//! Whether the wallet can pay each challenge of a `402`, read before
//! selection so that ranking never prefers a challenge the wallet cannot
//! pay (for example a gasless one in a token it does not hold) over one it
//! can.
//!
//! Only a `402` with several payable challenges is probed, at most
//! [`MAX_PROBED`] of them, within [`PROBE_TIMEOUT`]; a challenge whose
//! check fails or times out counts as payable (the payment itself then
//! decides). Nothing is signed.

use std::collections::HashSet;
use std::time::Duration;

use alloy_primitives::U256;
use mpp::protocol::core::{parse_www_authenticate_all_bytes, PaymentChallenge};
use reqwest::header::{HeaderMap, WWW_AUTHENTICATE};

use super::evm_charge::{Credential, EvmCharge};
use super::permit2::permit2_address;
use super::select::{self, Offer, Payable};
use super::solana_charge;
use super::tempo::network_for_chain;
use crate::chains::evm::to_alloy_address;
use crate::error::PaymentsError;
use crate::features::payer::Payer;

/// Most challenges probed for one `402`.
const MAX_PROBED: usize = 8;

/// How long the probe may take in all.
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// The ids of the challenges in `headers` (a `402`'s) the wallet cannot pay.
pub(super) async fn unaffordable(payer: &Payer, headers: &HeaderMap) -> HashSet<String> {
    let values: Vec<&[u8]> = headers
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .map(|value| value.as_bytes())
        .collect();
    let offers: Vec<(PaymentChallenge, Payable)> = parse_www_authenticate_all_bytes(values)
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(|challenge| {
            let payable = select::payable(&challenge).ok()?;
            Some((challenge, payable))
        })
        .take(MAX_PROBED)
        .collect();
    if offers.len() < 2 {
        return HashSet::new();
    }
    let mut unaffordable = HashSet::new();
    let probe = async {
        for (challenge, payable) in &offers {
            if matches!(affordable(payer, payable).await, Ok(false)) {
                unaffordable.insert(challenge.id.clone());
            }
        }
    };
    // A timeout keeps what was learned so far.
    let _ = tokio::time::timeout(PROBE_TIMEOUT, probe).await;
    unaffordable
}

async fn affordable(payer: &Payer, payable: &Payable) -> Result<bool, PaymentsError> {
    match payable {
        Payable::Tempo(offer) => tempo_affordable(payer, offer).await,
        Payable::Evm(charge) => evm_affordable(payer, charge).await,
        Payable::Solana(charge) => solana_charge::affordable(payer, charge).await,
    }
}

/// The wallet holds the amount (Tempo fees are paid in the stablecoin).
async fn tempo_affordable(payer: &Payer, offer: &Offer) -> Result<bool, PaymentsError> {
    let (network, chain) = network_for_chain(&payer.config, offer.chain_id)?;
    let rpc = payer.evm.connect(&network, &chain).await?;
    let held = rpc
        .erc20_balance(to_alloy_address(&offer.currency)?, payer.wallet)
        .await?;
    Ok(held >= U256::from(offer.amount))
}

/// The wallet holds the amount, and some native coin when the credential
/// (or the one-time Permit2 approval) needs gas.
async fn evm_affordable(payer: &Payer, charge: &EvmCharge) -> Result<bool, PaymentsError> {
    let (network, chain) = network_for_chain(&payer.config, charge.chain_id)?;
    let rpc = payer.evm.connect(&network, &chain).await?;
    let token = to_alloy_address(&charge.currency)?;
    let amount = U256::from(charge.amount);
    if rpc.erc20_balance(token, payer.wallet).await? < amount {
        return Ok(false);
    }
    let needs_gas = match &charge.credential {
        Credential::Authorization => false,
        Credential::Permit2(_) => {
            rpc.erc20_allowance(token, payer.wallet, permit2_address()?)
                .await?
                < amount
        }
        Credential::Hash | Credential::Transaction => true,
    };
    Ok(!needs_gas || rpc.native_balance(payer.wallet).await? > U256::ZERO)
}
