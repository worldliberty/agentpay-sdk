//! One token-contract call for an MPP charge, as an EIP-1559 transaction
//! signed through the signer daemon's policy-checked `BroadcastTx` (the same
//! pipeline as `Transfer`): nonce reserved, signature checked to recover to
//! the wallet over the transaction rebuilt from the same fields, then either
//! sent and confirmed (`hash` credentials) or handed to the merchant unsent
//! (`transaction` credentials).

use std::time::Duration;

use agentpay_api::payments::PaymentsConfig;
use agentpay_domain::{is_tempo_chain_id, AgentAction, BroadcastTx, EvmAddress};
use alloy_primitives::U256;

use crate::chains::evm::{hex_prefixed, to_alloy_address, verify_signed_transaction, EvmRpc};
use crate::error::PaymentsError;
use crate::features::evm::format_units;
use crate::features::payer::Payer;
use crate::signer::ApprovalWait;
use agentpay_api::WireDaemonError;

/// How long to wait for a sent transaction's receipt.
pub(super) const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);

/// What to do with the signed transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Delivery {
    /// Send it and wait for a successful receipt.
    Send,
    /// Return it unsent (the merchant broadcasts it).
    SignOnly,
}

/// A signed (and, with [`Delivery::Send`], confirmed) transaction.
#[derive(Debug, Clone)]
pub(super) struct SignedTx {
    /// The transaction as signed.
    pub(super) tx: BroadcastTx,
    /// `0x` + 64 hex.
    pub(super) hash: String,
    /// The raw signed transaction, `0x`-prefixed hex.
    pub(super) raw_hex: String,
}

/// The native coin of `network` as `(symbol, decimals)`: the configured
/// native token on it, else a generic name with 18 decimals.
fn native_coin(config: &PaymentsConfig, network: &str) -> (String, u8) {
    config
        .tokens
        .values()
        .find_map(|token| {
            token
                .chains
                .get(network)
                .filter(|deployment| deployment.is_native)
                .map(|deployment| (token.symbol.clone(), deployment.decimals))
        })
        .unwrap_or_else(|| ("of the native coin".to_string(), 18))
}

/// Refuses, before anything is signed, a transaction whose worst-case fee
/// (`gas_limit × max_fee_per_gas`) the wallet's native balance cannot pay.
/// Tempo chains are skipped: fees there are paid in the stablecoin.
async fn ensure_gas(
    payer: &Payer,
    rpc: &EvmRpc,
    network: &str,
    tx: &BroadcastTx,
) -> Result<(), PaymentsError> {
    if is_tempo_chain_id(tx.chain_id) {
        return Ok(());
    }
    let needed = U256::from(tx.gas_limit) * U256::from(tx.max_fee_per_gas_wei);
    let held = rpc.native_balance(payer.wallet).await?;
    if held >= needed {
        return Ok(());
    }
    let (symbol, decimals) = native_coin(&payer.config, network);
    Err(PaymentsError::InvalidRequest(format!(
        "paying on {network} needs up to {} {symbol} for gas and the wallet holds {}; fund it, \
         or pay a merchant that accepts a gasless credential (authorization or permit2); \
         nothing was signed",
        format_units(needed, decimals),
        format_units(held, decimals),
    )))
}

/// The unsigned transaction calling `data` on `contract` (no value), with
/// the pending nonce, the estimated gas, and current fees.
async fn build_call(
    payer: &Payer,
    rpc: &EvmRpc,
    chain_id: u64,
    contract: &EvmAddress,
    data: Vec<u8>,
) -> Result<BroadcastTx, PaymentsError> {
    let to = to_alloy_address(contract)?;
    let nonce = rpc.pending_nonce(payer.wallet).await?;
    let gas_limit = rpc
        .estimate_gas(payer.wallet, to, U256::ZERO, data.clone())
        .await?;
    let fees = rpc.fees().await?;
    Ok(BroadcastTx {
        chain_id,
        nonce,
        to: contract.clone(),
        value_wei: 0,
        data_hex: hex_prefixed(&data),
        gas_limit,
        max_fee_per_gas_wei: fees.max_fee_per_gas,
        max_priority_fee_per_gas_wei: fees.max_priority_fee_per_gas.min(fees.max_fee_per_gas),
        tx_type: 2,
        delegation_enabled: false,
    })
}

/// Checks, without signing anything, that the wallet could pay the gas of
/// calling `data` on `contract` ([`sign_call`] checks again before signing).
pub(super) async fn check_gas(
    payer: &Payer,
    rpc: &EvmRpc,
    network: &str,
    chain_id: u64,
    contract: &EvmAddress,
    data: Vec<u8>,
) -> Result<(), PaymentsError> {
    let tx = build_call(payer, rpc, chain_id, contract, data).await?;
    ensure_gas(payer, rpc, network, &tx).await
}

/// Signs a call of `data` on `contract` (no value) as the payer's agent on
/// `rpc`'s chain (the configured `network`) and delivers it as asked. A
/// wallet that cannot pay the gas is refused first; a revert or a missing
/// receipt fails the call; the merchant is never told about a payment that
/// did not land.
pub(super) async fn sign_call(
    payer: &Payer,
    rpc: &EvmRpc,
    network: &str,
    chain_id: u64,
    contract: &EvmAddress,
    data: Vec<u8>,
    delivery: Delivery,
) -> Result<SignedTx, PaymentsError> {
    let mut tx = build_call(payer, rpc, chain_id, contract, data).await?;
    ensure_gas(payer, rpc, network, &tx).await?;
    let signer = payer.signer();
    let reservation = signer.reserve_nonce(tx.chain_id, tx.nonce, false).await?;
    tx.nonce = reservation.nonce;
    let action = AgentAction::BroadcastTx { tx: tx.clone() };
    let mut result = signer.sign(action.clone(), payer.wait).await;
    let mut reservation_id = reservation.reservation_id;
    if matches!(
        result,
        Err(PaymentsError::Signer(
            WireDaemonError::MissingNonceReservation { .. }
        ))
    ) && !payer.wait.max_wait.is_zero()
    {
        // The reservation expired while an operator decided: reserve the
        // same nonce again and resend the approved request.
        let again = signer.reserve_nonce(tx.chain_id, tx.nonce, true).await?;
        reservation_id = again.reservation_id;
        result = signer.sign(action, ApprovalWait::none()).await;
    }
    let signature = match result {
        Ok(signature) => signature,
        Err(error) => {
            if let Err(release) = signer.release_nonce(reservation_id).await {
                tracing::warn!(
                    error = PaymentsError::from(release).kind(),
                    "failed to release a nonce reservation"
                );
            }
            return Err(error);
        }
    };
    let raw_tx_hex = signature.raw_tx_hex.as_deref().ok_or_else(|| {
        PaymentsError::SignerUnavailable("the signer daemon returned no signed transaction".into())
    })?;
    let verified = match verify_signed_transaction(
        raw_tx_hex,
        signature.tx_hash_hex.as_deref(),
        &tx,
        payer.wallet,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            // Nothing was sent: the nonce is free again.
            signer
                .release_unsent(&tx, signature.tx_hash_hex.as_deref())
                .await;
            return Err(error);
        }
    };
    let hash = hex_prefixed(verified.hash.as_slice());
    let signed = SignedTx {
        tx: tx.clone(),
        hash: hash.clone(),
        raw_hex: hex_prefixed(&verified.raw),
    };
    if delivery == Delivery::SignOnly {
        return Ok(signed);
    }
    if let Err(failure) = rpc.try_send_raw_transaction(&verified.raw).await {
        if failure.not_submitted {
            signer.release_unsent(&tx, Some(&hash)).await;
        }
        return Err(failure.error);
    }
    let receipt = rpc
        .wait_for_receipt(verified.hash, RECEIPT_TIMEOUT)
        .await
        .map_err(|_| {
            PaymentsError::ChainRpc(format!(
                "the payment transaction {hash} was sent, but its receipt could not be read; \
                 the merchant was not told"
            ))
        })?;
    match receipt {
        Some(receipt) if receipt.success => Ok(signed),
        Some(_) => Err(PaymentsError::ChainRpc(format!(
            "the payment transaction {hash} reverted; the merchant was not told"
        ))),
        None => Err(PaymentsError::ChainRpc(format!(
            "the payment transaction {hash} was sent but not mined within {}s; the merchant \
             was not told",
            RECEIPT_TIMEOUT.as_secs()
        ))),
    }
}
