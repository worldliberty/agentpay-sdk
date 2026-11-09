//! The signing pipeline shared by the EVM methods and `ResumeApproved`:
//! plan a transaction, reserve its nonce, have it signed, verify it, send it,
//! and wait for its receipt; or sign a typed action without a transaction.
//! A signature held for an operator becomes a stored [`PendingRecord`] and a
//! `ManualApprovalPending` result.

use std::time::Duration;

use agentpay_api::payments::{
    EvmPayment, EvmSignatureResult, EvmTransactionResult, EvmTxOptions,
    ManualApprovalPendingResult, PaymentsRpcResponse,
};
use agentpay_api::WireDaemonError;
use agentpay_domain::{AgentAction, BroadcastTx, EvmAddress, Signature};
use alloy_primitives::{Address, U256};

use super::pending::{Delivery, PendingRecord, PendingStore, RECORD_SCHEMA};
use crate::auth::AuthenticatedAgent;
use crate::chains::evm::{
    evm_address, hex_prefixed, to_alloy_address, verify_signed_transaction, EvmRpc,
};
use crate::error::PaymentsError;
use crate::signer::{AgentSigner, ApprovalWait};
use crate::state::AppState;

/// What a signing request is for: echoed in results and pending records.
#[derive(Debug, Clone)]
pub(super) struct Intent {
    /// The method that was called.
    pub(super) method: String,
    /// Chain key; `None` for typed data.
    pub(super) network: Option<String>,
    /// Chain id.
    pub(super) chain_id: u64,
    /// What a transfer or approval moves.
    pub(super) payment: Option<EvmPayment>,
}

/// A planned transaction and how to deliver it.
#[derive(Debug, Clone)]
pub(super) struct Submission {
    /// The transaction; its nonce is a minimum unless `exact_nonce`.
    pub(super) tx: BroadcastTx,
    /// Reserve exactly `tx.nonce` (an explicit or resumed nonce).
    pub(super) exact_nonce: bool,
    /// What to do once it is signed.
    pub(super) delivery: Delivery,
}

/// Builds the EIP-1559 transaction `from` → `to`, filling the nonce, gas
/// limit, and fees from the chain unless `options` gives them.
pub(super) async fn plan(
    rpc: &EvmRpc,
    from: Address,
    to: &EvmAddress,
    value_wei: u128,
    data: Vec<u8>,
    options: &EvmTxOptions,
) -> Result<BroadcastTx, PaymentsError> {
    let nonce = match options.nonce {
        Some(nonce) => nonce,
        None => rpc.pending_nonce(from).await?,
    };
    let data_hex = hex_prefixed(&data);
    let gas_limit = match options.gas_limit {
        Some(gas_limit) => gas_limit,
        None => {
            let to = to_alloy_address(to)?;
            rpc.estimate_gas(from, to, U256::from(value_wei), data)
                .await?
        }
    };
    let (max_fee, priority_fee) = match (
        options.max_fee_per_gas_wei,
        options.max_priority_fee_per_gas_wei,
    ) {
        (Some(max_fee), Some(priority_fee)) => (max_fee, priority_fee),
        (max_fee, priority_fee) => {
            let estimate = rpc.fees().await?;
            let max_fee = max_fee.unwrap_or(estimate.max_fee_per_gas);
            // An estimated tip never exceeds the fee cap.
            let priority_fee =
                priority_fee.unwrap_or(estimate.max_priority_fee_per_gas.min(max_fee));
            (max_fee, priority_fee)
        }
    };
    if max_fee == 0 {
        return Err(PaymentsError::ChainRpc(
            "could not determine a fee; set max_fee_per_gas_wei".into(),
        ));
    }
    Ok(BroadcastTx {
        chain_id: rpc.chain_id(),
        nonce,
        to: to.clone(),
        value_wei,
        data_hex,
        gas_limit,
        max_fee_per_gas_wei: max_fee,
        max_priority_fee_per_gas_wei: priority_fee,
        tx_type: 2,
        delegation_enabled: false,
    })
}

/// Reserves the nonce (exactly, or the lowest free nonce at or above it),
/// has the transaction signed, verifies it, and sends it as the submission says.
pub(super) async fn execute(
    state: &AppState,
    agent: &AuthenticatedAgent,
    rpc: &EvmRpc,
    intent: Intent,
    submission: Submission,
    wait: ApprovalWait,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let Submission {
        mut tx,
        exact_nonce,
        delivery,
    } = submission;
    let from = wallet(agent)?;
    let signer = agent.signer(state.signer.as_ref());
    let reservation = signer
        .reserve_nonce(tx.chain_id, tx.nonce, exact_nonce)
        .await?;
    tx.nonce = reservation.nonce;
    let action = AgentAction::BroadcastTx { tx: tx.clone() };
    let signature =
        match sign_reserved(&signer, &action, &tx, reservation.reservation_id, wait).await {
            Ok(signature) => signature,
            Err(PaymentsError::ManualApprovalPending {
                approval_request_id,
            }) => {
                return hold(
                    state,
                    agent,
                    intent,
                    action,
                    Some(delivery),
                    approval_request_id,
                )
            }
            Err(error) => return Err(error),
        };
    let raw_tx_hex = signature.raw_tx_hex.as_deref().ok_or_else(|| {
        PaymentsError::SignerUnavailable("the signer daemon returned no signed transaction".into())
    })?;
    let verified =
        match verify_signed_transaction(raw_tx_hex, signature.tx_hash_hex.as_deref(), &tx, from) {
            Ok(verified) => verified,
            Err(error) => {
                // Nothing was sent: the nonce is free again.
                signer
                    .release_unsent(&tx, signature.tx_hash_hex.as_deref())
                    .await;
                return Err(error);
            }
        };
    let (receipt, receipt_timed_out) = if delivery.broadcast {
        let sent = match rpc.try_send_raw_transaction(&verified.raw).await {
            Ok(sent) => sent,
            Err(failure) => {
                if failure.not_submitted {
                    let hash = hex_prefixed(verified.hash.as_slice());
                    signer.release_unsent(&tx, Some(&hash)).await;
                }
                return Err(failure.error);
            }
        };
        if sent != verified.hash {
            tracing::warn!("the node reported a different hash for a sent transaction");
        }
        if delivery.wait_for_receipt {
            let timeout = Duration::from_secs(delivery.receipt_timeout_secs);
            // The transaction is out: a failed receipt lookup must not turn
            // into an error the caller might answer by paying again.
            match rpc.wait_for_receipt(verified.hash, timeout).await {
                Ok(receipt) => {
                    let timed_out = receipt.is_none();
                    (receipt, timed_out)
                }
                Err(error) => {
                    tracing::warn!(kind = error.kind(), "receipt lookup failed after broadcast");
                    (None, true)
                }
            }
        } else {
            (None, false)
        }
    } else {
        (None, false)
    };
    Ok(PaymentsRpcResponse::EvmTransaction(EvmTransactionResult {
        network: rpc.network().to_string(),
        chain_id: tx.chain_id,
        payment: intent.payment,
        from: evm_address(from)?,
        to: tx.to,
        value_wei: tx.value_wei,
        data_hex: tx.data_hex,
        nonce: tx.nonce,
        gas_limit: tx.gas_limit,
        max_fee_per_gas_wei: tx.max_fee_per_gas_wei,
        max_priority_fee_per_gas_wei: tx.max_priority_fee_per_gas_wei,
        tx_hash: hex_prefixed(verified.hash.as_slice()),
        raw_tx_hex: hex_prefixed(&verified.raw),
        broadcast: delivery.broadcast,
        receipt,
        receipt_timed_out,
    }))
}

/// Signs `action` under the reservation `reservation_id`, and releases the
/// reservation if nothing was signed (denial, pending approval, outage).
async fn sign_reserved(
    signer: &AgentSigner<'_>,
    action: &AgentAction,
    tx: &BroadcastTx,
    reservation_id: uuid::Uuid,
    wait: ApprovalWait,
) -> Result<Signature, PaymentsError> {
    let mut reservation_id = reservation_id;
    let mut result = signer.sign(action.clone(), wait).await;
    let expired = matches!(
        result,
        Err(PaymentsError::Signer(
            WireDaemonError::MissingNonceReservation { .. }
        ))
    );
    if expired && !wait.max_wait.is_zero() {
        // The reservation (2 minutes) expired while an operator decided:
        // reserve the same nonce again and resend the approved request.
        let again = signer.reserve_nonce(tx.chain_id, tx.nonce, true).await?;
        reservation_id = again.reservation_id;
        result = signer.sign(action.clone(), ApprovalWait::none()).await;
    }
    if result.is_err() {
        if let Err(error) = signer.release_nonce(reservation_id).await {
            tracing::warn!(error = ?PaymentsError::from(error).kind(), "failed to release a nonce reservation");
        }
    }
    result
}

/// Signs a typed action (no transaction) and returns the signature.
pub(super) async fn sign_only(
    state: &AppState,
    agent: &AuthenticatedAgent,
    intent: Intent,
    action: AgentAction,
    wait: ApprovalWait,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let signer = agent.signer(state.signer.as_ref());
    let signature = match signer.sign(action.clone(), wait).await {
        Ok(signature) => signature,
        Err(PaymentsError::ManualApprovalPending {
            approval_request_id,
        }) => return hold(state, agent, intent, action, None, approval_request_id),
        Err(error) => return Err(error),
    };
    let signature_hex = match &action {
        AgentAction::Eip712TypedData { .. } => rsv_signature(&signature)?,
        _ => hex_prefixed(&signature.bytes),
    };
    Ok(PaymentsRpcResponse::EvmSignature(EvmSignatureResult {
        network: intent.network,
        chain_id: intent.chain_id,
        payment: intent.payment,
        action,
        signature_hex,
        r_hex: signature.r_hex,
        s_hex: signature.s_hex,
        v: signature.v,
    }))
}

/// The 65-byte `r || s || v` form (`v` = 27 or 28) of a typed-data signature.
fn rsv_signature(signature: &Signature) -> Result<String, PaymentsError> {
    let missing = || {
        PaymentsError::SignerUnavailable(
            "the signer daemon returned an incomplete signature".into(),
        )
    };
    let part = |value: &Option<String>| {
        value
            .as_deref()
            .and_then(|hex| hex.strip_prefix("0x"))
            .filter(|digits| digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase)
            .ok_or_else(missing)
    };
    let (r, s) = (part(&signature.r_hex)?, part(&signature.s_hex)?);
    let v = match signature.v {
        Some(v @ (0 | 1)) => v + 27,
        _ => return Err(missing()),
    };
    Ok(format!("0x{r}{s}{v:02x}"))
}

/// Stores `action` for `ResumeApproved` and reports it as pending.
fn hold(
    state: &AppState,
    agent: &AuthenticatedAgent,
    intent: Intent,
    action: AgentAction,
    delivery: Option<Delivery>,
    approval_request_id: uuid::Uuid,
) -> Result<PaymentsRpcResponse, PaymentsError> {
    let record = PendingRecord {
        schema: RECORD_SCHEMA,
        approval_request_id,
        agent_key_id: agent.credentials.agent_key_id,
        method: intent.method.clone(),
        network: intent.network.clone(),
        chain_id: intent.chain_id,
        payment: intent.payment.clone(),
        action: action.clone(),
        delivery,
    };
    pending_store(state)?.save(&record)?;
    Ok(PaymentsRpcResponse::ManualApprovalPending(
        ManualApprovalPendingResult {
            approval_request_id,
            method: intent.method,
            network: intent.network,
            chain_id: intent.chain_id,
            payment: intent.payment,
            action,
        },
    ))
}

/// The pending-approval store in the service's state directory (the
/// directory that holds `config.json`).
pub(super) fn pending_store(state: &AppState) -> Result<PendingStore, PaymentsError> {
    state
        .config
        .path()
        .parent()
        .map(PendingStore::new)
        .ok_or_else(|| PaymentsError::Internal("the state directory is unknown".into()))
}

/// The agent's EVM wallet address.
pub(super) fn wallet(agent: &AuthenticatedAgent) -> Result<Address, PaymentsError> {
    let address = agent.identity.evm_address.as_ref().ok_or_else(|| {
        PaymentsError::InvalidRequest("the agent's key cannot sign EVM transactions".into())
    })?;
    to_alloy_address(address)
}
