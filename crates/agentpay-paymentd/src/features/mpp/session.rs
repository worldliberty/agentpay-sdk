//! TIP-1034 (sessions v2) channel operations: open, top-up, voucher, and
//! cooperative close, each signed by the signer daemon through its typed
//! Tempo actions and checked here before anything leaves the process:
//!
//! - the channel id the daemon derives is recomputed with `mpp`
//!   (`compute_expiring_nonce_hash`, `compute_precompile_channel_id`) before
//!   the open is signed;
//! - transaction signatures must recover to the wallet over `tempo-alloy`'s
//!   signing hash of the rebuilt transaction;
//! - voucher signatures are checked with `mpp`'s own verifier, and close
//!   authorizations against `mpp`'s close digest.
//!
//! Credential payloads are `mpp`'s [`SessionCredentialPayload`], always with
//! the channel descriptor.

use std::str::FromStr;

use agentpay_domain::{
    AgentAction, TempoSessionV2CloseAuthorization, TempoSessionV2OpenTransaction,
    TempoSessionV2TopUpTransaction, TempoSessionV2Voucher,
};
use alloy_primitives::{hex, Address, B256};
use mpp::client::tempo::session::channel_ops::{
    build_channel_descriptor, compute_expiring_nonce_hash, compute_fee_payer_expiring_nonce_hash,
    create_precompile_top_up_payload,
};
use mpp::protocol::methods::tempo::compute_precompile_channel_id;
use mpp::protocol::methods::tempo::precompile_voucher::{
    precompile_close_authorization_signing_hash_with_escrow, verify_precompile_voucher_signature,
};
use mpp::protocol::methods::tempo::session::{ChannelDescriptor, SessionCredentialPayload};
use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

use super::select::Offer;
use super::store::SessionRecord;
use super::tempo::{self, TempoRpc};
use crate::chains::evm::{evm_address, to_alloy_address};
use crate::error::PaymentsError;
use crate::features::payer::{ensure_signed_by, recoverable, unix_now, Payer};

/// A freshly opened channel and its `open` credential payload.
pub(super) struct Opened {
    pub(super) record: SessionRecord,
    pub(super) payload: SessionCredentialPayload,
}

/// Opens a channel for `offer` with `deposit`, signing the open transaction
/// and a first voucher for `offer.amount`.
pub(super) async fn open(
    payer: &Payer,
    offer: &Offer,
    deposit: u128,
    session_key: &str,
    origin: &str,
) -> Result<Opened, PaymentsError> {
    let rpc = TempoRpc::connect(&payer.config, offer.chain_id).await?;
    let wallet = evm_address(payer.wallet)?;
    let salt = B256::from(rand::random::<[u8; 32]>());
    let gas_price = rpc.gas_price().await?;
    let now = unix_now();
    let mut action = TempoSessionV2OpenTransaction {
        chain_id: offer.chain_id,
        token: offer.currency.clone(),
        recipient: offer.recipient.clone(),
        operator: offer.operator.clone(),
        payer: wallet.clone(),
        authorized_signer: wallet.clone(),
        salt_hex: format!("{salt:#x}"),
        deposit_wei: deposit,
        tx: tempo::session_tx_params(
            gas_price,
            tempo::SPONSORED_GAS_LIMIT,
            now,
            None,
            offer.fee_payer,
            &offer.currency,
        ),
    };
    if !offer.fee_payer {
        let draft =
            tempo::transaction(offer.chain_id, &action.tx, encoded(action.encoded_calls())?)?;
        action.tx.gas_limit = rpc.estimate(&draft, payer.wallet).await?;
    }
    let tx = tempo::transaction(offer.chain_id, &action.tx, encoded(action.encoded_calls())?)?;
    let expiring_nonce_hash = if offer.fee_payer {
        compute_fee_payer_expiring_nonce_hash(&tx, payer.wallet)
    } else {
        compute_expiring_nonce_hash(&tx, payer.wallet)
    };
    let (recipient, operator, token) = (
        to_alloy_address(&offer.recipient)?,
        to_alloy_address(&offer.operator)?,
        to_alloy_address(&offer.currency)?,
    );
    let channel_id = compute_precompile_channel_id(
        payer.wallet,
        recipient,
        operator,
        token,
        salt,
        payer.wallet,
        expiring_nonce_hash,
        offer.chain_id,
    );
    let daemon_channel_id = action
        .channel_id()
        .map_err(|error| PaymentsError::InvalidRequest(format!("invalid session open: {error}")))?;
    if B256::from(daemon_channel_id) != channel_id {
        return Err(PaymentsError::Internal(
            "the session channel id does not match mpp's derivation; nothing was signed".into(),
        ));
    }
    let answer = payer
        .signer()
        .sign(
            AgentAction::TempoSessionV2OpenTransaction {
                authorization: action.clone(),
            },
            payer.wait,
        )
        .await?;
    let signature = recoverable(&answer)?;
    ensure_signed_by(
        &signature,
        tx.signature_hash(),
        payer.wallet,
        "session open transaction",
    )?;
    let transaction = hex_prefixed(&tempo::encode_signed(tx, signature, payer.wallet));
    let record = SessionRecord {
        agent_key_id: payer.agent_key_id(),
        session_key: session_key.to_string(),
        origin: origin.to_string(),
        chain_id: offer.chain_id,
        token: offer.currency.clone(),
        recipient: offer.recipient.clone(),
        operator: offer.operator.clone(),
        payer: wallet,
        salt_hex: action.salt_hex,
        expiring_nonce_hash_hex: format!("{expiring_nonce_hash:#x}"),
        channel_id_hex: format!("{channel_id:#x}"),
        deposit,
        cumulative: offer.amount,
    };
    let voucher_signature = sign_voucher(payer, &record, offer.amount).await?;
    let payload = SessionCredentialPayload::Open {
        payload_type: "transaction".into(),
        channel_id: record.channel_id_hex.clone(),
        transaction,
        descriptor: Some(descriptor(&record)?),
        settlement_route: None,
        authorized_signer: Some(payer.wallet.to_string()),
        cumulative_amount: offer.amount.to_string(),
        signature: hex_prefixed(&voucher_signature),
    };
    Ok(Opened { record, payload })
}

/// Signs a top-up of `additional` for `record`'s channel.
pub(super) async fn top_up(
    payer: &Payer,
    record: &SessionRecord,
    additional: u128,
    sponsored: bool,
) -> Result<SessionCredentialPayload, PaymentsError> {
    let rpc = TempoRpc::connect(&payer.config, record.chain_id).await?;
    let gas_price = rpc.gas_price().await?;
    let now = unix_now();
    // A random past validAfter keeps otherwise identical expiring
    // transactions distinct, as mppx does.
    let valid_after = Some(rand::random_range(1..now.saturating_sub(60).max(2)));
    let mut action = TempoSessionV2TopUpTransaction {
        chain_id: record.chain_id,
        token: record.token.clone(),
        recipient: record.recipient.clone(),
        operator: record.operator.clone(),
        payer: record.payer.clone(),
        authorized_signer: record.payer.clone(),
        salt_hex: record.salt_hex.clone(),
        expiring_nonce_hash_hex: record.expiring_nonce_hash_hex.clone(),
        channel_id_hex: record.channel_id_hex.clone(),
        additional_deposit_wei: additional,
        tx: tempo::session_tx_params(
            gas_price,
            tempo::SPONSORED_GAS_LIMIT,
            now,
            valid_after,
            sponsored,
            &record.token,
        ),
    };
    if !sponsored {
        let draft = tempo::transaction(
            record.chain_id,
            &action.tx,
            encoded(action.encoded_calls())?,
        )?;
        action.tx.gas_limit = rpc.estimate(&draft, payer.wallet).await?;
    }
    let tx = tempo::transaction(
        record.chain_id,
        &action.tx,
        encoded(action.encoded_calls())?,
    )?;
    let answer = payer
        .signer()
        .sign(
            AgentAction::TempoSessionV2TopUpTransaction {
                authorization: action,
            },
            payer.wait,
        )
        .await?;
    let signature = recoverable(&answer)?;
    ensure_signed_by(
        &signature,
        tx.signature_hash(),
        payer.wallet,
        "session top-up transaction",
    )?;
    let transaction = hex_prefixed(&tempo::encode_signed(tx, signature, payer.wallet));
    Ok(create_precompile_top_up_payload(
        channel_id(record)?,
        descriptor(record)?,
        transaction,
        additional,
    ))
}

/// A voucher payload for `cumulative` on `record`'s channel.
pub(super) async fn voucher(
    payer: &Payer,
    record: &SessionRecord,
    cumulative: u128,
) -> Result<SessionCredentialPayload, PaymentsError> {
    let signature = sign_voucher(payer, record, cumulative).await?;
    Ok(SessionCredentialPayload::Voucher {
        channel_id: record.channel_id_hex.clone(),
        descriptor: Some(descriptor(record)?),
        settlement_route: None,
        cumulative_amount: cumulative.to_string(),
        signature: hex_prefixed(&signature),
    })
}

/// A cooperative close payload: a voucher and a close authorization for
/// `cumulative`.
pub(super) async fn close(
    payer: &Payer,
    record: &SessionRecord,
    cumulative: u128,
) -> Result<SessionCredentialPayload, PaymentsError> {
    let voucher_signature = sign_voucher(payer, record, cumulative).await?;
    let answer = payer
        .signer()
        .sign(
            AgentAction::TempoSessionV2CloseAuthorization {
                authorization: TempoSessionV2CloseAuthorization {
                    voucher: voucher_action(record, cumulative),
                },
            },
            payer.wait,
        )
        .await?;
    let signature = recoverable(&answer)?;
    let digest = precompile_close_authorization_signing_hash_with_escrow(
        channel_id(record)?,
        cumulative,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        record.chain_id,
    )
    .map_err(|error| PaymentsError::InvalidRequest(format!("invalid close amount: {error}")))?;
    ensure_signed_by(
        &signature,
        digest,
        payer.wallet,
        "session close authorization",
    )?;
    Ok(SessionCredentialPayload::Close {
        channel_id: record.channel_id_hex.clone(),
        descriptor: Some(descriptor(record)?),
        settlement_route: None,
        cumulative_amount: cumulative.to_string(),
        signature: hex_prefixed(&voucher_signature),
        close_signature: Some(hex_prefixed(&tempo::primitive_signature_bytes(signature))),
    })
}

/// Signs and checks a voucher; returns its canonical TIP-1020 bytes.
async fn sign_voucher(
    payer: &Payer,
    record: &SessionRecord,
    cumulative: u128,
) -> Result<Vec<u8>, PaymentsError> {
    let answer = payer
        .signer()
        .sign(
            AgentAction::TempoSessionV2Voucher {
                authorization: voucher_action(record, cumulative),
            },
            payer.wait,
        )
        .await?;
    let bytes = tempo::primitive_signature_bytes(recoverable(&answer)?);
    let verified = verify_precompile_voucher_signature(
        &bytes,
        payer.wallet,
        channel_id(record)?,
        cumulative,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        record.chain_id,
    )
    .unwrap_or(false);
    if !verified {
        return Err(PaymentsError::SignedTransactionMismatch(
            "the session voucher signature does not verify for the channel".into(),
        ));
    }
    Ok(bytes)
}

fn voucher_action(record: &SessionRecord, cumulative: u128) -> TempoSessionV2Voucher {
    TempoSessionV2Voucher {
        chain_id: record.chain_id,
        token: record.token.clone(),
        recipient: record.recipient.clone(),
        operator: record.operator.clone(),
        payer: record.payer.clone(),
        authorized_signer: record.payer.clone(),
        salt_hex: record.salt_hex.clone(),
        expiring_nonce_hash_hex: record.expiring_nonce_hash_hex.clone(),
        channel_id_hex: record.channel_id_hex.clone(),
        cumulative_amount_wei: cumulative,
    }
}

/// The channel id of `record`, recomputed from its terms with `mpp`; a
/// record whose stored id disagrees is refused.
pub(super) fn channel_id(record: &SessionRecord) -> Result<B256, PaymentsError> {
    let parse = |value: &str| B256::from_str(value).ok();
    let stored = parse(&record.channel_id_hex);
    let (salt, expiring) = (
        parse(&record.salt_hex),
        parse(&record.expiring_nonce_hash_hex),
    );
    let (Some(stored), Some(salt), Some(expiring)) = (stored, salt, expiring) else {
        return Err(PaymentsError::Persistence(
            "a persisted session channel is malformed".into(),
        ));
    };
    let payer: Address = to_alloy_address(&record.payer)?;
    let computed = compute_precompile_channel_id(
        payer,
        to_alloy_address(&record.recipient)?,
        to_alloy_address(&record.operator)?,
        to_alloy_address(&record.token)?,
        salt,
        payer,
        expiring,
        record.chain_id,
    );
    if computed != stored {
        return Err(PaymentsError::Persistence(
            "a persisted session channel's id does not match its terms".into(),
        ));
    }
    Ok(stored)
}

/// The channel descriptor `mpp` servers use to find and verify the channel.
fn descriptor(record: &SessionRecord) -> Result<ChannelDescriptor, PaymentsError> {
    let payer = to_alloy_address(&record.payer)?;
    let parse = |value: &str| {
        B256::from_str(value).map_err(|_| {
            PaymentsError::Persistence("a persisted session channel is malformed".into())
        })
    };
    Ok(build_channel_descriptor(
        payer,
        to_alloy_address(&record.recipient)?,
        to_alloy_address(&record.operator)?,
        to_alloy_address(&record.token)?,
        parse(&record.salt_hex)?,
        payer,
        parse(&record.expiring_nonce_hash_hex)?,
    ))
}

fn encoded<T>(calls: Result<T, agentpay_domain::DomainError>) -> Result<T, PaymentsError> {
    calls.map_err(|error| {
        PaymentsError::InvalidRequest(format!("invalid session transaction: {error}"))
    })
}

fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
