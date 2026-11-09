//! Verifies a signed transaction from the signer daemon against the request,
//! before it is returned or sent (ported from the TypeScript `signed-tx.ts`,
//! `assertSignedBroadcastTransactionMatchesRequest`).
//!
//! The signed envelope is decoded (exactly, with no trailing bytes), must be
//! an EIP-1559 transaction, and every field that decides what the
//! transaction does must equal the request: chain id, nonce, recipient,
//! value, calldata, gas limit, both fee caps, and an empty access list. The
//! signer recovered from the signature must be the agent's wallet, and the
//! hash the signer daemon reported must be the envelope's hash. Errors name
//! the field but never quote addresses or values.

use agentpay_domain::BroadcastTx;
use alloy_consensus::{SignableTransaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, Address, TxKind, B256, U256};

use super::convert::{parse_calldata, parse_tx_hash, to_alloy_address};
use crate::error::PaymentsError;

/// A signed transaction that matches its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTransaction {
    /// The signed envelope bytes.
    pub raw: Vec<u8>,
    /// The transaction hash.
    pub hash: B256,
}

/// Checks that `raw_tx_hex` (as returned by `SignForAgent`) is `expected`,
/// signed by `from`, with hash `reported_hash` when one was reported.
pub fn verify_signed_transaction(
    raw_tx_hex: &str,
    reported_hash: Option<&str>,
    expected: &BroadcastTx,
    from: Address,
) -> Result<VerifiedTransaction, PaymentsError> {
    let raw = raw_tx_hex
        .strip_prefix("0x")
        .and_then(|digits| alloy_primitives::hex::decode(digits).ok())
        .ok_or_else(|| mismatch("encoding"))?;
    let envelope = TxEnvelope::decode_2718_exact(&raw).map_err(|_| mismatch("encoding"))?;
    let TxEnvelope::Eip1559(signed) = envelope else {
        return Err(mismatch("transaction type"));
    };
    if expected.tx_type != 2 {
        return Err(mismatch("transaction type"));
    }
    let tx = signed.tx();
    let expected_to = to_alloy_address(&expected.to)?;
    let expected_data = parse_calldata(&normalized_calldata(&expected.data_hex))?;
    let checks = [
        (tx.chain_id == expected.chain_id, "chain id"),
        (tx.nonce == expected.nonce, "nonce"),
        (tx.to == TxKind::Call(expected_to), "recipient"),
        (tx.value == U256::from(expected.value_wei), "value"),
        (tx.input.as_ref() == expected_data.as_slice(), "calldata"),
        (tx.gas_limit == expected.gas_limit, "gas limit"),
        (
            tx.max_fee_per_gas == expected.max_fee_per_gas_wei,
            "max fee per gas",
        ),
        (
            tx.max_priority_fee_per_gas == expected.max_priority_fee_per_gas_wei,
            "max priority fee per gas",
        ),
        (tx.access_list.is_empty(), "access list"),
    ];
    if let Some((_, field)) = checks.iter().find(|(ok, _)| !ok) {
        return Err(mismatch(field));
    }
    let signer = signed
        .signature()
        .recover_address_from_prehash(&tx.signature_hash())
        .map_err(|_| mismatch("signature"))?;
    if signer != from {
        return Err(mismatch("signer"));
    }
    let hash = keccak256(&raw);
    if *signed.hash() != hash {
        return Err(mismatch("hash"));
    }
    if let Some(reported) = reported_hash {
        if parse_tx_hash(reported).ok() != Some(hash) {
            return Err(mismatch("reported hash"));
        }
    }
    Ok(VerifiedTransaction { raw, hash })
}

/// `data_hex` with a `0x` prefix (the domain type accepts it without one).
fn normalized_calldata(data_hex: &str) -> String {
    if data_hex.starts_with("0x") {
        data_hex.to_string()
    } else {
        format!("0x{data_hex}")
    }
}

fn mismatch(field: &str) -> PaymentsError {
    PaymentsError::SignedTransactionMismatch(format!(
        "the signed transaction's {field} does not match the request"
    ))
}
