//! Conversions between alloy types and the wire types.

use std::str::FromStr;

use agentpay_api::payments::{EvmReceipt, EvmTransactionInfo};
use agentpay_domain::EvmAddress;
use alloy_consensus::Transaction as _;
use alloy_eips::Typed2718;
use alloy_network::TransactionResponse;
use alloy_primitives::{hex, Address, B256};
use alloy_rpc_types_eth::{Transaction, TransactionReceipt};

use crate::error::PaymentsError;

/// The wire form of `address`: `0x` + 40 lower-case hex characters.
pub fn evm_address(address: Address) -> Result<EvmAddress, PaymentsError> {
    EvmAddress::from_str(&hex_prefixed(address.as_slice()))
        .map_err(|_| PaymentsError::Internal("failed to encode an EVM address".into()))
}

/// The alloy form of a wire address.
pub fn to_alloy_address(address: &EvmAddress) -> Result<Address, PaymentsError> {
    Address::from_str(address.as_str())
        .map_err(|_| PaymentsError::InvalidRequest("invalid EVM address".into()))
}

/// `0x`-prefixed hex of `bytes`.
#[must_use]
pub fn hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Parses a `0x` + 64 hex transaction hash.
pub fn parse_tx_hash(value: &str) -> Result<B256, PaymentsError> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| {
            PaymentsError::InvalidRequest("tx_hash must be 0x followed by 64 hex digits".into())
        })?;
    B256::from_str(digits)
        .map_err(|_| PaymentsError::InvalidRequest("tx_hash is not valid hex".into()))
}

/// Parses `0x`-prefixed calldata (`"0x"` is empty).
pub fn parse_calldata(value: &str) -> Result<Vec<u8>, PaymentsError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| PaymentsError::InvalidRequest("data_hex must start with 0x".into()))?;
    hex::decode(digits)
        .map_err(|_| PaymentsError::InvalidRequest("data_hex is not valid hex".into()))
}

/// The wire form of a receipt.
pub fn receipt(receipt: &TransactionReceipt) -> Result<EvmReceipt, PaymentsError> {
    Ok(EvmReceipt {
        tx_hash: hex_prefixed(receipt.transaction_hash.as_slice()),
        success: receipt.status(),
        block_number: receipt.block_number,
        block_hash: receipt.block_hash.map(|hash| hex_prefixed(hash.as_slice())),
        gas_used: receipt.gas_used,
        effective_gas_price_wei: receipt.effective_gas_price,
        contract_address: receipt.contract_address.map(evm_address).transpose()?,
    })
}

/// The wire form of a transaction.
pub fn transaction(tx: &Transaction) -> Result<EvmTransactionInfo, PaymentsError> {
    Ok(EvmTransactionInfo {
        tx_hash: hex_prefixed(tx.tx_hash().as_slice()),
        block_number: tx.block_number,
        from: evm_address(tx.from())?,
        to: tx.to().map(evm_address).transpose()?,
        nonce: tx.nonce(),
        value_wei: tx.value().to_string(),
        input_hex: hex_prefixed(tx.input()),
        gas_limit: tx.gas_limit(),
        tx_type: tx.ty(),
        chain_id: tx.chain_id(),
    })
}
