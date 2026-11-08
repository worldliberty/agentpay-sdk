use std::collections::BTreeSet;

use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::*;

mod broadcast;
mod model;
mod permit2;
mod policy;
mod retired;
mod solana;
mod solana_payment;
mod tempo;
mod typed_data;

sol! {
    function approve(address spender, uint256 value);
    function transfer(address to, uint256 value);
    function increaseAllowance(address spender, uint256 addedValue);
    function setApprovalForAll(address operator, bool approved);
}

fn broadcast_tx_with_calldata(data_hex: String, value_wei: u128) -> BroadcastTx {
    BroadcastTx {
        chain_id: 1,
        nonce: 0,
        to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .expect("to"),
        value_wei,
        data_hex,
        gas_limit: 60_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    }
}

fn unix_timestamp(value: OffsetDateTime) -> u64 {
    value.unix_timestamp().try_into().expect("unix timestamp")
}

fn future_unix_timestamp(offset: time::Duration) -> u64 {
    unix_timestamp(OffsetDateTime::now_utc() + offset)
}

fn mutate_checksum_case(checksummed: &str) -> String {
    let mut invalid = checksummed.to_owned();
    let (index, ch) = invalid
        .char_indices()
        .skip(2)
        .find(|(_, ch)| ch.is_ascii_alphabetic())
        .expect("checksummed address should contain alphabetic characters");
    let flipped = if ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase()
    } else {
        ch.to_ascii_lowercase()
    };
    invalid.replace_range(index..index + ch.len_utf8(), &flipped.to_string());
    assert_ne!(invalid, checksummed);

    invalid
}

sol! {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    function permit(address owner, PermitSingle permitSingle, bytes signature);
    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);
    function receiveWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature);
    function transferWithMemo(address to, uint256 amount, bytes32 memo);
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
