//! Address, hex, integer, and RLP encoding helpers shared by the action types.

use alloy_primitives::{Address, U160, U256};

use crate::{DomainError, EvmAddress};

pub(super) fn evm_to_alloy_address(address: &EvmAddress) -> Result<Address, DomainError> {
    Address::parse_checksummed(address.as_str(), None)
        .or_else(|_| address.as_str().parse())
        .map_err(|_| DomainError::InvalidAddress)
}

pub(super) fn alloy_address_to_evm(address: Address) -> Result<EvmAddress, DomainError> {
    let value = format!("0x{}", hex::encode(address.as_slice()));
    value.parse::<EvmAddress>()
}

pub(super) fn zero_evm_address() -> EvmAddress {
    "0x0000000000000000000000000000000000000000"
        .parse()
        .expect("zero address literal must be valid")
}

pub(super) fn decode_hex_payload(input: &str) -> Result<Vec<u8>, DomainError> {
    let trimmed = input.trim();
    let payload = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if !payload.len().is_multiple_of(2) || !payload.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(DomainError::InvalidTransactionDataHex);
    }
    hex::decode(payload).map_err(|_| DomainError::InvalidTransactionDataHex)
}

pub(super) fn decode_hex_32(input: &str, label: &str) -> Result<[u8; 32], DomainError> {
    let bytes = decode_hex_payload(input).map_err(|_| {
        DomainError::InvalidTypedDataDomain(format!("{label} must be a 32-byte hex value"))
    })?;
    if bytes.len() != 32 {
        return Err(DomainError::InvalidTypedDataDomain(format!(
            "{label} must be exactly 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(super) fn u256_to_u128(value: U256) -> Result<u128, DomainError> {
    if value > U256::from(u128::MAX) {
        return Err(DomainError::AmountOutOfRange);
    }
    Ok(value.to::<u128>())
}

pub(super) fn u160_to_u128(value: U160) -> Result<u128, DomainError> {
    let bytes = value.to_be_bytes::<20>();
    if bytes[..4].iter().any(|byte| *byte != 0) {
        return Err(DomainError::AmountOutOfRange);
    }
    Ok(u128::from_be_bytes(
        bytes[4..].try_into().expect("16-byte slice"),
    ))
}

pub(super) fn rlp_encode_u64(value: u64) -> Vec<u8> {
    rlp_encode_u128(u128::from(value))
}

pub(super) fn rlp_encode_u128(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_encode_bytes(&bytes[first_non_zero..])
}

pub(super) fn rlp_encode_u256_bytes(value: &[u8; 32]) -> Vec<u8> {
    let first_non_zero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    rlp_encode_bytes(&value[first_non_zero..])
}

pub(super) fn rlp_encode_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return vec![value[0]];
    }
    if value.len() <= 55 {
        let mut out = Vec::with_capacity(1 + value.len());
        out.push(0x80 + value.len() as u8);
        out.extend(value);
        return out;
    }

    let len_bytes = usize_to_be_bytes_no_leading_zero(value.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + value.len());
    out.push(rlp_long_length_prefix(0xb7, len_bytes.len()));
    out.extend(len_bytes);
    out.extend(value);
    out
}

pub(super) fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(Vec::len).sum();
    let mut payload: Vec<u8> = Vec::with_capacity(payload_len);
    for item in items {
        payload.extend_from_slice(item);
    }

    if payload.len() <= 55 {
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(0xc0 + payload.len() as u8);
        out.extend(payload);
        return out;
    }

    let len_bytes = usize_to_be_bytes_no_leading_zero(payload.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + payload.len());
    out.push(rlp_long_length_prefix(0xf7, len_bytes.len()));
    out.extend(len_bytes);
    out.extend(payload);
    out
}

fn rlp_long_length_prefix(offset: u8, len_of_len: usize) -> u8 {
    assert!(
        len_of_len <= 8,
        "RLP payload length-of-length must be <= 8 bytes"
    );
    offset + u8::try_from(len_of_len).expect("RLP payload length-of-length must fit in u8")
}

fn usize_to_be_bytes_no_leading_zero(value: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes[first_non_zero..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_long_length_prefix_accepts_u64_sized_lengths() {
        assert_eq!(rlp_long_length_prefix(0xb7, 1), 0xb8);
        assert_eq!(rlp_long_length_prefix(0xb7, 8), 0xbf);
        assert_eq!(rlp_long_length_prefix(0xf7, 1), 0xf8);
        assert_eq!(rlp_long_length_prefix(0xf7, 8), 0xff);
    }

    #[test]
    #[should_panic(expected = "RLP payload length-of-length must be <= 8 bytes")]
    fn rlp_long_length_prefix_rejects_lengths_larger_than_u64() {
        let _ = rlp_long_length_prefix(0xb7, 9);
    }

    #[test]
    fn rlp_integer_encoding_strips_leading_zeroes() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(rlp_encode_u64(0x7f), vec![0x7f]);
        assert_eq!(rlp_encode_u64(0x80), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_u128(0x0100), vec![0x82, 0x01, 0x00]);
        assert_eq!(rlp_encode_u64(0x0100), rlp_encode_u128(0x0100));
    }
}
