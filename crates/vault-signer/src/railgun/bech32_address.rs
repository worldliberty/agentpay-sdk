//! Railgun `0zk1…` bech32m address encoding.
//!
//! Wire layout (73 bytes total, then bech32m-encoded with HRP `0zk`):
//!   [0]      version = 0x01
//!   [1..33]  masterPublicKey (32-byte big-endian field element)
//!   [33..41] networkID XOR'd with ASCII `"railgun"` (8 bytes)
//!   [41..73] viewingPublicKey (32-byte ed25519 compressed point)
//!
//! `ALL_CHAINS_NETWORK_ID = "ffffffffffffffff"` indicates a cross-chain
//! address. The `"railgun"` ASCII XOR is JS `buffer-xor`: when one operand
//! is shorter, missing bytes are treated as 0, so byte 7 of the result is
//! `networkID[7]` unchanged (the 8th byte of "railgun" doesn't exist).

use bech32::{Bech32m, Hrp};

use crate::SignerError;

const HRP_RAW: &str = "0zk";
const VERSION: u8 = 0x01;
const RAILGUN: &[u8] = b"railgun";
const ALL_CHAINS_NETWORK_ID: [u8; 8] = [0xff; 8];

fn xor_network_id(network_id: [u8; 8]) -> [u8; 8] {
    let mut out = network_id;
    for (i, byte) in out.iter_mut().enumerate() {
        // `buffer-xor` semantics: bytes beyond the shorter operand are XOR'd
        // with implicit zero, so byte 7 (past "railgun"[6]) stays unchanged.
        if let Some(&r) = RAILGUN.get(i) {
            *byte ^= r;
        }
    }
    out
}

/// Encodes a Railgun shielded address. `master_public_key` is the 32-byte
/// big-endian Poseidon hash, `viewing_public_key` the 32-byte ed25519
/// compressed key. `network_id` defaults to `ALL_CHAINS` when `None`.
pub fn encode_address(
    master_public_key: [u8; 32],
    viewing_public_key: [u8; 32],
    network_id: Option<[u8; 8]>,
) -> Result<String, SignerError> {
    let nid = xor_network_id(network_id.unwrap_or(ALL_CHAINS_NETWORK_ID));
    let mut payload = [0u8; 73];
    payload[0] = VERSION;
    payload[1..33].copy_from_slice(&master_public_key);
    payload[33..41].copy_from_slice(&nid);
    payload[41..73].copy_from_slice(&viewing_public_key);

    let hrp =
        Hrp::parse(HRP_RAW).map_err(|e| SignerError::RailgunCrypto(format!("bech32 hrp: {e}")))?;
    bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|e| SignerError::RailgunCrypto(format!("bech32 encode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn matches_engine_addresses() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let got = encode_address(
                h32(&wallet.master_public_key_hex),
                h32(&wallet.viewing.public_key_hex),
                None,
            )
            .expect("encode");
            assert_eq!(
                got, wallet.address,
                "address mismatch on index {}",
                wallet.index
            );
            assert!(got.len() <= 127, "address {} exceeds bech32m cap", got);
        }
    }
}
