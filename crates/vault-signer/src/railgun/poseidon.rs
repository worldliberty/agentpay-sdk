//! Poseidon over BN254 (circomlibjs-compatible) for Railgun.
//!
//! Wraps `light-poseidon`'s `new_circom(arity)` constructor — the same
//! constants and round schedule as `@railgun-community/circomlibjs`'s
//! `poseidon.js`, which in turn is the iden3 / circomlibjs reference.
//!
//! Inputs and outputs are 32-byte big-endian field elements; each input must
//! already be reduced mod the BN254 scalar field `Fr`, otherwise the hasher
//! errors. `light-poseidon` caps the arity at 12 (t=13); Railgun's circuits
//! used here only need arity up to 5.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonError};

use crate::SignerError;

fn map_err(err: PoseidonError) -> SignerError {
    SignerError::RailgunCrypto(format!("poseidon: {err}"))
}

/// Hashes 1..=12 big-endian 32-byte field elements with circomlibjs-compatible
/// Poseidon parameters over BN254. Returns the 32-byte big-endian digest.
///
/// Each input is reduced mod `p` before hashing — Railgun's JS path interprets
/// raw `bigint` inputs and the underlying poseidon WASM lib silently reduces,
/// so untrusted byte strings (e.g. raw private keys that happen to exceed
/// `p`) must not be rejected here.
pub fn poseidon_bn254_be(inputs: &[[u8; 32]]) -> Result<[u8; 32], SignerError> {
    if inputs.is_empty() {
        return Err(SignerError::RailgunCrypto(
            "poseidon requires at least one input".into(),
        ));
    }
    let reduced: Vec<[u8; 32]> = inputs
        .iter()
        .map(|chunk| {
            let fe = Fr::from_be_bytes_mod_order(chunk);
            let bytes = fe.into_bigint().to_bytes_be();
            // BN254 Fr is 254 bits → at most 32 bytes; left-pad to 32.
            let mut out = [0u8; 32];
            out[32 - bytes.len()..].copy_from_slice(&bytes);
            out
        })
        .collect();
    let mut hasher = Poseidon::<Fr>::new_circom(reduced.len()).map_err(map_err)?;
    let refs: Vec<&[u8]> = reduced.iter().map(|chunk| chunk.as_slice()).collect();
    hasher.hash_bytes_be(&refs).map_err(map_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    fn h(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).expect("hex");
        bytes.try_into().expect("32 bytes")
    }

    #[test]
    fn matches_circomlibjs_poseidon_samples() {
        let vectors = load();
        for sample in &vectors.poseidon_samples {
            let inputs: Vec<[u8; 32]> = sample.inputs_hex.iter().map(|s| h(s)).collect();
            let got = poseidon_bn254_be(&inputs).expect("hash");
            let want = h(&sample.output_hex);
            assert_eq!(
                hex::encode(got),
                hex::encode(want),
                "poseidon mismatch on inputs {:?}",
                sample.inputs_hex,
            );
        }
    }
}
