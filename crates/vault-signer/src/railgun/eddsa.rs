//! iden3 EdDSA-Poseidon over Baby Jubjub (Railgun spending authority).
//!
//! Ported line-by-line from `@railgun-community/circomlibjs`'s
//! `eddsa.signPoseidon` / `eddsa.verifyPoseidon`. The brief described this as
//! SHA-512-based; the actual reference uses **original BLAKE-512** (the SHA-3
//! finalist), provided by the `blake-hash` npm package. We use the
//! `blake512-hash` Rust crate (same constants, cross-verified bit-for-bit).
//!
//! Algorithm:
//!     h1 = blake512(prv)                                 // 64 bytes
//!     sBuff = prune(h1[0..32])                           // X25519 clamp
//!     s = LE-int(sBuff)                                  // unreduced
//!     A = mulPointEscalar(B8, s >> 3)                    // public key
//!     msgBuff = LE-int-to-bytes(msg_scalar, 32)
//!     rBuff = blake512(h1[32..64] || msgBuff)            // 64 bytes
//!     r = LE-int(rBuff) mod subOrder
//!     R8 = mulPointEscalar(B8, r)
//!     hm = poseidon([R8.x, R8.y, A.x, A.y, msg_scalar])  // BN254 Fr
//!     S = (r + hm * s) mod subOrder
//!
//! Verification:
//!     hm  = poseidon([sig.R8.x, sig.R8.y, A.x, A.y, msg])
//!     LHS = B8 * S
//!     RHS = sig.R8 + A * (hm * 8)                        // ×8 since A uses s>>3
//!     LHS ?= RHS

use ark_ed_on_bn254::Fr as ScalarField;
use ark_ff::{BigInteger, PrimeField};
// `blake512-hash` is built on `digest@0.10`; `sha2` re-exports that same trait
// so we route through it to avoid pulling in another digest version.
use blake512_hash::Blake512;
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::railgun::babyjubjub::{
    self, add as bj_add, fr_to_be_bytes, mul_point_escalar_le, BASE8,
};
use crate::railgun::poseidon::poseidon_bn254_be;
use crate::SignerError;

/// One signature `(R8, S)`. `R8` is a Baby Jubjub point; `S` is a scalar in
/// `ark_ed_on_bn254::Fr` (i.e., reduced mod the Baby Jubjub subgroup order).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EddsaSignature {
    pub r8: babyjubjub::Point,
    pub s: ScalarField,
}

impl EddsaSignature {
    /// Serializes as `R8.x || R8.y || S` (96 bytes, all 32-byte big-endian).
    ///
    /// This is the unpacked form snarkjs / `circomlibjs` expect when feeding
    /// the signature into a Baby Jubjub circuit as three field-element private
    /// inputs. The 64-byte packed form (`packPoint(R8) || S`) exists too but
    /// requires the circuit to call `unpack_point` again — the unpacked form
    /// matches what the Railgun proving inputs actually want.
    #[must_use]
    pub fn to_unpacked_xy_s_bytes(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..32].copy_from_slice(&fr_to_be_bytes(self.r8.x));
        out[32..64].copy_from_slice(&fr_to_be_bytes(self.r8.y));
        let s_bytes = self.s.into_bigint().to_bytes_be();
        // BN254 Fr serializes as ≤32 bytes; left-pad to a canonical 32.
        out[64 + (32 - s_bytes.len())..].copy_from_slice(&s_bytes);
        out
    }
}

fn prune(buff: &mut [u8; 32]) {
    // Standard X25519 / Ed25519 clamp.
    buff[0] &= 0xf8;
    buff[31] &= 0x7f;
    buff[31] |= 0x40;
}

fn blake512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake512::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    bytes
}

fn derive_s_and_prefix(prv: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let h1 = blake512(prv);
    let mut s_buff = [0u8; 32];
    s_buff.copy_from_slice(&h1[..32]);
    prune(&mut s_buff);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&h1[32..]);
    (Zeroizing::new(s_buff), Zeroizing::new(prefix))
}

/// `eddsa.prv2pub(prv)` — public spending key, Base8 multiplied by `s >> 3`.
pub fn prv_to_pub(prv: &[u8; 32]) -> babyjubjub::Point {
    let (s_buff, _) = derive_s_and_prefix(prv);
    // `s >> 3` discards three low bits — they're zero anyway after `prune`,
    // but the iden3 code explicitly shifts so the scalar multiplied is `s/8`.
    let mut shifted = [0u8; 32];
    for i in 0..32 {
        let lo = s_buff[i] >> 3;
        let hi = if i + 1 < 32 { s_buff[i + 1] << 5 } else { 0 };
        shifted[i] = lo | hi;
    }
    mul_point_escalar_le(&BASE8, &shifted)
}

fn le_bytes_to_scalar_mod_suborder(bytes: &[u8]) -> ScalarField {
    ScalarField::from_le_bytes_mod_order(bytes)
}

fn message_scalar_be_to_le32(msg_be: &[u8; 32]) -> [u8; 32] {
    let mut le = *msg_be;
    le.reverse();
    le
}

/// `eddsa.signPoseidon(prv, msg)` — produces `(R8, S)`. `msg_scalar_be` is
/// the 32-byte big-endian Poseidon-input integer (the engine treats it as a
/// bigint and `leInt2Buff(msg, 32)`s it for the blake step).
pub fn sign_poseidon(
    prv: &[u8; 32],
    msg_scalar_be: &[u8; 32],
) -> Result<EddsaSignature, SignerError> {
    let (s_buff, prefix) = derive_s_and_prefix(prv);

    // `r = blake512(prefix || msgBuff_le) mod subOrder`
    let mut r_input = Vec::with_capacity(64);
    r_input.extend_from_slice(prefix.as_ref());
    r_input.extend_from_slice(&message_scalar_be_to_le32(msg_scalar_be));
    let r_hash = blake512(&r_input);
    let r = le_bytes_to_scalar_mod_suborder(&r_hash);

    // R8 = B8 * r
    let r_le: Vec<u8> = r.into_bigint().to_bytes_le();
    let r8 = mul_point_escalar_le(&BASE8, &r_le);

    // A = B8 * (s >> 3)  (reconstruct from prv so we don't need the caller to pass it)
    let a = prv_to_pub(prv);

    // hm = poseidon([R8.x, R8.y, A.x, A.y, msg])
    let inputs = [
        fr_to_be_bytes(r8.x),
        fr_to_be_bytes(r8.y),
        fr_to_be_bytes(a.x),
        fr_to_be_bytes(a.y),
        *msg_scalar_be,
    ];
    let hm_be = poseidon_bn254_be(&inputs)?;

    // S = (r + hm * s) mod subOrder. The JS keeps `s` unreduced (a raw 256-bit
    // integer); modular reduction happens implicitly during `Fr.add`/`Fr.mul`,
    // so we just reduce here.
    let s = le_bytes_to_scalar_mod_suborder(s_buff.as_ref());
    let hm = ScalarField::from_be_bytes_mod_order(&hm_be);
    let s_out = r + hm * s;

    Ok(EddsaSignature { r8, s: s_out })
}

/// `eddsa.verifyPoseidon(msg, sig, A)`.
pub fn verify_poseidon(
    msg_scalar_be: &[u8; 32],
    sig: &EddsaSignature,
    a: &babyjubjub::Point,
) -> Result<bool, SignerError> {
    if !sig.r8.in_curve() || !a.in_curve() {
        return Ok(false);
    }

    let inputs = [
        fr_to_be_bytes(sig.r8.x),
        fr_to_be_bytes(sig.r8.y),
        fr_to_be_bytes(a.x),
        fr_to_be_bytes(a.y),
        *msg_scalar_be,
    ];
    let hm_be = poseidon_bn254_be(&inputs)?;

    // Pleft = B8 * S
    let s_le = sig.s.into_bigint().to_bytes_le();
    let p_left = mul_point_escalar_le(&BASE8, &s_le);

    // Pright = R8 + A * (hm * 8)
    let hm = ScalarField::from_be_bytes_mod_order(&hm_be);
    let eight = ScalarField::from(8u64);
    let hm8 = hm * eight;
    let hm8_le = hm8.into_bigint().to_bytes_le();
    let a_hm8 = mul_point_escalar_le(a, &hm8_le);
    let p_right = bj_add(&sig.r8, &a_hm8);

    Ok(p_left == p_right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn spending_pub_matches_fixture() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let prv = h32(&wallet.spending.private_key_hex);
            let pub_key = prv_to_pub(&prv);
            let x_hex = hex::encode(fr_to_be_bytes(pub_key.x));
            let y_hex = hex::encode(fr_to_be_bytes(pub_key.y));
            assert_eq!(
                x_hex, wallet.spending.public_key.x_hex,
                "x idx={}",
                wallet.index
            );
            assert_eq!(
                y_hex, wallet.spending.public_key.y_hex,
                "y idx={}",
                wallet.index
            );
        }
    }

    #[test]
    fn sign_matches_fixture() {
        // The fixture's `messageHashHex` is `poseidon([messageScalar])` — the
        // engine pre-hashes before passing to `signEDDSA`. Our primitive
        // signs whatever bigint the caller hands in; the higher-level
        // Railgun call path will do the poseidon wrapping itself.
        let vectors = load();
        for wallet in &vectors.wallets {
            let prv = h32(&wallet.spending.private_key_hex);
            for sample in &wallet.eddsa_signatures {
                let msg = h32(&sample.message_hash_hex);
                let sig = sign_poseidon(&prv, &msg).expect("sign");
                assert_eq!(
                    hex::encode(fr_to_be_bytes(sig.r8.x)),
                    sample.signature.r8_x_hex,
                    "R8.x wallet={} msg={}",
                    wallet.index,
                    sample.message_scalar_hex
                );
                assert_eq!(
                    hex::encode(fr_to_be_bytes(sig.r8.y)),
                    sample.signature.r8_y_hex,
                    "R8.y wallet={} msg={}",
                    wallet.index,
                    sample.message_scalar_hex
                );
                let s_be = {
                    let bytes = sig.s.into_bigint().to_bytes_be();
                    let mut padded = [0u8; 32];
                    padded[32 - bytes.len()..].copy_from_slice(&bytes);
                    padded
                };
                assert_eq!(
                    hex::encode(s_be),
                    sample.signature.s_hex,
                    "S wallet={} msg={}",
                    wallet.index,
                    sample.message_scalar_hex
                );
            }
        }
    }

    #[test]
    fn verify_round_trips() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let prv = h32(&wallet.spending.private_key_hex);
            let a = prv_to_pub(&prv);
            for sample in &wallet.eddsa_signatures {
                let msg = h32(&sample.message_hash_hex);
                let sig = sign_poseidon(&prv, &msg).expect("sign");
                let ok = verify_poseidon(&msg, &sig, &a).expect("verify");
                assert!(ok, "verify failed wallet={}", wallet.index);
            }
        }
    }
}
