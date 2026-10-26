//! Baby Jubjub (iden3 parameterization) twisted Edwards curve over BN254.
//!
//! We implement directly against the iden3 form `A·x² + y² = 1 + D·x²y²` with
//! `A = 168700`, `D = 168696`, using `ark_bn254::Fr` (== Babyjub's base field
//! `Fq`) for coordinate arithmetic. The arkworks `ark-ed-on-bn254` crate
//! provides the same curve but in the *normalized* twisted Edwards form
//! `x² + y² = 1 + (D/A)·x²y²`, which has a *different generator* and would
//! require a coordinate transform on every point we read or pack. Matching
//! Railgun's wire bytes is simpler if we just use the iden3 form directly.
//!
//! The subgroup generator `B8` (cofactor-cleared) lives at the iden3
//! constants and is what every Railgun spending-key operation multiplies by.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, MontFp, PrimeField, Zero};

use crate::SignerError;

/// Affine Baby Jubjub point in iden3 parameterization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

const A: Fr = MontFp!("168700");
const D: Fr = MontFp!("168696");

/// The cofactor-cleared subgroup generator `B8` from iden3 / circomlibjs.
/// Every Railgun spending operation multiplies by this point — not the raw
/// curve generator, which lies outside the prime-order subgroup.
pub const BASE8: Point = Point {
    x: MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    y: MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
};

/// Identity element `(0, 1)`.
pub const IDENTITY: Point = Point {
    x: Fr::ZERO,
    y: Fr::ONE,
};

impl Point {
    /// Returns `true` if the point satisfies the curve equation.
    pub fn in_curve(&self) -> bool {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        let lhs = A * x2 + y2;
        let rhs = Fr::ONE + D * x2 * y2;
        lhs == rhs
    }
}

/// Affine twisted-Edwards point addition (iden3 formula). Returns the sum of
/// `a + b` on the iden3 Baby Jubjub curve.
pub fn add(a: &Point, b: &Point) -> Point {
    // From iden3 babyjub.js:
    //   res.x = (a.x*b.y + a.y*b.x) / (1 + d*a.x*b.x*a.y*b.y)
    //   res.y = ((a.y - A*a.x)*(b.x + b.y) + A*a.x*b.y - a.y*b.x) / (1 - d*...)
    let beta = a.x * b.y;
    let gamma = a.y * b.x;
    let delta = (a.y - A * a.x) * (b.x + b.y);
    let tau = beta * gamma;
    let dtau = D * tau;

    Point {
        x: (beta + gamma) / (Fr::ONE + dtau),
        y: (delta + A * beta - gamma) / (Fr::ONE - dtau),
    }
}

/// Returns `2·p`.
pub fn double(p: &Point) -> Point {
    add(p, p)
}

/// `mulPointEscalar(base, e)` per circomlibjs — double-and-add over an
/// arbitrary big-endian scalar. The scalar is iterated bit-by-bit
/// little-endian (`shr` loop in JS).
pub fn mul_point_escalar_be(base: &Point, scalar_be: &[u8]) -> Point {
    // Convert BE bytes to LE bits, MSB-first within each byte.
    let mut bits: Vec<bool> = Vec::with_capacity(scalar_be.len() * 8);
    for &byte in scalar_be.iter().rev() {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1);
        }
    }
    let mut res = IDENTITY;
    let mut exp = *base;
    for bit in bits {
        if bit {
            res = add(&res, &exp);
        }
        exp = double(&exp);
    }
    res
}

/// `mulPointEscalar(base, e)` with the scalar already as little-endian bytes.
pub fn mul_point_escalar_le(base: &Point, scalar_le: &[u8]) -> Point {
    let be: Vec<u8> = scalar_le.iter().rev().copied().collect();
    mul_point_escalar_be(base, &be)
}

/// circomlibjs `babyjub.packPoint(P)` — little-endian 32-byte y-coordinate
/// with the high bit of byte 31 set when `x` is in the "negative" half of
/// the field (`x > p/2`, matching ffjavascript's `F.lt(P[0], F.zero)`).
pub fn pack_point(p: &Point) -> [u8; 32] {
    let mut bytes = fr_to_le_bytes(p.y);
    if is_negative_half(p.x) {
        bytes[31] |= 0x80;
    }
    bytes
}

/// circomlibjs `babyjub.unpackPoint(buff)`. Returns `None` for malformed input
/// (out-of-range y, or no square root for the implied x).
pub fn unpack_point(buff: &[u8; 32]) -> Option<Point> {
    let sign_set = (buff[31] & 0x80) != 0;
    let mut y_bytes = *buff;
    y_bytes[31] &= 0x7f;
    let y = fr_from_le_bytes(&y_bytes)?;

    // Recover x from y: A*x² + y² = 1 + D*x²y²  =>  x² = (1 - y²) / (A - D*y²)
    let y2 = y * y;
    let num = Fr::ONE - y2;
    let den = A - D * y2;
    if den.is_zero() {
        return None;
    }
    let x2 = num / den;
    let x_candidate = sqrt_fr(x2)?;
    // `sqrt` returns *some* root; we must canonicalize. After this normalization,
    // `x` is in the positive half (`x <= p/2`); then negate iff the sign bit was set.
    let x_positive = if is_negative_half(x_candidate) {
        -x_candidate
    } else {
        x_candidate
    };
    let x = if sign_set { -x_positive } else { x_positive };

    let p = Point { x, y };
    if !p.in_curve() {
        return None;
    }
    Some(p)
}

fn fr_to_le_bytes(value: Fr) -> [u8; 32] {
    let bigint = value.into_bigint();
    let le = bigint.to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len()].copy_from_slice(&le);
    out
}

fn fr_from_le_bytes(bytes: &[u8; 32]) -> Option<Fr> {
    // PrimeField::from_le_bytes_mod_order reduces, but ffjavascript rejects
    // y values >= p. Reject those here too to match `Scalar.gt(P[1], exports.p)`.
    let candidate = Fr::from_le_bytes_mod_order(bytes);
    let mut reduced = [0u8; 32];
    let le = candidate.into_bigint().to_bytes_le();
    reduced[..le.len()].copy_from_slice(&le);
    if reduced != *bytes {
        return None;
    }
    Some(candidate)
}

/// Matches ffjavascript `F.lt(x, F.zero)`: cast `x` to a signed
/// representative (`x > p/2 ? x - p : x`) and check `< 0`. Equivalent to
/// `x > p/2`.
fn is_negative_half(x: Fr) -> bool {
    // p / 2 (rounded down). p is odd, so this is (p-1)/2.
    // We compute by comparing the LE-encoded bigint to a precomputed half.
    let x_le = x.into_bigint().to_bytes_le();
    // Compare against (p-1)/2 little-endian:
    //   p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    //   (p-1)/2 = 10944121435919637611123202872628637544274182200208017171849102093287904247808
    const HALF_LE: [u8; 32] = [
        0x00, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33,
        0x28, 0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e,
        0x64, 0x18,
    ];
    // Compare big-endian, i.e., from byte 31 down to byte 0.
    for i in (0..32).rev() {
        let a = *x_le.get(i).unwrap_or(&0);
        let b = HALF_LE[i];
        match a.cmp(&b) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    false
}

/// Tonelli-Shanks square root in `Fr_bn254` via the arkworks `sqrt()` impl.
fn sqrt_fr(value: Fr) -> Option<Fr> {
    value.sqrt()
}

/// Helper to convert a Baby Jubjub coordinate Fr to a 32-byte big-endian hex
/// — useful for matching JS test vectors which dump `xHex` / `yHex` in BE.
pub fn fr_to_be_bytes(value: Fr) -> [u8; 32] {
    let mut le = fr_to_le_bytes(value);
    le.reverse();
    le
}

/// Helper to load an Fr from 32 big-endian bytes. Returns `None` if the value
/// is >= p.
pub fn fr_from_be_bytes(be: &[u8; 32]) -> Option<Fr> {
    let mut le = *be;
    le.reverse();
    fr_from_le_bytes(&le)
}

/// Errors from the more strongly-typed wrappers below.
pub fn require_in_curve(point: &Point) -> Result<(), SignerError> {
    if !point.in_curve() {
        return Err(SignerError::RailgunCrypto(
            "point is not on Baby Jubjub".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base8_is_on_curve() {
        assert!(
            BASE8.in_curve(),
            "Base8 must satisfy the iden3 curve equation"
        );
    }

    #[test]
    fn double_matches_add() {
        let p = mul_point_escalar_be(&BASE8, &[5u8]);
        let d1 = double(&p);
        let d2 = add(&p, &p);
        assert_eq!(d1, d2);
    }

    #[test]
    fn round_trip_pack_unpack() {
        for k in [1u8, 2, 7, 99, 250] {
            let p = mul_point_escalar_be(&BASE8, &[k]);
            let packed = pack_point(&p);
            let recovered = unpack_point(&packed).expect("unpack");
            assert_eq!(recovered, p, "round-trip k={k}");
        }
    }

    #[test]
    fn mul_by_one_is_identity_op() {
        let p = mul_point_escalar_be(&BASE8, &[1u8]);
        assert_eq!(p, BASE8);
    }
}
