//! Railgun viewing-key ECDH primitives.
//!
//! The module is named `x25519` because Railgun's engine source labels these
//! as "X25519 viewing keys", but the actual implementation in
//! `engine/src/utils/keys-utils.ts` and `scalar-multiply.ts` operates on
//! **Ed25519 compressed Edwards points** via `@noble/ed25519::Point.multiply`,
//! not Curve25519 / Montgomery `x25519`. The two are isomorphic at the
//! mathematical level but produce different wire bytes; we must use Ed25519
//! point arithmetic to match the JS reference.
//!
//! Two operations are exposed:
//! - `get_public_viewing_key(seed)` — `ed25519::getPublicKey(seed)`, returning
//!   the 32-byte compressed Ed25519 public key.
//! - `get_shared_symmetric_key(my_priv, their_pub)` — `sha256(their_pub *
//!   ed25519_scalar(my_priv))`, returning a 32-byte AES key.

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::SignerError;

/// `getPublicViewingKey(seed)` — Ed25519 compressed public key from a 32-byte
/// seed. Uses standard RFC 8032 derivation: clamp + scalar-mult of the
/// Ed25519 base point.
pub fn get_public_viewing_key(seed: &[u8; 32]) -> [u8; 32] {
    let sk = SigningKey::from_bytes(seed);
    sk.verifying_key().to_bytes()
}

/// `getPrivateScalarFromPrivateKey(seed)` — derive the RFC 8032 clamped scalar
/// from the 32-byte seed, reduced mod the Ed25519 group order `L`. The JS
/// special-cases scalar == 0 by returning `L`, which in practice is identical
/// modulo `L` (the point `L·B = identity` either way); we just reduce.
fn ed25519_scalar_from_seed(seed: &[u8; 32]) -> Scalar {
    let hash = Sha512::digest(seed);
    let mut head = [0u8; 32];
    head.copy_from_slice(&hash[..32]);
    // RFC 8032 clamp == `adjustBytes25519(..., 'le')` in keys-utils.ts.
    head[0] &= 0b1111_1000;
    head[31] &= 0b0111_1111;
    head[31] |= 0b0100_0000;
    Scalar::from_bytes_mod_order(head)
}

/// `getSharedSymmetricKey(my_priv, their_pub)` — Ed25519 point scalar mult
/// followed by SHA-256. Returns `None` if `their_pub` is not a valid Edwards
/// point, mirroring the JS `try { ... } catch { return undefined; }`.
pub fn get_shared_symmetric_key(
    my_priv: &[u8; 32],
    their_pub: &[u8; 32],
) -> Option<Zeroizing<[u8; 32]>> {
    let compressed = CompressedEdwardsY(*their_pub);
    let point = compressed.decompress()?;
    let scalar = ed25519_scalar_from_seed(my_priv);
    let product = (point * scalar).compress().to_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(product));
    Some(Zeroizing::new(out))
}

/// Wraps `get_shared_symmetric_key` with a typed error for callers that need
/// to distinguish "bad input point" from success.
pub fn shared_symmetric_key(
    my_priv: &[u8; 32],
    their_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SignerError> {
    get_shared_symmetric_key(my_priv, their_pub).ok_or_else(|| {
        SignerError::RailgunCrypto("invalid Edwards point in shared-key derivation".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn viewing_pub_matches_wallets() {
        // Wallet viewing.publicKeyHex is `getPublicViewingKey(viewing.privateKeyHex)`.
        let vectors = load();
        for wallet in &vectors.wallets {
            let priv_bytes = h32(&wallet.viewing.private_key_hex);
            let got = get_public_viewing_key(&priv_bytes);
            assert_eq!(
                hex::encode(got),
                wallet.viewing.public_key_hex,
                "viewing pub mismatch on index {}",
                wallet.index
            );
        }
    }

    #[test]
    fn shared_key_matches_engine_sample() {
        let vectors = load();
        for sample in &vectors.shared_key_samples {
            let my = h32(&sample.sender_viewing_priv_hex);
            let their_pub = h32(&sample.receiver_viewing_pub_hex);
            let got = shared_symmetric_key(&my, &their_pub).expect("derive");
            assert_eq!(hex::encode(&*got), sample.shared_key_hex);
        }
    }

    #[test]
    fn shared_key_recomputes_receiver_pub() {
        // Sanity: the recorded receiver pub is derived from receiver priv.
        let vectors = load();
        for sample in &vectors.shared_key_samples {
            let recv_priv = h32(&sample.receiver_viewing_priv_hex);
            let got = get_public_viewing_key(&recv_priv);
            assert_eq!(hex::encode(got), sample.receiver_viewing_pub_hex);
        }
    }
}
