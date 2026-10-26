//! High-level Railgun wallet derivations on top of the lower primitives.
//!
//! - `get_nullifying_key(viewing_priv)` = poseidon([priv as bigint])
//! - `get_master_public_key(spend_pub, nullifying_key)` = poseidon([x, y, nk])
//! - `get_nullifier(nk, leaf_index)` = poseidon([nk, leaf_index])
//!
//! All field elements travel as 32-byte big-endian; the JS engine likewise
//! pads each `bigint` to UINT_256 before hashing.

use std::fmt;

use zeroize::Zeroizing;

use crate::railgun::{
    aes_gcm, babyjubjub, bech32_address, bip32, eddsa, poseidon::poseidon_bn254_be, x25519,
};
use crate::SignerError;

/// Bundle of everything a Railgun wallet exposes once derived from a seed.
///
/// Private key material is wrapped in [`Zeroizing`] and redacted from `Debug`
/// output (the nullifying key is derived from the viewing private key and is
/// redacted too); callers must keep the struct itself short-lived.
/// Public-only callers (e.g. the admin CLI's `railgun-public-key`
/// subcommand) should read `encoded_address` and drop the rest immediately.
#[derive(Clone)]
pub struct RailgunWalletKeys {
    /// Baby Jubjub spending private key (raw 32 bytes from the BIP32 chain).
    pub spending_private_key: Zeroizing<[u8; 32]>,
    /// Baby Jubjub spending public key as `(x, y)` big-endian 32-byte field
    /// elements (matches the Poseidon-input encoding used downstream).
    pub spending_public_key_x_be: [u8; 32],
    pub spending_public_key_y_be: [u8; 32],
    /// Curve25519 viewing private key (raw 32 bytes from the BIP32 chain).
    pub viewing_private_key: Zeroizing<[u8; 32]>,
    /// Ed25519-compressed 32-byte viewing public key.
    pub viewing_public_key: [u8; 32],
    /// `poseidon([viewing_priv])`.
    pub nullifying_key: [u8; 32],
    /// `poseidon([spend_pub.x, spend_pub.y, nullifying_key])`.
    pub master_public_key: [u8; 32],
    /// Bech32m-encoded `0zk1…` address with `ALL_CHAINS` network id.
    pub encoded_address: String,
}

impl fmt::Debug for RailgunWalletKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RailgunWalletKeys")
            .field("spending_private_key", &"<redacted>")
            .field(
                "spending_public_key_x_be",
                &hex::encode(self.spending_public_key_x_be),
            )
            .field(
                "spending_public_key_y_be",
                &hex::encode(self.spending_public_key_y_be),
            )
            .field("viewing_private_key", &"<redacted>")
            .field("viewing_public_key", &hex::encode(self.viewing_public_key))
            .field("nullifying_key", &"<redacted>")
            .field("master_public_key", &hex::encode(self.master_public_key))
            .field("encoded_address", &self.encoded_address)
            .finish()
    }
}

/// Derives one full Railgun wallet (spending + viewing pair at `index`) from
/// a raw seed. The seed can be either a BIP-39 mnemonic seed or, in the
/// daemon's case, the secp256k1 vault key bytes — `master_key_from_seed`
/// accepts arbitrary input length.
pub fn derive_wallet_keys(seed: &[u8], index: u32) -> Result<RailgunWalletKeys, SignerError> {
    let spending_path = format!("{}{}'", bip32::SPENDING_PATH_PREFIX, index);
    let viewing_path = format!("{}{}'", bip32::VIEWING_PATH_PREFIX, index);

    let spending_node = bip32::derive_from_seed_bytes(seed, &spending_path)?;
    let viewing_node = bip32::derive_from_seed_bytes(seed, &viewing_path)?;

    let spending_priv: [u8; 32] = *spending_node.chain_key;
    let viewing_priv: [u8; 32] = *viewing_node.chain_key;

    let spending_point = eddsa::prv_to_pub(&spending_priv);
    let spending_x_be = babyjubjub::fr_to_be_bytes(spending_point.x);
    let spending_y_be = babyjubjub::fr_to_be_bytes(spending_point.y);

    let viewing_pub = x25519::get_public_viewing_key(&viewing_priv);
    let nullifying_key = get_nullifying_key(&viewing_priv)?;
    let master_public_key = get_master_public_key(&spending_x_be, &spending_y_be, &nullifying_key)?;
    let encoded_address = bech32_address::encode_address(master_public_key, viewing_pub, None)?;

    Ok(RailgunWalletKeys {
        spending_private_key: Zeroizing::new(spending_priv),
        spending_public_key_x_be: spending_x_be,
        spending_public_key_y_be: spending_y_be,
        viewing_private_key: Zeroizing::new(viewing_priv),
        viewing_public_key: viewing_pub,
        nullifying_key,
        master_public_key,
        encoded_address,
    })
}

/// Attempts to decrypt one on-chain commitment ciphertext using the wallet's
/// viewing private key.
///
/// Pipeline: `ECDH(viewing_priv, ephemeral_pub) → SHA-256 → AES-256-GCM(iv,
/// tag, ciphertext)`. Returns `Ok(None)` when the AEAD authentication tag
/// fails — that's the "not for us" signal during balance-scan trial decrypt
/// loops; the sidecar should treat it as a clean skip, not an error.
///
/// Returns `Ok(Some(chunks))` where each chunk is a 32-byte slice of the
/// decrypted plaintext, mirroring the engine's `AES.encryptGCM([chunk_hex...])`
/// input layout. Interpreting those chunks (decoded master public key, token
/// hash, random + value) is the sidecar's job since the layout is engine-
/// version-specific.
///
/// The ciphertext length must be a multiple of 32 bytes; non-aligned input
/// returns `RailgunCrypto` so a wire-format bug shows up as a hard error
/// instead of silently rejecting valid notes.
pub fn decrypt_note_chunks(
    viewing_private_key: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Option<Vec<[u8; 32]>>, SignerError> {
    if ciphertext.len() % 32 != 0 {
        return Err(SignerError::RailgunCrypto(format!(
            "note ciphertext must be a whole number of 32-byte chunks; got {} bytes",
            ciphertext.len()
        )));
    }

    // ECDH against the sender's ephemeral viewing pubkey. Bad input point
    // (off-curve / non-canonical) propagates as `None`: that note can't have
    // been validly addressed to anyone, so the trial-decrypt result is "skip".
    let shared = match x25519::get_shared_symmetric_key(viewing_private_key, ephemeral_pubkey) {
        Some(k) => k,
        None => return Ok(None),
    };

    // AES-GCM decrypt; auth-tag failure (wrong recipient) is the "not for us"
    // signal during balance scans.
    let plaintext = match aes_gcm::decrypt(&*shared, iv, ciphertext, tag) {
        Ok(pt) => pt,
        Err(_) => return Ok(None),
    };

    let mut chunks = Vec::with_capacity(plaintext.len() / 32);
    for chunk in plaintext.chunks_exact(32) {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(chunk);
        chunks.push(buf);
    }
    Ok(Some(chunks))
}

/// `WalletNode.getNullifyingKey()` — reinterprets the 32-byte viewing private
/// key as a big-endian bigint and feeds it as the lone Poseidon input.
pub fn get_nullifying_key(viewing_private_key: &[u8; 32]) -> Result<[u8; 32], SignerError> {
    poseidon_bn254_be(&[*viewing_private_key])
}

/// `WalletNode.getMasterPublicKey(spend_pub, nullifying_key)` — Poseidon over
/// the spending public-key affine coordinates concatenated with the
/// nullifying key (a 32-byte field element).
pub fn get_master_public_key(
    spending_public_key_x_be: &[u8; 32],
    spending_public_key_y_be: &[u8; 32],
    nullifying_key: &[u8; 32],
) -> Result<[u8; 32], SignerError> {
    poseidon_bn254_be(&[
        *spending_public_key_x_be,
        *spending_public_key_y_be,
        *nullifying_key,
    ])
}

/// `Note.getNullifier(nk, leafIndex)` — Poseidon over (nullifying_key, leaf
/// index padded to 32 bytes big-endian).
pub fn get_nullifier(nullifying_key: &[u8; 32], leaf_index: u64) -> Result<[u8; 32], SignerError> {
    let mut leaf = [0u8; 32];
    leaf[24..].copy_from_slice(&leaf_index.to_be_bytes());
    poseidon_bn254_be(&[*nullifying_key, leaf])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).expect("hex").try_into().expect("32 bytes")
    }

    #[test]
    fn nullifying_keys_match_fixture() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let priv_bytes = h32(&wallet.viewing.private_key_hex);
            let got = get_nullifying_key(&priv_bytes).expect("nk");
            assert_eq!(
                hex::encode(got),
                wallet.nullifying_key_hex,
                "wallet index {}",
                wallet.index
            );
        }
    }

    #[test]
    fn master_public_keys_match_fixture() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let x = h32(&wallet.spending.public_key.x_hex);
            let y = h32(&wallet.spending.public_key.y_hex);
            let nk = h32(&wallet.nullifying_key_hex);
            let got = get_master_public_key(&x, &y, &nk).expect("mpk");
            assert_eq!(
                hex::encode(got),
                wallet.master_public_key_hex,
                "wallet index {}",
                wallet.index
            );
        }
    }

    #[test]
    fn nullifiers_match_fixture() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let nk = h32(&wallet.nullifying_key_hex);
            for n in &wallet.nullifiers {
                let leaf: u64 = n.leaf_index.parse().expect("u64");
                let got = get_nullifier(&nk, leaf).expect("nullifier");
                assert_eq!(
                    hex::encode(got),
                    n.nullifier_hex,
                    "wallet index {}, leaf {}",
                    wallet.index,
                    leaf
                );
            }
        }
    }

    fn h16(s: &str) -> [u8; 16] {
        hex::decode(s).expect("hex").try_into().expect("16 bytes")
    }

    #[test]
    fn decrypt_note_chunks_round_trip_matches_engine_sample() {
        let vectors = load();
        for sample in &vectors.note_encryption_samples {
            let receiver_priv = h32(&sample.receiver_viewing_priv_hex);
            let ephemeral_pub = h32(&sample.sender_ephemeral_pub_hex);
            let iv = h16(&sample.iv_hex);
            let tag = h16(&sample.tag_hex);
            let ciphertext: Vec<u8> = sample
                .ciphertext_chunks_hex
                .iter()
                .flat_map(|c| hex::decode(c).expect("ct hex"))
                .collect();

            let chunks =
                decrypt_note_chunks(&receiver_priv, &ephemeral_pub, &iv, &ciphertext, &tag)
                    .expect("decrypt does not error")
                    .expect("auth tag must verify with the recorded inputs");
            assert_eq!(
                chunks.len(),
                sample.plaintext_chunks_hex.len(),
                "chunk count must match the engine output",
            );
            for (i, chunk) in chunks.iter().enumerate() {
                assert_eq!(
                    hex::encode(chunk),
                    sample.plaintext_chunks_hex[i],
                    "chunk {i} mismatch",
                );
            }
        }
    }

    #[test]
    fn decrypt_note_chunks_returns_none_on_auth_failure() {
        let vectors = load();
        let Some(sample) = vectors.note_encryption_samples.first() else {
            panic!("fixture must include at least one note encryption sample");
        };

        let receiver_priv = h32(&sample.receiver_viewing_priv_hex);
        let ephemeral_pub = h32(&sample.sender_ephemeral_pub_hex);
        let iv = h16(&sample.iv_hex);
        // Tamper with the tag — the AEAD check must fail and the daemon must
        // signal "not for us" via Ok(None) rather than surfacing the AEAD
        // error to the sidecar (which would mask legitimate skipped notes).
        let mut tag = h16(&sample.tag_hex);
        tag[0] ^= 0x01;
        let ciphertext: Vec<u8> = sample
            .ciphertext_chunks_hex
            .iter()
            .flat_map(|c| hex::decode(c).expect("ct hex"))
            .collect();

        let result = decrypt_note_chunks(&receiver_priv, &ephemeral_pub, &iv, &ciphertext, &tag)
            .expect("auth failure is Ok(None), not Err");
        assert!(
            result.is_none(),
            "tampered tag must signal skip, not decrypt to garbage; got {result:?}",
        );
    }

    #[test]
    fn railgun_wallet_keys_debug_redacts_private_material() {
        let vectors = load();
        let seed_bytes = hex::decode(&vectors.mnemonic.seed_hex).expect("seed hex");
        let wallet = vectors.wallets.first().expect("fixture wallet");
        let keys = derive_wallet_keys(&seed_bytes, wallet.index).expect("derive");

        let rendered = format!("{keys:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains(&wallet.address));
        assert!(rendered.contains(&wallet.master_public_key_hex));
        for secret_hex in [
            &wallet.spending.private_key_hex,
            &wallet.viewing.private_key_hex,
            &wallet.nullifying_key_hex,
        ] {
            assert!(!rendered.contains(secret_hex.as_str()), "{rendered}");
        }
        // Guard against the derived Debug's decimal byte-array rendering too.
        assert!(!rendered.contains(&format!("{:?}", keys.spending_private_key.as_ref())));
        assert!(!rendered.contains(&format!("{:?}", keys.viewing_private_key.as_ref())));
        assert!(!rendered.contains(&format!("{:?}", keys.nullifying_key)));
    }

    #[test]
    fn derive_wallet_keys_matches_fixture_end_to_end() {
        // Integration: feed the BIP-39 seed used by the JS generator straight
        // into `derive_wallet_keys` and confirm every observable output (keys,
        // pubkey coords, nullifying key, master pubkey, encoded address)
        // matches what the engine produced.
        let vectors = load();
        let seed_bytes = hex::decode(&vectors.mnemonic.seed_hex).expect("seed hex");
        for wallet in &vectors.wallets {
            let keys = derive_wallet_keys(&seed_bytes, wallet.index)
                .unwrap_or_else(|err| panic!("derive idx={}: {err}", wallet.index));
            assert_eq!(
                hex::encode(keys.spending_private_key.as_ref()),
                wallet.spending.private_key_hex,
                "spending priv, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(keys.spending_public_key_x_be),
                wallet.spending.public_key.x_hex,
                "spending pub.x, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(keys.spending_public_key_y_be),
                wallet.spending.public_key.y_hex,
                "spending pub.y, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(keys.viewing_private_key.as_ref()),
                wallet.viewing.private_key_hex,
                "viewing priv, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(keys.viewing_public_key),
                wallet.viewing.public_key_hex,
                "viewing pub, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(keys.nullifying_key),
                wallet.nullifying_key_hex,
                "nullifying, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(keys.master_public_key),
                wallet.master_public_key_hex,
                "master pub, idx={}",
                wallet.index
            );
            assert_eq!(
                keys.encoded_address, wallet.address,
                "encoded address, idx={}",
                wallet.index
            );
        }
    }
}
