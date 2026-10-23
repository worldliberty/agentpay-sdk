//! Railgun's custom hardened-only BIP32 derivation over Baby Jubjub.
//!
//! Diverges from BIP-0032 in three places:
//! 1. The master HMAC key is the **UTF-8 bytes of `"babyjubjub seed"`**, not
//!    BIP-32's `"Bitcoin seed"`.
//! 2. Only hardened derivation exists: every segment gets `0x80000000` added.
//!    Soft derivation is not implemented in the JS engine.
//! 3. The child HMAC pre-image is the JS string `"00" + chainKey + index4`
//!    that is then **hex-decoded** by `ByteUtils.arrayify` before HMAC. That
//!    decoded form is `[0x00] || chain_key (32B) || index_be (4B)` = 37
//!    bytes. The brief mistakenly described this as ASCII-hex; the engine's
//!    `bytesLikeify` step undoes the hex encoding before the HMAC ingests it.
//!
//! Mnemonic → seed uses standard BIP-39 PBKDF2-HMAC-SHA512(2048).

use std::fmt;

use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::SignerError;

type HmacSha512 = Hmac<Sha512>;

/// Spending path `m/44'/1984'/0'/0'/<index>'`.
pub const SPENDING_PATH_PREFIX: &str = "m/44'/1984'/0'/0'/";
/// Viewing path `m/420'/1984'/0'/0'/<index>'`.
pub const VIEWING_PATH_PREFIX: &str = "m/420'/1984'/0'/0'/";

const HARDENED_OFFSET: u32 = 0x80000000;
const CURVE_SEED: &[u8] = b"babyjubjub seed";

/// One node in the Railgun BIP32-like tree.
///
/// Both halves are secret (the chain code lets anyone derive every child
/// key), so `Debug` redacts them.
#[derive(Clone)]
pub struct KeyNode {
    /// 32-byte chain key (becomes the spending / viewing private key at the
    /// leaf).
    pub chain_key: Zeroizing<[u8; 32]>,
    /// 32-byte chain code, fed forward as the HMAC key on the next step.
    pub chain_code: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for KeyNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyNode")
            .field("chain_key", &"<redacted>")
            .field("chain_code", &"<redacted>")
            .finish()
    }
}

/// Decode a `m/a'/b'/c'/…` Railgun path into the raw segment indices (without
/// the hardened offset). Rejects malformed paths.
pub fn parse_path(path: &str) -> Result<Vec<u32>, SignerError> {
    if !path.starts_with("m/") {
        return Err(SignerError::RailgunCrypto(format!(
            "invalid derivation path: {path}"
        )));
    }
    let segments = path[2..].split('/');
    let mut out = Vec::new();
    for seg in segments {
        let stripped = seg
            .strip_suffix('\'')
            .ok_or_else(|| SignerError::RailgunCrypto("non-hardened segment".into()))?;
        let value: u32 = stripped
            .parse()
            .map_err(|_| SignerError::RailgunCrypto(format!("bad segment '{seg}'")))?;
        out.push(value);
    }
    Ok(out)
}

/// BIP-39 mnemonic → 64-byte seed (PBKDF2-HMAC-SHA512(2048), salt = `mnemonic`
/// + passphrase). Empty passphrase to match `Mnemonic.toSeed(mnemonic)` in the
/// engine.
pub fn mnemonic_to_seed(
    mnemonic: &str,
    passphrase: &str,
) -> Result<Zeroizing<[u8; 64]>, SignerError> {
    let m = Mnemonic::parse_in_normalized(Language::English, mnemonic)
        .map_err(|e| SignerError::RailgunCrypto(format!("bip39 mnemonic: {e}")))?;
    Ok(Zeroizing::new(m.to_seed_normalized(passphrase)))
}

/// `getMasterKeyFromSeed(seed)` — HMAC-SHA512("babyjubjub seed", seed).
pub fn master_key_from_seed(seed: &[u8]) -> Result<KeyNode, SignerError> {
    let mut mac = HmacSha512::new_from_slice(CURVE_SEED)
        .map_err(|e| SignerError::RailgunCrypto(format!("hmac: {e}")))?;
    mac.update(seed);
    let out = mac.finalize().into_bytes();
    split_chain(&out)
}

/// `childKeyDerivationHardened(node, index)` — single step. Index is the raw
/// (un-hardened) value; we add `0x80000000` internally because Railgun does
/// not support non-hardened derivation.
pub fn child_key_derivation_hardened(node: &KeyNode, index: u32) -> Result<KeyNode, SignerError> {
    let hardened_index = index
        .checked_add(HARDENED_OFFSET)
        .ok_or_else(|| SignerError::RailgunCrypto("index out of range".into()))?;
    let mut pre_image = Vec::with_capacity(1 + 32 + 4);
    pre_image.push(0u8);
    pre_image.extend_from_slice(node.chain_key.as_ref());
    pre_image.extend_from_slice(&hardened_index.to_be_bytes());
    let mut mac = HmacSha512::new_from_slice(node.chain_code.as_ref())
        .map_err(|e| SignerError::RailgunCrypto(format!("hmac: {e}")))?;
    mac.update(&pre_image);
    let out = mac.finalize().into_bytes();
    split_chain(&out)
}

/// `WalletNode.fromMnemonic(mnemonic).derive(path)` — master + all segments.
pub fn derive_from_mnemonic(mnemonic: &str, path: &str) -> Result<KeyNode, SignerError> {
    let seed = mnemonic_to_seed(mnemonic, "")?;
    derive_from_seed_bytes(seed.as_ref(), path)
}

/// Same as [`derive_from_mnemonic`] but starting from raw seed bytes.
///
/// Used by the daemon to derive a Railgun wallet deterministically from the
/// existing secp256k1 vault key bytes — bypassing BIP-39 entirely, since
/// AgentPay does not own a BIP-39 mnemonic for users provisioned via fresh
/// secp256k1 key generation. The 32-byte secp256k1 private key is HMAC'd
/// under `"babyjubjub seed"` exactly as a BIP-39 seed would be, so the
/// derivation is fully deterministic per wallet.
pub fn derive_from_seed_bytes(seed: &[u8], path: &str) -> Result<KeyNode, SignerError> {
    let mut node = master_key_from_seed(seed)?;
    for segment in parse_path(path)? {
        node = child_key_derivation_hardened(&node, segment)?;
    }
    Ok(node)
}

fn split_chain(hmac_out: &[u8]) -> Result<KeyNode, SignerError> {
    if hmac_out.len() != 64 {
        return Err(SignerError::RailgunCrypto(
            "hmac output must be 64 bytes".into(),
        ));
    }
    let mut chain_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    chain_key.copy_from_slice(&hmac_out[..32]);
    chain_code.copy_from_slice(&hmac_out[32..]);
    Ok(KeyNode {
        chain_key: Zeroizing::new(chain_key),
        chain_code: Zeroizing::new(chain_code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    #[test]
    fn mnemonic_seed_matches_fixture() {
        let vectors = load();
        let seed =
            mnemonic_to_seed(&vectors.mnemonic.mnemonic, &vectors.mnemonic.password).expect("seed");
        assert_eq!(hex::encode(seed.as_ref()), vectors.mnemonic.seed_hex);
    }

    #[test]
    fn key_node_debug_redacts_chain_key_and_code() {
        let vectors = load();
        let wallet = vectors.wallets.first().expect("fixture wallet");
        let path = format!("{SPENDING_PATH_PREFIX}{}'", wallet.index);
        let node = derive_from_mnemonic(&vectors.mnemonic.mnemonic, &path).expect("derive");

        let rendered = format!("{node:?}");
        assert_eq!(
            rendered,
            "KeyNode { chain_key: \"<redacted>\", chain_code: \"<redacted>\" }"
        );
        assert!(!rendered.contains(&wallet.spending.chain_key_hex));
        assert!(!rendered.contains(&wallet.spending.chain_code_hex));
        assert!(!rendered.contains(&format!("{:?}", node.chain_key.as_ref())));
        assert!(!rendered.contains(&format!("{:?}", node.chain_code.as_ref())));
    }

    #[test]
    fn derives_wallet_chain_keys_and_codes() {
        let vectors = load();
        for wallet in &vectors.wallets {
            let spending_path = format!("{SPENDING_PATH_PREFIX}{}'", wallet.index);
            let viewing_path = format!("{VIEWING_PATH_PREFIX}{}'", wallet.index);
            let s = derive_from_mnemonic(&vectors.mnemonic.mnemonic, &spending_path)
                .expect("spending derive");
            let v = derive_from_mnemonic(&vectors.mnemonic.mnemonic, &viewing_path)
                .expect("viewing derive");
            assert_eq!(
                hex::encode(s.chain_key.as_ref()),
                wallet.spending.chain_key_hex,
                "spending chain key, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(s.chain_code.as_ref()),
                wallet.spending.chain_code_hex,
                "spending chain code, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(v.chain_key.as_ref()),
                wallet.viewing.chain_key_hex,
                "viewing chain key, idx={}",
                wallet.index
            );
            assert_eq!(
                hex::encode(v.chain_code.as_ref()),
                wallet.viewing.chain_code_hex,
                "viewing chain code, idx={}",
                wallet.index
            );
        }
    }
}
