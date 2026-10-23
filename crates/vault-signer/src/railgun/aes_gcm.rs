//! AES-256-GCM with Railgun's non-standard 16-byte IV.
//!
//! Node's `crypto.createCipheriv('aes-256-gcm', key, iv16)` accepts a 16-byte
//! IV (GHASH expands it into J0 via the long-IV path). The `aes-gcm` crate's
//! `Aes256Gcm` typedef pins `U12`; we instantiate `AesGcm::<Aes256, U16>`
//! explicitly so encrypt/decrypt match Node's wire output byte-for-byte.
//!
//! Plaintext + ciphertext are passed in as concatenated chunk slices to mirror
//! Node's `cipher.update()` loop; the result is one contiguous Vec.

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    AesGcm, Key, Nonce,
};
use generic_array::typenum::U16;
use zeroize::Zeroizing;

use crate::SignerError;

type Aes256GcmIv16 = AesGcm<Aes256, U16>;

fn cipher(key: &[u8; 32]) -> Aes256GcmIv16 {
    let key_ref = Key::<Aes256GcmIv16>::from_slice(key);
    Aes256GcmIv16::new(key_ref)
}

/// Encrypts `plaintext` and returns `(ciphertext, tag16)`. The tag is split
/// out to mirror Node's `cipher.getAuthTag()` behaviour; `aes-gcm`'s `encrypt`
/// appends the tag, so we slice it back off.
pub fn encrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), SignerError> {
    let c = cipher(key);
    let nonce = Nonce::<<Aes256GcmIv16 as AeadCore>::NonceSize>::from_slice(iv);
    let mut out = c
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|e| SignerError::RailgunCrypto(format!("aes-gcm encrypt: {e}")))?;
    let tag_start = out.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[tag_start..]);
    out.truncate(tag_start);
    Ok((out, tag))
}

/// Decrypts `ciphertext` given the explicit `tag`. Returns a zeroizing buffer
/// to encourage callers to drop plaintext promptly.
pub fn decrypt(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Zeroizing<Vec<u8>>, SignerError> {
    let c = cipher(key);
    let nonce = Nonce::<<Aes256GcmIv16 as AeadCore>::NonceSize>::from_slice(iv);
    let mut combined = Vec::with_capacity(ciphertext.len() + 16);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    let pt = c
        .decrypt(
            nonce,
            Payload {
                msg: &combined,
                aad: &[],
            },
        )
        .map_err(|e| SignerError::RailgunCrypto(format!("aes-gcm decrypt: {e}")))?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::railgun::test_vectors::load;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("hex")
    }

    #[test]
    fn matches_engine_aes_gcm_samples() {
        let vectors = load();
        for sample in &vectors.aes_gcm_samples {
            let key: [u8; 32] = h(&sample.shared_key_hex).try_into().unwrap();
            let iv: [u8; 16] = h(&sample.iv_hex).try_into().unwrap();
            let plaintext: Vec<u8> = sample
                .plaintext_chunks_hex
                .iter()
                .flat_map(|c| h(c))
                .collect();
            let expected_ct: Vec<u8> = sample
                .ciphertext_chunks_hex
                .iter()
                .flat_map(|c| h(c))
                .collect();
            let expected_tag: [u8; 16] = h(&sample.tag_hex).try_into().unwrap();

            let (ct, tag) = encrypt(&key, &iv, &plaintext).expect("encrypt");
            assert_eq!(hex::encode(&ct), hex::encode(&expected_ct), "ciphertext");
            assert_eq!(hex::encode(tag), hex::encode(expected_tag), "tag");

            let pt = decrypt(&key, &iv, &expected_ct, &expected_tag).expect("decrypt");
            assert_eq!(
                hex::encode(&*pt),
                hex::encode(&plaintext),
                "decrypt round-trip"
            );
        }
    }
}
