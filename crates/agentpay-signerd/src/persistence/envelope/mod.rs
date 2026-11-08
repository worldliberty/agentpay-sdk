//! Encrypted state envelope format.
//!
//! The state file is a JSON envelope around an XChaCha20-Poly1305 ciphertext of
//! the serialized [`PersistedDaemonState`]. Two envelope versions exist:
//!
//! - **v2 (current)**: the 32-byte key is derived with HKDF-SHA256 from the
//!   machine [`StateSecret`] (input key material) and a random per-file salt,
//!   with `info = "agentpay-state-v2"`. The envelope version and salt are bound
//!   as associated data, so header tampering fails authentication.
//! - **v1 (legacy, read-only)**: the key was Argon2id(vault password). These
//!   files are only opened to migrate them to v2; see [`legacy`].

pub(super) mod legacy;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{PersistedDaemonState, StateSecret, CURRENT_SCHEMA_VERSION};
use crate::daemon::prepare_loaded_state;

/// Current envelope version (HKDF-SHA256 over the machine secret).
pub(super) const ENVELOPE_VERSION: u8 = 2;

/// Legacy envelope version (Argon2id over the vault password).
pub(super) const LEGACY_PASSWORD_ENVELOPE_VERSION: u8 = 1;

/// Domain-separation label used as the HKDF `info` and AEAD associated-data prefix.
const STATE_KEY_DOMAIN: &[u8] = b"agentpay-state-v2";

pub(super) const SALT_LEN: usize = 16;

pub(super) const KEY_LEN: usize = 32;

pub(super) const NONCE_LEN: usize = 24;

/// A derived state-file encryption key together with the salt it was derived with.
pub(super) struct StateKey {
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
}

impl StateKey {
    /// Derives the v2 key for `salt` from the machine secret.
    pub(super) fn derive(secret: &StateSecret, salt: [u8; SALT_LEN]) -> Result<Self, String> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        Hkdf::<Sha256>::new(Some(&salt), secret.expose())
            .expand(STATE_KEY_DOMAIN, key.as_mut())
            .map_err(|err| format!("failed to derive state key: {err}"))?;
        Ok(Self { key, salt })
    }

    /// Derives a key under a fresh random salt (used for new and migrated files).
    pub(super) fn generate(secret: &StateSecret) -> Result<Self, String> {
        Self::derive(secret, rand::random::<[u8; SALT_LEN]>())
    }

    #[cfg(test)]
    pub(super) fn key_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    #[cfg(test)]
    pub(super) fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }
}

/// Serialized v2 envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct EncryptedStateEnvelope {
    pub(super) version: u8,
    pub(super) salt_hex: String,
    pub(super) nonce_hex: String,
    pub(super) ciphertext_hex: String,
}

/// Minimal view used to dispatch on the envelope version before full parsing.
#[derive(Deserialize)]
struct EnvelopeHeader {
    version: u8,
}

/// Reads the envelope version without interpreting the rest of the file.
pub(super) fn envelope_version(bytes: &[u8]) -> Result<u8, String> {
    serde_json::from_slice::<EnvelopeHeader>(bytes)
        .map(|header| header.version)
        .map_err(|err| format!("failed to parse state envelope: {err}"))
}

/// Opens a v2 envelope with the machine secret.
///
/// Returns the validated state and the key so the store can re-seal it under
/// the same salt.
pub(super) fn open_state(
    bytes: &[u8],
    secret: &StateSecret,
) -> Result<(PersistedDaemonState, StateKey), String> {
    let envelope: EncryptedStateEnvelope = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse state envelope: {err}"))?;
    if envelope.version != ENVELOPE_VERSION {
        return Err(format!(
            "unsupported state file version {}; expected {}",
            envelope.version, ENVELOPE_VERSION
        ));
    }
    let salt = decode_fixed::<SALT_LEN>(&envelope.salt_hex, "salt")?;
    let nonce = decode_fixed::<NONCE_LEN>(&envelope.nonce_hex, "nonce")?;
    let ciphertext = hex::decode(&envelope.ciphertext_hex)
        .map_err(|err| format!("invalid state ciphertext encoding: {err}"))?;
    let key = StateKey::derive(secret, salt)?;
    let aad = associated_data(ENVELOPE_VERSION, &salt);
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(key.key.as_ref().into())
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                "failed to decrypt state (wrong state secret or tampered file)".to_string()
            })?,
    );
    Ok((parse_state_payload(&plaintext)?, key))
}

/// Seals `state` into serialized v2 envelope bytes.
pub(super) fn seal_state(
    state: &PersistedDaemonState,
    key: &StateKey,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(state)
            .map_err(|err| format!("failed to serialize daemon state: {err}"))?,
    );
    seal_plaintext(&plaintext, key, nonce)
}

/// Encrypts an already-serialized state payload into v2 envelope bytes.
pub(super) fn seal_plaintext(
    plaintext: &[u8],
    key: &StateKey,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let aad = associated_data(ENVELOPE_VERSION, &key.salt);
    let ciphertext = XChaCha20Poly1305::new(key.key.as_ref().into())
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|err| format!("failed to encrypt daemon state: {err}"))?;
    serde_json::to_vec(&EncryptedStateEnvelope {
        version: ENVELOPE_VERSION,
        salt_hex: hex::encode(key.salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
    .map_err(|err| format!("failed to serialize state envelope: {err}"))
}

/// Associated data binding the envelope header: domain label, version, salt.
fn associated_data(version: u8, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(STATE_KEY_DOMAIN.len() + 1 + SALT_LEN);
    aad.extend_from_slice(STATE_KEY_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(salt);
    aad
}

/// Decodes a hex header field that must be exactly `N` bytes.
pub(super) fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes =
        hex::decode(value).map_err(|err| format!("invalid state {label} encoding: {err}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("invalid state {label} length"))
}

/// Deserializes a decrypted payload, enforces the schema version, and validates integrity.
pub(super) fn parse_state_payload(plaintext: &[u8]) -> Result<PersistedDaemonState, String> {
    let state: PersistedDaemonState = serde_json::from_slice(plaintext)
        .map_err(|err| format!("failed to deserialize state payload: {err}"))?;
    if state.schema_version.0 > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported state schema version {}; this daemon supports up to {}",
            state.schema_version.0, CURRENT_SCHEMA_VERSION
        ));
    }
    prepare_loaded_state(state)
        .map_err(|err| format!("loaded state failed integrity validation: {err}"))
}
