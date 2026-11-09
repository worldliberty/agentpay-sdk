//! Legacy (v1) state envelope: Argon2id(vault password) + XChaCha20-Poly1305.
//!
//! The daemon no longer writes this format. It only decrypts it once, when the
//! operator supplies the old vault password to migrate the file to the v2
//! (machine secret) envelope.

use argon2::{Argon2, ParamsBuilder};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    decode_fixed, parse_state_payload, KEY_LEN, LEGACY_PASSWORD_ENVELOPE_VERSION, NONCE_LEN,
    SALT_LEN,
};
use crate::persistence::PersistedDaemonState;

/// Argon2id parameters recorded in a v1 envelope header.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::persistence) struct KdfParams {
    pub(in crate::persistence) memory_kib: u32,
    pub(in crate::persistence) time_cost: u32,
    pub(in crate::persistence) parallelism: u32,
}

/// Upper bounds for KDF parameters read back from a legacy state file.
///
/// The parameters live in the unauthenticated envelope header, so a tampered
/// file could otherwise request gigabytes of Argon2 memory and crash the daemon
/// during migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::persistence) struct KdfLimits {
    pub(in crate::persistence) max_memory_kib: u32,
    pub(in crate::persistence) max_time_cost: u32,
    pub(in crate::persistence) max_parallelism: u32,
}

impl KdfLimits {
    pub(in crate::persistence) fn from_config(config: &crate::DaemonConfig) -> Self {
        Self {
            max_memory_kib: config.max_persisted_argon2_memory_kib,
            max_time_cost: config.max_persisted_argon2_time_cost,
            max_parallelism: config.max_persisted_argon2_parallelism,
        }
    }

    fn validate(&self, kdf: &KdfParams) -> Result<(), String> {
        if kdf.memory_kib > self.max_memory_kib {
            return Err(format!(
                "state file kdf memory_kib {} exceeds configured maximum {}",
                kdf.memory_kib, self.max_memory_kib
            ));
        }
        if kdf.time_cost > self.max_time_cost {
            return Err(format!(
                "state file kdf time_cost {} exceeds configured maximum {}",
                kdf.time_cost, self.max_time_cost
            ));
        }
        if kdf.parallelism > self.max_parallelism {
            return Err(format!(
                "state file kdf parallelism {} exceeds configured maximum {}",
                kdf.parallelism, self.max_parallelism
            ));
        }
        Ok(())
    }
}

/// Serialized v1 envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(in crate::persistence) struct LegacyStateEnvelope {
    pub(in crate::persistence) version: u8,
    pub(in crate::persistence) kdf: KdfParams,
    pub(in crate::persistence) salt_hex: String,
    pub(in crate::persistence) nonce_hex: String,
    pub(in crate::persistence) ciphertext_hex: String,
}

/// Decrypts and validates a v1 envelope with the legacy vault password.
pub(in crate::persistence) fn open_legacy_state(
    bytes: &[u8],
    password: &str,
    kdf_limits: &KdfLimits,
) -> Result<PersistedDaemonState, String> {
    let envelope: LegacyStateEnvelope = serde_json::from_slice(bytes)
        .map_err(|err| format!("failed to parse legacy state envelope: {err}"))?;
    if envelope.version != LEGACY_PASSWORD_ENVELOPE_VERSION {
        return Err(format!(
            "unsupported legacy state file version {}; expected {}",
            envelope.version, LEGACY_PASSWORD_ENVELOPE_VERSION
        ));
    }
    kdf_limits.validate(&envelope.kdf)?;
    let salt = decode_fixed::<SALT_LEN>(&envelope.salt_hex, "salt")?;
    let nonce = decode_fixed::<NONCE_LEN>(&envelope.nonce_hex, "nonce")?;
    let ciphertext = hex::decode(&envelope.ciphertext_hex)
        .map_err(|err| format!("invalid state ciphertext encoding: {err}"))?;
    let key = derive_legacy_key(password, &salt, &envelope.kdf)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt((&nonce).into(), ciphertext.as_ref())
            .map_err(|_| {
                "failed to decrypt legacy state (wrong vault password or tampered file)".to_string()
            })?,
    );
    parse_state_payload(&plaintext)
}

/// Derives the v1 key: Argon2id(password, salt) with the header's parameters.
pub(in crate::persistence) fn derive_legacy_key(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = ParamsBuilder::new()
        .m_cost(kdf.memory_kib)
        .t_cost(kdf.time_cost)
        .p_cost(kdf.parallelism)
        .build()
        .map_err(|err| format!("invalid state kdf params: {err}"))?;
    let argon = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|err| format!("failed to derive state key: {err}"))?;
    Ok(key)
}

/// Builds a v1 envelope exactly as pre-v2 daemons wrote it (test fixture helper).
#[cfg(test)]
pub(in crate::persistence) fn seal_legacy_plaintext(
    plaintext: &[u8],
    password: &str,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    kdf: KdfParams,
) -> LegacyStateEnvelope {
    let key = derive_legacy_key(password, &salt, &kdf).expect("derive legacy key");
    let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt((&nonce).into(), plaintext)
        .expect("encrypt legacy state");
    LegacyStateEnvelope {
        version: LEGACY_PASSWORD_ENVELOPE_VERSION,
        kdf,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    }
}
