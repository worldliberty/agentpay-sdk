//! Shared loader for `tests/fixtures/railgun_vectors.json`.
//!
//! Every submodule's `#[cfg(test)]` block calls into this to avoid each one
//! re-implementing the deserializer for the same fixture. The integration
//! test at `tests/railgun_vectors.rs` does the schema-shape assertions; here
//! we just give submodule tests typed access to the bytes they need.

#![cfg(test)]
#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VectorFile {
    pub mnemonic: MnemonicVector,
    pub wallets: Vec<WalletVector>,
    pub poseidon_samples: Vec<PoseidonVector>,
    pub shared_key_samples: Vec<SharedKeyVector>,
    pub aes_gcm_samples: Vec<AesGcmVector>,
    pub note_encryption_samples: Vec<NoteEncryptionVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MnemonicVector {
    pub mnemonic: String,
    pub password: String,
    pub seed_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WalletVector {
    pub index: u32,
    pub spending: SpendingVector,
    pub viewing: ViewingVector,
    pub nullifying_key_hex: String,
    pub master_public_key_hex: String,
    pub address: String,
    pub nullifiers: Vec<NullifierVector>,
    pub eddsa_signatures: Vec<EddsaVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpendingVector {
    pub chain_key_hex: String,
    pub chain_code_hex: String,
    pub private_key_hex: String,
    pub public_key: PublicKeyVector,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ViewingVector {
    pub chain_key_hex: String,
    pub chain_code_hex: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PublicKeyVector {
    pub x_hex: String,
    pub y_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NullifierVector {
    pub leaf_index: String,
    pub nullifier_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EddsaVector {
    pub message_scalar_hex: String,
    pub message_hash_hex: String,
    pub signature: EddsaSignature,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EddsaSignature {
    pub r8_x_hex: String,
    pub r8_y_hex: String,
    pub s_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PoseidonVector {
    pub inputs_hex: Vec<String>,
    pub output_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedKeyVector {
    pub sender_viewing_priv_hex: String,
    pub receiver_viewing_priv_hex: String,
    pub receiver_viewing_pub_hex: String,
    pub shared_key_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AesGcmVector {
    pub shared_key_hex: String,
    pub iv_hex: String,
    pub plaintext_chunks_hex: Vec<String>,
    pub ciphertext_chunks_hex: Vec<String>,
    pub tag_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteEncryptionVector {
    pub sender_viewing_priv_hex: String,
    pub sender_ephemeral_pub_hex: String,
    pub receiver_viewing_priv_hex: String,
    pub receiver_viewing_pub_hex: String,
    pub shared_key_hex: String,
    pub iv_hex: String,
    pub tag_hex: String,
    pub plaintext_chunks_hex: Vec<String>,
    pub ciphertext_chunks_hex: Vec<String>,
}

pub(crate) fn load() -> VectorFile {
    let raw = include_str!("../../tests/fixtures/railgun_vectors.json");
    serde_json::from_str::<VectorFile>(raw).expect("railgun fixture parses as VectorFile")
}
