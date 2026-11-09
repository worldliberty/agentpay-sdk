use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Signature result returned by the signer backend and `SignForAgent`.
///
/// Which optional fields are present depends on the action: EVM digests add
/// `r_hex`/`s_hex`/`v`; broadcast transactions add `raw_tx_hex`/`tx_hash_hex`;
/// Solana actions add `signature_base58`, `raw_tx_base64`, and `tx_id`. Absent
/// fields are omitted from the JSON, never `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema, TS)]
pub struct Signature {
    /// Signature bytes as a JSON array of byte values (0-255): ECDSA ASN.1 DER
    /// (`X9.62`) for secp256k1, the raw 64-byte signature for Ed25519.
    pub bytes: Vec<u8>,
    /// Optional base58-encoded Ed25519 signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub signature_base58: Option<String>,
    /// Optional 32-byte `r` scalar as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub r_hex: Option<String>,
    /// Optional 32-byte `s` scalar as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub s_hex: Option<String>,
    /// Optional ECDSA `v` value (`0`/`1` for typed txs).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub v: Option<u64>,
    /// Optional signed raw transaction bytes as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub raw_tx_hex: Option<String>,
    /// Optional transaction hash as `0x`-prefixed hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tx_hash_hex: Option<String>,
    /// Optional signed serialized transaction encoded as base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub raw_tx_base64: Option<String>,
    /// Optional chain-native transaction identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tx_id: Option<String>,
}

impl Signature {
    /// Constructs a signature response from DER bytes.
    #[must_use]
    pub fn from_der(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            ..Self::default()
        }
    }
}
