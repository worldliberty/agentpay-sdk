//! Domain types for the Railgun signing surface.
//!
//! These structs are the wire shape that crosses the trust boundary between
//! the Rust daemon (which owns all key material) and the TypeScript
//! `apps/railgun-prover` sidecar (which orchestrates Merkle sync, proof
//! generation via snarkjs, and Waku broadcasting). The sidecar never sees
//! the Baby Jubjub spending key or the viewing key in plaintext; it sends
//! ciphertexts, note descriptors, and merkle paths to the daemon and
//! receives back Poseidon-derived nullifier outputs, decrypted note bodies,
//! and zk-witness field elements.
//!
//! Field elements are encoded as lowercase hex of the canonical 32-byte
//! big-endian representation expected by `snarkjs` / `circom`. The Rust
//! daemon is responsible for normalising encoding on the boundary so the
//! sidecar can pass values straight into the prover.

use serde::{Deserialize, Serialize};

use crate::EvmAddress;

/// Identifier for one of Railgun's two parallel commitment trees. The
/// nullifier and witness computation must use the right Merkle root depending
/// on whether the note lives in the legacy or current UTXO tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RailgunTreeNumber {
    /// UTXO tree (current commitment tree as of engine v8+).
    Utxo,
    /// Legacy UTXO tree maintained for historical notes.
    LegacyUtxo,
}

/// Input bundle for [`VaultSignerBackend::railgun_compute_nullifier`].
///
/// Carries the note descriptor the daemon needs to derive the nullifier
/// Poseidon hash without revealing the spending key. The sidecar reads these
/// fields from its local engine state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunNoteInput {
    /// EVM chain id the note lives on.
    pub chain_id: u64,
    /// Which commitment tree the note belongs to.
    pub tree_number: RailgunTreeNumber,
    /// Leaf index in `tree_number` for the note's commitment.
    pub leaf_index: u64,
    /// Lowercase hex of the 32-byte commitment hash for this note.
    pub commitment_hex: String,
    /// Lowercase hex of the 32-byte random field element bound to the note.
    pub random_hex: String,
    /// Token contract address the note represents.
    pub token: EvmAddress,
    /// Note value as a decimal-string-encoded u128 (matches the rest of the
    /// domain wire format for amounts).
    #[serde(with = "crate::u128_as_decimal_string")]
    pub value_wei: u128,
}

/// Result of decrypting a Railgun commitment ciphertext with the viewing key.
///
/// Returns the **raw decrypted chunks** — interpreting them (decoding the
/// encoded master public key, looking up the token from its Poseidon hash,
/// splitting random + value out of chunk 2) is the sidecar's job because
/// Railgun's note layout is engine-version-specific and the daemon should
/// not need to track protocol bumps.
///
/// For a V2 transact note the engine emits three 32-byte chunks:
/// - `chunks_hex[0]` — `encodedMasterPublicKey` (bigint, big-endian)
/// - `chunks_hex[1]` — `tokenHash` (Poseidon hash, big-endian)
/// - `chunks_hex[2]` — `random (16 bytes) || value (16 bytes)`
///
/// The memo lives in a separately encrypted blob (`memo_utf8`) and the
/// annotation data needed to decode the master public key from `chunks_hex[0]`
/// is yet another separate ciphertext — both stay outside this struct so the
/// trait method remains a pure "AES-GCM under the daemon's viewing key".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunDecryptedNote {
    /// Raw decrypted chunks, lowercase 32-byte hex each.
    pub chunks_hex: Vec<String>,
}

/// Encrypted Railgun commitment payload as read from the chain.
///
/// Wire shape matches the engine's `AES.encryptGCM` output augmented with the
/// sender's ephemeral viewing public key (used by the daemon to compute the
/// X25519 shared key via ECDH with the wallet's viewing private key).
///
/// If `data_chunks_hex` decrypts cleanly the commitment belongs to this
/// wallet; on auth-tag failure the daemon returns `Ok(None)` and the sidecar
/// skips the commitment without recording an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunNoteCiphertext {
    /// Lowercase hex of the 32-byte sender-side ephemeral viewing public key
    /// (Ed25519 compressed point) emitted alongside the commitment.
    pub ephemeral_pubkey_hex: String,
    /// Lowercase hex of the **16-byte** AES-GCM IV. Railgun uses 16 bytes
    /// (non-standard — NIST recommends 12) so the Rust port must instantiate
    /// `AesGcm::<Aes256, U16>` explicitly.
    pub iv_hex: String,
    /// Lowercase hex of the 16-byte AES-GCM authentication tag.
    pub tag_hex: String,
    /// Encrypted body, one entry per 32-byte chunk. V2 transact notes use
    /// 3 chunks; future versions may differ — the daemon just decrypts them.
    pub data_chunks_hex: Vec<String>,
}

/// Public-key bundle returned by [`VaultSignerBackend::railgun_viewing_public_key`].
///
/// `viewing_pubkey_hex` is the X25519 public key used by senders to ECDH-encrypt
/// notes addressed to this wallet. `master_pubkey_hex` is the Baby Jubjub public
/// key of the spending key — needed both for the wallet's encoded `0zk1...`
/// address and as a witness input to the prover (the circuit checks that the
/// spend authority matches the note recipient).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunViewingPublicKeys {
    /// Lowercase hex of the 32-byte viewing X25519 public key.
    pub viewing_pubkey_hex: String,
    /// Lowercase hex of the 32-byte Baby Jubjub spending master public key.
    pub master_pubkey_hex: String,
}

/// Per-note Merkle inclusion proof, supplied by the sidecar so the daemon
/// can return the corresponding witness path elements without ever loading
/// the full Merkle tree itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunMerklePath {
    /// Which tree this path is for.
    pub tree_number: RailgunTreeNumber,
    /// Leaf index of the note's commitment.
    pub leaf_index: u64,
    /// Sibling hashes ordered leaf → root, each lowercase 32-byte hex.
    pub path_elements_hex: Vec<String>,
    /// Merkle root the path resolves to, lowercase 32-byte hex. The circuit
    /// pins the proof to a specific root snapshot.
    pub root_hex: String,
}

/// Output of [`VaultSignerBackend::railgun_witness_inputs`].
///
/// Holds the private inputs the snarkjs prover needs that are derived from
/// the spending key: one nullifier per spent note plus a single transaction
/// signature over the sidecar-pre-hashed Poseidon message digest.
///
/// Wire format:
/// - `nullifiers_hex[i]`: lowercase hex of the 32-byte Poseidon nullifier
///   for spent note `i`. Matches the order of the input `notes` slice.
/// - `spending_signatures_hex`: a single entry per transaction in the iden3
///   EdDSA-Poseidon unpacked form `R8.x || R8.y || S` (96 bytes hex). The
///   sidecar splits this into three 32-byte field elements when feeding the
///   circuit. `Vec` shape is kept for forward compatibility with batched
///   variants that sign per-note.
/// - `spend_authority_pubkey_hex`: lowercase hex of the packed Baby Jubjub
///   spending public key (32 bytes, y-coordinate + sign bit of x — the iden3
///   `packPoint` convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunWitnessBundle {
    /// Per-spent-note nullifier hashes, in the same order as the input notes.
    pub nullifiers_hex: Vec<String>,
    /// One unpacked EdDSA-Poseidon signature per transaction (`R8.x || R8.y || S`).
    pub spending_signatures_hex: Vec<String>,
    /// Spend authority public key (packed Baby Jubjub), 32-byte lowercase hex.
    pub spend_authority_pubkey_hex: String,
}

/// Output of [`VaultSignerBackend::railgun_compute_nullifier`].
///
/// A single 32-byte nullifier hash, lowercase hex. The daemon derives this
/// via Poseidon over the spending key and note descriptor without exposing
/// either to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailgunNullifier {
    /// Lowercase hex of the 32-byte nullifier.
    pub nullifier_hex: String,
}
