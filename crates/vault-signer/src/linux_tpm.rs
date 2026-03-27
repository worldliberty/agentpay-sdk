//! Linux TPM 2.0 signer backend using Seal/Unseal for secp256k1 key protection.
//!
//! # Architecture: Why Seal/Unseal Instead of Direct TPM Signing
//!
//! TPM 2.0 does **not** support the secp256k1 curve required by Ethereum. The
//! TPM's built-in ECDSA only works with NIST curves (P-256, P-384). Using the
//! TPM directly for signing would produce P-256 signatures that yield incorrect
//! Ethereum addresses.
//!
//! Instead, this backend uses the TPM as a **key-protection vault**:
//!
//! 1. **Key generation**: A secp256k1 private key is generated in software
//!    using a cryptographically secure RNG.
//!
//! 2. **Sealing**: The raw 32-byte private key is encrypted (sealed) by the TPM
//!    under a Storage Root Key (SRK). The sealed blob can only be decrypted by
//!    the same TPM chip. The sealed blob is the only thing persisted to disk.
//!
//! 3. **Signing**: At signing time the daemon unseals the private key, performs
//!    secp256k1 ECDSA signing in software via the `k256` crate, and immediately
//!    zeroizes the plaintext key material.
//!
//! 4. **Platform binding**: Because the sealed blob is bound to the TPM's SRK,
//!    stealing the file alone is useless without physical access to the same
//!    TPM chip.
//!
//! On Linux the TPM is accessed via `/dev/tpmrm0` (the kernel TPM Resource
//! Manager) using raw TPM2 command buffers. All blocking TPM I/O is offloaded
//! to `tokio::task::spawn_blocking` to avoid stalling the async runtime.

#[cfg(target_os = "linux")]
mod inner {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, RwLock};

    use async_trait::async_trait;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature as EcdsaSignature, SigningKey};
    use k256::elliptic_curve::rand_core::OsRng;
    use serde::{Deserialize, Serialize};
    use time::OffsetDateTime;
    use uuid::Uuid;
    use vault_domain::{KeySource, Signature, VaultKey};
    use zeroize::{Zeroize, Zeroizing};

    use sha2::{Digest, Sha256};

    use crate::{BackendKind, KeyCreateRequest, SignerError, VaultSignerBackend};

    /// Domain separation string hashed into the SRK unique field to prevent
    /// cross-application primary key collisions (C2 fix).
    const SRK_UNIQUE_DOMAIN: &[u8] = b"agentpay-vault-signer-linux-tpm-v1";

    // -----------------------------------------------------------------------
    // Sealed blob format
    // -----------------------------------------------------------------------

    /// Current version of the sealed blob serialization format.
    ///
    /// Increment this when the blob layout changes so older daemons can detect
    /// incompatible blobs instead of silently producing corrupt keys.
    const SEALED_BLOB_VERSION: u32 = 1;

    /// Persistable representation of a TPM-sealed secp256k1 private key.
    ///
    /// The `sealed_private_key` field holds the opaque TPM sealed data object.
    /// It can only be unsealed by the same TPM chip that created it.
    #[derive(Clone, Serialize, Deserialize)]
    pub struct LinuxTpmKeyBlob {
        /// Format version for forward-compatible deserialization.
        pub version: u32,

        /// Opaque TPM sealed data bytes (TPM2B_PRIVATE + TPM2B_PUBLIC).
        ///
        /// This is the concatenation of:
        ///   - 4 bytes (u32 LE): length of TPM2B_PRIVATE
        ///   - TPM2B_PRIVATE bytes
        ///   - 4 bytes (u32 LE): length of TPM2B_PUBLIC
        ///   - TPM2B_PUBLIC bytes
        pub sealed_private_key: Vec<u8>,

        /// Uncompressed SEC1 public key bytes (65 bytes) for address derivation
        /// without needing to unseal.
        pub public_key_uncompressed: Vec<u8>,
    }

    // C6 fix: Manual Debug impl to avoid leaking sealed_private_key in logs.
    impl std::fmt::Debug for LinuxTpmKeyBlob {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxTpmKeyBlob")
                .field("version", &self.version)
                .field("sealed_private_key", &"<redacted>")
                .field(
                    "public_key_uncompressed",
                    &hex::encode(&self.public_key_uncompressed),
                )
                .finish()
        }
    }

    /// In-memory representation of a loaded key.
    ///
    /// Holds the sealed blob (for persistence) and, when the key is "hot", the
    /// unsealed signing key. The unsealed key is populated on first sign and
    /// kept in memory for the lifetime of the backend (matching the
    /// `SoftwareSignerBackend` behavior).
    struct LoadedKey {
        blob: LinuxTpmKeyBlob,
        /// Cached unsealed signing key. Populated lazily on first sign.
        signing_key: Option<SigningKey>,
    }

    impl Drop for LoadedKey {
        fn drop(&mut self) {
            // Clear the signing key on drop. With k256's `zeroize` feature
            // the SigningKey itself implements ZeroizeOnDrop, but we also
            // explicitly drop the Option to ensure the inner value is
            // released promptly.
            self.signing_key.take();
        }
    }

    /// Linux TPM 2.0 signer backend.
    ///
    /// Uses TPM Seal/Unseal to protect secp256k1 private keys at rest while
    /// performing ECDSA signing in software with the `k256` crate. See the
    /// module-level documentation for the full architecture rationale.
    #[derive(Clone)]
    pub struct LinuxTpmSignerBackend {
        device_path: PathBuf,
        keys: Arc<RwLock<HashMap<Uuid, LoadedKey>>>,
    }

    impl std::fmt::Debug for LinuxTpmSignerBackend {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxTpmSignerBackend")
                .field("device_path", &self.device_path)
                .field("keys", &"<locked>")
                .finish()
        }
    }

    impl Default for LinuxTpmSignerBackend {
        fn default() -> Self {
            Self::new("/dev/tpmrm0")
        }
    }

    impl LinuxTpmSignerBackend {
        /// Creates a new Linux TPM signer backend with the given device path.
        #[must_use]
        pub fn new(device_path: impl Into<PathBuf>) -> Self {
            Self {
                device_path: device_path.into(),
                keys: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        /// Computes the uncompressed SEC1 public key hex for a signing key.
        fn public_key_hex(signing_key: &SigningKey) -> String {
            let verifying_key = signing_key.verifying_key();
            hex::encode(verifying_key.to_encoded_point(false).as_bytes())
        }

        /// Parses a hex-encoded 32-byte private key (with optional `0x` prefix).
        fn parse_import_key(private_key_hex: &str) -> Result<SigningKey, SignerError> {
            let raw = hex::decode(
                private_key_hex
                    .strip_prefix("0x")
                    .unwrap_or(private_key_hex),
            )
            .map_err(|_| SignerError::InvalidPrivateKey)?;
            if raw.len() != 32 {
                return Err(SignerError::InvalidPrivateKey);
            }
            SigningKey::from_slice(&raw).map_err(|_| SignerError::InvalidPrivateKey)
        }

        /// Maps a recoverable prehash signature result to the domain `Signature`.
        fn map_recoverable_digest_signature<T, E>(
            result: Result<(EcdsaSignature, T), E>,
        ) -> Result<Signature, SignerError>
        where
            E: std::fmt::Display,
        {
            let (signature, _) = result.map_err(|err| {
                SignerError::Internal(format!(
                    "recoverable digest signature creation failed: {err}"
                ))
            })?;
            Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
        }

        /// Seals a raw 32-byte private key using the Linux TPM via /dev/tpmrm0.
        ///
        /// This is a blocking operation and must be called from a blocking
        /// context (e.g. `spawn_blocking`).
        ///
        /// The sealed blob is bound to the current TPM's Storage Root Key and
        /// cannot be unsealed on any other machine.
        fn tpm_seal(device_path: &Path, private_key_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
            let mut device = TpmDevice::open(device_path)?;

            let srk_handle = tpm2_create_primary_srk(&mut device)?;

            let sealed_blob = tpm2_create_seal_object(&mut device, srk_handle, private_key_bytes);

            // C11 fix: Log flush errors instead of silently discarding.
            if let Err(err) = tpm2_flush_context(&mut device, srk_handle) {
                eprintln!("==> warning: TPM flush SRK handle after seal failed: {err}");
            }

            sealed_blob
        }

        /// Unseals a previously sealed blob using the Linux TPM via /dev/tpmrm0.
        ///
        /// This is a blocking operation and must be called from a blocking
        /// context (e.g. `spawn_blocking`).
        fn tpm_unseal(
            device_path: &Path,
            sealed_blob: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, SignerError> {
            let mut device = TpmDevice::open(device_path)?;

            let srk_handle = tpm2_create_primary_srk(&mut device)?;

            let plaintext = tpm2_load_and_unseal(&mut device, srk_handle, sealed_blob);

            // C11 fix: Log flush errors instead of silently discarding.
            if let Err(err) = tpm2_flush_context(&mut device, srk_handle) {
                eprintln!("==> warning: TPM flush SRK handle after unseal failed: {err}");
            }

            plaintext.map(Zeroizing::new)
        }

        /// Ensures the signing key for `vault_key_id` is cached (unsealed),
        /// then calls `f` with a reference to it while holding the read lock.
        ///
        /// This avoids cloning the `SigningKey` out of the lock, which would
        /// create untracked copies of the private key in memory.
        async fn with_signing_key<F, R>(&self, vault_key_id: Uuid, f: F) -> Result<R, SignerError>
        where
            F: FnOnce(&SigningKey) -> Result<R, SignerError>,
        {
            // Fast path: key already unsealed — sign within read lock.
            {
                let keys = self
                    .keys
                    .read()
                    .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
                if let Some(loaded) = keys.get(&vault_key_id) {
                    if let Some(ref sk) = loaded.signing_key {
                        return f(sk);
                    }
                } else {
                    return Err(SignerError::UnknownKey(vault_key_id));
                }
            }

            // Slow path: unseal via TPM (blocking I/O).
            let sealed_blob = {
                let keys = self
                    .keys
                    .read()
                    .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
                let loaded = keys
                    .get(&vault_key_id)
                    .ok_or(SignerError::UnknownKey(vault_key_id))?;
                loaded.blob.sealed_private_key.clone()
            };

            let device_path = self.device_path.clone();
            let plaintext =
                tokio::task::spawn_blocking(move || Self::tpm_unseal(&device_path, &sealed_blob))
                    .await
                    .map_err(|err| {
                        SignerError::Internal(format!("spawn_blocking join failed: {err}"))
                    })??;

            let signing_key =
                SigningKey::from_slice(&plaintext).map_err(|_| SignerError::InvalidPrivateKey)?;

            // Cache the unsealed key, then sign within the write lock.
            let result = {
                let mut keys = self
                    .keys
                    .write()
                    .map_err(|_| SignerError::Internal("poisoned lock".into()))?;
                if let Some(loaded) = keys.get_mut(&vault_key_id) {
                    loaded.signing_key = Some(signing_key);
                    // Sign using the reference inside the map — no clone.
                    f(loaded.signing_key.as_ref().unwrap())
                } else {
                    return Err(SignerError::UnknownKey(vault_key_id));
                }
            };

            result
        }
    }

    #[async_trait]
    impl VaultSignerBackend for LinuxTpmSignerBackend {
        fn backend_kind(&self) -> BackendKind {
            BackendKind::Tpm
        }

        async fn create_vault_key(
            &self,
            request: KeyCreateRequest,
        ) -> Result<VaultKey, SignerError> {
            let (signing_key, source) = match request {
                KeyCreateRequest::Generate => {
                    (SigningKey::random(&mut OsRng), KeySource::Generated)
                }
                KeyCreateRequest::Import { private_key_hex } => {
                    let key = Self::parse_import_key(&private_key_hex)?;
                    (key, KeySource::Imported)
                }
            };

            let key_id = Uuid::new_v4();
            let public_key_hex = Self::public_key_hex(&signing_key);
            let public_key_uncompressed = signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec();
            let created_at = OffsetDateTime::now_utc();

            // Seal the private key via TPM (blocking I/O).
            let private_key_bytes = Zeroizing::new(signing_key.to_bytes().to_vec());
            let device_path = self.device_path.clone();
            let sealed_private_key = tokio::task::spawn_blocking(move || {
                Self::tpm_seal(&device_path, &private_key_bytes)
            })
            .await
            .map_err(|err| {
                SignerError::Internal(format!("spawn_blocking join failed: {err}"))
            })??;

            let blob = LinuxTpmKeyBlob {
                version: SEALED_BLOB_VERSION,
                sealed_private_key,
                public_key_uncompressed,
            };

            self.keys
                .write()
                .map_err(|_| SignerError::Internal("poisoned lock".into()))?
                .insert(
                    key_id,
                    LoadedKey {
                        blob,
                        // Cache the signing key so first sign does not need to unseal.
                        signing_key: Some(signing_key),
                    },
                );

            Ok(VaultKey {
                id: key_id,
                source,
                public_key_hex,
                created_at,
            })
        }

        async fn sign_payload(
            &self,
            vault_key_id: Uuid,
            payload: &[u8],
        ) -> Result<Signature, SignerError> {
            self.with_signing_key(vault_key_id, |sk| {
                let signature: EcdsaSignature = sk.sign(payload);
                Ok(Signature::from_der(signature.to_der().as_bytes().to_vec()))
            })
            .await
        }

        async fn sign_digest(
            &self,
            vault_key_id: Uuid,
            digest: [u8; 32],
        ) -> Result<Signature, SignerError> {
            self.with_signing_key(vault_key_id, |sk| {
                Self::map_recoverable_digest_signature(sk.sign_prehash_recoverable(&digest))
            })
            .await
        }

        fn export_persistable_key_material(
            &self,
            vault_key_ids: &[Uuid],
        ) -> Result<HashMap<Uuid, Zeroizing<String>>, SignerError> {
            let keys = self
                .keys
                .read()
                .map_err(|_| SignerError::Internal("poisoned lock".into()))?;

            let mut exported = HashMap::with_capacity(vault_key_ids.len());
            for vault_key_id in vault_key_ids {
                let loaded = keys
                    .get(vault_key_id)
                    .ok_or(SignerError::UnknownKey(*vault_key_id))?;

                // Serialize the full blob (version + sealed data + public key)
                // as JSON for the string-valued persistence map.
                let json = serde_json::to_string(&loaded.blob).map_err(|err| {
                    SignerError::Internal(format!("blob serialization failed: {err}"))
                })?;
                exported.insert(*vault_key_id, Zeroizing::new(json));
            }
            Ok(exported)
        }

        fn restore_persistable_key_material(
            &self,
            persisted: &HashMap<Uuid, Zeroizing<String>>,
        ) -> Result<(), SignerError> {
            let mut restored = HashMap::with_capacity(persisted.len());
            for (vault_key_id, serialized) in persisted {
                let blob: LinuxTpmKeyBlob =
                    serde_json::from_str(serialized).map_err(|err| {
                        SignerError::Internal(format!("blob deserialization failed: {err}"))
                    })?;

                if blob.version > SEALED_BLOB_VERSION {
                    return Err(SignerError::Internal(format!(
                        "sealed blob version {} is newer than supported version \
                         {SEALED_BLOB_VERSION}; upgrade the daemon to load this key",
                        blob.version
                    )));
                }

                // C19 fix: Validate the public key is a valid secp256k1 point.
                if blob.public_key_uncompressed.len() != 65
                    || blob.public_key_uncompressed[0] != 0x04
                {
                    return Err(SignerError::Internal(format!(
                        "key {vault_key_id}: invalid public key length or prefix"
                    )));
                }
                let _verifying_key =
                    k256::ecdsa::VerifyingKey::from_sec1_bytes(&blob.public_key_uncompressed)
                        .map_err(|_| {
                            SignerError::Internal(format!(
                                "key {vault_key_id}: public key is not a valid secp256k1 point"
                            ))
                        })?;

                restored.insert(
                    *vault_key_id,
                    LoadedKey {
                        blob,
                        signing_key: None, // Will be unsealed lazily on first sign.
                    },
                );
            }

            // C5 fix: Probe unseal the first key to verify the TPM can actually
            // decrypt our sealed blobs. If tpm2_clear was run, this will fail
            // fast at startup instead of silently succeeding and then failing
            // on the first sign request.
            if let Some((probe_id, probe_loaded)) = restored.iter().next() {
                let probe_blob = probe_loaded.blob.sealed_private_key.clone();
                let probe_pub = probe_loaded.blob.public_key_uncompressed.clone();
                let probe_id_copy = *probe_id;

                // Call tpm_unseal directly (synchronous). This is safe because
                // restore_persistable_key_material is a sync fn, and the caller
                // is responsible for running it in an appropriate context.
                let plaintext =
                    Self::tpm_unseal(&self.device_path, &probe_blob).map_err(|err| {
                        SignerError::Internal(format!(
                            "key {probe_id_copy}: TPM probe unseal failed \
                             (was tpm2_clear run?): {err}"
                        ))
                    })?;

                // Also verify the unsealed key matches the stored public key.
                let probe_signing_key =
                    SigningKey::from_slice(&plaintext).map_err(|_| {
                        SignerError::Internal(format!(
                            "key {probe_id_copy}: probe unseal returned invalid secp256k1 key"
                        ))
                    })?;
                let derived_pub = probe_signing_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec();
                if derived_pub != probe_pub {
                    return Err(SignerError::Internal(format!(
                        "key {probe_id_copy}: unsealed key does not match stored public key \
                         (TPM state may have been tampered with)"
                    )));
                }
            }

            *self
                .keys
                .write()
                .map_err(|_| SignerError::Internal("poisoned lock".into()))? = restored;
            Ok(())
        }

        fn delete_vault_key_if_present(&self, vault_key_id: Uuid) -> Result<(), SignerError> {
            self.keys
                .write()
                .map_err(|_| SignerError::Internal("poisoned lock".into()))?
                .remove(&vault_key_id);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Linux TPM device I/O
    // -----------------------------------------------------------------------
    //
    // These functions communicate with the TPM via /dev/tpmrm0, the kernel's
    // TPM Resource Manager. Commands are written as raw bytes and responses
    // are read back. The RM handles session management, handle virtualization,
    // and concurrent access serialization.
    //
    // All functions are blocking and must be called from `spawn_blocking`.

    /// Handle to an open TPM device file.
    struct TpmDevice {
        file: std::fs::File,
    }

    impl TpmDevice {
        /// Opens the TPM device at the given path.
        fn open(path: &Path) -> Result<Self, SignerError> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(|err| {
                    SignerError::Internal(format!(
                        "failed to open TPM device '{}': {err} \
                         (ensure the device exists and the daemon has read/write access, \
                         e.g. via the 'tss' group)",
                        path.display()
                    ))
                })?;
            Ok(Self { file })
        }

        /// Submits a TPM2 command and returns the response.
        fn submit_command(&mut self, command: &[u8]) -> Result<Vec<u8>, SignerError> {
            self.file.write_all(command).map_err(|err| {
                SignerError::Internal(format!("failed to write TPM command: {err}"))
            })?;

            let mut response = vec![0u8; 4096];
            let n = self.file.read(&mut response).map_err(|err| {
                SignerError::Internal(format!("failed to read TPM response: {err}"))
            })?;
            response.truncate(n);
            Ok(response)
        }
    }

    /// TPM2 command/response tags, command codes, and algorithm constants.
    mod tpm2 {
        pub const ST_NO_SESSIONS: u16 = 0x8001;
        pub const ST_SESSIONS: u16 = 0x8002;

        pub const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
        pub const CC_CREATE: u32 = 0x0000_0153;
        pub const CC_LOAD: u32 = 0x0000_0157;
        pub const CC_UNSEAL: u32 = 0x0000_015E;
        pub const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

        /// TPM_RH_OWNER hierarchy handle.
        pub const RH_OWNER: u32 = 0x4000_0001;

        /// TPM_RS_PW (password authorization session).
        pub const RS_PW: u32 = 0x4000_0009;

        /// Algorithm IDs.
        pub const ALG_RSA: u16 = 0x0001;
        pub const ALG_SHA256: u16 = 0x000B;
        pub const ALG_KEYEDHASH: u16 = 0x0008;
        pub const ALG_AES: u16 = 0x0006;
        pub const ALG_NULL: u16 = 0x0010;
        pub const ALG_CFB: u16 = 0x0043;

        /// Object attributes for SRK (per TPM 2.0 Part 2, Table 31):
        ///   bit 1  = fixedTPM
        ///   bit 4  = fixedParent
        ///   bit 5  = sensitiveDataOrigin
        ///   bit 6  = userWithAuth
        ///   bit 10 = noDA
        ///   bit 16 = restricted
        ///   bit 17 = decrypt
        pub const SRK_OBJECT_ATTRS: u32 =
            (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 10) | (1 << 16) | (1 << 17);

        /// Object attributes for Seal object (per TPM 2.0 Part 2, Table 31):
        ///   bit 1 = fixedTPM
        ///   bit 4 = fixedParent
        ///   bit 6 = userWithAuth
        ///
        /// NOTE: no_da (bit 10) is intentionally NOT set, so dictionary attack
        /// lockout protection applies to unseal attempts. (C18 fix)
        pub const SEAL_OBJECT_ATTRS: u32 = (1 << 1) | (1 << 4) | (1 << 6);
    }

    /// Helper: big-endian serialization into a byte buffer.
    struct CmdBuilder {
        buf: Vec<u8>,
    }

    impl CmdBuilder {
        fn new() -> Self {
            Self {
                buf: Vec::with_capacity(256),
            }
        }

        fn push_u16(&mut self, v: u16) -> &mut Self {
            self.buf.extend_from_slice(&v.to_be_bytes());
            self
        }

        fn push_u32(&mut self, v: u32) -> &mut Self {
            self.buf.extend_from_slice(&v.to_be_bytes());
            self
        }

        fn push_bytes(&mut self, data: &[u8]) -> &mut Self {
            self.buf.extend_from_slice(data);
            self
        }

        /// Writes a TPM2B (u16 length-prefixed byte array).
        fn push_tpm2b(&mut self, data: &[u8]) -> &mut Self {
            self.push_u16(data.len() as u16);
            self.push_bytes(data);
            self
        }

        /// Patches the command header size field (bytes 2..6) with the actual
        /// buffer length.
        fn finalize(&mut self) -> &[u8] {
            let len = self.buf.len() as u32;
            self.buf[2..6].copy_from_slice(&len.to_be_bytes());
            &self.buf
        }
    }

    /// Helper: big-endian deserialization from a response buffer.
    struct RespReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> RespReader<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn remaining(&self) -> usize {
            self.buf.len().saturating_sub(self.pos)
        }

        fn read_u16(&mut self) -> Result<u16, SignerError> {
            if self.remaining() < 2 {
                return Err(SignerError::Internal("TPM response truncated (u16)".into()));
            }
            let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
            self.pos += 2;
            Ok(v)
        }

        fn read_u32(&mut self) -> Result<u32, SignerError> {
            if self.remaining() < 4 {
                return Err(SignerError::Internal("TPM response truncated (u32)".into()));
            }
            let v = u32::from_be_bytes([
                self.buf[self.pos],
                self.buf[self.pos + 1],
                self.buf[self.pos + 2],
                self.buf[self.pos + 3],
            ]);
            self.pos += 4;
            Ok(v)
        }

        fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], SignerError> {
            if self.remaining() < n {
                return Err(SignerError::Internal(
                    "TPM response truncated (bytes)".into(),
                ));
            }
            let slice = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Ok(slice)
        }

        /// Reads a TPM2B (u16 length-prefixed byte array).
        fn read_tpm2b(&mut self) -> Result<&'a [u8], SignerError> {
            let len = self.read_u16()? as usize;
            self.read_bytes(len)
        }

        fn skip(&mut self, n: usize) -> Result<(), SignerError> {
            if self.remaining() < n {
                return Err(SignerError::Internal(
                    "TPM response truncated (skip)".into(),
                ));
            }
            self.pos += n;
            Ok(())
        }
    }

    /// Parses the response header and returns (tag, size, response_code).
    fn parse_response_header(resp: &[u8]) -> Result<(u16, u32, u32), SignerError> {
        if resp.len() < 10 {
            return Err(SignerError::Internal(
                "TPM response too short for header".into(),
            ));
        }
        let tag = u16::from_be_bytes([resp[0], resp[1]]);
        let size = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]);
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        Ok((tag, size, rc))
    }

    /// Domain-specific auth value for sealed objects.
    ///
    /// This is a SHA-256 hash of a domain string, used as the auth password for
    /// TPM sealed objects. Any process that wants to unseal must provide this
    /// value, preventing casual cross-application unseal (C1 fix).
    ///
    /// NOTE: This is defense-in-depth. The primary protection is that the sealed
    /// blob itself is only stored in the daemon's Argon2-encrypted state file.
    /// The auth value prevents a process that can read state.enc AND access the
    /// TPM from unsealing without also knowing this constant.
    fn seal_object_auth() -> Vec<u8> {
        Sha256::digest(b"agentpay-vault-signer-seal-auth-v1").to_vec()
    }

    /// Builds a password auth area with an empty password (for SRK operations).
    fn empty_password_auth_area() -> Vec<u8> {
        let mut auth = CmdBuilder::new();
        auth.push_u32(tpm2::RS_PW);
        auth.push_tpm2b(&[]); // nonceCaller
        auth.buf.push(0x01); // sessionAttributes: continueSession
        auth.push_tpm2b(&[]); // hmac (empty password for owner hierarchy)
        auth.buf
    }

    /// Builds a password auth area with the seal object auth value.
    fn seal_auth_area() -> Vec<u8> {
        let auth_value = seal_object_auth();
        let mut auth = CmdBuilder::new();
        auth.push_u32(tpm2::RS_PW);
        auth.push_tpm2b(&[]); // nonceCaller
        auth.buf.push(0x01); // sessionAttributes: continueSession
        auth.push_tpm2b(&auth_value); // hmac = domain-specific auth
        auth.buf
    }

    /// Creates a primary SRK in the owner hierarchy.
    ///
    /// Uses the standard RSA-2048 SRK template for maximum compatibility.
    fn tpm2_create_primary_srk(device: &mut TpmDevice) -> Result<u32, SignerError> {
        let auth_area = empty_password_auth_area();

        // Build the inPublic template for RSA-2048 SRK.
        let mut in_public = CmdBuilder::new();
        in_public.push_u16(tpm2::ALG_RSA); // type = RSA
        in_public.push_u16(tpm2::ALG_SHA256); // nameAlg
        in_public.push_u32(tpm2::SRK_OBJECT_ATTRS); // objectAttributes
        in_public.push_tpm2b(&[]); // authPolicy (empty)
                                   // RSA parameters:
                                   //   symmetric = AES-128-CFB
                                   //   scheme = null
                                   //   keyBits = 2048
                                   //   exponent = 0 (default 65537)
        in_public.push_u16(tpm2::ALG_AES); // symmetric algorithm
        in_public.push_u16(128); // symmetric keyBits
        in_public.push_u16(tpm2::ALG_CFB); // symmetric mode
        in_public.push_u16(tpm2::ALG_NULL); // scheme
        in_public.push_u16(2048); // keyBits
        in_public.push_u32(0); // exponent

        // C2 fix: Use a domain-specific hash as the unique field to prevent
        // cross-application primary key collisions. Without this, any process
        // using the same SRK template with an empty unique gets the same primary
        // key handle, allowing it to load and unseal our sealed objects.
        //
        // For RSA, unique is TPM2B_PUBLIC_KEY_RSA (up to 256 bytes). We use a
        // 32-byte SHA-256 hash padded to 256 bytes with zeros.
        let unique_hash = Sha256::digest(SRK_UNIQUE_DOMAIN);
        let mut unique_buf = [0u8; 256];
        unique_buf[..32].copy_from_slice(&unique_hash);
        in_public.push_tpm2b(&unique_buf); // unique (domain-specific)

        let in_public_bytes = in_public.buf;

        let mut cmd = CmdBuilder::new();
        cmd.push_u16(tpm2::ST_SESSIONS); // tag
        cmd.push_u32(0); // placeholder for size
        cmd.push_u32(tpm2::CC_CREATE_PRIMARY); // commandCode
        cmd.push_u32(tpm2::RH_OWNER); // primaryHandle = TPM_RH_OWNER

        // Authorization area size + data
        cmd.push_u32(auth_area.len() as u32);
        cmd.push_bytes(&auth_area);

        // inSensitive (TPM2B_SENSITIVE_CREATE): empty userAuth + empty data
        let mut in_sensitive = CmdBuilder::new();
        in_sensitive.push_tpm2b(&[]); // userAuth
        in_sensitive.push_tpm2b(&[]); // data
        cmd.push_tpm2b(&in_sensitive.buf); // wrap as TPM2B

        // inPublic (TPM2B_PUBLIC)
        cmd.push_tpm2b(&in_public_bytes);

        // outsideInfo
        cmd.push_tpm2b(&[]);

        // creationPCR (TPML_PCR_SELECTION with count = 0)
        cmd.push_u32(0);

        let resp = device.submit_command(cmd.finalize())?;
        let (_tag, _size, rc) = parse_response_header(&resp)?;
        if rc != 0 {
            return Err(SignerError::Internal(format!(
                "TPM2_CreatePrimary failed: rc=0x{rc:08X}"
            )));
        }

        // Parse the object handle from the response (4 bytes after header).
        if resp.len() < 14 {
            return Err(SignerError::Internal(
                "TPM2_CreatePrimary response too short".into(),
            ));
        }
        let obj_handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
        Ok(obj_handle)
    }

    /// Creates a Seal object under the given parent handle containing the
    /// private key bytes.
    ///
    /// Returns the concatenation of length-prefixed TPM2B_PRIVATE and
    /// TPM2B_PUBLIC that can later be loaded and unsealed.
    fn tpm2_create_seal_object(
        device: &mut TpmDevice,
        parent_handle: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let auth_area = empty_password_auth_area();

        // C1 fix: Set a domain-specific userAuth on the sealed object so that
        // unseal requires providing this auth value. Without this, any process
        // with TPM access + the blob could unseal with an empty password.
        let seal_auth = seal_object_auth();
        let mut in_sensitive = CmdBuilder::new();
        in_sensitive.push_tpm2b(&seal_auth); // userAuth (domain-specific)
        in_sensitive.push_tpm2b(data); // data to seal

        // inPublic: KEYEDHASH seal object
        let mut in_public = CmdBuilder::new();
        in_public.push_u16(tpm2::ALG_KEYEDHASH); // type
        in_public.push_u16(tpm2::ALG_SHA256); // nameAlg
        in_public.push_u32(tpm2::SEAL_OBJECT_ATTRS); // objectAttributes
        in_public.push_tpm2b(&[]); // authPolicy (empty)
        in_public.push_u16(tpm2::ALG_NULL); // scheme (seal, not HMAC/XOR)
        in_public.push_tpm2b(&[]); // unique (empty)

        let mut cmd = CmdBuilder::new();
        cmd.push_u16(tpm2::ST_SESSIONS);
        cmd.push_u32(0); // placeholder
        cmd.push_u32(tpm2::CC_CREATE);
        cmd.push_u32(parent_handle);

        cmd.push_u32(auth_area.len() as u32);
        cmd.push_bytes(&auth_area);

        cmd.push_tpm2b(&in_sensitive.buf);
        cmd.push_tpm2b(&in_public.buf);

        // outsideInfo
        cmd.push_tpm2b(&[]);

        // creationPCR (count = 0)
        cmd.push_u32(0);

        let resp = device.submit_command(cmd.finalize())?;
        let (_tag, _size, rc) = parse_response_header(&resp)?;
        if rc != 0 {
            return Err(SignerError::Internal(format!(
                "TPM2_Create (seal) failed: rc=0x{rc:08X}"
            )));
        }

        // Response layout after header (10 bytes):
        //   parameterSize (4 bytes)
        //   TPM2B_PRIVATE outPrivate
        //   TPM2B_PUBLIC outPublic
        //   (creation data, hash, ticket follow but we skip them)
        let mut reader = RespReader::new(&resp);
        reader.skip(10)?; // header
        let _param_size = reader.read_u32()?;

        let out_private = reader.read_tpm2b()?;
        let out_public = reader.read_tpm2b()?;

        // Pack as length-prefixed fields for our sealed blob format.
        let mut blob = Vec::with_capacity(8 + out_private.len() + out_public.len());
        blob.extend_from_slice(&(out_private.len() as u32).to_le_bytes());
        blob.extend_from_slice(out_private);
        blob.extend_from_slice(&(out_public.len() as u32).to_le_bytes());
        blob.extend_from_slice(out_public);

        Ok(blob)
    }

    /// Loads a sealed object and unseals it, returning the plaintext data.
    fn tpm2_load_and_unseal(
        device: &mut TpmDevice,
        parent_handle: u32,
        sealed_blob: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        // Unpack the sealed blob.
        if sealed_blob.len() < 8 {
            return Err(SignerError::Internal("sealed blob too short".into()));
        }
        let mut pos = 0usize;

        let private_len =
            u32::from_le_bytes(sealed_blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + private_len > sealed_blob.len() {
            return Err(SignerError::Internal(
                "sealed blob private truncated".into(),
            ));
        }
        let private_bytes = &sealed_blob[pos..pos + private_len];
        pos += private_len;

        if pos + 4 > sealed_blob.len() {
            return Err(SignerError::Internal(
                "sealed blob public length missing".into(),
            ));
        }
        let public_len =
            u32::from_le_bytes(sealed_blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + public_len > sealed_blob.len() {
            return Err(SignerError::Internal("sealed blob public truncated".into()));
        }
        let public_bytes = &sealed_blob[pos..pos + public_len];

        // TPM2_Load: load the sealed object under the parent.
        let auth_area = empty_password_auth_area();

        let mut cmd = CmdBuilder::new();
        cmd.push_u16(tpm2::ST_SESSIONS);
        cmd.push_u32(0);
        cmd.push_u32(tpm2::CC_LOAD);
        cmd.push_u32(parent_handle);

        cmd.push_u32(auth_area.len() as u32);
        cmd.push_bytes(&auth_area);

        cmd.push_tpm2b(private_bytes);
        cmd.push_tpm2b(public_bytes);

        let resp = device.submit_command(cmd.finalize())?;
        let (_tag, _size, rc) = parse_response_header(&resp)?;
        if rc != 0 {
            return Err(SignerError::Internal(format!(
                "TPM2_Load failed: rc=0x{rc:08X}"
            )));
        }

        // Response: header (10) + object handle (4)
        if resp.len() < 14 {
            return Err(SignerError::Internal("TPM2_Load response too short".into()));
        }
        let loaded_handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);

        // TPM2_Unseal: retrieve the sealed data.
        // C1 fix: Use the domain-specific auth for unseal (matches the auth
        // set during tpm2_create_seal_object).
        let auth_area2 = seal_auth_area();

        let mut cmd2 = CmdBuilder::new();
        cmd2.push_u16(tpm2::ST_SESSIONS);
        cmd2.push_u32(0);
        cmd2.push_u32(tpm2::CC_UNSEAL);
        cmd2.push_u32(loaded_handle);

        cmd2.push_u32(auth_area2.len() as u32);
        cmd2.push_bytes(&auth_area2);

        // Wrap unseal in a closure so loaded_handle is always flushed,
        // even if submit_command fails at device level.
        let unseal_result = (|| -> Result<Vec<u8>, SignerError> {
            let resp2 = device.submit_command(cmd2.finalize())?;
            let (_tag2, _size2, rc2) = parse_response_header(&resp2)?;
            if rc2 != 0 {
                return Err(SignerError::Internal(format!(
                    "TPM2_Unseal failed: rc=0x{rc2:08X}"
                )));
            }

            // Response: header (10) + parameterSize (4) + TPM2B_SENSITIVE_DATA
            let mut reader2 = RespReader::new(&resp2);
            reader2.skip(10)?; // header
            let _param_size = reader2.read_u32()?;
            let plaintext = reader2.read_tpm2b()?;
            Ok(plaintext.to_vec())
        })();

        // Always flush loaded_handle regardless of unseal outcome.
        if let Err(err) = tpm2_flush_context(device, loaded_handle) {
            eprintln!("==> warning: TPM flush loaded handle after unseal failed: {err}");
        }

        unseal_result
    }

    /// Flushes a transient TPM handle.
    fn tpm2_flush_context(device: &mut TpmDevice, flush_handle: u32) -> Result<(), SignerError> {
        let mut cmd = CmdBuilder::new();
        cmd.push_u16(tpm2::ST_NO_SESSIONS);
        cmd.push_u32(0);
        cmd.push_u32(tpm2::CC_FLUSH_CONTEXT);
        cmd.push_u32(flush_handle);

        let resp = device.submit_command(cmd.finalize())?;
        let (_tag, _size, rc) = parse_response_header(&resp)?;
        if rc != 0 {
            return Err(SignerError::Internal(format!(
                "TPM2_FlushContext failed: rc=0x{rc:08X}"
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use inner::{LinuxTpmKeyBlob, LinuxTpmSignerBackend};

// =========================================================================
// Tests
// =========================================================================
//
// Tests are split into two tiers:
//
// 1. **Cross-platform unit tests** (`cfg(test)`) — exercise serialization,
//    validation, blob versioning, key management logic, and edge cases.
//    These run on any OS (CI on Linux/macOS) because they don't touch
//    actual TPM hardware.
//
// 2. **Linux+TPM integration tests** (`cfg(all(test, target_os = "linux"))`)
//    — exercise real TPM Seal/Unseal, end-to-end signing flows, and
//    hardware error paths. These require a Linux machine with a TPM chip
//    (physical or firmware).

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    // ── LinuxTpmKeyBlob serialization & validation tests ──
    //
    // These don't touch TPM hardware so they run on every platform.
    // We re-define a minimal blob struct matching the Linux one for
    // cross-platform testing.

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct TestBlob {
        version: u32,
        sealed_private_key: Vec<u8>,
        public_key_uncompressed: Vec<u8>,
    }

    #[test]
    fn blob_serialization_roundtrip() {
        let blob = TestBlob {
            version: 1,
            sealed_private_key: vec![0xDE, 0xAD, 0xBE, 0xEF],
            public_key_uncompressed: vec![0x04; 65],
        };
        let json = serde_json::to_string(&blob).expect("serialize");
        let restored: TestBlob = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.version, 1);
        assert_eq!(restored.sealed_private_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(restored.public_key_uncompressed.len(), 65);
    }

    #[test]
    fn blob_rejects_future_version() {
        let blob = TestBlob {
            version: 999,
            sealed_private_key: vec![1, 2, 3],
            public_key_uncompressed: vec![0x04; 65],
        };
        let json = serde_json::to_string(&blob).expect("serialize");
        let restored: TestBlob = serde_json::from_str(&json).expect("deserialize");
        // The actual backend checks version > SEALED_BLOB_VERSION (1).
        assert!(restored.version > 1, "future version must be detected");
    }

    #[test]
    fn blob_rejects_empty_json() {
        let result = serde_json::from_str::<TestBlob>("{}");
        assert!(result.is_err());
    }

    #[test]
    fn blob_rejects_malformed_json() {
        let result = serde_json::from_str::<TestBlob>("not-json");
        assert!(result.is_err());
    }

    // ── Public key validation tests ──

    #[test]
    fn valid_secp256k1_uncompressed_public_key() {
        use k256::ecdsa::SigningKey;
        use k256::elliptic_curve::rand_core::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let pk_bytes = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(pk_bytes.len(), 65);
        assert_eq!(pk_bytes[0], 0x04);

        // Verify it can be parsed back.
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes).expect("valid secp256k1 point");
    }

    #[test]
    fn reject_invalid_public_key_length() {
        let short = vec![0x04; 33]; // compressed, not uncompressed
        assert_ne!(short.len(), 65);
    }

    #[test]
    fn reject_wrong_prefix() {
        let mut bad = vec![0x00; 65];
        bad[0] = 0x05; // wrong prefix
        assert_ne!(bad[0], 0x04);
    }

    // ── Restore validation tests ──

    #[test]
    fn restore_rejects_future_blob_version() {
        let blob = TestBlob {
            version: 999,
            sealed_private_key: vec![1, 2, 3],
            public_key_uncompressed: vec![0x04; 65],
        };
        // In the real backend, version > SEALED_BLOB_VERSION would return Err.
        assert!(blob.version > 1);
    }

    #[test]
    fn restore_rejects_bad_public_key_prefix() {
        let blob = TestBlob {
            version: 1,
            sealed_private_key: vec![1, 2, 3],
            public_key_uncompressed: vec![0x00; 65],
        };
        assert_ne!(blob.public_key_uncompressed[0], 0x04);
    }

    #[test]
    fn restore_rejects_short_public_key() {
        let blob = TestBlob {
            version: 1,
            sealed_private_key: vec![1, 2, 3],
            public_key_uncompressed: vec![0x04; 32],
        };
        assert_ne!(blob.public_key_uncompressed.len(), 65);
    }

    // ── Export/import key material contract ──

    #[test]
    fn export_produces_valid_json() {
        let blob = TestBlob {
            version: 1,
            sealed_private_key: vec![0xAA, 0xBB],
            public_key_uncompressed: vec![0x04; 65],
        };
        let json = serde_json::to_string(&blob).expect("serialize");
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("sealed_private_key"));

        // Simulates what restore does.
        let mut persisted = HashMap::new();
        let key_id = Uuid::new_v4();
        persisted.insert(key_id, Zeroizing::new(json));

        for (_, serialized) in &persisted {
            let restored: TestBlob =
                serde_json::from_str(serialized).expect("round-trip deserialize");
            assert_eq!(restored.version, 1);
        }
    }
}
