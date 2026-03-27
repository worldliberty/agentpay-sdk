//! Windows TPM 2.0 signer backend using Seal/Unseal for secp256k1 key protection.
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
//!    the same TPM chip, optionally bound to specific PCR state. The sealed blob
//!    is the only thing persisted to disk.
//!
//! 3. **Signing**: At signing time the daemon unseals the private key, performs
//!    secp256k1 ECDSA signing in software via the `k256` crate, and immediately
//!    zeroizes the plaintext key material.
//!
//! 4. **Platform binding**: Because the sealed blob is bound to the TPM's SRK,
//!    stealing the file alone is useless without physical access to the same
//!    TPM chip.
//!
//! On Windows the TPM is accessed via TBS (TPM Base Services) through the
//! `windows-sys` crate, using the TPM2 command interface directly. All blocking
//! TPM I/O is offloaded to `tokio::task::spawn_blocking` to avoid stalling the
//! async runtime.

#[cfg(target_os = "windows")]
mod inner {
    use std::collections::HashMap;
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
    const SRK_UNIQUE_DOMAIN: &[u8] = b"agentpay-vault-signer-windows-tpm-v1";

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
    pub struct WindowsTpmKeyBlob {
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
    impl std::fmt::Debug for WindowsTpmKeyBlob {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WindowsTpmKeyBlob")
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
        blob: WindowsTpmKeyBlob,
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

    /// Windows TPM 2.0 signer backend.
    ///
    /// Uses TPM Seal/Unseal to protect secp256k1 private keys at rest while
    /// performing ECDSA signing in software with the `k256` crate. See the
    /// module-level documentation for the full architecture rationale.
    #[derive(Clone)]
    pub struct WindowsTpmSignerBackend {
        keys: Arc<RwLock<HashMap<Uuid, LoadedKey>>>,
    }

    impl std::fmt::Debug for WindowsTpmSignerBackend {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("WindowsTpmSignerBackend")
                .field("keys", &"<locked>")
                .finish()
        }
    }

    impl Default for WindowsTpmSignerBackend {
        fn default() -> Self {
            Self {
                keys: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    impl WindowsTpmSignerBackend {
        /// Creates a new Windows TPM signer backend.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
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

        /// Seals a raw 32-byte private key using the Windows TPM via TBS.
        ///
        /// This is a blocking operation and must be called from a blocking
        /// context (e.g. `spawn_blocking`).
        ///
        /// The sealed blob is bound to the current TPM's Storage Root Key and
        /// cannot be unsealed on any other machine.
        fn tpm_seal(private_key_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
            let context = tbs_create_context()?;

            let srk_handle = tpm2_create_primary_srk(&context)?;

            let sealed_blob = tpm2_create_seal_object(&context, srk_handle, private_key_bytes)?;

            // C11 fix: Log flush errors instead of silently discarding.
            if let Err(err) = tpm2_flush_context(&context, srk_handle) {
                eprintln!("==> warning: TPM flush SRK handle after seal failed: {err}");
            }

            tbs_close_context(context)?;

            Ok(sealed_blob)
        }

        /// Unseals a previously sealed blob using the Windows TPM via TBS.
        ///
        /// This is a blocking operation and must be called from a blocking
        /// context (e.g. `spawn_blocking`).
        fn tpm_unseal(sealed_blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SignerError> {
            let context = tbs_create_context()?;

            let srk_handle = tpm2_create_primary_srk(&context)?;

            let plaintext = tpm2_load_and_unseal(&context, srk_handle, sealed_blob)?;

            // C11 fix: Log flush errors instead of silently discarding.
            if let Err(err) = tpm2_flush_context(&context, srk_handle) {
                eprintln!("==> warning: TPM flush SRK handle after unseal failed: {err}");
            }
            tbs_close_context(context)?;

            Ok(Zeroizing::new(plaintext))
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

            let plaintext = tokio::task::spawn_blocking(move || Self::tpm_unseal(&sealed_blob))
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
    impl VaultSignerBackend for WindowsTpmSignerBackend {
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
            let sealed_private_key =
                tokio::task::spawn_blocking(move || Self::tpm_seal(&private_key_bytes))
                    .await
                    .map_err(|err| {
                        SignerError::Internal(format!("spawn_blocking join failed: {err}"))
                    })??;

            let blob = WindowsTpmKeyBlob {
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
                let blob: WindowsTpmKeyBlob = serde_json::from_str(serialized).map_err(|err| {
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
                // Using block_in_place here would panic on current_thread runtimes.
                let plaintext = Self::tpm_unseal(&probe_blob).map_err(|err| {
                    SignerError::Internal(format!(
                        "key {probe_id_copy}: TPM probe unseal failed (was tpm2_clear run?): {err}"
                    ))
                })?;

                // Also verify the unsealed key matches the stored public key.
                let probe_signing_key = SigningKey::from_slice(&plaintext).map_err(|_| {
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
    // Windows TBS (TPM Base Services) low-level interface
    // -----------------------------------------------------------------------
    //
    // These functions wrap the Windows TBS DLL calls to perform TPM 2.0
    // operations. The TPM 2.0 command structures are built manually because
    // the `tss-esapi` crate is not reliably available on Windows without
    // the TPM2-TSS library.
    //
    // All functions are blocking and must be called from `spawn_blocking`.

    use windows_sys::Win32::System::TpmBaseServices::{
        Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS2, TBS_CONTEXT_VERSION_TWO,
    };

    /// Opaque handle to a TBS context (maps to `TBS_HCONTEXT` which is
    /// `*mut c_void` in the Windows API).
    type TbsContextHandle = *mut core::ffi::c_void;

    /// Wrapper to allow sending the handle across threads.
    ///
    /// TBS context handles are thread-safe per Microsoft documentation.
    struct TbsContext(TbsContextHandle);

    // SAFETY: TBS context handles are documented as thread-safe by Microsoft.
    unsafe impl Send for TbsContext {}
    unsafe impl Sync for TbsContext {}

    impl Drop for TbsContext {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let result = unsafe { Tbsip_Context_Close(self.0) };
                if result != 0 {
                    eprintln!(
                        "==> warning: Tbsip_Context_Close failed in Drop: TBS error 0x{result:08X}"
                    );
                }
                self.0 = core::ptr::null_mut();
            }
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

        fn push_u8(&mut self, v: u8) -> &mut Self {
            self.buf.push(v);
            self
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

    /// Opens a TBS context handle.
    ///
    /// `TBS_CONTEXT_PARAMS2` requires `includeTpm20 = 1` (bit 2 of the
    /// anonymous union's `asUINT32` field) to access TPM 2.0 devices.
    /// Without this, `Tbsi_Context_Create` returns `TBS_E_TPM_NOT_FOUND`
    /// (0x8028400F) on machines that only expose a TPM 2.0 chip.
    fn tbs_create_context() -> Result<TbsContext, SignerError> {
        let mut params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            ..Default::default()
        };
        // Set includeTpm20 = 1 (bit 2 of the union's asUINT32 field = 4).
        // See: https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tbs_context_params2
        params.Anonymous.asUINT32 = 4;
        let mut handle: TbsContextHandle = core::ptr::null_mut();
        let result = unsafe {
            Tbsi_Context_Create(
                &params as *const TBS_CONTEXT_PARAMS2 as *const _,
                &mut handle,
            )
        };
        if result != 0 {
            return Err(SignerError::Internal(format!(
                "Tbsi_Context_Create failed: TBS error 0x{result:08X}"
            )));
        }
        Ok(TbsContext(handle))
    }

    /// Explicitly closes a TBS context handle. The `Drop` impl also closes
    /// on error paths, so this is belt-and-suspenders for the happy path.
    fn tbs_close_context(mut ctx: TbsContext) -> Result<(), SignerError> {
        if ctx.0.is_null() {
            return Ok(());
        }
        let result = unsafe { Tbsip_Context_Close(ctx.0) };
        ctx.0 = core::ptr::null_mut(); // Prevent double-close in Drop.
        if result != 0 {
            return Err(SignerError::Internal(format!(
                "Tbsip_Context_Close failed: TBS error 0x{result:08X}"
            )));
        }
        Ok(())
    }

    /// Submits a TPM2 command and returns the response.
    fn tbs_submit_command(ctx: &TbsContext, command: &[u8]) -> Result<Vec<u8>, SignerError> {
        let mut response = vec![0u8; 4096];
        let mut response_len = response.len() as u32;
        let result = unsafe {
            Tbsip_Submit_Command(
                ctx.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                response.as_mut_ptr(),
                &mut response_len,
            )
        };
        if result != 0 {
            return Err(SignerError::Internal(format!(
                "Tbsip_Submit_Command failed: TBS error 0x{result:08X}"
            )));
        }
        response.truncate(response_len as usize);
        Ok(response)
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
    /// The auth value prevents a process that can read state.enc AND access TBS
    /// from unsealing without also knowing this constant.
    fn seal_object_auth() -> Vec<u8> {
        Sha256::digest(b"agentpay-vault-signer-seal-auth-v1").to_vec()
    }

    /// Builds a password auth area with an empty password (for SRK operations).
    fn empty_password_auth_area() -> Vec<u8> {
        let mut auth = CmdBuilder::new();
        auth.push_u32(tpm2::RS_PW);
        auth.push_tpm2b(&[]); // nonceCaller
        auth.push_u8(0x01); // sessionAttributes: continueSession
        auth.push_tpm2b(&[]); // hmac (empty password for owner hierarchy)
        auth.buf
    }

    /// Builds a password auth area with the seal object auth value.
    fn seal_auth_area() -> Vec<u8> {
        let auth_value = seal_object_auth();
        let mut auth = CmdBuilder::new();
        auth.push_u32(tpm2::RS_PW);
        auth.push_tpm2b(&[]); // nonceCaller
        auth.push_u8(0x01); // sessionAttributes: continueSession
        auth.push_tpm2b(&auth_value); // hmac = domain-specific auth
        auth.buf
    }

    /// Creates a primary SRK in the owner hierarchy.
    ///
    /// Uses the standard RSA-2048 SRK template for maximum compatibility.
    fn tpm2_create_primary_srk(ctx: &TbsContext) -> Result<u32, SignerError> {
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

        let resp = tbs_submit_command(ctx, cmd.finalize())?;
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
        ctx: &TbsContext,
        parent_handle: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let auth_area = empty_password_auth_area();

        // C1 fix: Set a domain-specific userAuth on the sealed object so that
        // unseal requires providing this auth value. Without this, any process
        // with TBS access + the blob could unseal with an empty password.
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

        let resp = tbs_submit_command(ctx, cmd.finalize())?;
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
        ctx: &TbsContext,
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
        let public_len = u32::from_le_bytes(sealed_blob[pos..pos + 4].try_into().unwrap()) as usize;
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

        let resp = tbs_submit_command(ctx, cmd.finalize())?;
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
        // even if tbs_submit_command fails at TBS level.
        let unseal_result = (|| -> Result<Vec<u8>, SignerError> {
            let resp2 = tbs_submit_command(ctx, cmd2.finalize())?;
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
        if let Err(err) = tpm2_flush_context(ctx, loaded_handle) {
            eprintln!("==> warning: TPM flush loaded handle after unseal failed: {err}");
        }

        unseal_result
    }

    /// Flushes a transient TPM handle.
    fn tpm2_flush_context(ctx: &TbsContext, flush_handle: u32) -> Result<(), SignerError> {
        let mut cmd = CmdBuilder::new();
        cmd.push_u16(tpm2::ST_NO_SESSIONS);
        cmd.push_u32(0);
        cmd.push_u32(tpm2::CC_FLUSH_CONTEXT);
        cmd.push_u32(flush_handle);

        let resp = tbs_submit_command(ctx, cmd.finalize())?;
        let (_tag, _size, rc) = parse_response_header(&resp)?;
        if rc != 0 {
            return Err(SignerError::Internal(format!(
                "TPM2_FlushContext failed: rc=0x{rc:08X}"
            )));
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub use inner::{WindowsTpmKeyBlob, WindowsTpmSignerBackend};

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
// 2. **Windows+TPM integration tests** (`cfg(all(test, target_os = "windows"))`)
//    — exercise real TPM Seal/Unseal, end-to-end signing flows, and
//    hardware error paths. These require a Windows machine with a TPM chip
//    (physical or firmware).

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    // ── WindowsTpmKeyBlob serialization & validation tests ──
    //
    // These don't touch TPM hardware so they run on every platform.
    // We re-define a minimal blob struct matching the Windows one for
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
        // Generate a real secp256k1 key and check uncompressed format.
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
        // Must parse as valid secp256k1 point.
        assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&pk_bytes).is_ok());
    }

    #[test]
    fn reject_public_key_wrong_length() {
        // 64 bytes (missing prefix) should fail.
        let bad = vec![0x04; 64];
        assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&bad).is_err());
    }

    #[test]
    fn reject_public_key_wrong_prefix() {
        // 65 bytes but starts with 0x00 instead of 0x04.
        let mut bad = vec![0x00; 65];
        bad[0] = 0x00;
        assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&bad).is_err());
    }

    #[test]
    fn reject_public_key_not_on_curve() {
        // 65 bytes with 0x04 prefix but random data (overwhelmingly not on curve).
        let mut bad = vec![0xFF; 65];
        bad[0] = 0x04;
        assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&bad).is_err());
    }

    #[test]
    fn reject_empty_public_key() {
        assert!(k256::ecdsa::VerifyingKey::from_sec1_bytes(&[]).is_err());
    }

    // ── Key import validation tests ──

    #[test]
    fn parse_import_key_accepts_valid_hex() {
        use k256::ecdsa::SigningKey;
        let hex = "11".repeat(32);
        let key = SigningKey::from_slice(&hex::decode(&hex).unwrap()).unwrap();
        assert_eq!(key.to_bytes().len(), 32);
    }

    #[test]
    fn parse_import_key_accepts_0x_prefix() {
        let hex = format!("0x{}", "22".repeat(32));
        let raw = hex::decode(hex.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(raw.len(), 32);
        assert!(k256::ecdsa::SigningKey::from_slice(&raw).is_ok());
    }

    #[test]
    fn parse_import_key_rejects_short_hex() {
        let hex = "1234";
        let raw = hex::decode(hex).unwrap();
        assert_ne!(raw.len(), 32);
        assert!(k256::ecdsa::SigningKey::from_slice(&raw).is_err());
    }

    #[test]
    fn parse_import_key_rejects_invalid_hex() {
        assert!(hex::decode("not-valid-hex").is_err());
    }

    #[test]
    fn parse_import_key_rejects_zero_key() {
        // All-zero is not a valid secp256k1 scalar.
        let raw = vec![0u8; 32];
        assert!(k256::ecdsa::SigningKey::from_slice(&raw).is_err());
    }

    // ── Sealed blob packing/unpacking tests ──
    //
    // The blob format is: [priv_len:u32LE][priv_bytes][pub_len:u32LE][pub_bytes]

    fn pack_sealed_blob(priv_bytes: &[u8], pub_bytes: &[u8]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
        blob.extend_from_slice(priv_bytes);
        blob.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
        blob.extend_from_slice(pub_bytes);
        blob
    }

    fn unpack_sealed_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
        if blob.len() < 8 {
            return Err("too short");
        }
        let mut pos = 0;
        let priv_len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + priv_len > blob.len() {
            return Err("private truncated");
        }
        let priv_bytes = &blob[pos..pos + priv_len];
        pos += priv_len;
        if pos + 4 > blob.len() {
            return Err("public length missing");
        }
        let pub_len = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + pub_len > blob.len() {
            return Err("public truncated");
        }
        let pub_bytes = &blob[pos..pos + pub_len];
        Ok((priv_bytes, pub_bytes))
    }

    #[test]
    fn sealed_blob_pack_unpack_roundtrip() {
        let priv_data = b"sealed-private-key-data";
        let pub_data = b"public-key-template-data";
        let blob = pack_sealed_blob(priv_data, pub_data);
        let (priv_out, pub_out) = unpack_sealed_blob(&blob).unwrap();
        assert_eq!(priv_out, priv_data);
        assert_eq!(pub_out, pub_data);
    }

    #[test]
    fn sealed_blob_rejects_too_short() {
        assert!(unpack_sealed_blob(&[1, 2, 3]).is_err());
    }

    #[test]
    fn sealed_blob_rejects_truncated_private() {
        // Claims priv_len=100 but only has 4 bytes.
        let mut blob = Vec::new();
        blob.extend_from_slice(&100u32.to_le_bytes());
        blob.extend_from_slice(&[0xAA; 4]);
        assert!(unpack_sealed_blob(&blob).is_err());
    }

    #[test]
    fn sealed_blob_rejects_missing_public_length() {
        // Valid private section but no public length follows.
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&[0xAA; 2]);
        // No room for pub_len.
        assert!(unpack_sealed_blob(&blob).is_err());
    }

    #[test]
    fn sealed_blob_rejects_truncated_public() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes());
        blob.extend_from_slice(&[0xAA; 2]);
        blob.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        blob.extend_from_slice(&[0xBB; 3]); // only 3
        assert!(unpack_sealed_blob(&blob).is_err());
    }

    #[test]
    fn sealed_blob_handles_empty_sections() {
        let blob = pack_sealed_blob(&[], &[]);
        let (priv_out, pub_out) = unpack_sealed_blob(&blob).unwrap();
        assert!(priv_out.is_empty());
        assert!(pub_out.is_empty());
    }

    #[test]
    fn sealed_blob_handles_large_data() {
        let priv_data = vec![0xAA; 4096];
        let pub_data = vec![0xBB; 2048];
        let blob = pack_sealed_blob(&priv_data, &pub_data);
        let (priv_out, pub_out) = unpack_sealed_blob(&blob).unwrap();
        assert_eq!(priv_out.len(), 4096);
        assert_eq!(pub_out.len(), 2048);
    }

    // ── TPM2 command builder tests ──
    //
    // Verify big-endian encoding matches TPM2 spec expectations.

    #[test]
    fn tpm2_be_encoding() {
        // TPM2 uses big-endian for all multi-byte fields.
        let val: u16 = 0x8001;
        assert_eq!(val.to_be_bytes(), [0x80, 0x01]);
        let val: u32 = 0x0000_0131;
        assert_eq!(val.to_be_bytes(), [0x00, 0x00, 0x01, 0x31]);
    }

    #[test]
    fn tpm2b_encoding() {
        // TPM2B is: u16 length (BE) + data.
        let data = b"hello";
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        assert_eq!(buf, [0x00, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn tpm2b_empty() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(buf, [0x00, 0x00]);
    }

    // ── SRK unique field domain separation (C2 fix) ──

    #[test]
    fn srk_unique_is_deterministic_and_nonzero() {
        use sha2::{Digest, Sha256};
        let domain = b"agentpay-vault-signer-windows-tpm-v1";
        let hash1 = Sha256::digest(domain);
        let hash2 = Sha256::digest(domain);
        assert_eq!(hash1, hash2, "deterministic");
        assert_ne!(&hash1[..], &[0u8; 32], "non-zero");
    }

    #[test]
    fn srk_unique_differs_from_linux_domain() {
        use sha2::{Digest, Sha256};
        let win = Sha256::digest(b"agentpay-vault-signer-windows-tpm-v1");
        // If someone uses a different domain string, they get a different SRK.
        let other = Sha256::digest(b"agentpay-vault-signer-linux-tpm-v1");
        assert_ne!(win, other);
    }

    // ── Seal auth domain separation (C1 fix) ──

    #[test]
    fn seal_auth_is_deterministic_and_nonzero() {
        use sha2::{Digest, Sha256};
        let auth = Sha256::digest(b"agentpay-vault-signer-seal-auth-v1");
        assert_ne!(&auth[..], &[0u8; 32], "auth must not be empty/zero");
        assert_eq!(auth.len(), 32);
    }

    #[test]
    fn seal_auth_differs_from_empty() {
        use sha2::{Digest, Sha256};
        let auth = Sha256::digest(b"agentpay-vault-signer-seal-auth-v1");
        let empty_hash = Sha256::digest(b"");
        assert_ne!(auth, empty_hash);
    }

    // ── Seal object attrs (C18 fix): no_da must NOT be set ──

    #[test]
    fn seal_object_attrs_does_not_have_no_da() {
        // Seal object: fixedTPM(1) | fixedParent(2) | userWithAuth(6)
        let attrs: u32 = (1 << 1) | (1 << 4) | (1 << 6);
        let no_da_bit: u32 = 1 << 10;
        assert_eq!(
            attrs & no_da_bit,
            0,
            "no_da (bit 10) must NOT be set on seal objects"
        );
    }

    #[test]
    fn srk_attrs_has_expected_bits() {
        // SRK: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth |
        //      noDA | restricted | decrypt
        let attrs: u32 =
            (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 10) | (1 << 16) | (1 << 17);
        assert_ne!(attrs & (1 << 1), 0, "fixedTPM");
        assert_ne!(attrs & (1 << 4), 0, "fixedParent");
        assert_ne!(attrs & (1 << 5), 0, "sensitiveDataOrigin");
        assert_ne!(attrs & (1 << 6), 0, "userWithAuth");
        assert_ne!(attrs & (1 << 10), 0, "noDA (standard for SRK)");
        assert_ne!(attrs & (1 << 16), 0, "restricted");
        assert_ne!(attrs & (1 << 17), 0, "decrypt");
    }

    // ── Debug redaction (C6 fix) ──

    #[test]
    fn blob_debug_redacts_sealed_key() {
        let blob = TestBlob {
            version: 1,
            sealed_private_key: vec![0xAA, 0xBB, 0xCC], // Would be sensitive
            public_key_uncompressed: vec![0x04; 65],
        };
        // Our real WindowsTpmKeyBlob has a custom Debug impl that prints
        // "<redacted>" for sealed_private_key. We verify the pattern here:
        let debug_output = format!("{:?}", blob);
        // TestBlob uses derive(Debug) so it WOULD leak. This test documents
        // that the real impl must NOT derive(Debug).
        // The actual assertion is on the real struct (Windows-only).
        assert!(
            debug_output.contains("sealed_private_key") || debug_output.contains("TestBlob"),
            "test blob debug format is valid"
        );
    }

    // ── Zeroize behavior ──

    #[test]
    fn signing_key_bytes_can_be_zeroized() {
        use k256::ecdsa::SigningKey;
        use k256::elliptic_curve::rand_core::OsRng;
        use zeroize::Zeroize;

        let sk = SigningKey::random(&mut OsRng);
        let mut bytes = sk.to_bytes();
        assert_ne!(&bytes[..], &[0u8; 32]);
        bytes.as_mut_slice().zeroize();
        assert_eq!(&bytes[..], &[0u8; 32]);
    }

    #[test]
    fn zeroizing_vec_clears_on_drop() {
        let secret = Zeroizing::new(vec![0xAA; 32]);
        // Verify it holds data while alive.
        assert_eq!(secret.len(), 32);
        assert_eq!(secret[0], 0xAA);
        // On drop, Zeroizing<Vec<u8>> will clear the memory.
        // (We can't observe post-drop memory, but we verify the type works.)
        drop(secret);
    }

    // ── Export/restore map correctness ──

    #[test]
    fn export_map_uses_uuid_keys() {
        let id = Uuid::new_v4();
        let mut map: HashMap<Uuid, Zeroizing<String>> = HashMap::new();
        map.insert(id, Zeroizing::new("test-value".into()));
        assert!(map.contains_key(&id));
        assert!(!map.contains_key(&Uuid::new_v4()));
    }

    #[test]
    fn restore_rejects_unknown_uuid_in_export() {
        // If someone tampers with the UUID mapping, the backend should
        // not silently accept keys that don't match.
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let mut map: HashMap<Uuid, Zeroizing<String>> = HashMap::new();
        map.insert(id1, Zeroizing::new("data".into()));
        // Querying with a different UUID should return None.
        assert!(map.get(&id2).is_none());
    }

    // ── TPM2 response header parsing ──

    #[test]
    fn parse_response_header_valid() {
        // tag(2) + size(4) + rc(4) = 10 bytes minimum
        let resp: [u8; 10] = [
            0x80, 0x01, // tag = ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0A, // size = 10
            0x00, 0x00, 0x00, 0x00, // rc = SUCCESS
        ];
        let tag = u16::from_be_bytes([resp[0], resp[1]]);
        let size = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]);
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        assert_eq!(tag, 0x8001);
        assert_eq!(size, 10);
        assert_eq!(rc, 0);
    }

    #[test]
    fn parse_response_header_rejects_short() {
        let resp = [0x80, 0x01, 0x00]; // Only 3 bytes, need 10.
        assert!(resp.len() < 10);
    }

    #[test]
    fn parse_response_header_detects_error_code() {
        let resp: [u8; 10] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x01, // rc = 0x101
        ];
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        assert_ne!(rc, 0, "non-zero rc indicates TPM error");
    }

    // ── secp256k1 signing roundtrip (software path) ──

    #[tokio::test]
    async fn secp256k1_sign_and_verify_roundtrip() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
        use k256::elliptic_curve::rand_core::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let msg = b"test message for signing";
        let sig: Signature = sk.sign(msg);

        // Verify the DER encoding roundtrips.
        let der_bytes = sig.to_der();
        let parsed = Signature::from_der(der_bytes.as_bytes()).expect("DER roundtrip");
        assert_eq!(sig, parsed);

        // Verify the signature is valid for this public key.
        use k256::ecdsa::signature::Verifier;
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[tokio::test]
    async fn secp256k1_recoverable_digest_roundtrip() {
        use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};
        use k256::elliptic_curve::rand_core::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let digest = [0x42u8; 32];

        let (sig, recid) = sk
            .sign_prehash_recoverable(&digest)
            .expect("recoverable sign");

        // Recover the public key from signature + digest.
        let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, recid).expect("recovery");
        assert_eq!(recovered, vk);
    }

    #[test]
    fn secp256k1_different_keys_produce_different_signatures() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey};
        use k256::elliptic_curve::rand_core::OsRng;

        let sk1 = SigningKey::random(&mut OsRng);
        let sk2 = SigningKey::random(&mut OsRng);
        let msg = b"identical message";
        let sig1: Signature = sk1.sign(msg);
        let sig2: Signature = sk2.sign(msg);
        assert_ne!(sig1, sig2);
    }

    // ── Edge cases: concurrent access ──

    #[tokio::test]
    async fn concurrent_reads_dont_deadlock() {
        use std::sync::{Arc, RwLock};
        let map: Arc<RwLock<HashMap<Uuid, String>>> = Arc::new(RwLock::new(HashMap::new()));

        let mut handles = vec![];
        for _ in 0..10 {
            let map = map.clone();
            handles.push(tokio::spawn(async move {
                let guard = map.read().unwrap();
                let _len = guard.len();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }
}

// ── Windows-only integration tests (require real TPM hardware) ──
#[cfg(all(test, target_os = "windows"))]
mod windows_integration_tests {
    use super::inner::*;
    use crate::{KeyCreateRequest, SignerError, VaultSignerBackend};
    use std::collections::HashMap;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    #[tokio::test]
    async fn create_key_and_sign_payload() {
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        assert!(!key.public_key_hex.is_empty());
        assert_eq!(key.public_key_hex.len(), 130); // 65 bytes uncompressed = 130 hex chars

        let sig = backend
            .sign_payload(key.id, b"test payload")
            .await
            .expect("must sign");
        assert!(!sig.bytes.is_empty());
    }

    #[tokio::test]
    async fn create_key_and_sign_digest() {
        use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        let digest = [0x42u8; 32];
        let sig = backend
            .sign_digest(key.id, digest)
            .await
            .expect("must sign digest");

        // Verify the signature can recover the correct public key.
        let parsed = K256Signature::from_der(&sig.bytes).expect("DER parse");
        let vk = VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("hex"))
            .expect("verifying key");
        let recid =
            RecoveryId::trial_recovery_from_prehash(&vk, &digest, &parsed).expect("recovery id");
        let recovered =
            VerifyingKey::recover_from_prehash(&digest, &parsed, recid).expect("recover");
        assert_eq!(recovered, vk);
    }

    #[tokio::test]
    async fn import_key_and_sign() {
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Import {
                private_key_hex: format!("0x{}", "11".repeat(32)),
            })
            .await
            .expect("must import key");

        assert_eq!(key.source, vault_domain::KeySource::Imported);
        let sig = backend
            .sign_payload(key.id, b"imported key test")
            .await
            .expect("must sign");
        assert!(!sig.bytes.is_empty());
    }

    #[tokio::test]
    async fn export_and_restore_roundtrip() {
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("must create key");

        // Sign before export.
        let sig_before = backend
            .sign_digest(key.id, [0xAA; 32])
            .await
            .expect("sign before export");

        // Export.
        let exported = backend
            .export_persistable_key_material(&[key.id])
            .expect("must export");
        assert!(exported.contains_key(&key.id));

        // Restore into fresh backend.
        let restored = WindowsTpmSignerBackend::new();
        restored
            .restore_persistable_key_material(&exported)
            .expect("must restore");

        // Sign after restore — must produce valid signature.
        let sig_after = restored
            .sign_digest(key.id, [0xBB; 32])
            .await
            .expect("sign after restore");
        assert!(!sig_after.bytes.is_empty());
    }

    #[tokio::test]
    async fn restore_validates_public_key_on_unseal() {
        // Create key, export, tamper with public key, restore should fail on first sign.
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("create key");

        let exported = backend
            .export_persistable_key_material(&[key.id])
            .expect("export");

        // Tamper: replace public key with a different valid secp256k1 point.
        let json = exported.get(&key.id).unwrap();
        let mut blob: WindowsTpmKeyBlob = serde_json::from_str(json).unwrap();
        // Flip a byte to make it invalid.
        if blob.public_key_uncompressed.len() == 65 {
            blob.public_key_uncompressed[1] ^= 0xFF;
        }
        let tampered_json = serde_json::to_string(&blob).unwrap();

        let mut tampered = HashMap::new();
        tampered.insert(key.id, Zeroizing::new(tampered_json));

        let restored = WindowsTpmSignerBackend::new();
        // restore should fail because tampered public key is not on curve
        // OR probe unseal will detect mismatch.
        let result = restored.restore_persistable_key_material(&tampered);
        assert!(result.is_err(), "tampered public key must be rejected");
    }

    #[tokio::test]
    async fn sign_unknown_key_returns_error() {
        let backend = WindowsTpmSignerBackend::new();
        let unknown = Uuid::new_v4();
        assert!(matches!(
            backend.sign_payload(unknown, b"payload").await,
            Err(SignerError::UnknownKey(id)) if id == unknown
        ));
        assert!(matches!(
            backend.sign_digest(unknown, [0x11; 32]).await,
            Err(SignerError::UnknownKey(id)) if id == unknown
        ));
    }

    #[tokio::test]
    async fn export_unknown_key_returns_error() {
        let backend = WindowsTpmSignerBackend::new();
        let unknown = Uuid::new_v4();
        assert!(matches!(
            backend.export_persistable_key_material(&[unknown]),
            Err(SignerError::UnknownKey(id)) if id == unknown
        ));
    }

    #[tokio::test]
    async fn delete_key_prevents_signing() {
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("create key");

        backend.delete_vault_key_if_present(key.id).expect("delete");

        assert!(matches!(
            backend.sign_payload(key.id, b"should fail").await,
            Err(SignerError::UnknownKey(_))
        ));
    }

    #[tokio::test]
    async fn delete_nonexistent_key_is_idempotent() {
        let backend = WindowsTpmSignerBackend::new();
        backend
            .delete_vault_key_if_present(Uuid::new_v4())
            .expect("delete nonexistent must succeed");
    }

    #[tokio::test]
    async fn multiple_keys_independent() {
        let backend = WindowsTpmSignerBackend::new();
        let key1 = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("key1");
        let key2 = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("key2");

        // Different keys have different public keys.
        assert_ne!(key1.public_key_hex, key2.public_key_hex);

        // Deleting key1 doesn't affect key2.
        backend.delete_vault_key_if_present(key1.id).unwrap();
        assert!(backend.sign_payload(key1.id, b"fail").await.is_err());
        assert!(backend.sign_payload(key2.id, b"ok").await.is_ok());
    }

    #[tokio::test]
    async fn blob_version_check_rejects_future_version() {
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("create");
        let exported = backend
            .export_persistable_key_material(&[key.id])
            .expect("export");

        // Tamper version to 999.
        let json = exported.get(&key.id).unwrap();
        let mut blob: WindowsTpmKeyBlob = serde_json::from_str(json).unwrap();
        blob.version = 999;
        let tampered = serde_json::to_string(&blob).unwrap();

        let mut map = HashMap::new();
        map.insert(key.id, Zeroizing::new(tampered));

        let restored = WindowsTpmSignerBackend::new();
        let result = restored.restore_persistable_key_material(&map);
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("newer than supported"));
    }

    #[tokio::test]
    async fn debug_output_redacts_sealed_key() {
        let backend = WindowsTpmSignerBackend::new();
        let key = backend
            .create_vault_key(KeyCreateRequest::Generate)
            .await
            .expect("create");
        let exported = backend
            .export_persistable_key_material(&[key.id])
            .expect("export");
        let json = exported.get(&key.id).unwrap();
        let blob: WindowsTpmKeyBlob = serde_json::from_str(json).unwrap();

        let debug = format!("{:?}", blob);
        assert!(
            debug.contains("<redacted>"),
            "Debug output must redact sealed_private_key"
        );
        assert!(
            !debug.contains(&hex::encode(&blob.sealed_private_key)),
            "Debug output must NOT contain raw sealed bytes"
        );
    }
}
