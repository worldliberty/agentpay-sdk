//! Raw TPM 2.0 command encoding and device I/O for seal/unseal.
//!
//! These functions communicate with the TPM via /dev/tpmrm0, the kernel's
//! TPM Resource Manager. Commands are written as raw bytes and responses
//! are read back. The RM handles session management, handle virtualization,
//! and concurrent access serialization.
//!
//! All functions are blocking and must be called from `spawn_blocking` (or an
//! equivalent blocking context).

use std::io::{Read, Write};
use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::SignerError;

/// Domain separation string hashed into the SRK unique field to prevent
/// cross-application primary key collisions (C2 fix).
const SRK_UNIQUE_DOMAIN: &[u8] = b"agentpay-vault-signer-linux-tpm-v1";

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;

const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_CREATE: u32 = 0x0000_0153;
const CC_LOAD: u32 = 0x0000_0157;
const CC_UNSEAL: u32 = 0x0000_015E;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

/// TPM_RH_OWNER hierarchy handle.
const RH_OWNER: u32 = 0x4000_0001;

/// TPM_RS_PW (password authorization session).
const RS_PW: u32 = 0x4000_0009;

/// Algorithm IDs.
const ALG_RSA: u16 = 0x0001;
const ALG_SHA256: u16 = 0x000B;
const ALG_KEYEDHASH: u16 = 0x0008;
const ALG_AES: u16 = 0x0006;
const ALG_NULL: u16 = 0x0010;
const ALG_CFB: u16 = 0x0043;

/// Object attributes for SRK (per TPM 2.0 Part 2, Table 31):
///   bit 1  = fixedTPM
///   bit 4  = fixedParent
///   bit 5  = sensitiveDataOrigin
///   bit 6  = userWithAuth
///   bit 10 = noDA
///   bit 16 = restricted
///   bit 17 = decrypt
const SRK_OBJECT_ATTRS: u32 =
    (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 10) | (1 << 16) | (1 << 17);

/// Object attributes for Seal object (per TPM 2.0 Part 2, Table 31):
///   bit 1 = fixedTPM
///   bit 4 = fixedParent
///   bit 6 = userWithAuth
///
/// NOTE: no_da (bit 10) is intentionally NOT set, so dictionary attack
/// lockout protection applies to unseal attempts. (C18 fix)
const SEAL_OBJECT_ATTRS: u32 = (1 << 1) | (1 << 4) | (1 << 6);

/// Seals a raw private key under the TPM's Storage Root Key.
///
/// The sealed blob is bound to the current TPM's SRK and cannot be unsealed
/// on any other machine.
pub(super) fn seal(device_path: &Path, private_key_bytes: &[u8]) -> Result<Vec<u8>, SignerError> {
    let mut device = TpmDevice::open(device_path)?;
    let srk_handle = create_primary_srk(&mut device)?;
    let sealed_blob = create_seal_object(&mut device, srk_handle, private_key_bytes);
    // C11 fix: Log flush errors instead of silently discarding.
    if let Err(err) = flush_context(&mut device, srk_handle) {
        eprintln!("==> warning: TPM flush SRK handle after seal failed: {err}");
    }
    sealed_blob
}

/// Unseals a blob previously produced by [`seal`] on the same TPM.
pub(super) fn unseal(
    device_path: &Path,
    sealed_blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SignerError> {
    let mut device = TpmDevice::open(device_path)?;
    let srk_handle = create_primary_srk(&mut device)?;
    let plaintext = load_and_unseal(&mut device, srk_handle, sealed_blob);
    // C11 fix: Log flush errors instead of silently discarding.
    if let Err(err) = flush_context(&mut device, srk_handle) {
        eprintln!("==> warning: TPM flush SRK handle after unseal failed: {err}");
    }
    plaintext.map(Zeroizing::new)
}

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
        self.file
            .write_all(command)
            .map_err(|err| SignerError::Internal(format!("failed to write TPM command: {err}")))?;

        let mut response = vec![0u8; 4096];
        let n = self
            .file
            .read(&mut response)
            .map_err(|err| SignerError::Internal(format!("failed to read TPM response: {err}")))?;
        response.truncate(n);
        Ok(response)
    }

    /// Submits a command and fails on a non-zero TPM response code.
    fn submit_checked(&mut self, command: &[u8], name: &str) -> Result<Vec<u8>, SignerError> {
        let resp = self.submit_command(command)?;
        let (_tag, _size, rc) = parse_response_header(&resp)?;
        if rc != 0 {
            return Err(SignerError::Internal(format!(
                "{name} failed: rc=0x{rc:08X}"
            )));
        }
        Ok(resp)
    }
}

/// Helper: big-endian serialization into a byte buffer.
pub(super) struct CmdBuilder {
    buf: Vec<u8>,
}

impl CmdBuilder {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    /// Starts a command with `tag`, a size placeholder, and `command_code`.
    pub(super) fn command(tag: u16, command_code: u32) -> Self {
        let mut cmd = Self::new();
        cmd.push_u16(tag);
        cmd.push_u32(0); // size, patched by `finalize`
        cmd.push_u32(command_code);
        cmd
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
    pub(super) fn push_tpm2b(&mut self, data: &[u8]) -> &mut Self {
        self.push_u16(data.len() as u16);
        self.push_bytes(data);
        self
    }

    /// Writes an authorization area (u32 size followed by the area bytes).
    fn push_auth_area(&mut self, auth_area: &[u8]) -> &mut Self {
        self.push_u32(auth_area.len() as u32);
        self.push_bytes(auth_area)
    }

    /// Patches the command header size field (bytes 2..6) with the actual
    /// buffer length.
    pub(super) fn finalize(&mut self) -> &[u8] {
        let len = self.buf.len() as u32;
        self.buf[2..6].copy_from_slice(&len.to_be_bytes());
        &self.buf
    }
}

/// Helper: big-endian deserialization from a response buffer.
pub(super) struct RespReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> RespReader<'a> {
    pub(super) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub(super) fn read_u16(&mut self) -> Result<u16, SignerError> {
        let bytes = self.read_array::<2>("u16")?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub(super) fn read_u32(&mut self) -> Result<u32, SignerError> {
        let bytes = self.read_array::<4>("u32")?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_array<const N: usize>(&mut self, what: &str) -> Result<[u8; N], SignerError> {
        if self.remaining() < N {
            return Err(SignerError::Internal(format!(
                "TPM response truncated ({what})"
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    pub(super) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], SignerError> {
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
    pub(super) fn read_tpm2b(&mut self) -> Result<&'a [u8], SignerError> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    pub(super) fn skip(&mut self, n: usize) -> Result<(), SignerError> {
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
pub(super) fn parse_response_header(resp: &[u8]) -> Result<(u16, u32, u32), SignerError> {
    if resp.len() < 10 {
        return Err(SignerError::Internal(
            "TPM response too short for header".into(),
        ));
    }
    let mut reader = RespReader::new(resp);
    Ok((reader.read_u16()?, reader.read_u32()?, reader.read_u32()?))
}

/// Reads the object handle that follows the 10-byte response header.
fn response_handle(resp: &[u8], name: &str) -> Result<u32, SignerError> {
    let mut reader = RespReader::new(resp);
    reader.skip(10)?;
    reader
        .read_u32()
        .map_err(|_| SignerError::Internal(format!("{name} response too short")))
}

/// Packs `TPM2B_PRIVATE` and `TPM2B_PUBLIC` as `u32 LE length || bytes` pairs,
/// the persisted sealed-blob layout.
pub(super) fn pack_sealed_blob(private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8 + private.len() + public.len());
    blob.extend_from_slice(&(private.len() as u32).to_le_bytes());
    blob.extend_from_slice(private);
    blob.extend_from_slice(&(public.len() as u32).to_le_bytes());
    blob.extend_from_slice(public);
    blob
}

/// Splits a sealed blob produced by [`pack_sealed_blob`] into its private and public parts.
pub(super) fn unpack_sealed_blob(sealed_blob: &[u8]) -> Result<(&[u8], &[u8]), SignerError> {
    fn take_part<'a>(rest: &mut &'a [u8], label: &str) -> Result<&'a [u8], SignerError> {
        let (len, tail) = rest
            .split_first_chunk::<4>()
            .ok_or_else(|| SignerError::Internal(format!("sealed blob {label} length missing")))?;
        let len = u32::from_le_bytes(*len) as usize;
        if tail.len() < len {
            return Err(SignerError::Internal(format!(
                "sealed blob {label} truncated"
            )));
        }
        let (part, tail) = tail.split_at(len);
        *rest = tail;
        Ok(part)
    }

    let mut rest = sealed_blob;
    let private = take_part(&mut rest, "private")?;
    let public = take_part(&mut rest, "public")?;
    Ok((private, public))
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

/// Builds a password auth area carrying `password` as the session HMAC.
fn password_auth_area(password: &[u8]) -> Vec<u8> {
    let mut auth = CmdBuilder::new();
    auth.push_u32(RS_PW);
    auth.push_tpm2b(&[]); // nonceCaller
    auth.buf.push(0x01); // sessionAttributes: continueSession
    auth.push_tpm2b(password); // hmac
    auth.buf
}

/// Builds a password auth area with an empty password (for SRK operations).
fn empty_password_auth_area() -> Vec<u8> {
    password_auth_area(&[])
}

/// Builds a password auth area with the seal object auth value.
fn seal_auth_area() -> Vec<u8> {
    password_auth_area(&seal_object_auth())
}

/// Creates a primary SRK in the owner hierarchy.
///
/// Uses the standard RSA-2048 SRK template for maximum compatibility.
fn create_primary_srk(device: &mut TpmDevice) -> Result<u32, SignerError> {
    // Build the inPublic template for RSA-2048 SRK.
    let mut in_public = CmdBuilder::new();
    in_public.push_u16(ALG_RSA); // type = RSA
    in_public.push_u16(ALG_SHA256); // nameAlg
    in_public.push_u32(SRK_OBJECT_ATTRS); // objectAttributes
    in_public.push_tpm2b(&[]); // authPolicy (empty)

    // RSA parameters: symmetric = AES-128-CFB, scheme = null, keyBits = 2048,
    // exponent = 0 (default 65537).
    in_public.push_u16(ALG_AES); // symmetric algorithm
    in_public.push_u16(128); // symmetric keyBits
    in_public.push_u16(ALG_CFB); // symmetric mode
    in_public.push_u16(ALG_NULL); // scheme
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

    // inSensitive (TPM2B_SENSITIVE_CREATE): empty userAuth + empty data
    let mut in_sensitive = CmdBuilder::new();
    in_sensitive.push_tpm2b(&[]); // userAuth
    in_sensitive.push_tpm2b(&[]); // data

    let mut cmd = CmdBuilder::command(ST_SESSIONS, CC_CREATE_PRIMARY);
    cmd.push_u32(RH_OWNER); // primaryHandle = TPM_RH_OWNER
    cmd.push_auth_area(&empty_password_auth_area());
    cmd.push_tpm2b(&in_sensitive.buf); // inSensitive wrapped as TPM2B
    cmd.push_tpm2b(&in_public.buf); // inPublic (TPM2B_PUBLIC)
    cmd.push_tpm2b(&[]); // outsideInfo
    cmd.push_u32(0); // creationPCR (TPML_PCR_SELECTION with count = 0)

    let resp = device.submit_checked(cmd.finalize(), "TPM2_CreatePrimary")?;
    response_handle(&resp, "TPM2_CreatePrimary")
}

/// Creates a Seal object under the given parent handle containing the
/// private key bytes.
///
/// Returns the packed TPM2B_PRIVATE and TPM2B_PUBLIC (see [`pack_sealed_blob`])
/// that can later be loaded and unsealed.
fn create_seal_object(
    device: &mut TpmDevice,
    parent_handle: u32,
    data: &[u8],
) -> Result<Vec<u8>, SignerError> {
    // C1 fix: Set a domain-specific userAuth on the sealed object so that
    // unseal requires providing this auth value. Without this, any process
    // with TPM access + the blob could unseal with an empty password.
    let mut in_sensitive = CmdBuilder::new();
    in_sensitive.push_tpm2b(&seal_object_auth()); // userAuth (domain-specific)
    in_sensitive.push_tpm2b(data); // data to seal

    // inPublic: KEYEDHASH seal object
    let mut in_public = CmdBuilder::new();
    in_public.push_u16(ALG_KEYEDHASH); // type
    in_public.push_u16(ALG_SHA256); // nameAlg
    in_public.push_u32(SEAL_OBJECT_ATTRS); // objectAttributes
    in_public.push_tpm2b(&[]); // authPolicy (empty)
    in_public.push_u16(ALG_NULL); // scheme (seal, not HMAC/XOR)
    in_public.push_tpm2b(&[]); // unique (empty)

    let mut cmd = CmdBuilder::command(ST_SESSIONS, CC_CREATE);
    cmd.push_u32(parent_handle);
    cmd.push_auth_area(&empty_password_auth_area());
    cmd.push_tpm2b(&in_sensitive.buf);
    cmd.push_tpm2b(&in_public.buf);
    cmd.push_tpm2b(&[]); // outsideInfo
    cmd.push_u32(0); // creationPCR (count = 0)

    let resp = device.submit_checked(cmd.finalize(), "TPM2_Create (seal)")?;

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
    Ok(pack_sealed_blob(out_private, out_public))
}

/// Loads a sealed object and unseals it, returning the plaintext data.
fn load_and_unseal(
    device: &mut TpmDevice,
    parent_handle: u32,
    sealed_blob: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let (private_bytes, public_bytes) = unpack_sealed_blob(sealed_blob)?;

    // TPM2_Load: load the sealed object under the parent.
    let mut cmd = CmdBuilder::command(ST_SESSIONS, CC_LOAD);
    cmd.push_u32(parent_handle);
    cmd.push_auth_area(&empty_password_auth_area());
    cmd.push_tpm2b(private_bytes);
    cmd.push_tpm2b(public_bytes);

    let resp = device.submit_checked(cmd.finalize(), "TPM2_Load")?;
    let loaded_handle = response_handle(&resp, "TPM2_Load")?;

    // TPM2_Unseal: retrieve the sealed data.
    // C1 fix: Use the domain-specific auth for unseal (matches the auth
    // set during create_seal_object).
    let mut unseal_cmd = CmdBuilder::command(ST_SESSIONS, CC_UNSEAL);
    unseal_cmd.push_u32(loaded_handle);
    unseal_cmd.push_auth_area(&seal_auth_area());

    // Wrap unseal in a closure so loaded_handle is always flushed,
    // even if submit_command fails at device level.
    let unseal_result = (|| -> Result<Vec<u8>, SignerError> {
        let resp = device.submit_checked(unseal_cmd.finalize(), "TPM2_Unseal")?;
        // Response: header (10) + parameterSize (4) + TPM2B_SENSITIVE_DATA
        let mut reader = RespReader::new(&resp);
        reader.skip(10)?; // header
        let _param_size = reader.read_u32()?;
        Ok(reader.read_tpm2b()?.to_vec())
    })();

    // Always flush loaded_handle regardless of unseal outcome.
    if let Err(err) = flush_context(device, loaded_handle) {
        eprintln!("==> warning: TPM flush loaded handle after unseal failed: {err}");
    }

    unseal_result
}

/// Flushes a transient TPM handle.
fn flush_context(device: &mut TpmDevice, flush_handle: u32) -> Result<(), SignerError> {
    let mut cmd = CmdBuilder::command(ST_NO_SESSIONS, CC_FLUSH_CONTEXT);
    cmd.push_u32(flush_handle);
    device.submit_checked(cmd.finalize(), "TPM2_FlushContext")?;
    Ok(())
}
