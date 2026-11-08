//! Signer backends for vault keys.
//!
//! The daemon depends on [`VaultSignerBackend`] so the software signer and the
//! Linux TPM seal/unseal signer can be swapped without changing policy logic.

#![forbid(unsafe_code)]

mod backend;
#[cfg(target_os = "linux")]
mod linux_tpm;
mod software;

pub use backend::{BackendKind, KeyCreateRequest, SignerError, VaultSignerBackend};
#[cfg(target_os = "linux")]
pub use linux_tpm::{LinuxTpmKeyBlob, LinuxTpmSignerBackend};
pub use software::SoftwareSignerBackend;

#[cfg(test)]
mod tests;
