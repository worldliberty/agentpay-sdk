//! Agent-side SDK for daemon-mediated token operations.
//!
//! - [`AgentOperations`]: the high-level signing surface (ERC-20, native, Solana,
//!   EIP-3009, Tempo sessions, EIP-712, and raw broadcast transactions).
//! - [`AgentSdk`]: the default implementation, generic over any
//!   `KeyManagerDaemonApi` (in-process daemon or a transport client).
//! - [`AgentSdkError`]: errors surfaced by SDK operations.

#![forbid(unsafe_code)]

mod error;
mod operations;
mod sdk;

pub use error::AgentSdkError;
pub use operations::AgentOperations;
pub use sdk::AgentSdk;

#[cfg(test)]
mod tests;
