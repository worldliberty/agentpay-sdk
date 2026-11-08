//! Method families. Each module handles the methods of one family and is
//! reached from one match arm in [`crate::dispatch`].
//!
//! A handler has the signature
//!
//! ```ignore
//! pub async fn handle(
//!     state: &AppState,
//!     agent: &AuthenticatedAgent,
//!     request: PaymentsRpcRequest,
//! ) -> Result<PaymentsRpcResponse, PaymentsError>
//! ```
//!
//! and matches only its own variants (anything else is an internal error).
//! The caller is already authenticated; sign through
//! `agent.signer(state.signer.as_ref())`.

pub mod activity;
pub mod config;
pub(crate) mod eip3009;
pub mod evm;
pub(crate) mod http;
pub mod mpp;
pub(crate) mod payer;
pub mod proxy;
pub mod solana;
pub mod telemetry;
pub mod wallet;
pub mod x402;
