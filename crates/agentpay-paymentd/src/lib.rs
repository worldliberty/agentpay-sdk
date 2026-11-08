//! `agentpay-paymentd`: the unprivileged AgentPay payments service.
//!
//! It runs as a dedicated service account (`_agentpay` on macOS, `agentpay` on
//! Linux, created by `agentpay-setup`), refuses to run as root, and does all
//! network I/O: chain RPC, x402, MPP, and funding. It holds no keys and no
//! credentials: every signature comes from the root signer daemon, requested
//! as the calling agent and checked against that agent's policies. The wire
//! contract is `agentpay_api::payments`; `docs/daemon-api.md` documents it.
//!
//! # Module map
//!
//! | Module | Role |
//! |---|---|
//! | [`runtime`] | startup: root refusal, state directory, instance lock, serve |
//! | [`cli`] | flags and resolved [`cli::Options`] |
//! | [`client`] | [`client::PaymentsClient`], a Rust client for the payments socket |
//! | [`server`] | [`server::PaymentsService`] on the shared Unix transport; logging per request |
//! | [`dispatch`] | authenticates the caller, then one match arm per method family |
//! | [`auth`] | delegated authentication ([`auth::AuthenticatedAgent`]) |
//! | [`signer`] | [`signer::SignerClient`] seam and [`signer::AgentSigner`] operations |
//! | [`config`] | configuration defaults, validation, and storage |
//! | [`chains`] | chain provider registry (EVM, Solana) |
//! | [`features`] | method family handlers |
//! | [`proxy`] | the local paying proxy (`ProxyStart`) |
//! | [`state`] | [`state::AppState`] shared by handlers |
//! | [`telemetry`] | anonymous opt-out analytics and crash reports |
//! | [`error`] | [`error::PaymentsError`] and its wire form |
//!
//! # Adding a method family
//!
//! See "Adding a paymentd method" in `docs/daemon-api.md`: define the wire
//! types and fixtures in `agentpay-api`, add a `features/<family>.rs` handler,
//! add one arm in [`dispatch`], and test it with the signer doubles.

#![forbid(unsafe_code)]

pub mod auth;
pub mod chains;
pub mod cli;
pub mod client;
pub mod config;
pub mod dispatch;
pub mod error;
pub mod features;
pub mod logging;
pub mod proxy;
pub mod runtime;
pub mod server;
pub mod signer;
pub mod state;
pub mod telemetry;

#[cfg(test)]
mod test_support;
