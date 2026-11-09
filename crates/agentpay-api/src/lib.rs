//! The AgentPay daemon API: the documented, versioned contract between the
//! AgentPay daemon and every client (the bundled CLIs and TUI, and third-party
//! integrations).
//!
//! This crate is the single source of truth for what travels over the daemon
//! socket. It has no I/O: transports (`agentpay-transport`) and the daemon
//! (`agentpay-signerd`) depend on it. The JSON Schema in `docs/api/schema.json` and
//! the TypeScript types in `client/src/generated/` are generated from these
//! types by `cargo xtask gen-api`, and the prose specification lives in
//! `docs/daemon-api.md`.
//!
//! # At a glance
//!
//! - **Transport:** a local Unix domain socket per service: the signer
//!   daemon's is owned by root (`/Library/AgentPay/run/daemon.sock` on macOS,
//!   `/run/agentpay/daemon.sock` on Linux), the payments service's by its
//!   service account. One request and one response per connection, each a
//!   length-prefixed JSON frame ([`envelope`]).
//! - **Two services:** the root signer daemon ([`rpc`]) and the unprivileged
//!   payments service ([`payments`]), with the same framing and versioning.
//! - **Requests:** [`DaemonRpcRequest`], `{"method": "...", "params": {...}}`
//!   ([`PaymentsRpcRequest`] for the payments service).
//! - **Responses:** [`DaemonRpcResponse`] on success, [`WireDaemonError`] on
//!   failure ([`PaymentsRpcResponse`] / [`WirePaymentsError`] for the payments service).
//! - **Handshake:** `Hello` returns [`HelloResponse`] with the [`API_VERSION`]
//!   and capabilities ([`version`]).
//! - **Authorization:** kernel-verified peer uid allowlists, agent bearer
//!   tokens, and admin authority from a root peer or a Secure Enclave-backed
//!   lease ([`auth`]).
//! - **Encodings:** amounts are decimal strings, timestamps are 9-element
//!   arrays ([`types`]).
//!
//! # Example
//!
//! ```
//! use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse, HelloResponse, WireRequest};
//!
//! let request = DaemonRpcRequest::Hello;
//! let envelope = WireRequest {
//!     body_json: serde_json::to_string(&request).unwrap(),
//! };
//! assert_eq!(
//!     serde_json::to_string(&envelope).unwrap(),
//!     r#"{"body_json":"{\"method\":\"Hello\"}"}"#
//! );
//!
//! let response: DaemonRpcResponse = serde_json::from_str(
//!     r#"{"type":"Hello","data":{"api_version":"1.0.0","daemon_version":"1.0.0","capabilities":["Hello"]}}"#,
//! )
//! .unwrap();
//! let DaemonRpcResponse::Hello(hello) = response else { unreachable!() };
//! assert!(agentpay_api::ApiVersion::CURRENT
//!     .is_compatible_with(&agentpay_api::ApiVersion::parse(&hello.api_version).unwrap()));
//! assert!(hello.supports("Hello"));
//! # let _ = HelloResponse::for_daemon("1.0.0");
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod auth;
pub mod codegen;
pub mod envelope;
pub mod error;
pub mod payments;
pub mod rpc;
pub mod types;
pub mod version;

pub use auth::{AccessLevel, AgentAuth};
pub use envelope::{WireRequest, WireResponse, MAX_WIRE_BODY_BYTES};
pub use error::WireDaemonError;
pub use payments::{PaymentsRpcRequest, PaymentsRpcResponse, WirePaymentsError};
pub use rpc::{DaemonRpcRequest, DaemonRpcResponse};
pub use types::{AgentIdentity, AgentPolicyInfo, AgentPolicySummary, PolicySummary};
pub use version::{ApiVersion, HelloResponse, API_VERSION};

#[cfg(test)]
mod tests;
