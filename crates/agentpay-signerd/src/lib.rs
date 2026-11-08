//! Core daemon authorization and signing pipeline.
//!
//! This crate is transport-agnostic: CLIs, SDKs, and the Unix-socket transport call the
//! same [`KeyManagerDaemonApi`] trait.
//!
//! # Layout
//!
//! - [`api`](KeyManagerDaemonApi): the transport-neutral daemon API trait.
//! - `daemon`: [`InMemoryDaemon`], the reference implementation, split by concern
//!   (authentication, policies, keys, signing, nonces, manual approvals, recovery,
//!   Tempo channels, and state persistence).
//! - `rpc`: [`InMemoryDaemon::handle_rpc`], which dispatches the wire requests
//!   defined in `agentpay-api` (`DaemonRpcRequest` / `DaemonRpcResponse`).
//! - `wire_error`: conversions between [`DaemonError`] and its serializable
//!   mirror `agentpay_api::WireDaemonError`.
//! - `backup`: encrypted offline wallet backups (scrypt + AES-256-GCM, format v2).
//! - `persistence`: the encrypted on-disk state store ([`PersistentStoreConfig`]),
//!   keyed by the machine [`StateSecret`] (with one-time migration from legacy
//!   vault-password files via [`LegacyStatePassword`]).
//! - `context`: [`RequestContext`], the transport-verified caller identity used
//!   for admin authorization (root peer or admin lease).
//! - `config` / `error`: [`DaemonConfig`] and [`DaemonError`].

#![forbid(unsafe_code)]

mod api;
mod backup;
mod config;
mod context;
mod daemon;
mod error;
mod persistence;
mod rpc;
mod wire_error;

pub use agentpay_api::{AgentAuth, AgentIdentity, PolicySummary};
pub use api::KeyManagerDaemonApi;
pub use config::DaemonConfig;
pub use context::RequestContext;
pub use daemon::{InMemoryDaemon, MAX_NONCE_SKIP};
pub use error::DaemonError;
pub use persistence::{LegacyStatePassword, PersistentStoreConfig, StateSecret, STATE_SECRET_LEN};
