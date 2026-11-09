//! Unix-domain socket transport for daemon RPC calls.
//!
//! This transport is intended for local long-running daemon deployments where
//! CLIs/SDK clients communicate with a separate process over a filesystem
//! socket path.
//!
//! Module map:
//!
//! - `client`: [`UnixDaemonClient`], the `KeyManagerDaemonApi` adapter that
//!   performs one RPC per connection.
//! - `server`: [`UnixDaemonServer`], the bounded accept loop and per-connection
//!   request handling for any [`RpcService`].
//! - `service`: the [`RpcService`] trait a server hosts, and [`SignerdService`]
//!   for the signer daemon (the payments service implements its own).
//! - `wire`: length-prefixed JSON frame I/O for the envelopes defined in
//!   `agentpay_api::envelope`.
//! - `peer_auth`: peer-euid checks and allowlist-derived socket permissions;
//!   which allowlist governs a request comes from
//!   `agentpay_api::DaemonRpcRequest::access_level`.
//! - `socket_trust`: ownership/permission/symlink checks for socket paths and
//!   their parent directories.

#![forbid(unsafe_code)]

mod client;
mod error;
mod peer_auth;
mod server;
mod service;
mod socket_trust;
mod wire;

pub use client::UnixDaemonClient;
pub use error::UnixTransportError;
pub use server::UnixDaemonServer;
pub use service::{RpcService, SignerdService};
pub use socket_trust::{
    assert_root_owned_daemon_socket_path, assert_service_socket_path,
    assert_trusted_daemon_socket_path,
};

#[cfg(test)]
mod tests;
