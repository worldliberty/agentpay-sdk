//! API versioning, the `Hello` handshake payload, and capability names.
//!
//! # Compatibility policy
//!
//! [`API_VERSION`] follows [Semantic Versioning](https://semver.org) and
//! versions the wire contract only, independently of the daemon release.
//! `1.0.0` is the first published version; these rules apply to every change
//! after it (`1.1.0` added the payments method `AddToken`):
//!
//! - **Patch** (`1.0.x`): documentation or validation fixes with no wire change.
//! - **Minor** (`1.x.0`): additive changes only. New methods, new response
//!   variants for new methods, new optional request fields, new error kinds,
//!   new capabilities. A client built for `1.2` works unchanged against a
//!   `1.5` daemon.
//! - **Major** (`x.0.0`): anything else (removed or renamed methods or
//!   fields, changed encodings, changed semantics).
//!
//! A client is compatible with a daemon when both use the same major version
//! (see [`ApiVersion::is_compatible_with`]). Within a major version, clients
//! detect optional features through [`HelloResponse::capabilities`] rather than
//! by comparing minor versions.
//!
//! # Deprecation policy
//!
//! A method or field slated for removal is first marked deprecated in its
//! rustdoc and in `docs/daemon-api.md` (with the replacement), keeps working
//! for at least one further minor release, and is removed only in the next
//! major version. Its capability string keeps being advertised for as long as
//! it is served.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::payments::PaymentsRpcRequest;
use crate::rpc::DaemonRpcRequest;

/// The wire-contract version implemented by this crate (semver).
pub const API_VERSION: &str = "1.1.0";

/// Capability: admin challenges use the `agentpay-admin-challenge-v1` message
/// format documented in [`crate::auth`].
pub const CAPABILITY_ADMIN_CHALLENGE_V1: &str = "admin_challenge.v1";

/// Capability: every `u128` amount, count, and limit on the wire (including
/// inside `PolicyError`) is a decimal string.
pub const CAPABILITY_DECIMAL_STRING_AMOUNTS: &str = "amounts.decimal_string";

/// Feature capabilities this version of the contract defines, in addition to
/// one capability per RPC method name.
pub const FEATURE_CAPABILITIES: &[&str] = &[
    CAPABILITY_ADMIN_CHALLENGE_V1,
    CAPABILITY_DECIMAL_STRING_AMOUNTS,
];

/// Every capability a daemon implementing exactly this crate advertises:
/// each method name from [`DaemonRpcRequest::METHOD_NAMES`] followed by
/// [`FEATURE_CAPABILITIES`].
#[must_use]
pub fn daemon_capabilities() -> Vec<String> {
    DaemonRpcRequest::METHOD_NAMES
        .iter()
        .chain(FEATURE_CAPABILITIES)
        .map(|capability| (*capability).to_string())
        .collect()
}

/// Capability: `MppFetch` and the paying proxy pay MPP `evm` and `arbitrum`
/// `charge` challenges (`draft-evm-charge-00`) on configured EVM networks.
pub const CAPABILITY_MPP_EVM_CHARGE: &str = "mpp.evm_charge";

/// Capability: `MppFetch` and the paying proxy pay MPP `solana` `charge`
/// challenges (`draft-solana-charge-00`, pull mode) on configured Solana
/// clusters.
pub const CAPABILITY_MPP_SOLANA_CHARGE: &str = "mpp.solana_charge";

/// Feature capabilities the payments service advertises in addition to one
/// capability per payments method name.
pub const PAYMENTS_FEATURE_CAPABILITIES: &[&str] = &[
    CAPABILITY_DECIMAL_STRING_AMOUNTS,
    CAPABILITY_MPP_EVM_CHARGE,
    CAPABILITY_MPP_SOLANA_CHARGE,
];

/// Every capability a payments service implementing exactly this crate
/// advertises: each method name from [`PaymentsRpcRequest::METHOD_NAMES`]
/// followed by [`PAYMENTS_FEATURE_CAPABILITIES`].
#[must_use]
pub fn payments_capabilities() -> Vec<String> {
    PaymentsRpcRequest::METHOD_NAMES
        .iter()
        .chain(PAYMENTS_FEATURE_CAPABILITIES)
        .map(|capability| (*capability).to_string())
        .collect()
}

/// Service identity and contract version, returned by the `Hello` handshake of
/// both the signer daemon and the payments service.
///
/// JSON:
/// ```json
/// {"api_version": "1.0.0", "daemon_version": "1.0.0", "capabilities": ["Hello", "SignForAgent", "admin_challenge.v1"]}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
pub struct HelloResponse {
    /// Wire-contract version the daemon implements (semver, for example `"1.0.0"`).
    pub api_version: String,
    /// Daemon release version (semver of the daemon build, for example
    /// `"1.0.0"`). Informational; compatibility is decided by `api_version`.
    pub daemon_version: String,
    /// Supported capabilities: every RPC method name the daemon serves (for
    /// example `"SignForAgent"`) plus dotted feature names (for example
    /// `"admin_challenge.v1"`). Unknown entries must be ignored.
    pub capabilities: Vec<String>,
}

impl HelloResponse {
    /// Builds the handshake payload for a daemon whose release version is `daemon_version`.
    #[must_use]
    pub fn for_daemon(daemon_version: &str) -> Self {
        Self {
            api_version: API_VERSION.to_string(),
            daemon_version: daemon_version.to_string(),
            capabilities: daemon_capabilities(),
        }
    }

    /// Builds the handshake payload for a payments service whose release
    /// version is `service_version`.
    #[must_use]
    pub fn for_payments_service(service_version: &str) -> Self {
        Self {
            api_version: API_VERSION.to_string(),
            daemon_version: service_version.to_string(),
            capabilities: payments_capabilities(),
        }
    }

    /// Returns whether the daemon advertises `capability`.
    #[must_use]
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|value| value == capability)
    }
}

/// A parsed `major.minor.patch` API version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion {
    /// Incremented for breaking wire changes.
    pub major: u64,
    /// Incremented for additive wire changes.
    pub minor: u64,
    /// Incremented for fixes without wire changes.
    pub patch: u64,
}

impl ApiVersion {
    /// The version implemented by this crate ([`API_VERSION`]).
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 1,
        patch: 0,
    };

    /// Parses `major.minor.patch`; pre-release and build suffixes are rejected.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.trim().split('.');
        let mut next = || parts.next()?.parse::<u64>().ok();
        let version = Self {
            major: next()?,
            minor: next()?,
            patch: next()?,
        };
        parts.next().is_none().then_some(version)
    }

    /// Returns whether a client speaking `self` can talk to a daemon speaking
    /// `daemon`: true exactly when the major versions match.
    #[must_use]
    pub fn is_compatible_with(&self, daemon: &Self) -> bool {
        self.major == daemon.major
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
