//! paymentd's configuration: chains, tokens, RPC endpoints, and the default
//! network and asset (`bsc` + `USD1`).
//!
//! The wire types live in `agentpay_api::payments` (they are part of the
//! public contract); this module owns their built-in values ([`builtin`]),
//! validation ([`validate`]), and storage ([`ConfigStore`]).
//!
//! **Ownership.** The configuration belongs to the payments service, not to the
//! client user: it lives in paymentd's state directory, writable only by the
//! service account, and clients change it through `SetConfig`. A user process
//! therefore cannot redirect another agent's RPC traffic by editing a file in
//! its home directory.

pub mod builtin;
mod store;
mod validate;

pub use builtin::{
    add_missing_builtin_deployments, add_missing_builtin_networks, builtin_chain, default_config,
    seeded_deployment_keys, upgrade_retired_defaults, upgrade_retired_deployments, BuiltinChain,
    BUILTIN_CHAINS, BUILTIN_TOKENS, NEW_SEEDED_DEPLOYMENTS, ORIGINAL_SEEDED_CHAINS,
    RETIRED_DEFAULT_DEPLOYMENTS, RETIRED_DEFAULT_RPC_URLS, SEEDED_CHAINS,
};
pub(crate) use store::{read_trusted, write_atomically};
pub use store::{ConfigStore, CONFIG_FILE_NAME, CONFIG_SCHEMA};
pub use validate::{check_rpc_url, validate, MAX_DECIMALS, MAX_ENTRIES, MAX_FALLBACK_RPC_URLS};

#[cfg(test)]
mod tests;
