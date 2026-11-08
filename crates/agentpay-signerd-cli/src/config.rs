//! Daemon startup configuration: command-line arguments, state-secret input,
//! filesystem path resolution, and peer-euid allowlists.

pub(crate) mod args;
pub(crate) mod paths;
pub(crate) mod peers;
pub(crate) mod secret;
