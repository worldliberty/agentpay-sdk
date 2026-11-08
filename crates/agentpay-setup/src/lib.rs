//! Privileged installer for the AgentPay daemon.
//!
//! `agentpay-setup` runs as root (the AgentPay client invokes it through `sudo`) and owns
//! everything that needs root on the host:
//! - copying the daemon and helper binaries into a root-owned prefix;
//! - generating the daemon machine secret and storing it root-only;
//! - migrating installs that still use a vault password;
//! - creating the unprivileged payments service account;
//! - writing, starting and removing the launchd/systemd services: the root signer daemon and
//!   the payments service (`agentpay-paymentd`), which runs as that account.
//!
//! It never prompts and never accepts secrets in arguments or the environment. All OS effects
//! go through [`system::System`] so the step logic is unit-tested against an in-memory fake.

pub mod cli;
pub mod install;
pub mod layout;
pub mod manifest;
pub mod migrate;
pub mod payments;
pub mod report;
pub mod secret;
pub mod service;
pub mod status;
pub mod system;
pub mod trust;
pub mod uninstall;
pub mod users;

#[cfg(test)]
mod tests;
