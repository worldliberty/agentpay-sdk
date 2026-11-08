//! `agentpay-daemon`: long-running local daemon process for policy-gated signing.
//!
//! Startup sequence:
//!
//! 1. Parse CLI flags/environment ([`config::args`]) and read the state secret
//!    (and, for a one-time migration, the legacy vault password) from stdin
//!    ([`config::secret`]).
//! 2. Resolve and harden the state file and socket paths ([`config::paths`]),
//!    take the exclusive state-file lock ([`state_lock`]), and build the admin
//!    and agent peer-euid allowlists ([`config::peers`]).
//! 3. Select the signer backend and start the daemon ([`runtime`]), then serve
//!    RPCs over the unix socket until a shutdown signal arrives ([`server`]).

mod config;
mod runtime;
mod server;
mod state_lock;
#[cfg(test)]
mod test_support;

use anyhow::Result;
use clap::Parser;

use crate::config::args::Cli;
use crate::config::secret::read_state_unlock;
use crate::runtime::{run_cli_with_runtime, RealDaemonRuntime};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let unlock = read_state_unlock(cli.migrate_from_password_stdin)?;
    let runtime = RealDaemonRuntime;
    run_cli_with_runtime(cli, unlock, &runtime).await
}
