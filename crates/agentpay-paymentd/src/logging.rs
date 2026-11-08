//! Structured logging to stderr (launchd log file or the systemd journal).
//!
//! What may be logged follows the telemetry privacy rules: method names,
//! outcomes, error kinds, timings, peer uids, and socket paths. Never agent
//! tokens, private keys, request bodies, wallet or recipient addresses, or
//! RPC URLs (they can embed API keys). Handlers log through `tracing` and keep
//! such values out of fields and messages.

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

/// Installs the global subscriber with `filter` (for example `info`).
pub fn init(filter: &str) -> Result<()> {
    let filter =
        EnvFilter::try_new(filter).with_context(|| format!("invalid log filter '{filter}'"))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .try_init()
        .map_err(|err| anyhow::anyhow!("failed to install the logger: {err}"))
}
