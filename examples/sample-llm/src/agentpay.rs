//! Talking to AgentPay the way a third-party tool should: through the
//! `agentpay` CLI and its `--json` output, decoded with `agentpay-api`'s own
//! types (the CLI prints the wire types unchanged).
//!
//! The CLI finds the agent's credentials in the OS secret store, so this tool
//! never sees the agent token. The only secret it holds is the paying proxy's
//! URL, kept in memory (`Zeroizing`) and dropped when the proxy stops.

use std::path::PathBuf;
use std::process::Command;

use agentpay_api::payments::{ProxyStartResult, ProxyStatusResult, WalletSummaryResult};
use serde::de::DeserializeOwned;
use serde::Deserialize;

/// An error `agentpay` reported, with its own next step.
#[derive(Debug)]
pub struct AgentPayError {
    pub message: String,
    pub next: Option<String>,
}

impl std::fmt::Display for AgentPayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(next) = &self.next {
            write!(f, "\nNext: {next}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AgentPayError {}

#[derive(Deserialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Deserialize)]
struct ErrorDetail {
    message: String,
    next_action: Option<String>,
}

/// The `agentpay` program: `AGENTPAY_BIN`, else the installed one, else
/// `agentpay` on `PATH`.
pub fn program() -> PathBuf {
    if let Some(path) = std::env::var_os("AGENTPAY_BIN") {
        return PathBuf::from(path);
    }
    let installed = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".agentpay/bin/agentpay"))
        .filter(|path| path.exists());
    installed.unwrap_or_else(|| PathBuf::from("agentpay"))
}

/// Runs `agentpay <args> --json` and decodes its output.
pub fn agentpay<T: DeserializeOwned>(args: &[&str]) -> Result<T, AgentPayError> {
    let output = Command::new(program())
        .args(args)
        .arg("--json")
        .output()
        .map_err(|error| AgentPayError {
            message: format!("could not run agentpay: {error}"),
            next: Some("Install AgentPay, or set AGENTPAY_BIN to the agentpay program.".into()),
        })?;
    if let Ok(ErrorBody { error }) = serde_json::from_slice::<ErrorBody>(&output.stdout) {
        return Err(AgentPayError {
            message: error.message,
            next: error.next_action,
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|error| AgentPayError {
        message: format!(
            "agentpay {} answered unexpectedly ({error}): {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        next: None,
    })
}

/// `agentpay wallet`: the agent's wallet and its balances.
pub fn wallet() -> Result<WalletSummaryResult, AgentPayError> {
    agentpay(&["wallet"])
}

/// `agentpay proxy status`.
pub fn proxy_status() -> Result<ProxyStatusResult, AgentPayError> {
    agentpay(&["proxy", "status"])
}

/// `agentpay proxy stop`.
pub fn proxy_stop() -> Result<ProxyStatusResult, AgentPayError> {
    agentpay(&["proxy", "stop"])
}

/// What the paying proxy may do for this tool.
pub struct ProxyTerms<'a> {
    /// The only host it serves.
    pub host: &'a str,
    /// The token MPP sessions are paid in.
    pub token: &'a str,
    /// Deposit of a new session channel (base units).
    pub deposit: u128,
    /// Cap on a channel's deposit and on any single payment (base units).
    pub max_spend: u128,
}

/// `agentpay proxy start`. The result's `proxy_url` is a secret: it can spend
/// within the agent's limits until the proxy stops.
pub fn proxy_start(terms: &ProxyTerms<'_>) -> Result<ProxyStartResult, AgentPayError> {
    let deposit = terms.deposit.to_string();
    let max_spend = terms.max_spend.to_string();
    agentpay(&[
        "proxy",
        "start",
        "--allow-host",
        terms.host,
        "--currency",
        terms.token,
        "--deposit",
        &deposit,
        "--max-deposit",
        &max_spend,
        "--max-amount",
        &max_spend,
    ])
}
