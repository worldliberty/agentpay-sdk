//! Command-line arguments and their resolved [`Options`].
//!
//! `agentpay-setup` passes every path and uid explicitly. Without flags the
//! service uses a development layout under `$AGENTPAY_HOME` (or
//! `~/.agentpay`), next to a signer daemon run by the same user.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Parser;

/// Per-frame I/O timeout for calls to the signer daemon.
const SIGNER_TIMEOUT: Duration = Duration::from_secs(10);

/// `agentpay-paymentd` command line.
#[derive(Debug, Clone, Parser)]
#[command(name = "agentpay-paymentd")]
#[command(about = "Unprivileged AgentPay payments service", version)]
pub struct Cli {
    /// Unix socket to serve (default: $AGENTPAY_HOME/paymentd.sock).
    #[arg(long, env = "AGENTPAY_PAYMENTD_SOCKET", value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Private state directory holding config.json (default: $AGENTPAY_HOME/paymentd).
    #[arg(long, env = "AGENTPAY_PAYMENTD_STATE_DIR", value_name = "PATH")]
    pub state_dir: Option<PathBuf>,
    /// The signer daemon's socket (default: $AGENTPAY_HOME/daemon.sock).
    #[arg(long, env = "AGENTPAY_SIGNER_SOCKET", value_name = "PATH")]
    pub signer_socket: Option<PathBuf>,
    /// Effective uid the signer daemon runs as: 0 in production (the socket
    /// must then be root-owned); this user's uid for a development signer.
    #[arg(
        long,
        env = "AGENTPAY_SIGNER_EUID",
        value_name = "UID",
        default_value_t = 0
    )]
    pub signer_euid: u32,
    /// Uids allowed to connect (default: only this user).
    #[arg(
        long = "allow-client-euid",
        env = "AGENTPAY_PAYMENTD_ALLOW_CLIENT_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..
    )]
    pub allow_client_euid: Vec<u32>,
    /// Log filter, for example `info` or `agentpay_paymentd=debug`.
    #[arg(
        long,
        env = "AGENTPAY_PAYMENTD_LOG",
        value_name = "FILTER",
        default_value = "info"
    )]
    pub log: String,
}

/// Fully resolved startup options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Socket to serve.
    pub socket: PathBuf,
    /// Private state directory.
    pub state_dir: PathBuf,
    /// Signer daemon socket.
    pub signer_socket: PathBuf,
    /// Signer daemon euid.
    pub signer_euid: u32,
    /// Peer uids allowed to connect.
    pub allowed_client_euids: BTreeSet<u32>,
    /// Per-frame I/O timeout for signer calls.
    pub signer_timeout: Duration,
}

impl Cli {
    /// Resolves defaults; `euid` is this process's effective uid.
    pub fn resolve(&self, euid: u32) -> Result<Options> {
        let home = || agentpay_home();
        let socket = match &self.socket {
            Some(path) => path.clone(),
            None => home()?.join("paymentd.sock"),
        };
        let state_dir = match &self.state_dir {
            Some(path) => path.clone(),
            None => home()?.join("paymentd"),
        };
        let signer_socket = match &self.signer_socket {
            Some(path) => path.clone(),
            None => home()?.join("daemon.sock"),
        };
        let mut allowed_client_euids: BTreeSet<u32> =
            self.allow_client_euid.iter().copied().collect();
        if allowed_client_euids.is_empty() {
            allowed_client_euids.insert(euid);
        }
        Ok(Options {
            socket,
            state_dir,
            signer_socket,
            signer_euid: self.signer_euid,
            allowed_client_euids,
            signer_timeout: SIGNER_TIMEOUT,
        })
    }
}

fn agentpay_home() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGENTPAY_HOME") {
        if path.is_empty() {
            bail!("AGENTPAY_HOME must not be empty");
        }
        return Ok(PathBuf::from(path));
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => Ok(PathBuf::from(home).join(".agentpay")),
        _ => bail!("HOME is not set; pass --socket, --state-dir, and --signer-socket"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_flags_win_and_clients_default_to_this_user() {
        let cli = Cli::try_parse_from([
            "agentpay-paymentd",
            "--socket",
            "/run/agentpay-paymentd/paymentd.sock",
            "--state-dir",
            "/var/lib/agentpay-paymentd",
            "--signer-socket",
            "/run/agentpay/daemon.sock",
        ])
        .expect("parse");
        let options = cli.resolve(301).expect("resolve");
        assert_eq!(
            options.socket,
            PathBuf::from("/run/agentpay-paymentd/paymentd.sock")
        );
        assert_eq!(
            options.state_dir,
            PathBuf::from("/var/lib/agentpay-paymentd")
        );
        assert_eq!(
            options.signer_socket,
            PathBuf::from("/run/agentpay/daemon.sock")
        );
        assert_eq!(options.signer_euid, 0);
        assert_eq!(options.allowed_client_euids, BTreeSet::from([301]));
    }

    #[test]
    fn client_allowlist_accepts_a_comma_separated_list() {
        let cli = Cli::try_parse_from([
            "agentpay-paymentd",
            "--socket",
            "/s",
            "--state-dir",
            "/d",
            "--signer-socket",
            "/t",
            "--allow-client-euid",
            "501,502",
            "--signer-euid",
            "501",
        ])
        .expect("parse");
        let options = cli.resolve(301).expect("resolve");
        assert_eq!(options.allowed_client_euids, BTreeSet::from([501, 502]));
        assert_eq!(options.signer_euid, 501);
    }

    #[test]
    fn secrets_have_no_flags() {
        for flag in ["--agent-auth-token", "--token", "--state-secret"] {
            assert!(Cli::try_parse_from(["agentpay-paymentd", flag, "x"]).is_err());
        }
    }
}
