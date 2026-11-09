//! Command-line arguments and environment variables accepted by `agentpay-daemon`.

use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

/// Signer backend used for daemon key creation and signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SignerBackendKind {
    Software,
    #[cfg(target_os = "linux")]
    Tpm,
}

#[derive(Debug, Parser)]
#[command(name = "agentpay-daemon")]
#[command(about = "Long-running local daemon process for policy-gated signing")]
#[command(group(
    ArgGroup::new("state_unlock")
        .required(true)
        .args(["state_secret_stdin", "migrate_from_password_stdin"])
))]
pub(crate) struct Cli {
    #[arg(
        long,
        default_value_t = false,
        help = "Read the 32-byte state secret from stdin as 64 hex characters"
    )]
    pub(crate) state_secret_stdin: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Migrate a legacy vault-password state file: stdin is the legacy vault password, a newline, then the hex state secret"
    )]
    pub(crate) migrate_from_password_stdin: bool,
    #[arg(
        long,
        env = "AGENTPAY_STATE_FILE",
        value_name = "PATH",
        help = "Encrypted persistent daemon state file path (default: $AGENTPAY_HOME/daemon-state.enc or ~/.agentpay/daemon-state.enc)"
    )]
    pub(crate) state_file: Option<PathBuf>,
    #[arg(
        long,
        env = "AGENTPAY_DAEMON_SOCKET",
        value_name = "PATH",
        help = "Unix socket path for daemon RPC (default: $AGENTPAY_HOME/daemon.sock or ~/.agentpay/daemon.sock)"
    )]
    pub(crate) daemon_socket: Option<PathBuf>,
    #[arg(
        long,
        env = "AGENTPAY_SIGNER_BACKEND",
        value_enum,
        default_value_t = SignerBackendKind::Software,
        value_name = "BACKEND",
        help = "Signer backend for daemon key creation and signing"
    )]
    pub(crate) signer_backend: SignerBackendKind,
    #[cfg(target_os = "linux")]
    #[arg(
        long,
        env = "AGENTPAY_TPM_DEVICE",
        default_value = "/dev/tpmrm0",
        value_name = "PATH",
        help = "TPM device path for Linux TPM signer backend"
    )]
    pub(crate) tpm_device: PathBuf,
    #[arg(
        long = "allow-admin-euid",
        env = "AGENTPAY_ALLOW_ADMIN_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..,
        help = "Additional non-root admin client euid(s) allowed to connect for privileged RPCs. Root (0) is always allowed."
    )]
    pub(crate) allow_admin_euid: Vec<u32>,
    #[arg(
        long = "allow-agent-euid",
        env = "AGENTPAY_ALLOW_AGENT_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..,
        help = "Additional non-root agent client euid(s) allowed to connect for signing and nonce RPCs. Root (0) is always allowed."
    )]
    pub(crate) allow_agent_euid: Vec<u32>,
    #[arg(
        long = "allow-client-euid",
        env = "AGENTPAY_ALLOW_CLIENT_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..,
        help = "Legacy compatibility alias that grants the same non-root client euid(s) both admin and agent access. Root (0) is always allowed."
    )]
    pub(crate) allow_client_euid: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, SignerBackendKind};

    const SECRET_FLAG: &str = "--state-secret-stdin";

    #[test]
    fn cli_rejects_inline_secrets_and_retired_password_flags() {
        for retired in [
            vec!["--vault-password", "vault-secret"],
            vec!["--vault-password-stdin"],
            vec!["--non-interactive"],
            vec!["--state-secret", "00"],
        ] {
            let mut args = vec!["agentpay-daemon", SECRET_FLAG];
            args.extend(retired.iter().copied());
            let err = Cli::try_parse_from(args).expect_err("must reject");
            assert!(err.to_string().contains(retired[0]));
        }
    }

    #[test]
    fn cli_requires_exactly_one_state_unlock_source() {
        assert!(Cli::try_parse_from(["agentpay-daemon"]).is_err());
        assert!(Cli::try_parse_from([
            "agentpay-daemon",
            SECRET_FLAG,
            "--migrate-from-password-stdin"
        ])
        .is_err());
        let cli = Cli::try_parse_from(["agentpay-daemon", "--migrate-from-password-stdin"])
            .expect("migration flag");
        assert!(cli.migrate_from_password_stdin && !cli.state_secret_stdin);
    }

    #[test]
    fn signer_backend_defaults_to_software_and_rejects_secure_enclave() {
        let cli = Cli::try_parse_from(["agentpay-daemon", SECRET_FLAG]).expect("parse defaults");
        assert_eq!(cli.signer_backend, SignerBackendKind::Software);
        let cli = Cli::try_parse_from([
            "agentpay-daemon",
            SECRET_FLAG,
            "--signer-backend",
            "software",
        ])
        .expect("parse software");
        assert_eq!(cli.signer_backend, SignerBackendKind::Software);
        assert!(Cli::try_parse_from([
            "agentpay-daemon",
            SECRET_FLAG,
            "--signer-backend",
            "secure-enclave"
        ])
        .is_err());
        #[cfg(target_os = "linux")]
        assert_eq!(
            Cli::try_parse_from(["agentpay-daemon", SECRET_FLAG, "--signer-backend", "tpm"])
                .expect("parse tpm")
                .signer_backend,
            SignerBackendKind::Tpm
        );
        #[cfg(not(target_os = "linux"))]
        assert!(
            Cli::try_parse_from(["agentpay-daemon", SECRET_FLAG, "--signer-backend", "tpm"])
                .is_err()
        );
    }
}
