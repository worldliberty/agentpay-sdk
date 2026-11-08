//! `agentpay-setup` entry point: parse arguments, require root, dispatch.

use std::process::ExitCode;

use agentpay_setup::cli::{self, Cli, EXIT_FAILURE};
use agentpay_setup::layout::{Layout, Platform};
use agentpay_setup::system::real::RealSystem;
use clap::Parser;
use nix::sys::stat::{umask, Mode};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut stdout = std::io::stdout().lock();

    let Some(platform) = Platform::current() else {
        cli::report_early_failure(
            &mut stdout,
            &cli,
            "agentpay-setup supports macOS and Linux only",
            "Run AgentPay on macOS or Linux.",
        );
        return ExitCode::from(EXIT_FAILURE);
    };
    if !nix::unistd::geteuid().is_root() {
        cli::report_early_failure(
            &mut stdout,
            &cli,
            "agentpay-setup must run as root",
            "Rerun it with sudo, e.g. sudo agentpay-setup status",
        );
        return ExitCode::from(EXIT_FAILURE);
    }

    // Files are created with explicit modes; a predictable umask keeps intermediate parents sane.
    umask(Mode::from_bits_truncate(0o022));
    let layout = Layout::for_platform(platform);
    ExitCode::from(cli::run(&cli, &RealSystem, &layout, &mut stdout))
}
