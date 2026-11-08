//! Command-line interface and dispatch.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use crate::install::{self, InstallOptions};
use crate::layout::Layout;
use crate::report::{Done, Failure, Reporter};
use crate::status;
use crate::system::System;
use crate::uninstall::{self, UninstallOptions};

/// How long install waits for the daemon socket.
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit status for a failed command (clap uses 2 for usage errors).
pub const EXIT_FAILURE: u8 = 1;

/// Top-level arguments.
#[derive(Debug, Parser)]
#[command(
    name = "agentpay-setup",
    version,
    about = "Install, inspect or remove the AgentPay daemon (run as root via sudo)",
    long_about = "Install, inspect or remove the root-managed AgentPay daemon.\n\n\
        Must run as root. Never prompts and never reads secrets from arguments or the \
        environment; the daemon machine secret is generated on first install and stored \
        root-only (macOS System Keychain, Linux /var/lib/agentpay/daemon-secret)."
)]
pub struct Cli {
    /// Print one JSON document instead of human-readable steps.
    #[arg(long, global = true)]
    pub json: bool,
    /// Command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Install or upgrade the daemon (idempotent).
    Install {
        /// Login name of the user the daemon serves (admin and agent access).
        #[arg(long, value_name = "NAME")]
        user: String,
        /// Directory containing the new binaries (default: this binary's directory).
        #[arg(long, value_name = "DIR")]
        bin_dir: Option<PathBuf>,
        /// macOS recovery: an `agentpay-system-keychain` binary from the release that wrote a
        /// keychain item the installed helper cannot read: the legacy vault password (e.g.
        /// `~/.agentpay/legacy/bin/agentpay-system-keychain`), or the machine secret after a
        /// setup that stopped partway. It is copied root-only and used only to read that item.
        #[arg(long, value_name = "PATH")]
        legacy_helper: Option<PathBuf>,
    },
    /// Report whether the daemon is installed, running and reachable.
    Status,
    /// Stop and remove the daemon.
    Uninstall {
        /// Keep the encrypted wallet state and machine secret for a later install.
        #[arg(long)]
        keep_state: bool,
        /// Installing user, to also remove a legacy macOS keychain item (default: from the
        /// install record).
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
    },
}

/// Short name of the subcommand, used in JSON output.
pub fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Install { .. } => "install",
        Command::Status => "status",
        Command::Uninstall { .. } => "uninstall",
    }
}

/// Prints a failure detected before any step ran (not root, unsupported platform).
pub fn report_early_failure(out: &mut dyn Write, cli: &Cli, message: &str, next: &str) {
    let _ = if cli.json {
        let document = json!({
            "ok": false,
            "command": command_name(&cli.command),
            "steps": [],
            "result": null,
            "error": message,
            "next_action": next,
        });
        writeln!(out, "{document:#}")
    } else {
        writeln!(out, "{message}\n\nNext: {next}")
    };
}

/// Prints the end of a report and tells whether the command succeeded.
fn finish(reporter: Reporter<'_>, outcome: Result<Value, Failure>, message: &str) -> bool {
    let printed = match &outcome {
        Ok(result) => reporter.finish_ok(message, result.clone()),
        Err(failure) => reporter.finish_err(failure, Value::Null),
    };
    printed.is_ok() && outcome.is_ok()
}

/// Runs `cli` against `sys`, writing the report to `out`. Returns the process exit status.
pub fn run(cli: &Cli, sys: &dyn System, layout: &Layout, out: &mut dyn Write) -> u8 {
    let name = command_name(&cli.command);
    let ok = match &cli.command {
        Command::Install {
            user,
            bin_dir,
            legacy_helper,
        } => {
            let Some(source_dir) = bin_dir.clone().or_else(default_bin_dir) else {
                report_early_failure(
                    out,
                    cli,
                    "could not determine the directory of agentpay-setup",
                    "Pass the directory holding the AgentPay binaries with --bin-dir.",
                );
                return EXIT_FAILURE;
            };
            let options = InstallOptions {
                user: user.clone(),
                source_dir,
                legacy_helper: legacy_helper.clone(),
                socket_timeout: SOCKET_TIMEOUT,
            };
            let heading = format!("AgentPay setup · install for {user}");
            let next = format!(
                "Fix the problem above, then rerun: sudo agentpay-setup install --user {user}"
            );
            let mut reporter = Reporter::new(out, cli.json, name, &heading, next);
            let outcome = install::install(sys, layout, &options, &mut reporter);
            finish(
                reporter,
                outcome,
                "AgentPay daemon is installed and running.",
            )
        }
        Command::Status => {
            let heading = "AgentPay setup · status";
            let next = "Fix the problem above, then rerun: sudo agentpay-setup status";
            let mut reporter = Reporter::new(out, cli.json, name, heading, next);
            match status::collect(sys, layout) {
                Ok(current) => {
                    let result = status::to_json(&current);
                    match status::report(&current, layout, &mut reporter) {
                        None => reporter
                            .finish_ok("AgentPay daemon is healthy.", result)
                            .is_ok(),
                        Some(next) => {
                            let failure = Failure {
                                step: "status".into(),
                                message: "the AgentPay daemon is not healthy".into(),
                                next,
                            };
                            let _ = reporter.finish_err(&failure, result);
                            false
                        }
                    }
                }
                Err(error) => {
                    let outcome =
                        reporter.step("Status", || -> anyhow::Result<(Value, Done)> { Err(error) });
                    finish(reporter, outcome, "")
                }
            }
        }
        Command::Uninstall { keep_state, user } => {
            let options = UninstallOptions {
                keep_state: *keep_state,
                user: user.clone(),
            };
            let next = "Fix the problem above, then rerun: sudo agentpay-setup uninstall";
            let heading = "AgentPay setup · uninstall";
            let mut reporter = Reporter::new(out, cli.json, name, heading, next);
            let message = if *keep_state {
                "AgentPay daemon removed. Wallet state and machine secret were kept."
            } else {
                "AgentPay daemon, wallet state and machine secret removed."
            };
            let outcome = uninstall::uninstall(sys, layout, &options, &mut reporter);
            finish(reporter, outcome, message)
        }
    };
    if ok {
        0
    } else {
        EXIT_FAILURE
    }
}

/// The directory containing the running `agentpay-setup` binary.
pub fn default_bin_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    exe.parent().map(PathBuf::from)
}
