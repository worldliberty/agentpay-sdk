//! `cargo xtask test-install`: runs `scripts/install.sh` end to end against a release served
//! from a temp directory (`file://`), each scenario in its own throwaway `HOME`.
//!
//! By default the release is a small synthetic one built with the real bundling code (its
//! programs are shell stubs), so the test needs no network and no release build. With
//! `--dist <dir>` it installs the real tarball for this machine from `cargo xtask dist` and
//! also runs the installed `agentpay` and `agentpay-setup`.
//!
//! The installer runs under `/bin/sh` in a new session (no controlling terminal), with a
//! minimal environment, so it can never prompt and never sees the real home directory. It
//! never needs sudo, and nothing here uses it.

mod fixture;
mod scenarios;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::{bail, Context, Result};
use clap::Args;

use crate::dist::target::Target;
use crate::dist::VERSION;
use fixture::Releases;

/// An older synthetic release, for downgrade and upgrade scenarios.
pub const OLD_VERSION: &str = "0.0.1";

/// Options of `cargo xtask test-install`.
#[derive(Debug, Args)]
pub struct TestInstallArgs {
    /// Install the real release tarball for this machine from DIR (as written by
    /// `cargo xtask dist`) instead of a synthetic one.
    #[arg(long, value_name = "DIR")]
    pub dist: Option<PathBuf>,
}

/// Shared state of one test run.
pub struct Ctx {
    /// The installer under test.
    pub script: PathBuf,
    /// Scratch directory (canonical, so it matches what the installer resolves).
    pub work: PathBuf,
    /// The good release tree.
    pub releases: Releases,
    /// The current release's tarball.
    pub tarball: PathBuf,
    /// Version of the current release.
    pub version: &'static str,
    /// This machine's target.
    pub target: Target,
    /// Whether the release is a real `dist` build.
    pub real: bool,
}

/// Result of one installer run.
pub struct Run {
    /// Whether it exited with status 0.
    pub ok: bool,
    /// Exit code, if any.
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl Run {
    fn from_output(output: Output) -> Self {
        Self {
            ok: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Fails unless the run succeeded.
    pub fn expect_ok(&self) -> Result<()> {
        if !self.ok {
            bail!(
                "expected success, got {:?}\n{}",
                self.code,
                self.transcript()
            );
        }
        Ok(())
    }

    /// Fails unless the run failed with `needle` in its output.
    pub fn expect_failure(&self, needle: &str) -> Result<()> {
        if self.ok {
            bail!(
                "expected a failure, but it succeeded\n{}",
                self.transcript()
            );
        }
        if !self.stdout.contains(needle) && !self.stderr.contains(needle) {
            bail!("expected {needle:?} in the output\n{}", self.transcript());
        }
        Ok(())
    }

    /// Both streams, for error messages.
    pub fn transcript(&self) -> String {
        format!("--- stdout\n{}--- stderr\n{}", self.stdout, self.stderr)
    }
}

impl Ctx {
    /// A fresh, canonical home directory with its own TMPDIR.
    pub fn home(&self, name: &str) -> Result<PathBuf> {
        let home = self.work.join("homes").join(name);
        std::fs::create_dir_all(home.join("tmp"))?;
        Ok(home)
    }

    fn command(&self, home: &Path, env: &[(&str, &str)]) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("SHELL", "/bin/zsh")
            .env("TMPDIR", home.join("tmp"))
            .env("AGENTPAY_RELEASES_URL", self.releases.url())
            .current_dir(home);
        for (key, value) in env {
            command.env(key, value);
        }
        detach_from_terminal(&mut command);
        command
    }

    /// Runs `sh install.sh <args>` in `home` with extra environment `env`.
    pub fn install(&self, home: &Path, env: &[(&str, &str)], args: &[&str]) -> Result<Run> {
        let output = self
            .command(home, env)
            .arg(&self.script)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .context("failed to run the installer")?;
        Ok(Run::from_output(output))
    }

    /// Runs the installer the way `curl ... | sh -s -- <args>` does: the script on stdin.
    pub fn install_piped(&self, home: &Path, args: &[&str]) -> Result<Run> {
        let script = std::fs::File::open(&self.script)?;
        let output = self
            .command(home, &[])
            .args(["-s", "--"])
            .args(args)
            .stdin(script)
            .output()
            .context("failed to run the installer")?;
        Ok(Run::from_output(output))
    }

    /// Runs an installed program with the same minimal environment.
    pub fn run_program(&self, home: &Path, program: &Path, args: &[&str]) -> Result<Run> {
        let output = Command::new(program)
            .args(args)
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("TMPDIR", home.join("tmp"))
            .env("AGENTPAY_TELEMETRY", "0")
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to run {}", program.display()))?;
        Ok(Run::from_output(output))
    }
}

/// Starts the child in a new session so it has no controlling terminal: `/dev/tty` cannot be
/// opened, exactly as for an installer piped into `sh` from a non-interactive agent.
fn detach_from_terminal(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe and touches no memory of the parent.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Runs every scenario and reports whether all passed.
pub fn run(root: &Path, args: &TestInstallArgs) -> Result<bool> {
    let target = Target::host()?;
    let temp = tempfile::Builder::new()
        .prefix("agentpay-test-install-")
        .tempdir()?;
    let work = std::fs::canonicalize(temp.path())?;
    let releases = Releases::new(work.join("releases"))?;

    let tarball = match &args.dist {
        Some(dir) => {
            let tarball = dir.join(target.asset_name(VERSION));
            if !tarball.is_file() {
                bail!(
                    "{} is missing; run `cargo xtask dist` first",
                    tarball.display()
                );
            }
            tarball
        }
        None => fixture::synthetic_release(root, &work, VERSION, target)?,
    };
    releases.publish(VERSION, &tarball, true)?;
    let old = fixture::synthetic_release(root, &work, OLD_VERSION, target)?;
    releases.publish(OLD_VERSION, &old, false)?;

    let ctx = Ctx {
        script: root.join("scripts/install.sh"),
        work,
        releases,
        tarball,
        version: VERSION,
        target,
        real: args.dist.is_some(),
    };
    let kind = if ctx.real { "dist" } else { "synthetic" };
    println!(
        "test-install: {} {kind} release for {}",
        VERSION,
        target.triple()
    );

    let mut failed = Vec::new();
    for (name, scenario) in scenarios::ALL {
        match scenario(&ctx) {
            Ok(()) => println!("  ok    {name}"),
            Err(error) => {
                println!("  FAIL  {name}\n{}", indent(&format!("{error:#}")));
                failed.push(*name);
            }
        }
    }
    if failed.is_empty() {
        println!(
            "test-install: all {} scenarios passed",
            scenarios::ALL.len()
        );
        Ok(true)
    } else {
        // Keep the scratch directory for inspection.
        let kept = temp.keep();
        eprintln!(
            "test-install: {} scenario(s) failed: {}\n  scratch directory kept at {}",
            failed.len(),
            failed.join(", "),
            kept.display()
        );
        Ok(false)
    }
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|line| format!("        {line}\n"))
        .collect()
}
