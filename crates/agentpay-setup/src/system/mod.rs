//! The operating-system boundary of `agentpay-setup`.
//!
//! Every side effect the installer performs (filesystem changes, child processes such as
//! `launchctl`, `systemctl`, `dscl`, `useradd` and the keychain helper, account lookups, socket
//! probes and randomness) goes through the [`System`] trait. The step logic in
//! [`crate::install`], [`crate::status`] and [`crate::uninstall`] only talks to this trait, which
//! lets the unit tests drive full install/uninstall flows against an in-memory fake without root.
//!
//! Secret handling rules enforced at this boundary:
//! - secrets reach child processes only through [`Cmd::stdin`], never through arguments or the
//!   environment (the real runner clears the environment of every child);
//! - command output that may carry a secret is returned as [`Zeroizing`] bytes.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use zeroize::Zeroizing;

pub mod real;

#[cfg(test)]
pub mod fake;

/// Kind of filesystem entry, as seen by `lstat` (symlinks are not followed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (never followed).
    Symlink,
    /// Unix domain socket.
    Socket,
    /// Anything else (FIFO, device, ...).
    Other,
}

/// The subset of `lstat` results the installer cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    /// Entry kind.
    pub kind: FileKind,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Permission bits including setuid/setgid/sticky (`st_mode & 0o7777`).
    pub mode: u32,
}

/// A local account resolved from the system user database.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Account {
    /// Login name.
    pub name: String,
    /// User id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
}

/// A child process invocation.
///
/// `program` is resolved against a fixed system `PATH` by the real runner; the child gets an
/// otherwise empty environment.
#[derive(Clone, PartialEq, Eq)]
pub struct Cmd {
    /// Program name or absolute path.
    pub program: String,
    /// Arguments. Must never contain secret material.
    pub args: Vec<String>,
    /// Bytes written to the child's stdin, then stdin is closed. The only channel for secrets.
    pub stdin: Option<Zeroizing<Vec<u8>>>,
}

impl Cmd {
    /// Creates a command with no arguments and no stdin.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            stdin: None,
        }
    }

    /// Appends one argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Supplies stdin bytes (used for secrets).
    pub fn stdin(mut self, bytes: Zeroizing<Vec<u8>>) -> Self {
        self.stdin = Some(bytes);
        self
    }

    /// Human-readable command line for error messages. Stdin is never rendered.
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cmd")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("stdin", &self.stdin.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// Result of a finished child process.
pub struct CmdOutput {
    /// Exit code (`-1` when killed by a signal).
    pub code: i32,
    /// Captured stdout. Zeroized on drop because keychain reads print secrets here.
    pub stdout: Zeroizing<Vec<u8>>,
    /// Captured stderr (lossy UTF-8). Tools invoked by the installer never print secrets here.
    pub stderr: String,
}

impl CmdOutput {
    /// Whether the process exited with status 0.
    pub fn success(&self) -> bool {
        self.code == 0
    }

    /// Stdout as lossy UTF-8, for non-secret output such as `launchctl print`.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// Every operating-system effect the installer needs.
///
/// Paths are absolute. Ownership of everything the installer creates is `root` (uid 0, gid 0),
/// so the write helpers do not take an owner; the few directories the payments service account
/// owns are handed over with [`System::set_owner`].
pub trait System {
    /// `lstat` the path; `Ok(None)` if it does not exist.
    fn lstat(&self, path: &Path) -> Result<Option<FileMeta>>;
    /// Resolves symlinks in an existing path.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf>;
    /// Reads a whole file. Refuses symlinks. Contents are zeroized on drop.
    fn read_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>>;
    /// Whether two regular files have identical contents.
    fn same_contents(&self, a: &Path, b: &Path) -> Result<bool>;
    /// Atomically writes `contents` to `path` (temp file + rename) as root with `mode`.
    fn write_file(&self, path: &Path, contents: &[u8], mode: u32) -> Result<()>;
    /// Atomically copies `src` to `dest` as root with `mode`.
    fn copy_file(&self, src: &Path, dest: &Path, mode: u32) -> Result<()>;
    /// Creates `path` and missing parents, then sets the leaf to root ownership and `mode`.
    /// Refuses to operate on a symlink.
    fn ensure_dir(&self, path: &Path, mode: u32) -> Result<()>;
    /// Changes the owner of an existing directory or file without following a symlink at
    /// `path` (used for the directories the payments service account owns).
    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()>;
    /// Removes a file, symlink or socket. Returns whether something was removed.
    fn remove_file(&self, path: &Path) -> Result<bool>;
    /// Recursively removes a directory. Returns whether something was removed.
    fn remove_dir_all(&self, path: &Path) -> Result<bool>;
    /// Runs a child process to completion, capturing its output.
    fn run(&self, cmd: &Cmd) -> Result<CmdOutput>;
    /// Looks up a user by login name.
    fn lookup_user(&self, name: &str) -> Result<Option<Account>>;
    /// Looks up a group id by name.
    fn lookup_group(&self, name: &str) -> Result<Option<u32>>;
    /// Whether something accepts connections on the Unix socket at `path`.
    fn socket_accepts(&self, path: &Path) -> bool;
    /// Sleeps (the fake advances a virtual clock instead).
    fn sleep(&self, duration: Duration);
    /// Fills `buf` from the operating system CSPRNG.
    fn fill_random(&self, buf: &mut [u8]) -> Result<()>;
}

/// Runs `cmd` and fails with its stderr when it exits non-zero.
pub fn run_checked(sys: &dyn System, cmd: &Cmd) -> Result<CmdOutput> {
    let output = sys.run(cmd)?;
    if !output.success() {
        anyhow::bail!(
            "`{}` failed (exit {}){}",
            cmd.display(),
            output.code,
            stderr_suffix(&output.stderr)
        );
    }
    Ok(output)
}

/// Formats a trimmed stderr excerpt for error messages (empty when there is none).
pub fn stderr_suffix(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        let excerpt: String = trimmed.chars().take(400).collect();
        format!(": {excerpt}")
    }
}
