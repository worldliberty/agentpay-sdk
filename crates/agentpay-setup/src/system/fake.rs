//! In-memory [`System`] used by the unit tests.
//!
//! It simulates just enough of macOS (launchctl, `security`, the keychain helper, dscl) and
//! Linux (systemctl, useradd/groupadd) for the install, status and uninstall flows to run end to
//! end without root, and it records every command and file write so tests can assert
//! idempotency and that secrets never appear in arguments.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use zeroize::Zeroizing;

use super::{Account, Cmd, CmdOutput, FileKind, FileMeta, System};
use crate::layout::{Layout, Platform};

/// A file or directory in the fake filesystem.
#[derive(Debug, Clone)]
pub struct Node {
    /// Metadata reported by `lstat`.
    pub meta: FileMeta,
    /// File contents (empty for directories and sockets).
    pub data: Vec<u8>,
}

/// Mutable simulated machine state.
#[derive(Debug, Default)]
pub struct State {
    /// Filesystem entries.
    pub files: BTreeMap<PathBuf, Node>,
    /// System Keychain generic passwords keyed by (service, account).
    pub keychain: BTreeMap<(String, String), String>,
    /// Contents of the helper binary that wrote each keychain item. Like the real System
    /// Keychain ACL, only a helper with identical contents (at any path) can read it back.
    pub keychain_acl: BTreeMap<(String, String), Vec<u8>>,
    /// Local users.
    pub users: BTreeMap<String, Account>,
    /// Local groups.
    pub groups: BTreeMap<String, u32>,
    /// Whether the service is loaded/enabled.
    pub service_loaded: bool,
    /// Whether the daemon process is running.
    pub service_running: bool,
    /// Whether the payments service is loaded/enabled.
    pub payments_loaded: bool,
    /// Whether the payments service is running.
    pub payments_running: bool,
    /// Every command run, in order.
    pub commands: Vec<Cmd>,
    /// Every file written or copied, in order.
    pub writes: Vec<PathBuf>,
    /// Number of `sleep` calls.
    pub sleeps: u32,
    /// When set, the daemon never creates its socket.
    pub socket_never_ready: bool,
    /// When set, the payments service never creates its socket.
    pub payments_socket_never_ready: bool,
    /// When set, keychain helper reads fail (e.g. an ACL bound to a replaced helper).
    pub keychain_read_fails: bool,
    /// When set, the administrator declines the macOS keychain access dialog.
    pub keychain_approval_denied: bool,
    /// When set, the daemon's migration mode fails.
    pub migration_fails: bool,
    /// Stdin lines received by the daemon migration mode.
    pub migration_stdin: Vec<String>,
    rng_counter: u8,
}

/// The fake machine.
pub struct FakeSystem {
    /// Platform being simulated.
    pub platform: Platform,
    /// Shared mutable state.
    pub state: RefCell<State>,
}

const ROOT_DIR: FileMeta = FileMeta {
    kind: FileKind::Dir,
    uid: 0,
    gid: 0,
    mode: 0o755,
};

impl FakeSystem {
    fn new(platform: Platform) -> Self {
        let sys = Self {
            platform,
            state: RefCell::new(State::default()),
        };
        sys.add_user("alice", 501, 20);
        // Directories every supported OS already has.
        match platform {
            Platform::Macos => sys.mkdir("/Library/LaunchDaemons"),
            Platform::Linux => sys.mkdir("/etc/systemd/system"),
        }
        sys
    }

    /// A fake macOS machine with user `alice` (uid 501).
    pub fn macos() -> Self {
        Self::new(Platform::Macos)
    }

    /// A fake Linux machine with user `alice` (uid 501).
    pub fn linux() -> Self {
        Self::new(Platform::Linux)
    }

    /// Adds a local account.
    pub fn add_user(&self, name: &str, uid: u32, gid: u32) {
        let account = Account {
            name: name.into(),
            uid,
            gid,
        };
        self.state.borrow_mut().users.insert(name.into(), account);
    }

    /// Creates a root-owned directory and its parents.
    pub fn mkdir(&self, path: impl AsRef<Path>) {
        let mut state = self.state.borrow_mut();
        for ancestor in path.as_ref().ancestors() {
            state.files.entry(ancestor.to_path_buf()).or_insert(Node {
                meta: ROOT_DIR,
                data: Vec::new(),
            });
        }
    }

    /// Creates a file with the given owner and mode (parents are created as root 0755).
    pub fn put_file(&self, path: impl AsRef<Path>, data: &[u8], uid: u32, mode: u32) {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            self.mkdir(parent);
        }
        let meta = FileMeta {
            kind: FileKind::File,
            uid,
            gid: 0,
            mode,
        };
        let node = Node {
            meta,
            data: data.to_vec(),
        };
        self.state.borrow_mut().files.insert(path.into(), node);
    }

    /// Changes the mode of an existing entry.
    pub fn set_mode(&self, path: &Path, mode: u32) {
        if let Some(node) = self.state.borrow_mut().files.get_mut(path) {
            node.meta.mode = mode;
        }
    }

    /// Contents of a file as UTF-8, if present.
    pub fn file_text(&self, path: impl AsRef<Path>) -> Option<String> {
        let state = self.state.borrow();
        let node = state.files.get(path.as_ref())?;
        Some(String::from_utf8_lossy(&node.data).into_owned())
    }

    /// Whether a path exists.
    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.state.borrow().files.contains_key(path.as_ref())
    }

    /// Command lines run so far.
    pub fn command_lines(&self) -> Vec<String> {
        self.state
            .borrow()
            .commands
            .iter()
            .map(Cmd::display)
            .collect()
    }

    /// Clears the command and write logs (used between install runs).
    pub fn clear_logs(&self) {
        let mut state = self.state.borrow_mut();
        state.commands.clear();
        state.writes.clear();
    }

    /// Panics if `secret` appears in any command's program or arguments.
    pub fn assert_secret_never_leaked(&self, secret: &str) {
        for cmd in &self.state.borrow().commands {
            assert!(
                !cmd.display().contains(secret),
                "secret leaked into argv: {cmd:?}"
            );
        }
    }

    fn layout(&self) -> Layout {
        Layout::for_platform(self.platform)
    }

    fn start_daemon(state: &mut State, layout: &Layout) {
        state.service_running = true;
        if state.socket_never_ready {
            return;
        }
        for ancestor in layout.socket.ancestors().skip(1) {
            state.files.entry(ancestor.into()).or_insert(Node {
                meta: ROOT_DIR,
                data: Vec::new(),
            });
        }
        let meta = FileMeta {
            kind: FileKind::Socket,
            uid: 0,
            gid: 0,
            mode: 0o666,
        };
        state.files.insert(
            layout.socket.clone(),
            Node {
                meta,
                data: Vec::new(),
            },
        );
    }

    fn stop_daemon(state: &mut State, layout: &Layout) {
        state.service_running = false;
        state.files.remove(&layout.socket);
    }

    /// Starts the payments service: like systemd's `RuntimeDirectory=`, the socket directory is
    /// created for the service account when missing; the socket belongs to that account.
    fn start_payments(state: &mut State, layout: &Layout) {
        state.payments_running = true;
        if state.socket_never_ready || state.payments_socket_never_ready {
            return;
        }
        let owner = state
            .users
            .get(layout.service_user)
            .map_or((999, 999), |account| (account.uid, account.gid));
        let run_dir = layout.payments.run_dir.clone();
        state.files.entry(run_dir).or_insert(Node {
            meta: FileMeta {
                kind: FileKind::Dir,
                uid: owner.0,
                gid: owner.1,
                mode: 0o755,
            },
            data: Vec::new(),
        });
        let meta = FileMeta {
            kind: FileKind::Socket,
            uid: owner.0,
            gid: owner.1,
            mode: 0o666,
        };
        state.files.insert(
            layout.payments.socket.clone(),
            Node {
                meta,
                data: Vec::new(),
            },
        );
    }

    fn stop_payments(state: &mut State, layout: &Layout) {
        state.payments_running = false;
        state.files.remove(&layout.payments.socket);
    }

    fn start_unit(state: &mut State, layout: &Layout, payments: bool) {
        if payments {
            Self::start_payments(state, layout);
        } else {
            Self::start_daemon(state, layout);
        }
    }

    fn stop_unit(state: &mut State, layout: &Layout, payments: bool) {
        if payments {
            Self::stop_payments(state, layout);
        } else {
            Self::stop_daemon(state, layout);
        }
    }

    fn loaded(state: &State, payments: bool) -> bool {
        if payments {
            state.payments_loaded
        } else {
            state.service_loaded
        }
    }

    fn running(state: &State, payments: bool) -> bool {
        if payments {
            state.payments_running
        } else {
            state.service_running
        }
    }

    /// Sets the loaded flag of a unit and returns its previous value.
    fn set_loaded(state: &mut State, payments: bool, loaded: bool) -> bool {
        let flag = if payments {
            &mut state.payments_loaded
        } else {
            &mut state.service_loaded
        };
        std::mem::replace(flag, loaded)
    }

    fn simulate(&self, cmd: &Cmd) -> CmdOutput {
        let layout = self.layout();
        let mut state = self.state.borrow_mut();
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
        let stdin = cmd
            .stdin
            .as_ref()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();
        let ok = |stdout: &str| output(0, stdout, "");
        let program = cmd.program.rsplit('/').next().unwrap_or_default();
        // launchctl/systemctl arguments name the payments unit by its label or plist path.
        let payments = args.iter().any(|arg| arg.contains("paymentd"));
        match (program, args.as_slice()) {
            ("launchctl", ["print", _]) if Self::loaded(&state, payments) => ok(&format!(
                "state = {}\n\tpid = 4242\n",
                if Self::running(&state, payments) {
                    "running"
                } else {
                    "waiting"
                }
            )),
            ("launchctl", ["print", _]) => output(113, "", "Could not find service"),
            ("launchctl", ["bootout", _]) => {
                let was_loaded = Self::set_loaded(&mut state, payments, false);
                Self::stop_unit(&mut state, &layout, payments);
                output(if was_loaded { 0 } else { 3 }, "", "")
            }
            ("launchctl", ["bootstrap", "system", _]) => {
                Self::set_loaded(&mut state, payments, true);
                Self::start_unit(&mut state, &layout, payments);
                ok("")
            }
            ("launchctl", ["kickstart", "-k", _]) => {
                Self::start_unit(&mut state, &layout, payments);
                ok("")
            }
            ("launchctl", ["enable" | "disable", _]) => ok(""),
            ("security", ["find-generic-password", "-s", s, "-a", a, "-w", _]) => {
                let key = (s.to_string(), a.to_string());
                match state.keychain.get(&key) {
                    _ if state.keychain_approval_denied => output(51, "", "User canceled"),
                    Some(value) => ok(&format!("{value}\n")),
                    None => output(44, "", "item not found"),
                }
            }
            ("security", [action, "-s", service, "-a", account, _]) => {
                let key = (service.to_string(), account.to_string());
                // Root's `security` deletes an item whatever helper its ACL trusts.
                let found = match *action {
                    "delete-generic-password" => {
                        state.keychain_acl.remove(&key);
                        state.keychain.remove(&key).is_some()
                    }
                    _ => state.keychain.contains_key(&key),
                };
                output(if found { 0 } else { 44 }, "", "")
            }
            (
                "agentpay-system-keychain",
                [action, "--keychain", _, "--service", s, "--account", a, rest @ ..],
            ) => {
                let key = (s.to_string(), a.to_string());
                let helper = state
                    .files
                    .get(Path::new(&cmd.program))
                    .map(|node| node.data.clone());
                let trusted = state
                    .keychain_acl
                    .get(&key)
                    .is_none_or(|acl| Some(acl) == helper.as_ref());
                match *action {
                    "read-generic-password" if state.keychain_read_fails || !trusted => {
                        output(1, "", "failed to read generic password")
                    }
                    "read-generic-password" => match state.keychain.get(&key) {
                        Some(value) => ok(&format!("{value}\n")),
                        None => output(1, "", "item not found"),
                    },
                    // Like the real helper: it cannot see (so cannot delete) an item another
                    // helper build wrote, and then adding a second one fails.
                    "replace-generic-password" if !trusted && state.keychain.contains_key(&key) => {
                        output(
                            1,
                            "",
                            "failed to create restricted generic password item: The specified \
                             item already exists in the keychain.",
                        )
                    }
                    "replace-generic-password" if rest == ["--password-stdin"] => {
                        state
                            .keychain
                            .insert(key.clone(), stdin.trim_end().to_string());
                        match helper {
                            Some(contents) => state.keychain_acl.insert(key, contents),
                            None => state.keychain_acl.remove(&key),
                        };
                        ok("")
                    }
                    _ => output(2, "", "bad helper invocation"),
                }
            }
            ("dscl", [".", "-list", "/Users", "UniqueID"]) => {
                let lines: Vec<String> = state
                    .users
                    .values()
                    .map(|u| format!("{} {}", u.name, u.uid))
                    .collect();
                ok(&lines.join("\n"))
            }
            ("dscl", [".", "-list", "/Groups", "PrimaryGroupID"]) => {
                let lines: Vec<String> = state
                    .groups
                    .iter()
                    .map(|(n, g)| format!("{n} {g}"))
                    .collect();
                ok(&lines.join("\n"))
            }
            ("dscl", [".", "-create", record, rest @ ..]) => {
                Self::dscl_create(&mut state, record, rest);
                ok("")
            }
            ("groupadd", [.., name]) => {
                state.groups.insert(name.to_string(), 998);
                ok("")
            }
            ("useradd", [.., name]) => {
                let gid = if args.contains(&"--user-group") {
                    state.groups.insert(name.to_string(), 999);
                    999
                } else {
                    state.groups.get("agentpay").copied().unwrap_or(998)
                };
                let account = Account {
                    name: name.to_string(),
                    uid: 999,
                    gid,
                };
                state.users.insert(name.to_string(), account);
                ok("")
            }
            ("systemctl", ["is-active", _]) if Self::running(&state, payments) => ok("active\n"),
            ("systemctl", ["is-active", _]) => output(3, "inactive\n", ""),
            ("systemctl", ["is-enabled", _]) if Self::loaded(&state, payments) => ok("enabled\n"),
            ("systemctl", ["is-enabled", _]) => output(1, "disabled\n", ""),
            ("systemctl", ["daemon-reload"]) => ok(""),
            ("systemctl", ["enable", _]) => {
                Self::set_loaded(&mut state, payments, true);
                ok("")
            }
            ("systemctl", ["restart", _]) => {
                Self::start_unit(&mut state, &layout, payments);
                ok("")
            }
            ("systemctl", ["stop", _]) => {
                Self::stop_unit(&mut state, &layout, payments);
                ok("")
            }
            ("systemctl", ["disable", "--now", _]) => {
                Self::set_loaded(&mut state, payments, false);
                Self::stop_unit(&mut state, &layout, payments);
                ok("")
            }
            ("agentpay-daemon", _) => {
                state.migration_stdin = stdin.lines().map(str::to_owned).collect();
                if state.migration_fails {
                    output(1, "", "failed to decrypt state: authentication failed")
                } else {
                    ok("")
                }
            }
            _ => output(
                127,
                "",
                &format!("fake: unexpected command {}", cmd.display()),
            ),
        }
    }

    fn dscl_create(state: &mut State, record: &str, rest: &[&str]) {
        let parse = |value: Option<&&str>| value.and_then(|v| v.parse::<u32>().ok());
        if let Some(name) = record.strip_prefix("/Groups/") {
            if rest.first() == Some(&"PrimaryGroupID") {
                if let Some(gid) = parse(rest.get(1)) {
                    state.groups.insert(name.into(), gid);
                }
            }
        } else if let Some(name) = record.strip_prefix("/Users/") {
            let entry = state.users.entry(name.into()).or_insert(Account {
                name: name.into(),
                uid: u32::MAX,
                gid: u32::MAX,
            });
            match (rest.first(), parse(rest.get(1))) {
                (Some(&"UniqueID"), Some(uid)) => entry.uid = uid,
                (Some(&"PrimaryGroupID"), Some(gid)) => entry.gid = gid,
                _ => {}
            }
        }
    }

    fn require_parent_dir(state: &State, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", path.display()))?;
        match state.files.get(parent) {
            Some(node) if node.meta.kind == FileKind::Dir => Ok(()),
            _ => bail!("parent directory {} does not exist", parent.display()),
        }
    }
}

fn output(code: i32, stdout: &str, stderr: &str) -> CmdOutput {
    CmdOutput {
        code,
        stdout: Zeroizing::new(stdout.as_bytes().to_vec()),
        stderr: stderr.into(),
    }
}

impl System for FakeSystem {
    fn lstat(&self, path: &Path) -> Result<Option<FileMeta>> {
        Ok(self.state.borrow().files.get(path).map(|node| node.meta))
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn read_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let state = self.state.borrow();
        match state.files.get(path) {
            Some(node) if node.meta.kind == FileKind::File => Ok(Zeroizing::new(node.data.clone())),
            Some(_) => bail!("{} is not a regular file", path.display()),
            None => bail!("{} does not exist", path.display()),
        }
    }

    fn same_contents(&self, a: &Path, b: &Path) -> Result<bool> {
        Ok(self.read_file(a)? == self.read_file(b)?)
    }

    fn write_file(&self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        let mut state = self.state.borrow_mut();
        Self::require_parent_dir(&state, path)?;
        let meta = FileMeta {
            kind: FileKind::File,
            uid: 0,
            gid: 0,
            mode,
        };
        let node = Node {
            meta,
            data: contents.to_vec(),
        };
        state.files.insert(path.into(), node);
        state.writes.push(path.into());
        Ok(())
    }

    fn copy_file(&self, src: &Path, dest: &Path, mode: u32) -> Result<()> {
        let data = self.read_file(src)?;
        self.write_file(dest, &data, mode)
    }

    fn ensure_dir(&self, path: &Path, mode: u32) -> Result<()> {
        if let Some(meta) = self.lstat(path)? {
            if meta.kind != FileKind::Dir {
                bail!("{} exists and is not a directory", path.display());
            }
        }
        self.mkdir(path);
        let mut state = self.state.borrow_mut();
        if let Some(node) = state.files.get_mut(path) {
            node.meta = FileMeta { mode, ..ROOT_DIR };
        }
        Ok(())
    }

    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        let mut state = self.state.borrow_mut();
        match state.files.get_mut(path) {
            Some(node) if node.meta.kind == FileKind::Symlink => {
                bail!("{} is a symlink", path.display())
            }
            Some(node) => {
                node.meta.uid = uid;
                node.meta.gid = gid;
                Ok(())
            }
            None => bail!("{} does not exist", path.display()),
        }
    }

    fn remove_file(&self, path: &Path) -> Result<bool> {
        let mut state = self.state.borrow_mut();
        match state.files.get(path) {
            Some(node) if node.meta.kind == FileKind::Dir => bail!("{} is a dir", path.display()),
            Some(_) => Ok(state.files.remove(path).is_some()),
            None => Ok(false),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> Result<bool> {
        let mut state = self.state.borrow_mut();
        let before = state.files.len();
        state
            .files
            .retain(|candidate, _| !candidate.starts_with(path));
        Ok(state.files.len() != before)
    }

    fn run(&self, cmd: &Cmd) -> Result<CmdOutput> {
        self.state.borrow_mut().commands.push(cmd.clone());
        Ok(self.simulate(cmd))
    }

    fn lookup_user(&self, name: &str) -> Result<Option<Account>> {
        let state = self.state.borrow();
        Ok(state
            .users
            .get(name)
            .filter(|account| account.uid != u32::MAX && account.gid != u32::MAX)
            .cloned())
    }

    fn lookup_group(&self, name: &str) -> Result<Option<u32>> {
        Ok(self.state.borrow().groups.get(name).copied())
    }

    fn socket_accepts(&self, path: &Path) -> bool {
        let state = self.state.borrow();
        let running = if path == self.layout().payments.socket {
            state.payments_running
        } else {
            state.service_running
        };
        running && state.files.contains_key(path)
    }

    fn sleep(&self, _duration: Duration) {
        self.state.borrow_mut().sleeps += 1;
    }

    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        let mut state = self.state.borrow_mut();
        state.rng_counter = state.rng_counter.wrapping_add(1);
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte = state.rng_counter ^ (index as u8).wrapping_mul(31).wrapping_add(7);
        }
        Ok(())
    }
}
