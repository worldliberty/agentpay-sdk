//! The production [`System`] implementation backed by the local machine.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use nix::unistd::{Gid, Group, Uid, User};
use zeroize::Zeroizing;

use super::{Account, Cmd, CmdOutput, FileKind, FileMeta, System};

/// Fixed search path for child processes; the inherited `PATH` is never trusted under sudo.
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The real machine.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSystem;

fn meta_from(metadata: &fs::Metadata) -> FileMeta {
    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        FileKind::Symlink
    } else if file_type.is_dir() {
        FileKind::Dir
    } else if file_type.is_file() {
        FileKind::File
    } else if file_type.is_socket() {
        FileKind::Socket
    } else {
        FileKind::Other
    };
    FileMeta {
        kind,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    }
}

/// Opens an existing regular file without following a final symlink.
fn open_regular_nofollow(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    Ok(file)
}

/// Writes through `fill` into a root-owned temp file next to `dest`, then renames it into place.
fn write_atomically(
    dest: &Path,
    mode: u32,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<()> {
    if let Ok(existing) = fs::symlink_metadata(dest) {
        if existing.is_dir() {
            bail!("{} is a directory", dest.display());
        }
    }
    let parent = dest
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", dest.display()))?;
    let name = dest
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", dest.display()))?
        .to_string_lossy();
    let temp = parent.join(format!(".{name}.tmp.{}", std::process::id()));
    let _ = fs::remove_file(&temp);

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temp)
            .with_context(|| format!("failed to create {}", temp.display()))?;
        fill(&mut file).with_context(|| format!("failed to write {}", temp.display()))?;
        nix::unistd::fchown(&file, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
            .with_context(|| format!("failed to chown {}", temp.display()))?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&temp, dest)
            .with_context(|| format!("failed to move {} into place", dest.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

impl System for RealSystem {
    fn lstat(&self, path: &Path) -> Result<Option<FileMeta>> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(meta_from(&metadata))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("failed to stat {}", path.display())),
        }
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        fs::canonicalize(path).with_context(|| format!("failed to resolve {}", path.display()))
    }

    fn read_file(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let mut file = open_regular_nofollow(path)?;
        let mut contents = Zeroizing::new(Vec::new());
        file.read_to_end(&mut contents)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(contents)
    }

    fn same_contents(&self, a: &Path, b: &Path) -> Result<bool> {
        let (mut left, mut right) = (open_regular_nofollow(a)?, open_regular_nofollow(b)?);
        if left.metadata()?.len() != right.metadata()?.len() {
            return Ok(false);
        }
        let (mut left_buf, mut right_buf) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
        loop {
            let read = left.read(&mut left_buf)?;
            if read == 0 {
                return Ok(true);
            }
            right.read_exact(&mut right_buf[..read])?;
            if left_buf[..read] != right_buf[..read] {
                return Ok(false);
            }
        }
    }

    fn write_file(&self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        write_atomically(path, mode, |file| file.write_all(contents))
    }

    fn copy_file(&self, src: &Path, dest: &Path, mode: u32) -> Result<()> {
        let mut source = open_regular_nofollow(src)?;
        write_atomically(dest, mode, |file| io::copy(&mut source, file).map(|_| ()))
    }

    fn ensure_dir(&self, path: &Path, mode: u32) -> Result<()> {
        match self.lstat(path)? {
            Some(meta) if meta.kind == FileKind::Symlink => {
                bail!("{} must not be a symlink", path.display())
            }
            Some(meta) if meta.kind != FileKind::Dir => {
                bail!("{} exists and is not a directory", path.display())
            }
            Some(_) => {}
            None => fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?,
        }
        nix::unistd::chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
            .with_context(|| format!("failed to chown {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to chmod {}", path.display()))
    }

    fn set_owner(&self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        nix::unistd::fchownat(
            nix::fcntl::AT_FDCWD,
            path,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(gid)),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .with_context(|| format!("failed to chown {} to {uid}:{gid}", path.display()))
    }

    fn remove_file(&self, path: &Path) -> Result<bool> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("failed to remove {}", path.display()))
            }
        }
    }

    fn remove_dir_all(&self, path: &Path) -> Result<bool> {
        match self.lstat(path)? {
            None => Ok(false),
            Some(meta) if meta.kind != FileKind::Dir => {
                bail!("{} is not a directory", path.display())
            }
            Some(_) => fs::remove_dir_all(path)
                .map(|()| true)
                .with_context(|| format!("failed to remove {}", path.display())),
        }
    }

    fn run(&self, cmd: &Cmd) -> Result<CmdOutput> {
        let mut child = Command::new(&cmd.program)
            .args(&cmd.args)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("LC_ALL", "C")
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start `{}`", cmd.program))?;

        // Feed stdin from a thread so a chatty child can never deadlock against a full pipe.
        let writer = match (child.stdin.take(), cmd.stdin.clone()) {
            (Some(mut pipe), Some(bytes)) => Some(std::thread::spawn(move || {
                let result = pipe.write_all(&bytes);
                drop(pipe);
                result
            })),
            _ => None,
        };
        let output = child
            .wait_with_output()
            .with_context(|| format!("failed to wait for `{}`", cmd.program))?;
        if let Some(writer) = writer {
            match writer.join() {
                Ok(Ok(())) => {}
                // The child may legitimately exit before reading everything (e.g. on error).
                Ok(Err(error)) if error.kind() == io::ErrorKind::BrokenPipe => {}
                Ok(Err(error)) => {
                    return Err(error).with_context(|| format!("failed to feed `{}`", cmd.program))
                }
                Err(_) => bail!("stdin writer for `{}` panicked", cmd.program),
            }
        }
        Ok(CmdOutput {
            code: output.status.code().unwrap_or(-1),
            stdout: Zeroizing::new(output.stdout),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn lookup_user(&self, name: &str) -> Result<Option<Account>> {
        let user =
            User::from_name(name).with_context(|| format!("failed to look up user {name}"))?;
        Ok(user.map(|user| Account {
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
        }))
    }

    fn lookup_group(&self, name: &str) -> Result<Option<u32>> {
        let group =
            Group::from_name(name).with_context(|| format!("failed to look up group {name}"))?;
        Ok(group.map(|group| group.gid.as_raw()))
    }

    fn socket_accepts(&self, path: &Path) -> bool {
        UnixStream::connect(path).is_ok()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|error| anyhow!("operating system RNG failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_clears_environment_and_passes_stdin() {
        // A value in the parent environment must never reach the child.
        std::env::set_var("AGENTPAY_SETUP_TEST_SECRET", "leaky");
        let cmd = Cmd::new("/bin/sh")
            .args(["-c", "cat; echo; env"])
            .stdin(Zeroizing::new(b"from-stdin".to_vec()));
        let output = RealSystem.run(&cmd).expect("run sh");
        let stdout = output.stdout_text();
        assert!(output.success());
        assert!(stdout.starts_with("from-stdin"));
        assert!(!stdout.contains("leaky"));
        assert!(stdout.contains(&format!("PATH={SAFE_PATH}")));
    }

    #[test]
    fn run_reports_exit_code_and_stderr() {
        let output = RealSystem
            .run(&Cmd::new("/bin/sh").args(["-c", "echo nope >&2; exit 3"]))
            .expect("run sh");
        assert_eq!(output.code, 3);
        assert_eq!(output.stderr.trim(), "nope");
    }

    #[test]
    fn same_contents_and_lstat_work_on_regular_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (a, b, c) = (
            dir.path().join("a"),
            dir.path().join("b"),
            dir.path().join("c"),
        );
        fs::write(&a, b"same").unwrap();
        fs::write(&b, b"same").unwrap();
        fs::write(&c, b"diff").unwrap();
        assert!(RealSystem.same_contents(&a, &b).unwrap());
        assert!(!RealSystem.same_contents(&a, &c).unwrap());
        assert_eq!(RealSystem.lstat(&a).unwrap().unwrap().kind, FileKind::File);
        assert!(RealSystem
            .lstat(&dir.path().join("missing"))
            .unwrap()
            .is_none());
        std::os::unix::fs::symlink(&a, dir.path().join("link")).unwrap();
        assert!(RealSystem.read_file(&dir.path().join("link")).is_err());
    }

    #[test]
    fn fill_random_produces_distinct_values() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        RealSystem.fill_random(&mut a).unwrap();
        RealSystem.fill_random(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
