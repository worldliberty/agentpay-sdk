//! `cargo xtask dist`: builds the release tarball for one target.
//!
//! 1. Builds the daemon binaries with cargo (`--release --locked --target <triple>`, with the
//!    repository and cargo home remapped out of embedded paths), plus `agentpay-auth` on macOS.
//! 2. Builds the client from a clean copy of `client/` (`npm ci` + `npm run build`), so the
//!    working copy's `node_modules` and `dist` are never touched.
//! 3. Fetches the pinned Node.js runtime and checks it against its pinned SHA-256.
//! 4. Assembles the release (see [`bundle`]), installs the client's production dependencies
//!    (`npm ci --omit=dev --ignore-scripts`), fails if a file mentions the builder's home
//!    directory, and writes `manifest.json`.
//! 5. Packs `dist/agentpay-<version>-<os>-<arch>.tar.gz` reproducibly and rewrites
//!    `dist/SHA256SUMS`.
//!
//! Cross-compiling between operating systems is not supported; macOS can build both of its
//! architectures (`rustup target add x86_64-apple-darwin`).

pub mod bundle;
pub mod node;
pub mod target;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Args;

use crate::macos_auth::{self, Arch, BuildArgs, Profile};
use bundle::{Inputs, ReleaseInfo};
use node::NodeRuntime;
use target::{Os, Target};

/// The release version: the workspace version, shared by every crate and the client.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Options of `cargo xtask dist`.
#[derive(Debug, Args)]
pub struct DistArgs {
    /// Rust target triple to build, e.g. x86_64-apple-darwin (default: this machine's).
    #[arg(long, value_name = "TRIPLE")]
    pub target: Option<String>,
    /// Directory that receives the tarball and SHA256SUMS (default: dist/ in the repository).
    #[arg(long, value_name = "DIR")]
    pub out_dir: Option<PathBuf>,
}

/// Builds the release for the requested target and returns the tarball's path.
pub fn run(root: &Path, args: &DistArgs) -> Result<PathBuf> {
    let target = match &args.target {
        Some(triple) => Target::parse(triple)?,
        None => Target::host()?,
    };
    if target.os() != Target::host()?.os() {
        bail!(
            "cannot build {} here: build each OS's release on that OS",
            target.triple()
        );
    }
    check_client_version(root)?;
    let target_dir = macos_auth::target_dir(root);
    let work = target_dir.join("dist").join(target.triple());
    let info = release_info(root, target)?;

    let binaries = build_binaries(root, target)?;
    let client = build_client(root, &work.join("client-src"))?;
    let node = NodeRuntime::for_target(target);
    let archive = node.fetch(&target_dir.join("dist").join("cache"))?;
    let node_dir = work.join("node");
    reset_dir(&node_dir)?;
    node.extract(&archive, &node_dir)?;

    let stage = work.join("stage");
    reset_dir(&stage)?;
    let release = stage.join(target.release_name(VERSION));
    bundle::assemble(
        &release,
        &Inputs {
            binaries,
            client_package: client.clone(),
            client_dist: client.join("dist"),
            node: node_dir,
            license: root.join("LICENSE"),
        },
    )?;
    install_client_dependencies(&release.join("client"))?;
    check_no_leaks(root, &release)?;
    bundle::write_manifest(&release, &info)?;

    let out_dir = args.out_dir.clone().unwrap_or_else(|| root.join("dist"));
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let tarball = out_dir.join(target.asset_name(VERSION));
    let digest = bundle::write_tarball(&release, &tarball, info.source_date_epoch)?;
    let sums = bundle::write_checksums(&out_dir, VERSION)?;
    let size = std::fs::metadata(&tarball)?.len();
    println!(
        "dist: {} ({:.1} MB)\n      sha256 {digest}\n      {}",
        tarball.display(),
        size as f64 / 1_048_576.0,
        sums.display()
    );
    Ok(tarball)
}

/// Fails unless `client/package.json` carries the workspace version.
fn check_client_version(root: &Path) -> Result<()> {
    let path = root.join("client/package.json");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let package: serde_json::Value = serde_json::from_str(&text)?;
    match package["version"].as_str() {
        Some(version) if version == VERSION => Ok(()),
        other => bail!(
            "client/package.json has version {other:?} but the workspace is {VERSION}; \
             bump them together"
        ),
    }
}

fn release_info(root: &Path, target: Target) -> Result<ReleaseInfo> {
    let commit = git(root, &["rev-parse", "HEAD"])?;
    let dirty = !git(root, &["status", "--porcelain"])?.is_empty();
    let source_date_epoch = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) if !value.trim().is_empty() => value
            .trim()
            .parse()
            .context("SOURCE_DATE_EPOCH must be a number of seconds")?,
        _ => git(root, &["log", "-1", "--format=%ct"])?
            .parse()
            .context("unexpected `git log` output")?,
    };
    if dirty {
        println!("dist: warning: the working tree has uncommitted changes");
    }
    Ok(ReleaseInfo {
        version: VERSION.to_owned(),
        target,
        commit,
        dirty,
        source_date_epoch,
        node_version: node::NODE_VERSION.to_owned(),
    })
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .context("failed to run git")?;
    if !output.status.success() {
        bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

/// Builds the cargo binaries (and `agentpay-auth` on macOS); returns `(name, path)` pairs.
fn build_binaries(root: &Path, target: Target) -> Result<Vec<(String, PathBuf)>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.current_dir(root).args([
        "build",
        "--release",
        "--locked",
        "--target",
        target.triple(),
    ]);
    for binary in target.cargo_binaries() {
        command.args(["--bin", binary]);
    }
    command
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rustflags(root))
        .env_remove("RUSTFLAGS");
    run_command(&mut command)?;

    let out = macos_auth::target_dir(root)
        .join(target.triple())
        .join("release");
    let mut binaries: Vec<(String, PathBuf)> = target
        .cargo_binaries()
        .into_iter()
        .map(|name| (name.to_owned(), out.join(name)))
        .collect();
    if target.os() == Os::Macos {
        let arch = match target {
            Target::MacosX86_64 => Arch::X86_64,
            _ => Arch::Arm64,
        };
        let auth = macos_auth::build(
            root,
            &BuildArgs {
                archs: vec![arch],
                profile: Profile::Release,
            },
        )?;
        binaries.push((macos_auth::BINARY_NAME.to_owned(), auth));
    }
    Ok(binaries)
}

/// The caller's rustflags plus prefix remaps that keep the repository path and the builder's
/// cargo home out of panic messages and other embedded paths.
fn encoded_rustflags(root: &Path) -> String {
    let mut flags: Vec<String> = match std::env::var("CARGO_ENCODED_RUSTFLAGS") {
        Ok(encoded) if !encoded.is_empty() => encoded.split('\x1f').map(str::to_owned).collect(),
        _ => std::env::var("RUSTFLAGS")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
    };
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    flags.extend(remap_flags(root, cargo_home.as_deref()));
    flags.join("\x1f")
}

fn remap_flags(root: &Path, cargo_home: Option<&Path>) -> Vec<String> {
    let mut flags = vec![format!("--remap-path-prefix={}=/agentpay", root.display())];
    if let Some(cargo_home) = cargo_home {
        flags.push(format!(
            "--remap-path-prefix={}=/cargo",
            cargo_home.display()
        ));
    }
    flags
}

/// Copies the client's sources (tracked and untracked-but-not-ignored files) into `dir` and
/// builds them there. Returns `dir`, which then holds `package.json` and `dist/`.
fn build_client(root: &Path, dir: &Path) -> Result<PathBuf> {
    reset_dir(dir)?;
    let mut copied = 0;
    for path in crate::repo_files(root)? {
        let Ok(relative) = path.strip_prefix("client") else {
            continue;
        };
        let source = root.join(&path);
        if !source.is_file() {
            continue;
        }
        bundle::copy_file(&source, &dir.join(relative), false)?;
        copied += 1;
    }
    if copied == 0 {
        bail!("client/ has no files");
    }
    run_command(npm(dir).args(["ci"]))?;
    run_command(npm(dir).args(["run", "build"]))?;
    Ok(dir.to_path_buf())
}

/// Installs the client's runtime dependencies, exactly as locked, without install scripts.
fn install_client_dependencies(client: &Path) -> Result<()> {
    run_command(npm(client).args(["ci", "--omit=dev", "--ignore-scripts"]))?;
    // One client directory serves both macOS architectures, so no native addons.
    let native: Vec<String> = bundle::walk(&client.join("node_modules"))?
        .into_iter()
        .filter(|entry| entry.path.ends_with(".node"))
        .map(|entry| entry.path)
        .collect();
    if !native.is_empty() {
        bail!(
            "the client's runtime dependencies include native addons: {}",
            native.join(", ")
        );
    }
    Ok(())
}

fn npm(dir: &Path) -> Command {
    let mut command = Command::new("npm");
    command
        .current_dir(dir)
        .env("npm_config_audit", "false")
        .env("npm_config_fund", "false")
        .env("npm_config_update_notifier", "false");
    command
}

/// Fails when any built file embeds the builder's home directory or the repository path. The
/// upstream Node.js binary is not checked.
fn check_no_leaks(root: &Path, release: &Path) -> Result<()> {
    let mut needles = vec![root.display().to_string()];
    if let Some(home) = std::env::var_os("HOME") {
        needles.push(PathBuf::from(home).display().to_string());
    }
    let leaks = bundle::find_leaks(release, &needles, &["node/"])?;
    if !leaks.is_empty() {
        bail!(
            "these release files mention the build machine's home or repository path: {}",
            leaks.join(", ")
        );
    }
    Ok(())
}

/// Removes and recreates `dir`.
fn reset_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .with_context(|| format!("failed to remove {}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))
}

fn run_command(command: &mut Command) -> Result<()> {
    let rendered = render(command);
    println!("+ {rendered}");
    let status = command
        .status()
        .with_context(|| format!("failed to run {rendered}"))?;
    if !status.success() {
        bail!("{rendered} failed with {status}");
    }
    Ok(())
}

fn render(command: &Command) -> String {
    let mut parts: Vec<OsString> = vec![command.get_program().to_owned()];
    parts.extend(command.get_args().map(ToOwned::to_owned));
    parts
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaps_cover_the_repository_and_cargo_home() {
        assert_eq!(
            remap_flags(
                Path::new("/src/agentpay"),
                Some(Path::new("/home/u/.cargo"))
            ),
            [
                "--remap-path-prefix=/src/agentpay=/agentpay",
                "--remap-path-prefix=/home/u/.cargo=/cargo"
            ]
        );
        assert_eq!(remap_flags(Path::new("/r"), None).len(), 1);
    }

    #[test]
    fn workspace_and_client_versions_agree() {
        let root = crate::repo_root().unwrap();
        check_client_version(&root).unwrap();
    }
}
