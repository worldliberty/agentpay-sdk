//! Assembles a release directory and packs it reproducibly.
//!
//! Release layout (the tarball holds one top-level directory, `agentpay-<version>-<os>-<arch>`):
//!
//! ```text
//! bin/agentpay              launcher: runs client/dist/cli.js on node/bin/node
//! bin/agentpay-setup        symlink to ../libexec/agentpay-setup (run with sudo)
//! libexec/                  agentpay-setup, agentpay-daemon, agentpay-paymentd, and on macOS
//!                           agentpay-system-keychain and agentpay-auth; agentpay-setup copies
//!                           the daemon binaries from its own directory
//! client/                   package.json, package-lock.json, dist/, node_modules/ (production)
//! node/                     bin/node and LICENSE of the pinned Node.js runtime
//! LICENSE
//! manifest.json             version, target, commit, and every file's size, mode and SHA-256
//! ```
//!
//! Packing is deterministic: entries are sorted by path, owned by uid/gid 0 with empty user
//! and group names, stamped with one fixed mtime, and have normalized modes (0755 for
//! directories and executables, 0644 for other files); the gzip header carries no name or
//! timestamp.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use flate2::{Compression, GzBuilder};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::target::Target;

/// Manifest file name at the release root.
pub const MANIFEST: &str = "manifest.json";
/// Checksum file published next to the tarballs.
pub const CHECKSUMS: &str = "SHA256SUMS";
/// The `bin/agentpay` launcher.
pub const LAUNCHER: &str = include_str!("agentpay.sh");
/// Version of the manifest format.
const MANIFEST_SCHEMA: u64 = 1;

/// What a release path is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A directory.
    Dir,
    /// A regular file.
    File {
        /// Whether any execute bit is set.
        executable: bool,
        /// Size in bytes.
        size: u64,
        /// Lowercase hex SHA-256 of the contents.
        sha256: String,
    },
    /// A symbolic link.
    Symlink {
        /// The link target as stored.
        target: String,
    },
}

impl Kind {
    /// The mode recorded in the tarball and the manifest.
    fn mode(&self) -> u32 {
        match self {
            Self::Dir
            | Self::File {
                executable: true, ..
            } => 0o755,
            Self::File { .. } => 0o644,
            Self::Symlink { .. } => 0o777,
        }
    }
}

/// One path in a release directory, relative to its root and `/`-separated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Relative path.
    pub path: String,
    /// What it is.
    pub kind: Kind,
}

/// Facts about a build recorded in the manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseInfo {
    /// Release version (the workspace version).
    pub version: String,
    /// Target the binaries were built for.
    pub target: Target,
    /// Source commit.
    pub commit: String,
    /// Whether the working tree had uncommitted changes.
    pub dirty: bool,
    /// Timestamp applied to every tarball entry (`SOURCE_DATE_EPOCH` or the commit time).
    pub source_date_epoch: u64,
    /// Bundled Node.js version.
    pub node_version: String,
}

/// Where `assemble` takes the release contents from.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// `(file name, built binary)` pairs copied into `libexec/`.
    pub binaries: Vec<(String, PathBuf)>,
    /// Directory holding the client's `package.json` and `package-lock.json`.
    pub client_package: PathBuf,
    /// The compiled client (`client/dist`).
    pub client_dist: PathBuf,
    /// Directory holding the runtime's `bin/node` and `LICENSE`.
    pub node: PathBuf,
    /// The repository LICENSE.
    pub license: PathBuf,
}

/// Lays out a release in the empty or missing directory `release`. The client's production
/// dependencies (`client/node_modules`) are installed afterwards by the caller.
pub fn assemble(release: &Path, inputs: &Inputs) -> Result<()> {
    if release.exists() {
        bail!("{} already exists", release.display());
    }
    let bin = release.join("bin");
    let libexec = release.join("libexec");
    let client = release.join("client");
    for dir in [&bin, &libexec, &client] {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }

    write_file(&bin.join("agentpay"), LAUNCHER.as_bytes(), true)?;
    std::os::unix::fs::symlink("../libexec/agentpay-setup", bin.join("agentpay-setup"))
        .context("failed to link bin/agentpay-setup")?;

    if !inputs
        .binaries
        .iter()
        .any(|(name, _)| name == "agentpay-setup")
    {
        bail!("the release must include agentpay-setup");
    }
    for (name, source) in &inputs.binaries {
        copy_file(source, &libexec.join(name), true)?;
    }

    for name in ["package.json", "package-lock.json"] {
        copy_file(&inputs.client_package.join(name), &client.join(name), false)?;
    }
    copy_tree(&inputs.client_dist, &client.join("dist"))?;
    if !client.join("dist/cli.js").is_file() {
        bail!(
            "{} has no cli.js; build the client first",
            inputs.client_dist.display()
        );
    }

    copy_file(
        &inputs.node.join("bin/node"),
        &release.join("node/bin/node"),
        true,
    )?;
    copy_file(
        &inputs.node.join("LICENSE"),
        &release.join("node/LICENSE"),
        false,
    )?;
    copy_file(&inputs.license, &release.join("LICENSE"), false)?;
    Ok(())
}

/// Lists everything under `root` (not `root` itself), sorted by path.
pub fn walk(root: &Path) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    walk_into(root, "", &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn walk_into(dir: &Path, prefix: &str, entries: &mut Vec<Entry>) -> Result<()> {
    let listing =
        std::fs::read_dir(dir).with_context(|| format!("failed to list {}", dir.display()))?;
    for item in listing {
        let item = item?;
        let name = item.file_name();
        let Some(name) = name.to_str() else {
            bail!("{} has a non-UTF-8 name", item.path().display());
        };
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let full = item.path();
        let meta = std::fs::symlink_metadata(&full)?;
        let kind = if meta.is_dir() {
            walk_into(&full, &path, entries)?;
            Kind::Dir
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&full)?;
            let Some(target) = target.to_str() else {
                bail!("{} links to a non-UTF-8 path", full.display());
            };
            Kind::Symlink {
                target: target.to_owned(),
            }
        } else if meta.is_file() {
            use std::os::unix::fs::PermissionsExt;
            Kind::File {
                executable: meta.permissions().mode() & 0o111 != 0,
                size: meta.len(),
                sha256: sha256_file(&full)?,
            }
        } else {
            bail!("{} is not a file, directory or symlink", full.display());
        };
        entries.push(Entry { path, kind });
    }
    Ok(())
}

/// The manifest for a release whose contents are `entries` (the manifest itself excluded).
pub fn manifest(info: &ReleaseInfo, entries: &[Entry]) -> Value {
    let files: Vec<Value> = entries
        .iter()
        .filter(|entry| entry.path != MANIFEST)
        .filter_map(|entry| match &entry.kind {
            Kind::Dir => None,
            Kind::File { size, sha256, .. } => Some(json!({
                "path": entry.path,
                "mode": format!("{:04o}", entry.kind.mode()),
                "size": size,
                "sha256": sha256,
            })),
            Kind::Symlink { target } => Some(json!({
                "path": entry.path,
                "link": target,
            })),
        })
        .collect();
    json!({
        "schema": MANIFEST_SCHEMA,
        "name": "agentpay",
        "version": info.version,
        "os": info.target.os_label(),
        "arch": info.target.arch_label(),
        "target": info.target.triple(),
        "commit": info.commit,
        "dirty": info.dirty,
        "source_date_epoch": info.source_date_epoch,
        "node": info.node_version,
        "files": files,
    })
}

/// Writes `manifest.json` into the release directory.
pub fn write_manifest(release: &Path, info: &ReleaseInfo) -> Result<()> {
    let entries = walk(release)?;
    let mut text = serde_json::to_string_pretty(&manifest(info, &entries))?;
    text.push('\n');
    write_file(&release.join(MANIFEST), text.as_bytes(), false)
}

/// Packs the release directory into `out` as a gzip-compressed tarball whose single top-level
/// directory is named after `release`. Returns the tarball's SHA-256.
pub fn write_tarball(release: &Path, out: &Path, mtime: u64) -> Result<String> {
    let Some(top) = release.file_name().and_then(|name| name.to_str()) else {
        bail!("{} has no usable directory name", release.display());
    };
    let entries = walk(release)?;
    let file = File::create(out).with_context(|| format!("failed to create {}", out.display()))?;
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(BufWriter::new(file), Compression::best());
    let mut tar = tar::Builder::new(gzip);
    tar.follow_symlinks(false);

    append_entry(&mut tar, release, top, &Kind::Dir, mtime)?;
    for entry in &entries {
        let path = format!("{top}/{}", entry.path);
        append_entry(
            &mut tar,
            &release.join(&entry.path),
            &path,
            &entry.kind,
            mtime,
        )?;
    }
    let gzip = tar.into_inner().context("failed to finish the tarball")?;
    let mut writer = gzip.finish().context("failed to finish gzip")?;
    writer.flush()?;
    drop(writer);
    sha256_file(out)
}

fn append_entry<W: Write>(
    tar: &mut tar::Builder<W>,
    source: &Path,
    path: &str,
    kind: &Kind,
    mtime: u64,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_mtime(mtime);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mode(kind.mode());
    match kind {
        Kind::Dir => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            tar.append_data(&mut header, format!("{path}/"), io::empty())?;
        }
        Kind::File { size, .. } => {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(*size);
            let file = File::open(source)
                .with_context(|| format!("failed to open {}", source.display()))?;
            tar.append_data(&mut header, path, file)?;
        }
        Kind::Symlink { target } => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            tar.append_link(&mut header, path, target)?;
        }
    }
    Ok(())
}

/// Rewrites `SHA256SUMS` in `out_dir` for every `agentpay-<version>-*.tar.gz` there, sorted by
/// name, in the `sha256sum` format (`<digest>  <name>`).
pub fn write_checksums(out_dir: &Path, version: &str) -> Result<PathBuf> {
    let prefix = format!("agentpay-{version}-");
    let mut lines = Vec::new();
    for item in std::fs::read_dir(out_dir)
        .with_context(|| format!("failed to list {}", out_dir.display()))?
    {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && name.ends_with(".tar.gz") && item.path().is_file() {
            lines.push((name, sha256_file(&item.path())?));
        }
    }
    let path = out_dir.join(CHECKSUMS);
    write_file(&path, checksums_text(lines).as_bytes(), false)?;
    Ok(path)
}

/// Formats `(name, digest)` pairs as a sorted `sha256sum` listing.
pub fn checksums_text(mut lines: Vec<(String, String)>) -> String {
    lines.sort();
    lines
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect()
}

/// Returns the release paths (outside `skip` prefixes) whose contents include any of
/// `needles`, such as the builder's home directory.
pub fn find_leaks(release: &Path, needles: &[String], skip: &[&str]) -> Result<Vec<String>> {
    let needles: Vec<&[u8]> = needles
        .iter()
        .map(String::as_bytes)
        .filter(|needle| needle.len() > 1)
        .collect();
    let mut leaks = Vec::new();
    for entry in walk(release)? {
        if !matches!(entry.kind, Kind::File { .. })
            || skip.iter().any(|prefix| entry.path.starts_with(prefix))
        {
            continue;
        }
        let contents = std::fs::read(release.join(&entry.path))?;
        if needles.iter().any(|needle| contains(&contents, needle)) {
            leaks.push(entry.path);
        }
    }
    Ok(leaks)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Lowercase hex SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Writes `contents` to `path` with mode 0755 or 0644.
pub fn write_file(path: &Path, contents: &[u8], executable: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    set_mode(path, executable)
}

/// Copies a regular file and normalizes its mode.
pub fn copy_file(source: &Path, dest: &Path, executable: bool) -> Result<()> {
    if !source.is_file() {
        bail!("{} is missing", source.display());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, dest)
        .with_context(|| format!("failed to copy {} to {}", source.display(), dest.display()))?;
    set_mode(dest, executable)
}

/// Copies a directory of regular files (symlinks are not followed and not allowed).
pub fn copy_tree(source: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in walk(source)? {
        let from = source.join(&entry.path);
        let to = dest.join(&entry.path);
        match entry.kind {
            Kind::Dir => std::fs::create_dir_all(&to)?,
            Kind::File { executable, .. } => copy_file(&from, &to, executable)?,
            Kind::Symlink { .. } => bail!("{} is a symlink", from.display()),
        }
    }
    Ok(())
}

fn set_mode(path: &Path, executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set the mode of {}", path.display()))
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
