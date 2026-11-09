//! Release fixtures for `test-install`: a GitHub-like download tree in a temp directory.
//!
//! ```text
//! <releases>/download/v<version>/<asset>, SHA256SUMS
//! <releases>/latest/download/<asset>, SHA256SUMS
//! ```
//!
//! The installer reads it through `AGENTPAY_RELEASES_URL=file://<releases>`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::dist::bundle::{self, Inputs, ReleaseInfo, CHECKSUMS};
use crate::dist::target::Target;

/// A release tree on disk.
pub struct Releases {
    /// Root of the tree.
    pub root: PathBuf,
}

impl Releases {
    /// An empty tree at `root`.
    pub fn new(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// `file://` URL of the tree.
    pub fn url(&self) -> String {
        format!("file://{}", self.root.display())
    }

    /// Directory of one tagged release.
    pub fn tag_dir(&self, version: &str) -> PathBuf {
        self.root.join("download").join(format!("v{version}"))
    }

    /// Publishes `tarball` as `version`, optionally also as the latest release.
    pub fn publish(&self, version: &str, tarball: &Path, latest: bool) -> Result<()> {
        let Some(name) = tarball.file_name() else {
            bail!("{} has no file name", tarball.display());
        };
        let mut dirs = vec![self.tag_dir(version)];
        if latest {
            dirs.push(self.root.join("latest").join("download"));
        }
        for dir in dirs {
            std::fs::create_dir_all(&dir)?;
            std::fs::copy(tarball, dir.join(name))
                .with_context(|| format!("failed to copy {}", tarball.display()))?;
            bundle::write_checksums(&dir, version)?;
        }
        Ok(())
    }

    /// Path of a published file.
    pub fn file(&self, version: &str, name: &str) -> PathBuf {
        self.tag_dir(version).join(name)
    }

    /// Path of a release's SHA256SUMS.
    pub fn checksums(&self, version: &str) -> PathBuf {
        self.file(version, CHECKSUMS)
    }
}

/// Builds a small release for `target` whose programs are shell stubs. Its `node` answers
/// `--version` with `version`, so the launcher and the installer's start check work end to end.
pub fn synthetic_release(
    root: &Path,
    work: &Path,
    version: &str,
    target: Target,
) -> Result<PathBuf> {
    let inputs_dir = work.join(format!("inputs-{version}"));
    let mut binaries = Vec::new();
    let mut names = target.cargo_binaries();
    if target.os() == crate::dist::target::Os::Macos {
        names.push("agentpay-auth");
    }
    for name in names {
        let path = inputs_dir.join("libexec").join(name);
        let script = format!("#!/bin/sh\necho \"{name} {version}\"\n");
        bundle::write_file(&path, script.as_bytes(), true)?;
        binaries.push((name.to_owned(), path));
    }
    let client = inputs_dir.join("client");
    let package = format!("{{\n  \"name\": \"agentpay\",\n  \"version\": \"{version}\"\n}}\n");
    bundle::write_file(&client.join("package.json"), package.as_bytes(), false)?;
    bundle::write_file(&client.join("package-lock.json"), b"{}\n", false)?;
    bundle::write_file(
        &client.join("dist/cli.js"),
        b"// synthetic client for cargo xtask test-install\n",
        false,
    )?;
    let node = inputs_dir.join("node");
    let stub = format!(
        "#!/bin/sh\n# Synthetic node for cargo xtask test-install.\n\
         for arg in \"$@\"; do\n  if [ \"$arg\" = --version ]; then echo {version}; exit 0; fi\n\
         done\necho \"stub node $*\"\n"
    );
    bundle::write_file(&node.join("bin/node"), stub.as_bytes(), true)?;
    bundle::write_file(&node.join("LICENSE"), b"synthetic\n", false)?;

    let stage = work.join(format!("stage-{version}"));
    if stage.exists() {
        std::fs::remove_dir_all(&stage)?;
    }
    let release = stage.join(target.release_name(version));
    bundle::assemble(
        &release,
        &Inputs {
            binaries,
            client_package: client.clone(),
            client_dist: client.join("dist"),
            node,
            license: root.join("LICENSE"),
        },
    )?;
    let info = ReleaseInfo {
        version: version.to_owned(),
        target,
        commit: "synthetic".into(),
        dirty: false,
        source_date_epoch: 0,
        node_version: "synthetic".into(),
    };
    bundle::write_manifest(&release, &info)?;
    let tarball = work.join(target.asset_name(version));
    bundle::write_tarball(&release, &tarball, 0)?;
    Ok(tarball)
}
