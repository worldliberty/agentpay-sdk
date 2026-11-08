//! The Node.js runtime bundled with each release.
//!
//! The client is a Node program. Rather than requiring a suitable Node on every machine (the
//! old installer bootstrapped one through Homebrew), each release ships a pinned official Node
//! build: only `bin/node` and its `LICENSE`. The archives are downloaded from nodejs.org at
//! build time and must match the SHA-256 digests pinned below, which were taken from the
//! release's `SHASUMS256.txt`. To update Node, change [`NODE_VERSION`] and every digest
//! together.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;

use super::bundle::sha256_file;
use super::target::Target;

/// The bundled Node.js version (an active LTS line).
pub const NODE_VERSION: &str = "24.22.2";

/// SHA-256 of `node-v<NODE_VERSION>-<platform>.tar.gz` for each target.
fn pinned_sha256(target: Target) -> &'static str {
    match target {
        Target::MacosArm64 => "aa9549349e47dffaa42dcf95d6e06ade8c4bdafc980979883b88767670df385a",
        Target::MacosX86_64 => "d5e336d588c45be0c37dbd52cc29895593009ca4997a77a1fd02815131ed0e52",
        Target::LinuxX86_64 => "361718c444e49af2ca5a110c83ba6a8901143f23ab285ebbef0341f391f482a9",
        Target::LinuxArm64 => "95c264150aceb7f3437a29fd6984924f5f8d1511ea3cbd6c508b83f6c555dae2",
    }
}

/// The pinned Node.js build for one target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRuntime {
    /// Node.js version.
    pub version: &'static str,
    /// Upstream archive name, e.g. `node-v24.22.2-darwin-arm64.tar.gz`.
    pub archive: String,
    /// Download URL.
    pub url: String,
    /// Pinned SHA-256 of the archive.
    pub sha256: &'static str,
}

impl NodeRuntime {
    /// The pinned runtime for `target`.
    pub fn for_target(target: Target) -> Self {
        let stem = format!("node-v{NODE_VERSION}-{}", target.node_platform());
        Self {
            version: NODE_VERSION,
            url: format!("https://nodejs.org/dist/v{NODE_VERSION}/{stem}.tar.gz"),
            archive: format!("{stem}.tar.gz"),
            sha256: pinned_sha256(target),
        }
    }

    /// The archive's top-level directory.
    fn stem(&self) -> &str {
        self.archive.trim_end_matches(".tar.gz")
    }

    /// Returns the verified archive in `cache_dir`, downloading it when it is missing or does
    /// not match the pinned digest.
    pub fn fetch(&self, cache_dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(cache_dir)
            .with_context(|| format!("failed to create {}", cache_dir.display()))?;
        let archive = cache_dir.join(&self.archive);
        if archive.is_file() && sha256_file(&archive)? == self.sha256 {
            println!("dist: using cached {}", self.archive);
            return Ok(archive);
        }
        let partial = cache_dir.join(format!("{}.partial", self.archive));
        println!("dist: downloading {}", self.url);
        let status = Command::new("curl")
            .args([
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--retry",
                "3",
                "--output",
            ])
            .arg(&partial)
            .arg(&self.url)
            .status()
            .context("failed to run curl")?;
        if !status.success() {
            bail!("downloading {} failed with {status}", self.url);
        }
        let actual = sha256_file(&partial)?;
        if actual != self.sha256 {
            // Leave nothing behind that a later run could mistake for a good download.
            let _ = std::fs::remove_file(&partial);
            bail!(
                "{} has SHA-256 {actual}, expected the pinned {}",
                self.archive,
                self.sha256
            );
        }
        std::fs::rename(&partial, &archive)
            .with_context(|| format!("failed to move {}", archive.display()))?;
        Ok(archive)
    }

    /// Writes `bin/node` (mode 0755) and `LICENSE` from the verified `archive` into `dest`.
    pub fn extract(&self, archive: &Path, dest: &Path) -> Result<()> {
        if sha256_file(archive)? != self.sha256 {
            bail!("{} does not match the pinned SHA-256", archive.display());
        }
        let wanted = [
            (format!("{}/bin/node", self.stem()), "bin/node", 0o755),
            (format!("{}/LICENSE", self.stem()), "LICENSE", 0o644),
        ];
        let file =
            File::open(archive).with_context(|| format!("failed to open {}", archive.display()))?;
        let mut tar = tar::Archive::new(GzDecoder::new(BufReader::new(file)));
        let mut found = 0;
        for entry in tar
            .entries()
            .context("failed to read the Node.js archive")?
        {
            let mut entry = entry.context("failed to read the Node.js archive")?;
            let path = entry.path()?.to_string_lossy().into_owned();
            let Some((_, relative, mode)) = wanted.iter().find(|(name, _, _)| *name == path) else {
                continue;
            };
            if !entry.header().entry_type().is_file() {
                bail!("{path} in {} is not a regular file", self.archive);
            }
            let out_path = dest.join(relative);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = File::create(&out_path)
                .with_context(|| format!("failed to create {}", out_path.display()))?;
            io::copy(&mut entry, &mut out)?;
            set_mode(&out_path, *mode)?;
            found += 1;
        }
        if found != wanted.len() {
            bail!("{} is missing bin/node or LICENSE", self.archive);
        }
        Ok(())
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("failed to set the mode of {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_has_a_well_formed_pin() {
        for target in Target::ALL {
            let runtime = NodeRuntime::for_target(target);
            assert_eq!(runtime.sha256.len(), 64, "{target:?}");
            assert!(
                runtime
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{target:?}"
            );
            assert!(runtime.url.starts_with("https://nodejs.org/dist/v"));
            assert!(runtime.url.ends_with(&runtime.archive));
        }
        let digests: std::collections::BTreeSet<_> = Target::ALL
            .iter()
            .map(|t| NodeRuntime::for_target(*t).sha256)
            .collect();
        assert_eq!(digests.len(), Target::ALL.len(), "digests must differ");
    }

    #[test]
    fn bundled_node_satisfies_the_client_engines_range() {
        // client/package.json requires Node >= 20.
        let major: u32 = NODE_VERSION
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or(0);
        assert!(major >= 20, "{NODE_VERSION}");
        assert_eq!(major % 2, 0, "ship an LTS (even) Node.js line");
    }

    #[test]
    fn client_is_developed_and_tested_on_the_bundled_node_major() {
        // CI and the release workflow read client/.nvmrc, so it must name the shipped major.
        let nvmrc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../client/.nvmrc"),
        )
        .unwrap();
        let bundled_major = NODE_VERSION.split('.').next().unwrap();
        assert_eq!(nvmrc.trim().split('.').next(), Some(bundled_major));
    }

    #[test]
    fn extract_rejects_an_archive_that_is_not_the_pinned_one() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("fake.tar.gz");
        std::fs::write(&archive, b"not node").unwrap();
        let runtime = NodeRuntime::for_target(Target::LinuxX86_64);
        let error = runtime.extract(&archive, dir.path()).unwrap_err();
        assert!(error.to_string().contains("pinned SHA-256"), "{error:#}");
    }
}
