//! Builds `agentpay-auth`, the Swift helper that keeps the macOS admin key in the Secure
//! Enclave (`native/macos/AgentPayAuth.swift`).
//!
//! The helper is a single Swift file compiled with `xcrun swiftc`; there is no Xcode project
//! and no Swift package. Building several architectures produces a universal binary via
//! `lipo`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};

/// The helper's source, relative to the repository root.
pub const SOURCE: &str = "native/macos/AgentPayAuth.swift";
/// File name of the built helper.
pub const BINARY_NAME: &str = "agentpay-auth";
/// Oldest macOS release the helper supports.
const MACOS_DEPLOYMENT_TARGET: &str = "13";

/// CPU architectures the helper can be built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Arch {
    /// Apple silicon.
    #[value(name = "arm64")]
    Arm64,
    /// Intel.
    #[value(name = "x86_64")]
    X86_64,
}

impl Arch {
    /// The architecture name Apple's toolchain uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::X86_64 => "x86_64",
        }
    }

    /// The architecture this xtask was compiled for, if the helper supports it.
    pub fn host() -> Option<Self> {
        match std::env::consts::ARCH {
            "aarch64" => Some(Self::Arm64),
            "x86_64" => Some(Self::X86_64),
            _ => None,
        }
    }

    /// The `swiftc -target` triple, e.g. `arm64-apple-macos13`.
    pub fn target_triple(self) -> String {
        format!("{}-apple-macos{MACOS_DEPLOYMENT_TARGET}", self.as_str())
    }
}

/// Cargo-style output profile: selects `target/debug` or `target/release`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Write to `target/debug`.
    Debug,
    /// Write to `target/release`.
    Release,
}

impl Profile {
    fn dir_name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

/// Options shared by `build-macos-auth` and `test-macos-auth`.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Architecture to build. Repeat it (`--arch arm64 --arch x86_64`) for a universal
    /// binary. Defaults to the host architecture.
    #[arg(long = "arch", value_enum)]
    pub archs: Vec<Arch>,
    /// Profile directory under `target/` that receives the binary. The helper is always
    /// compiled with optimizations.
    #[arg(long, value_enum, default_value_t = Profile::Release)]
    pub profile: Profile,
}

impl BuildArgs {
    /// The requested architectures, sorted and deduplicated, or the host architecture.
    fn resolved_archs(&self) -> Result<Vec<Arch>> {
        let mut archs = if self.archs.is_empty() {
            vec![Arch::host().context("unsupported host architecture; pass --arch")?]
        } else {
            self.archs.clone()
        };
        archs.sort_unstable();
        archs.dedup();
        Ok(archs)
    }
}

/// Builds the helper and returns the path of the binary.
pub fn build(root: &Path, args: &BuildArgs) -> Result<PathBuf> {
    if !cfg!(target_os = "macos") {
        bail!("{BINARY_NAME} can only be built on macOS");
    }
    let archs = args.resolved_archs()?;
    let source = root.join(SOURCE);
    let out_dir = target_dir(root).join(args.profile.dir_name());
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let output = out_dir.join(BINARY_NAME);

    if let [arch] = archs.as_slice() {
        compile(&source, *arch, &output)?;
    } else {
        let slices_dir = out_dir.join(format!("{BINARY_NAME}-slices"));
        std::fs::create_dir_all(&slices_dir)
            .with_context(|| format!("failed to create {}", slices_dir.display()))?;
        let mut slices = Vec::with_capacity(archs.len());
        for arch in archs {
            let slice = slices_dir.join(format!("{BINARY_NAME}-{}", arch.as_str()));
            compile(&source, arch, &slice)?;
            slices.push(slice);
        }
        let mut lipo = Command::new("xcrun");
        lipo.args(["lipo", "-create", "-output"])
            .arg(&output)
            .args(&slices);
        run(&mut lipo)?;
    }
    Ok(output)
}

/// The cargo target directory: `$CARGO_TARGET_DIR` when set, otherwise `<root>/target`.
pub fn target_dir(root: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) if !dir.is_empty() => root.join(dir),
        _ => root.join("target"),
    }
}

fn compile(source: &Path, arch: Arch, output: &Path) -> Result<()> {
    let mut swiftc = Command::new("xcrun");
    swiftc.args(swiftc_args(source, arch, output));
    run(&mut swiftc)
}

/// Arguments for `xcrun`: Swift 6 language mode with warnings as errors, so the helper keeps
/// compiling cleanly under strict concurrency checking.
fn swiftc_args(source: &Path, arch: Arch, output: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        "swiftc",
        "-O",
        "-swift-version",
        "6",
        "-warnings-as-errors",
        "-target",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.push(arch.target_triple().into());
    args.push(source.into());
    args.push("-o".into());
    args.push(output.into());
    args
}

fn run(command: &mut Command) -> Result<()> {
    let rendered = format!("{command:?}");
    println!("+ {rendered}");
    let status = command
        .status()
        .with_context(|| format!("failed to run {rendered}"))?;
    if !status.success() {
        bail!("{rendered} failed with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_triples_use_the_deployment_target() {
        assert_eq!(Arch::Arm64.target_triple(), "arm64-apple-macos13");
        assert_eq!(Arch::X86_64.target_triple(), "x86_64-apple-macos13");
    }

    #[test]
    fn archs_default_to_host_and_are_deduplicated() {
        let host = BuildArgs {
            archs: Vec::new(),
            profile: Profile::Release,
        };
        if let Some(arch) = Arch::host() {
            assert_eq!(host.resolved_archs().ok(), Some(vec![arch]));
        }
        let universal = BuildArgs {
            archs: vec![Arch::X86_64, Arch::Arm64, Arch::X86_64],
            profile: Profile::Debug,
        };
        assert_eq!(
            universal.resolved_archs().ok(),
            Some(vec![Arch::Arm64, Arch::X86_64])
        );
    }

    #[test]
    fn swiftc_invocation_targets_the_arch_and_output() {
        let args = swiftc_args(Path::new("a.swift"), Arch::Arm64, Path::new("out/bin"));
        let args: Vec<&str> = args.iter().filter_map(|arg| arg.to_str()).collect();
        assert_eq!(
            args,
            [
                "swiftc",
                "-O",
                "-swift-version",
                "6",
                "-warnings-as-errors",
                "-target",
                "arm64-apple-macos13",
                "a.swift",
                "-o",
                "out/bin"
            ]
        );
    }
}
