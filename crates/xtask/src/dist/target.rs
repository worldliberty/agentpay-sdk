//! The release targets `cargo xtask dist` can build, and how each one is named.

use anyhow::{bail, Result};

/// A supported release target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// macOS on Apple silicon.
    MacosArm64,
    /// macOS on Intel.
    MacosX86_64,
    /// Linux (glibc) on x86_64.
    LinuxX86_64,
    /// Linux (glibc) on arm64.
    LinuxArm64,
}

/// Operating system of a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    /// macOS.
    Macos,
    /// Linux.
    Linux,
}

/// Daemon and helper binaries built by cargo on every platform, installed into `libexec/`.
const CARGO_BINARIES: &[&str] = &["agentpay-daemon", "agentpay-paymentd", "agentpay-setup"];
/// The macOS System Keychain helper (`agentpay-setup` installs it on macOS only).
pub const KEYCHAIN_HELPER: &str = "agentpay-system-keychain";

impl Target {
    /// Every supported target, in release order.
    pub const ALL: [Self; 4] = [
        Self::MacosArm64,
        Self::MacosX86_64,
        Self::LinuxX86_64,
        Self::LinuxArm64,
    ];

    /// The Rust target triple.
    pub fn triple(self) -> &'static str {
        match self {
            Self::MacosArm64 => "aarch64-apple-darwin",
            Self::MacosX86_64 => "x86_64-apple-darwin",
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Self::LinuxArm64 => "aarch64-unknown-linux-gnu",
        }
    }

    /// Parses a Rust target triple.
    pub fn parse(triple: &str) -> Result<Self> {
        match Self::ALL
            .into_iter()
            .find(|target| target.triple() == triple)
        {
            Some(target) => Ok(target),
            None => {
                let supported: Vec<&str> = Self::ALL.iter().map(|t| t.triple()).collect();
                bail!(
                    "unsupported target {triple}; supported: {}",
                    supported.join(", ")
                )
            }
        }
    }

    /// The target matching this machine.
    pub fn host() -> Result<Self> {
        Self::from_os_arch(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// The target for Rust's `std::env::consts::{OS, ARCH}` values.
    fn from_os_arch(os: &str, arch: &str) -> Result<Self> {
        match (os, arch) {
            ("macos", "aarch64") => Ok(Self::MacosArm64),
            ("macos", "x86_64") => Ok(Self::MacosX86_64),
            ("linux", "x86_64") => Ok(Self::LinuxX86_64),
            ("linux", "aarch64") => Ok(Self::LinuxArm64),
            _ => bail!("AgentPay releases are not built for {os}/{arch}"),
        }
    }

    /// Operating system.
    pub fn os(self) -> Os {
        match self {
            Self::MacosArm64 | Self::MacosX86_64 => Os::Macos,
            Self::LinuxX86_64 | Self::LinuxArm64 => Os::Linux,
        }
    }

    /// OS name used in asset names and by the installer (`uname -s`, normalized).
    pub fn os_label(self) -> &'static str {
        match self.os() {
            Os::Macos => "macos",
            Os::Linux => "linux",
        }
    }

    /// CPU name used in asset names and by the installer (`uname -m`, normalized).
    pub fn arch_label(self) -> &'static str {
        match self {
            Self::MacosArm64 | Self::LinuxArm64 => "arm64",
            Self::MacosX86_64 | Self::LinuxX86_64 => "x86_64",
        }
    }

    /// Node.js's platform name in its release file names.
    pub fn node_platform(self) -> &'static str {
        match self {
            Self::MacosArm64 => "darwin-arm64",
            Self::MacosX86_64 => "darwin-x64",
            Self::LinuxX86_64 => "linux-x64",
            Self::LinuxArm64 => "linux-arm64",
        }
    }

    /// Binaries cargo builds for this target, all installed into `libexec/`.
    pub fn cargo_binaries(self) -> Vec<&'static str> {
        let mut binaries = CARGO_BINARIES.to_vec();
        if self.os() == Os::Macos {
            binaries.push(KEYCHAIN_HELPER);
        }
        binaries.sort_unstable();
        binaries
    }

    /// Name of the release directory and tarball stem: `agentpay-<version>-<os>-<arch>`.
    pub fn release_name(self, version: &str) -> String {
        format!(
            "agentpay-{version}-{}-{}",
            self.os_label(),
            self.arch_label()
        )
    }

    /// File name of the release tarball.
    pub fn asset_name(self, version: &str) -> String {
        format!("{}.tar.gz", self.release_name(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triples_round_trip() {
        for target in Target::ALL {
            assert_eq!(Target::parse(target.triple()).ok(), Some(target));
        }
        assert!(Target::parse("x86_64-pc-windows-msvc").is_err());
        assert!(Target::parse("x86_64-unknown-linux-musl").is_err());
    }

    #[test]
    fn asset_names_match_what_the_installer_derives_from_uname() {
        assert_eq!(
            Target::MacosArm64.asset_name("0.6.0"),
            "agentpay-0.6.0-macos-arm64.tar.gz"
        );
        assert_eq!(
            Target::MacosX86_64.asset_name("0.6.0"),
            "agentpay-0.6.0-macos-x86_64.tar.gz"
        );
        assert_eq!(
            Target::LinuxX86_64.asset_name("1.0.0-rc.1"),
            "agentpay-1.0.0-rc.1-linux-x86_64.tar.gz"
        );
        assert_eq!(
            Target::LinuxArm64.release_name("0.6.0"),
            "agentpay-0.6.0-linux-arm64"
        );
    }

    #[test]
    fn host_mapping_covers_supported_platforms() {
        assert_eq!(
            Target::from_os_arch("macos", "aarch64").ok(),
            Some(Target::MacosArm64)
        );
        assert_eq!(
            Target::from_os_arch("linux", "x86_64").ok(),
            Some(Target::LinuxX86_64)
        );
        assert!(Target::from_os_arch("windows", "x86_64").is_err());
        assert!(Target::from_os_arch("linux", "riscv64").is_err());
    }

    #[test]
    fn keychain_helper_ships_on_macos_only() {
        assert_eq!(
            Target::MacosArm64.cargo_binaries(),
            [
                "agentpay-daemon",
                "agentpay-paymentd",
                "agentpay-setup",
                "agentpay-system-keychain"
            ]
        );
        assert_eq!(
            Target::LinuxArm64.cargo_binaries(),
            ["agentpay-daemon", "agentpay-paymentd", "agentpay-setup"]
        );
    }
}
