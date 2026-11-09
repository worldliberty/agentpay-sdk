//! Where the managed daemon lives on each supported platform.
//!
//! The paths and labels match what the previous TypeScript installer used
//! (`managed-daemon-platform.ts`), so an existing install is upgraded in place.

use std::path::{Path, PathBuf};

/// System Keychain used for the macOS machine secret.
pub const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
/// Keychain service of the machine secret (macOS).
pub const SECRET_KEYCHAIN_SERVICE: &str = "agentpay-daemon-secret";
/// Keychain account of the machine secret. The secret is per machine, not per user.
pub const SECRET_KEYCHAIN_ACCOUNT: &str = "agentpay";
/// Keychain service under which older releases stored the vault password (macOS).
pub const LEGACY_KEYCHAIN_SERVICE: &str = "agentpay-daemon-password";
/// File name of the daemon binary.
pub const DAEMON_BIN: &str = "agentpay-daemon";
/// File name of the macOS System Keychain helper binary.
pub const KEYCHAIN_HELPER_BIN: &str = "agentpay-system-keychain";
/// File name of the service runner script.
pub const RUNNER_SCRIPT: &str = "run-agentpay-daemon.sh";
/// File name of the payments service binary.
pub const PAYMENTD_BIN: &str = "agentpay-paymentd";

/// Supported service platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// macOS with launchd and the System Keychain.
    Macos,
    /// Linux with systemd and a root-only secret file.
    Linux,
}

impl Platform {
    /// The platform this binary was compiled for, if supported.
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

/// Where a root-only secret is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretLocation {
    /// Generic-password item in the macOS System Keychain.
    Keychain {
        /// Item service attribute.
        service: String,
        /// Item account attribute.
        account: String,
    },
    /// Root-owned `0600` file.
    File {
        /// File path.
        path: PathBuf,
    },
}

impl SecretLocation {
    /// Short human description, e.g. for step details.
    pub fn describe(&self) -> String {
        match self {
            Self::Keychain { service, .. } => format!("System Keychain ({service})"),
            Self::File { path } => path.display().to_string(),
        }
    }
}

/// A file installed into the managed bin directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBinary {
    /// File name inside both the source and the managed bin directory.
    pub name: &'static str,
    /// Mode of the installed copy.
    pub mode: u32,
}

/// Where the unprivileged payments service (`agentpay-paymentd`) lives.
///
/// It runs as [`Layout::service_user`], so its socket directory, state
/// directory and log directory are owned by that account, not by root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentsLayout {
    /// launchd label or systemd unit name (without `.service`).
    pub label: &'static str,
    /// Socket directory, owned by the service account.
    pub run_dir: PathBuf,
    /// Payments socket.
    pub socket: PathBuf,
    /// Private state directory (holds `config.json`), owned by the service account.
    pub state_dir: PathBuf,
    /// Log directory owned by the service account (macOS; systemd uses the journal).
    pub log_dir: Option<PathBuf>,
    /// launchd plist or systemd unit path.
    pub service_file: PathBuf,
}

/// One launchd job or systemd unit managed by the installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUnit<'a> {
    /// Target platform.
    pub platform: Platform,
    /// launchd label or systemd unit name (without `.service`).
    pub label: &'a str,
    /// launchd plist or systemd unit path.
    pub service_file: &'a Path,
}

/// Every path, label and name the installer touches on one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Target platform.
    pub platform: Platform,
    /// launchd label or systemd unit name (without `.service`).
    pub label: &'static str,
    /// Root-owned install prefix.
    pub prefix: PathBuf,
    /// Root-owned directory holding the daemon, helpers and runner.
    pub bin_dir: PathBuf,
    /// Directory of the daemon socket.
    pub run_dir: PathBuf,
    /// Daemon socket path.
    pub socket: PathBuf,
    /// Root-only state directory.
    pub state_dir: PathBuf,
    /// Encrypted daemon state file.
    pub state_file: PathBuf,
    /// Root-only log directory (macOS; systemd uses the journal).
    pub log_dir: Option<PathBuf>,
    /// launchd plist or systemd unit path.
    pub service_file: PathBuf,
    /// Install manifest written after a successful install.
    pub manifest: PathBuf,
    /// Machine secret location.
    pub secret: SecretLocation,
    /// Name of the unprivileged payments service account.
    pub service_user: &'static str,
    /// Files copied from the source bin directory (the runner is embedded separately).
    pub binaries: Vec<ManagedBinary>,
    /// The payments service.
    pub payments: PaymentsLayout,
}

impl Layout {
    /// The production layout for `platform`.
    pub fn for_platform(platform: Platform) -> Self {
        match platform {
            Platform::Macos => Self {
                platform,
                label: "com.agentpay.daemon",
                prefix: "/Library/AgentPay".into(),
                bin_dir: "/Library/AgentPay/bin".into(),
                run_dir: "/Library/AgentPay/run".into(),
                socket: "/Library/AgentPay/run/daemon.sock".into(),
                state_dir: "/var/db/agentpay".into(),
                state_file: "/var/db/agentpay/daemon-state.enc".into(),
                log_dir: Some("/var/log/agentpay".into()),
                service_file: "/Library/LaunchDaemons/com.agentpay.daemon.plist".into(),
                manifest: "/Library/AgentPay/install.json".into(),
                secret: SecretLocation::Keychain {
                    service: SECRET_KEYCHAIN_SERVICE.into(),
                    account: SECRET_KEYCHAIN_ACCOUNT.into(),
                },
                service_user: "_agentpay",
                binaries: vec![
                    ManagedBinary {
                        name: DAEMON_BIN,
                        mode: 0o755,
                    },
                    ManagedBinary {
                        name: KEYCHAIN_HELPER_BIN,
                        mode: 0o700,
                    },
                    ManagedBinary {
                        name: PAYMENTD_BIN,
                        mode: 0o755,
                    },
                ],
                payments: PaymentsLayout {
                    label: "com.agentpay.paymentd",
                    run_dir: "/Library/AgentPay/run/paymentd".into(),
                    socket: "/Library/AgentPay/run/paymentd/paymentd.sock".into(),
                    state_dir: "/var/db/agentpay-paymentd".into(),
                    log_dir: Some("/var/log/agentpay-paymentd".into()),
                    service_file: "/Library/LaunchDaemons/com.agentpay.paymentd.plist".into(),
                },
            },
            Platform::Linux => Self {
                platform,
                label: "agentpay-daemon",
                prefix: "/opt/agentpay".into(),
                bin_dir: "/opt/agentpay/bin".into(),
                run_dir: "/run/agentpay".into(),
                socket: "/run/agentpay/daemon.sock".into(),
                state_dir: "/var/lib/agentpay".into(),
                state_file: "/var/lib/agentpay/daemon-state.enc".into(),
                log_dir: None,
                service_file: "/etc/systemd/system/agentpay-daemon.service".into(),
                manifest: "/opt/agentpay/install.json".into(),
                secret: SecretLocation::File {
                    path: "/var/lib/agentpay/daemon-secret".into(),
                },
                service_user: "agentpay",
                binaries: vec![
                    ManagedBinary {
                        name: DAEMON_BIN,
                        mode: 0o700,
                    },
                    // Executed by the payments service account, so it must be world-executable.
                    ManagedBinary {
                        name: PAYMENTD_BIN,
                        mode: 0o755,
                    },
                ],
                payments: PaymentsLayout {
                    label: "agentpay-paymentd",
                    run_dir: "/run/agentpay-paymentd".into(),
                    socket: "/run/agentpay-paymentd/paymentd.sock".into(),
                    state_dir: "/var/lib/agentpay-paymentd".into(),
                    log_dir: None,
                    service_file: "/etc/systemd/system/agentpay-paymentd.service".into(),
                },
            },
        }
    }

    /// Where older releases stored the vault password. On macOS the item is keyed by the
    /// account name of the user who ran setup, so `user` is required to locate it.
    pub fn legacy_secret(&self, user: &str) -> SecretLocation {
        match self.platform {
            Platform::Macos => SecretLocation::Keychain {
                service: LEGACY_KEYCHAIN_SERVICE.into(),
                account: user.into(),
            },
            Platform::Linux => SecretLocation::File {
                path: self.state_dir.join("daemon-password"),
            },
        }
    }

    /// Path of a managed binary inside the root-owned bin directory.
    pub fn managed(&self, name: &str) -> PathBuf {
        self.bin_dir.join(name)
    }

    /// Managed daemon binary.
    pub fn daemon_bin(&self) -> PathBuf {
        self.managed(DAEMON_BIN)
    }

    /// Managed payments service binary.
    pub fn paymentd_bin(&self) -> PathBuf {
        self.managed(PAYMENTD_BIN)
    }

    /// The root signer daemon's service unit.
    pub fn signer_unit(&self) -> ServiceUnit<'_> {
        ServiceUnit {
            platform: self.platform,
            label: self.label,
            service_file: &self.service_file,
        }
    }

    /// The payments service's unit.
    pub fn payments_unit(&self) -> ServiceUnit<'_> {
        ServiceUnit {
            platform: self.platform,
            label: self.payments.label,
            service_file: &self.payments.service_file,
        }
    }

    /// Directories owned by the payments service account, with their modes, in
    /// creation order. On Linux systemd creates them (`StateDirectory=`,
    /// `RuntimeDirectory=`) with the unit's `User=`, so there are none.
    pub fn payments_directories(&self) -> Vec<(PathBuf, u32)> {
        if self.platform != Platform::Macos {
            return Vec::new();
        }
        let mut dirs = vec![
            (self.payments.run_dir.clone(), 0o755),
            (self.payments.state_dir.clone(), 0o700),
        ];
        if let Some(log_dir) = &self.payments.log_dir {
            dirs.push((log_dir.clone(), 0o700));
        }
        dirs
    }

    /// Managed runner script.
    pub fn runner(&self) -> PathBuf {
        self.managed(RUNNER_SCRIPT)
    }

    /// Managed keychain helper (macOS only).
    pub fn keychain_helper(&self) -> Option<PathBuf> {
        (self.platform == Platform::Macos).then(|| self.managed(KEYCHAIN_HELPER_BIN))
    }

    /// Root-owned copy of the keychain helper an older release installed (macOS only).
    ///
    /// The legacy vault-password item's ACL trusts that helper's code hash (not its path), and a
    /// new helper build cannot read it. Install keeps the old binary here until the legacy
    /// password has been migrated, so a failed or interrupted migration can still be retried.
    pub fn previous_keychain_helper(&self) -> Option<PathBuf> {
        (self.platform == Platform::Macos)
            .then(|| self.bin_dir.join("previous").join(KEYCHAIN_HELPER_BIN))
    }

    /// Present while the services may still run binaries older than those installed: written
    /// before binaries are replaced, removed once both services have restarted. A setup that
    /// stops in between leaves it, so the next one restarts the services even though the
    /// binaries already look up to date.
    pub fn restart_marker(&self) -> PathBuf {
        self.bin_dir.join(".restart-pending")
    }

    /// Directories created by install, with their modes, in creation order.
    pub fn directories(&self) -> Vec<(PathBuf, u32)> {
        let mut dirs = vec![
            (self.prefix.clone(), 0o755),
            (self.bin_dir.clone(), 0o755),
            (self.state_dir.clone(), 0o700),
        ];
        // On Linux systemd owns /run/agentpay through RuntimeDirectory=, recreating it per boot.
        if self.platform == Platform::Macos {
            dirs.push((self.run_dir.clone(), 0o755));
        }
        if let Some(log_dir) = &self.log_dir {
            dirs.push((log_dir.clone(), 0o700));
        }
        dirs
    }

    /// Runner script embedded in this binary, so the runner always matches the installer.
    pub fn runner_script(&self) -> &'static str {
        match self.platform {
            Platform::Macos => include_str!("../../../scripts/launchd/run-agentpay-daemon.sh"),
            Platform::Linux => include_str!("../../../scripts/systemd/run-agentpay-daemon.sh"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn layouts_keep_legacy_paths_for_in_place_upgrades() {
        let mac = Layout::for_platform(Platform::Macos);
        assert_eq!(mac.socket, Path::new("/Library/AgentPay/run/daemon.sock"));
        assert_eq!(
            mac.state_file,
            Path::new("/var/db/agentpay/daemon-state.enc")
        );
        assert_eq!(
            mac.legacy_secret("alice"),
            SecretLocation::Keychain {
                service: "agentpay-daemon-password".into(),
                account: "alice".into()
            }
        );
        let linux = Layout::for_platform(Platform::Linux);
        assert_eq!(linux.socket, Path::new("/run/agentpay/daemon.sock"));
        assert_eq!(
            linux.legacy_secret("alice"),
            SecretLocation::File {
                path: "/var/lib/agentpay/daemon-password".into()
            }
        );
        assert!(linux.keychain_helper().is_none());
    }

    #[test]
    fn payments_service_lives_beside_the_signer_but_owns_its_directories() {
        let mac = Layout::for_platform(Platform::Macos);
        assert_eq!(
            mac.payments.socket,
            Path::new("/Library/AgentPay/run/paymentd/paymentd.sock")
        );
        assert!(mac.payments.socket.starts_with(&mac.payments.run_dir));
        assert!(mac.payments.run_dir.starts_with(&mac.run_dir));
        assert_eq!(mac.payments_directories().len(), 3);
        let linux = Layout::for_platform(Platform::Linux);
        assert_eq!(
            linux.payments.socket,
            Path::new("/run/agentpay-paymentd/paymentd.sock")
        );
        // A separate runtime directory: systemd removes /run/agentpay when the signer stops.
        assert!(!linux.payments.run_dir.starts_with(&linux.run_dir));
        assert!(linux.payments_directories().is_empty());
        for layout in [mac, linux] {
            let paymentd = layout.binaries.iter().find(|b| b.name == PAYMENTD_BIN);
            assert_eq!(paymentd.map(|b| b.mode), Some(0o755));
            assert_ne!(layout.signer_unit().label, layout.payments_unit().label);
        }
    }

    #[test]
    fn runner_scripts_use_the_state_secret_flag() {
        for platform in [Platform::Macos, Platform::Linux] {
            let script = Layout::for_platform(platform).runner_script();
            assert!(script.contains("--state-secret-stdin"));
            assert!(!script.contains("vault-password"));
        }
    }
}
