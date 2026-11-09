//! The launchd/systemd service definition and service-manager operations.
//!
//! The definition only references the root-owned runner script and non-secret configuration;
//! the runner fetches the machine secret from root-only storage at start and hands it to the
//! daemon on stdin (see `scripts/launchd/run-agentpay-daemon.sh` and
//! `scripts/systemd/run-agentpay-daemon.sh`).

use std::time::Duration;

use anyhow::{bail, Result};
use serde::Serialize;

use crate::layout::{Layout, Platform, SecretLocation, ServiceUnit, SYSTEM_KEYCHAIN};
use crate::system::{run_checked, stderr_suffix, Cmd, System};

/// How many times `launchctl bootstrap` is attempted; a bootout that is still settling makes the
/// first attempt fail with an I/O error.
const BOOTSTRAP_ATTEMPTS: u32 = 5;

/// Non-secret daemon configuration baked into the service definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// Non-root uids allowed to call admin RPCs.
    pub admin_uids: Vec<u32>,
    /// Non-root uids allowed to call agent RPCs.
    pub agent_uids: Vec<u32>,
}

/// Observed service state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct ServiceState {
    /// Loaded into launchd / enabled in systemd.
    pub loaded: bool,
    /// The daemon process is running.
    pub running: bool,
}

fn join_uids(uids: &[u32]) -> String {
    uids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Environment passed to the runner script, in a stable order.
fn environment(layout: &Layout, config: &DaemonConfig) -> Vec<(&'static str, String)> {
    let mut env = vec![
        (
            "AGENTPAY_DAEMON_BIN",
            layout.daemon_bin().display().to_string(),
        ),
        (
            "AGENTPAY_STATE_FILE",
            layout.state_file.display().to_string(),
        ),
        (
            "AGENTPAY_DAEMON_SOCKET",
            layout.socket.display().to_string(),
        ),
    ];
    match &layout.secret {
        SecretLocation::Keychain { service, account } => {
            if let Some(helper) = layout.keychain_helper() {
                env.push(("AGENTPAY_KEYCHAIN_HELPER", helper.display().to_string()));
            }
            env.push(("AGENTPAY_KEYCHAIN", SYSTEM_KEYCHAIN.to_string()));
            env.push(("AGENTPAY_KEYCHAIN_SERVICE", service.clone()));
            env.push(("AGENTPAY_KEYCHAIN_ACCOUNT", account.clone()));
        }
        SecretLocation::File { path } => {
            env.push(("AGENTPAY_SECRET_FILE", path.display().to_string()));
        }
    }
    env.push(("AGENTPAY_SIGNER_BACKEND", "software".to_string()));
    env.push(("AGENTPAY_ALLOW_ADMIN_EUID", join_uids(&config.admin_uids)));
    env.push(("AGENTPAY_ALLOW_AGENT_EUID", join_uids(&config.agent_uids)));
    env
}

/// Escapes a value for a plist `<string>`.
pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Quotes a value for a systemd unit line, neutralising `%` specifiers.
pub(crate) fn systemd_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    format!("\"{escaped}\"")
}

/// Renders the launchd plist or systemd unit for `layout`.
pub fn render_definition(layout: &Layout, config: &DaemonConfig) -> String {
    let env = environment(layout, config);
    match layout.platform {
        Platform::Macos => render_plist(layout, &env),
        Platform::Linux => render_unit(layout, &env),
    }
}

fn render_plist(layout: &Layout, env: &[(&'static str, String)]) -> String {
    let log_dir = layout
        .log_dir
        .as_ref()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|| "/var/log".into());
    let label = layout.label;
    let mut env_xml = String::new();
    for (key, value) in env {
        env_xml.push_str(&format!(
            "      <key>{key}</key>\n      <string>{}</string>\n",
            xml_escape(value)
        ));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{runner}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
{env_xml}    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>Umask</key>
    <integer>63</integer>
    <key>WorkingDirectory</key>
    <string>{state_dir}</string>
    <key>StandardOutPath</key>
    <string>{log_dir}/{label}.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/{label}.err.log</string>
  </dict>
</plist>
"#,
        runner = xml_escape(&layout.runner().display().to_string()),
        state_dir = xml_escape(&layout.state_dir.display().to_string()),
        log_dir = xml_escape(&log_dir),
    )
}

fn render_unit(layout: &Layout, env: &[(&'static str, String)]) -> String {
    let env_lines: String = env
        .iter()
        .map(|(key, value)| format!("Environment={}\n", systemd_quote(&format!("{key}={value}"))))
        .collect();
    let dir_name = |path: &std::path::Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "agentpay".into())
    };
    format!(
        "[Unit]
Description=AgentPay signing daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
{env_lines}ExecStart={runner}
Restart=always
RestartSec=2
StateDirectory={state}
StateDirectoryMode=0700
RuntimeDirectory={run}
RuntimeDirectoryMode=0755
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
",
        runner = systemd_quote(&layout.runner().display().to_string()),
        state = dir_name(&layout.state_dir),
        run = dir_name(&layout.run_dir),
    )
}

fn launchd_target(unit: &ServiceUnit<'_>) -> String {
    format!("system/{}", unit.label)
}

fn systemd_unit(unit: &ServiceUnit<'_>) -> String {
    format!("{}.service", unit.label)
}

/// Queries the service manager about `unit`.
pub fn state(sys: &dyn System, unit: &ServiceUnit<'_>) -> Result<ServiceState> {
    match unit.platform {
        Platform::Macos => {
            let output = sys.run(&Cmd::new("launchctl").args(["print", &launchd_target(unit)]))?;
            if !output.success() {
                return Ok(ServiceState::default());
            }
            let running = output
                .stdout_text()
                .lines()
                .any(|line| line.trim() == "state = running");
            Ok(ServiceState {
                loaded: true,
                running,
            })
        }
        Platform::Linux => {
            let name = systemd_unit(unit);
            let enabled = sys.run(&Cmd::new("systemctl").args(["is-enabled", &name]))?;
            let active = sys.run(&Cmd::new("systemctl").args(["is-active", &name]))?;
            Ok(ServiceState {
                loaded: enabled.success(),
                running: active.success() && active.stdout_text().trim() == "active",
            })
        }
    }
}

/// Stops `unit` and unloads it from launchd (macOS) or stops it (Linux).
/// Succeeds when the service was not running.
pub fn stop(sys: &dyn System, unit: &ServiceUnit<'_>) -> Result<()> {
    let cmd = match unit.platform {
        Platform::Macos => Cmd::new("launchctl").args(["bootout", &launchd_target(unit)]),
        Platform::Linux => Cmd::new("systemctl").args(["stop", &systemd_unit(unit)]),
    };
    // Exit codes for "not loaded" differ across OS versions; the state query below is the check.
    let _ = sys.run(&cmd)?;
    if state(sys, unit)?.running {
        bail!("{} is still running after `{}`", unit.label, cmd.display());
    }
    Ok(())
}

/// Starts `unit`, reloading its definition first when `reload` is set; otherwise restarts
/// the already-loaded service.
pub fn start(sys: &dyn System, unit: &ServiceUnit<'_>, reload: bool) -> Result<()> {
    match unit.platform {
        Platform::Macos => {
            let target = launchd_target(unit);
            if !reload && state(sys, unit)?.loaded {
                run_checked(
                    sys,
                    &Cmd::new("launchctl").args(["kickstart", "-k", &target]),
                )?;
                return Ok(());
            }
            let _ = sys.run(&Cmd::new("launchctl").args(["bootout", &target]))?;
            run_checked(sys, &Cmd::new("launchctl").args(["enable", &target]))?;
            let plist = unit.service_file.display().to_string();
            let bootstrap = Cmd::new("launchctl").args(["bootstrap", "system", &plist]);
            let mut attempt = 1;
            loop {
                let output = sys.run(&bootstrap)?;
                if output.success() {
                    return Ok(());
                }
                if attempt >= BOOTSTRAP_ATTEMPTS {
                    bail!(
                        "`{}` failed (exit {}){}",
                        bootstrap.display(),
                        output.code,
                        stderr_suffix(&output.stderr)
                    );
                }
                attempt += 1;
                sys.sleep(Duration::from_millis(500));
            }
        }
        Platform::Linux => {
            let name = systemd_unit(unit);
            if reload {
                run_checked(sys, &Cmd::new("systemctl").arg("daemon-reload"))?;
            }
            run_checked(sys, &Cmd::new("systemctl").args(["enable", &name]))?;
            run_checked(sys, &Cmd::new("systemctl").args(["restart", &name]))?;
            Ok(())
        }
    }
}

/// Stops and disables `unit` and deletes its definition. Returns whether a definition
/// file was removed.
pub fn remove(sys: &dyn System, unit: &ServiceUnit<'_>) -> Result<bool> {
    match unit.platform {
        Platform::Macos => {
            let target = launchd_target(unit);
            let _ = sys.run(&Cmd::new("launchctl").args(["bootout", &target]))?;
            let _ = sys.run(&Cmd::new("launchctl").args(["disable", &target]))?;
            sys.remove_file(unit.service_file)
        }
        Platform::Linux => {
            let name = systemd_unit(unit);
            let _ = sys.run(&Cmd::new("systemctl").args(["disable", "--now", &name]))?;
            let removed = sys.remove_file(unit.service_file)?;
            let _ = sys.run(&Cmd::new("systemctl").arg("daemon-reload"))?;
            Ok(removed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DaemonConfig {
        DaemonConfig {
            admin_uids: vec![501],
            agent_uids: vec![501, 301],
        }
    }

    #[test]
    fn plist_references_runner_and_keychain_but_no_secret_material() {
        let layout = Layout::for_platform(Platform::Macos);
        let plist = render_definition(&layout, &config());
        assert!(plist.contains("<string>/Library/AgentPay/bin/run-agentpay-daemon.sh</string>"));
        assert!(plist.contains("<key>AGENTPAY_KEYCHAIN_SERVICE</key>"));
        assert!(plist.contains("<string>agentpay-daemon-secret</string>"));
        assert!(plist.contains("<string>501,301</string>"));
        assert!(plist.contains("/var/log/agentpay/com.agentpay.daemon.err.log"));
        assert!(!plist.contains("PASSWORD"));
    }

    #[test]
    fn unit_uses_systemd_managed_directories() {
        let layout = Layout::for_platform(Platform::Linux);
        let unit = render_definition(&layout, &config());
        assert!(unit.contains("ExecStart=\"/opt/agentpay/bin/run-agentpay-daemon.sh\""));
        assert!(
            unit.contains("Environment=\"AGENTPAY_SECRET_FILE=/var/lib/agentpay/daemon-secret\"")
        );
        assert!(unit.contains("RuntimeDirectory=agentpay\n"));
        assert!(unit.contains("StateDirectory=agentpay\n"));
        assert!(unit.contains("Environment=\"AGENTPAY_ALLOW_AGENT_EUID=501,301\""));
    }

    #[test]
    fn escaping_neutralises_markup_and_specifiers() {
        assert_eq!(xml_escape("a<b>&\"'"), "a&lt;b&gt;&amp;&quot;&apos;");
        assert_eq!(systemd_quote("x%i\"\\"), "\"x%%i\\\"\\\\\"");
    }
}
