//! The payments service (`agentpay-paymentd`): its launchd/systemd definition and the
//! directories its service account owns.
//!
//! Unlike the signer daemon it needs no secret, so the definition runs the binary directly (no
//! runner script) as the service account, with every path and uid passed as a flag:
//! - `--socket` / `--state-dir`: its own socket and private state (`config.json`);
//! - `--signer-socket` / `--signer-euid 0`: the root signer daemon it asks for signatures.
//!   Signerd accepts those calls because install puts the service account's uid on signerd's
//!   agent allowlist (`--allow-agent-euid`);
//! - `--allow-client-euid`: the installing user, the only client allowed to connect.

use std::path::Path;

use anyhow::Result;

use crate::layout::{Layout, Platform};
use crate::service::{systemd_quote, xml_escape};
use crate::system::{Account, FileKind, System};

/// Non-secret configuration of the payments service definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentsServiceConfig {
    /// Uids allowed to connect to the payments socket.
    pub client_uids: Vec<u32>,
}

/// Command line of the payments service.
fn arguments(layout: &Layout, config: &PaymentsServiceConfig) -> Vec<String> {
    let clients = config
        .client_uids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    vec![
        layout.paymentd_bin().display().to_string(),
        "--socket".into(),
        layout.payments.socket.display().to_string(),
        "--state-dir".into(),
        layout.payments.state_dir.display().to_string(),
        "--signer-socket".into(),
        layout.socket.display().to_string(),
        "--signer-euid".into(),
        "0".into(),
        "--allow-client-euid".into(),
        clients,
    ]
}

/// Renders the launchd plist or systemd unit that runs the payments service as `account`.
pub fn render_definition(
    layout: &Layout,
    account: &Account,
    config: &PaymentsServiceConfig,
) -> String {
    let args = arguments(layout, config);
    match layout.platform {
        Platform::Macos => render_plist(layout, account, &args),
        Platform::Linux => render_unit(layout, account, &args),
    }
}

fn render_plist(layout: &Layout, account: &Account, args: &[String]) -> String {
    let label = layout.payments.label;
    let log_dir = layout
        .payments
        .log_dir
        .as_ref()
        .map(|dir| dir.display().to_string())
        .unwrap_or_else(|| "/var/log".into());
    let args_xml: String = args
        .iter()
        .map(|arg| format!("      <string>{}</string>\n", xml_escape(arg)))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}    </array>
    <key>UserName</key>
    <string>{user}</string>
    <key>GroupName</key>
    <string>{user}</string>
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
        user = xml_escape(&account.name),
        state_dir = xml_escape(&layout.payments.state_dir.display().to_string()),
        log_dir = xml_escape(&log_dir),
    )
}

fn render_unit(layout: &Layout, account: &Account, args: &[String]) -> String {
    let exec: Vec<String> = args.iter().map(|arg| systemd_quote(arg)).collect();
    let dir_name = |path: &Path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "agentpay-paymentd".into())
    };
    format!(
        "[Unit]
Description=AgentPay payments service
After=network-online.target {signer}.service
Wants=network-online.target {signer}.service

[Service]
Type=simple
User={user}
Group={user}
ExecStart={exec}
Restart=always
RestartSec=2
StateDirectory={state}
StateDirectoryMode=0700
RuntimeDirectory={run}
RuntimeDirectoryMode=0755
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
UMask=0077
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
",
        signer = layout.label,
        user = account.name,
        exec = exec.join(" "),
        state = dir_name(&layout.payments.state_dir),
        run = dir_name(&layout.payments.run_dir),
    )
}

/// Creates the directories the service account owns ([`Layout::payments_directories`]) and
/// hands them to `account`. Returns how many were created or changed.
pub fn ensure_directories(sys: &dyn System, layout: &Layout, account: &Account) -> Result<usize> {
    let mut changed = 0;
    for (dir, mode) in layout.payments_directories() {
        let before = sys.lstat(&dir)?;
        let wanted = |meta: &crate::system::FileMeta| {
            meta.kind == FileKind::Dir
                && meta.uid == account.uid
                && meta.gid == account.gid
                && meta.mode == mode
        };
        if before.as_ref().is_some_and(wanted) {
            continue;
        }
        sys.ensure_dir(&dir, mode)?;
        sys.set_owner(&dir, account.uid, account.gid)?;
        changed += 1;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::fake::FakeSystem;

    fn account(name: &str, uid: u32) -> Account {
        Account {
            name: name.into(),
            uid,
            gid: uid,
        }
    }

    fn config() -> PaymentsServiceConfig {
        PaymentsServiceConfig {
            client_uids: vec![501],
        }
    }

    #[test]
    fn plist_runs_paymentd_as_the_service_account_with_explicit_paths() {
        let layout = Layout::for_platform(Platform::Macos);
        let plist = render_definition(&layout, &account("_agentpay", 300), &config());
        for expected in [
            "<string>com.agentpay.paymentd</string>",
            "<string>/Library/AgentPay/bin/agentpay-paymentd</string>",
            "<string>/Library/AgentPay/run/paymentd/paymentd.sock</string>",
            "<string>/var/db/agentpay-paymentd</string>",
            "<string>/Library/AgentPay/run/daemon.sock</string>",
            "<key>UserName</key>\n    <string>_agentpay</string>",
            "<string>--allow-client-euid</string>\n      <string>501</string>",
            "/var/log/agentpay-paymentd/com.agentpay.paymentd.err.log",
        ] {
            assert!(plist.contains(expected), "missing {expected}\n{plist}");
        }
        assert!(!plist.contains("KEYCHAIN"));
    }

    #[test]
    fn unit_runs_unprivileged_after_the_signer() {
        let layout = Layout::for_platform(Platform::Linux);
        let unit = render_definition(&layout, &account("agentpay", 999), &config());
        for expected in [
            "User=agentpay\n",
            "After=network-online.target agentpay-daemon.service\n",
            "ExecStart=\"/opt/agentpay/bin/agentpay-paymentd\" \"--socket\" \"/run/agentpay-paymentd/paymentd.sock\"",
            "\"--signer-socket\" \"/run/agentpay/daemon.sock\" \"--signer-euid\" \"0\"",
            "StateDirectory=agentpay-paymentd\n",
            "RuntimeDirectory=agentpay-paymentd\n",
            "CapabilityBoundingSet=\n",
        ] {
            assert!(unit.contains(expected), "missing {expected}\n{unit}");
        }
        assert!(!unit.contains("User=root"));
    }

    #[test]
    fn macos_directories_are_handed_to_the_service_account_once() {
        let sys = FakeSystem::macos();
        let layout = Layout::for_platform(Platform::Macos);
        let owner = account("_agentpay", 300);
        assert_eq!(ensure_directories(&sys, &layout, &owner).unwrap(), 3);
        let state = sys.lstat(&layout.payments.state_dir).unwrap().unwrap();
        assert_eq!((state.uid, state.gid, state.mode), (300, 300, 0o700));
        let run = sys.lstat(&layout.payments.run_dir).unwrap().unwrap();
        assert_eq!((run.uid, run.mode), (300, 0o755));
        assert_eq!(ensure_directories(&sys, &layout, &owner).unwrap(), 0);

        let linux = FakeSystem::linux();
        let layout = Layout::for_platform(Platform::Linux);
        assert_eq!(ensure_directories(&linux, &layout, &owner).unwrap(), 0);
    }
}
