//! Status, uninstall and CLI dispatch.

use clap::Parser;

use super::*;
use crate::cli::{run, Cli};
use crate::status;

fn dispatch(machine: &Machine, args: &[&str]) -> (u8, String) {
    let cli = Cli::try_parse_from(std::iter::once("agentpay-setup").chain(args.iter().copied()))
        .expect("valid arguments");
    let mut out = Vec::new();
    let code = run(&cli, &machine.sys, &machine.layout, &mut out);
    (code, String::from_utf8(out).unwrap())
}

fn json(output: &str) -> Value {
    serde_json::from_str(output).expect("one JSON document")
}

#[test]
fn status_before_install_points_at_setup() {
    let machine = Machine::macos();
    let (code, output) = dispatch(&machine, &["status", "--json"]);
    let document = json(&output);
    assert_eq!(code, 1);
    assert_eq!(document["ok"], false);
    assert_eq!(document["result"]["installed"], false);
    assert!(document["next_action"]
        .as_str()
        .unwrap()
        .contains("install"));
}

#[test]
fn status_after_install_is_healthy_without_reading_the_secret() {
    for machine in [Machine::macos(), Machine::linux()] {
        machine.install().ok();
        machine.sys.clear_logs();
        let (code, output) = dispatch(&machine, &["status", "--json"]);
        let document = json(&output);
        assert_eq!(code, 0, "{output}");
        let result = &document["result"];
        assert_eq!(result["secret_present"], true);
        assert_eq!(result["socket_state"], "ready");
        assert_eq!(result["socket_trusted"], true);
        assert_eq!(result["service"]["running"], true);
        assert_eq!(result["manifest"]["user"], "alice");
        assert_eq!(result["legacy_secret_present"], false);
        assert!(!machine
            .sys
            .command_lines()
            .iter()
            .any(|c| c.contains("read-generic-password")));
    }
}

#[test]
fn status_flags_a_stopped_daemon_and_pending_migration() {
    let machine = Machine::linux();
    machine.install().ok();
    machine.sys.state.borrow_mut().service_running = false;
    let current = status::collect(&machine.sys, &machine.layout).unwrap();
    assert!(!current.healthy());
    let (code, output) = dispatch(&machine, &["status"]);
    assert_eq!(code, 1);
    assert!(output.contains("✗  Daemon "));
    assert!(output.contains("Next: Check the daemon log: sudo journalctl"));

    machine
        .sys
        .put_file("/var/lib/agentpay/daemon-password", b"pw", 0, 0o600);
    let current = status::collect(&machine.sys, &machine.layout).unwrap();
    assert_eq!(current.legacy_secret_present, Some(true));
}

#[test]
fn uninstall_removes_service_binaries_state_and_secrets() {
    let machine = Machine::macos();
    machine.install().ok();
    machine.seed_state();
    // A leftover legacy item is removed too (found through the install record's user).
    let key = (LEGACY_KEYCHAIN_SERVICE.to_string(), "alice".to_string());
    machine
        .sys
        .state
        .borrow_mut()
        .keychain
        .insert(key, "pw".into());

    let (code, output) = dispatch(&machine, &["uninstall"]);
    assert_eq!(code, 0, "{output}");
    let sys = &machine.sys;
    assert!(!sys.exists(&machine.layout.service_file));
    assert!(!sys.exists(&machine.layout.prefix));
    assert!(!sys.exists(&machine.layout.state_dir));
    assert!(!sys.exists("/var/log/agentpay"));
    assert!(sys.state.borrow().keychain.is_empty());
    assert!(!sys.state.borrow().service_running);
    assert!(output.contains("wallet state and machine secret removed"));

    // Uninstalling again is a no-op that still succeeds.
    let (code, output) = dispatch(&machine, &["uninstall", "--json"]);
    assert_eq!(code, 0);
    assert!(json(&output)["steps"]
        .as_array()
        .unwrap()
        .iter()
        .all(|step| step["changed"] == false));
}

#[test]
fn uninstall_keep_state_allows_a_clean_reinstall() {
    let machine = Machine::macos();
    machine.install().ok();
    machine.seed_state();
    let secret = machine.stored_secret().unwrap();

    let (code, _) = dispatch(&machine, &["uninstall", "--keep-state"]);
    assert_eq!(code, 0);
    let sys = &machine.sys;
    assert!(sys.exists(&machine.layout.state_file));
    assert!(sys.exists("/Library/AgentPay/bin/agentpay-system-keychain"));
    assert!(!sys.exists("/Library/AgentPay/bin/agentpay-daemon"));
    assert_eq!(machine.stored_secret().unwrap(), secret);

    machine.install().ok();
    assert_eq!(machine.stored_secret().unwrap(), secret);
}

#[test]
fn install_json_output_is_a_single_document() {
    let machine = Machine::linux();
    let (code, output) = dispatch(
        &machine,
        &[
            "install",
            "--user",
            "alice",
            "--bin-dir",
            SOURCE_DIR,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{output}");
    let document = json(&output);
    assert_eq!(document["ok"], true);
    assert_eq!(document["command"], "install");
    assert!(document["steps"].as_array().unwrap().len() >= 10);
    let secret = machine.stored_secret().unwrap();
    assert!(!output.contains(&secret));
}

#[test]
fn cli_rejects_secret_arguments() {
    for args in [
        vec!["agentpay-setup", "install", "--user", "a", "--secret", "x"],
        vec![
            "agentpay-setup",
            "install",
            "--user",
            "a",
            "--vault-password",
            "x",
        ],
        vec!["agentpay-setup", "install"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}
