//! The payments service: installed beside the signer daemon, run as the service account, and
//! reachable by signerd as an agent peer.

use super::*;
use crate::status;
use crate::system::System;
use crate::uninstall::{uninstall, UninstallOptions};

#[test]
fn install_runs_paymentd_as_the_service_account_on_both_platforms() {
    for machine in [Machine::macos(), Machine::linux()] {
        let run = machine.install();
        let result = run.ok();
        let layout = &machine.layout;
        let sys = &machine.sys;
        let account = sys
            .lookup_user(layout.service_user)
            .unwrap()
            .expect("service account");

        let binary = sys.lstat(&layout.paymentd_bin()).unwrap().expect("binary");
        assert_eq!((binary.uid, binary.mode), (0, 0o755));

        let definition = sys
            .file_text(&layout.payments.service_file)
            .expect("definition");
        assert!(definition.contains(&account.name));
        assert!(definition.contains("--signer-euid"));
        assert!(!definition.contains("root"), "paymentd never runs as root");

        // Signerd lets the service account in as an agent peer, and only as one.
        let signer = sys
            .file_text(&layout.service_file)
            .expect("signer definition");
        let agent_uids = format!("501,{}", account.uid);
        assert!(signer.contains(&agent_uids), "{signer}");
        assert!(!signer.contains(&format!(
            "ADMIN_EUID</key>\n      <string>501,{}",
            account.uid
        )));

        let socket = sys.lstat(&layout.payments.socket).unwrap().expect("socket");
        assert_eq!(socket.uid, account.uid);
        assert!(sys.state.borrow().payments_running);
        assert_eq!(
            result["payments_socket"],
            layout.payments.socket.display().to_string()
        );
        for title in ["Payments definition", "Payments service", "Payments socket"] {
            assert!(run.output.contains(title), "missing step {title}");
        }

        let current = status::collect(sys, layout).unwrap();
        assert!(current.healthy(), "{current:?}");
        assert_eq!(current.payments_socket_state, "ready");
    }
}

#[test]
fn macos_payments_directories_belong_to_the_service_account() {
    let machine = Machine::macos();
    machine.install().ok();
    let account = machine.sys.lookup_user("_agentpay").unwrap().unwrap();
    for (dir, mode) in machine.layout.payments_directories() {
        let meta = machine.sys.lstat(&dir).unwrap().expect("directory");
        assert_eq!(
            (meta.uid, meta.gid, meta.mode),
            (account.uid, account.gid, mode)
        );
    }
}

#[test]
fn a_stopped_payments_service_is_unhealthy_and_restarted_by_install() {
    let machine = Machine::linux();
    machine.install().ok();
    machine.sys.state.borrow_mut().payments_running = false;
    let current = status::collect(&machine.sys, &machine.layout).unwrap();
    assert!(!current.healthy());

    machine.sys.clear_logs();
    let run = machine.install();
    run.ok();
    let commands = machine.sys.command_lines();
    assert!(commands.contains(&"systemctl restart agentpay-paymentd.service".into()));
    assert!(!commands.contains(&"systemctl restart agentpay-daemon.service".into()));
}

#[test]
fn a_payments_socket_that_never_appears_fails_with_its_log_hint() {
    let machine = Machine::macos();
    machine.install().ok();
    {
        let mut state = machine.sys.state.borrow_mut();
        state.payments_running = false;
        state.files.remove(&machine.layout.payments.socket);
        state.payments_socket_never_ready = true;
    }
    let run = machine.install();
    let failure = run.failure();
    assert_eq!(failure.step, "Payments socket");
    assert!(
        failure.next.contains("payments service log"),
        "{}",
        failure.next
    );
    // The signer daemon was left alone.
    assert!(machine.sys.state.borrow().service_running);
}

#[test]
fn uninstall_removes_paymentd_unless_state_is_kept() {
    let machine = Machine::macos();
    machine.install().ok();
    let config = machine.layout.payments.state_dir.join("config.json");
    machine.sys.put_file(&config, b"{}", 300, 0o600);

    let mut out = Vec::new();
    let mut reporter = Reporter::new(&mut out, false, "uninstall", "test", "rerun");
    let options = UninstallOptions {
        keep_state: true,
        user: None,
    };
    uninstall(&machine.sys, &machine.layout, &options, &mut reporter).expect("uninstall");
    let sys = &machine.sys;
    assert!(!sys.exists(&machine.layout.payments.service_file));
    assert!(!sys.exists(machine.layout.paymentd_bin()));
    assert!(!sys.exists(&machine.layout.payments.run_dir));
    assert!(sys.exists(&config), "kept with --keep-state");
    assert!(!sys.state.borrow().payments_running);

    let mut out = Vec::new();
    let mut reporter = Reporter::new(&mut out, false, "uninstall", "test", "rerun");
    uninstall(
        &machine.sys,
        &machine.layout,
        &UninstallOptions::default(),
        &mut reporter,
    )
    .expect("uninstall");
    assert!(!machine.sys.exists(&machine.layout.payments.state_dir));
    assert!(!machine.sys.exists("/var/log/agentpay-paymentd"));
}
