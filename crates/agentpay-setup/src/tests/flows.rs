//! Install flows: fresh install, idempotency, upgrades and migration branching.

use super::*;
use crate::system::System;

#[test]
fn fresh_macos_install_sets_everything_up() {
    let machine = Machine::macos();
    let run = machine.install();
    let result = run.ok();
    let sys = &machine.sys;

    let secret = machine.stored_secret().expect("secret stored");
    assert_eq!(secret.len(), 64);
    machine.assert_secret_hidden(&run, &secret);

    assert!(sys.exists("/Library/AgentPay/bin/agentpay-daemon"));
    assert!(sys.exists("/Library/AgentPay/bin/agentpay-system-keychain"));
    let runner = sys
        .file_text("/Library/AgentPay/bin/run-agentpay-daemon.sh")
        .unwrap();
    assert!(runner.contains("--state-secret-stdin"));
    let plist = sys.file_text(&machine.layout.service_file).unwrap();
    assert!(
        plist.contains("<string>501,300</string>"),
        "agent uids: user + service"
    );
    assert!(sys.exists(&machine.layout.manifest));
    assert!(sys.state.borrow().service_running);
    assert_eq!(result["service_user"], "_agentpay");
    assert_eq!(result["migrated"], false);

    // The secret was written through the *installed* helper, so its ACL trusts that binary.
    let store = sys
        .command_lines()
        .into_iter()
        .find(|line| line.contains("replace-generic-password"))
        .unwrap();
    assert!(store.starts_with("/Library/AgentPay/bin/agentpay-system-keychain "));

    for title in ["Installing for", "Machine secret", "Daemon socket"] {
        assert!(run.output.contains(title), "missing step {title}");
    }
    assert!(!run.output.contains('✗'));
}

#[test]
fn second_install_changes_nothing() {
    for machine in [Machine::macos(), Machine::linux()] {
        machine.install().ok();
        let secret = machine.stored_secret();
        machine.sys.clear_logs();

        let run = machine.install();
        assert_eq!(run.ok()["changed"], false, "{}", run.output);
        assert!(machine.sys.state.borrow().writes.is_empty());
        assert_eq!(machine.mutating_commands(), Vec::<String>::new());
        assert_eq!(machine.stored_secret(), secret);
        assert!(run.output.contains("already running"));
    }
}

#[test]
fn upgrade_restarts_daemon_but_keeps_the_secret() {
    let machine = Machine::linux();
    machine.install().ok();
    let secret = machine.stored_secret();
    machine.put_source("agentpay-daemon", b"v2");
    machine.sys.clear_logs();

    let run = machine.install();
    run.ok();
    assert_eq!(machine.stored_secret(), secret);
    let commands = machine.sys.command_lines();
    assert!(commands.contains(&"systemctl restart agentpay-daemon.service".into()));
    assert!(!commands.iter().any(|c| c == "systemctl daemon-reload"));
    assert!(run.output.contains("restarted"));
}

#[test]
fn macos_helper_upgrade_reseals_the_same_secret() {
    let machine = Machine::macos();
    machine.install().ok();
    let secret = machine.stored_secret().unwrap();
    machine.put_source(KEYCHAIN_HELPER_BIN, b"helper-v2");
    machine.sys.clear_logs();

    let run = machine.install();
    run.ok();
    assert_eq!(machine.stored_secret().unwrap(), secret);
    let commands = machine.sys.command_lines();
    let read = commands
        .iter()
        .position(|c| c.contains("read-generic-password"));
    let store = commands
        .iter()
        .position(|c| c.contains("replace-generic-password"));
    assert!(
        read.unwrap() < store.unwrap(),
        "read with old helper before re-sealing"
    );
    assert!(run.output.contains("re-sealed"));
    machine.assert_secret_hidden(&run, &secret);
}

#[test]
fn unreadable_secret_with_state_stops_before_touching_binaries() {
    let machine = Machine::macos();
    machine.install().ok();
    machine.seed_state();
    machine.put_source(KEYCHAIN_HELPER_BIN, b"helper-v2");
    {
        let mut state = machine.sys.state.borrow_mut();
        state.keychain_read_fails = true;
        state.keychain_approval_denied = true;
    }
    machine.sys.clear_logs();

    let run = machine.install();
    assert_eq!(run.failure().step, "Existing install");
    assert!(machine.sys.state.borrow().writes.is_empty());
    assert!(run.output.contains('✗'));
    assert!(run.output.contains("not approved"), "{}", run.output);
}

#[test]
fn a_helper_replaced_without_resealing_is_recovered_with_one_approved_read() {
    // A setup stopped after replacing the helper and before re-sealing: the installed helper
    // cannot read the secret, so the daemon would not start again.
    let machine = Machine::macos();
    machine.install().ok();
    machine.seed_state();
    let secret = machine.stored_secret().unwrap();
    machine.put_source(KEYCHAIN_HELPER_BIN, b"helper-v2");
    let helper = machine.layout.managed(KEYCHAIN_HELPER_BIN);
    machine.sys.put_file(&helper, b"helper-v2", 0, 0o700);
    machine.sys.clear_logs();

    let run = machine.install();
    run.ok();
    assert_eq!(machine.stored_secret().unwrap(), secret, "the same secret");
    let commands = machine.sys.command_lines();
    assert!(
        commands
            .iter()
            .any(|c| c.starts_with("security find-generic-password")),
        "read once with approval: {commands:?}"
    );
    assert!(run.output.contains("re-sealed"));
    // The installed helper can read it again.
    let key = ("agentpay-daemon-secret".to_string(), "agentpay".to_string());
    assert_eq!(
        machine.sys.state.borrow().keychain_acl.get(&key),
        Some(&b"helper-v2".to_vec())
    );
    machine.assert_secret_hidden(&run, &secret);
}

#[test]
fn the_helper_that_wrote_the_secret_recovers_it_without_a_dialog() {
    let machine = Machine::macos();
    machine.install().ok();
    machine.seed_state();
    let secret = machine.stored_secret().unwrap();
    // The installed helper was replaced; the old build is still on disk somewhere.
    let old = machine.layout.managed(KEYCHAIN_HELPER_BIN);
    let old_contents = machine.sys.state.borrow().files[&old].data.clone();
    machine
        .sys
        .put_file("/Users/alice/old-helper", &old_contents, 501, 0o755);
    machine.put_source(KEYCHAIN_HELPER_BIN, b"helper-v2");
    machine.sys.put_file(&old, b"helper-v2", 0, 0o700);
    machine.sys.state.borrow_mut().keychain_approval_denied = true;
    machine.sys.clear_logs();

    let run = machine.install_with_legacy_helper(Some("/Users/alice/old-helper"));
    run.ok();
    assert_eq!(machine.stored_secret().unwrap(), secret);
    assert!(run.output.contains("re-sealed"));
    let previous = machine.layout.previous_keychain_helper().unwrap();
    assert!(
        !machine.sys.state.borrow().files.contains_key(&previous),
        "the adopted helper is removed afterwards"
    );
}

#[test]
fn services_restart_after_a_setup_that_stopped_once_binaries_were_replaced() {
    let machine = Machine::macos();
    machine.install().ok();
    // A previous setup copied a new payments binary, then stopped before restarting anything.
    machine.put_source("agentpay-paymentd", b"paymentd-v2");
    machine.sys.put_file(
        machine.layout.managed("agentpay-paymentd"),
        b"paymentd-v2",
        0,
        0o755,
    );
    let marker = machine.layout.restart_marker();
    machine.sys.put_file(&marker, b"", 0, 0o600);
    machine.sys.clear_logs();

    let run = machine.install();
    run.ok();
    assert!(
        run.output.contains("services still need a restart"),
        "{}",
        run.output
    );
    assert!(!run.output.contains("already running"), "{}", run.output);
    assert!(
        !machine.sys.state.borrow().files.contains_key(&marker),
        "the marker is removed once both services restarted"
    );
    // The next run has nothing to do.
    machine.sys.clear_logs();
    let again = machine.install();
    again.ok();
    assert!(again.output.contains("already running"), "{}", again.output);
}

#[test]
fn legacy_install_is_migrated_with_secrets_on_stdin_only() {
    for machine in [Machine::macos(), Machine::linux()] {
        machine.seed_legacy_install(true);
        let run = machine.install();
        assert_eq!(run.ok()["migrated"], true, "{}", run.output);

        let secret = machine.stored_secret().expect("new secret stored");
        let stdin = machine.sys.state.borrow().migration_stdin.clone();
        assert_eq!(stdin, vec!["legacy vault pw".to_string(), secret.clone()]);
        machine.assert_secret_hidden(&run, &secret);
        machine.assert_secret_hidden(&run, "legacy vault pw");

        let legacy = machine.layout.legacy_secret("alice");
        assert!(!crate::secret::is_present(&machine.sys, &legacy).unwrap());

        // The old daemon is stopped before the state is migrated, and started again after.
        let commands = machine.sys.command_lines();
        let stop = commands
            .iter()
            .position(|c| c.starts_with("launchctl bootout") || c.starts_with("systemctl stop"));
        let migrate = commands
            .iter()
            .position(|c| c.contains(crate::migrate::MIGRATE_FLAG));
        assert!(stop.unwrap() < migrate.unwrap());
        assert!(machine.sys.state.borrow().service_running);
    }
}

#[test]
fn failed_migration_keeps_legacy_password_and_retry_reuses_the_new_secret() {
    let machine = Machine::linux();
    machine.seed_legacy_install(true);
    machine.sys.state.borrow_mut().migration_fails = true;

    let run = machine.install();
    assert_eq!(run.failure().step, "Wallet state");
    assert!(run.failure().next.contains("not changed"));
    assert!(machine.sys.exists("/var/lib/agentpay/daemon-password"));
    let first_secret = machine
        .stored_secret()
        .expect("new secret stored before migrating");

    machine.sys.state.borrow_mut().migration_fails = false;
    machine.install().ok();
    assert_eq!(machine.stored_secret().unwrap(), first_secret);
    assert!(!machine.sys.exists("/var/lib/agentpay/daemon-password"));
}

/// Where an older release kept its own copy of the keychain helper.
const USER_LEGACY_HELPER: &str = "/Users/alice/.agentpay/legacy/bin/agentpay-system-keychain";

fn previous_helper(machine: &Machine) -> PathBuf {
    machine.layout.previous_keychain_helper().unwrap()
}

#[test]
fn failed_macos_migration_keeps_the_old_helper_so_a_retry_can_read_the_legacy_password() {
    let machine = Machine::macos();
    machine.seed_legacy_install(true);
    machine.sys.state.borrow_mut().migration_fails = true;

    let run = machine.install();
    assert_eq!(run.failure().step, "Wallet state");
    // The new helper replaced the old one, which is preserved root-only.
    let managed = machine.layout.keychain_helper().unwrap();
    assert_eq!(machine.sys.file_text(&managed).unwrap(), "v1");
    let previous = previous_helper(&machine);
    assert_eq!(machine.sys.file_text(&previous).unwrap(), "old-helper");
    let meta = machine.sys.lstat(&previous).unwrap().unwrap();
    assert_eq!((meta.uid, meta.mode), (0, 0o700));

    machine.sys.state.borrow_mut().migration_fails = false;
    let retry = machine.install();
    assert_eq!(retry.ok()["migrated"], true, "{}", retry.output);
    assert!(!machine.sys.exists(&previous), "removed once migrated");
    assert!(
        !crate::secret::is_present(&machine.sys, &machine.layout.legacy_secret("alice")).unwrap()
    );
}

/// Simulates an earlier setup that replaced the helper without keeping the old one.
fn lose_the_trusted_helper(machine: &Machine) {
    let managed = machine.layout.keychain_helper().unwrap();
    machine.sys.put_file(&managed, b"v1", 0, 0o755);
}

#[test]
fn lost_helper_falls_back_to_the_macos_approval_dialog() {
    let machine = Machine::macos();
    machine.seed_legacy_install(true);
    lose_the_trusted_helper(&machine);

    let run = machine.install();
    assert_eq!(run.ok()["migrated"], true, "{}", run.output);
    machine.assert_secret_hidden(&run, "legacy vault pw");
    let commands = machine.sys.command_lines();
    let approval = commands
        .iter()
        .find(|c| c.starts_with("security find-generic-password") && c.contains(" -w "))
        .unwrap();
    assert!(
        approval.ends_with("-w /Library/Keychains/System.keychain"),
        "{approval}"
    );
}

#[test]
fn declined_approval_changes_nothing_and_explains_the_options() {
    let machine = Machine::macos();
    machine.seed_legacy_install(true);
    lose_the_trusted_helper(&machine);
    machine.sys.state.borrow_mut().keychain_approval_denied = true;

    let run = machine.install();
    let failure = run.failure();
    assert_eq!(failure.step, "Existing install");
    for hint in ["not changed", "Allow", "--legacy-helper"] {
        assert!(failure.next.contains(hint), "{}", failure.next);
    }
    assert!(machine.sys.exists(&machine.layout.state_file));
    assert!(machine.sys.state.borrow().writes.is_empty());
}

#[test]
fn legacy_helper_recovers_a_replaced_helper() {
    let machine = Machine::macos();
    machine.seed_legacy_install(true);
    lose_the_trusted_helper(&machine);
    machine.sys.state.borrow_mut().keychain_approval_denied = true;

    machine
        .sys
        .put_file(USER_LEGACY_HELPER, b"old-helper", 501, 0o755);
    let run = machine.install_with_legacy_helper(Some(USER_LEGACY_HELPER));
    assert_eq!(run.ok()["migrated"], true, "{}", run.output);
    machine.assert_secret_hidden(&run, "legacy vault pw");
    // The user-owned file was copied, never run in place.
    assert!(!machine
        .sys
        .command_lines()
        .iter()
        .any(|c| c.starts_with(USER_LEGACY_HELPER)));
    assert!(!machine.sys.exists(previous_helper(&machine)));
}

#[test]
fn legacy_helper_must_be_a_regular_file() {
    let machine = Machine::macos();
    machine.seed_legacy_install(true);
    let run = machine.install_with_legacy_helper(Some("/Users/alice/missing"));
    assert_eq!(run.failure().step, "Existing install");
    assert!(run.failure().next.contains("not a symlink"));
    assert!(machine.sys.state.borrow().writes.is_empty());

    let linux = Machine::linux();
    let run = linux.install_with_legacy_helper(Some(USER_LEGACY_HELPER));
    assert!(run.failure().next.contains("without --legacy-helper"));
}

#[test]
fn legacy_password_without_state_is_discarded() {
    let machine = Machine::macos();
    machine.seed_legacy_install(false);
    let run = machine.install();
    assert_eq!(run.ok()["migrated"], false);
    assert!(run.output.contains("old vault password discarded"));
    assert!(machine.stored_secret().is_some());
    assert!(!machine
        .sys
        .command_lines()
        .iter()
        .any(|c| c.contains(crate::migrate::MIGRATE_FLAG)));
}

#[test]
fn state_without_secret_is_refused_with_a_next_action() {
    let machine = Machine::linux();
    machine.seed_state();
    let run = machine.install();
    let failure = run.failure();
    assert_eq!(failure.step, "Existing install");
    assert!(failure.next.contains("uninstall"));
    assert!(machine.stored_secret().is_none());
}

#[test]
fn invalid_users_and_sources_are_rejected_early() {
    let machine = Machine::linux();
    machine.sys.add_user("root", 0, 0);
    for user in ["root", "nobody-here", "-rf", "a b"] {
        let options = InstallOptions {
            user: user.into(),
            source_dir: PathBuf::from(SOURCE_DIR),
            legacy_helper: None,
            socket_timeout: Duration::from_secs(1),
        };
        let mut sink = Vec::new();
        let mut reporter = Reporter::new(&mut sink, true, "install", "", "rerun");
        let failure = install(&machine.sys, &machine.layout, &options, &mut reporter).unwrap_err();
        assert_eq!(failure.step, "Installing for", "user {user}");
    }

    let missing = Machine::linux();
    let source = Path::new(SOURCE_DIR).join("agentpay-daemon");
    missing.sys.remove_file(&source).unwrap();
    let run = missing.install();
    assert_eq!(run.failure().step, "Source binaries");
    assert!(run.failure().next.contains("Reinstall"));
    assert!(missing.sys.command_lines().is_empty());
}

#[test]
fn socket_that_never_appears_points_at_the_log() {
    let machine = Machine::macos();
    machine.sys.state.borrow_mut().socket_never_ready = true;
    let run = machine.install();
    let failure = run.failure();
    assert_eq!(failure.step, "Daemon socket");
    assert!(failure
        .next
        .contains("/var/log/agentpay/com.agentpay.daemon.err.log"));
    assert!(run.output.contains('✗'));
}
