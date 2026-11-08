#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework_sys::base::errSecAuthFailed;

    const ERR_SEC_AUTH_FAILED: i32 = errSecAuthFailed;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

    fn unique_temp_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock drift")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "agentpay-system-keychain-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn run(command: &str, args: &[&str]) -> Output {
        Command::new(command)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("failed to run {command}: {error}"))
    }

    fn run_with_stdin(command: &Path, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to run {}: {error}", command.display()));
        child
            .stdin
            .as_mut()
            .expect("stdin pipe")
            .write_all(stdin.as_bytes())
            .expect("write stdin");
        child
            .wait_with_output()
            .unwrap_or_else(|error| panic!("failed to wait for {}: {error}", command.display()))
    }

    fn cleanup_keychain(path: &Path) {
        let _ = run(
            "security",
            &[
                "delete-keychain",
                path.to_str().expect("keychain path utf-8"),
            ],
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn helper_owned_items_are_not_readable_without_interaction() {
        if std::env::var_os("AGENTPAY_TEST_ISOLATED").is_some() {
            eprintln!("skipping macOS keychain ACL integration test under isolated harness");
            return;
        }

        let helper = PathBuf::from(env!("CARGO_BIN_EXE_agentpay-system-keychain"));
        let temp_dir = unique_temp_dir();
        let keychain_path = temp_dir.join("acl-test.keychain-db");
        let keychain_path_str = keychain_path.to_str().expect("keychain path utf-8");
        let keychain_password = "agentpay-test-keychain-password";
        let service = "agentpay-test-service";
        let account = "agentpay-test-account";
        let secret = "agentpay-test-daemon-password";

        let create = run(
            "security",
            &[
                "create-keychain",
                "-p",
                keychain_password,
                keychain_path_str,
            ],
        );
        assert!(
            create.status.success(),
            "create-keychain failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );

        let unlock = run(
            "security",
            &[
                "unlock-keychain",
                "-p",
                keychain_password,
                keychain_path_str,
            ],
        );
        assert!(
            unlock.status.success(),
            "unlock-keychain failed: {}",
            String::from_utf8_lossy(&unlock.stderr)
        );

        let replace = run_with_stdin(
            &helper,
            &[
                "replace-generic-password",
                "--keychain",
                keychain_path_str,
                "--service",
                service,
                "--account",
                account,
                "--password-stdin",
            ],
            &format!("{secret}\n"),
        );
        assert!(
            replace.status.success(),
            "helper replace failed: {}",
            String::from_utf8_lossy(&replace.stderr)
        );

        let _interaction_guard =
            SecKeychain::disable_user_interaction().expect("disable keychain UI for test process");
        let keychain = SecKeychain::open(&keychain_path).expect("open test keychain");
        let non_helper_read = keychain.find_generic_password(service, account);
        match non_helper_read {
            Ok((password, _)) => panic!(
                "untrusted process unexpectedly read helper-owned password: {}",
                String::from_utf8_lossy(password.as_ref())
            ),
            Err(error)
                if matches!(
                    error.code(),
                    ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED
                ) => {}
            Err(error) => panic!("unexpected keychain error for untrusted read: {error:?}"),
        }

        let helper_read = run(
            helper.to_str().expect("helper path utf-8"),
            &[
                "read-generic-password",
                "--keychain",
                keychain_path_str,
                "--service",
                service,
                "--account",
                account,
            ],
        );
        assert!(
            helper_read.status.success(),
            "helper read failed: {}",
            String::from_utf8_lossy(&helper_read.stderr)
        );
        assert_eq!(
            String::from_utf8(helper_read.stdout).expect("utf-8 stdout"),
            format!("{secret}\n")
        );

        cleanup_keychain(&keychain_path);
        fs::remove_dir_all(&temp_dir).expect("remove temp dir");
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn helper_acl_test_is_macos_only() {}
