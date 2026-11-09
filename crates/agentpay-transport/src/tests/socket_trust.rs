//! Tests for socket path and directory trust checks.

use std::path::Path;

use super::short_test_root;
use crate::socket_trust::{
    assert_root_owned_daemon_socket_path, assert_service_socket_path,
    assert_trusted_daemon_socket_path, ensure_socket_parent, remove_existing_socket_file,
};

#[test]
#[cfg(unix)]
fn ensure_socket_parent_rejects_group_writable_ancestor_directory() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "agentpay-socket-parent-ancestor-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let shared = root.join("shared");
    let nested = shared.join("nested");
    create_private_dir(&nested);
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777))
        .expect("set insecure ancestor permissions");
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700))
        .expect("set nested permissions");

    let path = nested.join("daemon.sock");
    let err = ensure_socket_parent(&path).expect_err("must reject");
    assert!(err.contains("must not be writable by group/other"));

    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700))
        .expect("restore cleanup permissions");
    std::fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
#[cfg(unix)]
fn assert_root_owned_daemon_socket_path_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!(
        "agentpay-client-socket-symlink-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    create_private_dir(&root);

    let target = root.join("daemon.sock.target");
    std::fs::write(&target, "not a socket").expect("write target");
    let linked = root.join("daemon.sock");
    symlink(&target, &linked).expect("create symlink");

    let err = assert_root_owned_daemon_socket_path(&linked).expect_err("must reject");
    assert!(err.contains("must not be a symlink"));

    std::fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
#[cfg(unix)]
fn assert_root_owned_daemon_socket_path_rejects_non_socket_files() {
    let root = std::env::temp_dir().join(format!(
        "agentpay-client-socket-file-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    create_private_dir(&root);

    let file = root.join("daemon.sock");
    std::fs::write(&file, "not a socket").expect("write file");

    let err = assert_root_owned_daemon_socket_path(&file).expect_err("must reject");
    assert!(err.contains("must be a unix socket"));

    std::fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
#[cfg(unix)]
fn assert_trusted_daemon_socket_path_accepts_current_user_socket_and_rejects_bad_parents() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener as StdUnixListener;

    let err =
        assert_trusted_daemon_socket_path(Path::new("")).expect_err("empty path must be rejected");
    assert!(err.contains("must not be empty"));

    let err = assert_trusted_daemon_socket_path(Path::new("daemon.sock")).expect_err("must reject");
    assert!(err.contains("must have a parent directory"));

    let root = short_test_root("trusted");
    let real_dir = root.join("real");
    create_private_dir(&real_dir);
    let socket_path = real_dir.join("daemon.sock");
    let _listener = StdUnixListener::bind(&socket_path).expect("bind socket");
    assert_eq!(
        assert_trusted_daemon_socket_path(&socket_path).expect("trusted socket"),
        socket_path
    );

    let linked_dir = root.join("linked");
    symlink(&real_dir, &linked_dir).expect("symlink dir");
    let err = assert_trusted_daemon_socket_path(&linked_dir.join("daemon.sock"))
        .expect_err("symlink parent must fail");
    assert!(err.contains("socket directory"));
    assert!(err.contains("must not be a symlink"));

    std::fs::remove_file(root.join("linked")).expect("remove symlink");
    std::fs::remove_file(socket_path).expect("remove socket");
    std::fs::remove_dir_all(root).expect("cleanup");
}

#[test]
#[cfg(unix)]
fn remove_existing_socket_file_covers_missing_socket_and_non_socket_paths() {
    use std::os::unix::net::UnixListener as StdUnixListener;

    let root = short_test_root("rm");
    create_private_dir(&root);

    let missing = root.join("missing.sock");
    remove_existing_socket_file(&missing).expect("missing is a noop");

    let file = root.join("file.sock");
    std::fs::write(&file, "not a socket").expect("write file");
    let err = remove_existing_socket_file(&file).expect_err("non-socket path");
    assert!(err.contains("is not a unix socket"));
    std::fs::remove_file(&file).expect("remove file");

    let socket = root.join("daemon.sock");
    let _listener = StdUnixListener::bind(&socket).expect("bind socket");
    drop(_listener);
    remove_existing_socket_file(&socket).expect("remove socket");
    assert!(!socket.exists());

    std::fs::remove_dir_all(root).expect("cleanup");
}

#[test]
#[cfg(unix)]
fn assert_service_socket_path_pins_the_owner_and_directory_chain() {
    use std::os::unix::fs::PermissionsExt;

    let root = short_test_root("svc");
    create_private_dir(&root);
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let socket = root.join("paymentd.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
    let me = nix::unistd::geteuid().as_raw();

    assert_service_socket_path(&socket, me).expect("owned by the expected uid");
    let err = assert_service_socket_path(&socket, me.wrapping_add(1)).expect_err("wrong owner");
    assert!(err.contains("must be owned by uid"), "{err}");

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o775)).expect("mode");
    let err = assert_service_socket_path(&socket, me).expect_err("group-writable directory");
    assert!(err.contains("must not be writable by group/other"), "{err}");

    let file = root.join("not-a-socket");
    std::fs::write(&file, b"x").expect("file");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let err = assert_service_socket_path(&file, me).expect_err("regular file");
    assert!(err.contains("must be a unix socket"), "{err}");

    std::fs::remove_dir_all(&root).expect("cleanup");
}

/// `mkdir -p` with mode `0700`, independent of the umask (a group-writable umask such as
/// Ubuntu's 002 would make the directories fail the very checks under test).
fn create_private_dir(path: &std::path::Path) {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .expect("create private test directory");
}
