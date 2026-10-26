use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use zeroize::Zeroizing;

use crate::{OutputFormat, OutputTarget};

const MAX_SECRET_STDIN_BYTES: u64 = 16 * 1024;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const GROUP_OTHER_WRITE_MODE_MASK: u32 = 0o022;
#[cfg(unix)]
const STICKY_BIT_MODE: u32 = 0o1000;

pub(crate) fn resolve_vault_password(
    from_stdin: bool,
    non_interactive: bool,
) -> Result<Zeroizing<String>> {
    if from_stdin {
        return read_secret_from_reader(std::io::stdin(), "vault password");
    }

    if non_interactive {
        bail!("vault password is required in non-interactive mode; use --vault-password-stdin");
    }

    let prompted = Zeroizing::new(
        rpassword::prompt_password("Vault password: ").context("failed to read password input")?,
    );
    validate_password(prompted, "prompt")
}

pub(crate) fn validate_password(
    password: impl Into<Zeroizing<String>>,
    source: &str,
) -> Result<Zeroizing<String>> {
    let password = password.into();
    if password.as_bytes().len() > MAX_SECRET_STDIN_BYTES as usize {
        bail!("vault password from {source} must not exceed {MAX_SECRET_STDIN_BYTES} bytes");
    }
    if password.trim().is_empty() {
        bail!("vault password from {source} must not be empty or whitespace");
    }
    Ok(password)
}

/// Reads a secret from a regular, owner-only file. The file is opened exactly once with
/// `O_NOFOLLOW` and every check runs against the opened descriptor (`fstat`), so the path cannot
/// be swapped for a symlink or another file between the checks and the read.
pub(crate) fn read_secret_from_file(path: &Path, label: &str) -> Result<Zeroizing<String>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return anyhow!("{label} file '{}' must not be a symlink", path.display());
        }
        anyhow!("failed to open {label} file '{}': {error}", path.display())
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {label} file '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} file '{}' must be a regular file", path.display());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "{label} file '{}' must not grant group/other permissions",
            path.display()
        );
    }

    let mut raw = Zeroizing::new(String::new());
    file.take(MAX_SECRET_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("failed to read {label} file '{}'", path.display()))?;
    if raw.as_bytes().len() > MAX_SECRET_STDIN_BYTES as usize {
        bail!(
            "{label} file '{}' must not exceed {MAX_SECRET_STDIN_BYTES} bytes",
            path.display()
        );
    }
    let secret = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_string());
    validate_password(secret, "file")
}

/// Reads a secret from an inherited file descriptor, typically the read end of a pipe the parent
/// process wired up as fd 3. The descriptor must not be one of the standard streams, must be open,
/// and is consumed (closed) after the bounded read.
#[cfg(unix)]
pub(crate) fn read_secret_from_fd(fd: i32, label: &str) -> Result<Zeroizing<String>> {
    use std::os::unix::io::FromRawFd;

    if fd < 3 {
        bail!("{label} file descriptor must be 3 or greater (got {fd})");
    }
    // SAFETY: `fcntl(F_GETFD)` only queries descriptor flags and has no side effects.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        bail!(
            "{label} file descriptor {fd} is not open: {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: the descriptor was verified open above, was inherited from the parent process for
    // this purpose only, and is not wrapped or used anywhere else in this process. Ownership moves
    // into `File`, which closes it when dropped.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    read_secret_from_source(file, label, &format!("file descriptor {fd}"))
}

#[cfg(not(unix))]
pub(crate) fn read_secret_from_fd(_fd: i32, label: &str) -> Result<Zeroizing<String>> {
    bail!("reading the {label} from a file descriptor is only supported on unix platforms")
}

fn read_secret_from_reader(reader: impl Read, label: &str) -> Result<Zeroizing<String>> {
    read_secret_from_source(reader, label, "stdin")
}

fn read_secret_from_source(
    mut reader: impl Read,
    label: &str,
    source: &str,
) -> Result<Zeroizing<String>> {
    let mut raw = Zeroizing::new(String::new());
    reader
        .by_ref()
        .take(MAX_SECRET_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("failed to read {label} from {source}"))?;
    if raw.as_bytes().len() > MAX_SECRET_STDIN_BYTES as usize {
        bail!("{label} must not exceed {MAX_SECRET_STDIN_BYTES} bytes");
    }
    let secret = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_string());
    validate_password(secret, source)
}

#[cfg(test)]
mod tests {
    use super::{
        emit_output, ensure_output_parent, print_status, read_secret_from_fd,
        read_secret_from_file, read_secret_from_reader, resolve_output_target,
        resolve_vault_password, should_print_status, validate_password, write_output_file,
    };
    use crate::{OutputFormat, OutputTarget};
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn read_secret_from_reader_rejects_oversized_stdin() {
        let oversized = Cursor::new(vec![b'a'; (16 * 1024) + 1]);
        let err = read_secret_from_reader(oversized, "vault password").expect_err("must fail");
        assert!(err.to_string().contains("must not exceed"));
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_from_file_checks_opened_descriptor() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = temp_path("agentpay-admin-secret-file");
        fs::create_dir_all(&root).expect("create root");
        let secret_path = root.join("secret.txt");
        fs::write(&secret_path, "key-material\n").expect("write secret");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("chmod");

        let secret = read_secret_from_file(&secret_path, "imported vault private key")
            .expect("owner-only regular file");
        assert_eq!(secret.as_str(), "key-material");

        let link_path = root.join("secret-link.txt");
        symlink(&secret_path, &link_path).expect("symlink");
        let err = read_secret_from_file(&link_path, "imported vault private key")
            .expect_err("symlink must be rejected");
        assert!(err.to_string().contains("must not be a symlink"));

        let err = read_secret_from_file(&root, "imported vault private key")
            .expect_err("directory must be rejected");
        assert!(err.to_string().contains("must be a regular file"));

        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o640)).expect("chmod");
        let err = read_secret_from_file(&secret_path, "imported vault private key")
            .expect_err("group-readable file must be rejected");
        assert!(err.to_string().contains("group/other"));

        fs::write(&secret_path, "a".repeat((16 * 1024) + 1)).expect("write oversized");
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let err = read_secret_from_file(&secret_path, "imported vault private key")
            .expect_err("oversized file must be rejected");
        assert!(err.to_string().contains("must not exceed"));

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    fn pipe_with_contents(contents: &[u8]) -> i32 {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;

        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid two-element buffer for `pipe`.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: the write end was just created by `pipe` and is owned only here.
        let mut writer = unsafe { fs::File::from_raw_fd(fds[1]) };
        writer.write_all(contents).expect("write pipe");
        drop(writer);
        fds[0]
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_from_fd_reads_pipe() {
        let fd = pipe_with_contents(b"key-material\n");
        let secret = read_secret_from_fd(fd, "imported vault private key").expect("pipe secret");
        assert_eq!(secret.as_str(), "key-material");
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_from_fd_rejects_oversized_and_empty_input() {
        let fd = pipe_with_contents(&vec![b'a'; (16 * 1024) + 1]);
        let err = read_secret_from_fd(fd, "imported vault private key").expect_err("oversized");
        assert!(err.to_string().contains("must not exceed"));

        let fd = pipe_with_contents(b"\n");
        let err = read_secret_from_fd(fd, "imported vault private key").expect_err("empty");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[cfg(unix)]
    #[test]
    fn read_secret_from_fd_rejects_standard_streams_and_closed_descriptors() {
        for fd in [-1, 0, 1, 2] {
            let err = read_secret_from_fd(fd, "imported vault private key")
                .expect_err("standard stream must be rejected");
            assert!(err.to_string().contains("must be 3 or greater"));
        }

        // Far above any realistic open-descriptor count, so it is never open in the test process
        // (closing and reusing a real descriptor would race with parallel tests).
        let err = read_secret_from_fd(1_000_000, "imported vault private key")
            .expect_err("closed descriptor must be rejected");
        assert!(err.to_string().contains("is not open"));
    }

    #[test]
    fn validate_password_rejects_oversized_non_stdin_secret() {
        let err = validate_password("a".repeat((16 * 1024) + 1), "argument or environment")
            .expect_err("must fail");
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn read_secret_from_reader_trims_newlines_and_accepts_valid_secret() {
        let secret =
            read_secret_from_reader(Cursor::new(b"vault-secret\r\n".to_vec()), "vault password")
                .expect("valid stdin secret");
        assert_eq!(secret.as_str(), "vault-secret");
    }

    #[test]
    fn validate_password_accepts_non_empty_secret() {
        let password =
            validate_password("vault-secret".to_string(), "prompt").expect("valid password");
        assert_eq!(password.as_str(), "vault-secret");
    }

    #[test]
    fn resolve_vault_password_requires_stdin_in_non_interactive_mode() {
        let err = resolve_vault_password(false, true).expect_err("must fail");
        assert!(err.to_string().contains("use --vault-password-stdin"));
    }

    #[test]
    fn resolve_output_target_covers_stdout_and_file_paths() {
        let stdout_target = resolve_output_target(None, false).expect("default stdout");
        assert!(matches!(stdout_target, OutputTarget::Stdout));

        let file_target = resolve_output_target(Some(PathBuf::from("out.json")), false)
            .expect("file output target");
        assert!(matches!(
            file_target,
            OutputTarget::File {
                path,
                overwrite: false
            } if path == PathBuf::from("out.json")
        ));

        let err = resolve_output_target(Some(PathBuf::from("-")), true).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("--overwrite cannot be used with --output -"));
    }

    #[test]
    fn emit_output_to_stdout_and_print_status_cover_text_paths() {
        emit_output("stdout output", &OutputTarget::Stdout).expect("stdout output");
        assert!(should_print_status(OutputFormat::Text, false));
        assert!(!should_print_status(OutputFormat::Json, false));
        assert!(!should_print_status(OutputFormat::Text, true));
        print_status("status output", OutputFormat::Text, false);
        print_status("quiet output", OutputFormat::Text, true);
        print_status("json output", OutputFormat::Json, false);
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_rejects_symlinked_parent_directory() {
        let root = temp_path("vault-cli-admin-output-symlink");
        let actual = root.join("actual");
        let linked = root.join("linked");
        fs::create_dir_all(&actual).expect("create actual directory");
        std::os::unix::fs::symlink(&actual, &linked).expect("create symlink parent");

        let err = ensure_output_parent(&linked.join("output.json")).expect_err("must reject");
        assert!(err.to_string().contains("must not be a symlink"));

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_rejects_group_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-mode");
        let insecure = root.join("shared");
        fs::create_dir_all(&insecure).expect("create insecure directory");
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o777))
            .expect("set insecure permissions");

        let err = ensure_output_parent(&insecure.join("output.json")).expect_err("must reject");
        assert!(err
            .to_string()
            .contains("must not be writable by group/other"));

        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_rejects_group_writable_ancestor_directory() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-ancestor-mode");
        let insecure = root.join("shared");
        let nested = insecure.join("nested");
        fs::create_dir_all(&nested).expect("create nested directory");
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o777))
            .expect("set insecure ancestor permissions");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
            .expect("set nested permissions");

        let err = ensure_output_parent(&nested.join("output.json")).expect_err("must reject");
        assert!(err
            .to_string()
            .contains("must not be writable by group/other"));

        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_creates_private_missing_directories() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-create");
        fs::create_dir_all(&root).expect("create root directory");

        let nested_output = root.join("nested").join("deeper").join("output.json");
        ensure_output_parent(&nested_output).expect("must create parent directories");

        let nested_mode = fs::metadata(root.join("nested"))
            .expect("nested metadata")
            .permissions()
            .mode()
            & 0o777;
        let deeper_mode = fs::metadata(root.join("nested").join("deeper"))
            .expect("deeper metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(nested_mode, 0o700);
        assert_eq!(deeper_mode, 0o700);

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_rejects_directory_path() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-dir-path");
        fs::create_dir_all(&root).expect("create root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure root permissions");

        let err = ensure_output_parent(&root).expect_err("directory path must fail");
        assert!(err
            .to_string()
            .contains("is a directory; provide a file path"));

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_allows_sticky_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-sticky-ancestor");
        let shared = root.join("shared");
        let nested = shared.join("nested");
        fs::create_dir_all(&nested).expect("create nested directory");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777))
            .expect("set sticky shared permissions");
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
            .expect("set secure nested permissions");

        ensure_output_parent(&nested.join("output.json"))
            .expect("sticky world-writable ancestor should be allowed");

        fs::set_permissions(&shared, fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn write_output_file_overwrite_replaces_existing_hard_link_instead_of_mutating_shared_inode() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-overwrite-hardlink");
        fs::create_dir_all(&root).expect("create root directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure root directory permissions");

        let output_path = root.join("output.json");
        let alias_path = root.join("output-alias.json");
        fs::write(&output_path, "old\n").expect("write original output file");
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))
            .expect("secure original output file permissions");
        fs::hard_link(&output_path, &alias_path).expect("create hard link alias");

        write_output_file(&output_path, "new", true).expect("overwrite output file");

        assert_eq!(
            fs::read_to_string(&output_path).expect("read replaced output"),
            "new\n"
        );
        assert_eq!(
            fs::read_to_string(&alias_path).expect("read hard link alias"),
            "old\n"
        );

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn write_output_file_creates_new_file_and_rejects_existing_without_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-output-create-file");
        fs::create_dir_all(&root).expect("create root directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure root directory permissions");

        let output_path = root.join("output.json");
        write_output_file(&output_path, "created", false).expect("write new output file");
        assert_eq!(
            fs::read_to_string(&output_path).expect("read created output"),
            "created\n"
        );
        assert_eq!(
            fs::metadata(&output_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let err = write_output_file(&output_path, "second", false)
            .expect_err("existing file without overwrite must fail");
        assert!(err
            .to_string()
            .contains("already exists; pass --overwrite to replace it"));

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn emit_output_to_file_target_writes_expected_content() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-admin-emit-output-file");
        fs::create_dir_all(&root).expect("create root directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure root directory permissions");

        let output_path = root.join("output.json");
        emit_output(
            "file output",
            &OutputTarget::File {
                path: output_path.clone(),
                overwrite: false,
            },
        )
        .expect("emit output to file");
        assert_eq!(
            fs::read_to_string(&output_path).expect("read emitted file"),
            "file output\n"
        );

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }
}

pub(crate) fn resolve_output_format(
    format: Option<OutputFormat>,
    json: bool,
) -> Result<OutputFormat> {
    if json {
        if matches!(format, Some(OutputFormat::Text)) {
            bail!("--json cannot be combined with --format text");
        }
        return Ok(OutputFormat::Json);
    }
    Ok(format.unwrap_or(OutputFormat::Text))
}

pub(crate) fn resolve_output_target(
    target: Option<PathBuf>,
    overwrite: bool,
) -> Result<OutputTarget> {
    match target {
        Some(path) if path.as_os_str() == "-" => {
            if overwrite {
                bail!("--overwrite cannot be used with --output - (stdout)");
            }
            Ok(OutputTarget::Stdout)
        }
        Some(path) => Ok(OutputTarget::File { path, overwrite }),
        None => Ok(OutputTarget::Stdout),
    }
}

pub(crate) fn emit_output(output: &str, target: &OutputTarget) -> Result<()> {
    match target {
        OutputTarget::Stdout => {
            println!("{output}");
            Ok(())
        }
        OutputTarget::File { path, overwrite } => {
            ensure_output_parent(path)?;
            write_output_file(path, output, *overwrite)
        }
    }
}

pub(crate) fn ensure_output_parent(path: &Path) -> Result<()> {
    if is_symlink_path(path)? {
        bail!("output path '{}' must not be a symlink", path.display());
    }
    if path.is_dir() {
        bail!(
            "output path '{}' is a directory; provide a file path",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_secure_output_directory(parent)?;
        }
    }
    Ok(())
}

fn ensure_secure_output_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            assert_secure_output_directory(path, &metadata, false)?;
            assert_secure_output_directory_ancestors(path)?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    ensure_secure_output_directory(parent)?;
                }
            }

            std::fs::create_dir(path)
                .with_context(|| format!("failed to create output directory {}", path.display()))?;

            #[cfg(unix)]
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
                .with_context(|| {
                    format!(
                        "failed to set output directory permissions on {}",
                        path.display()
                    )
                })?;

            let metadata = std::fs::symlink_metadata(path).with_context(|| {
                format!(
                    "failed to inspect output directory metadata {}",
                    path.display()
                )
            })?;
            assert_secure_output_directory(path, &metadata, false)?;
            assert_secure_output_directory_ancestors(path)
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to inspect output directory metadata {}",
                path.display()
            )
        }),
    }
}

#[cfg(unix)]
fn assert_secure_output_directory_ancestors(path: &Path) -> Result<()> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize output directory {}", path.display()))?;

    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor).with_context(|| {
            format!(
                "failed to inspect ancestor output directory metadata {}",
                ancestor.display()
            )
        })?;
        assert_secure_output_directory(ancestor, &metadata, true)?;
    }

    Ok(())
}

#[cfg(not(unix))]
fn assert_secure_output_directory_ancestors(_path: &Path) -> Result<()> {
    Ok(())
}

fn assert_secure_output_directory(
    path: &Path,
    metadata: &std::fs::Metadata,
    #[cfg(unix)] allow_sticky_group_other_write: bool,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        bail!(
            "output directory '{}' must not be a symlink",
            path.display()
        );
    }
    if !metadata.is_dir() {
        bail!("output directory '{}' must be a directory", path.display());
    }

    #[cfg(unix)]
    if metadata.permissions().mode() & GROUP_OTHER_WRITE_MODE_MASK != 0 {
        if allow_sticky_group_other_write && metadata.permissions().mode() & STICKY_BIT_MODE != 0 {
            return Ok(());
        }

        bail!(
            "output directory '{}' must not be writable by group/other",
            path.display()
        );
    }

    Ok(())
}

pub(crate) fn write_output_file(path: &Path, output: &str, overwrite: bool) -> Result<()> {
    if overwrite {
        return write_output_file_atomic_replace(path, output);
    }

    let mut options = OpenOptions::new();
    options.write(true);
    options.create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = options.open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow!(
                "output path '{}' already exists; pass --overwrite to replace it",
                path.display()
            )
        } else {
            err.into()
        }
    })?;
    file.write_all(output.as_bytes())
        .with_context(|| format!("failed to write output to {}", path.display()))?;
    file.write_all(b"\n")
        .with_context(|| format!("failed to write output to {}", path.display()))?;
    #[cfg(unix)]
    {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set output permissions on {}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn write_output_file_atomic_replace(path: &Path, output: &str) -> Result<()> {
    let temp_path = temporary_output_path(path);
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
            options.custom_flags(libc::O_NOFOLLOW);
        }

        let mut file = options.open(&temp_path).with_context(|| {
            format!(
                "failed to create temporary output file {}",
                temp_path.display()
            )
        })?;
        file.write_all(output.as_bytes())
            .with_context(|| format!("failed to write output to {}", temp_path.display()))?;
        file.write_all(b"\n")
            .with_context(|| format!("failed to write output to {}", temp_path.display()))?;
        #[cfg(unix)]
        {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .with_context(|| {
                    format!(
                        "failed to set output permissions on {}",
                        temp_path.display()
                    )
                })?;
        }
        drop(file);

        #[cfg(windows)]
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove output file {}", path.display()))?;
        }

        std::fs::rename(&temp_path, path)
            .with_context(|| format!("failed to replace output file {}", path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    result
}

fn temporary_output_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    parent.join(format!(
        ".{file_name}.tmp-{}-{timestamp}",
        std::process::id()
    ))
}

fn is_symlink_path(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err)
            .with_context(|| format!("failed to inspect output path metadata {}", path.display())),
    }
}

pub(crate) fn should_print_status(format: OutputFormat, quiet: bool) -> bool {
    format == OutputFormat::Text && !quiet
}

pub(crate) fn print_status(message: &str, format: OutputFormat, quiet: bool) {
    if should_print_status(format, quiet) {
        eprintln!("==> {message}");
    }
}
