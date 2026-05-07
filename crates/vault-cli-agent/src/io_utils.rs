use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use zeroize::{Zeroize, Zeroizing};

use crate::{AgentCommandOutput, OutputFormat, OutputTarget};

const MAX_SECRET_STDIN_BYTES: u64 = 16 * 1024;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const GROUP_OTHER_WRITE_MODE_MASK: u32 = 0o022;
#[cfg(unix)]
const STICKY_BIT_MODE: u32 = 0o1000;

pub(crate) fn resolve_agent_auth_token(
    cli_value: Option<String>,
    env_value: Option<String>,
    from_stdin: bool,
    non_interactive: bool,
) -> Result<Zeroizing<String>> {
    if from_stdin {
        return read_secret_from_reader(std::io::stdin(), "agent auth token");
    }

    if let Some(value) = cli_value {
        validate_secret(value.into(), "argument")?;
        bail!(
            "--agent-auth-token is disabled for security; use --agent-auth-token-stdin or AGENTPAY_AGENT_AUTH_TOKEN"
        );
    }

    if let Some(value) = env_value {
        return validate_secret(value.into(), "environment");
    }

    if non_interactive {
        bail!(
            "agent auth token is required in non-interactive mode; use AGENTPAY_AGENT_AUTH_TOKEN or --agent-auth-token-stdin"
        );
    }

    let prompted = rpassword::prompt_password("Agent auth token: ")
        .context("failed to read agent auth token input")?;
    validate_secret(prompted.into(), "prompt")
}

fn validate_secret(mut value: Zeroizing<String>, source: &str) -> Result<Zeroizing<String>> {
    if value.as_bytes().len() > MAX_SECRET_STDIN_BYTES as usize {
        value.zeroize();
        bail!("{source} secret must not exceed {MAX_SECRET_STDIN_BYTES} bytes");
    }
    if value.trim().is_empty() {
        value.zeroize();
        bail!("{source} secret must not be empty or whitespace");
    }
    Ok(value)
}

fn read_secret_from_reader(mut reader: impl Read, label: &str) -> Result<Zeroizing<String>> {
    let mut raw = String::new();
    reader
        .by_ref()
        .take(MAX_SECRET_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("failed to read {label} from stdin"))?;
    if raw.as_bytes().len() > MAX_SECRET_STDIN_BYTES as usize {
        raw.zeroize();
        bail!("{label} must not exceed {MAX_SECRET_STDIN_BYTES} bytes");
    }
    let secret = Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_string());
    raw.zeroize();
    validate_secret(secret, "stdin")
}

#[cfg(test)]
mod tests {
    use super::{
        emit_output, ensure_output_parent, is_symlink_path, print_agent_output,
        read_secret_from_reader, resolve_agent_auth_token, resolve_output_target,
        temporary_output_path, validate_secret, write_output_file,
    };
    use crate::{AgentCommandOutput, OutputFormat, OutputTarget};
    use std::fs;
    use std::io::{Cursor, Read};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
    }

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
        let err = read_secret_from_reader(oversized, "agent auth token").expect_err("must fail");
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn read_secret_from_reader_trims_newlines_and_rejects_blank_values() {
        let trimmed = read_secret_from_reader(Cursor::new("agent-token\r\n"), "agent auth token")
            .expect("trimmed token");
        assert_eq!(trimmed.as_str(), "agent-token");

        let err =
            read_secret_from_reader(Cursor::new(" \n"), "agent auth token").expect_err("must fail");
        assert!(err.to_string().contains("must not be empty or whitespace"));
    }

    #[test]
    fn read_secret_from_reader_propagates_io_errors() {
        let err =
            read_secret_from_reader(FailingReader, "agent auth token").expect_err("must fail");
        assert!(err
            .to_string()
            .contains("failed to read agent auth token from stdin"));
    }

    #[test]
    fn validate_secret_rejects_oversized_non_stdin_secret() {
        let err = validate_secret(
            "a".repeat((16 * 1024) + 1).into(),
            "argument or environment",
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn validate_secret_rejects_whitespace_only() {
        let err = validate_secret(" \t ".to_string().into(), "environment").expect_err("must fail");
        assert!(err.to_string().contains("must not be empty or whitespace"));
    }

    #[test]
    fn resolve_agent_auth_token_covers_env_and_non_interactive_paths() {
        let token = resolve_agent_auth_token(None, Some("secret".to_string()), false, false)
            .expect("environment token");
        assert_eq!(token.as_str(), "secret");

        let err = resolve_agent_auth_token(None, None, false, true).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("agent auth token is required in non-interactive mode"));
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_rejects_symlinked_parent_directory() {
        let root = temp_path("vault-cli-agent-output-symlink");
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

        let root = temp_path("vault-cli-agent-output-mode");
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

        let root = temp_path("vault-cli-agent-output-ancestor-mode");
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

        let root = temp_path("vault-cli-agent-output-create");
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
    fn ensure_output_parent_rejects_directory_output_path() {
        let root = temp_path("vault-cli-agent-output-directory");
        fs::create_dir_all(&root).expect("create root directory");

        let err = ensure_output_parent(&root).expect_err("must reject directory path");
        assert!(err
            .to_string()
            .contains("is a directory; provide a file path"));

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_output_parent_rejects_symlinked_output_path() {
        use std::os::unix::fs::symlink;

        let root = temp_path("vault-cli-agent-output-path-symlink");
        fs::create_dir_all(&root).expect("create root directory");
        let target = root.join("target.json");
        let link = root.join("link.json");
        fs::write(&target, "seed\n").expect("seed target");
        symlink(&target, &link).expect("symlink output path");

        let err = ensure_output_parent(&link).expect_err("must reject symlink path");
        assert!(err.to_string().contains("must not be a symlink"));
        assert!(is_symlink_path(&link).expect("symlink metadata"));

        fs::remove_dir_all(&root).expect("cleanup temp tree");
    }

    #[test]
    #[cfg(unix)]
    fn write_output_file_overwrite_replaces_existing_hard_link_instead_of_mutating_shared_inode() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_path("vault-cli-agent-output-overwrite-hardlink");
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
    fn resolve_output_target_preserves_file_paths() {
        let path = temp_path("vault-cli-agent-output-target");
        let target = resolve_output_target(Some(path.clone()), true).expect("target");
        match target {
            OutputTarget::File {
                path: actual,
                overwrite,
            } => {
                assert_eq!(actual, path);
                assert!(overwrite);
            }
            OutputTarget::Stdout => panic!("expected file target"),
        }
    }

    #[test]
    fn emit_output_and_print_agent_output_write_expected_content() {
        let output_path = temp_path("vault-cli-agent-emit-output");
        let agent_output_path = temp_path("vault-cli-agent-render-output");

        emit_output(
            "hello",
            &OutputTarget::File {
                path: output_path.clone(),
                overwrite: false,
            },
        )
        .expect("emit file output");
        assert_eq!(
            fs::read_to_string(&output_path).expect("read output"),
            "hello\n"
        );

        let output = AgentCommandOutput {
            command: "broadcast".to_string(),
            network: "1".to_string(),
            asset: "native_eth".to_string(),
            counterparty: "0x2000000000000000000000000000000000000000".to_string(),
            amount_wei: "7".to_string(),
            estimated_max_gas_spend_wei: Some("21000".to_string()),
            tx_type: Some("0x02".to_string()),
            delegation_enabled: Some(false),
            signature_hex: "0xdead".to_string(),
            signature_base58: None,
            r_hex: Some("0x01".to_string()),
            s_hex: Some("0x02".to_string()),
            v: Some(1),
            raw_tx_hex: Some("0xbeef".to_string()),
            tx_hash_hex: Some("0xcafe".to_string()),
            raw_tx_base64: None,
            tx_id: None,
        };

        print_agent_output(
            &output,
            OutputFormat::Text,
            &OutputTarget::File {
                path: agent_output_path.clone(),
                overwrite: false,
            },
        )
        .expect("text render");
        let rendered = fs::read_to_string(&agent_output_path).expect("read rendered");
        assert!(rendered.contains("Command: broadcast"));
        assert!(rendered.contains("Estimated Max Gas Spend (wei): 21000"));
        assert!(rendered.contains("Delegation Enabled: false"));
        assert!(rendered.contains("Tx Hash: 0xcafe"));

        print_agent_output(
            &output,
            OutputFormat::Json,
            &OutputTarget::File {
                path: agent_output_path.clone(),
                overwrite: true,
            },
        )
        .expect("json render");
        let rendered = fs::read_to_string(&agent_output_path).expect("read rendered");
        assert!(rendered.contains("\"command\": \"broadcast\""));
        assert!(rendered.contains("\"tx_hash_hex\": \"0xcafe\""));

        fs::remove_file(&output_path).expect("cleanup output");
        fs::remove_file(&agent_output_path).expect("cleanup rendered");
    }

    #[test]
    fn temporary_output_path_stays_in_parent_directory() {
        let output = temp_path("vault-cli-agent-temp-output");
        let temp = temporary_output_path(&output);
        assert_eq!(temp.parent(), output.parent());
        assert!(temp
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .contains(".tmp-"));
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

fn write_output_file_atomic_replace(path: &Path, output: &str) -> Result<()> {
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

pub(crate) fn print_agent_output(
    output: &AgentCommandOutput,
    format: OutputFormat,
    target: &OutputTarget,
) -> Result<()> {
    let rendered = match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(output).context("failed to serialize output")?
        }
        OutputFormat::Text => [
            format!("Command: {}", output.command),
            format!("Network: {}", output.network),
            format!("Asset: {}", output.asset),
            format!("Counterparty: {}", output.counterparty),
            format!("Amount (wei): {}", output.amount_wei),
            output
                .estimated_max_gas_spend_wei
                .as_ref()
                .map(|value| format!("Estimated Max Gas Spend (wei): {value}"))
                .unwrap_or_default(),
            output
                .tx_type
                .as_ref()
                .map(|value| format!("Tx Type: {value}"))
                .unwrap_or_default(),
            output
                .delegation_enabled
                .as_ref()
                .map(|value| format!("Delegation Enabled: {value}"))
                .unwrap_or_default(),
            format!("Signature: {}", output.signature_hex),
            output
                .signature_base58
                .as_ref()
                .map(|value| format!("Signature (base58): {value}"))
                .unwrap_or_default(),
            output
                .r_hex
                .as_ref()
                .map(|value| format!("r: {value}"))
                .unwrap_or_default(),
            output
                .s_hex
                .as_ref()
                .map(|value| format!("s: {value}"))
                .unwrap_or_default(),
            output
                .v
                .as_ref()
                .map(|value| format!("v: {value}"))
                .unwrap_or_default(),
            output
                .raw_tx_hex
                .as_ref()
                .map(|value| format!("Raw Tx: {value}"))
                .unwrap_or_default(),
            output
                .tx_hash_hex
                .as_ref()
                .map(|value| format!("Tx Hash: {value}"))
                .unwrap_or_default(),
            output
                .raw_tx_base64
                .as_ref()
                .map(|value| format!("Raw Tx (base64): {value}"))
                .unwrap_or_default(),
            output
                .tx_id
                .as_ref()
                .map(|value| format!("Tx ID: {value}"))
                .unwrap_or_default(),
        ]
        .into_iter()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n"),
    };
    emit_output(&rendered, target)
}
