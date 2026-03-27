use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use clap::{Parser, ValueEnum};
use vault_daemon::{DaemonConfig, InMemoryDaemon, PersistentStoreConfig};
use vault_signer::{SecureEnclaveSignerBackend, SoftwareSignerBackend};
#[cfg(target_os = "linux")]
use vault_signer::LinuxTpmSignerBackend;
use vault_transport_unix::UnixDaemonServer;
use zeroize::{Zeroize, Zeroizing};

mod relay_sync;

const MAX_SECRET_STDIN_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SignerBackendKind {
    SecureEnclave,
    Software,
    #[cfg(target_os = "linux")]
    Tpm,
}

#[derive(Debug, Parser)]
#[command(name = "agentpay-daemon")]
#[command(about = "Long-running local daemon process for policy-gated signing")]
struct Cli {
    #[arg(
        long,
        default_value_t = false,
        help = "Read vault password from stdin (trailing newlines are trimmed)"
    )]
    vault_password_stdin: bool,
    #[arg(
        long,
        default_value_t = false,
        help = "Do not prompt for password; require --vault-password-stdin"
    )]
    non_interactive: bool,
    #[arg(
        long,
        env = "AGENTPAY_STATE_FILE",
        value_name = "PATH",
        help = "Encrypted persistent daemon state file path (default: $AGENTPAY_HOME/daemon-state.enc or ~/.agentpay/daemon-state.enc)"
    )]
    state_file: Option<PathBuf>,
    #[arg(
        long,
        env = "AGENTPAY_DAEMON_SOCKET",
        value_name = "PATH",
        help = "Unix socket path for daemon RPC (default: $AGENTPAY_HOME/daemon.sock or ~/.agentpay/daemon.sock)"
    )]
    daemon_socket: Option<PathBuf>,
    #[arg(
        long,
        env = "AGENTPAY_SECURE_ENCLAVE_LABEL_PREFIX",
        default_value = "com.agentpay.vault",
        value_name = "PREFIX",
        help = "Secure Enclave key label prefix"
    )]
    secure_enclave_label_prefix: String,
    #[arg(
        long,
        env = "AGENTPAY_SIGNER_BACKEND",
        value_enum,
        default_value_t = default_signer_backend(),
        value_name = "BACKEND",
        help = "Signer backend for daemon key creation and signing"
    )]
    signer_backend: SignerBackendKind,
    #[cfg(target_os = "linux")]
    #[arg(
        long,
        env = "AGENTPAY_TPM_DEVICE",
        default_value = "/dev/tpmrm0",
        value_name = "PATH",
        help = "TPM device path for Linux TPM signer backend"
    )]
    tpm_device: PathBuf,
    #[arg(
        long = "allow-admin-euid",
        env = "AGENTPAY_ALLOW_ADMIN_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..,
        help = "Additional non-root admin client euid(s) allowed to connect for privileged RPCs. Root (0) is always allowed."
    )]
    allow_admin_euid: Vec<u32>,
    #[arg(
        long = "allow-agent-euid",
        env = "AGENTPAY_ALLOW_AGENT_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..,
        help = "Additional non-root agent client euid(s) allowed to connect for signing and nonce RPCs. Root (0) is always allowed."
    )]
    allow_agent_euid: Vec<u32>,
    #[arg(
        long = "allow-client-euid",
        env = "AGENTPAY_ALLOW_CLIENT_EUID",
        value_name = "UID[,UID...]",
        value_delimiter = ',',
        num_args = 1..,
        help = "Legacy compatibility alias that grants the same non-root client euid(s) both admin and agent access. Root (0) is always allowed."
    )]
    allow_client_euid: Vec<u32>,
}

/// Returns the platform-appropriate default signer backend.
///
/// - macOS: Secure Enclave (hardware-backed, non-exportable keys)
/// - Linux/other: Software (in-process secp256k1, Argon2-encrypted state)
const fn default_signer_backend() -> SignerBackendKind {
    #[cfg(target_os = "macos")]
    {
        SignerBackendKind::SecureEnclave
    }
    #[cfg(not(target_os = "macos"))]
    {
        SignerBackendKind::Software
    }
}

#[derive(Debug, Clone)]
struct AllowedPeerEuids {
    admin: BTreeSet<u32>,
    agent: BTreeSet<u32>,
}

struct StateFileLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: valid fd with best-effort unlock during drop.
            unsafe {
                let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

#[async_trait]
trait DaemonRuntime {
    async fn run_secure_enclave(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        vault_password: Zeroizing<String>,
        state_file: PathBuf,
        secure_enclave_label_prefix: String,
        signer_backend_label: &'static str,
    ) -> Result<()>;

    async fn run_software(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        vault_password: Zeroizing<String>,
        state_file: PathBuf,
        signer_backend_label: &'static str,
    ) -> Result<()>;

    #[cfg(target_os = "linux")]
    async fn run_tpm(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        vault_password: Zeroizing<String>,
        state_file: PathBuf,
        tpm_device: PathBuf,
        signer_backend_label: &'static str,
    ) -> Result<()>;
}

struct RealDaemonRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let vault_password = resolve_vault_password(cli.vault_password_stdin, cli.non_interactive)?;
    let runtime = RealDaemonRuntime;
    run_cli_with_runtime(cli, vault_password, &runtime).await
}

async fn run_cli_with_runtime<R>(
    cli: Cli,
    vault_password: Zeroizing<String>,
    runtime: &R,
) -> Result<()>
where
    R: DaemonRuntime + ?Sized,
{
    validate_signer_backend_runtime(cli.signer_backend)?;
    let state_file = resolve_state_file_path(cli.state_file.clone())?;
    let daemon_socket = resolve_socket_path(cli.daemon_socket.clone())?;
    let _state_lock = acquire_state_file_lock(&state_file)?;

    let allowed_peer_euids = resolve_allowed_peer_euids(
        &cli.allow_admin_euid,
        &cli.allow_agent_euid,
        &cli.allow_client_euid,
    )?;
    if !cli.allow_client_euid.is_empty() {
        eprintln!(
            "==> warning: --allow-client-euid grants both admin and agent access; prefer --allow-admin-euid and --allow-agent-euid"
        );
    }

    dispatch_runtime(
        cli,
        vault_password,
        state_file,
        daemon_socket,
        allowed_peer_euids,
        runtime,
    )
    .await
}

async fn dispatch_runtime<R>(
    cli: Cli,
    vault_password: Zeroizing<String>,
    state_file: PathBuf,
    daemon_socket: PathBuf,
    allowed_peer_euids: AllowedPeerEuids,
    runtime: &R,
) -> Result<()>
where
    R: DaemonRuntime + ?Sized,
{
    let signer_backend_label = relay_signer_backend_label(cli.signer_backend);
    match cli.signer_backend {
        SignerBackendKind::SecureEnclave => {
            runtime
                .run_secure_enclave(
                    daemon_socket,
                    allowed_peer_euids,
                    vault_password,
                    state_file,
                    cli.secure_enclave_label_prefix,
                    signer_backend_label,
                )
                .await
        }
        SignerBackendKind::Software => {
            runtime
                .run_software(
                    daemon_socket,
                    allowed_peer_euids,
                    vault_password,
                    state_file,
                    signer_backend_label,
                )
                .await
        }
        #[cfg(target_os = "linux")]
        SignerBackendKind::Tpm => {
            runtime
                .run_tpm(
                    daemon_socket,
                    allowed_peer_euids,
                    vault_password,
                    state_file,
                    cli.tpm_device,
                    signer_backend_label,
                )
                .await
        }
    }
}

fn print_server_banner(daemon_socket: &Path, allowed_peer_euids: &AllowedPeerEuids) {
    eprintln!(
        "==> daemon listening on {} (allowed admin euid(s): {}; allowed agent euid(s): {})",
        daemon_socket.display(),
        format_allowed_euids(&allowed_peer_euids.admin),
        format_allowed_euids(&allowed_peer_euids.agent)
    );
    eprintln!("==> press Ctrl+C to stop");
}

async fn bind_server(
    daemon_socket: PathBuf,
    allowed_peer_euids: &AllowedPeerEuids,
) -> Result<UnixDaemonServer> {
    let server = UnixDaemonServer::bind_with_allowed_peer_euids(
        daemon_socket.clone(),
        allowed_peer_euids.admin.clone(),
        allowed_peer_euids.agent.clone(),
    )
    .await
    .with_context(|| {
        format!(
            "failed to bind daemon socket at {}",
            daemon_socket.display()
        )
    })?;
    print_server_banner(&daemon_socket, allowed_peer_euids);
    Ok(server)
}

async fn run_bound_daemon<B>(
    server: UnixDaemonServer,
    daemon: Arc<InMemoryDaemon<B>>,
    signer_backend_label: &'static str,
) -> Result<()>
where
    B: vault_signer::VaultSignerBackend + Send + Sync + 'static,
{
    let relay_task = relay_sync::spawn_relay_sync_task(Arc::clone(&daemon), signer_backend_label);
    server
        .run_until_shutdown(daemon, async {
            let _ = tokio::signal::ctrl_c().await;
            relay_task.abort();
        })
        .await
        .context("daemon server loop failed")
}

#[async_trait]
impl DaemonRuntime for RealDaemonRuntime {
    async fn run_secure_enclave(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        mut vault_password: Zeroizing<String>,
        state_file: PathBuf,
        secure_enclave_label_prefix: String,
        signer_backend_label: &'static str,
    ) -> Result<()> {
        let server = bind_server(daemon_socket, &allowed_peer_euids).await?;
        let daemon = InMemoryDaemon::new_with_persistent_store(
            &vault_password,
            SecureEnclaveSignerBackend::new(secure_enclave_label_prefix),
            DaemonConfig::default(),
            PersistentStoreConfig::new(state_file),
        );
        vault_password.zeroize();
        let daemon = Arc::new(daemon.context("failed to initialize daemon")?);
        run_bound_daemon(server, daemon, signer_backend_label).await
    }

    async fn run_software(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        mut vault_password: Zeroizing<String>,
        state_file: PathBuf,
        signer_backend_label: &'static str,
    ) -> Result<()> {
        let server = bind_server(daemon_socket, &allowed_peer_euids).await?;
        let daemon = InMemoryDaemon::new_with_persistent_store(
            &vault_password,
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
            PersistentStoreConfig::new(state_file),
        );
        vault_password.zeroize();
        let daemon = Arc::new(daemon.context("failed to initialize daemon")?);
        run_bound_daemon(server, daemon, signer_backend_label).await
    }

    #[cfg(target_os = "linux")]
    async fn run_tpm(
        &self,
        daemon_socket: PathBuf,
        allowed_peer_euids: AllowedPeerEuids,
        mut vault_password: Zeroizing<String>,
        state_file: PathBuf,
        tpm_device: PathBuf,
        signer_backend_label: &'static str,
    ) -> Result<()> {
        let server = bind_server(daemon_socket, &allowed_peer_euids).await?;
        let daemon = InMemoryDaemon::new_with_persistent_store(
            &vault_password,
            LinuxTpmSignerBackend::new(tpm_device),
            DaemonConfig::default(),
            PersistentStoreConfig::new(state_file),
        );
        vault_password.zeroize();
        let daemon = Arc::new(daemon.context("failed to initialize daemon")?);
        run_bound_daemon(server, daemon, signer_backend_label).await
    }
}

fn relay_signer_backend_label(backend: SignerBackendKind) -> &'static str {
    match backend {
        SignerBackendKind::SecureEnclave => "secure-enclave",
        SignerBackendKind::Software => "software",
        #[cfg(target_os = "linux")]
        SignerBackendKind::Tpm => "tpm",
    }
}

fn validate_signer_backend_runtime(backend: SignerBackendKind) -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        if matches!(backend, SignerBackendKind::SecureEnclave) {
            bail!("Secure Enclave daemon mode is supported only on macOS");
        }
    }

    #[cfg(target_os = "macos")]
    {
        let euid = nix::unistd::geteuid().as_raw();
        if matches!(backend, SignerBackendKind::SecureEnclave) && euid != 0 {
            bail!("secure enclave daemon mode requires root daemon context (current euid: {euid})");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Tpm variant only exists on Linux, but guard against misconfigured builds.
        let _ = backend;
    }

    Ok(())
}

fn resolve_vault_password(from_stdin: bool, non_interactive: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        return read_secret_from_reader(std::io::stdin(), "vault password");
    }

    if non_interactive {
        bail!("vault password is required in non-interactive mode; use --vault-password-stdin");
    }

    let prompted =
        rpassword::prompt_password("Vault password: ").context("failed to read password input")?;
    validate_password(prompted.into(), "prompt")
}

fn validate_password(mut password: Zeroizing<String>, source: &str) -> Result<Zeroizing<String>> {
    if password.as_bytes().len() > MAX_SECRET_STDIN_BYTES as usize {
        password.zeroize();
        bail!("vault password from {source} must not exceed {MAX_SECRET_STDIN_BYTES} bytes");
    }
    if password.trim().is_empty() {
        password.zeroize();
        bail!("vault password from {source} must not be empty or whitespace");
    }
    Ok(password)
}

fn read_secret_from_reader(
    mut reader: impl std::io::Read,
    label: &str,
) -> Result<Zeroizing<String>> {
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
    validate_password(secret, "stdin")
}

fn resolve_allowed_peer_euids(
    configured_admin: &[u32],
    configured_agent: &[u32],
    configured_legacy: &[u32],
) -> Result<AllowedPeerEuids> {
    resolve_allowed_peer_euids_with_sudo_uid(
        configured_admin,
        configured_agent,
        configured_legacy,
        None,
    )
}

fn resolve_allowed_peer_euids_with_sudo_uid(
    configured_admin: &[u32],
    configured_agent: &[u32],
    configured_legacy: &[u32],
    _sudo_uid: Option<u32>,
) -> Result<AllowedPeerEuids> {
    let mut admin = BTreeSet::from([0]);
    let mut agent = BTreeSet::from([0]);

    admin.extend(configured_legacy.iter().copied());
    admin.extend(configured_admin.iter().copied());
    agent.extend(configured_legacy.iter().copied());
    agent.extend(configured_agent.iter().copied());

    Ok(AllowedPeerEuids { admin, agent })
}

fn format_allowed_euids(values: &BTreeSet<u32>) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn resolve_state_file_path(cli_value: Option<PathBuf>) -> Result<PathBuf> {
    let path = match cli_value {
        Some(path) => path,
        None => default_state_file_path()?,
    };
    ensure_file_parent(&path, "state")?;
    Ok(path)
}

fn resolve_socket_path(cli_value: Option<PathBuf>) -> Result<PathBuf> {
    let path = match cli_value {
        Some(path) => path,
        None => default_socket_path()?,
    };
    ensure_file_parent(&path, "socket")?;
    Ok(path)
}

fn acquire_state_file_lock(path: &Path) -> Result<StateFileLock> {
    let lock_path = lock_path(path);
    ensure_file_parent(&lock_path, "state lock")?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&lock_path)
        .with_context(|| format!("failed to open state lock file {}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: valid fd for advisory lock in-process lifetime.
        unsafe {
            if libc::flock(file.as_raw_fd(), libc::LOCK_EX) != 0 {
                return Err(anyhow!(
                    "failed to acquire state lock on {}",
                    lock_path.display()
                ));
            }
        }
    }
    Ok(StateFileLock {
        #[cfg(unix)]
        file,
    })
}

fn default_state_file_path() -> Result<PathBuf> {
    Ok(agentpay_home_dir()?.join("daemon-state.enc"))
}

fn default_socket_path() -> Result<PathBuf> {
    Ok(agentpay_home_dir()?.join("daemon.sock"))
}

fn agentpay_home_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AGENTPAY_HOME") {
        let candidate = PathBuf::from(path);
        if candidate.as_os_str().is_empty() {
            bail!("AGENTPAY_HOME must not be empty");
        }
        return Ok(candidate);
    }

    let Some(home) = std::env::var_os("HOME") else {
        bail!("HOME is not set; use AGENTPAY_HOME to choose config directory");
    };
    let mut path = PathBuf::from(home);
    path.push(".agentpay");
    Ok(path)
}

fn ensure_file_parent(path: &Path, label: &str) -> Result<()> {
    if is_symlink(path)? {
        bail!("{label} path '{}' must not be a symlink", path.display());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
            if is_symlink(parent)? {
                bail!(
                    "{label} directory '{}' must not be a symlink",
                    parent.display()
                );
            }
            ensure_secure_directory_owner(parent, label)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn assert_allowed_directory_owner(
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
    label: &str,
) -> Result<()> {
    if owner_uid == 0 {
        return Ok(());
    }

    if effective_uid == 0 {
        bail!(
            "{label} directory '{}' must be owned by root; found uid {owner_uid}",
            path.display()
        );
    }

    if owner_uid != effective_uid {
        bail!(
            "{label} directory '{}' must be owned by current user or root; found uid {owner_uid}",
            path.display()
        );
    }

    Ok(())
}

#[cfg(unix)]
fn ensure_secure_directory_owner(path: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    const STICKY_BIT_MODE: u32 = 0o1000;

    fn validate_directory(
        path: &Path,
        metadata: &std::fs::Metadata,
        effective_uid: u32,
        label: &str,
        allow_sticky_group_other_write: bool,
    ) -> Result<()> {
        if !metadata.is_dir() {
            bail!("{label} directory '{}' is not a directory", path.display());
        }
        assert_allowed_directory_owner(path, metadata.uid(), effective_uid, label)?;
        let mode = metadata.mode() & 0o7777;
        if mode & 0o022 != 0 && !(allow_sticky_group_other_write && mode & STICKY_BIT_MODE != 0) {
            bail!(
                "{label} directory '{}' must not be writable by group/other (current mode {:o})",
                path.display(),
                mode & 0o777
            );
        }
        Ok(())
    }

    let effective_uid = nix::unistd::geteuid().as_raw();
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect {label} directory {}", path.display()))?;
    validate_directory(path, &metadata, effective_uid, label, false)?;

    let canonical = std::fs::canonicalize(path).with_context(|| {
        format!(
            "failed to canonicalize {label} directory {}",
            path.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).with_context(|| {
            format!(
                "failed to inspect ancestor {label} directory {}",
                ancestor.display()
            )
        })?;
        validate_directory(ancestor, &metadata, effective_uid, label, true)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_secure_directory_owner(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

fn is_symlink(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("failed to inspect metadata for {}", path.display()))
        }
    }
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

#[cfg(test)]
mod tests {
    use super::{
        acquire_state_file_lock, default_socket_path, default_state_file_path, dispatch_runtime,
        ensure_file_parent, format_allowed_euids, is_symlink, lock_path, read_secret_from_reader,
        relay_signer_backend_label, resolve_allowed_peer_euids,
        resolve_allowed_peer_euids_with_sudo_uid, resolve_socket_path, resolve_state_file_path,
        resolve_vault_password, run_cli_with_runtime, validate_password,
        validate_signer_backend_runtime, agentpay_home_dir, AllowedPeerEuids, Cli, DaemonRuntime,
        SignerBackendKind,
    };
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use clap::Parser;
    use std::collections::BTreeSet;
    use std::io::{Cursor, Read};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroizing;

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_path(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ))
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RuntimeCall {
        SecureEnclave {
            daemon_socket: PathBuf,
            allowed_admin: BTreeSet<u32>,
            allowed_agent: BTreeSet<u32>,
            vault_password: String,
            state_file: PathBuf,
            secure_enclave_label_prefix: String,
            signer_backend_label: &'static str,
        },
        Software {
            daemon_socket: PathBuf,
            allowed_admin: BTreeSet<u32>,
            allowed_agent: BTreeSet<u32>,
            vault_password: String,
            state_file: PathBuf,
            signer_backend_label: &'static str,
        },
        #[cfg(target_os = "linux")]
        Tpm {
            daemon_socket: PathBuf,
            allowed_admin: BTreeSet<u32>,
            allowed_agent: BTreeSet<u32>,
            vault_password: String,
            state_file: PathBuf,
            tpm_device: PathBuf,
            signer_backend_label: &'static str,
        },
    }

    struct FakeRuntime {
        calls: Mutex<Vec<RuntimeCall>>,
        fail_message: Option<&'static str>,
    }

    #[async_trait]
    impl DaemonRuntime for FakeRuntime {
        async fn run_secure_enclave(
            &self,
            daemon_socket: PathBuf,
            allowed_peer_euids: AllowedPeerEuids,
            vault_password: Zeroizing<String>,
            state_file: PathBuf,
            secure_enclave_label_prefix: String,
            signer_backend_label: &'static str,
        ) -> Result<()> {
            self.calls
                .lock()
                .expect("lock")
                .push(RuntimeCall::SecureEnclave {
                    daemon_socket,
                    allowed_admin: allowed_peer_euids.admin,
                    allowed_agent: allowed_peer_euids.agent,
                    vault_password: vault_password.to_string(),
                    state_file,
                    secure_enclave_label_prefix,
                    signer_backend_label,
                });
            match self.fail_message {
                Some(message) => Err(anyhow!(message)),
                None => Ok(()),
            }
        }

        async fn run_software(
            &self,
            daemon_socket: PathBuf,
            allowed_peer_euids: AllowedPeerEuids,
            vault_password: Zeroizing<String>,
            state_file: PathBuf,
            signer_backend_label: &'static str,
        ) -> Result<()> {
            self.calls
                .lock()
                .expect("lock")
                .push(RuntimeCall::Software {
                    daemon_socket,
                    allowed_admin: allowed_peer_euids.admin,
                    allowed_agent: allowed_peer_euids.agent,
                    vault_password: vault_password.to_string(),
                    state_file,
                    signer_backend_label,
                });
            match self.fail_message {
                Some(message) => Err(anyhow!(message)),
                None => Ok(()),
            }
        }

        #[cfg(target_os = "linux")]
        async fn run_tpm(
            &self,
            daemon_socket: PathBuf,
            allowed_peer_euids: AllowedPeerEuids,
            vault_password: Zeroizing<String>,
            state_file: PathBuf,
            tpm_device: PathBuf,
            signer_backend_label: &'static str,
        ) -> Result<()> {
            self.calls
                .lock()
                .expect("lock")
                .push(RuntimeCall::Tpm {
                    daemon_socket,
                    allowed_admin: allowed_peer_euids.admin,
                    allowed_agent: allowed_peer_euids.agent,
                    vault_password: vault_password.to_string(),
                    state_file,
                    tpm_device,
                    signer_backend_label,
                });
            match self.fail_message {
                Some(message) => Err(anyhow!(message)),
                None => Ok(()),
            }
        }
    }

    fn sample_cli(root: &Path, signer_backend: SignerBackendKind) -> Cli {
        Cli {
            vault_password_stdin: false,
            non_interactive: false,
            state_file: Some(root.join("state").join("daemon-state.enc")),
            daemon_socket: Some(root.join("socket").join("daemon.sock")),
            secure_enclave_label_prefix: "com.agentpay.test".to_string(),
            signer_backend,
            #[cfg(target_os = "linux")]
            tpm_device: "/dev/tpmrm0".into(),
            allow_admin_euid: vec![11],
            allow_agent_euid: vec![22],
            allow_client_euid: vec![33],
        }
    }

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn validate_password_rejects_oversized_non_stdin_secret() {
        let err = validate_password(
            "a".repeat((16 * 1024) + 1).into(),
            "argument or environment",
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn validate_password_rejects_whitespace_only() {
        let err = validate_password(" \n\t ".to_string().into(), "stdin").expect_err("must fail");
        assert!(err.to_string().contains("must not be empty or whitespace"));
    }

    #[test]
    fn cli_rejects_inline_vault_password_argument() {
        let err = Cli::try_parse_from([
            "agentpay-daemon",
            "--vault-password",
            "vault-secret",
            "--non-interactive",
        ])
        .expect_err("must reject");
        assert!(err.to_string().contains("--vault-password"));
    }

    #[test]
    fn resolve_vault_password_requires_stdin_in_non_interactive_mode() {
        let err = resolve_vault_password(false, true).expect_err("must fail");
        assert!(err.to_string().contains("use --vault-password-stdin"));
    }

    #[test]
    fn read_secret_from_reader_trims_trailing_newlines() {
        let secret = read_secret_from_reader(Cursor::new("vault-secret\r\n"), "vault password")
            .expect("trimmed secret");
        assert_eq!(secret.as_str(), "vault-secret");
    }

    #[test]
    fn read_secret_from_reader_rejects_blank_after_trimming() {
        let err =
            read_secret_from_reader(Cursor::new(" \n"), "vault password").expect_err("must fail");
        assert!(err.to_string().contains("must not be empty or whitespace"));
    }

    #[test]
    fn read_secret_from_reader_propagates_io_errors() {
        let err = read_secret_from_reader(FailingReader, "vault password").expect_err("must fail");
        assert!(err
            .to_string()
            .contains("failed to read vault password from stdin"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_file_parent_accepts_current_user_owned_directory() {
        let parent = temp_path("agentpay-daemon-parent");
        std::fs::create_dir_all(&parent).expect("create parent");
        let path = parent.join("daemon-state.enc");
        ensure_file_parent(&path, "state").expect("current-user-owned directory should pass");
        std::fs::remove_dir_all(&parent).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_file_parent_rejects_group_writable_ancestor_directory() {
        use std::os::unix::fs::PermissionsExt;

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "agentpay-daemon-parent-ancestor-{}-{}",
            std::process::id(),
            unique
        ));
        let shared = root.join("shared");
        let nested = shared.join("nested");
        std::fs::create_dir_all(&nested).expect("create nested directory");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777))
            .expect("set insecure ancestor permissions");
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700))
            .expect("set nested permissions");

        let path = nested.join("daemon-state.enc");
        let err = ensure_file_parent(&path, "state").expect_err("must reject");
        assert!(err
            .to_string()
            .contains("must not be writable by group/other"));

        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700))
            .expect("restore cleanup permissions");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn resolve_allowed_peer_euids_keeps_root_only_when_allowlists_are_omitted() {
        let resolved = resolve_allowed_peer_euids_with_sudo_uid(&[], &[], &[], Some(501))
            .expect("allowed peer euids");

        assert_eq!(resolved.admin, BTreeSet::from([0]));
        assert_eq!(resolved.agent, BTreeSet::from([0]));
    }

    #[test]
    fn resolve_allowed_peer_euids_supports_split_admin_and_agent_allowlists() {
        let resolved = resolve_allowed_peer_euids_with_sudo_uid(&[11], &[22], &[33], Some(501))
            .expect("allowed peer euids");

        assert_eq!(resolved.admin, BTreeSet::from([0, 11, 33]));
        assert_eq!(resolved.agent, BTreeSet::from([0, 22, 33]));
    }

    #[test]
    fn resolve_allowed_peer_euids_wrapper_matches_internal_helper() {
        let resolved = resolve_allowed_peer_euids(&[7], &[8], &[9]).expect("allowed peer euids");
        assert_eq!(resolved.admin, BTreeSet::from([0, 7, 9]));
        assert_eq!(resolved.agent, BTreeSet::from([0, 8, 9]));
    }

    #[test]
    fn relay_signer_backend_label_matches_runtime_backend() {
        assert_eq!(
            relay_signer_backend_label(SignerBackendKind::SecureEnclave),
            "secure-enclave"
        );
        assert_eq!(
            relay_signer_backend_label(SignerBackendKind::Software),
            "software"
        );
    }

    #[test]
    fn validate_signer_backend_runtime_accepts_software_everywhere() {
        validate_signer_backend_runtime(SignerBackendKind::Software).expect("software backend");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn validate_signer_backend_runtime_rejects_secure_enclave_off_macos() {
        let err = validate_signer_backend_runtime(SignerBackendKind::SecureEnclave)
            .expect_err("must fail");
        assert!(err
            .to_string()
            .contains("Secure Enclave daemon mode is supported only on macOS"));
    }

    #[test]
    fn format_allowed_euids_renders_sorted_csv() {
        assert_eq!(
            format_allowed_euids(&BTreeSet::from([0, 11, 33])),
            "0,11,33"
        );
    }

    #[test]
    fn lock_path_appends_lock_suffix() {
        assert_eq!(
            lock_path(Path::new("/tmp/agentpay/daemon-state.enc")),
            PathBuf::from("/tmp/agentpay/daemon-state.enc.lock")
        );
    }

    #[test]
    fn agentpay_home_dir_prefers_agentpay_home_and_falls_back_to_home() {
        let _guard = env_lock().lock().expect("env lock");
        let agentpay_home = temp_path("agentpay-home");
        let home = temp_path("home-dir");

        std::env::set_var("AGENTPAY_HOME", &agentpay_home);
        std::env::set_var("HOME", &home);
        assert_eq!(agentpay_home_dir().expect("agentpay home"), agentpay_home);

        std::env::remove_var("AGENTPAY_HOME");
        assert_eq!(
            agentpay_home_dir().expect("home fallback"),
            home.join(".agentpay")
        );

        std::env::remove_var("HOME");
    }

    #[test]
    fn agentpay_home_dir_rejects_empty_and_missing_env() {
        let _guard = env_lock().lock().expect("env lock");

        std::env::set_var("AGENTPAY_HOME", "");
        let err = agentpay_home_dir().expect_err("must reject empty AGENTPAY_HOME");
        assert!(err.to_string().contains("AGENTPAY_HOME must not be empty"));

        std::env::remove_var("AGENTPAY_HOME");
        std::env::remove_var("HOME");
        let err = agentpay_home_dir().expect_err("must reject missing HOME");
        assert!(err
            .to_string()
            .contains("HOME is not set; use AGENTPAY_HOME to choose config directory"));
    }

    #[test]
    fn default_paths_and_resolvers_use_agentpay_home() {
        let _guard = env_lock().lock().expect("env lock");
        let agentpay_home = temp_path("agentpay-daemon-defaults");
        std::env::set_var("AGENTPAY_HOME", &agentpay_home);

        assert_eq!(
            default_state_file_path().expect("default state"),
            agentpay_home.join("daemon-state.enc")
        );
        assert_eq!(
            default_socket_path().expect("default socket"),
            agentpay_home.join("daemon.sock")
        );
        assert_eq!(
            resolve_state_file_path(None).expect("resolved state"),
            agentpay_home.join("daemon-state.enc")
        );
        assert_eq!(
            resolve_socket_path(None).expect("resolved socket"),
            agentpay_home.join("daemon.sock")
        );

        std::env::remove_var("AGENTPAY_HOME");
    }

    #[test]
    fn dispatch_runtime_routes_to_expected_backend() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-dispatch");
        let state_file = root.join("state.enc");
        let daemon_socket = root.join("daemon.sock");
        let allowed = AllowedPeerEuids {
            admin: BTreeSet::from([0, 11, 33]),
            agent: BTreeSet::from([0, 22, 33]),
        };

        let secure_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };
        runtime
            .block_on(dispatch_runtime(
                sample_cli(&root, SignerBackendKind::SecureEnclave),
                "vault-secret".to_string().into(),
                state_file.clone(),
                daemon_socket.clone(),
                allowed.clone(),
                &secure_runtime,
            ))
            .expect("secure enclave dispatch");
        assert_eq!(
            secure_runtime.calls.lock().expect("lock").as_slice(),
            &[RuntimeCall::SecureEnclave {
                daemon_socket: daemon_socket.clone(),
                allowed_admin: BTreeSet::from([0, 11, 33]),
                allowed_agent: BTreeSet::from([0, 22, 33]),
                vault_password: "vault-secret".to_string(),
                state_file: state_file.clone(),
                secure_enclave_label_prefix: "com.agentpay.test".to_string(),
                signer_backend_label: "secure-enclave",
            }]
        );

        let software_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };
        runtime
            .block_on(dispatch_runtime(
                sample_cli(&root, SignerBackendKind::Software),
                "vault-secret".to_string().into(),
                state_file.clone(),
                daemon_socket.clone(),
                allowed,
                &software_runtime,
            ))
            .expect("software dispatch");
        assert_eq!(
            software_runtime.calls.lock().expect("lock").as_slice(),
            &[RuntimeCall::Software {
                daemon_socket,
                allowed_admin: BTreeSet::from([0, 11, 33]),
                allowed_agent: BTreeSet::from([0, 22, 33]),
                vault_password: "vault-secret".to_string(),
                state_file,
                signer_backend_label: "software",
            }]
        );
    }

    #[test]
    fn run_cli_with_runtime_resolves_paths_and_lock_before_invoking_runtime() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-run-runtime");
        let cli = sample_cli(&root, SignerBackendKind::Software);
        let fake_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };

        runtime
            .block_on(run_cli_with_runtime(
                cli,
                "vault-secret".to_string().into(),
                &fake_runtime,
            ))
            .expect("runtime dispatch");

        assert!(root.join("state").exists());
        assert!(root.join("socket").exists());
        assert!(root.join("state").join("daemon-state.enc.lock").exists());
        assert_eq!(fake_runtime.calls.lock().expect("lock").len(), 1);

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn run_cli_with_runtime_rejects_secure_enclave_before_runtime_invocation() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-secure-enclave");
        let fake_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: None,
        };

        let err = runtime
            .block_on(run_cli_with_runtime(
                sample_cli(&root, SignerBackendKind::SecureEnclave),
                "vault-secret".to_string().into(),
                &fake_runtime,
            ))
            .expect_err("secure enclave must fail");
        assert!(err
            .to_string()
            .contains("Secure Enclave daemon mode is supported only on macOS"));
        assert!(fake_runtime.calls.lock().expect("lock").is_empty());
    }

    #[test]
    fn dispatch_runtime_bubbles_runtime_failures() {
        let runtime = test_runtime();
        let root = temp_path("agentpay-daemon-runtime-error");
        let err_runtime = FakeRuntime {
            calls: Mutex::new(Vec::new()),
            fail_message: Some("runtime boom"),
        };

        let err = runtime
            .block_on(dispatch_runtime(
                sample_cli(&root, SignerBackendKind::Software),
                "vault-secret".to_string().into(),
                root.join("daemon-state.enc"),
                root.join("daemon.sock"),
                AllowedPeerEuids {
                    admin: BTreeSet::from([0]),
                    agent: BTreeSet::from([0]),
                },
                &err_runtime,
            ))
            .expect_err("runtime failure must bubble");
        assert!(err.to_string().contains("runtime boom"));
    }

    #[test]
    fn explicit_state_and_socket_paths_are_preserved() {
        let root = temp_path("agentpay-daemon-explicit");
        let state = root.join("state").join("daemon-state.enc");
        let socket = root.join("sock").join("daemon.sock");

        let resolved_state = resolve_state_file_path(Some(state.clone())).expect("state path");
        let resolved_socket = resolve_socket_path(Some(socket.clone())).expect("socket path");
        assert_eq!(resolved_state, state);
        assert_eq!(resolved_socket, socket);
        assert!(root.join("state").exists());
        assert!(root.join("sock").exists());

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn acquire_state_file_lock_creates_lock_file() {
        let root = temp_path("agentpay-daemon-lock");
        let state_path = root.join("daemon-state.enc");

        let lock = acquire_state_file_lock(&state_path).expect("lock file");
        let lock_file = lock_path(&state_path);
        assert!(lock_file.exists());
        drop(lock);

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn ensure_file_parent_rejects_symlink_path_and_is_symlink_reports_it() {
        use std::os::unix::fs::symlink;

        let root = temp_path("agentpay-daemon-symlink");
        std::fs::create_dir_all(&root).expect("create root");
        let target = root.join("real-state.enc");
        let link = root.join("linked-state.enc");
        std::fs::write(&target, "seed").expect("seed");
        symlink(&target, &link).expect("symlink");

        assert!(is_symlink(&link).expect("symlink metadata"));
        let err = ensure_file_parent(&link, "state").expect_err("must reject symlink file");
        assert!(err.to_string().contains("must not be a symlink"));

        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn is_symlink_returns_false_for_missing_path() {
        let missing = temp_path("agentpay-daemon-missing");
        assert!(!is_symlink(&missing).expect("missing path is not symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_rejects_non_root_owner_for_root_runtime() {
        let err = super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 501, 0, "state")
            .expect_err("root runtime must reject non-root owner");

        assert!(err.to_string().contains("must be owned by root"));
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_allows_root_owner_for_root_runtime() {
        super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 0, 0, "state")
            .expect("root runtime should allow root-owned directories");
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_allows_current_user_for_non_root_runtime() {
        super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 501, 501, "state")
            .expect("non-root runtime should allow current-user-owned directories");
    }

    #[cfg(unix)]
    #[test]
    fn assert_allowed_directory_owner_rejects_other_user_for_non_root_runtime() {
        let err = super::assert_allowed_directory_owner(Path::new("/tmp/agentpay"), 502, 501, "state")
            .expect_err("non-root runtime must reject another user's directory");

        assert!(err
            .to_string()
            .contains("must be owned by current user or root"));
    }
}
