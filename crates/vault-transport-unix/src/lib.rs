//! Unix-domain socket transport for daemon RPC calls.
//!
//! This transport is intended for local long-running daemon deployments where
//! CLIs/SDK clients communicate with a separate process over a filesystem
//! socket path.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use uuid::Uuid;
use vault_daemon::{
    DaemonError, DaemonRpcRequest, DaemonRpcResponse, InMemoryDaemon, KeyManagerDaemonApi,
    PolicySummary,
};
use vault_domain::{
    AdminSession, AgentCredentials, Lease, ManualApprovalDecision, ManualApprovalRequest,
    ManualApprovalStatus, NonceReleaseRequest, NonceReservation, NonceReservationRequest,
    PolicyAttachment, RelayConfig, SignRequest, Signature, SpendingPolicy, VaultKey,
};
use vault_policy::{PolicyEvaluation, PolicyExplanation};
use vault_signer::{KeyCreateRequest, SignerError, VaultSignerBackend};
use zeroize::Zeroize;

const MAX_WIRE_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Validates that a client daemon socket path is an existing trusted unix socket in a secure directory.
pub fn assert_trusted_daemon_socket_path(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("daemon socket path must not be empty".to_string());
    }

    if is_symlink(path)? {
        return Err(format!(
            "socket path '{}' must not be a symlink",
            path.display()
        ));
    }

    let Some(parent) = path.parent() else {
        return Err(format!(
            "socket path '{}' must have a parent directory",
            path.display()
        ));
    };
    if parent.as_os_str().is_empty() {
        return Err(format!(
            "socket path '{}' must have a parent directory",
            path.display()
        ));
    }
    if is_symlink(parent)? {
        return Err(format!(
            "socket directory '{}' must not be a symlink",
            parent.display()
        ));
    }
    ensure_secure_socket_directory(parent)?;

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect socket path '{}': {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        if !metadata.file_type().is_socket() {
            return Err(format!(
                "socket path '{}' must be a unix socket",
                path.display()
            ));
        }
        let uid = metadata.uid();
        let allowed = allowed_owner_uids()?;
        if !allowed.contains(&uid) {
            return Err(format!(
                "socket path '{}' must be owned by current user, sudo caller, or root (found uid {uid})",
                path.display(),
            ));
        }
    }

    Ok(path.to_path_buf())
}

/// Validates that a client daemon socket path is an existing root-owned unix socket in a secure directory.
pub fn assert_root_owned_daemon_socket_path(path: &Path) -> Result<PathBuf, String> {
    let resolved = assert_trusted_daemon_socket_path(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::symlink_metadata(&resolved).map_err(|err| {
            format!(
                "failed to inspect socket path '{}': {err}",
                resolved.display()
            )
        })?;
        if metadata.uid() != 0 {
            return Err(format!(
                "socket path '{}' must be owned by root",
                resolved.display()
            ));
        }
    }

    Ok(resolved)
}

/// Errors returned by unix socket transport.
#[derive(Debug, Error)]
pub enum UnixTransportError {
    /// Message serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Protocol-level failure.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Underlying daemon returned an error.
    #[error("daemon error: {0}")]
    Daemon(#[from] DaemonError),
    /// Filesystem/socket operation failed.
    #[error("io error: {0}")]
    Io(String),
    /// Timed out waiting for I/O.
    #[error("transport timeout")]
    Timeout,
    /// Client process is not authorized by daemon peer-euid policy.
    #[error("unauthorized peer euid (allowed {allowed:?}, got {actual})")]
    UnauthorizedPeerEuid { allowed: Vec<u32>, actual: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireRequest {
    body_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireResponse {
    ok: bool,
    body_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data")]
enum WireDaemonError {
    AuthenticationFailed,
    UnknownLease,
    InvalidLease,
    TooManyActiveLeases,
    UnknownVaultKey(Uuid),
    UnknownAgentKey(Uuid),
    UnknownPolicy(Uuid),
    UnknownManualApprovalRequest(Uuid),
    AgentAuthenticationFailed,
    PayloadActionMismatch,
    PayloadTooLarge {
        max_bytes: usize,
    },
    InvalidRequestTimestamps,
    RequestExpired,
    RequestReplayDetected,
    TooManyTrackedReplayIds {
        max_tracked: usize,
    },
    InvalidPolicyAttachment(String),
    InvalidNonceReservation(String),
    TooManyActiveNonceReservations {
        max_active: usize,
    },
    UnknownNonceReservation(Uuid),
    MissingNonceReservation {
        chain_id: u64,
        nonce: u64,
    },
    InvalidPolicy(String),
    InvalidRelayConfig(String),
    ManualApprovalRequired {
        approval_request_id: Uuid,
        relay_url: Option<String>,
        frontend_url: Option<String>,
    },
    ManualApprovalRejected {
        approval_request_id: Uuid,
    },
    ManualApprovalRequestNotPending {
        approval_request_id: Uuid,
        status: ManualApprovalStatus,
    },
    Policy(vault_policy::PolicyError),
    Signer(SignerError),
    PasswordHash(String),
    InvalidConfig(String),
    LockPoisoned,
    Transport(String),
    Persistence(String),
}

impl From<DaemonError> for WireDaemonError {
    fn from(value: DaemonError) -> Self {
        match value {
            DaemonError::AuthenticationFailed => Self::AuthenticationFailed,
            DaemonError::UnknownLease => Self::UnknownLease,
            DaemonError::InvalidLease => Self::InvalidLease,
            DaemonError::TooManyActiveLeases => Self::TooManyActiveLeases,
            DaemonError::UnknownVaultKey(id) => Self::UnknownVaultKey(id),
            DaemonError::UnknownAgentKey(id) => Self::UnknownAgentKey(id),
            DaemonError::UnknownPolicy(id) => Self::UnknownPolicy(id),
            DaemonError::UnknownManualApprovalRequest(id) => Self::UnknownManualApprovalRequest(id),
            DaemonError::AgentAuthenticationFailed => Self::AgentAuthenticationFailed,
            DaemonError::PayloadActionMismatch => Self::PayloadActionMismatch,
            DaemonError::PayloadTooLarge { max_bytes } => Self::PayloadTooLarge { max_bytes },
            DaemonError::InvalidRequestTimestamps => Self::InvalidRequestTimestamps,
            DaemonError::RequestExpired => Self::RequestExpired,
            DaemonError::RequestReplayDetected => Self::RequestReplayDetected,
            DaemonError::TooManyTrackedReplayIds { max_tracked } => {
                Self::TooManyTrackedReplayIds { max_tracked }
            }
            DaemonError::InvalidPolicyAttachment(msg) => Self::InvalidPolicyAttachment(msg),
            DaemonError::InvalidNonceReservation(msg) => Self::InvalidNonceReservation(msg),
            DaemonError::TooManyActiveNonceReservations { max_active } => {
                Self::TooManyActiveNonceReservations { max_active }
            }
            DaemonError::UnknownNonceReservation(id) => Self::UnknownNonceReservation(id),
            DaemonError::MissingNonceReservation { chain_id, nonce } => {
                Self::MissingNonceReservation { chain_id, nonce }
            }
            DaemonError::InvalidPolicy(msg) => Self::InvalidPolicy(msg),
            DaemonError::InvalidRelayConfig(msg) => Self::InvalidRelayConfig(msg),
            DaemonError::ManualApprovalRequired {
                approval_request_id,
                relay_url,
                frontend_url,
            } => Self::ManualApprovalRequired {
                approval_request_id,
                relay_url,
                frontend_url,
            },
            DaemonError::ManualApprovalRejected {
                approval_request_id,
            } => Self::ManualApprovalRejected {
                approval_request_id,
            },
            DaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            } => Self::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            },
            DaemonError::Policy(err) => Self::Policy(err),
            DaemonError::Signer(err) => Self::Signer(err),
            DaemonError::PasswordHash(msg) => Self::PasswordHash(msg),
            DaemonError::InvalidConfig(msg) => Self::InvalidConfig(msg),
            DaemonError::LockPoisoned => Self::LockPoisoned,
            DaemonError::Transport(msg) => Self::Transport(msg),
            DaemonError::Persistence(msg) => Self::Persistence(msg),
        }
    }
}

impl WireDaemonError {
    fn into_daemon_error(self) -> DaemonError {
        match self {
            WireDaemonError::AuthenticationFailed => DaemonError::AuthenticationFailed,
            WireDaemonError::UnknownLease => DaemonError::UnknownLease,
            WireDaemonError::InvalidLease => DaemonError::InvalidLease,
            WireDaemonError::TooManyActiveLeases => DaemonError::TooManyActiveLeases,
            WireDaemonError::UnknownVaultKey(id) => DaemonError::UnknownVaultKey(id),
            WireDaemonError::UnknownAgentKey(id) => DaemonError::UnknownAgentKey(id),
            WireDaemonError::UnknownPolicy(id) => DaemonError::UnknownPolicy(id),
            WireDaemonError::UnknownManualApprovalRequest(id) => {
                DaemonError::UnknownManualApprovalRequest(id)
            }
            WireDaemonError::AgentAuthenticationFailed => DaemonError::AgentAuthenticationFailed,
            WireDaemonError::PayloadActionMismatch => DaemonError::PayloadActionMismatch,
            WireDaemonError::PayloadTooLarge { max_bytes } => {
                DaemonError::PayloadTooLarge { max_bytes }
            }
            WireDaemonError::InvalidRequestTimestamps => DaemonError::InvalidRequestTimestamps,
            WireDaemonError::RequestExpired => DaemonError::RequestExpired,
            WireDaemonError::RequestReplayDetected => DaemonError::RequestReplayDetected,
            WireDaemonError::TooManyTrackedReplayIds { max_tracked } => {
                DaemonError::TooManyTrackedReplayIds { max_tracked }
            }
            WireDaemonError::InvalidPolicyAttachment(msg) => {
                DaemonError::InvalidPolicyAttachment(msg)
            }
            WireDaemonError::InvalidNonceReservation(msg) => {
                DaemonError::InvalidNonceReservation(msg)
            }
            WireDaemonError::TooManyActiveNonceReservations { max_active } => {
                DaemonError::TooManyActiveNonceReservations { max_active }
            }
            WireDaemonError::UnknownNonceReservation(id) => {
                DaemonError::UnknownNonceReservation(id)
            }
            WireDaemonError::MissingNonceReservation { chain_id, nonce } => {
                DaemonError::MissingNonceReservation { chain_id, nonce }
            }
            WireDaemonError::InvalidPolicy(msg) => DaemonError::InvalidPolicy(msg),
            WireDaemonError::InvalidRelayConfig(msg) => DaemonError::InvalidRelayConfig(msg),
            WireDaemonError::ManualApprovalRequired {
                approval_request_id,
                relay_url,
                frontend_url,
            } => DaemonError::ManualApprovalRequired {
                approval_request_id,
                relay_url,
                frontend_url,
            },
            WireDaemonError::ManualApprovalRejected {
                approval_request_id,
            } => DaemonError::ManualApprovalRejected {
                approval_request_id,
            },
            WireDaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            } => DaemonError::ManualApprovalRequestNotPending {
                approval_request_id,
                status,
            },
            WireDaemonError::Policy(err) => DaemonError::Policy(err),
            WireDaemonError::Signer(err) => DaemonError::Signer(err),
            WireDaemonError::PasswordHash(msg) => DaemonError::PasswordHash(msg),
            WireDaemonError::InvalidConfig(msg) => DaemonError::InvalidConfig(msg),
            WireDaemonError::LockPoisoned => DaemonError::LockPoisoned,
            WireDaemonError::Transport(msg) => DaemonError::Transport(msg),
            WireDaemonError::Persistence(msg) => DaemonError::Persistence(msg),
        }
    }
}

/// Client adapter backed by unix-domain socket transport.
#[derive(Debug, Clone)]
pub struct UnixDaemonClient {
    socket_path: PathBuf,
    timeout: Duration,
    expected_server_euid: u32,
}

impl UnixDaemonClient {
    /// Creates a unix transport client.
    #[must_use]
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Self {
        Self::new_with_expected_server_euid(socket_path, timeout, nix::unistd::geteuid().as_raw())
    }

    /// Creates a unix transport client with explicit expected daemon euid.
    ///
    /// This allows hardened callers to pin daemon identity (for example `0` for root daemon).
    #[must_use]
    pub fn new_with_expected_server_euid(
        socket_path: PathBuf,
        timeout: Duration,
        expected_server_euid: u32,
    ) -> Self {
        Self {
            socket_path,
            timeout,
            expected_server_euid,
        }
    }

    /// Performs a single daemon RPC call.
    pub async fn call_rpc(
        &self,
        request: DaemonRpcRequest,
    ) -> Result<DaemonRpcResponse, UnixTransportError> {
        let mut request = request;
        let mut stream = tokio::time::timeout(self.timeout, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        let peer_euid = peer_euid(&stream).map_err(UnixTransportError::Io)?;
        if peer_euid != self.expected_server_euid {
            return Err(UnixTransportError::UnauthorizedPeerEuid {
                allowed: vec![self.expected_server_euid],
                actual: peer_euid,
            });
        }

        let body_json = serde_json::to_string(&request)
            .map_err(|err| UnixTransportError::Serialization(err.to_string()));
        request.zeroize_secrets();
        let mut body_json = body_json?;
        if body_json.len() > MAX_WIRE_BODY_BYTES {
            body_json.zeroize();
            return Err(UnixTransportError::Protocol(format!(
                "wire request body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
            )));
        }
        let mut wire_request = WireRequest { body_json };
        let write_result = write_frame(&mut stream, &wire_request, self.timeout).await;
        wire_request.body_json.zeroize();
        write_result?;

        let mut response: WireResponse = read_frame(&mut stream, self.timeout).await?;
        if response.ok {
            let parsed = serde_json::from_str::<DaemonRpcResponse>(&response.body_json)
                .map_err(|err| UnixTransportError::Serialization(err.to_string()));
            response.body_json.zeroize();
            parsed
        } else {
            let daemon_error = match serde_json::from_str::<WireDaemonError>(&response.body_json) {
                Ok(err) => Err(UnixTransportError::Daemon(err.into_daemon_error())),
                Err(_) => Err(UnixTransportError::Daemon(DaemonError::Transport(
                    response.body_json.clone(),
                ))),
            };
            response.body_json.zeroize();
            daemon_error
        }
    }
}

/// Unix daemon socket server bound to a local path.
pub struct UnixDaemonServer {
    listener: UnixListener,
    socket_path: PathBuf,
    allowed_admin_peer_euids: BTreeSet<u32>,
    allowed_agent_peer_euids: BTreeSet<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcAccessLevel {
    Admin,
    Agent,
}

fn rpc_access_level(request: &DaemonRpcRequest) -> RpcAccessLevel {
    match request {
        DaemonRpcRequest::IssueLease { .. }
        | DaemonRpcRequest::AddPolicy { .. }
        | DaemonRpcRequest::ListPolicies { .. }
        | DaemonRpcRequest::ListPolicySummaries { .. }
        | DaemonRpcRequest::DisablePolicy { .. }
        | DaemonRpcRequest::CreateVaultKey { .. }
        | DaemonRpcRequest::CreateAgentKey { .. }
        | DaemonRpcRequest::RefreshAgentKey { .. }
        | DaemonRpcRequest::ExportVaultPrivateKey { .. }
        | DaemonRpcRequest::SolanaPublicKey { .. }
        | DaemonRpcRequest::RotateAgentAuthToken { .. }
        | DaemonRpcRequest::RevokeAgentKey { .. }
        | DaemonRpcRequest::ListManualApprovalRequests { .. }
        | DaemonRpcRequest::DecideManualApprovalRequest { .. }
        | DaemonRpcRequest::SetRelayConfig { .. }
        | DaemonRpcRequest::GetRelayConfig { .. } => RpcAccessLevel::Admin,
        DaemonRpcRequest::EvaluateForAgent { .. }
        | DaemonRpcRequest::ExplainForAgent { .. }
        | DaemonRpcRequest::ReserveNonce { .. }
        | DaemonRpcRequest::ReleaseNonce { .. }
        | DaemonRpcRequest::SignForAgent { .. } => RpcAccessLevel::Agent,
    }
}

fn validate_allowed_peer_euids(
    label: &str,
    values: &BTreeSet<u32>,
) -> Result<(), UnixTransportError> {
    if values.is_empty() {
        return Err(UnixTransportError::Protocol(format!(
            "allowed {label} peer euid set must not be empty"
        )));
    }

    Ok(())
}

fn socket_mode_for_allowed_peer_euids(
    allowed_admin_peer_euids: &BTreeSet<u32>,
    allowed_agent_peer_euids: &BTreeSet<u32>,
) -> u32 {
    let only_root_admin =
        allowed_admin_peer_euids.len() == 1 && allowed_admin_peer_euids.contains(&0);
    let only_root_agent =
        allowed_agent_peer_euids.len() == 1 && allowed_agent_peer_euids.contains(&0);

    if only_root_admin && only_root_agent {
        0o600
    } else {
        0o666
    }
}

fn combined_allowed_peer_euids(
    allowed_admin_peer_euids: &BTreeSet<u32>,
    allowed_agent_peer_euids: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    allowed_admin_peer_euids
        .union(allowed_agent_peer_euids)
        .copied()
        .collect()
}

impl UnixDaemonServer {
    /// Binds server to `socket_path` and restricts clients to `allowed_peer_euids`.
    pub async fn bind(
        socket_path: PathBuf,
        allowed_peer_euids: BTreeSet<u32>,
    ) -> Result<Self, UnixTransportError> {
        Self::bind_with_allowed_peer_euids(
            socket_path,
            allowed_peer_euids.clone(),
            allowed_peer_euids,
        )
        .await
    }

    /// Binds server to `socket_path` with separate admin and agent peer-euid allowlists.
    pub async fn bind_with_allowed_peer_euids(
        socket_path: PathBuf,
        allowed_admin_peer_euids: BTreeSet<u32>,
        allowed_agent_peer_euids: BTreeSet<u32>,
    ) -> Result<Self, UnixTransportError> {
        validate_allowed_peer_euids("admin", &allowed_admin_peer_euids)?;
        validate_allowed_peer_euids("agent", &allowed_agent_peer_euids)?;

        ensure_socket_parent(&socket_path).map_err(UnixTransportError::Io)?;
        remove_existing_socket_file(&socket_path).map_err(UnixTransportError::Io)?;

        let listener = UnixListener::bind(&socket_path)
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let socket_mode = socket_mode_for_allowed_peer_euids(
                &allowed_admin_peer_euids,
                &allowed_agent_peer_euids,
            );
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(socket_mode))
                .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        }

        Ok(Self {
            listener,
            socket_path,
            allowed_admin_peer_euids,
            allowed_agent_peer_euids,
        })
    }

    /// Runs accept loop until `shutdown` resolves.
    pub async fn run_until_shutdown<B, S>(
        self,
        daemon: Arc<InMemoryDaemon<B>>,
        shutdown: S,
    ) -> Result<(), UnixTransportError>
    where
        B: VaultSignerBackend + 'static,
        S: std::future::Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    break;
                }
                accept_result = self.listener.accept() => {
                    let (stream, _) = accept_result
                        .map_err(|err| UnixTransportError::Io(err.to_string()))?;
                    let daemon = daemon.clone();
                    let allowed_admin_peer_euids = self.allowed_admin_peer_euids.clone();
                    let allowed_agent_peer_euids = self.allowed_agent_peer_euids.clone();
                    workers.push(tokio::spawn(async move {
                        let _ = handle_connection(
                            stream,
                            daemon,
                            allowed_admin_peer_euids,
                            allowed_agent_peer_euids,
                        )
                        .await;
                    }));
                }
            }
        }

        for worker in workers {
            let _ = worker.await;
        }
        Ok(())
    }

    /// Returns bound socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for UnixDaemonServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn handle_connection<B>(
    mut stream: UnixStream,
    daemon: Arc<InMemoryDaemon<B>>,
    allowed_admin_peer_euids: BTreeSet<u32>,
    allowed_agent_peer_euids: BTreeSet<u32>,
) -> Result<(), UnixTransportError>
where
    B: VaultSignerBackend + 'static,
{
    let peer_euid = peer_euid(&stream).map_err(UnixTransportError::Io)?;
    let globally_allowed_peer_euids =
        combined_allowed_peer_euids(&allowed_admin_peer_euids, &allowed_agent_peer_euids);
    if !globally_allowed_peer_euids.contains(&peer_euid) {
        return Err(UnixTransportError::UnauthorizedPeerEuid {
            allowed: globally_allowed_peer_euids.into_iter().collect(),
            actual: peer_euid,
        });
    }

    let mut request: WireRequest = read_frame(&mut stream, Duration::from_secs(10)).await?;
    if request.body_json.len() > MAX_WIRE_BODY_BYTES {
        request.body_json.zeroize();
        return Err(UnixTransportError::Protocol(format!(
            "wire request body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }

    let daemon_request = serde_json::from_str(&request.body_json)
        .map_err(|err| UnixTransportError::Serialization(err.to_string()));
    request.body_json.zeroize();
    let mut daemon_request: DaemonRpcRequest = daemon_request?;
    let allowed_peer_euids = match rpc_access_level(&daemon_request) {
        RpcAccessLevel::Admin => &allowed_admin_peer_euids,
        RpcAccessLevel::Agent => &allowed_agent_peer_euids,
    };
    if !allowed_peer_euids.contains(&peer_euid) {
        daemon_request.zeroize_secrets();
        return Err(UnixTransportError::UnauthorizedPeerEuid {
            allowed: allowed_peer_euids.iter().copied().collect(),
            actual: peer_euid,
        });
    }

    let response = match daemon.handle_rpc(daemon_request).await {
        Ok(success) => {
            let mut success = success;
            let body_json = serde_json::to_string(&success)
                .map_err(|err| UnixTransportError::Serialization(err.to_string()));
            success.zeroize_secrets();
            WireResponse {
                ok: true,
                body_json: body_json?,
            }
        }
        Err(err) => WireResponse {
            ok: false,
            body_json: serde_json::to_string(&WireDaemonError::from(err))
                .map_err(|ser| UnixTransportError::Serialization(ser.to_string()))?,
        },
    };
    let mut response = response;
    let write_result = write_frame(&mut stream, &response, Duration::from_secs(10)).await;
    response.body_json.zeroize();
    write_result?;
    Ok(())
}

async fn write_frame<T: Serialize>(
    stream: &mut UnixStream,
    value: &T,
    timeout: Duration,
) -> Result<(), UnixTransportError> {
    let mut payload = serde_json::to_vec(value)
        .map_err(|err| UnixTransportError::Serialization(err.to_string()))?;
    if payload.len() > MAX_WIRE_BODY_BYTES {
        payload.zeroize();
        return Err(UnixTransportError::Protocol(format!(
            "wire body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }
    let len = payload.len() as u32;
    let result = async {
        tokio::time::timeout(timeout, stream.write_all(&len.to_be_bytes()))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        tokio::time::timeout(timeout, stream.write_all(&payload))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        Ok(())
    }
    .await;
    payload.zeroize();
    result
}

async fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<T, UnixTransportError> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| UnixTransportError::Timeout)?
        .map_err(|err| UnixTransportError::Io(err.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_WIRE_BODY_BYTES {
        return Err(UnixTransportError::Protocol(format!(
            "wire frame exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }

    let mut payload = vec![0u8; len];
    let result = async {
        tokio::time::timeout(timeout, stream.read_exact(&mut payload))
            .await
            .map_err(|_| UnixTransportError::Timeout)?
            .map_err(|err| UnixTransportError::Io(err.to_string()))?;
        serde_json::from_slice::<T>(&payload)
            .map_err(|err| UnixTransportError::Serialization(err.to_string()))
    }
    .await;
    payload.zeroize();
    result
}

fn ensure_socket_parent(path: &Path) -> Result<(), String> {
    if is_symlink(path)? {
        return Err(format!(
            "socket path '{}' must not be a symlink",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                format!(
                    "failed to create socket directory '{}': {err}",
                    parent.display()
                )
            })?;
            if is_symlink(parent)? {
                return Err(format!(
                    "socket directory '{}' must not be a symlink",
                    parent.display()
                ));
            }
            ensure_secure_socket_directory(parent)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_secure_socket_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    const GROUP_OTHER_WRITE_MODE_MASK: u32 = 0o022;
    const STICKY_BIT_MODE: u32 = 0o1000;

    fn allowed_owner_uids() -> Result<BTreeSet<u32>, String> {
        let mut allowed = BTreeSet::new();
        allowed.insert(nix::unistd::geteuid().as_raw());
        if nix::unistd::geteuid().as_raw() == 0 {
            if let Some(raw) = std::env::var_os("SUDO_UID") {
                let rendered = raw.to_string_lossy();
                let parsed = rendered
                    .parse::<u32>()
                    .map_err(|_| format!("invalid SUDO_UID value '{rendered}'"))?;
                allowed.insert(parsed);
            }
        }
        Ok(allowed)
    }

    fn validate_directory(
        path: &Path,
        metadata: &std::fs::Metadata,
        allow_sticky_group_other_write: bool,
    ) -> Result<(), String> {
        if !metadata.is_dir() {
            return Err(format!(
                "socket directory '{}' must be a directory",
                path.display()
            ));
        }

        let uid = metadata.uid();
        if uid != 0 {
            let allowed = allowed_owner_uids()?;
            if !allowed.contains(&uid) {
                return Err(format!(
                    "socket directory '{}' must be owned by current user, sudo caller, or root (found uid {uid})",
                    path.display()
                ));
            }
        }

        let mode = metadata.mode() & 0o7777;
        if mode & GROUP_OTHER_WRITE_MODE_MASK != 0
            && !(allow_sticky_group_other_write && mode & STICKY_BIT_MODE != 0)
        {
            return Err(format!(
                "socket directory '{}' must not be writable by group/other",
                path.display()
            ));
        }

        Ok(())
    }

    let metadata = std::fs::metadata(path).map_err(|err| {
        format!(
            "failed to inspect socket directory '{}': {err}",
            path.display()
        )
    })?;
    validate_directory(path, &metadata, false)?;

    let canonical = std::fs::canonicalize(path).map_err(|err| {
        format!(
            "failed to canonicalize socket directory '{}': {err}",
            path.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = std::fs::metadata(ancestor).map_err(|err| {
            format!(
                "failed to inspect ancestor socket directory '{}': {err}",
                ancestor.display()
            )
        })?;
        validate_directory(ancestor, &metadata, true)?;
    }

    Ok(())
}

#[cfg(unix)]
fn allowed_owner_uids() -> Result<BTreeSet<u32>, String> {
    let mut allowed = BTreeSet::new();
    allowed.insert(nix::unistd::geteuid().as_raw());
    allowed.insert(0);
    if nix::unistd::geteuid().as_raw() == 0 {
        if let Some(raw) = std::env::var_os("SUDO_UID") {
            let rendered = raw.to_string_lossy();
            let parsed = rendered
                .parse::<u32>()
                .map_err(|_| format!("invalid SUDO_UID value '{rendered}'"))?;
            allowed.insert(parsed);
        }
    }
    Ok(allowed)
}

#[cfg(not(unix))]
fn ensure_secure_socket_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn remove_existing_socket_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect socket path '{}': {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            return Err(format!(
                "socket path '{}' exists and is not a unix socket",
                path.display()
            ));
        }
    }
    std::fs::remove_file(path)
        .map_err(|err| format!("failed to remove stale socket '{}': {err}", path.display()))
}

fn is_symlink(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "failed to inspect metadata for '{}': {err}",
            path.display()
        )),
    }
}

fn peer_euid(stream: &UnixStream) -> Result<u32, String> {
    let creds = stream.peer_cred().map_err(|err| err.to_string())?;
    Ok(creds.uid())
}

#[async_trait]
impl KeyManagerDaemonApi for UnixDaemonClient {
    async fn issue_lease(&self, vault_password: &str) -> Result<Lease, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::IssueLease {
                vault_password: vault_password.to_string(),
            })
            .await
        {
            Ok(DaemonRpcResponse::Lease(lease)) => Ok(lease),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn add_policy(
        &self,
        session: &AdminSession,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::AddPolicy {
                session: session.clone(),
                policy,
            })
            .await
        {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn list_policies(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<SpendingPolicy>, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ListPolicies {
                session: session.clone(),
            })
            .await
        {
            Ok(DaemonRpcResponse::Policies(policies)) => Ok(policies),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn list_policy_summaries(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<PolicySummary>, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ListPolicySummaries {
                session: session.clone(),
            })
            .await
        {
            Ok(DaemonRpcResponse::PolicySummaries(summaries)) => Ok(summaries),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn disable_policy(
        &self,
        session: &AdminSession,
        policy_id: Uuid,
    ) -> Result<(), DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::DisablePolicy {
                session: session.clone(),
                policy_id,
            })
            .await
        {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn create_vault_key(
        &self,
        session: &AdminSession,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::CreateVaultKey {
                session: session.clone(),
                request,
            })
            .await
        {
            Ok(DaemonRpcResponse::VaultKey(key)) => Ok(key),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn create_agent_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::CreateAgentKey {
                session: session.clone(),
                vault_key_id,
                attachment,
            })
            .await
        {
            Ok(DaemonRpcResponse::AgentCredentials(agent_credentials)) => Ok(agent_credentials),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn refresh_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::RefreshAgentKey {
                session: session.clone(),
                agent_key_id,
                vault_key_id,
                attachment,
            })
            .await
        {
            Ok(DaemonRpcResponse::AgentCredentials(agent_credentials)) => Ok(agent_credentials),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn export_vault_private_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<Option<String>, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ExportVaultPrivateKey {
                session: session.clone(),
                vault_key_id,
            })
            .await
        {
            Ok(DaemonRpcResponse::PrivateKey(private_key)) => Ok(private_key),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn solana_public_key_hex(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::SolanaPublicKey {
                session: session.clone(),
                vault_key_id,
            })
            .await
        {
            Ok(DaemonRpcResponse::PublicKey(public_key)) => Ok(public_key),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn rotate_agent_auth_token(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::RotateAgentAuthToken {
                session: session.clone(),
                agent_key_id,
            })
            .await
        {
            Ok(DaemonRpcResponse::AuthToken(token)) => Ok(token),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn revoke_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::RevokeAgentKey {
                session: session.clone(),
                agent_key_id,
            })
            .await
        {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn list_manual_approval_requests(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ListManualApprovalRequests {
                session: session.clone(),
            })
            .await
        {
            Ok(DaemonRpcResponse::ManualApprovalRequests(requests)) => Ok(requests),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn decide_manual_approval_request(
        &self,
        session: &AdminSession,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::DecideManualApprovalRequest {
                session: session.clone(),
                approval_request_id,
                decision,
                rejection_reason,
            })
            .await
        {
            Ok(DaemonRpcResponse::ManualApprovalRequest(request)) => Ok(request),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn set_relay_config(
        &self,
        session: &AdminSession,
        relay_url: Option<String>,
        frontend_url: Option<String>,
    ) -> Result<RelayConfig, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::SetRelayConfig {
                session: session.clone(),
                relay_url,
                frontend_url,
            })
            .await
        {
            Ok(DaemonRpcResponse::RelayConfig(relay_config)) => Ok(relay_config),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn get_relay_config(&self, session: &AdminSession) -> Result<RelayConfig, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::GetRelayConfig {
                session: session.clone(),
            })
            .await
        {
            Ok(DaemonRpcResponse::RelayConfig(relay_config)) => Ok(relay_config),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::EvaluateForAgent { request })
            .await
        {
            Ok(DaemonRpcResponse::PolicyEvaluation(evaluation)) => Ok(evaluation),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ExplainForAgent { request })
            .await
        {
            Ok(DaemonRpcResponse::PolicyExplanation(explanation)) => Ok(explanation),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ReserveNonce { request })
            .await
        {
            Ok(DaemonRpcResponse::NonceReservation(reservation)) => Ok(reservation),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::ReleaseNonce { request })
            .await
        {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError> {
        match self
            .call_rpc(DaemonRpcRequest::SignForAgent { request })
            .await
        {
            Ok(DaemonRpcResponse::Signature(sig)) => Ok(sig),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(UnixTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        assert_root_owned_daemon_socket_path, assert_trusted_daemon_socket_path,
        combined_allowed_peer_euids, ensure_socket_parent, handle_connection, read_frame,
        remove_existing_socket_file, rpc_access_level, socket_mode_for_allowed_peer_euids,
        write_frame, RpcAccessLevel, UnixDaemonClient, UnixDaemonServer, UnixTransportError,
        WireDaemonError, WireRequest, WireResponse, MAX_WIRE_BODY_BYTES,
    };
    use serde_json::to_vec;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use time::OffsetDateTime;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;
    use uuid::Uuid;
    use vault_daemon::{
        DaemonConfig, DaemonError, DaemonRpcRequest, DaemonRpcResponse, InMemoryDaemon,
        KeyManagerDaemonApi,
    };
    use vault_domain::{
        AdminSession, AgentAction, AgentCredentials, EntityScope, ManualApprovalStatus,
        NonceReleaseRequest, NonceReservationRequest, PolicyAttachment, PolicyType, RelayConfig,
        SignRequest, SpendingPolicy,
    };
    use vault_policy::{PolicyDecision, PolicyError};
    use vault_signer::SoftwareSignerBackend;
    use vault_signer::{KeyCreateRequest, SignerError};

    fn unique_socket_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "agentpay-{}-{}-{}.sock",
            label,
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ))
    }

    fn short_test_root(label: &str) -> std::path::PathBuf {
        let base = if Path::new("/private/tmp").is_dir() {
            Path::new("/private/tmp")
        } else {
            Path::new("/tmp")
        };
        base.join(format!(
            "w-{}-{}",
            label,
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        ))
    }

    fn singleton_allowed_set(euid: u32) -> BTreeSet<u32> {
        let mut set = BTreeSet::new();
        set.insert(euid);
        set
    }

    fn dummy_agent_request() -> SignRequest {
        SignRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: "agent-secret".to_string().into(),
            payload: vec![1, 2, 3],
            action: AgentAction::TransferNative {
                chain_id: 1,
                to: "0x2222222222222222222222222222222222222222"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(1),
        }
    }

    fn policy_all_per_tx(max_amount_wei: u128) -> SpendingPolicy {
        SpendingPolicy::new(
            0,
            PolicyType::PerTxMaxSpending,
            max_amount_wei,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("policy")
    }

    fn admin_session(lease: vault_domain::Lease) -> AdminSession {
        AdminSession {
            vault_password: "vault-password".to_string(),
            lease,
        }
    }

    fn sign_request(credentials: &AgentCredentials, amount_wei: u128) -> SignRequest {
        let action = AgentAction::TransferNative {
            chain_id: 1,
            to: "0x2222222222222222222222222222222222222222"
                .parse()
                .expect("recipient"),
            amount_wei,
        };
        let now = OffsetDateTime::now_utc();
        SignRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            payload: to_vec(&action).expect("serialize action"),
            action,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        }
    }

    fn nonce_reservation_request(
        credentials: &AgentCredentials,
        min_nonce: u64,
    ) -> NonceReservationRequest {
        let now = OffsetDateTime::now_utc();
        NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        }
    }

    fn nonce_release_request(
        credentials: &AgentCredentials,
        reservation_id: Uuid,
    ) -> NonceReleaseRequest {
        let now = OffsetDateTime::now_utc();
        NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        }
    }

    async fn spawn_one_shot_server(
        socket_path: std::path::PathBuf,
        response: WireResponse,
    ) -> tokio::task::JoinHandle<()> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).expect("create server parent");
        }
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind fake server");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _: WireRequest = read_frame(&mut stream, Duration::from_secs(2))
                .await
                .expect("read request");
            write_frame(&mut stream, &response, Duration::from_secs(2))
                .await
                .expect("write response");
        })
    }

    #[cfg(unix)]
    fn socket_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777
    }

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
        std::fs::create_dir_all(&nested).expect("create nested directory");
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
        std::fs::create_dir_all(&root).expect("create root directory");

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
        std::fs::create_dir_all(&root).expect("create root directory");

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

        let err = assert_trusted_daemon_socket_path(Path::new(""))
            .expect_err("empty path must be rejected");
        assert!(err.contains("must not be empty"));

        let err =
            assert_trusted_daemon_socket_path(Path::new("daemon.sock")).expect_err("must reject");
        assert!(err.contains("must have a parent directory"));

        let root = short_test_root("trusted");
        let real_dir = root.join("real");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
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

    #[tokio::test(flavor = "current_thread")]
    async fn write_and_read_frame_cover_protocol_and_serialization_errors() {
        let (mut writer, mut reader) = UnixStream::pair().expect("stream pair");
        let message = WireRequest {
            body_json: "{\"ok\":true}".to_string(),
        };
        write_frame(&mut writer, &message, Duration::from_secs(2))
            .await
            .expect("write frame");
        let decoded: WireRequest = read_frame(&mut reader, Duration::from_secs(2))
            .await
            .expect("read frame");
        assert_eq!(decoded.body_json, message.body_json);

        let oversized = WireRequest {
            body_json: "x".repeat(MAX_WIRE_BODY_BYTES + 1),
        };
        let err = write_frame(&mut writer, &oversized, Duration::from_secs(2))
            .await
            .expect_err("oversized write");
        assert!(
            matches!(err, UnixTransportError::Protocol(message) if message.contains("wire body exceeds max bytes"))
        );

        let (mut invalid_writer, mut invalid_reader) = UnixStream::pair().expect("stream pair");
        invalid_writer
            .write_all(&((MAX_WIRE_BODY_BYTES as u32) + 1).to_be_bytes())
            .await
            .expect("write length");
        let err = read_frame::<WireRequest>(&mut invalid_reader, Duration::from_secs(2))
            .await
            .expect_err("oversized read");
        assert!(
            matches!(err, UnixTransportError::Protocol(message) if message.contains("wire frame exceeds max bytes"))
        );

        let (mut malformed_writer, mut malformed_reader) = UnixStream::pair().expect("stream pair");
        malformed_writer
            .write_all(&(4u32).to_be_bytes())
            .await
            .expect("write length");
        malformed_writer
            .write_all(b"nope")
            .await
            .expect("write body");
        let err = read_frame::<WireRequest>(&mut malformed_reader, Duration::from_secs(2))
            .await
            .expect_err("malformed read");
        assert!(matches!(err, UnixTransportError::Serialization(_)));
    }

    #[test]
    #[cfg(unix)]
    fn remove_existing_socket_file_covers_missing_socket_and_non_socket_paths() {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let root = short_test_root("rm");
        std::fs::create_dir_all(&root).expect("create root");

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unix_round_trip_for_issue_lease() {
        let socket_path = unique_socket_path("lease");
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let server = UnixDaemonServer::bind(
            socket_path.clone(),
            singleton_allowed_set(nix::unistd::geteuid().as_raw()),
        )
        .await
        .expect("server");
        let server_task = tokio::spawn({
            let daemon = daemon.clone();
            async move {
                server
                    .run_until_shutdown(daemon, async {
                        std::future::pending::<()>().await;
                    })
                    .await
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));
        let lease = client.issue_lease("vault-password").await.expect("lease");
        assert_eq!(lease.lease_id.get_version_num(), 4);

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unix_round_trip_for_full_key_manager_api_surface() {
        let socket_path = unique_socket_path("full-surface");
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let server = UnixDaemonServer::bind(
            socket_path.clone(),
            singleton_allowed_set(nix::unistd::geteuid().as_raw()),
        )
        .await
        .expect("server");
        let server_task = tokio::spawn({
            let daemon = daemon.clone();
            async move {
                server
                    .run_until_shutdown(daemon, async {
                        std::future::pending::<()>().await;
                    })
                    .await
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));

        let lease = client.issue_lease("vault-password").await.expect("lease");
        let session = admin_session(lease);

        let policy = policy_all_per_tx(100);
        client
            .add_policy(&session, policy.clone())
            .await
            .expect("add policy");

        let policies = client.list_policies(&session).await.expect("list policies");
        assert_eq!(policies.len(), 1);
        assert!(policies[0].enabled);

        let vault_key = client
            .create_vault_key(&session, KeyCreateRequest::Generate)
            .await
            .expect("create vault key");
        let exported = client
            .export_vault_private_key(&session, vault_key.id)
            .await
            .expect("export key");
        assert!(exported.is_some());

        let mut credentials = client
            .create_agent_key(&session, vault_key.id, PolicyAttachment::AllPolicies)
            .await
            .expect("create agent key");

        let evaluation = client
            .evaluate_for_agent(sign_request(&credentials, 1))
            .await
            .expect("evaluate");
        assert_eq!(evaluation.evaluated_policy_ids, vec![policy.id]);

        let explanation = client
            .explain_for_agent(sign_request(&credentials, 1))
            .await
            .expect("explain");
        assert!(matches!(explanation.decision, PolicyDecision::Allow));

        let signature = client
            .sign_for_agent(sign_request(&credentials, 1))
            .await
            .expect("sign");
        assert!(!signature.bytes.is_empty());

        let reservation = client
            .reserve_nonce(nonce_reservation_request(&credentials, 7))
            .await
            .expect("reserve nonce");
        assert_eq!(reservation.nonce, 7);
        client
            .release_nonce(nonce_release_request(
                &credentials,
                reservation.reservation_id,
            ))
            .await
            .expect("release nonce");

        let rotated_token = client
            .rotate_agent_auth_token(&session, credentials.agent_key.id)
            .await
            .expect("rotate token");
        credentials.auth_token = rotated_token.into();

        let approvals = client
            .list_manual_approval_requests(&session)
            .await
            .expect("list approvals");
        assert!(approvals.is_empty());

        let relay_config = client
            .set_relay_config(
                &session,
                Some("http://127.0.0.1:8787".to_string()),
                Some("https://relay.example".to_string()),
            )
            .await
            .expect("set relay config");
        assert_eq!(
            relay_config,
            RelayConfig {
                relay_url: Some("http://127.0.0.1:8787".to_string()),
                frontend_url: Some("https://relay.example".to_string()),
                daemon_id_hex: relay_config.daemon_id_hex.clone(),
                daemon_public_key_hex: relay_config.daemon_public_key_hex.clone(),
            }
        );
        let current_relay_config = client
            .get_relay_config(&session)
            .await
            .expect("get relay config");
        assert_eq!(current_relay_config.relay_url, relay_config.relay_url);
        assert_eq!(current_relay_config.frontend_url, relay_config.frontend_url);

        client
            .disable_policy(&session, policy.id)
            .await
            .expect("disable policy");
        let disabled = client.list_policies(&session).await.expect("list disabled");
        assert_eq!(disabled.len(), 1);
        assert!(!disabled[0].enabled);

        client
            .revoke_agent_key(&session, credentials.agent_key.id)
            .await
            .expect("revoke agent");
        let err = client
            .sign_for_agent(sign_request(&credentials, 1))
            .await
            .expect_err("revoked agent must fail");
        assert!(
            matches!(
                err,
                DaemonError::UnknownAgentKey(id) if id == credentials.agent_key.id
            ) || matches!(err, DaemonError::AgentAuthenticationFailed)
        );

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_rejects_unexpected_daemon_euid() {
        let socket_path = unique_socket_path("peer-euid");
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let allowed_euid = nix::unistd::geteuid().as_raw();
        let server =
            UnixDaemonServer::bind(socket_path.clone(), singleton_allowed_set(allowed_euid))
                .await
                .expect("server");
        let server_task = tokio::spawn({
            let daemon = daemon.clone();
            async move {
                server
                    .run_until_shutdown(daemon, async {
                        std::future::pending::<()>().await;
                    })
                    .await
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let mismatched_expected_euid = allowed_euid.saturating_add(1);
        let client = UnixDaemonClient::new_with_expected_server_euid(
            socket_path.clone(),
            Duration::from_secs(2),
            mismatched_expected_euid,
        );
        let err = client
            .issue_lease("vault-password")
            .await
            .expect_err("must fail");
        assert!(
            err.to_string().contains("unauthorized peer euid"),
            "unexpected error: {err}"
        );

        server_task.abort();
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn call_rpc_surfaces_wire_daemon_errors_and_transport_fallbacks() {
        let socket_path = unique_socket_path("wire-error");
        let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));

        let daemon_task = spawn_one_shot_server(
            socket_path.clone(),
            WireResponse {
                ok: false,
                body_json: serde_json::to_string(&WireDaemonError::UnknownLease)
                    .expect("serialize daemon error"),
            },
        )
        .await;
        let err = client
            .call_rpc(DaemonRpcRequest::IssueLease {
                vault_password: "vault-password".to_string(),
            })
            .await
            .expect_err("daemon error");
        assert!(matches!(
            err,
            UnixTransportError::Daemon(DaemonError::UnknownLease)
        ));
        daemon_task.await.expect("daemon task");

        let transport_task = spawn_one_shot_server(
            socket_path,
            WireResponse {
                ok: false,
                body_json: "plain transport failure".to_string(),
            },
        )
        .await;
        let err = client
            .call_rpc(DaemonRpcRequest::IssueLease {
                vault_password: "vault-password".to_string(),
            })
            .await
            .expect_err("transport fallback");
        assert!(matches!(
            err,
            UnixTransportError::Daemon(DaemonError::Transport(message))
                if message == "plain transport failure"
        ));
        transport_task.await.expect("transport task");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn issue_lease_rejects_unexpected_response_types() {
        let socket_path = unique_socket_path("unexpected-response");
        let client = UnixDaemonClient::new(socket_path.clone(), Duration::from_secs(2));
        let response_task = spawn_one_shot_server(
            socket_path,
            WireResponse {
                ok: true,
                body_json: serde_json::to_string(&DaemonRpcResponse::Unit)
                    .expect("serialize response"),
            },
        )
        .await;

        let err = client
            .issue_lease("vault-password")
            .await
            .expect_err("wrong response type");
        assert!(
            matches!(err, DaemonError::Transport(message) if message == "unexpected response type")
        );

        response_task.await.expect("response task");
    }

    #[test]
    fn rpc_access_level_classifies_admin_and_agent_requests() {
        let admin_request = vault_daemon::DaemonRpcRequest::IssueLease {
            vault_password: "vault-password".to_string(),
        };
        let agent_request = vault_daemon::DaemonRpcRequest::EvaluateForAgent {
            request: dummy_agent_request(),
        };

        assert_eq!(rpc_access_level(&admin_request), RpcAccessLevel::Admin);
        assert_eq!(rpc_access_level(&agent_request), RpcAccessLevel::Agent);
    }

    #[test]
    fn socket_mode_is_private_only_when_both_allowlists_are_root_only() {
        assert_eq!(
            socket_mode_for_allowed_peer_euids(
                &singleton_allowed_set(0),
                &singleton_allowed_set(0)
            ),
            0o600
        );

        let current_euid = nix::unistd::geteuid().as_raw();
        let non_root_euid = if current_euid == 0 { 1 } else { current_euid };
        assert_eq!(
            socket_mode_for_allowed_peer_euids(
                &singleton_allowed_set(0),
                &singleton_allowed_set(non_root_euid)
            ),
            0o666
        );
    }

    #[test]
    fn combined_allowed_peer_euids_deduplicates_split_allowlists() {
        let current_euid = nix::unistd::geteuid().as_raw();
        let combined = combined_allowed_peer_euids(
            &BTreeSet::from([0, current_euid]),
            &BTreeSet::from([current_euid, current_euid.saturating_add(1)]),
        );

        assert_eq!(
            combined,
            BTreeSet::from([0, current_euid, current_euid.saturating_add(1)])
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bind_rejects_empty_admin_and_agent_allowlists() {
        let socket_path = unique_socket_path("empty-allowlists");
        let err = match UnixDaemonServer::bind_with_allowed_peer_euids(
            socket_path.clone(),
            BTreeSet::new(),
            singleton_allowed_set(nix::unistd::geteuid().as_raw()),
        )
        .await
        {
            Ok(_) => panic!("empty admin allowlist must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, UnixTransportError::Protocol(message) if message.contains("allowed admin peer euid set must not be empty"))
        );

        let err = match UnixDaemonServer::bind_with_allowed_peer_euids(
            socket_path,
            singleton_allowed_set(nix::unistd::geteuid().as_raw()),
            BTreeSet::new(),
        )
        .await
        {
            Ok(_) => panic!("empty agent allowlist must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(err, UnixTransportError::Protocol(message) if message.contains("allowed agent peer euid set must not be empty"))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_until_shutdown_honors_ready_shutdown_and_exposes_socket_path() {
        let socket_path = unique_socket_path("ready-shutdown");
        let server = UnixDaemonServer::bind(
            socket_path.clone(),
            singleton_allowed_set(nix::unistd::geteuid().as_raw()),
        )
        .await
        .expect("server");
        assert_eq!(server.socket_path(), socket_path.as_path());

        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        server
            .run_until_shutdown(daemon, async {})
            .await
            .expect("shutdown must succeed");
    }

    #[test]
    fn wire_daemon_error_roundtrip_covers_all_variants() {
        let manual_approval_id = Uuid::new_v4();
        let unknown_vault_key = Uuid::new_v4();
        let unknown_agent_key = Uuid::new_v4();
        let unknown_policy = Uuid::new_v4();
        let unknown_approval = Uuid::new_v4();
        let unknown_reservation = Uuid::new_v4();

        let cases = vec![
            (
                DaemonError::AuthenticationFailed,
                DaemonError::AuthenticationFailed.to_string(),
            ),
            (
                DaemonError::UnknownLease,
                DaemonError::UnknownLease.to_string(),
            ),
            (
                DaemonError::InvalidLease,
                DaemonError::InvalidLease.to_string(),
            ),
            (
                DaemonError::TooManyActiveLeases,
                DaemonError::TooManyActiveLeases.to_string(),
            ),
            (
                DaemonError::UnknownVaultKey(unknown_vault_key),
                DaemonError::UnknownVaultKey(unknown_vault_key).to_string(),
            ),
            (
                DaemonError::UnknownAgentKey(unknown_agent_key),
                DaemonError::UnknownAgentKey(unknown_agent_key).to_string(),
            ),
            (
                DaemonError::UnknownPolicy(unknown_policy),
                DaemonError::UnknownPolicy(unknown_policy).to_string(),
            ),
            (
                DaemonError::UnknownManualApprovalRequest(unknown_approval),
                DaemonError::UnknownManualApprovalRequest(unknown_approval).to_string(),
            ),
            (
                DaemonError::AgentAuthenticationFailed,
                DaemonError::AgentAuthenticationFailed.to_string(),
            ),
            (
                DaemonError::PayloadActionMismatch,
                DaemonError::PayloadActionMismatch.to_string(),
            ),
            (
                DaemonError::PayloadTooLarge { max_bytes: 1024 },
                DaemonError::PayloadTooLarge { max_bytes: 1024 }.to_string(),
            ),
            (
                DaemonError::InvalidRequestTimestamps,
                DaemonError::InvalidRequestTimestamps.to_string(),
            ),
            (
                DaemonError::RequestExpired,
                DaemonError::RequestExpired.to_string(),
            ),
            (
                DaemonError::RequestReplayDetected,
                DaemonError::RequestReplayDetected.to_string(),
            ),
            (
                DaemonError::TooManyTrackedReplayIds { max_tracked: 32 },
                DaemonError::TooManyTrackedReplayIds { max_tracked: 32 }.to_string(),
            ),
            (
                DaemonError::InvalidPolicyAttachment("attachment".to_string()),
                DaemonError::InvalidPolicyAttachment("attachment".to_string()).to_string(),
            ),
            (
                DaemonError::InvalidNonceReservation("nonce".to_string()),
                DaemonError::InvalidNonceReservation("nonce".to_string()).to_string(),
            ),
            (
                DaemonError::TooManyActiveNonceReservations { max_active: 64 },
                DaemonError::TooManyActiveNonceReservations { max_active: 64 }.to_string(),
            ),
            (
                DaemonError::UnknownNonceReservation(unknown_reservation),
                DaemonError::UnknownNonceReservation(unknown_reservation).to_string(),
            ),
            (
                DaemonError::MissingNonceReservation {
                    chain_id: 1,
                    nonce: 7,
                },
                DaemonError::MissingNonceReservation {
                    chain_id: 1,
                    nonce: 7,
                }
                .to_string(),
            ),
            (
                DaemonError::InvalidPolicy("policy".to_string()),
                DaemonError::InvalidPolicy("policy".to_string()).to_string(),
            ),
            (
                DaemonError::InvalidRelayConfig("relay".to_string()),
                DaemonError::InvalidRelayConfig("relay".to_string()).to_string(),
            ),
            (
                DaemonError::ManualApprovalRequired {
                    approval_request_id: manual_approval_id,
                    relay_url: Some("https://relay.example".to_string()),
                    frontend_url: Some("https://frontend.example".to_string()),
                },
                DaemonError::ManualApprovalRequired {
                    approval_request_id: manual_approval_id,
                    relay_url: Some("https://relay.example".to_string()),
                    frontend_url: Some("https://frontend.example".to_string()),
                }
                .to_string(),
            ),
            (
                DaemonError::ManualApprovalRejected {
                    approval_request_id: manual_approval_id,
                },
                DaemonError::ManualApprovalRejected {
                    approval_request_id: manual_approval_id,
                }
                .to_string(),
            ),
            (
                DaemonError::ManualApprovalRequestNotPending {
                    approval_request_id: manual_approval_id,
                    status: ManualApprovalStatus::Approved,
                },
                DaemonError::ManualApprovalRequestNotPending {
                    approval_request_id: manual_approval_id,
                    status: ManualApprovalStatus::Approved,
                }
                .to_string(),
            ),
            (
                DaemonError::Policy(PolicyError::NoAttachedPolicies),
                DaemonError::Policy(PolicyError::NoAttachedPolicies).to_string(),
            ),
            (
                DaemonError::Signer(SignerError::InvalidPrivateKey),
                DaemonError::Signer(SignerError::InvalidPrivateKey).to_string(),
            ),
            (
                DaemonError::PasswordHash("hash".to_string()),
                DaemonError::PasswordHash("hash".to_string()).to_string(),
            ),
            (
                DaemonError::InvalidConfig("config".to_string()),
                DaemonError::InvalidConfig("config".to_string()).to_string(),
            ),
            (
                DaemonError::Transport("transport".to_string()),
                DaemonError::Transport("transport".to_string()).to_string(),
            ),
            (
                DaemonError::Persistence("persistence".to_string()),
                DaemonError::Persistence("persistence".to_string()).to_string(),
            ),
            (
                DaemonError::LockPoisoned,
                DaemonError::LockPoisoned.to_string(),
            ),
        ];

        for (original, expected_message) in cases {
            let wire = WireDaemonError::from(original);
            let recovered = wire.into_daemon_error();
            assert_eq!(recovered.to_string(), expected_message);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_connection_rejects_admin_requests_from_agent_only_peers() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let current_euid = nix::unistd::geteuid().as_raw();
        let (mut client_stream, server_stream) = UnixStream::pair().expect("stream pair");
        let wire_request = WireRequest {
            body_json: serde_json::to_string(&vault_daemon::DaemonRpcRequest::IssueLease {
                vault_password: "vault-password".to_string(),
            })
            .expect("serialize request"),
        };
        write_frame(&mut client_stream, &wire_request, Duration::from_secs(2))
            .await
            .expect("write request");

        let err = handle_connection(
            server_stream,
            daemon,
            singleton_allowed_set(current_euid.saturating_add(1)),
            singleton_allowed_set(current_euid),
        )
        .await
        .expect_err("must reject admin request");

        assert!(
            matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
        );
        assert!(
            read_frame::<WireResponse>(&mut client_stream, Duration::from_millis(50))
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_connection_rejects_globally_unauthorized_peer_without_frame_read() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let current_euid = nix::unistd::geteuid().as_raw();
        let (_client_stream, server_stream) = UnixStream::pair().expect("stream pair");

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handle_connection(
                server_stream,
                daemon,
                singleton_allowed_set(current_euid.saturating_add(1)),
                singleton_allowed_set(current_euid.saturating_add(2)),
            ),
        )
        .await
        .expect("globally unauthorized peer should be rejected before read timeout");

        let err = result.expect_err("must reject globally unauthorized peer");
        assert!(
            matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_connection_prioritizes_unauthorized_over_deserialization_for_globally_unauthorized_peer(
    ) {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let current_euid = nix::unistd::geteuid().as_raw();
        let (mut client_stream, server_stream) = UnixStream::pair().expect("stream pair");
        let wire_request = WireRequest {
            body_json: "{not-json".to_string(),
        };
        write_frame(&mut client_stream, &wire_request, Duration::from_secs(2))
            .await
            .expect("write malformed request");

        let err = handle_connection(
            server_stream,
            daemon,
            singleton_allowed_set(current_euid.saturating_add(1)),
            singleton_allowed_set(current_euid.saturating_add(2)),
        )
        .await
        .expect_err("must reject globally unauthorized peer");

        assert!(
            matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_connection_rejects_agent_requests_from_admin_only_peers() {
        let daemon = Arc::new(
            InMemoryDaemon::new(
                "vault-password",
                SoftwareSignerBackend::default(),
                DaemonConfig::default(),
            )
            .expect("daemon"),
        );
        let current_euid = nix::unistd::geteuid().as_raw();
        let (mut client_stream, server_stream) = UnixStream::pair().expect("stream pair");
        let wire_request = WireRequest {
            body_json: serde_json::to_string(&vault_daemon::DaemonRpcRequest::EvaluateForAgent {
                request: dummy_agent_request(),
            })
            .expect("serialize request"),
        };
        write_frame(&mut client_stream, &wire_request, Duration::from_secs(2))
            .await
            .expect("write request");

        let err = handle_connection(
            server_stream,
            daemon,
            singleton_allowed_set(current_euid),
            singleton_allowed_set(current_euid.saturating_add(1)),
        )
        .await
        .expect_err("must reject agent request");

        assert!(
            matches!(err, UnixTransportError::UnauthorizedPeerEuid { actual, .. } if actual == current_euid)
        );
        assert!(
            read_frame::<WireResponse>(&mut client_stream, Duration::from_millis(50))
                .await
                .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bind_with_split_allowlists_keeps_root_only_socket_private() {
        let socket_path = unique_socket_path("split-root-only-mode");
        let server = UnixDaemonServer::bind_with_allowed_peer_euids(
            socket_path.clone(),
            singleton_allowed_set(0),
            singleton_allowed_set(0),
        )
        .await
        .expect("server");

        #[cfg(unix)]
        assert_eq!(socket_mode(&socket_path), 0o600);

        drop(server);
    }
}
