//! XPC transport adapter for daemon RPC calls.
//!
//! This crate uses Apple XPC primitives to exchange typed daemon RPC messages
//! between a server and a client.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::runtime::Handle;
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
use vault_policy::{PolicyError, PolicyEvaluation, PolicyExplanation};
use vault_signer::{KeyCreateRequest, SignerError, VaultSignerBackend};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
use block::{Block, ConcreteBlock, RcBlock};
#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags as CodeSignFlags, GuestAttributes, SecCode, SecRequirement,
};

#[cfg(target_os = "macos")]
type XpcObject = *mut c_void;
#[cfg(target_os = "macos")]
type XpcConnection = *mut c_void;
#[cfg(target_os = "macos")]
type DispatchQueue = *mut c_void;
#[cfg(target_os = "macos")]
type XpcType = *const c_void;
#[cfg(target_os = "macos")]
type PeerBlocks = Arc<Mutex<HashMap<usize, SendablePeerBlock>>>;

#[cfg(target_os = "macos")]
const DISPATCH_QUEUE_PRIORITY_DEFAULT: isize = 0;

/// Wrapper for copied peer callback blocks stored by the server.
///
/// The underlying copied Objective-C block is heap-managed by Apple runtime and
/// can be retained/released across threads. Access to the map is synchronized by
/// a mutex, and blocks are only invoked by XPC runtime callbacks.
#[cfg(target_os = "macos")]
struct SendablePeerBlock {
    _block: RcBlock<(XpcObject,), ()>,
}

#[cfg(target_os = "macos")]
fn lock_peer_blocks<'a>(
    peer_blocks: &'a PeerBlocks,
) -> Result<std::sync::MutexGuard<'a, HashMap<usize, SendablePeerBlock>>, XpcTransportError> {
    peer_blocks
        .lock()
        .map_err(|_| XpcTransportError::Internal("peer block registry lock poisoned".to_string()))
}

#[cfg(target_os = "macos")]
fn retain_peer_block(
    peer_blocks: &PeerBlocks,
    peer_key: usize,
    peer_block: &RcBlock<(XpcObject,), ()>,
) -> Result<(), XpcTransportError> {
    lock_peer_blocks(peer_blocks)?.insert(
        peer_key,
        SendablePeerBlock {
            _block: peer_block.clone(),
        },
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn release_peer_block(peer_blocks: &PeerBlocks, peer_key: usize) -> Result<(), XpcTransportError> {
    lock_peer_blocks(peer_blocks)?.remove(&peer_key);
    Ok(())
}

// SAFETY: copied Objective-C blocks are reference-counted runtime objects that
// are designed for cross-thread ownership transfer.
#[cfg(target_os = "macos")]
unsafe impl Send for SendablePeerBlock {}
// SAFETY: all shared access is mediated by synchronization on the block map.
#[cfg(target_os = "macos")]
unsafe impl Sync for SendablePeerBlock {}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn xpc_connection_create(name: *const c_char, target_queue: DispatchQueue) -> XpcConnection;
    fn xpc_connection_create_from_endpoint(endpoint: XpcObject) -> XpcConnection;
    fn xpc_endpoint_create(connection: XpcConnection) -> XpcObject;

    fn xpc_connection_set_event_handler(connection: XpcConnection, handler: *mut c_void);
    fn xpc_connection_resume(connection: XpcConnection);
    fn xpc_connection_cancel(connection: XpcConnection);
    fn xpc_connection_send_message(connection: XpcConnection, message: XpcObject);
    fn xpc_connection_get_euid(connection: XpcConnection) -> libc::uid_t;
    fn xpc_connection_get_pid(connection: XpcConnection) -> libc::pid_t;

    fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const XpcObject,
        count: usize,
    ) -> XpcObject;
    fn xpc_dictionary_set_string(dict: XpcObject, key: *const c_char, value: *const c_char);
    fn xpc_dictionary_set_bool(dict: XpcObject, key: *const c_char, value: bool);
    fn xpc_dictionary_get_string(dict: XpcObject, key: *const c_char) -> *const c_char;
    fn xpc_dictionary_get_bool(dict: XpcObject, key: *const c_char) -> bool;

    fn xpc_get_type(object: XpcObject) -> XpcType;

    fn xpc_retain(object: XpcObject) -> XpcObject;
    fn xpc_release(object: XpcObject);

    static _xpc_type_dictionary: c_void;
    static _xpc_type_connection: c_void;
}

#[cfg(target_os = "macos")]
#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    fn dispatch_get_global_queue(identifier: isize, flags: usize) -> DispatchQueue;
}

/// Errors returned by XPC transport.
#[derive(Debug, Error)]
pub enum XpcTransportError {
    /// XPC is unavailable on this platform.
    #[error("xpc transport is supported only on macOS")]
    UnsupportedPlatform,
    /// Message serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Protocol-level violation.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Underlying daemon returned an error.
    #[error("daemon error: {0}")]
    Daemon(#[from] DaemonError),
    /// Timed out waiting for response.
    #[error("timed out waiting for xpc response")]
    Timeout,
    /// Daemon server must run as root for hardened local-access boundary.
    #[error("xpc daemon server must run as root (euid 0)")]
    RequiresRoot,
    /// Code-signing policy was invalid or client failed requirement checks.
    #[error("code-signing authorization error: {0}")]
    CodeSigning(String),
    /// Other transport failures.
    #[error("transport internal error: {0}")]
    Internal(String),
}

#[derive(Clone)]
struct WireRequest {
    request_id: String,
    body_json: Zeroizing<String>,
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireRequest")
            .field("request_id", &self.request_id)
            .field("body_json", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
struct WireResponse {
    request_id: String,
    ok: bool,
    body_json: Zeroizing<String>,
}

impl fmt::Debug for WireResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireResponse")
            .field("request_id", &self.request_id)
            .field("ok", &self.ok)
            .field("body_json", &"<redacted>")
            .finish()
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum IncomingWireMessage {
    Response(WireResponse),
    DecodeError(XpcTransportError),
}

const MAX_WIRE_BODY_BYTES: usize = 256 * 1024;
const MAX_WIRE_REQUEST_ID_BYTES: usize = 128;

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
    Policy(PolicyError),
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

/// Opaque endpoint handle used to connect XPC clients.
#[cfg(target_os = "macos")]
pub struct XpcEndpoint {
    raw: XpcObject,
}

#[cfg(target_os = "macos")]
impl Clone for XpcEndpoint {
    fn clone(&self) -> Self {
        // SAFETY: balanced retain/release lifecycle.
        unsafe {
            xpc_retain(self.raw);
        }
        Self { raw: self.raw }
    }
}

#[cfg(target_os = "macos")]
impl Drop for XpcEndpoint {
    fn drop(&mut self) {
        // SAFETY: balanced retain/release lifecycle.
        unsafe {
            xpc_release(self.raw);
        }
    }
}

#[cfg(target_os = "macos")]
impl fmt::Debug for XpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XpcEndpoint").finish_non_exhaustive()
    }
}

/// XPC server bound to an in-memory daemon instance.
#[cfg(target_os = "macos")]
pub struct XpcDaemonServer {
    listener: XpcConnection,
    endpoint: XpcEndpoint,
    _listener_block: RcBlock<(XpcObject,), ()>,
    _peer_blocks: PeerBlocks,
}

#[cfg(target_os = "macos")]
impl Drop for XpcDaemonServer {
    fn drop(&mut self) {
        // SAFETY: listener is owned by this instance.
        unsafe {
            xpc_release(self.listener);
        }
    }
}

#[cfg(target_os = "macos")]
impl XpcDaemonServer {
    /// Starts an anonymous XPC listener and binds it to daemon RPC handler.
    pub fn start_inmemory<B>(
        daemon: Arc<InMemoryDaemon<B>>,
        runtime_handle: Handle,
    ) -> Result<Self, XpcTransportError>
    where
        B: VaultSignerBackend + 'static,
    {
        let current_euid = unsafe { libc::geteuid() };
        if current_euid != 0 {
            return Err(XpcTransportError::RequiresRoot);
        }

        Self::start_inmemory_impl(daemon, runtime_handle, 0, None)
    }

    /// Starts an anonymous XPC listener and enforces a code-sign requirement
    /// string on each connecting client process.
    ///
    /// The requirement string uses Apple's requirement language (same syntax as
    /// `codesign -r`).
    pub fn start_inmemory_with_code_sign_requirement<B>(
        daemon: Arc<InMemoryDaemon<B>>,
        runtime_handle: Handle,
        required_client_code_signing_requirement: impl Into<String>,
    ) -> Result<Self, XpcTransportError>
    where
        B: VaultSignerBackend + 'static,
    {
        let current_euid = unsafe { libc::geteuid() };
        if current_euid != 0 {
            return Err(XpcTransportError::RequiresRoot);
        }

        Self::start_inmemory_impl(
            daemon,
            runtime_handle,
            0,
            Some(required_client_code_signing_requirement.into()),
        )
    }

    /// Starts an anonymous XPC listener and restricts clients to `allowed_euid`.
    ///
    /// This is intended for controlled test/dev environments and is only
    /// available in debug builds. Production should use [`Self::start_inmemory`]
    /// so non-root startup is rejected.
    #[cfg(debug_assertions)]
    pub fn start_inmemory_with_allowed_euid<B>(
        daemon: Arc<InMemoryDaemon<B>>,
        runtime_handle: Handle,
        allowed_euid: libc::uid_t,
    ) -> Result<Self, XpcTransportError>
    where
        B: VaultSignerBackend + 'static,
    {
        Self::start_inmemory_impl(daemon, runtime_handle, allowed_euid, None)
    }

    /// Starts an anonymous XPC listener, restricting clients to `allowed_euid`
    /// and a code-sign requirement.
    #[cfg(debug_assertions)]
    pub fn start_inmemory_with_allowed_euid_and_code_sign_requirement<B>(
        daemon: Arc<InMemoryDaemon<B>>,
        runtime_handle: Handle,
        allowed_euid: libc::uid_t,
        required_client_code_signing_requirement: impl Into<String>,
    ) -> Result<Self, XpcTransportError>
    where
        B: VaultSignerBackend + 'static,
    {
        Self::start_inmemory_impl(
            daemon,
            runtime_handle,
            allowed_euid,
            Some(required_client_code_signing_requirement.into()),
        )
    }

    fn start_inmemory_impl<B>(
        daemon: Arc<InMemoryDaemon<B>>,
        runtime_handle: Handle,
        allowed_euid: libc::uid_t,
        required_client_code_signing_requirement: Option<String>,
    ) -> Result<Self, XpcTransportError>
    where
        B: VaultSignerBackend + 'static,
    {
        let current_euid = unsafe { libc::geteuid() };
        if allowed_euid != current_euid {
            return Err(XpcTransportError::Internal(format!(
                "allowed_euid mismatch: requested {allowed_euid}, current daemon euid is {current_euid}"
            )));
        }

        if let Some(requirement) = required_client_code_signing_requirement.as_deref() {
            parse_code_sign_requirement(requirement)?;
        }

        // SAFETY: XPC/libdispatch APIs are FFI and require raw pointers.
        unsafe {
            let queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
            if queue.is_null() {
                return Err(XpcTransportError::Internal(
                    "dispatch_get_global_queue returned null".to_string(),
                ));
            }

            let listener = xpc_connection_create(ptr::null(), queue);
            if listener.is_null() {
                return Err(XpcTransportError::Internal(
                    "xpc_connection_create returned null".to_string(),
                ));
            }

            let daemon_outer = daemon.clone();
            let handle_outer = runtime_handle.clone();
            let required_client_code_signing_requirement_outer =
                required_client_code_signing_requirement.clone();
            let peer_blocks: PeerBlocks = Arc::new(Mutex::new(HashMap::new()));
            let peer_blocks_for_listener = peer_blocks.clone();
            let listener_block = ConcreteBlock::new(move |event: XpcObject| {
                // Listener callback receives peer connections.
                if !ptr::eq(xpc_get_type(event), &_xpc_type_connection) {
                    return;
                }
                let peer = event;
                let peer_euid = xpc_connection_get_euid(peer);
                if peer_euid != allowed_euid {
                    xpc_connection_cancel(peer);
                    return;
                }
                if let Some(requirement) = required_client_code_signing_requirement_outer.as_deref()
                {
                    if verify_peer_code_signing_requirement(peer, requirement).is_err() {
                        xpc_connection_cancel(peer);
                        return;
                    }
                }

                let daemon_inner = daemon_outer.clone();
                let handle_inner = handle_outer.clone();
                let peer_blocks_for_callback = peer_blocks_for_listener.clone();
                let peer_blocks_for_insert = peer_blocks_for_listener.clone();
                let peer_key = peer as usize;
                let peer_block = ConcreteBlock::new(move |message: XpcObject| {
                    if !ptr::eq(xpc_get_type(message), &_xpc_type_dictionary) {
                        if release_peer_block(&peer_blocks_for_callback, peer_key).is_err() {
                            xpc_connection_cancel(peer);
                        }
                        return;
                    }

                    let response = match decode_wire_request(message) {
                        Ok(request) => {
                            let mut request = request;
                            let daemon_request: Result<DaemonRpcRequest, XpcTransportError> =
                                serde_json::from_str(&request.body_json).map_err(|err| {
                                    XpcTransportError::Serialization(err.to_string())
                                });
                            request.body_json.zeroize();

                            match daemon_request {
                                Ok(req) => {
                                    match handle_inner.block_on(daemon_inner.handle_rpc(req)) {
                                        Ok(resp) => {
                                            let mut resp = resp;
                                            match serde_json::to_string(&resp) {
                                                Ok(body_json) => {
                                                    resp.zeroize_secrets();
                                                    WireResponse {
                                                        request_id: request.request_id,
                                                        ok: true,
                                                        body_json: body_json.into(),
                                                    }
                                                }
                                                Err(err) => {
                                                    resp.zeroize_secrets();
                                                    WireResponse {
                                                        request_id: request.request_id,
                                                        ok: false,
                                                        body_json: format!(
                                                            "failed to serialize daemon response: {err}"
                                                        )
                                                        .into(),
                                                    }
                                                }
                                            }
                                        }
                                        Err(err) => WireResponse {
                                            request_id: request.request_id,
                                            ok: false,
                                            body_json: serialize_wire_daemon_error(err).into(),
                                        },
                                    }
                                }
                                Err(err) => WireResponse {
                                    request_id: request.request_id,
                                    ok: false,
                                    body_json: err.to_string().into(),
                                },
                            }
                        }
                        Err(err) => WireResponse {
                            request_id: extract_safe_request_id(message),
                            ok: false,
                            body_json: err.to_string().into(),
                        },
                    };
                    let mut response = enforce_wire_response_limits(response);

                    let encoded = encode_wire_response(&response);
                    response.body_json.zeroize();
                    if let Ok(xpc_resp) = encoded {
                        xpc_connection_send_message(peer, xpc_resp);
                        xpc_release(xpc_resp);
                    }
                })
                .copy();

                if retain_peer_block(&peer_blocks_for_insert, peer_key, &peer_block).is_err() {
                    xpc_connection_cancel(peer);
                    return;
                }
                xpc_connection_set_event_handler(
                    peer,
                    &*peer_block as *const Block<_, _> as *mut c_void,
                );
                xpc_connection_resume(peer);
            })
            .copy();

            xpc_connection_set_event_handler(
                listener,
                &*listener_block as *const Block<_, _> as *mut c_void,
            );
            xpc_connection_resume(listener);

            let endpoint_raw = xpc_endpoint_create(listener);
            if endpoint_raw.is_null() {
                return Err(XpcTransportError::Internal(
                    "xpc_endpoint_create returned null".to_string(),
                ));
            }

            xpc_retain(listener);
            xpc_retain(endpoint_raw);

            Ok(Self {
                listener,
                endpoint: XpcEndpoint { raw: endpoint_raw },
                _listener_block: listener_block,
                _peer_blocks: peer_blocks,
            })
        }
    }

    /// Returns endpoint handle for clients.
    #[must_use]
    pub fn endpoint(&self) -> XpcEndpoint {
        self.endpoint.clone()
    }
}

#[cfg(target_os = "macos")]
fn parse_code_sign_requirement(requirement: &str) -> Result<SecRequirement, XpcTransportError> {
    requirement
        .parse::<SecRequirement>()
        .map_err(|err| XpcTransportError::CodeSigning(format!("invalid requirement string: {err}")))
}

#[cfg(target_os = "macos")]
fn verify_peer_code_signing_requirement(
    peer: XpcConnection,
    requirement: &str,
) -> Result<(), XpcTransportError> {
    let pid = unsafe { xpc_connection_get_pid(peer) };
    if pid <= 0 {
        return Err(XpcTransportError::CodeSigning(
            "peer pid is unavailable".to_string(),
        ));
    }

    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);

    let peer_code = SecCode::copy_guest_with_attribues(None, &attributes, CodeSignFlags::default())
        .map_err(|err| {
            XpcTransportError::CodeSigning(format!(
                "failed to resolve peer code object for pid {pid}: {err}"
            ))
        })?;
    let requirement = parse_code_sign_requirement(requirement)?;

    peer_code
        .check_validity(
            CodeSignFlags::STRICT_VALIDATE | CodeSignFlags::CHECK_TRUSTED_ANCHORS,
            &requirement,
        )
        .map_err(|err| {
            XpcTransportError::CodeSigning(format!(
                "peer code signature does not satisfy required policy for pid {pid}: {err}"
            ))
        })
}

#[cfg(target_os = "macos")]

include!("client_codec_api.rs");

#[cfg(all(test, target_os = "macos"))]
mod tests;
