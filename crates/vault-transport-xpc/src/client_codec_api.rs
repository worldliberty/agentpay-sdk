pub struct XpcDaemonClient {
    connection: XpcConnection,
    responses: Mutex<Receiver<IncomingWireMessage>>,
    timeout: Duration,
    _client_block: RcBlock<(XpcObject,), ()>,
}

// SAFETY: Apple XPC connections are reference-counted OS objects designed for
// cross-thread use. Access to response receiver is synchronized via `Mutex`.
#[cfg(target_os = "macos")]
unsafe impl Send for XpcDaemonClient {}
// SAFETY: methods requiring interior mutation synchronize shared state.
#[cfg(target_os = "macos")]
unsafe impl Sync for XpcDaemonClient {}

#[cfg(target_os = "macos")]
impl Drop for XpcDaemonClient {
    fn drop(&mut self) {
        // SAFETY: connection is owned by this instance.
        unsafe {
            xpc_release(self.connection);
        }
    }
}

#[cfg(target_os = "macos")]
impl XpcDaemonClient {
    /// Connects to daemon endpoint.
    pub fn connect(endpoint: &XpcEndpoint, timeout: Duration) -> Result<Self, XpcTransportError> {
        // SAFETY: endpoint comes from xpc_endpoint_create.
        unsafe {
            let connection = xpc_connection_create_from_endpoint(endpoint.raw);
            if connection.is_null() {
                return Err(XpcTransportError::Internal(
                    "xpc_connection_create_from_endpoint returned null".to_string(),
                ));
            }

            let (tx, rx) = mpsc::channel::<IncomingWireMessage>();
            let client_block = ConcreteBlock::new(move |message: XpcObject| {
                if !ptr::eq(xpc_get_type(message), &_xpc_type_dictionary) {
                    return;
                }
                let incoming = match decode_wire_response(message) {
                    Ok(resp) => IncomingWireMessage::Response(resp),
                    Err(err) => IncomingWireMessage::DecodeError(err),
                };
                if tx.send(incoming).is_err() {
                    // Receiver is dropped; nothing to do.
                }
            })
            .copy();

            xpc_connection_set_event_handler(
                connection,
                &*client_block as *const Block<_, _> as *mut c_void,
            );
            xpc_connection_resume(connection);

            xpc_retain(connection);

            Ok(Self {
                connection,
                responses: Mutex::new(rx),
                timeout,
                _client_block: client_block,
            })
        }
    }

    /// Performs a single RPC call.
    pub fn call_rpc(
        &self,
        request: DaemonRpcRequest,
    ) -> Result<DaemonRpcResponse, XpcTransportError> {
        let mut request = request;
        let responses = self
            .responses
            .lock()
            .map_err(|_| XpcTransportError::Internal("responses lock poisoned".to_string()))?;

        let request_id = Uuid::new_v4().to_string();
        let body_json = serde_json::to_string(&request)
            .map_err(|err| XpcTransportError::Serialization(err.to_string()));
        request.zeroize_secrets();
        let mut body_json = Zeroizing::new(body_json?);
        if let Err(err) = validate_wire_lengths(&request_id, body_json.as_str()) {
            body_json.zeroize();
            return Err(err);
        }

        let mut wire_request = WireRequest {
            request_id: request_id.clone(),
            body_json,
        };
        let xpc_request = encode_wire_request(&wire_request);
        wire_request.body_json.zeroize();
        let xpc_request = xpc_request?;

        // SAFETY: connection is resumed and message is a valid dictionary.
        unsafe {
            xpc_connection_send_message(self.connection, xpc_request);
            xpc_release(xpc_request);
        }

        // Keep send+receive in a single critical section so only one request is
        // in flight per connection; this prevents response/request-id mixups.
        let deadline = std::time::Instant::now() + self.timeout;
        let mut response = recv_matching_response(&responses, &request_id, deadline)?;

        if response.ok {
            let parsed = serde_json::from_str(response.body_json.as_str())
                .map_err(|err| XpcTransportError::Serialization(err.to_string()));
            response.body_json.zeroize();
            parsed
        } else {
            let daemon_error = match serde_json::from_str::<WireDaemonError>(
                response.body_json.as_str(),
            ) {
                Ok(err) => Err(XpcTransportError::Daemon(err.into_daemon_error())),
                Err(_) => Err(XpcTransportError::Daemon(DaemonError::Transport(
                    "failed to decode daemon error response".to_string(),
                ))),
            };
            response.body_json.zeroize();
            daemon_error
        }
    }
}

#[cfg(target_os = "macos")]
fn recv_matching_response(
    responses: &Receiver<IncomingWireMessage>,
    request_id: &str,
    deadline: std::time::Instant,
) -> Result<WireResponse, XpcTransportError> {
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(XpcTransportError::Timeout);
        }

        let remaining = deadline.saturating_duration_since(now);
        let incoming = responses
            .recv_timeout(remaining)
            .map_err(|_| XpcTransportError::Timeout)?;

        match incoming {
            IncomingWireMessage::DecodeError(err) => return Err(err),
            IncomingWireMessage::Response(response) => {
                if response.request_id == request_id {
                    return Ok(response);
                }
            }
        }
    }
}

fn serialize_wire_daemon_error(err: DaemonError) -> String {
    match serde_json::to_string(&WireDaemonError::from(err)) {
        Ok(json) => json,
        Err(serialize_err) => format!("failed to serialize daemon error: {serialize_err}"),
    }
}

#[cfg(target_os = "macos")]
fn encode_wire_request(req: &WireRequest) -> Result<XpcObject, XpcTransportError> {
    let dict = unsafe { xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    if dict.is_null() {
        return Err(XpcTransportError::Internal(
            "unable to allocate xpc dictionary".to_string(),
        ));
    }

    set_dict_string(dict, "agentpay_kind", "request")?;
    set_dict_string(dict, "agentpay_request_id", &req.request_id)?;
    set_dict_string(dict, "agentpay_body", req.body_json.as_str())?;
    Ok(dict)
}

#[cfg(target_os = "macos")]
fn decode_wire_request(message: XpcObject) -> Result<WireRequest, XpcTransportError> {
    let kind = get_dict_string(message, "agentpay_kind")?;
    if kind != "request" {
        return Err(XpcTransportError::Protocol(
            "unexpected request kind".to_string(),
        ));
    }

    let request_id = get_dict_string(message, "agentpay_request_id")?;
    let body_json = get_dict_secret_string(message, "agentpay_body")?;
    validate_wire_lengths(&request_id, body_json.as_str())?;

    Ok(WireRequest {
        request_id,
        body_json,
    })
}

#[cfg(target_os = "macos")]
fn encode_wire_response(resp: &WireResponse) -> Result<XpcObject, XpcTransportError> {
    let dict = unsafe { xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    if dict.is_null() {
        return Err(XpcTransportError::Internal(
            "unable to allocate xpc dictionary".to_string(),
        ));
    }

    set_dict_string(dict, "agentpay_kind", "response")?;
    set_dict_string(dict, "agentpay_request_id", &resp.request_id)?;
    set_dict_bool(dict, "agentpay_ok", resp.ok)?;
    set_dict_string(dict, "agentpay_body", resp.body_json.as_str())?;
    Ok(dict)
}

#[cfg(target_os = "macos")]
fn decode_wire_response(message: XpcObject) -> Result<WireResponse, XpcTransportError> {
    let kind = get_dict_string(message, "agentpay_kind")?;
    if kind != "response" {
        return Err(XpcTransportError::Protocol(
            "unexpected response kind".to_string(),
        ));
    }

    let request_id = get_dict_string(message, "agentpay_request_id")?;
    let body_json = get_dict_secret_string(message, "agentpay_body")?;
    validate_wire_lengths(&request_id, body_json.as_str())?;

    Ok(WireResponse {
        request_id,
        ok: get_dict_bool(message, "agentpay_ok")?,
        body_json,
    })
}

fn validate_wire_lengths(request_id: &str, body_json: &str) -> Result<(), XpcTransportError> {
    if request_id.len() > MAX_WIRE_REQUEST_ID_BYTES {
        return Err(XpcTransportError::Protocol(format!(
            "wire request id exceeds max bytes ({MAX_WIRE_REQUEST_ID_BYTES})"
        )));
    }
    if body_json.len() > MAX_WIRE_BODY_BYTES {
        return Err(XpcTransportError::Protocol(format!(
            "wire body exceeds max bytes ({MAX_WIRE_BODY_BYTES})"
        )));
    }
    Ok(())
}

fn enforce_wire_response_limits(response: WireResponse) -> WireResponse {
    let validation_err = match validate_wire_lengths(&response.request_id, response.body_json.as_str())
    {
        Ok(()) => return response,
        Err(err) => err,
    };

    let request_id = if response.request_id.len() <= MAX_WIRE_REQUEST_ID_BYTES {
        response.request_id
    } else {
        Uuid::nil().to_string()
    };

    let body_json = serde_json::to_string(&WireDaemonError::Transport(validation_err.to_string()))
        .unwrap_or_else(|_| {
            r#"{"kind":"Transport","data":"protocol error: oversized response"}"#.to_string()
        });

    WireResponse {
        request_id,
        ok: false,
        body_json: body_json.into(),
    }
}

#[cfg(target_os = "macos")]
fn extract_safe_request_id(message: XpcObject) -> String {
    get_dict_string(message, "agentpay_request_id")
        .ok()
        .filter(|id| id.len() <= MAX_WIRE_REQUEST_ID_BYTES)
        .unwrap_or_else(|| Uuid::nil().to_string())
}

#[cfg(target_os = "macos")]
fn set_dict_string(dict: XpcObject, key: &str, value: &str) -> Result<(), XpcTransportError> {
    let key = CString::new(key).map_err(|err| XpcTransportError::Protocol(err.to_string()))?;
    let value = CString::new(value).map_err(|err| XpcTransportError::Protocol(err.to_string()))?;
    unsafe {
        xpc_dictionary_set_string(dict, key.as_ptr(), value.as_ptr());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_dict_bool(dict: XpcObject, key: &str, value: bool) -> Result<(), XpcTransportError> {
    let key = CString::new(key).map_err(|err| XpcTransportError::Protocol(err.to_string()))?;
    unsafe {
        xpc_dictionary_set_bool(dict, key.as_ptr(), value);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn get_dict_string(dict: XpcObject, key: &str) -> Result<String, XpcTransportError> {
    let key = CString::new(key).map_err(|err| XpcTransportError::Protocol(err.to_string()))?;
    let value = unsafe { xpc_dictionary_get_string(dict, key.as_ptr()) };
    if value.is_null() {
        return Err(XpcTransportError::Protocol(format!("missing key: {key:?}")));
    }

    Ok(unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .to_string())
}

#[cfg(target_os = "macos")]
fn get_dict_secret_string(
    dict: XpcObject,
    key: &str,
) -> Result<Zeroizing<String>, XpcTransportError> {
    get_dict_string(dict, key).map(Zeroizing::new)
}

#[cfg(target_os = "macos")]
fn get_dict_bool(dict: XpcObject, key: &str) -> Result<bool, XpcTransportError> {
    let key = CString::new(key).map_err(|err| XpcTransportError::Protocol(err.to_string()))?;
    Ok(unsafe { xpc_dictionary_get_bool(dict, key.as_ptr()) })
}

/// Agent/client-side adapter backed by XPC transport.
#[cfg(target_os = "macos")]
#[async_trait]
impl KeyManagerDaemonApi for XpcDaemonClient {
    async fn issue_lease(&self, vault_password: &str) -> Result<Lease, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::IssueLease {
            vault_password: vault_password.to_string(),
        }) {
            Ok(DaemonRpcResponse::Lease(lease)) => Ok(lease),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn add_policy(
        &self,
        session: &AdminSession,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        match self.call_rpc(DaemonRpcRequest::AddPolicy {
            session: session.clone(),
            policy,
        }) {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn list_policies(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<SpendingPolicy>, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ListPolicies {
            session: session.clone(),
        }) {
            Ok(DaemonRpcResponse::Policies(policies)) => Ok(policies),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn list_policy_summaries(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<PolicySummary>, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ListPolicySummaries {
            session: session.clone(),
        }) {
            Ok(DaemonRpcResponse::PolicySummaries(summaries)) => Ok(summaries),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn disable_policy(
        &self,
        session: &AdminSession,
        policy_id: Uuid,
    ) -> Result<(), DaemonError> {
        match self.call_rpc(DaemonRpcRequest::DisablePolicy {
            session: session.clone(),
            policy_id,
        }) {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn create_vault_key(
        &self,
        session: &AdminSession,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::CreateVaultKey {
            session: session.clone(),
            request,
        }) {
            Ok(DaemonRpcResponse::VaultKey(key)) => Ok(key),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn create_agent_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::CreateAgentKey {
            session: session.clone(),
            vault_key_id,
            attachment,
        }) {
            Ok(DaemonRpcResponse::AgentCredentials(agent_credentials)) => Ok(agent_credentials),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
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
        match self.call_rpc(DaemonRpcRequest::RefreshAgentKey {
            session: session.clone(),
            agent_key_id,
            vault_key_id,
            attachment,
        }) {
            Ok(DaemonRpcResponse::AgentCredentials(agent_credentials)) => Ok(agent_credentials),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn export_vault_private_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<Option<String>, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ExportVaultPrivateKey {
            session: session.clone(),
            vault_key_id,
        }) {
            Ok(DaemonRpcResponse::PrivateKey(private_key)) => Ok(private_key),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn solana_public_key_hex(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::SolanaPublicKey {
            session: session.clone(),
            vault_key_id,
        }) {
            Ok(DaemonRpcResponse::PublicKey(public_key)) => Ok(public_key),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn rotate_agent_auth_token(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::RotateAgentAuthToken {
            session: session.clone(),
            agent_key_id,
        }) {
            Ok(DaemonRpcResponse::AuthToken(token)) => Ok(token),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn revoke_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        match self.call_rpc(DaemonRpcRequest::RevokeAgentKey {
            session: session.clone(),
            agent_key_id,
        }) {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn list_manual_approval_requests(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ListManualApprovalRequests {
            session: session.clone(),
        }) {
            Ok(DaemonRpcResponse::ManualApprovalRequests(requests)) => Ok(requests),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
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
        match self.call_rpc(DaemonRpcRequest::DecideManualApprovalRequest {
            session: session.clone(),
            approval_request_id,
            decision,
            rejection_reason,
        }) {
            Ok(DaemonRpcResponse::ManualApprovalRequest(request)) => Ok(request),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn set_relay_config(
        &self,
        session: &AdminSession,
        relay_url: Option<String>,
        frontend_url: Option<String>,
    ) -> Result<RelayConfig, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::SetRelayConfig {
            session: session.clone(),
            relay_url,
            frontend_url,
        }) {
            Ok(DaemonRpcResponse::RelayConfig(relay_config)) => Ok(relay_config),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn get_relay_config(&self, session: &AdminSession) -> Result<RelayConfig, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::GetRelayConfig {
            session: session.clone(),
        }) {
            Ok(DaemonRpcResponse::RelayConfig(relay_config)) => Ok(relay_config),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::EvaluateForAgent { request }) {
            Ok(DaemonRpcResponse::PolicyEvaluation(evaluation)) => Ok(evaluation),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ExplainForAgent { request }) {
            Ok(DaemonRpcResponse::PolicyExplanation(explanation)) => Ok(explanation),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ReserveNonce { request }) {
            Ok(DaemonRpcResponse::NonceReservation(reservation)) => Ok(reservation),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError> {
        match self.call_rpc(DaemonRpcRequest::ReleaseNonce { request }) {
            Ok(DaemonRpcResponse::Unit) => Ok(()),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }

    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError> {
        match self.call_rpc(DaemonRpcRequest::SignForAgent { request }) {
            Ok(DaemonRpcResponse::Signature(sig)) => Ok(sig),
            Ok(_) => Err(DaemonError::Transport(
                "unexpected response type".to_string(),
            )),
            Err(XpcTransportError::Daemon(err)) => Err(err),
            Err(err) => Err(DaemonError::Transport(err.to_string())),
        }
    }
}

/// Non-macOS fallback server type.
#[cfg(not(target_os = "macos"))]
pub struct XpcDaemonServer;

/// Non-macOS fallback client type.
#[cfg(not(target_os = "macos"))]
pub struct XpcDaemonClient;

#[cfg(not(target_os = "macos"))]
impl XpcDaemonServer {
    /// Always returns unsupported on non-macOS.
    pub fn start_inmemory<B>(
        _daemon: Arc<InMemoryDaemon<B>>,
        _runtime_handle: Handle,
    ) -> Result<Self, XpcTransportError>
    where
        B: VaultSignerBackend + 'static,
    {
        Err(XpcTransportError::UnsupportedPlatform)
    }
}
