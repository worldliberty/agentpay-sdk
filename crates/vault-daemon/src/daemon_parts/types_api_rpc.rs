/// Daemon-level errors.
pub(crate) const MAX_AUTH_SECRET_BYTES: usize = 16 * 1024;

#[derive(Debug, Error)]
pub enum DaemonError {
    /// Password mismatch.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Lease id was not issued by daemon.
    #[error("lease is unknown")]
    UnknownLease,
    /// Lease is expired or not yet valid.
    #[error("lease has expired or is not active yet")]
    InvalidLease,
    /// Lease issuance denied because active lease capacity was reached.
    #[error("too many active leases")]
    TooManyActiveLeases,
    /// Vault key id not found.
    #[error("unknown vault key id: {0}")]
    UnknownVaultKey(Uuid),
    /// Agent key id not found.
    #[error("unknown agent key id: {0}")]
    UnknownAgentKey(Uuid),
    /// Policy id not found.
    #[error("unknown policy id: {0}")]
    UnknownPolicy(Uuid),
    /// Manual approval request id not found.
    #[error("unknown manual approval request id: {0}")]
    UnknownManualApprovalRequest(Uuid),
    /// Agent key token did not match provisioned secret.
    #[error("agent authentication failed")]
    AgentAuthenticationFailed,
    /// Request payload did not match declared action.
    #[error("sign request payload/action mismatch")]
    PayloadActionMismatch,
    /// Request payload exceeded configured daemon limit.
    #[error("sign request payload exceeds max bytes ({max_bytes})")]
    PayloadTooLarge {
        /// Maximum allowed payload size in bytes.
        max_bytes: usize,
    },
    /// Request timestamp bounds were invalid.
    #[error("request timestamp bounds are invalid")]
    InvalidRequestTimestamps,
    /// Request has expired.
    #[error("request has expired")]
    RequestExpired,
    /// Request ID was already consumed.
    #[error("request id already used")]
    RequestReplayDetected,
    /// Replay protection table reached configured capacity.
    #[error("too many tracked replay ids (max {max_tracked})")]
    TooManyTrackedReplayIds {
        /// Maximum tracked replay ids allowed at once.
        max_tracked: usize,
    },
    /// Agent-key policy attachment was invalid.
    #[error("invalid agent policy attachment: {0}")]
    InvalidPolicyAttachment(String),
    /// Nonce reservation request was invalid.
    #[error("invalid nonce reservation request: {0}")]
    InvalidNonceReservation(String),
    /// Active nonce reservations reached configured capacity.
    #[error("too many active nonce reservations (max {max_active})")]
    TooManyActiveNonceReservations {
        /// Maximum active nonce reservations allowed at once.
        max_active: usize,
    },
    /// Nonce reservation id was not found.
    #[error("unknown nonce reservation id: {0}")]
    UnknownNonceReservation(Uuid),
    /// Signing a broadcast tx requires a matching nonce reservation.
    #[error("missing nonce reservation for chain_id {chain_id} and nonce {nonce}")]
    MissingNonceReservation {
        /// EVM chain id.
        chain_id: u64,
        /// Transaction nonce.
        nonce: u64,
    },
    /// Policy payload was invalid.
    #[error("invalid policy payload: {0}")]
    InvalidPolicy(String),
    /// Relay configuration payload was invalid.
    #[error("invalid relay configuration: {0}")]
    InvalidRelayConfig(String),
    /// Request requires explicit manual approval before signing can continue.
    #[error("manual approval required (request {approval_request_id})")]
    ManualApprovalRequired {
        approval_request_id: Uuid,
        relay_url: Option<String>,
        frontend_url: Option<String>,
    },
    /// Existing manual approval request was rejected.
    #[error("manual approval request {approval_request_id} was rejected")]
    ManualApprovalRejected { approval_request_id: Uuid },
    /// Manual approval request was already resolved and cannot be decided again.
    #[error("manual approval request {approval_request_id} is already {status:?}")]
    ManualApprovalRequestNotPending {
        approval_request_id: Uuid,
        status: ManualApprovalStatus,
    },
    /// Policy engine denied request.
    #[error("policy check failed: {0}")]
    Policy(#[from] PolicyError),
    /// Signer backend failed.
    #[error("signer backend error: {0}")]
    Signer(#[from] SignerError),
    /// Password hash failed.
    #[error("password hash error: {0}")]
    PasswordHash(String),
    /// Daemon configuration is invalid.
    #[error("invalid daemon configuration: {0}")]
    InvalidConfig(String),
    /// Transport or serialization layer failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// Persistent-state storage failed.
    #[error("persistent state error: {0}")]
    Persistence(String),
    /// Internal locking failure.
    #[error("internal lock poisoned")]
    LockPoisoned,
}

/// Daemon runtime configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Lease time-to-live.
    pub lease_ttl: Duration,
    /// Maximum number of active leases retained in memory.
    pub max_active_leases: usize,
    /// Maximum payload size accepted by `sign_for_agent`.
    pub max_sign_payload_bytes: usize,
    /// Maximum accepted request TTL (`expires_at - requested_at`).
    pub max_request_ttl: Duration,
    /// Maximum accepted future skew for `requested_at`.
    pub max_request_clock_skew: Duration,
    /// Maximum number of live replay ids retained in memory.
    pub max_tracked_replay_ids: usize,
    /// Default nonce reservation lease duration.
    pub nonce_reservation_ttl: Duration,
    /// Maximum number of active nonce reservations retained in memory.
    pub max_active_nonce_reservations: usize,
    /// Expiration window for pending or approved manual approval requests.
    pub manual_approval_active_ttl: Duration,
    /// Retention window for terminal manual approval requests before pruning.
    pub manual_approval_terminal_retention: Duration,
    /// Maximum number of distinct chain nonce heads tracked per vault key.
    pub max_tracked_nonce_chains_per_vault: usize,
    /// Consecutive failed admin password attempts allowed before temporary lockout.
    pub max_failed_admin_auth_attempts: u32,
    /// Temporary lockout duration after too many failed admin password attempts.
    pub admin_auth_lockout: Duration,
    /// Argon2 memory cost in KiB.
    pub argon2_memory_kib: u32,
    /// Argon2 time cost (iterations).
    pub argon2_time_cost: u32,
    /// Argon2 parallelism.
    pub argon2_parallelism: u32,
    /// Relay poll cadence for encrypted approval updates.
    pub relay_poll_interval: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            lease_ttl: Duration::minutes(30),
            max_active_leases: 1_024,
            max_sign_payload_bytes: 32 * 1024,
            max_request_ttl: Duration::minutes(5),
            max_request_clock_skew: Duration::seconds(30),
            max_tracked_replay_ids: 65_536,
            nonce_reservation_ttl: Duration::minutes(2),
            max_active_nonce_reservations: 16_384,
            manual_approval_active_ttl: Duration::hours(24),
            manual_approval_terminal_retention: Duration::days(8),
            max_tracked_nonce_chains_per_vault: 256,
            max_failed_admin_auth_attempts: 5,
            admin_auth_lockout: Duration::seconds(30),
            argon2_memory_kib: 19_456,
            argon2_time_cost: 2,
            argon2_parallelism: 1,
            relay_poll_interval: Duration::seconds(1),
        }
    }
}

/// Transport-neutral daemon API.
#[async_trait]
pub trait KeyManagerDaemonApi: Send + Sync {
    /// Issues a short-lived admin lease after validating vault password.
    async fn issue_lease(&self, vault_password: &str) -> Result<Lease, DaemonError>;

    /// Adds or replaces a policy by `policy.id`.
    ///
    /// Existing `PolicyAttachment::PolicySet` agent keys are left unchanged.
    /// New policy ids must be attached explicitly when the agent key is
    /// created.
    async fn add_policy(
        &self,
        session: &AdminSession,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError>;

    /// Lists all policies ordered by priority for an authenticated admin session.
    async fn list_policies(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<SpendingPolicy>, DaemonError>;

    /// Lists compact policy metadata for callers that only need ids and enabled state.
    async fn list_policy_summaries(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<PolicySummary>, DaemonError>;

    /// Disables a policy by id.
    ///
    /// Disabled policies remain listed but are ignored during evaluation.
    async fn disable_policy(
        &self,
        session: &AdminSession,
        policy_id: Uuid,
    ) -> Result<(), DaemonError>;

    /// Creates a vault key through configured signer backend.
    async fn create_vault_key(
        &self,
        session: &AdminSession,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError>;

    /// Exports a software-backed private key when the signer backend supports it.
    ///
    /// Backends such as Secure Enclave return `None` because the private key is
    /// intentionally non-exportable.
    async fn export_vault_private_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<Option<String>, DaemonError>;

    /// Returns the Solana Ed25519 public key derived for a vault key.
    async fn solana_public_key_hex(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<String, DaemonError>;

    /// Creates an agent key attached to all policies or a selected subset.
    ///
    /// `PolicyAttachment::PolicySet` is a static attachment snapshot. Later
    /// `add_policy` calls must not change existing `PolicySet` memberships.
    ///
    /// Returns an auth token that must be sent with each agent sign request.
    async fn create_agent_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError>;

    /// Replaces policy attachment on an existing agent key and rotates its auth token.
    ///
    /// The target agent key must already belong to `vault_key_id`.
    async fn refresh_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError>;

    /// Rotates the bearer token for an existing agent key.
    ///
    /// Returns the newly issued token.
    async fn rotate_agent_auth_token(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError>;

    /// Revokes an agent key and its auth token.
    async fn revoke_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError>;

    /// Lists manual approval requests for an authenticated admin session.
    async fn list_manual_approval_requests(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError>;

    /// Applies an approval or rejection decision to a pending approval request.
    async fn decide_manual_approval_request(
        &self,
        session: &AdminSession,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError>;

    /// Updates the relay API URL and optional frontend base URL used by the daemon.
    async fn set_relay_config(
        &self,
        session: &AdminSession,
        relay_url: Option<String>,
        frontend_url: Option<String>,
    ) -> Result<RelayConfig, DaemonError>;

    /// Returns the current relay configuration and daemon identity metadata.
    async fn get_relay_config(&self, session: &AdminSession) -> Result<RelayConfig, DaemonError>;

    /// Evaluates an agent request against current policy state without signing
    /// or recording spend.
    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError>;

    /// Returns an explanation for policy evaluation without signing or spend mutation.
    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError>;

    /// Reserves a unique nonce for a future broadcast transaction.
    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError>;

    /// Releases a previously reserved nonce lease.
    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError>;

    /// Evaluates policy and signs payload on success.
    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError>;
}

/// Compact policy metadata used when full policy scopes are unnecessary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySummary {
    pub id: Uuid,
    pub enabled: bool,
}

/// RPC request type for transport adapters.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum DaemonRpcRequest {
    /// Issue lease.
    IssueLease {
        /// Admin vault password.
        vault_password: String,
    },
    /// Add policy.
    AddPolicy {
        /// Admin session.
        session: AdminSession,
        /// Policy payload.
        policy: SpendingPolicy,
    },
    /// List policies.
    ListPolicies {
        /// Admin session.
        session: AdminSession,
    },
    /// List compact policy metadata.
    ListPolicySummaries {
        /// Admin session.
        session: AdminSession,
    },
    /// Disable policy.
    DisablePolicy {
        /// Admin session.
        session: AdminSession,
        /// Policy id to disable.
        policy_id: Uuid,
    },
    /// Create vault key.
    CreateVaultKey {
        /// Admin session.
        session: AdminSession,
        /// Create key request.
        request: KeyCreateRequest,
    },
    /// Create agent key.
    CreateAgentKey {
        /// Admin session.
        session: AdminSession,
        /// Backing vault key.
        vault_key_id: Uuid,
        /// Attachment mode.
        attachment: PolicyAttachment,
    },
    /// Refresh an existing agent key with a new attachment and auth token.
    RefreshAgentKey {
        /// Admin session.
        session: AdminSession,
        /// Existing agent key id.
        agent_key_id: Uuid,
        /// Backing vault key the agent must already reference.
        vault_key_id: Uuid,
        /// Replacement attachment mode.
        attachment: PolicyAttachment,
    },
    /// Export a software-backed vault private key when supported.
    ExportVaultPrivateKey {
        /// Admin session.
        session: AdminSession,
        /// Vault key id.
        vault_key_id: Uuid,
    },
    /// Derive/read a Solana public key for an existing vault key.
    SolanaPublicKey {
        /// Admin session.
        session: AdminSession,
        /// Vault key id.
        vault_key_id: Uuid,
    },
    /// Rotate agent auth token.
    RotateAgentAuthToken {
        /// Admin session.
        session: AdminSession,
        /// Agent key id.
        agent_key_id: Uuid,
    },
    /// Revoke agent key.
    RevokeAgentKey {
        /// Admin session.
        session: AdminSession,
        /// Agent key id.
        agent_key_id: Uuid,
    },
    /// List manual approval requests.
    ListManualApprovalRequests {
        /// Admin session.
        session: AdminSession,
    },
    /// Decide a manual approval request.
    DecideManualApprovalRequest {
        /// Admin session.
        session: AdminSession,
        /// Approval request id.
        approval_request_id: Uuid,
        /// Approval decision.
        decision: ManualApprovalDecision,
        /// Optional rejection reason.
        rejection_reason: Option<String>,
    },
    /// Set daemon relay configuration.
    SetRelayConfig {
        /// Admin session.
        session: AdminSession,
        /// Relay API URL.
        relay_url: Option<String>,
        /// Frontend base URL used for approval deep links.
        frontend_url: Option<String>,
    },
    /// Read daemon relay configuration.
    GetRelayConfig {
        /// Admin session.
        session: AdminSession,
    },
    /// Evaluate for agent without signing.
    EvaluateForAgent {
        /// Sign request payload.
        request: SignRequest,
    },
    /// Explain policy decision for agent request without signing.
    ExplainForAgent {
        /// Sign request payload.
        request: SignRequest,
    },
    /// Reserve a nonce for future broadcast signing.
    ReserveNonce {
        /// Reservation request payload.
        request: NonceReservationRequest,
    },
    /// Release an existing nonce reservation.
    ReleaseNonce {
        /// Release request payload.
        request: NonceReleaseRequest,
    },
    /// Sign for agent.
    SignForAgent {
        /// Sign request payload.
        request: SignRequest,
    },
}

impl DaemonRpcRequest {
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::IssueLease { vault_password } => vault_password.zeroize(),
            Self::AddPolicy { session, .. }
            | Self::ListPolicies { session }
            | Self::ListPolicySummaries { session }
            | Self::DisablePolicy { session, .. }
            | Self::CreateVaultKey { session, .. }
            | Self::CreateAgentKey { session, .. }
            | Self::RefreshAgentKey { session, .. }
            | Self::ExportVaultPrivateKey { session, .. }
            | Self::SolanaPublicKey { session, .. }
            | Self::RotateAgentAuthToken { session, .. }
            | Self::RevokeAgentKey { session, .. }
            | Self::ListManualApprovalRequests { session }
            | Self::DecideManualApprovalRequest { session, .. }
            | Self::SetRelayConfig { session, .. }
            | Self::GetRelayConfig { session } => session.zeroize_secrets(),
            Self::EvaluateForAgent { request }
            | Self::ExplainForAgent { request }
            | Self::SignForAgent { request } => request.zeroize_secrets(),
            Self::ReserveNonce { request } => request.zeroize_secrets(),
            Self::ReleaseNonce { request } => request.zeroize_secrets(),
        }
    }
}

impl std::fmt::Debug for DaemonRpcRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IssueLease { .. } => f
                .debug_struct("IssueLease")
                .field("vault_password", &"<redacted>")
                .finish(),
            Self::AddPolicy { session, policy } => f
                .debug_struct("AddPolicy")
                .field("session", session)
                .field("policy", policy)
                .finish(),
            Self::ListPolicies { session } => f
                .debug_struct("ListPolicies")
                .field("session", session)
                .finish(),
            Self::ListPolicySummaries { session } => f
                .debug_struct("ListPolicySummaries")
                .field("session", session)
                .finish(),
            Self::DisablePolicy { session, policy_id } => f
                .debug_struct("DisablePolicy")
                .field("session", session)
                .field("policy_id", policy_id)
                .finish(),
            Self::CreateVaultKey { session, request } => f
                .debug_struct("CreateVaultKey")
                .field("session", session)
                .field("request", request)
                .finish(),
            Self::CreateAgentKey {
                session,
                vault_key_id,
                attachment,
            } => f
                .debug_struct("CreateAgentKey")
                .field("session", session)
                .field("vault_key_id", vault_key_id)
                .field("attachment", attachment)
                .finish(),
            Self::RefreshAgentKey {
                session,
                agent_key_id,
                vault_key_id,
                attachment,
            } => f
                .debug_struct("RefreshAgentKey")
                .field("session", session)
                .field("agent_key_id", agent_key_id)
                .field("vault_key_id", vault_key_id)
                .field("attachment", attachment)
                .finish(),
            Self::ExportVaultPrivateKey {
                session,
                vault_key_id,
            } => f
                .debug_struct("ExportVaultPrivateKey")
                .field("session", session)
                .field("vault_key_id", vault_key_id)
                .finish(),
            Self::SolanaPublicKey {
                session,
                vault_key_id,
            } => f
                .debug_struct("SolanaPublicKey")
                .field("session", session)
                .field("vault_key_id", vault_key_id)
                .finish(),
            Self::RotateAgentAuthToken {
                session,
                agent_key_id,
            } => f
                .debug_struct("RotateAgentAuthToken")
                .field("session", session)
                .field("agent_key_id", agent_key_id)
                .finish(),
            Self::RevokeAgentKey {
                session,
                agent_key_id,
            } => f
                .debug_struct("RevokeAgentKey")
                .field("session", session)
                .field("agent_key_id", agent_key_id)
                .finish(),
            Self::ListManualApprovalRequests { session } => f
                .debug_struct("ListManualApprovalRequests")
                .field("session", session)
                .finish(),
            Self::DecideManualApprovalRequest {
                session,
                approval_request_id,
                decision,
                rejection_reason,
            } => f
                .debug_struct("DecideManualApprovalRequest")
                .field("session", session)
                .field("approval_request_id", approval_request_id)
                .field("decision", decision)
                .field("rejection_reason", rejection_reason)
                .finish(),
            Self::SetRelayConfig {
                session,
                relay_url,
                frontend_url,
            } => f
                .debug_struct("SetRelayConfig")
                .field("session", session)
                .field("relay_url", relay_url)
                .field("frontend_url", frontend_url)
                .finish(),
            Self::GetRelayConfig { session } => f
                .debug_struct("GetRelayConfig")
                .field("session", session)
                .finish(),
            Self::EvaluateForAgent { request } => f
                .debug_struct("EvaluateForAgent")
                .field("request", request)
                .finish(),
            Self::ExplainForAgent { request } => f
                .debug_struct("ExplainForAgent")
                .field("request", request)
                .finish(),
            Self::ReserveNonce { request } => f
                .debug_struct("ReserveNonce")
                .field("request", request)
                .finish(),
            Self::ReleaseNonce { request } => f
                .debug_struct("ReleaseNonce")
                .field("request", request)
                .finish(),
            Self::SignForAgent { request } => f
                .debug_struct("SignForAgent")
                .field("request", request)
                .finish(),
        }
    }
}

/// RPC response type for transport adapters.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum DaemonRpcResponse {
    /// No return data.
    Unit,
    /// Lease response.
    Lease(Lease),
    /// Policy list response.
    Policies(Vec<SpendingPolicy>),
    /// Compact policy metadata response.
    PolicySummaries(Vec<PolicySummary>),
    /// Policy evaluation response.
    PolicyEvaluation(PolicyEvaluation),
    /// Policy explanation response.
    PolicyExplanation(PolicyExplanation),
    /// Vault key response.
    VaultKey(VaultKey),
    /// Agent key + auth token response.
    AgentCredentials(AgentCredentials),
    /// Exported software-backed private key response.
    PrivateKey(Option<String>),
    /// Public key response.
    PublicKey(String),
    /// Rotated auth token response.
    AuthToken(String),
    /// Manual approval request list response.
    ManualApprovalRequests(Vec<ManualApprovalRequest>),
    /// Single manual approval request response.
    ManualApprovalRequest(ManualApprovalRequest),
    /// Relay config response.
    RelayConfig(RelayConfig),
    /// Nonce reservation response.
    NonceReservation(NonceReservation),
    /// Signature response.
    Signature(Signature),
}

impl DaemonRpcResponse {
    pub fn zeroize_secrets(&mut self) {
        match self {
            Self::AgentCredentials(credentials) => credentials.zeroize_secrets(),
            Self::PrivateKey(Some(private_key)) => private_key.zeroize(),
            Self::PrivateKey(None) => {}
            Self::AuthToken(token) => token.zeroize(),
            _ => {}
        }
    }
}

impl std::fmt::Debug for DaemonRpcResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit => f.write_str("Unit"),
            Self::Lease(lease) => f.debug_tuple("Lease").field(lease).finish(),
            Self::Policies(policies) => f.debug_tuple("Policies").field(policies).finish(),
            Self::PolicySummaries(summaries) => {
                f.debug_tuple("PolicySummaries").field(summaries).finish()
            }
            Self::PolicyEvaluation(evaluation) => {
                f.debug_tuple("PolicyEvaluation").field(evaluation).finish()
            }
            Self::PolicyExplanation(explanation) => f
                .debug_tuple("PolicyExplanation")
                .field(explanation)
                .finish(),
            Self::VaultKey(key) => f.debug_tuple("VaultKey").field(key).finish(),
            Self::AgentCredentials(credentials) => f
                .debug_tuple("AgentCredentials")
                .field(credentials)
                .finish(),
            Self::PrivateKey(Some(_)) => f.debug_tuple("PrivateKey").field(&"<redacted>").finish(),
            Self::PrivateKey(None) => f.debug_tuple("PrivateKey").field(&"<none>").finish(),
            Self::PublicKey(public_key) => f.debug_tuple("PublicKey").field(public_key).finish(),
            Self::AuthToken(_) => f.debug_tuple("AuthToken").field(&"<redacted>").finish(),
            Self::ManualApprovalRequests(requests) => f
                .debug_tuple("ManualApprovalRequests")
                .field(requests)
                .finish(),
            Self::ManualApprovalRequest(request) => f
                .debug_tuple("ManualApprovalRequest")
                .field(request)
                .finish(),
            Self::RelayConfig(config) => f.debug_tuple("RelayConfig").field(config).finish(),
            Self::NonceReservation(reservation) => f
                .debug_tuple("NonceReservation")
                .field(reservation)
                .finish(),
            Self::Signature(signature) => f.debug_tuple("Signature").field(signature).finish(),
        }
    }
}
