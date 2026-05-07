#[derive(Debug, Clone, Default)]
struct AdminAuthState {
    failed_attempts: u32,
    locked_until: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum RecoverableAgentRequest {
    Sign {
        payload_hash_hex: String,
    },
    ReserveNonce {
        chain_id: u64,
        min_nonce: u64,
        exact_nonce: bool,
    },
    ReleaseNonce {
        reservation_id: Uuid,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum RecoverableAgentResponse {
    Signature(Signature),
    NonceReservation(NonceReservation),
    Unit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoverableAgentResult {
    agent_key_id: Uuid,
    request: RecoverableAgentRequest,
    recover_until: OffsetDateTime,
    response: RecoverableAgentResponse,
}

enum ManualApprovalResolution {
    Approved(Option<Uuid>),
    Rejected(Uuid),
    Pending {
        approval_request_id: Uuid,
        relay_config: RelayConfig,
    },
}

struct ManualApprovalRetentionCutoffs {
    active: OffsetDateTime,
    terminal: OffsetDateTime,
}

const SPEND_LOG_RETENTION: Duration = Duration::days(8);

pub struct InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    signer_backend: B,
    policy_engine: PolicyEngine,
    admin_password_hash: String,
    config: DaemonConfig,
    leases: Arc<RwLock<HashMap<Uuid, Lease>>>,
    policies: Arc<RwLock<HashMap<Uuid, SpendingPolicy>>>,
    vault_keys: Arc<RwLock<HashMap<Uuid, VaultKey>>>,
    agent_keys: Arc<RwLock<HashMap<Uuid, AgentKey>>>,
    agent_auth_tokens: Arc<RwLock<HashMap<Uuid, [u8; 32]>>>,
    replay_ids: Arc<RwLock<HashMap<Uuid, OffsetDateTime>>>,
    nonce_heads: Arc<RwLock<HashMap<Uuid, HashMap<u64, u64>>>>,
    reusable_nonce_gaps: Arc<RwLock<ReusableNonceGaps>>,
    nonce_reservations: Arc<RwLock<HashMap<Uuid, NonceReservation>>>,
    spend_log: Arc<RwLock<Vec<SpendEvent>>>,
    manual_approval_requests: Arc<RwLock<HashMap<Uuid, ManualApprovalRequest>>>,
    relay_config: Arc<RwLock<RelayConfig>>,
    relay_private_key_hex: Arc<RwLock<Zeroizing<String>>>,
    admin_auth_state: Arc<RwLock<AdminAuthState>>,
    recoverable_agent_results: Arc<RwLock<HashMap<Uuid, RecoverableAgentResult>>>,
    state_store: Option<EncryptedStateStore>,
    signing_guard: tokio::sync::Mutex<()>,
    state_persist_guard: tokio::sync::Mutex<()>,
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Builds daemon and hashes admin password using Argon2.
    pub fn new(
        admin_password: &str,
        signer_backend: B,
        config: DaemonConfig,
    ) -> Result<Self, DaemonError> {
        validate_config(&config)?;
        validate_admin_password(admin_password)?;
        let admin_password_hash = hash_password(admin_password, &config)?;
        let state = prepare_loaded_state(PersistedDaemonState::default())?;
        Self::new_with_loaded_state(
            signer_backend,
            admin_password_hash,
            config,
            state,
            None,
        )
    }

    /// Builds daemon with encrypted persistent state on local filesystem.
    pub fn new_with_persistent_store(
        admin_password: &str,
        signer_backend: B,
        config: DaemonConfig,
        store_config: PersistentStoreConfig,
    ) -> Result<Self, DaemonError> {
        validate_config(&config)?;
        validate_admin_password(admin_password)?;
        let admin_password_hash = hash_password(admin_password, &config)?;
        let (state_store, state) =
            EncryptedStateStore::open_or_initialize(admin_password, &config, store_config)
                .map_err(DaemonError::Persistence)?;
        Self::new_with_loaded_state(
            signer_backend,
            admin_password_hash,
            config,
            state,
            Some(state_store),
        )
    }

    fn new_with_loaded_state(
        signer_backend: B,
        admin_password_hash: String,
        config: DaemonConfig,
        state: PersistedDaemonState,
        state_store: Option<EncryptedStateStore>,
    ) -> Result<Self, DaemonError> {
        let original_state = state.clone();
        let mut state = prepare_loaded_state(state)?;
        normalize_disabled_policy_set_attachments(&mut state);
        Self::scrub_persisted_ephemeral_state(&config, &mut state, OffsetDateTime::now_utc())?;
        validate_loaded_state(&state)?;
        signer_backend
            .restore_persistable_key_material(&state.software_signer_private_keys)
            .map_err(DaemonError::Signer)?;
        if state != original_state {
            if let Some(store) = &state_store {
                store.save(&state).map_err(DaemonError::Persistence)?;
            }
        }
        Ok(Self {
            signer_backend,
            policy_engine: PolicyEngine,
            admin_password_hash,
            config,
            leases: Arc::new(RwLock::new(state.leases)),
            policies: Arc::new(RwLock::new(state.policies)),
            vault_keys: Arc::new(RwLock::new(state.vault_keys)),
            agent_keys: Arc::new(RwLock::new(state.agent_keys)),
            agent_auth_tokens: Arc::new(RwLock::new(state.agent_auth_tokens)),
            replay_ids: Arc::new(RwLock::new(state.replay_ids)),
            nonce_heads: Arc::new(RwLock::new(state.nonce_heads)),
            reusable_nonce_gaps: Arc::new(RwLock::new(state.reusable_nonce_gaps)),
            nonce_reservations: Arc::new(RwLock::new(state.nonce_reservations)),
            spend_log: Arc::new(RwLock::new(state.spend_log)),
            manual_approval_requests: Arc::new(RwLock::new(state.manual_approval_requests)),
            relay_config: Arc::new(RwLock::new(state.relay_config)),
            relay_private_key_hex: Arc::new(RwLock::new(state.relay_private_key_hex)),
            admin_auth_state: Arc::new(RwLock::new(AdminAuthState::default())),
            recoverable_agent_results: Arc::new(RwLock::new(state.recoverable_agent_results)),
            state_store,
            signing_guard: tokio::sync::Mutex::new(()),
            state_persist_guard: tokio::sync::Mutex::new(()),
        })
    }

    /// Handles a serialized daemon RPC call.
    pub async fn handle_rpc(
        &self,
        request: DaemonRpcRequest,
    ) -> Result<DaemonRpcResponse, DaemonError> {
        match request {
            DaemonRpcRequest::IssueLease { vault_password } => {
                let mut vault_password = vault_password;
                let result = async {
                    Ok(DaemonRpcResponse::Lease(
                        self.issue_lease(&vault_password).await?,
                    ))
                }
                .await;
                vault_password.zeroize();
                result
            }
            DaemonRpcRequest::AddPolicy { session, policy } => {
                let mut session = session;
                let result = async {
                    self.add_policy(&session, policy).await?;
                    Ok(DaemonRpcResponse::Unit)
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::ListPolicies { session } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::Policies(
                        self.list_policies(&session).await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::ListPolicySummaries { session } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::PolicySummaries(
                        self.list_policy_summaries(&session).await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::DisablePolicy { session, policy_id } => {
                let mut session = session;
                let result = async {
                    self.disable_policy(&session, policy_id).await?;
                    Ok(DaemonRpcResponse::Unit)
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::CreateVaultKey { session, request } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::VaultKey(
                        self.create_vault_key(&session, request).await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::CreateAgentKey {
                session,
                vault_key_id,
                attachment,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::AgentCredentials(
                        self.create_agent_key(&session, vault_key_id, attachment)
                            .await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::RefreshAgentKey {
                session,
                agent_key_id,
                vault_key_id,
                attachment,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::AgentCredentials(
                        self.refresh_agent_key(&session, agent_key_id, vault_key_id, attachment)
                            .await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::ExportVaultPrivateKey {
                session,
                vault_key_id,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::PrivateKey(
                        self.export_vault_private_key(&session, vault_key_id)
                            .await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::SolanaPublicKey {
                session,
                vault_key_id,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::PublicKey(
                        self.solana_public_key_hex(&session, vault_key_id)
                            .await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::RotateAgentAuthToken {
                session,
                agent_key_id,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::AuthToken(
                        self.rotate_agent_auth_token(&session, agent_key_id).await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::RevokeAgentKey {
                session,
                agent_key_id,
            } => {
                let mut session = session;
                let result = async {
                    self.revoke_agent_key(&session, agent_key_id).await?;
                    Ok(DaemonRpcResponse::Unit)
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::ListManualApprovalRequests { session } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::ManualApprovalRequests(
                        self.list_manual_approval_requests(&session).await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::DecideManualApprovalRequest {
                session,
                approval_request_id,
                decision,
                rejection_reason,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::ManualApprovalRequest(
                        self.decide_manual_approval_request(
                            &session,
                            approval_request_id,
                            decision,
                            rejection_reason,
                        )
                        .await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::SetRelayConfig {
                session,
                relay_url,
                frontend_url,
            } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::RelayConfig(
                        self.set_relay_config(&session, relay_url, frontend_url)
                            .await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::GetRelayConfig { session } => {
                let mut session = session;
                let result = async {
                    Ok(DaemonRpcResponse::RelayConfig(
                        self.get_relay_config(&session).await?,
                    ))
                }
                .await;
                session.zeroize_secrets();
                result
            }
            DaemonRpcRequest::EvaluateForAgent { request } => Ok(
                DaemonRpcResponse::PolicyEvaluation(self.evaluate_for_agent(request).await?),
            ),
            DaemonRpcRequest::ExplainForAgent { request } => Ok(
                DaemonRpcResponse::PolicyExplanation(self.explain_for_agent(request).await?),
            ),
            DaemonRpcRequest::ReserveNonce { request } => Ok(DaemonRpcResponse::NonceReservation(
                self.reserve_nonce(request).await?,
            )),
            DaemonRpcRequest::ReleaseNonce { request } => {
                self.release_nonce(request).await?;
                Ok(DaemonRpcResponse::Unit)
            }
            DaemonRpcRequest::SignForAgent { request } => Ok(DaemonRpcResponse::Signature(
                self.sign_for_agent(request).await?,
            )),
        }
    }

    fn authenticate(&self, session: &AdminSession, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.authenticate_password(&session.vault_password)?;

        let lease = self
            .leases
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&session.lease.lease_id)
            .cloned()
            .ok_or(DaemonError::UnknownLease)?;

        if !lease.is_valid_at(now) {
            return Err(DaemonError::InvalidLease);
        }

        Ok(())
    }

    fn authenticate_password(&self, vault_password: &str) -> Result<(), DaemonError> {
        let now = OffsetDateTime::now_utc();
        self.enforce_admin_auth_lockout(now)?;

        if vault_password.len() > MAX_AUTH_SECRET_BYTES {
            self.record_failed_admin_auth(now)?;
            return Err(DaemonError::AuthenticationFailed);
        }

        let parsed = PasswordHash::new(&self.admin_password_hash)
            .map_err(|err| DaemonError::PasswordHash(format!("invalid hash in memory: {err}")))?;

        let verification_result = Argon2::default()
            .verify_password(vault_password.as_bytes(), &parsed)
            .map_err(|_| DaemonError::AuthenticationFailed);

        match verification_result {
            Ok(()) => {
                self.reset_admin_auth_state()?;
                Ok(())
            }
            Err(err) => {
                self.record_failed_admin_auth(now)?;
                Err(err)
            }
        }
    }

    fn enforce_admin_auth_lockout(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        let mut state = self
            .admin_auth_state
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;

        if let Some(locked_until) = state.locked_until {
            if locked_until > now {
                return Err(DaemonError::AuthenticationFailed);
            }
            state.locked_until = None;
            state.failed_attempts = 0;
        }

        Ok(())
    }

    fn reset_admin_auth_state(&self) -> Result<(), DaemonError> {
        let mut state = self
            .admin_auth_state
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        state.failed_attempts = 0;
        state.locked_until = None;
        Ok(())
    }

    fn record_failed_admin_auth(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        let mut state = self
            .admin_auth_state
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;

        if let Some(locked_until) = state.locked_until {
            if locked_until > now {
                return Ok(());
            }
            state.locked_until = None;
            state.failed_attempts = 0;
        }

        state.failed_attempts = state.failed_attempts.saturating_add(1);
        if state.failed_attempts >= self.config.max_failed_admin_auth_attempts {
            state.failed_attempts = 0;
            state.locked_until = Some(now.checked_add(self.config.admin_auth_lockout).ok_or_else(
                || {
                    DaemonError::InvalidConfig(
                        "admin_auth_lockout causes timestamp overflow".to_string(),
                    )
                },
            )?);
        }

        Ok(())
    }

    fn validate_request_timestamps(
        &self,
        requested_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        if expires_at <= now {
            return Err(DaemonError::RequestExpired);
        }
        if expires_at <= requested_at {
            return Err(DaemonError::InvalidRequestTimestamps);
        }
        if requested_at > now + self.config.max_request_clock_skew {
            return Err(DaemonError::InvalidRequestTimestamps);
        }
        let ttl = expires_at - requested_at;
        if ttl > self.config.max_request_ttl {
            return Err(DaemonError::InvalidRequestTimestamps);
        }
        Ok(())
    }

    fn authenticate_agent(
        &self,
        agent_key_id: Uuid,
        agent_auth_token: &str,
    ) -> Result<AgentKey, DaemonError> {
        if agent_auth_token.len() > MAX_AUTH_SECRET_BYTES {
            return Err(DaemonError::AgentAuthenticationFailed);
        }

        let expected_auth_hash = self
            .agent_auth_tokens
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .copied()
            .ok_or(DaemonError::AgentAuthenticationFailed)?;
        let presented_auth_hash = hash_agent_auth_token(agent_auth_token);
        if !constant_time_eq(&expected_auth_hash, &presented_auth_hash) {
            return Err(DaemonError::AgentAuthenticationFailed);
        }

        self.agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .cloned()
            .ok_or(DaemonError::AgentAuthenticationFailed)
    }

    fn authorize_request_payload(
        &self,
        request: &SignRequest,
    ) -> Result<(AgentKey, AgentAction), DaemonError> {
        if request.payload.len() > self.config.max_sign_payload_bytes {
            return Err(DaemonError::PayloadTooLarge {
                max_bytes: self.config.max_sign_payload_bytes,
            });
        }

        let agent_key = self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;

        let payload_action: AgentAction = serde_json::from_slice(&request.payload)
            .map_err(|_| DaemonError::PayloadActionMismatch)?;
        payload_action
            .validate()
            .map_err(|_| DaemonError::PayloadActionMismatch)?;
        if payload_action != request.action {
            return Err(DaemonError::PayloadActionMismatch);
        }
        let canonical_payload =
            serde_json::to_vec(&request.action).map_err(|_| DaemonError::PayloadActionMismatch)?;
        if request.payload != canonical_payload {
            return Err(DaemonError::PayloadActionMismatch);
        }

        Ok((agent_key, payload_action))
    }

    fn explain_authorized_request(
        &self,
        request: &SignRequest,
        now: OffsetDateTime,
    ) -> Result<(AgentKey, AgentAction, PolicyExplanation), DaemonError> {
        self.validate_request_timestamps(request.requested_at, request.expires_at, now)?;
        let (agent_key, payload_action) = self.authorize_request_payload(request)?;

        let policies: Vec<SpendingPolicy> = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .cloned()
            .collect();

        let retention_start = now - Duration::days(8);
        let spend_history: Vec<SpendEvent> = self
            .spend_log
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .iter()
            .filter(|event| {
                Self::spend_event_is_within_retention_window(event, retention_start, now)
            })
            .cloned()
            .collect();

        let policy_explanation = self.policy_engine.explain(
            &policies,
            &agent_key.policies,
            &payload_action,
            &spend_history,
            request.agent_key_id,
            now,
        );

        Ok((agent_key, payload_action, policy_explanation))
    }

    fn evaluate_authorized_request(
        &self,
        request: &SignRequest,
        now: OffsetDateTime,
    ) -> Result<(AgentKey, AgentAction, PolicyEvaluation), DaemonError> {
        let (agent_key, payload_action, policy_explanation) =
            self.explain_authorized_request(request, now)?;
        match policy_explanation.decision {
            PolicyDecision::Allow => Ok((
                agent_key,
                payload_action,
                PolicyEvaluation {
                    evaluated_policy_ids: policy_explanation.evaluated_policy_ids,
                },
            )),
            PolicyDecision::Deny(err) => Err(DaemonError::Policy(err)),
        }
    }

    fn prune_leases(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.leases
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, lease| lease.is_valid_at(now));
        Ok(())
    }

    fn prune_replay_ids(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.replay_ids
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, expires_at| *expires_at > now);
        Ok(())
    }

    fn ensure_replay_id_available(
        &self,
        request_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_replay_ids(now)?;
        let replay_ids = self
            .replay_ids
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        if replay_ids.contains_key(&request_id) {
            return Err(DaemonError::RequestReplayDetected);
        }
        if replay_ids.len() >= self.config.max_tracked_replay_ids {
            return Err(DaemonError::TooManyTrackedReplayIds {
                max_tracked: self.config.max_tracked_replay_ids,
            });
        }
        Ok(())
    }

    fn register_replay_id(
        &self,
        request_id: Uuid,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_replay_ids(now)?;
        let mut replay_ids = self
            .replay_ids
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        if replay_ids.contains_key(&request_id) {
            return Err(DaemonError::RequestReplayDetected);
        }
        if replay_ids.len() >= self.config.max_tracked_replay_ids {
            return Err(DaemonError::TooManyTrackedReplayIds {
                max_tracked: self.config.max_tracked_replay_ids,
            });
        }
        replay_ids.insert(request_id, expires_at);
        Ok(())
    }

    fn prune_recoverable_agent_results(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, entry| entry.recover_until > now);
        Ok(())
    }

    fn record_recoverable_agent_result(
        &self,
        request_id: Uuid,
        result: RecoverableAgentResult,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_recoverable_agent_results(now)?;
        self.recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(request_id, result);
        Ok(())
    }

    fn record_recoverable_signature(
        &self,
        request: &SignRequest,
        signature: &Signature,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.record_recoverable_agent_result(
            request.request_id,
            RecoverableAgentResult {
                agent_key_id: request.agent_key_id,
                request: RecoverableAgentRequest::Sign {
                    payload_hash_hex: payload_hash_hex(&request.payload),
                },
                recover_until: now + Duration::days(8),
                response: RecoverableAgentResponse::Signature(signature.clone()),
            },
            now,
        )
    }

    fn record_recoverable_nonce_reservation(
        &self,
        request: &NonceReservationRequest,
        reservation: &NonceReservation,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.record_recoverable_agent_result(
            request.request_id,
            RecoverableAgentResult {
                agent_key_id: request.agent_key_id,
                request: RecoverableAgentRequest::ReserveNonce {
                    chain_id: request.chain_id,
                    min_nonce: request.min_nonce,
                    exact_nonce: request.exact_nonce,
                },
                recover_until: now + Duration::days(8),
                response: RecoverableAgentResponse::NonceReservation(reservation.clone()),
            },
            now,
        )
    }

    fn record_recoverable_nonce_release(
        &self,
        request: &NonceReleaseRequest,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.record_recoverable_agent_result(
            request.request_id,
            RecoverableAgentResult {
                agent_key_id: request.agent_key_id,
                request: RecoverableAgentRequest::ReleaseNonce {
                    reservation_id: request.reservation_id,
                },
                recover_until: now + Duration::days(8),
                response: RecoverableAgentResponse::Unit,
            },
            now,
        )
    }

    fn recover_signature_if_available(
        &self,
        request: &SignRequest,
        now: OffsetDateTime,
    ) -> Result<Option<Signature>, DaemonError> {
        self.prune_recoverable_agent_results(now)?;
        let Some(entry) = self
            .recoverable_agent_results
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&request.request_id)
            .cloned()
        else {
            return Ok(None);
        };

        self.authorize_request_payload(request)?;
        let request_payload_hash = payload_hash_hex(&request.payload);
        let matches_request = entry.agent_key_id == request.agent_key_id
            && matches!(
                &entry.request,
                RecoverableAgentRequest::Sign { payload_hash_hex }
                    if payload_hash_hex == &request_payload_hash
            );
        if !matches_request {
            return Err(DaemonError::RequestReplayDetected);
        }

        let RecoverableAgentResponse::Signature(signature) = entry.response else {
            return Err(DaemonError::RequestReplayDetected);
        };

        let _ = self.persist_state_if_enabled();
        Ok(Some(signature))
    }

    fn recover_nonce_reservation_if_available(
        &self,
        request: &NonceReservationRequest,
        now: OffsetDateTime,
    ) -> Result<Option<NonceReservation>, DaemonError> {
        self.prune_recoverable_agent_results(now)?;
        let Some(entry) = self
            .recoverable_agent_results
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&request.request_id)
            .cloned()
        else {
            return Ok(None);
        };

        self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;
        let matches_request = entry.agent_key_id == request.agent_key_id
            && matches!(
                entry.request,
                RecoverableAgentRequest::ReserveNonce {
                    chain_id,
                    min_nonce,
                    exact_nonce,
                } if chain_id == request.chain_id
                    && min_nonce == request.min_nonce
                    && exact_nonce == request.exact_nonce
            );
        if !matches_request {
            return Err(DaemonError::RequestReplayDetected);
        }

        let RecoverableAgentResponse::NonceReservation(reservation) = entry.response else {
            return Err(DaemonError::RequestReplayDetected);
        };

        let live_reservation = self
            .nonce_reservations
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&reservation.reservation_id)
            .cloned();
        if !matches!(
            &live_reservation,
            Some(current) if current == &reservation && current.expires_at > now
        ) {
            return Err(DaemonError::RequestReplayDetected);
        }

        let _ = self.persist_state_if_enabled();
        Ok(live_reservation)
    }

    fn recover_nonce_release_if_available(
        &self,
        request: &NonceReleaseRequest,
        now: OffsetDateTime,
    ) -> Result<bool, DaemonError> {
        self.prune_recoverable_agent_results(now)?;
        let Some(entry) = self
            .recoverable_agent_results
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&request.request_id)
            .cloned()
        else {
            return Ok(false);
        };

        self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;
        let matches_request = entry.agent_key_id == request.agent_key_id
            && matches!(
                entry.request,
                RecoverableAgentRequest::ReleaseNonce { reservation_id }
                    if reservation_id == request.reservation_id
            );
        if !matches_request {
            return Err(DaemonError::RequestReplayDetected);
        }

        if !matches!(entry.response, RecoverableAgentResponse::Unit) {
            return Err(DaemonError::RequestReplayDetected);
        }

        let _ = self.persist_state_if_enabled();
        Ok(true)
    }

    fn prune_nonce_reservations(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        let removed = {
            let mut reservations = self
                .nonce_reservations
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let removed = reservations
                .values()
                .filter(|reservation| !reservation.is_valid_at(now))
                .cloned()
                .collect::<Vec<_>>();
            // Treat future-issued reservations as inactive so corrupted state
            // cannot block nonce allocation or authorize a broadcast early.
            reservations.retain(|_, reservation| reservation.is_valid_at(now));
            removed
        };
        self.reclaim_unused_nonce_heads(&removed)?;
        Ok(())
    }

    fn manual_approval_retention_cutoffs(
        &self,
        now: OffsetDateTime,
    ) -> Result<ManualApprovalRetentionCutoffs, DaemonError> {
        Self::manual_approval_retention_cutoffs_for_config(&self.config, now)
    }

    fn manual_approval_retention_cutoffs_for_config(
        config: &DaemonConfig,
        now: OffsetDateTime,
    ) -> Result<ManualApprovalRetentionCutoffs, DaemonError> {
        let active = now
            .checked_sub(config.manual_approval_active_ttl)
            .ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "manual_approval_active_ttl causes timestamp underflow".to_string(),
                )
            })?;
        let terminal = now
            .checked_sub(config.manual_approval_terminal_retention)
            .ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "manual_approval_terminal_retention causes timestamp underflow".to_string(),
                )
            })?;
        Ok(ManualApprovalRetentionCutoffs { active, terminal })
    }

    fn manual_approval_request_retained_with_cutoffs(
        request: &ManualApprovalRequest,
        cutoffs: &ManualApprovalRetentionCutoffs,
    ) -> bool {
        let relevant_at = match request.status {
            ManualApprovalStatus::Pending
            | ManualApprovalStatus::Approved
            | ManualApprovalStatus::Rejected => request.updated_at,
            ManualApprovalStatus::Completed => request.completed_at.unwrap_or(request.updated_at),
        };
        let cutoff = match request.status {
            ManualApprovalStatus::Pending | ManualApprovalStatus::Approved => cutoffs.active,
            ManualApprovalStatus::Rejected | ManualApprovalStatus::Completed => cutoffs.terminal,
        };
        relevant_at > cutoff
    }

    fn retained_manual_approval_requests_at(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        let cutoffs = self.manual_approval_retention_cutoffs(now)?;
        Ok(self
            .manual_approval_requests
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .filter(|request| {
                Self::manual_approval_request_retained_with_cutoffs(request, &cutoffs)
            })
            .cloned()
            .collect())
    }

    fn prune_manual_approval_requests(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        let cutoffs = self.manual_approval_retention_cutoffs(now)?;
        self.manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, request| {
                Self::manual_approval_request_retained_with_cutoffs(request, &cutoffs)
            });
        Ok(())
    }

    fn spend_log_retention_start(now: OffsetDateTime) -> OffsetDateTime {
        now - SPEND_LOG_RETENTION
    }

    fn prune_spend_log(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        let retention_start = Self::spend_log_retention_start(now);
        self.spend_log
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|event| {
                Self::spend_event_is_within_retention_window(event, retention_start, now)
            });
        Ok(())
    }

    fn prune_empty_nonce_heads(&self) -> Result<(), DaemonError> {
        let mut nonce_heads = self
            .nonce_heads
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let mut reusable_nonce_gaps = self
            .reusable_nonce_gaps
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        Self::prune_empty_nonce_heads_map(&mut nonce_heads, &mut reusable_nonce_gaps);
        Ok(())
    }

    fn prune_empty_nonce_heads_map(
        nonce_heads: &mut HashMap<Uuid, HashMap<u64, u64>>,
        reusable_nonce_gaps: &mut ReusableNonceGaps,
    ) {
        nonce_heads.retain(|vault_key_id, chain_heads| {
            chain_heads.retain(|chain_id, head| {
                let keep = *head > 0;
                if !keep {
                    if let Some(chain_map) = reusable_nonce_gaps.get_mut(vault_key_id) {
                        chain_map.remove(chain_id);
                    }
                }
                keep
            });
            !chain_heads.is_empty()
        });
        reusable_nonce_gaps.retain(|vault_key_id, chain_gaps| {
            let Some(chain_heads) = nonce_heads.get(vault_key_id) else {
                return false;
            };
            chain_gaps.retain(|chain_id, gaps| chain_heads.contains_key(chain_id) && !gaps.is_empty());
            !chain_gaps.is_empty()
        });
    }
    fn reclaim_unused_nonce_heads(&self, removed: &[NonceReservation]) -> Result<(), DaemonError> {
        if removed.is_empty() {
            return self.prune_empty_nonce_heads();
        }

        let mut nonce_heads = self
            .nonce_heads
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let mut reusable_nonce_gaps = self
            .reusable_nonce_gaps
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        Self::reclaim_unused_nonce_heads_map(&mut nonce_heads, &mut reusable_nonce_gaps, removed);
        Ok(())
    }

    fn reclaim_unused_nonce_heads_map(
        nonce_heads: &mut HashMap<Uuid, HashMap<u64, u64>>,
        reusable_nonce_gaps: &mut ReusableNonceGaps,
        removed: &[NonceReservation],
    ) {
        let mut removed_by_scope = HashMap::<(Uuid, u64), std::collections::BTreeSet<u64>>::new();
        for reservation in removed {
            removed_by_scope
                .entry((reservation.vault_key_id, reservation.chain_id))
                .or_default()
                .insert(reservation.nonce);
        }

        for ((vault_key_id, chain_id), removed_nonces) in removed_by_scope {
            let Some(chain_heads) = nonce_heads.get_mut(&vault_key_id) else {
                continue;
            };
            let Some(head) = chain_heads.get_mut(&chain_id) else {
                continue;
            };
            let chain_gaps = reusable_nonce_gaps
                .entry(vault_key_id)
                .or_default()
                .entry(chain_id)
                .or_default();

            chain_gaps.extend(removed_nonces.into_iter().filter(|nonce| *nonce < *head));

            while *head > 0 {
                let candidate = *head - 1;
                if chain_gaps.remove(&candidate) {
                    *head = candidate;
                } else {
                    break;
                }
            }
        }
        Self::prune_empty_nonce_heads_map(nonce_heads, reusable_nonce_gaps);
    }

    fn scrub_persisted_ephemeral_state(
        config: &DaemonConfig,
        state: &mut PersistedDaemonState,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        state.leases.retain(|_, lease| lease.is_valid_at(now));
        state.replay_ids.retain(|_, expires_at| *expires_at > now);

        let removed_reservations = state
            .nonce_reservations
            .values()
            .filter(|reservation| reservation.expires_at <= now)
            .cloned()
            .collect::<Vec<_>>();
        state
            .nonce_reservations
            .retain(|_, reservation| reservation.expires_at > now);
        Self::reclaim_unused_nonce_heads_map(
            &mut state.nonce_heads,
            &mut state.reusable_nonce_gaps,
            &removed_reservations,
        );

        let retention_start = Self::spend_log_retention_start(now);
        state.spend_log.retain(|event| {
            Self::spend_event_is_within_retention_window(event, retention_start, now)
        });

        let cutoffs = Self::manual_approval_retention_cutoffs_for_config(config, now)?;
        state.manual_approval_requests.retain(|_, request| {
            Self::manual_approval_request_retained_with_cutoffs(request, &cutoffs)
        });
        Ok(())
    }

    fn scrub_ephemeral_state(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.prune_leases(now)?;
        self.prune_replay_ids(now)?;
        self.prune_nonce_reservations(now)?;
        self.prune_spend_log(now)?;
        self.prune_manual_approval_requests(now)?;
        self.prune_empty_nonce_heads()?;
        Ok(())
    }

    fn ensure_nonce_head_capacity<'a>(
        &self,
        nonce_heads: &'a mut HashMap<Uuid, HashMap<u64, u64>>,
        vault_key_id: Uuid,
        chain_id: u64,
        initial_head: u64,
    ) -> Result<&'a mut u64, DaemonError> {
        let max_tracked = self.config.max_tracked_nonce_chains_per_vault;
        let chain_heads = nonce_heads.entry(vault_key_id).or_default();
        if !chain_heads.contains_key(&chain_id) && chain_heads.len() >= max_tracked {
            return Err(DaemonError::InvalidNonceReservation(format!(
                "vault key {} already tracks the maximum {} nonce head chains",
                vault_key_id, max_tracked
            )));
        }
        Ok(chain_heads.entry(chain_id).or_insert(initial_head))
    }

    fn consume_nonce_reservation(
        &self,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        chain_id: u64,
        nonce: u64,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_nonce_reservations(now)?;
        let mut reservations = self
            .nonce_reservations
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let reservation_id = reservations
            .iter()
            .find_map(|(reservation_id, reservation)| {
                if reservation.agent_key_id == agent_key_id
                    && reservation.vault_key_id == vault_key_id
                    && reservation.chain_id == chain_id
                    && reservation.nonce == nonce
                {
                    Some(*reservation_id)
                } else {
                    None
                }
            })
            .ok_or(DaemonError::MissingNonceReservation { chain_id, nonce })?;
        reservations.remove(&reservation_id);
        Ok(())
    }

    fn spend_event_is_within_retention_window(
        event: &SpendEvent,
        retention_start: OffsetDateTime,
        now: OffsetDateTime,
    ) -> bool {
        event.at >= retention_start && event.at <= now
    }
    fn ensure_nonce_reservation(
        &self,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        chain_id: u64,
        nonce: u64,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_nonce_reservations(now)?;
        let reservations = self
            .nonce_reservations
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let _ = reservations
            .values()
            .find(|reservation| {
                reservation.agent_key_id == agent_key_id
                    && reservation.vault_key_id == vault_key_id
                    && reservation.chain_id == chain_id
                    && reservation.nonce == nonce
            })
            .ok_or(DaemonError::MissingNonceReservation { chain_id, nonce })?;
        Ok(())
    }

    fn resolve_manual_approval_request(
        &self,
        agent_key: &AgentKey,
        payload_action: &AgentAction,
        payload_hash: &str,
        triggered_by_policy_ids: Vec<Uuid>,
        now: OffsetDateTime,
    ) -> Result<ManualApprovalResolution, DaemonError> {
        let relay_config = self
            .relay_config
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        self.prune_manual_approval_requests(now)?;
        let mut requests = self
            .manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;

        let existing = requests
            .values()
            .filter(|existing| {
                existing.agent_key_id == agent_key.id
                    && existing.request_payload_hash_hex == payload_hash
                    && Self::manual_approval_policy_ids_match(
                        &existing.triggered_by_policy_ids,
                        &triggered_by_policy_ids,
                    )
                    && matches!(
                        existing.status,
                        ManualApprovalStatus::Pending
                            | ManualApprovalStatus::Approved
                            | ManualApprovalStatus::Rejected
                    )
            })
            .max_by(|left, right| left.created_at.cmp(&right.created_at))
            .cloned();

        if let Some(existing) = existing {
            return Ok(match existing.status {
                ManualApprovalStatus::Approved => {
                    ManualApprovalResolution::Approved(Some(existing.id))
                }
                ManualApprovalStatus::Pending => ManualApprovalResolution::Pending {
                    approval_request_id: existing.id,
                    relay_config,
                },
                ManualApprovalStatus::Rejected => ManualApprovalResolution::Rejected(existing.id),
                ManualApprovalStatus::Completed => {
                    unreachable!("manual approval reuse filter must exclude completed requests")
                }
            });
        }

        let approval_request_id = Uuid::new_v4();
        requests.insert(
            approval_request_id,
            ManualApprovalRequest {
                id: approval_request_id,
                agent_key_id: agent_key.id,
                vault_key_id: agent_key.vault_key_id,
                request_payload_hash_hex: payload_hash.to_string(),
                action: payload_action.clone(),
                chain_id: payload_action.chain_id(),
                asset: payload_action.asset(),
                recipient: payload_action.recipient(),
                amount_wei: payload_action.amount_wei(),
                created_at: now,
                updated_at: now,
                status: ManualApprovalStatus::Pending,
                triggered_by_policy_ids,
                completed_at: None,
                rejection_reason: None,
            },
        );

        Ok(ManualApprovalResolution::Pending {
            approval_request_id,
            relay_config,
        })
    }

    fn manual_approval_policy_ids_match(left: &[Uuid], right: &[Uuid]) -> bool {
        if left.len() != right.len() {
            return false;
        }

        left.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == right
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
    }

    fn complete_manual_approval_request(
        &self,
        approval_request_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        let mut requests = self
            .manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let request = requests.get_mut(&approval_request_id).ok_or(
            DaemonError::UnknownManualApprovalRequest(approval_request_id),
        )?;
        request.status = ManualApprovalStatus::Completed;
        request.updated_at = now;
        request.completed_at = Some(now);
        Ok(())
    }

    pub fn relay_registration_snapshot(&self) -> Result<RelayRegistrationSnapshot, DaemonError> {
        let now = OffsetDateTime::now_utc();
        let relay_config = self
            .relay_config
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        let policies = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let agent_keys = self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let manual_approval_requests = self.retained_manual_approval_requests_at(now)?;
        let latest_vault_key = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .filter(|key| key.algorithm == KeyAlgorithm::Secp256k1)
            .cloned()
            .max_by(|left, right| left.created_at.cmp(&right.created_at));
        let vault_public_key_hex = latest_vault_key
            .as_ref()
            .map(|key| key.public_key_hex.clone());
        let ethereum_address = latest_vault_key
            .as_ref()
            .map(|key| ethereum_address_from_public_key_hex(&key.public_key_hex))
            .transpose()?;

        Ok(RelayRegistrationSnapshot {
            relay_config,
            relay_private_key_hex: self
                .relay_private_key_hex
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            vault_public_key_hex,
            ethereum_address,
            policies,
            agent_keys,
            manual_approval_requests,
        })
    }

    pub async fn apply_relay_manual_approval_decision(
        &self,
        vault_password: &str,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        let lease = self.issue_lease(vault_password).await?;
        let session = AdminSession {
            vault_password: vault_password.to_string(),
            lease,
        };
        self.decide_manual_approval_request(
            &session,
            approval_request_id,
            decision,
            rejection_reason,
        )
        .await
    }

    pub fn decrypt_relay_envelope(
        &self,
        algorithm: &str,
        encapsulated_key_hex: &str,
        nonce_hex: &str,
        ciphertext_hex: &str,
    ) -> Result<Vec<u8>, DaemonError> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

        if algorithm.trim() != "x25519-xchacha20poly1305-v1" {
            return Err(DaemonError::InvalidRelayConfig(format!(
                "unsupported relay encryption algorithm: {algorithm}"
            )));
        }

        let private_key_hex = self
            .relay_private_key_hex
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        let encapsulated_key = hex::decode(encapsulated_key_hex.trim().trim_start_matches("0x"))
            .map_err(|err| {
                DaemonError::InvalidRelayConfig(format!(
                    "relay encapsulated key is invalid hex: {err}"
                ))
            })?;
        if encapsulated_key.len() != 32 {
            return Err(DaemonError::InvalidRelayConfig(
                "relay encapsulated key must be 32 bytes".to_string(),
            ));
        }
        let nonce = hex::decode(nonce_hex.trim().trim_start_matches("0x")).map_err(|err| {
            DaemonError::InvalidRelayConfig(format!("relay nonce is invalid hex: {err}"))
        })?;
        if nonce.len() != 24 {
            return Err(DaemonError::InvalidRelayConfig(
                "relay nonce must be 24 bytes".to_string(),
            ));
        }
        let ciphertext =
            hex::decode(ciphertext_hex.trim().trim_start_matches("0x")).map_err(|err| {
                DaemonError::InvalidRelayConfig(format!("relay ciphertext is invalid hex: {err}"))
            })?;

        let mut peer_public = [0u8; 32];
        peer_public.copy_from_slice(&encapsulated_key);
        let secret = relay_static_secret_from_hex(&private_key_hex, "relay private key")
            .map_err(DaemonError::InvalidRelayConfig)?;
        let peer = x25519_dalek::PublicKey::from(peer_public);
        let shared_secret = secret.diffie_hellman(&peer);
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());

        cipher
            .decrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                ciphertext.as_ref(),
            )
            .map_err(|_| {
                DaemonError::InvalidRelayConfig(
                    "failed to decrypt relay update payload".to_string(),
                )
            })
    }

    fn snapshot_state(&self) -> Result<PersistedDaemonState, DaemonError> {
        let leases = self
            .leases
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        let policies = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        let vault_keys = self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        let vault_key_ids = vault_keys.keys().copied().collect::<Vec<_>>();
        let software_signer_private_keys = self
            .signer_backend
            .export_persistable_key_material(&vault_key_ids)
            .map_err(DaemonError::Signer)?;

        Ok(PersistedDaemonState {
            leases,
            policies,
            vault_keys,
            software_signer_private_keys,
            agent_keys: self
                .agent_keys
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            agent_auth_tokens: self
                .agent_auth_tokens
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            replay_ids: self
                .replay_ids
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            nonce_heads: self
                .nonce_heads
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            reusable_nonce_gaps: self
                .reusable_nonce_gaps
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            nonce_reservations: self
                .nonce_reservations
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            recoverable_agent_results: self
                .recoverable_agent_results
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            spend_log: self
                .spend_log
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            manual_approval_requests: self
                .manual_approval_requests
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            relay_config: self
                .relay_config
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            relay_private_key_hex: self
                .relay_private_key_hex
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
        })
    }

    fn restore_state(&self, snapshot: PersistedDaemonState) -> Result<(), DaemonError> {
        let PersistedDaemonState {
            leases,
            policies,
            vault_keys,
            software_signer_private_keys,
            agent_keys,
            agent_auth_tokens,
            replay_ids,
            nonce_heads,
            reusable_nonce_gaps,
            nonce_reservations,
            recoverable_agent_results,
            spend_log,
            manual_approval_requests,
            relay_config,
            relay_private_key_hex,
        } = snapshot;
        self.signer_backend
            .restore_persistable_key_material(&software_signer_private_keys)
            .map_err(DaemonError::Signer)?;
        *self.leases.write().map_err(|_| DaemonError::LockPoisoned)? = leases;
        *self
            .policies
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = policies;
        *self
            .vault_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = vault_keys;
        *self
            .agent_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = agent_keys;
        *self
            .agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = agent_auth_tokens;
        *self
            .replay_ids
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = replay_ids;
        *self
            .nonce_heads
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = nonce_heads;
        *self
            .reusable_nonce_gaps
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = reusable_nonce_gaps;
        *self
            .nonce_reservations
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = nonce_reservations;
        *self
            .recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = recoverable_agent_results;
        *self
            .spend_log
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = spend_log;
        *self
            .manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = manual_approval_requests;
        *self
            .relay_config
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = relay_config;
        *self
            .relay_private_key_hex
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = relay_private_key_hex;
        Ok(())
    }

    fn backup_state_if_persistent(&self) -> Result<Option<PersistedDaemonState>, DaemonError> {
        if self.state_store.is_none() {
            return Ok(None);
        }
        Ok(Some(self.snapshot_state()?))
    }

    fn persist_state_if_enabled(&self) -> Result<(), DaemonError> {
        let Some(store) = &self.state_store else {
            return Ok(());
        };
        self.scrub_ephemeral_state(OffsetDateTime::now_utc())?;
        let snapshot = self.snapshot_state()?;
        store.save(&snapshot).map_err(DaemonError::Persistence)
    }

    fn persist_or_revert(&self, backup: Option<PersistedDaemonState>) -> Result<(), DaemonError> {
        match self.persist_state_if_enabled() {
            Ok(()) => Ok(()),
            Err(err) => {
                if let Some(snapshot) = backup {
                    self.restore_state(snapshot)?;
                }
                Err(err)
            }
        }
    }

    fn persist_signed_state_best_effort(
        &self,
        request: &SignRequest,
        signature: &Signature,
        now: OffsetDateTime,
    ) {
        // Once a signature has been produced, replay / nonce / spend state must remain live
        // even if the encrypted state file cannot be updated immediately.
        let _ = self.record_recoverable_signature(request, signature, now);
        let _ = self.persist_state_if_enabled();
    }

    async fn sign_typed_data_action(
        &self,
        vault_key: &VaultKey,
        action: &AgentAction,
    ) -> Result<Signature, DaemonError> {
        let digest = action
            .signing_hash()
            .map_err(map_domain_to_signer_error)?
            .ok_or_else(|| {
                DaemonError::Signer(SignerError::Unsupported(
                    "action does not produce an eip-712 signing digest".to_string(),
                ))
            })?;
        self.sign_digest_with_recovery(vault_key, digest, "typed-data signing")
            .await
    }

    async fn sign_digest_with_recovery(
        &self,
        vault_key: &VaultKey,
        digest_bytes: [u8; 32],
        operation: &str,
    ) -> Result<Signature, DaemonError> {
        let der_signature = self
            .signer_backend
            .sign_digest(vault_key.id, digest_bytes)
            .await?;

        let parsed = K256Signature::from_der(&der_signature.bytes).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "backend returned invalid DER signature for {operation}: {err}"
            )))
        })?;
        let parsed = parsed.normalize_s().unwrap_or(parsed);
        let verifying_key = parse_verifying_key(&vault_key.public_key_hex)?;
        let recovery_id =
            RecoveryId::trial_recovery_from_prehash(&verifying_key, &digest_bytes, &parsed)
                .map_err(|err| {
                    DaemonError::Signer(SignerError::Internal(format!(
                        "unable to derive signature recovery id for {operation}: {err}"
                    )))
                })?;

        let mut compact = [0u8; 64];
        compact.copy_from_slice(&parsed.to_bytes());
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&compact[..32]);
        s.copy_from_slice(&compact[32..]);
        let v = u8::from(recovery_id);

        Ok(Signature {
            bytes: parsed.to_der().as_bytes().to_vec(),
            signature_base58: None,
            r_hex: Some(format!("0x{}", hex::encode(r))),
            s_hex: Some(format!("0x{}", hex::encode(s))),
            v: Some(u64::from(v)),
            raw_tx_hex: None,
            tx_hash_hex: None,
            raw_tx_base64: None,
            tx_id: None,
        })
    }

    async fn sign_broadcast_eip1559(
        &self,
        vault_key: &VaultKey,
        tx: &vault_domain::BroadcastTx,
    ) -> Result<Signature, DaemonError> {
        let signing_message = tx
            .eip1559_signing_message()
            .map_err(map_domain_to_signer_error)?;
        let digest_bytes = alloy_primitives::keccak256(&signing_message).0;

        let mut signature = self
            .sign_digest_with_recovery(vault_key, digest_bytes, "tx signing")
            .await?;

        let r_hex = signature.r_hex.clone().ok_or_else(|| {
            DaemonError::Signer(SignerError::Internal("missing tx r value".to_string()))
        })?;
        let s_hex = signature.s_hex.clone().ok_or_else(|| {
            DaemonError::Signer(SignerError::Internal("missing tx s value".to_string()))
        })?;
        let v = signature.v.ok_or_else(|| {
            DaemonError::Signer(SignerError::Internal("missing tx recovery id".to_string()))
        })? as u8;

        let r_bytes = hex::decode(r_hex.trim_start_matches("0x")).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to decode tx r value: {err}"
            )))
        })?;
        let s_bytes = hex::decode(s_hex.trim_start_matches("0x")).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to decode tx s value: {err}"
            )))
        })?;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        let raw_tx = tx
            .eip1559_signed_raw_transaction(v, r, s)
            .map_err(map_domain_to_signer_error)?;
        let tx_hash = alloy_primitives::keccak256(&raw_tx);
        signature.raw_tx_hex = Some(format!("0x{}", hex::encode(raw_tx)));
        signature.tx_hash_hex = Some(format!("0x{}", hex::encode(tx_hash)));
        Ok(signature)
    }

    async fn sign_solana_spl_transfer(
        &self,
        vault_key: &VaultKey,
        transfer: &vault_domain::SolanaSplTransfer,
    ) -> Result<Signature, DaemonError> {
        let fee_payer = decode_solana_pubkey(&transfer.fee_payer)?;
        let mint = decode_solana_pubkey(&transfer.mint)?;
        let recipient_owner = decode_solana_pubkey(&transfer.recipient_owner)?;
        let signer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        if fee_payer != signer_pubkey {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana fee payer must match the vault-derived Solana wallet key".to_string(),
            )));
        }

        let recent_blockhash = transfer
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| map_domain_to_signer_error(vault_domain::DomainError::InvalidSolanaRecentBlockhash))?;
        let amount = u64::try_from(transfer.amount_wei)
            .map_err(|_| map_domain_to_signer_error(vault_domain::DomainError::AmountOutOfRange))?;
        let transfer_fee = transfer
            .transfer_fee_wei
            .map(u64::try_from)
            .transpose()
            .map_err(|_| map_domain_to_signer_error(vault_domain::DomainError::AmountOutOfRange))?;
        let token_program_id = solana_token_program_id(transfer.token_program);

        let source_ata = spl_associated_token_account::get_associated_token_address_with_program_id(
            &fee_payer,
            &mint,
            &token_program_id,
        );
        let destination_ata =
            spl_associated_token_account::get_associated_token_address_with_program_id(
                &recipient_owner,
                &mint,
                &token_program_id,
            );

        let mut instructions = Vec::with_capacity(4);
        if let Some(nonce_account) = &transfer.durable_nonce_account {
            let nonce_account = decode_solana_pubkey(nonce_account)?;
            instructions.push(solana_advance_nonce_account_instruction(
                &nonce_account,
                &fee_payer,
            ));
        }
        if let Some(limit) = transfer.compute_unit_limit {
            instructions.push(set_solana_compute_unit_limit_instruction(limit));
        }
        if let Some(price) = transfer.compute_unit_price_micro_lamports {
            instructions.push(set_solana_compute_unit_price_instruction(price));
        }
        instructions.push(build_solana_token_transfer_instruction(
            token_program_id,
            &source_ata,
            &mint,
            &destination_ata,
            &fee_payer,
            amount,
            transfer.decimals,
            transfer_fee,
        )?);

        self.sign_solana_instructions(vault_key, fee_payer, recent_blockhash, instructions)
            .await
    }

    async fn sign_solana_sol_transfer(
        &self,
        vault_key: &VaultKey,
        transfer: &vault_domain::SolanaSolTransfer,
    ) -> Result<Signature, DaemonError> {
        let fee_payer = decode_solana_pubkey(&transfer.fee_payer)?;
        let to = decode_solana_pubkey(&transfer.to)?;
        let signer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        if fee_payer != signer_pubkey {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana fee payer must match the vault-derived Solana wallet key".to_string(),
            )));
        }

        let recent_blockhash = transfer
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| map_domain_to_signer_error(vault_domain::DomainError::InvalidSolanaRecentBlockhash))?;
        let lamports = u64::try_from(transfer.amount_wei)
            .map_err(|_| map_domain_to_signer_error(vault_domain::DomainError::AmountOutOfRange))?;

        let mut instructions = Vec::with_capacity(4);
        if let Some(nonce_account) = &transfer.durable_nonce_account {
            let nonce_account = decode_solana_pubkey(nonce_account)?;
            instructions.push(solana_advance_nonce_account_instruction(
                &nonce_account,
                &fee_payer,
            ));
        }
        if let Some(limit) = transfer.compute_unit_limit {
            instructions.push(set_solana_compute_unit_limit_instruction(limit));
        }
        if let Some(price) = transfer.compute_unit_price_micro_lamports {
            instructions.push(set_solana_compute_unit_price_instruction(price));
        }
        instructions.push(solana_system_transfer_instruction(&fee_payer, &to, lamports));

        self.sign_solana_instructions(vault_key, fee_payer, recent_blockhash, instructions)
            .await
    }

    async fn sign_solana_nonce_account_create(
        &self,
        vault_key: &VaultKey,
        create: &vault_domain::SolanaNonceAccountCreate,
    ) -> Result<Signature, DaemonError> {
        let fee_payer = decode_solana_pubkey(&create.fee_payer)?;
        let nonce_account = decode_solana_pubkey(&create.nonce_account)?;
        let signer_pubkey = solana_sdk::pubkey::Pubkey::new_from_array(decode_public_key_hex_32(
            &self
                .signer_backend
                .solana_public_key_hex(vault_key.id)
                .map_err(DaemonError::Signer)?,
        )?);
        if fee_payer != signer_pubkey {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana fee payer must match the vault-derived Solana wallet key".to_string(),
            )));
        }

        let derived_nonce_account = solana_sdk::pubkey::Pubkey::create_with_seed(
            &fee_payer,
            &create.seed,
            &solana_system_program_id(),
        )
        .map_err(|err| {
            DaemonError::Signer(SignerError::Unsupported(format!(
                "invalid solana nonce account seed: {err}"
            )))
        })?;
        if nonce_account != derived_nonce_account {
            return Err(DaemonError::Signer(SignerError::Unsupported(
                "solana nonce account must be derived from the fee payer and seed".to_string(),
            )));
        }

        let recent_blockhash = create
            .recent_blockhash
            .parse::<solana_sdk::hash::Hash>()
            .map_err(|_| {
                map_domain_to_signer_error(vault_domain::DomainError::InvalidSolanaRecentBlockhash)
            })?;
        let rent_lamports = u64::try_from(create.rent_lamports)
            .map_err(|_| map_domain_to_signer_error(vault_domain::DomainError::AmountOutOfRange))?;
        let instructions = solana_create_nonce_account_with_seed_instructions(
            &fee_payer,
            &nonce_account,
            &create.seed,
            rent_lamports,
        );

        self.sign_solana_instructions(vault_key, fee_payer, recent_blockhash, instructions)
            .await
    }

    async fn sign_solana_instructions(
        &self,
        vault_key: &VaultKey,
        fee_payer: solana_sdk::pubkey::Pubkey,
        recent_blockhash: solana_sdk::hash::Hash,
        instructions: Vec<solana_sdk::instruction::Instruction>,
    ) -> Result<Signature, DaemonError> {
        let message = solana_sdk::message::Message::new_with_blockhash(
            &instructions,
            Some(&fee_payer),
            &recent_blockhash,
        );
        let signed = self
            .signer_backend
            .sign_solana_payload(vault_key.id, &message.serialize())
            .await?;
        let signature_bytes = <[u8; 64]>::try_from(signed.bytes.as_slice()).map_err(|_| {
            DaemonError::Signer(SignerError::Internal(
                "ed25519 backend returned invalid signature length".to_string(),
            ))
        })?;
        let tx_signature = solana_sdk::signature::Signature::from(signature_bytes);
        let transaction = solana_sdk::transaction::Transaction {
            signatures: vec![tx_signature],
            message,
        };
        let raw_tx = bincode::serialize(&transaction).map_err(|err| {
            DaemonError::Signer(SignerError::Internal(format!(
                "failed to serialize signed solana transaction: {err}"
            )))
        })?;
        let tx_id = tx_signature.to_string();

        Ok(Signature {
            bytes: signature_bytes.to_vec(),
            signature_base58: Some(tx_id.clone()),
            r_hex: None,
            s_hex: None,
            v: None,
            raw_tx_hex: None,
            tx_hash_hex: None,
            raw_tx_base64: Some(
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw_tx),
            ),
            tx_id: Some(tx_id),
        })
    }
}

const DEFAULT_RELAY_URL: &str = "http://localhost:8787";

fn relay_static_secret_from_hex(
    private_key_hex: &str,
    label: &str,
) -> Result<x25519_dalek::StaticSecret, String> {
    let private_key_bytes = Zeroizing::new(
        hex::decode(private_key_hex.trim().trim_start_matches("0x"))
            .map_err(|err| format!("{label} is invalid hex: {err}"))?,
    );
    if private_key_bytes.len() != 32 {
        return Err(format!("{label} must be 32 bytes"));
    }
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(private_key_bytes.as_slice());
    Ok(x25519_dalek::StaticSecret::from(std::mem::take(
        &mut *private_key,
    )))
}

fn decode_public_key_hex_32(public_key_hex: &str) -> Result<[u8; 32], DaemonError> {
    let bytes =
        hex::decode(public_key_hex.trim().trim_start_matches("0x")).map_err(|_| {
            DaemonError::Signer(SignerError::Internal(
                "Solana public key is not valid hex".to_string(),
            ))
        })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        DaemonError::Signer(SignerError::Internal(
            "Solana public key is not a 32-byte ed25519 key".to_string(),
        ))
    })
}

fn decode_solana_pubkey(address: &vault_domain::SolanaAddress) -> Result<solana_sdk::pubkey::Pubkey, DaemonError> {
    address
        .to_bytes()
        .map(solana_sdk::pubkey::Pubkey::new_from_array)
        .map_err(map_domain_to_signer_error)
}

fn solana_token_program_id(
    token_program: vault_domain::SolanaTokenProgram,
) -> solana_sdk::pubkey::Pubkey {
    match token_program {
        vault_domain::SolanaTokenProgram::Token => spl_token::ID,
        vault_domain::SolanaTokenProgram::Token2022 => spl_token_2022_interface::id(),
    }
}

fn build_solana_token_transfer_instruction(
    token_program_id: solana_sdk::pubkey::Pubkey,
    source_ata: &solana_sdk::pubkey::Pubkey,
    mint: &solana_sdk::pubkey::Pubkey,
    destination_ata: &solana_sdk::pubkey::Pubkey,
    fee_payer: &solana_sdk::pubkey::Pubkey,
    amount: u64,
    decimals: u8,
    transfer_fee: Option<u64>,
) -> Result<solana_sdk::instruction::Instruction, DaemonError> {
    if let Some(fee) = transfer_fee {
        return spl_token_2022_interface::extension::transfer_fee::instruction::transfer_checked_with_fee(
            &token_program_id,
            source_ata,
            mint,
            destination_ata,
            fee_payer,
            &[],
            amount,
            decimals,
            fee,
        )
        .map_err(|err| {
            DaemonError::Signer(SignerError::Unsupported(format!(
                "failed to build Token-2022 transfer-with-fee instruction: {err}"
            )))
        });
    }

    spl_token_2022_interface::instruction::transfer_checked(
        &token_program_id,
        source_ata,
        mint,
        destination_ata,
        fee_payer,
        &[],
        amount,
        decimals,
    )
    .map_err(|err| {
        DaemonError::Signer(SignerError::Unsupported(format!(
            "failed to build spl transfer instruction: {err}"
        )))
    })
}

fn solana_system_transfer_instruction(
    from: &solana_sdk::pubkey::Pubkey,
    to: &solana_sdk::pubkey::Pubkey,
    lamports: u64,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: "11111111111111111111111111111111"
            .parse()
            .expect("static system program id"),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*from, true),
            solana_sdk::instruction::AccountMeta::new(*to, false),
        ],
        data,
    }
}

fn solana_system_program_id() -> solana_sdk::pubkey::Pubkey {
    "11111111111111111111111111111111"
        .parse()
        .expect("static system program id")
}

fn solana_recent_blockhashes_sysvar_id() -> solana_sdk::pubkey::Pubkey {
    "SysvarRecentB1ockHashes11111111111111111111"
        .parse()
        .expect("static recent blockhashes sysvar id")
}

fn solana_rent_sysvar_id() -> solana_sdk::pubkey::Pubkey {
    "SysvarRent111111111111111111111111111111111"
        .parse()
        .expect("static rent sysvar id")
}

fn solana_create_account_with_seed_instruction(
    from: &solana_sdk::pubkey::Pubkey,
    new_account: &solana_sdk::pubkey::Pubkey,
    seed: &str,
    lamports: u64,
    space: u64,
    owner: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(4 + 32 + 8 + seed.len() + 8 + 8 + 32);
    data.extend_from_slice(&3u32.to_le_bytes());
    data.extend_from_slice(from.as_ref());
    data.extend_from_slice(&(seed.len() as u64).to_le_bytes());
    data.extend_from_slice(seed.as_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    solana_sdk::instruction::Instruction {
        program_id: solana_system_program_id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*from, true),
            solana_sdk::instruction::AccountMeta::new(*new_account, false),
        ],
        data,
    }
}

fn solana_initialize_nonce_account_instruction(
    nonce_account: &solana_sdk::pubkey::Pubkey,
    nonce_authority: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&6u32.to_le_bytes());
    data.extend_from_slice(nonce_authority.as_ref());
    solana_sdk::instruction::Instruction {
        program_id: solana_system_program_id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*nonce_account, false),
            solana_sdk::instruction::AccountMeta::new_readonly(
                solana_recent_blockhashes_sysvar_id(),
                false,
            ),
            solana_sdk::instruction::AccountMeta::new_readonly(solana_rent_sysvar_id(), false),
        ],
        data,
    }
}

fn solana_create_nonce_account_with_seed_instructions(
    fee_payer: &solana_sdk::pubkey::Pubkey,
    nonce_account: &solana_sdk::pubkey::Pubkey,
    seed: &str,
    rent_lamports: u64,
) -> Vec<solana_sdk::instruction::Instruction> {
    vec![
        solana_create_account_with_seed_instruction(
            fee_payer,
            nonce_account,
            seed,
            rent_lamports,
            80,
            &solana_system_program_id(),
        ),
        solana_initialize_nonce_account_instruction(nonce_account, fee_payer),
    ]
}

fn solana_advance_nonce_account_instruction(
    nonce_account: &solana_sdk::pubkey::Pubkey,
    nonce_authority: &solana_sdk::pubkey::Pubkey,
) -> solana_sdk::instruction::Instruction {
    let mut data = Vec::with_capacity(4);
    data.extend_from_slice(&4u32.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: solana_system_program_id(),
        accounts: vec![
            solana_sdk::instruction::AccountMeta::new(*nonce_account, false),
            solana_sdk::instruction::AccountMeta::new_readonly(
                solana_recent_blockhashes_sysvar_id(),
                false,
            ),
            solana_sdk::instruction::AccountMeta::new_readonly(*nonce_authority, true),
        ],
        data,
    }
}

fn set_solana_compute_unit_limit_instruction(limit: u32) -> solana_sdk::instruction::Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: "ComputeBudget111111111111111111111111111111"
            .parse()
            .expect("static compute budget program id"),
        accounts: vec![],
        data,
    }
}

fn set_solana_compute_unit_price_instruction(
    price: u64,
) -> solana_sdk::instruction::Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&price.to_le_bytes());
    solana_sdk::instruction::Instruction {
        program_id: "ComputeBudget111111111111111111111111111111"
            .parse()
            .expect("static compute budget program id"),
        accounts: vec![],
        data,
    }
}

fn ensure_relay_identity(state: &mut PersistedDaemonState) {
    if state.relay_private_key_hex.trim().is_empty() {
        let private_bytes = Zeroizing::new(rand::random::<[u8; 32]>());
        state.relay_private_key_hex = Zeroizing::new(hex::encode(&*private_bytes));
    }
    if state
        .relay_config
        .relay_url
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        state.relay_config.relay_url = Some(DEFAULT_RELAY_URL.to_string());
    }
    if state.relay_config.daemon_id_hex.trim().is_empty() {
        state.relay_config.daemon_id_hex = hex::encode(rand::random::<[u8; 32]>());
    }
    if state.relay_config.daemon_public_key_hex.trim().is_empty() {
        if let Ok(secret) =
            relay_static_secret_from_hex(&state.relay_private_key_hex, "relay private key")
        {
            let public = x25519_dalek::PublicKey::from(&secret);
            state.relay_config.daemon_public_key_hex = hex::encode(public.as_bytes());
        }
    }
}

fn ethereum_address_from_public_key_hex(public_key_hex: &str) -> Result<String, DaemonError> {
    let verifying_key = parse_verifying_key(public_key_hex)?;
    let encoded = verifying_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return Err(DaemonError::Signer(SignerError::Internal(
            "vault public key must be an uncompressed secp256k1 SEC1 point".to_string(),
        )));
    }
    let digest = alloy_primitives::keccak256(&public_key[1..]);
    let address = &digest.0[12..];
    Ok(format!("0x{}", hex::encode(address)))
}

fn manual_approval_frontend_url(
    relay_config: &RelayConfig,
    approval_request_id: Uuid,
    approval_capability: &str,
) -> Option<String> {
    relay_config
        .frontend_url
        .as_ref()
        .or(relay_config.relay_url.as_ref())
        .map(|frontend_url| {
            let daemon_id = relay_config.daemon_id_hex.trim();
            if daemon_id.is_empty() {
                format!(
                    "{}/approvals/{approval_request_id}?approvalCapability={approval_capability}",
                    frontend_url.trim_end_matches('/')
                )
            } else {
                format!(
                    "{}/approvals/{approval_request_id}?daemonId={daemon_id}&approvalCapability={approval_capability}",
                    frontend_url.trim_end_matches('/')
                )
            }
        })
}

fn payload_hash_hex(payload: &[u8]) -> String {
    let digest = Sha256::digest(payload);
    hex::encode(digest)
}
