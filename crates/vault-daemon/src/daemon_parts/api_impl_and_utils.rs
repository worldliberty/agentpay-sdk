#[async_trait]
impl<B> KeyManagerDaemonApi for InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    async fn issue_lease(&self, vault_password: &str) -> Result<Lease, DaemonError> {
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        self.authenticate_password(vault_password)?;
        let now = OffsetDateTime::now_utc();
        let expires_at = now.checked_add(self.config.lease_ttl).ok_or_else(|| {
            DaemonError::InvalidConfig("lease_ttl causes timestamp overflow".to_string())
        })?;
        let lease = Lease {
            lease_id: Uuid::new_v4(),
            issued_at: now,
            expires_at,
        };
        {
            let mut leases = self.leases.write().map_err(|_| DaemonError::LockPoisoned)?;
            // Retain only currently valid leases so corrupted/future-dated entries
            // cannot permanently consume capacity.
            leases.retain(|_, existing_lease| existing_lease.is_valid_at(now));
            if leases.len() >= self.config.max_active_leases {
                return Err(DaemonError::TooManyActiveLeases);
            }
            leases.insert(lease.lease_id, lease.clone());
        }
        self.persist_or_revert(backup)?;
        Ok(lease)
    }

    async fn add_policy(
        &self,
        session: &AdminSession,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let now = OffsetDateTime::now_utc();
        self.authenticate(session, now)?;
        validate_policy(&policy)?;
        self.prune_manual_approval_requests(now)?;
        if policy.policy_type != vault_domain::PolicyType::ManualApproval
            && self
                .manual_approval_requests
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .values()
                .any(|request| request.triggered_by_policy_ids.contains(&policy.id))
        {
            self.persist_or_revert(backup)?;
            return Err(DaemonError::InvalidPolicy(format!(
                "policy {} cannot change away from manual approval while retained approval requests still reference it",
                policy.id
            )));
        }

        {
            // Registering a policy must not rewrite existing PolicySet
            // attachments; those remain explicit and admin-controlled.
            let mut policies = self
                .policies
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            if policies.contains_key(&policy.id) {
                return Err(DaemonError::InvalidPolicy(format!(
                    "policy id {} already exists",
                    policy.id
                )));
            }
            policies.insert(policy.id, policy);
        }

        self.persist_or_revert(backup)?;
        Ok(())
    }

    async fn list_policies(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<SpendingPolicy>, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        let mut policies: Vec<SpendingPolicy> = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .cloned()
            .collect();
        policies.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        Ok(policies)
    }

    async fn disable_policy(
        &self,
        session: &AdminSession,
        policy_id: Uuid,
    ) -> Result<(), DaemonError> {
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        self.authenticate(session, OffsetDateTime::now_utc())?;
        {
            let mut policies = self
                .policies
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let policy = policies
                .get_mut(&policy_id)
                .ok_or(DaemonError::UnknownPolicy(policy_id))?;
            policy.enabled = false;
        }
        {
            let mut agent_keys = self
                .agent_keys
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            for agent_key in agent_keys.values_mut() {
                if let PolicyAttachment::PolicySet(policy_ids) = &mut agent_key.policies {
                    // Keep stored attachments aligned with evaluation, which ignores disabled policies.
                    policy_ids.remove(&policy_id);
                }
            }
        }
        self.persist_or_revert(backup)?;
        Ok(())
    }

    async fn create_vault_key(
        &self,
        session: &AdminSession,
        request: KeyCreateRequest,
    ) -> Result<VaultKey, DaemonError> {
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        self.authenticate(session, OffsetDateTime::now_utc())?;

        let vault_key = self.signer_backend.create_vault_key(request).await?;
        if let Err(err) = self
            .vault_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)
            .map(|mut vault_keys| {
                vault_keys.insert(vault_key.id, vault_key.clone());
            })
        {
            if let Err(cleanup_err) = self.signer_backend.delete_vault_key_if_present(vault_key.id) {
                return Err(DaemonError::Signer(SignerError::Internal(format!(
                    "create_vault_key cleanup failed after error `{err}`: {cleanup_err}"
                ))));
            }
            return Err(err);
        }
        if let Err(err) = self.persist_or_revert(backup) {
            if let Err(cleanup_err) = self.signer_backend.delete_vault_key_if_present(vault_key.id) {
                return Err(DaemonError::Signer(SignerError::Internal(format!(
                    "create_vault_key cleanup failed after error `{err}`: {cleanup_err}"
                ))));
            }
            return Err(err);
        }
        Ok(vault_key)
    }

    async fn export_vault_private_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
    ) -> Result<Option<String>, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;

        if !self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .contains_key(&vault_key_id)
        {
            return Err(DaemonError::UnknownVaultKey(vault_key_id));
        }

        let mut exported = self
            .signer_backend
            .export_persistable_key_material(&[vault_key_id])
            .map_err(DaemonError::Signer)?;
        Ok(exported
            .remove(&vault_key_id)
            .map(|mut material| std::mem::take(&mut *material)))
    }

    async fn create_agent_key(
        &self,
        session: &AdminSession,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let now = OffsetDateTime::now_utc();
        self.authenticate(session, now)?;

        if !self
            .vault_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .contains_key(&vault_key_id)
        {
            return Err(DaemonError::UnknownVaultKey(vault_key_id));
        }

        validate_agent_key_attachment(self, &attachment)?;

        let agent_key = AgentKey {
            id: Uuid::new_v4(),
            vault_key_id,
            policies: attachment,
            created_at: now,
        };

        self.agent_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key.id, agent_key.clone());

        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key.id, hash_agent_auth_token(&auth_token));

        self.persist_or_revert(backup)?;
        Ok(AgentCredentials {
            agent_key,
            auth_token: auth_token.into(),
        })
    }

    async fn refresh_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
        vault_key_id: Uuid,
        attachment: PolicyAttachment,
    ) -> Result<AgentCredentials, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        validate_agent_key_attachment(self, &attachment)?;

        let agent_key = {
            let mut agent_keys = self
                .agent_keys
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let agent_key = agent_keys
                .get_mut(&agent_key_id)
                .ok_or(DaemonError::UnknownAgentKey(agent_key_id))?;
            if agent_key.vault_key_id != vault_key_id {
                return Err(DaemonError::InvalidPolicyAttachment(format!(
                    "agent key {agent_key_id} belongs to vault key {} instead of requested vault key {vault_key_id}",
                    agent_key.vault_key_id
                )));
            }
            agent_key.policies = attachment;
            agent_key.clone()
        };

        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key_id, hash_agent_auth_token(&auth_token));
        self.persist_or_revert(backup)?;
        Ok(AgentCredentials {
            agent_key,
            auth_token: auth_token.into(),
        })
    }

    async fn rotate_agent_auth_token(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<String, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        if !self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .contains_key(&agent_key_id)
        {
            return Err(DaemonError::UnknownAgentKey(agent_key_id));
        }

        let auth_token = generate_agent_auth_token();
        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .insert(agent_key_id, hash_agent_auth_token(&auth_token));
        self.persist_or_revert(backup)?;
        Ok(auth_token)
    }

    async fn revoke_agent_key(
        &self,
        session: &AdminSession,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        let _signing_guard = self.signing_guard.lock().await;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let now = OffsetDateTime::now_utc();
        let _ = self.manual_approval_retention_cutoffs(now)?;

        let removed = self
            .agent_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .remove(&agent_key_id)
            .is_some();
        if !removed {
            return Err(DaemonError::UnknownAgentKey(agent_key_id));
        }

        self.agent_auth_tokens
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .remove(&agent_key_id);
        self.spend_log
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|event| event.agent_key_id != agent_key_id);
        let removed_reservations = {
            let mut reservations = self
                .nonce_reservations
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let removed = reservations
                .values()
                .filter(|reservation| reservation.agent_key_id == agent_key_id)
                .cloned()
                .collect::<Vec<_>>();
            reservations.retain(|_, reservation| reservation.agent_key_id != agent_key_id);
            removed
        };
        self.reclaim_unused_nonce_heads(&removed_reservations)?;
        self.manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, request| request.agent_key_id != agent_key_id);
        self.prune_manual_approval_requests(now)?;
        self.recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, result| result.agent_key_id != agent_key_id);
        self.prune_manual_approval_requests(now)?;
        self.persist_or_revert(backup)?;
        Ok(())
    }

    async fn list_manual_approval_requests(
        &self,
        session: &AdminSession,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        let now = OffsetDateTime::now_utc();
        self.authenticate(session, now)?;
        let mut requests = self.retained_manual_approval_requests_at(now)?;
        requests.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(requests)
    }

    async fn decide_manual_approval_request(
        &self,
        session: &AdminSession,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        let now = OffsetDateTime::now_utc();
        let manual_approval_cutoffs = self.manual_approval_retention_cutoffs(now)?;

        let triggered_by_policy_ids = {
            let requests = self
                .manual_approval_requests
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let request = requests.get(&approval_request_id).ok_or(
                DaemonError::UnknownManualApprovalRequest(approval_request_id),
            )?;
            if request.status != ManualApprovalStatus::Pending {
                return Err(DaemonError::ManualApprovalRequestNotPending {
                    approval_request_id,
                    status: request.status,
                });
            }
            request.triggered_by_policy_ids.clone()
        };
        if matches!(decision, ManualApprovalDecision::Approve) {
            let policies = self
                .policies
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?;
            if let Err(err) = validate_manual_approval_policy_references(
                &policies,
                &triggered_by_policy_ids,
                true,
            ) {
                return Err(manual_approval_policy_reference_decision_error(
                    approval_request_id,
                    err,
                ));
            }
        }

        let updated = {
            let mut requests = self
                .manual_approval_requests
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let Some(request) = requests.get_mut(&approval_request_id) else {
                return Err(DaemonError::UnknownManualApprovalRequest(
                    approval_request_id,
                ));
            };
            if !Self::manual_approval_request_retained_with_cutoffs(
                request,
                &manual_approval_cutoffs,
            ) {
                requests.remove(&approval_request_id);
                drop(requests);
                self.persist_or_revert(backup)?;
                return Err(DaemonError::UnknownManualApprovalRequest(
                    approval_request_id,
                ));
            }
            if request.status != ManualApprovalStatus::Pending {
                return Err(DaemonError::ManualApprovalRequestNotPending {
                    approval_request_id,
                    status: request.status,
                });
            }
            request.updated_at = now;
            match decision {
                ManualApprovalDecision::Approve => {
                    request.status = ManualApprovalStatus::Approved;
                    request.rejection_reason = None;
                }
                ManualApprovalDecision::Reject => {
                    request.status = ManualApprovalStatus::Rejected;
                    request.rejection_reason = rejection_reason.and_then(|value| {
                        let trimmed = value.trim().to_string();
                        (!trimmed.is_empty()).then_some(trimmed)
                    });
                }
            }
            request.clone()
        };

        self.prune_manual_approval_requests(now)?;
        self.persist_or_revert(backup)?;
        Ok(updated)
    }

    async fn set_relay_config(
        &self,
        session: &AdminSession,
        relay_url: Option<String>,
        frontend_url: Option<String>,
    ) -> Result<RelayConfig, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;

        let normalized = normalize_optional_url("relay_url", relay_url)?;
        let normalized_frontend = normalize_optional_url("frontend_url", frontend_url)?;
        {
            let mut relay_config = self
                .relay_config
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?;
            relay_config.relay_url = normalized;
            relay_config.frontend_url = normalized_frontend;
        }

        let relay_config = self
            .relay_config
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        self.persist_or_revert(backup)?;
        Ok(relay_config)
    }

    async fn get_relay_config(&self, session: &AdminSession) -> Result<RelayConfig, DaemonError> {
        self.authenticate(session, OffsetDateTime::now_utc())?;
        Ok(self
            .relay_config
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone())
    }

    async fn evaluate_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyEvaluation, DaemonError> {
        let mut request = request;
        let result = {
            let now = OffsetDateTime::now_utc();
            let (_, _, policy_evaluation) = self.evaluate_authorized_request(&request, now)?;
            Ok(policy_evaluation)
        };
        request.zeroize_secrets();
        result
    }

    async fn explain_for_agent(
        &self,
        request: SignRequest,
    ) -> Result<PolicyExplanation, DaemonError> {
        let mut request = request;
        let result = {
            let now = OffsetDateTime::now_utc();
            let (_, _, policy_explanation) = self.explain_authorized_request(&request, now)?;
            Ok(policy_explanation)
        };
        request.zeroize_secrets();
        result
    }

    async fn reserve_nonce(
        &self,
        request: NonceReservationRequest,
    ) -> Result<NonceReservation, DaemonError> {
        let mut request = request;
        let result = async {
            let _signing_guard = self.signing_guard.lock().await;
            let _state_guard = self.state_persist_guard.lock().await;
            let backup = self.backup_state_if_persistent()?;
            let now = OffsetDateTime::now_utc();
            if let Some(reservation) = self.recover_nonce_reservation_if_available(&request, now)? {
                return Ok(reservation);
            }
            self.validate_request_timestamps(request.requested_at, request.expires_at, now)?;
            if request.chain_id == 0 {
                return Err(DaemonError::InvalidNonceReservation(
                    "chain_id must be greater than zero".to_string(),
                ));
            }
            let agent_key =
                self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;
            self.register_replay_id(request.request_id, request.expires_at, now)?;
            self.prune_nonce_reservations(now)?;
            if self
                .nonce_reservations
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .len()
                >= self.config.max_active_nonce_reservations
            {
                return Err(DaemonError::TooManyActiveNonceReservations {
                    max_active: self.config.max_active_nonce_reservations,
                });
            }

            let max_lease_expires = now + self.config.nonce_reservation_ttl;
            let lease_expires = if request.expires_at < max_lease_expires {
                request.expires_at
            } else {
                max_lease_expires
            };
            if lease_expires <= now {
                return Err(DaemonError::InvalidNonceReservation(
                    "nonce reservation would be immediately expired".to_string(),
                ));
            }

            let nonce = if request.exact_nonce {
                {
                    let reservations = self
                        .nonce_reservations
                        .read()
                        .map_err(|_| DaemonError::LockPoisoned)?;
                    if reservations.values().any(|reservation| {
                        reservation.vault_key_id == agent_key.vault_key_id
                            && reservation.chain_id == request.chain_id
                            && reservation.nonce == request.min_nonce
                    }) {
                        return Err(DaemonError::InvalidNonceReservation(format!(
                            "nonce {} is already reserved for chain_id {}",
                            request.min_nonce, request.chain_id
                        )));
                    }
                }

                let next_head = request.min_nonce.checked_add(1).ok_or_else(|| {
                    DaemonError::InvalidNonceReservation("nonce allocation overflow".to_string())
                })?;
                let mut nonce_heads = self
                    .nonce_heads
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?;
                let mut reusable_nonce_gaps = self
                    .reusable_nonce_gaps
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?;
                let head = self.ensure_nonce_head_capacity(
                    &mut nonce_heads,
                    agent_key.vault_key_id,
                    request.chain_id,
                    0,
                )?;
                let chain_gaps = reusable_nonce_gaps
                    .entry(agent_key.vault_key_id)
                    .or_default()
                    .entry(request.chain_id)
                    .or_default();
                if *head < request.min_nonce {
                    chain_gaps.extend(*head..request.min_nonce);
                }
                if *head <= request.min_nonce {
                    *head = next_head;
                }
                chain_gaps.remove(&request.min_nonce);
                request.min_nonce
            } else {
                let mut nonce_heads = self
                    .nonce_heads
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?;
                let mut reusable_nonce_gaps = self
                    .reusable_nonce_gaps
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?;
                let head = self.ensure_nonce_head_capacity(
                    &mut nonce_heads,
                    agent_key.vault_key_id,
                    request.chain_id,
                    0,
                )?;
                let chain_gaps = reusable_nonce_gaps
                    .entry(agent_key.vault_key_id)
                    .or_default()
                    .entry(request.chain_id)
                    .or_default();
                if *head < request.min_nonce {
                    chain_gaps.extend(*head..request.min_nonce);
                    *head = request.min_nonce;
                }
                if let Some(reclaimed_nonce) = chain_gaps.range(request.min_nonce..).next().copied()
                {
                    chain_gaps.remove(&reclaimed_nonce);
                    reclaimed_nonce
                } else {
                    let nonce = *head;
                    *head = head.checked_add(1).ok_or_else(|| {
                        DaemonError::InvalidNonceReservation(
                            "nonce allocation overflow".to_string(),
                        )
                    })?;
                    nonce
                }
            };

            let reservation = NonceReservation {
                reservation_id: Uuid::new_v4(),
                agent_key_id: request.agent_key_id,
                vault_key_id: agent_key.vault_key_id,
                chain_id: request.chain_id,
                nonce,
                issued_at: now,
                expires_at: lease_expires,
            };
            self.nonce_reservations
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?
                .insert(reservation.reservation_id, reservation.clone());
            self.record_recoverable_nonce_reservation(&request, &reservation, now)?;

            self.persist_or_revert(backup)?;
            Ok(reservation)
        }
        .await;
        request.zeroize_secrets();
        result
    }

    async fn release_nonce(&self, request: NonceReleaseRequest) -> Result<(), DaemonError> {
        let mut request = request;
        let result = async {
            let _signing_guard = self.signing_guard.lock().await;
            let _state_guard = self.state_persist_guard.lock().await;
            let backup = self.backup_state_if_persistent()?;
            let now = OffsetDateTime::now_utc();
            if self.recover_nonce_release_if_available(&request, now)? {
                return Ok(());
            }
            self.validate_request_timestamps(request.requested_at, request.expires_at, now)?;
            self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;
            self.register_replay_id(request.request_id, request.expires_at, now)?;
            self.prune_nonce_reservations(now)?;

            let released = {
                let mut reservations = self
                    .nonce_reservations
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?;
                let Some(existing) = reservations.get(&request.reservation_id) else {
                    return Err(DaemonError::UnknownNonceReservation(request.reservation_id));
                };
                if existing.agent_key_id != request.agent_key_id {
                    return Err(DaemonError::AgentAuthenticationFailed);
                }
                let released = existing.clone();
                reservations.remove(&request.reservation_id);
                released
            };
            self.reclaim_unused_nonce_heads(&[released])?;
            self.record_recoverable_nonce_release(&request, now)?;
            self.persist_or_revert(backup)?;
            Ok(())
        }
        .await;
        request.zeroize_secrets();
        result
    }

    async fn sign_for_agent(&self, request: SignRequest) -> Result<Signature, DaemonError> {
        let mut request = request;
        let result = async {
            let _signing_guard = self.signing_guard.lock().await;
            let _state_guard = self.state_persist_guard.lock().await;
            let now = OffsetDateTime::now_utc();
            if let Some(signature) = self.recover_signature_if_available(&request, now)? {
                return Ok(signature);
            }

            let backup = self.backup_state_if_persistent()?;
            self.prune_spend_log(now)?;
            self.prune_manual_approval_requests(now)?;

            let (agent_key, payload_action, policy_explanation) =
                self.explain_authorized_request(&request, now)?;
            self.ensure_replay_id_available(request.request_id, now)?;
            let approved_manual_request_id = match policy_explanation.decision {
                PolicyDecision::Allow => None,
                PolicyDecision::Deny(PolicyError::ManualApprovalRequired { policy_id, .. }) => {
                    let payload_hash = payload_hash_hex(&request.payload);
                    // Read the relay secret before creating or mutating approval state so a
                    // poisoned lock fails this request cleanly instead of silently dropping the
                    // secure approval link.
                    let relay_private_key_hex = self
                        .relay_private_key_hex
                        .read()
                        .map_err(|_| DaemonError::LockPoisoned)?
                        .clone();
                    match self.resolve_manual_approval_request(
                        &agent_key,
                        &payload_action,
                        &payload_hash,
                        vec![policy_id],
                        now,
                    )? {
                        ManualApprovalResolution::Approved(request_id) => request_id,
                        ManualApprovalResolution::Pending {
                            approval_request_id,
                            relay_config,
                        } => {
                            let frontend_url = manual_approval_capability_token(
                                &relay_private_key_hex,
                                approval_request_id,
                            )
                                .ok()
                                .and_then(|approval_capability| {
                                    manual_approval_frontend_url(
                                        &relay_config,
                                        approval_request_id,
                                        &approval_capability,
                                    )
                                });
                            self.persist_or_revert(backup)?;
                            return Err(DaemonError::ManualApprovalRequired {
                                approval_request_id,
                                relay_url: relay_config.relay_url.clone(),
                                frontend_url,
                            });
                        }
                    }
                }
                PolicyDecision::Deny(PolicyError::Eip712ManualApprovalRequired { policy_id, .. }) => {
                    let payload_hash = payload_hash_hex(&request.payload);
                    // Read the relay secret before creating or mutating approval state so a
                    // poisoned lock fails this request cleanly instead of silently dropping the
                    // secure approval link.
                    let relay_private_key_hex = self
                        .relay_private_key_hex
                        .read()
                        .map_err(|_| DaemonError::LockPoisoned)?
                        .clone();
                    match self.resolve_manual_approval_request(
                        &agent_key,
                        &payload_action,
                        &payload_hash,
                        policy_id.into_iter().collect(),
                        now,
                    )? {
                        ManualApprovalResolution::Approved(request_id) => request_id,
                        ManualApprovalResolution::Pending {
                            approval_request_id,
                            relay_config,
                        } => {
                            let frontend_url = manual_approval_capability_token(
                                &relay_private_key_hex,
                                approval_request_id,
                            )
                                .ok()
                                .and_then(|approval_capability| {
                                    manual_approval_frontend_url(
                                        &relay_config,
                                        approval_request_id,
                                        &approval_capability,
                                    )
                                });
                            self.persist_or_revert(backup)?;
                            return Err(DaemonError::ManualApprovalRequired {
                                approval_request_id,
                                relay_url: relay_config.relay_url.clone(),
                                frontend_url,
                            });
                        }
                    }
                }
                PolicyDecision::Deny(err) => return Err(DaemonError::Policy(err)),
            };
            let vault_key = self
                .vault_keys
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .get(&agent_key.vault_key_id)
                .cloned()
                .ok_or(DaemonError::UnknownVaultKey(agent_key.vault_key_id))?;

            if let AgentAction::BroadcastTx { tx } = &payload_action {
                self.ensure_nonce_reservation(
                    request.agent_key_id,
                    agent_key.vault_key_id,
                    tx.chain_id,
                    tx.nonce,
                    now,
                )?;
            }

            let signature = match &payload_action {
                AgentAction::BroadcastTx { tx } => {
                    if tx.tx_type != 0x02 {
                        return Err(DaemonError::Signer(SignerError::Unsupported(format!(
                            "broadcast transaction type 0x{:02x} is unsupported for signing",
                            tx.tx_type
                        ))));
                    }
                    self.sign_broadcast_eip1559(&vault_key, tx).await?
                }
                AgentAction::Permit2Permit { .. }
                | AgentAction::Eip3009TransferWithAuthorization { .. }
                | AgentAction::Eip3009ReceiveWithAuthorization { .. }
                | AgentAction::TempoSessionOpenTransaction { .. }
                | AgentAction::TempoSessionTopUpTransaction { .. }
                | AgentAction::TempoSessionVoucher { .. }
                | AgentAction::Eip712TypedData { .. } => {
                    self.sign_typed_data_action(&vault_key, &payload_action)
                        .await?
                }
                _ => {
                    self.signer_backend
                        .sign_payload(agent_key.vault_key_id, &request.payload)
                        .await?
                }
            };

            if let AgentAction::BroadcastTx { tx } = &payload_action {
                self.consume_nonce_reservation(
                    request.agent_key_id,
                    agent_key.vault_key_id,
                    tx.chain_id,
                    tx.nonce,
                    now,
                )?;
            }

            if let Some(approval_request_id) = approved_manual_request_id {
                self.complete_manual_approval_request(approval_request_id, now)?;
                self.prune_manual_approval_requests(now)?;
            }

            if payload_action.records_spend_event() {
                let event = SpendEvent {
                    agent_key_id: request.agent_key_id,
                    chain_id: payload_action.chain_id(),
                    asset: payload_action.asset(),
                    recipient: payload_action.recipient(),
                    amount_wei: payload_action.amount_wei(),
                    at: now,
                };
                self.spend_log
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?
                    .push(event);
            }
            self.register_replay_id(request.request_id, request.expires_at, now)?;
            self.persist_signed_state_best_effort(&request, &signature, now);

            Ok(signature)
        }
        .await;
        request.zeroize_secrets();
        result
    }
}

fn normalize_optional_url(
    label: &str,
    value: Option<String>,
) -> Result<Option<String>, DaemonError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        DaemonError::InvalidRelayConfig(format!("{label} must be a valid URL: {err}"))
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(DaemonError::InvalidRelayConfig(format!(
            "{label} must not include embedded username or password"
        )));
    }
    if parsed.query().is_some() {
        return Err(DaemonError::InvalidRelayConfig(format!(
            "{label} must not include a query string"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(DaemonError::InvalidRelayConfig(format!(
            "{label} must not include a fragment"
        )));
    }
    let host = parsed.host_str().ok_or_else(|| {
        DaemonError::InvalidRelayConfig(format!("{label} must include a hostname"))
    })?;
    match parsed.scheme() {
        "https" => Ok(Some(trimmed.to_string())),
        "http" if host.eq_ignore_ascii_case("localhost") => Ok(Some(trimmed.to_string())),
        "http" => {
            let is_loopback = host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
            if is_loopback {
                Ok(Some(trimmed.to_string()))
            } else {
                Err(DaemonError::InvalidRelayConfig(format!(
                    "{label} must use https unless it targets localhost or a loopback address"
                )))
            }
        }
        _ => Err(DaemonError::InvalidRelayConfig(format!(
            "{label} must use http or https"
        ))),
    }
}

fn validate_agent_key_attachment<B: VaultSignerBackend>(
    daemon: &InMemoryDaemon<B>,
    attachment: &PolicyAttachment,
) -> Result<(), DaemonError> {
    if let PolicyAttachment::PolicySet(ids) = attachment {
        if ids.is_empty() {
            return Err(DaemonError::InvalidPolicyAttachment(
                "policy set cannot be empty".to_string(),
            ));
        }
        let policies = daemon
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        for id in ids {
            let policy = policies.get(id).ok_or(DaemonError::UnknownPolicy(*id))?;
            if !policy.enabled {
                return Err(DaemonError::InvalidPolicyAttachment(format!(
                    "policy {id} is disabled and would not be enforced; enable it before attaching it to an agent key",
                )));
            }
        }
    }

    Ok(())
}

fn validate_admin_password(password: &str) -> Result<(), DaemonError> {
    if password.trim().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "admin_password must not be empty or whitespace".to_string(),
        ));
    }
    if password.len() > MAX_AUTH_SECRET_BYTES {
        return Err(DaemonError::InvalidConfig(format!(
            "admin_password must not exceed {MAX_AUTH_SECRET_BYTES} bytes"
        )));
    }

    Ok(())
}

fn hash_password(password: &str, config: &DaemonConfig) -> Result<String, DaemonError> {
    let salt = SaltString::generate(&mut PasswordOsRng);

    let params = ParamsBuilder::new()
        .m_cost(config.argon2_memory_kib)
        .t_cost(config.argon2_time_cost)
        .p_cost(config.argon2_parallelism)
        .build()
        .map_err(|err| DaemonError::PasswordHash(format!("invalid argon2 params: {err}")))?;

    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| DaemonError::PasswordHash(format!("hashing failed: {err}")))
}

fn validate_config(config: &DaemonConfig) -> Result<(), DaemonError> {
    if config.lease_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "lease_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_active_leases == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_active_leases must be greater than zero".to_string(),
        ));
    }
    if config.max_sign_payload_bytes == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_sign_payload_bytes must be greater than zero".to_string(),
        ));
    }
    if config.max_request_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "max_request_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_request_clock_skew < Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "max_request_clock_skew must be non-negative".to_string(),
        ));
    }
    if config.max_tracked_replay_ids == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_tracked_replay_ids must be greater than zero".to_string(),
        ));
    }
    if config.nonce_reservation_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "nonce_reservation_ttl must be greater than zero".to_string(),
        ));
    }
    if config.max_active_nonce_reservations == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_active_nonce_reservations must be greater than zero".to_string(),
        ));
    }
    if config.manual_approval_active_ttl <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "manual_approval_active_ttl must be greater than zero".to_string(),
        ));
    }
    if config.manual_approval_terminal_retention < Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "manual_approval_terminal_retention must be non-negative".to_string(),
        ));
    }
    if config.max_tracked_nonce_chains_per_vault == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_tracked_nonce_chains_per_vault must be greater than zero".to_string(),
        ));
    }
    if config.max_failed_admin_auth_attempts == 0 {
        return Err(DaemonError::InvalidConfig(
            "max_failed_admin_auth_attempts must be greater than zero".to_string(),
        ));
    }
    if config.admin_auth_lockout <= Duration::ZERO {
        return Err(DaemonError::InvalidConfig(
            "admin_auth_lockout must be greater than zero".to_string(),
        ));
    }
    if config.argon2_memory_kib == 0 {
        return Err(DaemonError::InvalidConfig(
            "argon2_memory_kib must be greater than zero".to_string(),
        ));
    }
    if config.argon2_time_cost == 0 {
        return Err(DaemonError::InvalidConfig(
            "argon2_time_cost must be greater than zero".to_string(),
        ));
    }
    if config.argon2_parallelism == 0 {
        return Err(DaemonError::InvalidConfig(
            "argon2_parallelism must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

fn map_domain_to_signer_error(err: vault_domain::DomainError) -> DaemonError {
    DaemonError::Signer(SignerError::Unsupported(format!(
        "action cannot be signed: {err}"
    )))
}

fn parse_verifying_key(public_key_hex: &str) -> Result<VerifyingKey, DaemonError> {
    let bytes =
        hex::decode(public_key_hex.strip_prefix("0x").unwrap_or(public_key_hex)).map_err(|_| {
            DaemonError::Signer(SignerError::Internal(
                "vault public key is not valid hex".to_string(),
            ))
        })?;
    VerifyingKey::from_sec1_bytes(&bytes).map_err(|err| {
        DaemonError::Signer(SignerError::Internal(format!(
            "vault public key is not valid secp256k1 SEC1 bytes: {err}"
        )))
    })
}

enum ManualApprovalPolicyReferenceError {
    Unknown(Uuid),
    Disabled(Uuid),
    NonManual(Uuid),
}

fn validate_manual_approval_policy_references(
    policies: &HashMap<Uuid, SpendingPolicy>,
    triggered_by_policy_ids: &[Uuid],
    require_enabled: bool,
) -> Result<(), ManualApprovalPolicyReferenceError> {
    for policy_id in triggered_by_policy_ids {
        let Some(policy) = policies.get(policy_id) else {
            return Err(ManualApprovalPolicyReferenceError::Unknown(*policy_id));
        };
        if !matches!(policy.policy_type, vault_domain::PolicyType::ManualApproval) {
            return Err(ManualApprovalPolicyReferenceError::NonManual(*policy_id));
        }
        if require_enabled && !policy.enabled {
            return Err(ManualApprovalPolicyReferenceError::Disabled(*policy_id));
        }
    }

    Ok(())
}

fn manual_approval_policy_reference_decision_error(
    approval_request_id: Uuid,
    err: ManualApprovalPolicyReferenceError,
) -> DaemonError {
    match err {
        ManualApprovalPolicyReferenceError::Unknown(policy_id) => {
            DaemonError::UnknownPolicy(policy_id)
        }
        ManualApprovalPolicyReferenceError::Disabled(policy_id) => {
            DaemonError::InvalidPolicy(format!(
                "manual approval request {} references disabled policy {}",
                approval_request_id, policy_id
            ))
        }
        ManualApprovalPolicyReferenceError::NonManual(policy_id) => {
            DaemonError::InvalidPolicy(format!(
                "manual approval request {} references non-manual policy {}",
                approval_request_id, policy_id
            ))
        }
    }
}

fn manual_approval_policy_reference_persistence_error(
    request_id: Uuid,
    err: ManualApprovalPolicyReferenceError,
) -> DaemonError {
    match err {
        ManualApprovalPolicyReferenceError::Unknown(policy_id) => DaemonError::Persistence(
            format!(
                "loaded manual approval request {} references unknown policy {}",
                request_id, policy_id
            ),
        ),
        ManualApprovalPolicyReferenceError::NonManual(policy_id) => DaemonError::Persistence(
            format!(
                "loaded manual approval request {} references non-manual policy {}",
                request_id, policy_id
            ),
        ),
        ManualApprovalPolicyReferenceError::Disabled(_) => unreachable!(
            "disabled policies are only rejected when approval-time validation requires enabled policies"
        ),
    }
}

fn prepare_loaded_state(mut state: PersistedDaemonState) -> Result<PersistedDaemonState, DaemonError> {
    ensure_relay_identity(&mut state);
    normalize_disabled_policy_set_attachments(&mut state);
    validate_loaded_state(&state)?;
    Ok(state)
}

fn validate_loaded_state(state: &PersistedDaemonState) -> Result<(), DaemonError> {
    for (lease_id, lease) in &state.leases {
        if lease.lease_id != *lease_id {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains lease entry keyed by {} but lease id is {}",
                lease_id, lease.lease_id
            )));
        }
        if lease.expires_at <= lease.issued_at {
            return Err(DaemonError::Persistence(format!(
                "loaded lease {} has invalid timestamps",
                lease.lease_id
            )));
        }
    }

    for (policy_id, policy) in &state.policies {
        if policy.id != *policy_id {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains policy entry keyed by {} but policy id is {}",
                policy_id, policy.id
            )));
        }
        validate_policy(policy)?;
    }

    for (vault_key_id, vault_key) in &state.vault_keys {
        if vault_key.id != *vault_key_id {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains vault key entry keyed by {} but vault key id is {}",
                vault_key_id, vault_key.id
            )));
        }
    }

    for signer_key_id in state.software_signer_private_keys.keys() {
        if !state.vault_keys.contains_key(signer_key_id) {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains signer key material for unknown vault key {}",
                signer_key_id
            )));
        }
    }

    for (agent_key_id, agent_key) in &state.agent_keys {
        if agent_key.id != *agent_key_id {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains agent key entry keyed by {} but agent id is {}",
                agent_key_id, agent_key.id
            )));
        }
        if !state.vault_keys.contains_key(&agent_key.vault_key_id) {
            return Err(DaemonError::Persistence(format!(
                "loaded state references unknown vault key {}",
                agent_key.vault_key_id
            )));
        }
        if let PolicyAttachment::PolicySet(policy_ids) = &agent_key.policies {
            for policy_id in policy_ids {
                let policy = state.policies.get(policy_id).ok_or_else(|| {
                    DaemonError::Persistence(format!(
                        "loaded state references unknown policy {} for agent {}",
                        policy_id, agent_key.id
                    ))
                })?;
                if !policy.enabled {
                    return Err(DaemonError::Persistence(format!(
                        "loaded state references disabled policy {} for agent {}",
                        policy_id, agent_key.id
                    )));
                }
            }
        }
    }

    for agent_key_id in state.agent_auth_tokens.keys() {
        if !state.agent_keys.contains_key(agent_key_id) {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains auth token for unknown agent {}",
                agent_key_id
            )));
        }
    }

    for (vault_key_id, chain_nonce_heads) in &state.nonce_heads {
        if !state.vault_keys.contains_key(vault_key_id) {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains nonce head for unknown vault key {}",
                vault_key_id
            )));
        }
        if chain_nonce_heads.contains_key(&0) {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains nonce head for vault key {} with invalid chain_id 0",
                vault_key_id
            )));
        }
    }

    for (reservation_id, reservation) in &state.nonce_reservations {
        if reservation.reservation_id != *reservation_id {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains nonce reservation entry keyed by {} but reservation id is {}",
                reservation_id, reservation.reservation_id
            )));
        }
        let Some(agent_key) = state.agent_keys.get(&reservation.agent_key_id) else {
            return Err(DaemonError::Persistence(format!(
                "loaded nonce reservation {} references unknown agent {}",
                reservation.reservation_id, reservation.agent_key_id
            )));
        };
        if reservation.vault_key_id != agent_key.vault_key_id {
            return Err(DaemonError::Persistence(format!(
                "loaded nonce reservation {} vault key mismatch for agent {}",
                reservation.reservation_id, reservation.agent_key_id
            )));
        }
        if reservation.chain_id == 0 {
            return Err(DaemonError::Persistence(format!(
                "loaded nonce reservation {} has invalid chain_id 0",
                reservation.reservation_id
            )));
        }
        if reservation.expires_at <= reservation.issued_at {
            return Err(DaemonError::Persistence(format!(
                "loaded nonce reservation {} has invalid timestamps",
                reservation.reservation_id
            )));
        }
    }

    for (request_id, result) in &state.recoverable_agent_results {
        let Some(agent_key) = state.agent_keys.get(&result.agent_key_id) else {
            return Err(DaemonError::Persistence(format!(
                "loaded recoverable agent result {} references unknown agent {}",
                request_id, result.agent_key_id
            )));
        };
        match (&result.request, &result.response) {
            (
                RecoverableAgentRequest::Sign { payload_hash_hex },
                RecoverableAgentResponse::Signature(_),
            ) => {
                if payload_hash_hex.trim().is_empty() {
                    return Err(DaemonError::Persistence(format!(
                        "loaded recoverable sign result {} has empty payload hash",
                        request_id
                    )));
                }
            }
            (
                RecoverableAgentRequest::ReserveNonce { chain_id, .. },
                RecoverableAgentResponse::NonceReservation(reservation),
            ) => {
                if *chain_id == 0 {
                    return Err(DaemonError::Persistence(format!(
                        "loaded recoverable nonce reservation result {} has invalid chain_id 0",
                        request_id
                    )));
                }
                if reservation.agent_key_id != result.agent_key_id {
                    return Err(DaemonError::Persistence(format!(
                        "loaded recoverable nonce reservation result {} agent mismatch",
                        request_id
                    )));
                }
                if reservation.vault_key_id != agent_key.vault_key_id {
                    return Err(DaemonError::Persistence(format!(
                        "loaded recoverable nonce reservation result {} vault key mismatch",
                        request_id
                    )));
                }
                if reservation.chain_id != *chain_id {
                    return Err(DaemonError::Persistence(format!(
                        "loaded recoverable nonce reservation result {} chain mismatch",
                        request_id
                    )));
                }
                if reservation.expires_at <= reservation.issued_at {
                    return Err(DaemonError::Persistence(format!(
                        "loaded recoverable nonce reservation result {} has invalid timestamps",
                        request_id
                    )));
                }
            }
            (RecoverableAgentRequest::ReleaseNonce { .. }, RecoverableAgentResponse::Unit) => {}
            _ => {
                return Err(DaemonError::Persistence(format!(
                    "loaded recoverable agent result {} has mismatched request/response types",
                    request_id
                )));
            }
        }
    }

    for (request_id, request) in &state.manual_approval_requests {
        if request.id != *request_id {
            return Err(DaemonError::Persistence(format!(
                "loaded state contains manual approval request entry keyed by {} but request id is {}",
                request_id, request.id
            )));
        }
        let Some(agent_key) = state.agent_keys.get(&request.agent_key_id) else {
            return Err(DaemonError::Persistence(format!(
                "loaded manual approval request {} references unknown agent {}",
                request.id, request.agent_key_id
            )));
        };
        if request.vault_key_id != agent_key.vault_key_id {
            return Err(DaemonError::Persistence(format!(
                "loaded manual approval request {} vault key mismatch for agent {}",
                request.id, request.agent_key_id
            )));
        }
        if request.chain_id == 0 {
            return Err(DaemonError::Persistence(format!(
                "loaded manual approval request {} has invalid chain_id 0",
                request.id
            )));
        }
        if request.request_payload_hash_hex.trim().is_empty() {
            return Err(DaemonError::Persistence(format!(
                "loaded manual approval request {} has empty payload hash",
                request.id
            )));
        }
        if request.updated_at < request.created_at {
            return Err(DaemonError::Persistence(format!(
                "loaded manual approval request {} has invalid timestamps",
                request.id
            )));
        }
        if matches!(request.status, ManualApprovalStatus::Completed)
            && request.completed_at.is_none()
        {
            return Err(DaemonError::Persistence(format!(
                "loaded manual approval request {} is completed without completed_at",
                request.id
            )));
        }
        if let Err(err) = validate_manual_approval_policy_references(
            &state.policies,
            &request.triggered_by_policy_ids,
            false,
        ) {
            return Err(manual_approval_policy_reference_persistence_error(
                request.id, err,
            ));
        }
    }

    let relay_url = normalize_optional_url("relay_url", state.relay_config.relay_url.clone())?;
    if relay_url != state.relay_config.relay_url {
        return Err(DaemonError::Persistence(
            "loaded relay configuration must be normalized".to_string(),
        ));
    }
    let frontend_url =
        normalize_optional_url("frontend_url", state.relay_config.frontend_url.clone())?;
    if frontend_url != state.relay_config.frontend_url {
        return Err(DaemonError::Persistence(
            "loaded relay frontend configuration must be normalized".to_string(),
        ));
    }

    let secret =
        relay_static_secret_from_hex(&state.relay_private_key_hex, "loaded relay private key")
            .map_err(DaemonError::Persistence)?;
    let public = x25519_dalek::PublicKey::from(&secret);
    let expected_public_key_hex = hex::encode(public.as_bytes());
    if state.relay_config.daemon_public_key_hex != expected_public_key_hex {
        return Err(DaemonError::Persistence(
            "loaded relay public key does not match stored private key".to_string(),
        ));
    }

    let daemon_id_bytes = hex::decode(
        state
            .relay_config
            .daemon_id_hex
            .trim()
            .trim_start_matches("0x"),
    )
    .map_err(|err| DaemonError::Persistence(format!("loaded daemon id is invalid hex: {err}")))?;
    if daemon_id_bytes.len() != 32 {
        return Err(DaemonError::Persistence(
            "loaded daemon id must be 32 bytes".to_string(),
        ));
    }

    Ok(())
}

fn normalize_disabled_policy_set_attachments(state: &mut PersistedDaemonState) {
    let policies = &state.policies;
    for agent_key in state.agent_keys.values_mut() {
        if let PolicyAttachment::PolicySet(policy_ids) = &mut agent_key.policies {
            policy_ids.retain(|policy_id| {
                policies
                    .get(policy_id)
                    .map(|policy| policy.enabled)
                    .unwrap_or(true)
            });
        }
    }
}

fn validate_policy(policy: &SpendingPolicy) -> Result<(), DaemonError> {
    match policy.policy_type {
        vault_domain::PolicyType::DailyMaxTxCount => {
            if policy.tx_count_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_tx_count must be greater than zero".to_string(),
                ));
            }
        }
        vault_domain::PolicyType::PerTxMaxFeePerGas => {
            if policy.fee_per_gas_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_fee_per_gas_wei must be greater than zero".to_string(),
                ));
            }
        }
        vault_domain::PolicyType::PerTxMaxPriorityFeePerGas => {
            if policy.priority_fee_per_gas_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_priority_fee_per_gas_wei must be greater than zero".to_string(),
                ));
            }
        }
        vault_domain::PolicyType::PerTxMaxCalldataBytes => {
            if policy.calldata_bytes_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_calldata_bytes must be greater than zero".to_string(),
                ));
            }
        }
        vault_domain::PolicyType::PerChainMaxGasSpend => {
            if policy.gas_spend_limit_wei().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_gas_spend_wei must be greater than zero".to_string(),
                ));
            }
        }
        vault_domain::PolicyType::Eip712Signing => {
            if policy.eip712_approval_type().is_none() {
                return Err(DaemonError::InvalidPolicy(
                    "approval_type must be set for eip712_signing".to_string(),
                ));
            }
            if !matches!(policy.recipients, vault_domain::EntityScope::All) {
                return Err(DaemonError::InvalidPolicy(
                    "eip712_signing recipient scope must be all".to_string(),
                ));
            }
            if !matches!(policy.assets, vault_domain::EntityScope::All) {
                return Err(DaemonError::InvalidPolicy(
                    "eip712_signing asset scope must be all".to_string(),
                ));
            }
        }
        _ if policy.max_amount_wei == 0 => {
            return Err(DaemonError::InvalidPolicy(
                "max_amount_wei must be greater than zero".to_string(),
            ));
        }
        _ => {}
    }

    if matches!(
        &policy.recipients,
        vault_domain::EntityScope::Set(values) if values.is_empty()
    ) {
        return Err(DaemonError::InvalidPolicy(
            "recipient set scope must not be empty".to_string(),
        ));
    }

    if matches!(
        &policy.assets,
        vault_domain::EntityScope::Set(values) if values.is_empty()
    ) {
        return Err(DaemonError::InvalidPolicy(
            "asset set scope must not be empty".to_string(),
        ));
    }

    if matches!(
        &policy.networks,
        vault_domain::EntityScope::Set(values)
            if values.is_empty() || values.iter().any(|chain_id| *chain_id == 0)
    ) {
        return Err(DaemonError::InvalidPolicy(
            "network set scope must not be empty and must not contain chain_id 0".to_string(),
        ));
    }

    Ok(())
}

fn generate_agent_auth_token() -> String {
    format!("{}.{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn hash_agent_auth_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}
