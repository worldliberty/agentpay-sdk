//! Snapshotting, restoring, and persisting daemon state, plus integrity validation
//! and scrubbing of expired ephemeral entries in loaded state.

use agentpay_domain::{ManualApprovalStatus, PolicyAttachment, SignRequest, Signature};
use agentpay_signer::VaultSignerBackend;
use time::OffsetDateTime;

use super::admin_auth::validate_persisted_admin_credential;
use super::manual_approval::{
    manual_approval_policy_reference_persistence_error, validate_manual_approval_policy_references,
};
use super::policies::validate_policy;
use super::recovery::{RecoverableAgentRequest, RecoverableAgentResponse};
use super::signed_nonces::{
    prune_signed_broadcasts, trim_signed_broadcasts, MAX_TRACKED_SIGNED_BROADCASTS,
};
use super::tempo_channels::MAX_TRACKED_TEMPO_CHANNELS;
use crate::persistence::{PersistedDaemonState, SchemaVersion};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(super) fn scrub_persisted_ephemeral_state(
        config: &DaemonConfig,
        state: &mut PersistedDaemonState,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
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
        state
            .spend_log
            .retain(|event| Self::spend_event_is_retained(event, retention_start));

        let cutoffs = Self::manual_approval_retention_cutoffs_for_config(config, now)?;
        state.manual_approval_requests.retain(|_, request| {
            Self::manual_approval_request_retained_with_cutoffs(request, &cutoffs)
        });

        state
            .recoverable_agent_results
            .retain(|_, entry| entry.recover_until > now);
        Self::trim_recoverable_agent_results(
            &mut state.recoverable_agent_results,
            config.max_recoverable_agent_results,
        );
        Self::trim_tempo_channels(&mut state.tempo_channels, MAX_TRACKED_TEMPO_CHANNELS);
        prune_signed_broadcasts(&mut state.signed_broadcasts, now);
        trim_signed_broadcasts(&mut state.signed_broadcasts, MAX_TRACKED_SIGNED_BROADCASTS);
        Ok(())
    }

    fn scrub_ephemeral_state(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.prune_replay_ids(now)?;
        self.prune_nonce_reservations(now)?;
        self.prune_spend_log(now)?;
        self.prune_manual_approval_requests(now)?;
        self.prune_empty_nonce_heads()?;
        Ok(())
    }

    pub(super) fn snapshot_state(&self) -> Result<PersistedDaemonState, DaemonError> {
        let admin_credentials = self
            .admin_credentials
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
            schema_version: SchemaVersion::default(),
            admin_credentials,
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
            tempo_channels: self
                .tempo_channels
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
            signed_broadcasts: self
                .signed_broadcasts
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .clone(),
        })
    }

    pub(super) fn restore_state(&self, snapshot: PersistedDaemonState) -> Result<(), DaemonError> {
        let PersistedDaemonState {
            schema_version: _,
            admin_credentials,
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
            tempo_channels,
            signed_broadcasts,
        } = snapshot;
        self.signer_backend
            .restore_persistable_key_material(&software_signer_private_keys)
            .map_err(DaemonError::Signer)?;
        *self
            .admin_credentials
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = admin_credentials;
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
            .tempo_channels
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = tempo_channels;
        *self
            .signed_broadcasts
            .write()
            .map_err(|_| DaemonError::LockPoisoned)? = signed_broadcasts;
        Ok(())
    }

    pub(super) fn backup_state_if_persistent(
        &self,
    ) -> Result<Option<PersistedDaemonState>, DaemonError> {
        if self.state_store.is_none() {
            return Ok(None);
        }
        Ok(Some(self.snapshot_state()?))
    }

    pub(super) fn persist_state_if_enabled(&self) -> Result<(), DaemonError> {
        let Some(store) = &self.state_store else {
            return Ok(());
        };
        self.scrub_ephemeral_state(OffsetDateTime::now_utc())?;
        let snapshot = self.snapshot_state()?;
        store.save(&snapshot).map_err(DaemonError::Persistence)
    }

    pub(super) fn persist_or_revert(
        &self,
        backup: Option<PersistedDaemonState>,
    ) -> Result<(), DaemonError> {
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

    pub(super) fn persist_signed_state_best_effort(
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
}

pub(crate) fn prepare_loaded_state(
    mut state: PersistedDaemonState,
) -> Result<PersistedDaemonState, DaemonError> {
    normalize_disabled_policy_set_attachments(&mut state);
    validate_loaded_state(&state)?;
    Ok(state)
}

pub(crate) fn validate_loaded_state(state: &PersistedDaemonState) -> Result<(), DaemonError> {
    for (credential_id, credential) in &state.admin_credentials {
        validate_persisted_admin_credential(*credential_id, credential)?;
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
            (RecoverableAgentRequest::ReleaseNonce { .. }, RecoverableAgentResponse::Unit)
            | (
                RecoverableAgentRequest::ReleaseSignedNonce { .. },
                RecoverableAgentResponse::Unit,
            ) => {}
            _ => {
                return Err(DaemonError::Persistence(format!(
                    "loaded recoverable agent result {} has mismatched request/response types",
                    request_id
                )));
            }
        }
    }

    for (tx_hash, record) in &state.signed_broadcasts {
        let Some(agent_key) = state.agent_keys.get(&record.agent_key_id) else {
            return Err(DaemonError::Persistence(format!(
                "loaded signed transaction {tx_hash} references unknown agent {}",
                record.agent_key_id
            )));
        };
        if record.vault_key_id != agent_key.vault_key_id || record.chain_id == 0 {
            return Err(DaemonError::Persistence(format!(
                "loaded signed transaction {tx_hash} has an invalid nonce scope"
            )));
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

    Ok(())
}

pub(super) fn normalize_disabled_policy_set_attachments(state: &mut PersistedDaemonState) {
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
