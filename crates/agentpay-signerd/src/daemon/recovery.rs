//! Recoverable agent results: idempotent replays of signatures and nonce
//! operations whose responses may have been lost (for example after a persist
//! failure).

use std::collections::HashMap;

use agentpay_domain::{
    NonceReleaseRequest, NonceReservation, NonceReservationRequest, SignRequest, Signature,
};
use agentpay_signer::VaultSignerBackend;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::signing::payload_hash_hex;
use crate::{DaemonError, InMemoryDaemon};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum RecoverableAgentRequest {
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
    ReleaseSignedNonce {
        chain_id: u64,
        nonce: u64,
        tx_hash_hex: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum RecoverableAgentResponse {
    Signature(Signature),
    NonceReservation(NonceReservation),
    Unit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RecoverableAgentResult {
    pub(super) agent_key_id: Uuid,
    pub(super) request: RecoverableAgentRequest,
    pub(super) recover_until: OffsetDateTime,
    pub(super) response: RecoverableAgentResponse,
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    fn prune_recoverable_agent_results(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        self.recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, entry| entry.recover_until > now);
        Ok(())
    }

    pub(super) fn record_recoverable_agent_result(
        &self,
        request_id: Uuid,
        result: RecoverableAgentResult,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        self.prune_recoverable_agent_results(now)?;
        let mut results = self
            .recoverable_agent_results
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        // Reserve room for the new entry so agent-driven retries can never grow
        // this table without bound; the oldest results are evicted first.
        let capacity_for_new_entry = self.config.max_recoverable_agent_results.saturating_sub(1);
        Self::trim_recoverable_agent_results(&mut results, capacity_for_new_entry);
        results.insert(request_id, result);
        Ok(())
    }

    /// Evicts the oldest recoverable results (by `recover_until`, then request id
    /// for determinism) until at most `max_entries` remain.
    pub(super) fn trim_recoverable_agent_results(
        results: &mut HashMap<Uuid, RecoverableAgentResult>,
        max_entries: usize,
    ) {
        if results.len() <= max_entries {
            return;
        }
        let excess = results.len() - max_entries;
        let mut ordered = results
            .iter()
            .map(|(request_id, entry)| (entry.recover_until, *request_id))
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        for (_, request_id) in ordered.into_iter().take(excess) {
            results.remove(&request_id);
        }
    }

    pub(super) fn record_recoverable_signature(
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

    pub(super) fn record_recoverable_nonce_reservation(
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

    pub(super) fn record_recoverable_nonce_release(
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

    pub(super) fn recover_signature_if_available(
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

    pub(super) fn recover_nonce_reservation_if_available(
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

    pub(super) fn recover_nonce_release_if_available(
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
}
