//! `ReleaseSignedNonce`: returning the nonce of a signed `BroadcastTx` whose
//! transaction never reached the network.
//!
//! Signing a `BroadcastTx` consumes its nonce reservation, and the allocator
//! never hands a consumed nonce out again. When the payments service then
//! fails to submit the transaction, the next payment would get the following
//! nonce and wait forever behind the gap. Every signed broadcast is therefore
//! remembered for [`SIGNED_BROADCAST_RELEASE_WINDOW`], keyed by its hash, so
//! the signing agent can hand the nonce back exactly once.
//!
//! Safety: the daemon cannot tell whether a transaction reached the network.
//! Releasing a nonce whose transaction is live lets the next transaction
//! replace or race it; both were allowed by policy and at most one is mined,
//! so the agent cannot exceed its limits this way. The spend recorded at
//! signing is deliberately kept, because refunding it on the agent's word
//! would let an agent that broadcasts the transaction itself spend past its
//! window limits. The payments service only calls this after a definitive
//! pre-submission failure.

use std::collections::HashMap;

use agentpay_domain::{NonceReservation, SignedNonceReleaseRequest};
use agentpay_signer::VaultSignerBackend;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::recovery::{RecoverableAgentRequest, RecoverableAgentResponse, RecoverableAgentResult};
use crate::{DaemonError, InMemoryDaemon};

/// How long after signing a broadcast's nonce can still be released.
pub(crate) const SIGNED_BROADCAST_RELEASE_WINDOW: Duration = Duration::minutes(10);

/// Most signed broadcasts remembered at once; the oldest are forgotten first.
pub(crate) const MAX_TRACKED_SIGNED_BROADCASTS: usize = 1024;

/// A signed `BroadcastTx` whose nonce may still be released (persisted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedBroadcastRecord {
    /// Agent key that signed it.
    pub(crate) agent_key_id: Uuid,
    /// Vault key that signed it (the nonce scope).
    pub(crate) vault_key_id: Uuid,
    /// EVM chain id.
    pub(crate) chain_id: u64,
    /// Transaction nonce.
    pub(crate) nonce: u64,
    /// `request_id` of the `SignForAgent` call, whose recorded signature is
    /// dropped on release.
    pub(crate) request_id: Uuid,
    /// When it was signed.
    pub(crate) signed_at: OffsetDateTime,
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    /// Remembers a freshly signed broadcast under its lowercase `0x` hash.
    pub(super) fn record_signed_broadcast(
        &self,
        tx_hash_hex: &str,
        record: SignedBroadcastRecord,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        let mut records = self
            .signed_broadcasts
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        prune_signed_broadcasts(&mut records, now);
        trim_signed_broadcasts(
            &mut records,
            MAX_TRACKED_SIGNED_BROADCASTS.saturating_sub(1),
        );
        records.insert(tx_hash_hex.to_ascii_lowercase(), record);
        Ok(())
    }

    pub(crate) async fn release_signed_nonce_impl(
        &self,
        request: SignedNonceReleaseRequest,
    ) -> Result<(), DaemonError> {
        let mut request = request;
        let result = async {
            let _signing_guard = self.signing_guard.lock().await;
            let _state_guard = self.state_persist_guard.lock().await;
            let backup = self.backup_state_if_persistent()?;
            let now = OffsetDateTime::now_utc();
            if self.recover_signed_nonce_release_if_available(&request, now)? {
                return Ok(());
            }
            self.validate_request_timestamps(request.requested_at, request.expires_at, now)?;
            self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;
            let tx_hash = normalize_tx_hash(&request.tx_hash_hex)?;

            let record = {
                let mut records = self
                    .signed_broadcasts
                    .write()
                    .map_err(|_| DaemonError::LockPoisoned)?;
                prune_signed_broadcasts(&mut records, now);
                let record = records
                    .get(&tx_hash)
                    .cloned()
                    .ok_or_else(|| DaemonError::UnknownSignedTransaction(tx_hash.clone()))?;
                if record.agent_key_id != request.agent_key_id {
                    return Err(DaemonError::AgentAuthenticationFailed);
                }
                if record.chain_id != request.chain_id || record.nonce != request.nonce {
                    return Err(DaemonError::InvalidNonceReservation(format!(
                        "transaction {tx_hash} was signed with chain_id {} and nonce {}",
                        record.chain_id, record.nonce
                    )));
                }
                records.remove(&tx_hash);
                record
            };
            self.register_replay_id(request.request_id, request.expires_at, now)?;
            self.prune_nonce_reservations(now)?;

            // An exact-nonce reservation may already hold the nonce again (a
            // replacement transaction); then it is not free.
            let reserved_again = self
                .nonce_reservations
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?
                .values()
                .any(|reservation| {
                    reservation.vault_key_id == record.vault_key_id
                        && reservation.chain_id == record.chain_id
                        && reservation.nonce == record.nonce
                });
            if !reserved_again {
                self.reclaim_unused_nonce_heads(&[NonceReservation {
                    reservation_id: Uuid::nil(),
                    agent_key_id: record.agent_key_id,
                    vault_key_id: record.vault_key_id,
                    chain_id: record.chain_id,
                    nonce: record.nonce,
                    issued_at: record.signed_at,
                    expires_at: now,
                }])?;
            }
            // A retry of the original signing request must not hand the
            // released transaction out again; its request id stays consumed.
            self.recoverable_agent_results
                .write()
                .map_err(|_| DaemonError::LockPoisoned)?
                .remove(&record.request_id);
            self.record_recoverable_agent_result(
                request.request_id,
                RecoverableAgentResult {
                    agent_key_id: request.agent_key_id,
                    request: RecoverableAgentRequest::ReleaseSignedNonce {
                        chain_id: request.chain_id,
                        nonce: request.nonce,
                        tx_hash_hex: tx_hash,
                    },
                    recover_until: now + Duration::days(8),
                    response: RecoverableAgentResponse::Unit,
                },
                now,
            )?;
            self.persist_or_revert(backup)?;
            Ok(())
        }
        .await;
        request.zeroize_secrets();
        result
    }

    fn recover_signed_nonce_release_if_available(
        &self,
        request: &SignedNonceReleaseRequest,
        now: OffsetDateTime,
    ) -> Result<bool, DaemonError> {
        let Some(entry) = self
            .recoverable_agent_results
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&request.request_id)
            .cloned()
        else {
            return Ok(false);
        };
        if entry.recover_until <= now {
            return Ok(false);
        }
        self.authenticate_agent(request.agent_key_id, &request.agent_auth_token)?;
        let matches_request = entry.agent_key_id == request.agent_key_id
            && matches!(
                &entry.request,
                RecoverableAgentRequest::ReleaseSignedNonce { chain_id, nonce, tx_hash_hex }
                    if *chain_id == request.chain_id
                        && *nonce == request.nonce
                        && tx_hash_hex.eq_ignore_ascii_case(request.tx_hash_hex.trim())
            );
        if !matches_request || !matches!(entry.response, RecoverableAgentResponse::Unit) {
            return Err(DaemonError::RequestReplayDetected);
        }
        Ok(true)
    }

    /// Forgets every signed broadcast of `agent_key_id` (agent revocation).
    pub(super) fn forget_signed_broadcasts_of_agent(
        &self,
        agent_key_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.signed_broadcasts
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, record| record.agent_key_id != agent_key_id);
        Ok(())
    }
}

/// Drops records older than the release window. Records stamped in the future
/// (the clock stepped back) are kept until the window has passed again.
pub(super) fn prune_signed_broadcasts(
    records: &mut HashMap<String, SignedBroadcastRecord>,
    now: OffsetDateTime,
) {
    records.retain(|_, record| record.signed_at + SIGNED_BROADCAST_RELEASE_WINDOW > now);
}

/// Forgets the oldest records until at most `max_entries` remain.
pub(super) fn trim_signed_broadcasts(
    records: &mut HashMap<String, SignedBroadcastRecord>,
    max_entries: usize,
) {
    if records.len() <= max_entries {
        return;
    }
    let mut ordered = records
        .iter()
        .map(|(hash, record)| (record.signed_at, hash.clone()))
        .collect::<Vec<_>>();
    ordered.sort_unstable();
    let excess = records.len() - max_entries;
    for (_, hash) in ordered.into_iter().take(excess) {
        records.remove(&hash);
    }
}

/// `0x` + 64 hex characters, lower-cased.
fn normalize_tx_hash(value: &str) -> Result<String, DaemonError> {
    let trimmed = value.trim();
    let valid = trimmed.len() == 66
        && trimmed.starts_with("0x")
        && trimmed[2..].bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err(DaemonError::InvalidNonceReservation(
            "tx_hash_hex must be 0x followed by 64 hex characters".to_string(),
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}
