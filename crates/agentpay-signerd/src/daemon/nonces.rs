//! EVM nonce reservation: per-agent/per-chain heads, reusable gaps, reservation
//! lifetime, and capacity bounds.

use std::collections::{BTreeSet, HashMap};

use agentpay_domain::{NonceReleaseRequest, NonceReservation, NonceReservationRequest};
use agentpay_signer::VaultSignerBackend;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DaemonError, InMemoryDaemon};

/// Reclaimed nonces per agent key and chain id that can be handed out again.
pub(crate) type ReusableNonceGaps = HashMap<Uuid, HashMap<u64, BTreeSet<u64>>>;

/// Maximum number of nonces a single reservation may skip ahead of the tracked
/// chain head. Larger skips would force the daemon to materialize every skipped
/// nonce as a reusable gap, so they are rejected up front.
pub const MAX_NONCE_SKIP: u64 = 1024;

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn reserve_nonce_impl(
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
            // Reject huge skips before touching replay/nonce state: every skipped
            // nonce below `min_nonce` would otherwise be materialized as a
            // reusable gap, so an agent could force unbounded allocations.
            self.ensure_nonce_skip_within_bounds(
                agent_key.vault_key_id,
                request.chain_id,
                request.min_nonce,
            )?;
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
                    // An untracked chain head (fresh daemon, restored wallet, or a
                    // head reclaimed and pruned) starts at `min_nonce`, the caller's
                    // view of the live on-chain nonce, without materializing gaps.
                    request.min_nonce,
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
                    // An untracked chain head (fresh daemon, restored wallet, or a
                    // head reclaimed and pruned) starts at `min_nonce`, the caller's
                    // view of the live on-chain nonce, without materializing gaps.
                    request.min_nonce,
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

    pub(crate) async fn release_nonce_impl(
        &self,
        request: NonceReleaseRequest,
    ) -> Result<(), DaemonError> {
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

    pub(super) fn prune_nonce_reservations(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
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

    pub(super) fn prune_empty_nonce_heads(&self) -> Result<(), DaemonError> {
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
            chain_gaps
                .retain(|chain_id, gaps| chain_heads.contains_key(chain_id) && !gaps.is_empty());
            !chain_gaps.is_empty()
        });
    }

    pub(super) fn reclaim_unused_nonce_heads(
        &self,
        removed: &[NonceReservation],
    ) -> Result<(), DaemonError> {
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

    pub(super) fn reclaim_unused_nonce_heads_map(
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

    pub(super) fn consume_nonce_reservation(
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

    pub(super) fn ensure_nonce_reservation(
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

    /// Rejects reservations that would skip more than [`MAX_NONCE_SKIP`] nonces
    /// past the currently tracked chain head.
    ///
    /// The bound only applies relative to a tracked head. An untracked chain
    /// (fresh daemon, restored wallet, or a head pruned after its reservations
    /// were reclaimed) is seeded at `min_nonce` by the allocator without
    /// creating gaps, so a large live on-chain nonce is not a skip.
    fn ensure_nonce_skip_within_bounds(
        &self,
        vault_key_id: Uuid,
        chain_id: u64,
        min_nonce: u64,
    ) -> Result<(), DaemonError> {
        let tracked_head = self
            .nonce_heads
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&vault_key_id)
            .and_then(|chain_heads| chain_heads.get(&chain_id))
            .copied();
        let Some(head) = tracked_head else {
            // Fail before any state is touched if a head seeded at `min_nonce`
            // could never advance past the reserved nonce.
            if min_nonce == u64::MAX {
                return Err(DaemonError::InvalidNonceReservation(
                    "nonce allocation overflow".to_string(),
                ));
            }
            return Ok(());
        };
        let requested_skip = min_nonce.saturating_sub(head);
        if requested_skip > MAX_NONCE_SKIP {
            return Err(DaemonError::NonceSkipTooLarge {
                requested_skip,
                max_skip: MAX_NONCE_SKIP,
            });
        }
        Ok(())
    }
}
