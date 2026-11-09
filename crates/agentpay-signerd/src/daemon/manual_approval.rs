//! Manual approval requests: creation and reuse during signing, admin decisions,
//! retention, and validation of the policies that triggered them.

use std::collections::HashMap;

use agentpay_domain::{
    AdminAuth, AgentAction, AgentKey, ApprovalReason, ManualApprovalDecision,
    ManualApprovalRequest, ManualApprovalStatus, SpendingPolicy,
};
use agentpay_signer::{SignerError, VaultSignerBackend};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DaemonConfig, DaemonError, InMemoryDaemon, RequestContext};

pub(super) enum ManualApprovalResolution {
    Approved(Option<Uuid>),
    Rejected(Uuid),
    Pending(Uuid),
}

pub(super) struct ManualApprovalRetentionCutoffs {
    active: OffsetDateTime,
    terminal: OffsetDateTime,
}

pub(super) enum ManualApprovalPolicyReferenceError {
    Unknown(Uuid),
    Disabled(Uuid),
    NonManual(Uuid),
}

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn list_manual_approval_requests_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
    ) -> Result<Vec<ManualApprovalRequest>, DaemonError> {
        let now = OffsetDateTime::now_utc();
        self.authorize_admin(ctx, auth, now)?;
        let mut requests = self.retained_manual_approval_requests_at(now)?;
        requests.sort_by_key(|request| std::cmp::Reverse(request.created_at));
        Ok(requests)
    }

    pub(crate) async fn decide_manual_approval_request_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        approval_request_id: Uuid,
        decision: ManualApprovalDecision,
        rejection_reason: Option<String>,
    ) -> Result<ManualApprovalRequest, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
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

    pub(super) fn manual_approval_retention_cutoffs(
        &self,
        now: OffsetDateTime,
    ) -> Result<ManualApprovalRetentionCutoffs, DaemonError> {
        Self::manual_approval_retention_cutoffs_for_config(&self.config, now)
    }

    pub(super) fn manual_approval_retention_cutoffs_for_config(
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

    pub(super) fn manual_approval_request_retained_with_cutoffs(
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

    pub(super) fn retained_manual_approval_requests_at(
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

    pub(super) fn prune_manual_approval_requests(
        &self,
        now: OffsetDateTime,
    ) -> Result<(), DaemonError> {
        let cutoffs = self.manual_approval_retention_cutoffs(now)?;
        self.manual_approval_requests
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|_, request| {
                Self::manual_approval_request_retained_with_cutoffs(request, &cutoffs)
            });
        Ok(())
    }

    pub(super) fn resolve_manual_approval_request(
        &self,
        agent_key: &AgentKey,
        payload_action: &AgentAction,
        payload_hash: &str,
        triggered_by_policy_ids: Vec<Uuid>,
        reasons: Vec<ApprovalReason>,
        now: OffsetDateTime,
    ) -> Result<ManualApprovalResolution, DaemonError> {
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
                ManualApprovalStatus::Pending => ManualApprovalResolution::Pending(existing.id),
                ManualApprovalStatus::Rejected => ManualApprovalResolution::Rejected(existing.id),
                ManualApprovalStatus::Completed => {
                    unreachable!("manual approval reuse filter must exclude completed requests")
                }
            });
        }

        let max_pending = self.config.max_pending_manual_approval_requests_per_agent;
        let pending_for_agent = requests
            .values()
            .filter(|request| {
                request.agent_key_id == agent_key.id
                    && request.status == ManualApprovalStatus::Pending
            })
            .count();
        if pending_for_agent >= max_pending {
            return Err(DaemonError::TooManyPendingManualApprovalRequests {
                agent_key_id: agent_key.id,
                max_pending,
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
                reasons,
                completed_at: None,
                rejection_reason: None,
            },
        );

        Ok(ManualApprovalResolution::Pending(approval_request_id))
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

    pub(super) fn complete_manual_approval_request(
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
}

pub(super) fn validate_manual_approval_policy_references(
    policies: &HashMap<Uuid, SpendingPolicy>,
    triggered_by_policy_ids: &[Uuid],
    require_enabled: bool,
) -> Result<(), ManualApprovalPolicyReferenceError> {
    for policy_id in triggered_by_policy_ids {
        let Some(policy) = policies.get(policy_id) else {
            return Err(ManualApprovalPolicyReferenceError::Unknown(*policy_id));
        };
        if !policy.may_require_manual_approval() {
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

pub(super) fn manual_approval_policy_reference_persistence_error(
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

pub(super) fn ensure_action_supports_manual_approval(
    action: &AgentAction,
) -> Result<(), DaemonError> {
    let missing_durable_nonce = match action {
        AgentAction::SolanaSolTransfer { transfer } => transfer.durable_nonce_account.is_none(),
        AgentAction::SolanaSplTransfer { transfer } => transfer.durable_nonce_account.is_none(),
        // A payment transaction carries the payee's recent blockhash and has no
        // durable nonce (payees verify the exact instruction list). It can wait
        // for approval; the signed transaction lands only if the approval comes
        // before the blockhash expires (about a minute).
        AgentAction::SolanaPaymentTransaction { .. } => false,
        _ => false,
    };
    if missing_durable_nonce {
        return Err(DaemonError::Signer(SignerError::Unsupported(
            "solana manual approval requires AgentPay-managed durable nonce setup; use the current transfer-sol or transfer-spl broadcast flow".to_string(),
        )));
    }
    Ok(())
}
