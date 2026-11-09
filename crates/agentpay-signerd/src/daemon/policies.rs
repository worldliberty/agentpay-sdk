//! Spending-policy administration and evaluation, including the spend log used
//! for windowed limits.

use agentpay_domain::{
    AdminAuth, AgentAction, AgentKey, PolicyAttachment, SignRequest, SpendEvent, SpendingPolicy,
};
use agentpay_policy::{PolicyDecision, PolicyError, PolicyEvaluation, PolicyExplanation};
use agentpay_signer::VaultSignerBackend;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{DaemonError, InMemoryDaemon, PolicySummary, RequestContext};

const SPEND_LOG_RETENTION: Duration = Duration::days(8);

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) async fn add_policy_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        policy: SpendingPolicy,
    ) -> Result<(), DaemonError> {
        let now = OffsetDateTime::now_utc();
        self.authorize_admin(ctx, auth, now)?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
        validate_policy(&policy)?;
        self.prune_manual_approval_requests(now)?;
        if !policy.may_require_manual_approval()
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

    pub(crate) async fn list_policies_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
    ) -> Result<Vec<SpendingPolicy>, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
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

    pub(crate) async fn list_policy_summaries_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
    ) -> Result<Vec<PolicySummary>, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let mut summaries: Vec<(u32, PolicySummary)> = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .values()
            .map(|policy| {
                (
                    policy.priority,
                    PolicySummary {
                        id: policy.id,
                        enabled: policy.enabled,
                    },
                )
            })
            .collect();
        summaries.sort_by(|(priority_a, summary_a), (priority_b, summary_b)| {
            priority_a
                .cmp(priority_b)
                .then_with(|| summary_a.id.cmp(&summary_b.id))
        });
        Ok(summaries
            .into_iter()
            .map(|(_priority, summary)| summary)
            .collect())
    }

    pub(crate) async fn disable_policy_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        policy_id: Uuid,
    ) -> Result<(), DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let _state_guard = self.state_persist_guard.lock().await;
        let backup = self.backup_state_if_persistent()?;
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

    pub(crate) async fn evaluate_for_agent_impl(
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

    pub(crate) async fn explain_for_agent_impl(
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

    pub(super) fn explain_authorized_request(
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
            // Future-dated spends (wall clock stepped backwards) stay in the
            // evaluated history so a clock step can never reset a budget.
            .filter(|event| Self::spend_event_is_retained(event, retention_start))
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
            // Evaluation reports the first reason a signature would wait for.
            PolicyDecision::ManualApproval(outcomes) => Err(DaemonError::Policy(
                outcomes
                    .into_iter()
                    .next()
                    .unwrap_or(PolicyError::NoApplicablePolicies),
            )),
        }
    }

    pub(super) fn spend_log_retention_start(now: OffsetDateTime) -> OffsetDateTime {
        now - SPEND_LOG_RETENTION
    }

    pub(super) fn prune_spend_log(&self, now: OffsetDateTime) -> Result<(), DaemonError> {
        let retention_start = Self::spend_log_retention_start(now);
        self.spend_log
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .retain(|event| Self::spend_event_is_retained(event, retention_start));
        Ok(())
    }

    /// Both pruning and policy evaluation only drop spends older than the
    /// retention window. Future-dated events are kept and counted on purpose:
    /// a backward wall-clock step must neither erase nor hide recent spends
    /// that still count against daily/weekly limits.
    pub(super) fn spend_event_is_retained(
        event: &SpendEvent,
        retention_start: OffsetDateTime,
    ) -> bool {
        event.at >= retention_start
    }
}

pub(super) fn validate_policy(policy: &SpendingPolicy) -> Result<(), DaemonError> {
    match policy.policy_type {
        agentpay_domain::PolicyType::DailyMaxTxCount => {
            if policy.tx_count_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_tx_count must be greater than zero".to_string(),
                ));
            }
        }
        agentpay_domain::PolicyType::PerTxMaxFeePerGas => {
            if policy.fee_per_gas_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_fee_per_gas_wei must be greater than zero".to_string(),
                ));
            }
        }
        agentpay_domain::PolicyType::PerTxMaxPriorityFeePerGas => {
            if policy.priority_fee_per_gas_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_priority_fee_per_gas_wei must be greater than zero".to_string(),
                ));
            }
        }
        agentpay_domain::PolicyType::PerTxMaxCalldataBytes => {
            if policy.calldata_bytes_limit().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_calldata_bytes must be greater than zero".to_string(),
                ));
            }
        }
        agentpay_domain::PolicyType::PerChainMaxGasSpend => {
            if policy.gas_spend_limit_wei().unwrap_or_default() == 0 {
                return Err(DaemonError::InvalidPolicy(
                    "max_gas_spend_wei must be greater than zero".to_string(),
                ));
            }
        }
        agentpay_domain::PolicyType::Eip712Signing => {
            if policy.eip712_approval_type().is_none() {
                return Err(DaemonError::InvalidPolicy(
                    "approval_type must be set for eip712_signing".to_string(),
                ));
            }
            if !matches!(policy.recipients, agentpay_domain::EntityScope::All) {
                return Err(DaemonError::InvalidPolicy(
                    "eip712_signing recipient scope must be all".to_string(),
                ));
            }
            if !matches!(policy.assets, agentpay_domain::EntityScope::All) {
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
        agentpay_domain::EntityScope::Set(values) if values.is_empty()
    ) {
        return Err(DaemonError::InvalidPolicy(
            "recipient set scope must not be empty".to_string(),
        ));
    }

    if matches!(
        &policy.assets,
        agentpay_domain::EntityScope::Set(values) if values.is_empty()
    ) {
        return Err(DaemonError::InvalidPolicy(
            "asset set scope must not be empty".to_string(),
        ));
    }

    if matches!(
        &policy.networks,
        agentpay_domain::EntityScope::Set(values)
            if values.is_empty() || values.iter().any(|chain_id| *chain_id == 0)
    ) {
        return Err(DaemonError::InvalidPolicy(
            "network set scope must not be empty and must not contain chain_id 0".to_string(),
        ));
    }

    Ok(())
}
