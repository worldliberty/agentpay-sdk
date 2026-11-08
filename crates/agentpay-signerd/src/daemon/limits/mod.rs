//! `ListSpendingLimits` and `SetSpendingLimits`: an agent's spending limit
//! rows, kept as ordinary policies (see `agentpay_api::rpc::limits`).
//!
//! Deny by default: setting limits attaches exactly the rows' policies (plus
//! the agent's generic EIP-712 policies) as a `PolicySet`, so an asset without
//! a row has no applicable policy and is never spendable.

mod rows;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use agentpay_api::rpc::limits::{SpendingLimit, SpendingLimitsReport};
use agentpay_domain::{AdminAuth, AgentKey, PolicyAttachment, PolicyType, SpendingPolicy};
use agentpay_signer::VaultSignerBackend;
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) use self::rows::{build_policies, validate_limits};
use crate::{DaemonError, InMemoryDaemon, RequestContext};

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) fn list_spending_limits_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        agent_key_id: Uuid,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        let now = OffsetDateTime::now_utc();
        self.authorize_admin(ctx, auth, now)?;
        self.spending_limits_report(agent_key_id, now)
    }

    pub(crate) async fn set_spending_limits_impl(
        &self,
        ctx: &RequestContext,
        auth: &AdminAuth,
        agent_key_id: Uuid,
        limits: Vec<SpendingLimit>,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        self.authorize_admin(ctx, auth, OffsetDateTime::now_utc())?;
        let limits = validate_limits(limits)?;
        let policies = build_policies(&limits)?;
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
        if let Err(err) = self.replace_agent_limit_policies(agent_key_id, policies) {
            if let Some(snapshot) = backup {
                self.restore_state(snapshot)?;
            }
            return Err(err);
        }
        self.persist_or_revert(backup)?;
        self.spending_limits_report(agent_key_id, OffsetDateTime::now_utc())
    }

    /// The agent's rows and usage, read from its enabled policies.
    pub(super) fn spending_limits_report(
        &self,
        agent_key_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<SpendingLimitsReport, DaemonError> {
        let agent_key = self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .cloned()
            .ok_or(DaemonError::UnknownAgentKey(agent_key_id))?;
        let (rows, other_policy_ids) = {
            let policies = self
                .policies
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?;
            let governing: Vec<&SpendingPolicy> = policies
                .values()
                .filter(|policy| policy.enabled && agent_key.policies.applies_to(policy.id))
                .collect();
            rows::derive_rows(&governing)
        };
        let spend_log = self
            .spend_log
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .clone();
        Ok(SpendingLimitsReport {
            agent_key_id,
            limits: rows::statuses(rows, &spend_log, agent_key_id, now),
            other_policy_ids,
            as_of: now,
        })
    }

    /// Adds `new_policies` and makes them (plus the agent's enabled
    /// `Eip712Signing` policies) the agent's whole `PolicySet`. The agent's
    /// previous spending policies are disabled when no other agent key can
    /// be governed by them, and only detached otherwise.
    ///
    /// The caller holds the signing and state guards, has checked that the
    /// agent exists, and persists (or restores its snapshot on error).
    pub(super) fn replace_agent_limit_policies(
        &self,
        agent_key_id: Uuid,
        new_policies: Vec<SpendingPolicy>,
    ) -> Result<(), DaemonError> {
        let agent_key = self
            .agent_keys
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get(&agent_key_id)
            .cloned()
            .ok_or(DaemonError::UnknownAgentKey(agent_key_id))?;
        let (previous_spending, kept_typed_data) = self.governing_policy_ids(&agent_key)?;
        let mut attached = self.insert_new_policies(new_policies)?;
        attached.extend(kept_typed_data);
        self.agent_keys
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?
            .get_mut(&agent_key_id)
            .ok_or(DaemonError::UnknownAgentKey(agent_key_id))?
            .policies = PolicyAttachment::policy_set(attached)
            .map_err(|err| DaemonError::InvalidPolicyAttachment(err.to_string()))?;
        self.retire_unused_policies(&previous_spending)
    }

    /// Splits the enabled policies governing `agent_key` into spending
    /// policies and generic EIP-712 policies.
    pub(super) fn governing_policy_ids(
        &self,
        agent_key: &AgentKey,
    ) -> Result<(BTreeSet<Uuid>, BTreeSet<Uuid>), DaemonError> {
        let policies = self
            .policies
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let (typed_data, spending): (Vec<&SpendingPolicy>, Vec<&SpendingPolicy>) = policies
            .values()
            .filter(|policy| policy.enabled && agent_key.policies.applies_to(policy.id))
            .partition(|policy| policy.policy_type == PolicyType::Eip712Signing);
        Ok((
            spending.into_iter().map(|policy| policy.id).collect(),
            typed_data.into_iter().map(|policy| policy.id).collect(),
        ))
    }

    /// Inserts freshly built policies and returns their ids.
    pub(super) fn insert_new_policies(
        &self,
        new_policies: Vec<SpendingPolicy>,
    ) -> Result<BTreeSet<Uuid>, DaemonError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        let mut ids = BTreeSet::new();
        for policy in new_policies {
            if policies.contains_key(&policy.id) || !ids.insert(policy.id) {
                return Err(DaemonError::InvalidPolicy(format!(
                    "policy id {} already exists",
                    policy.id
                )));
            }
            policies.insert(policy.id, policy);
        }
        Ok(ids)
    }

    /// Disables each of `candidates` that no remaining agent key can be
    /// governed by: none lists it in its `PolicySet`, and none is attached to
    /// `AllPolicies` (which would be governed by every enabled policy).
    pub(super) fn retire_unused_policies(
        &self,
        candidates: &BTreeSet<Uuid>,
    ) -> Result<(), DaemonError> {
        let in_use: Vec<Uuid> = {
            let agent_keys = self
                .agent_keys
                .read()
                .map_err(|_| DaemonError::LockPoisoned)?;
            candidates
                .iter()
                .copied()
                .filter(|id| {
                    agent_keys
                        .values()
                        .any(|agent| agent.policies.applies_to(*id))
                })
                .collect()
        };
        let mut policies = self
            .policies
            .write()
            .map_err(|_| DaemonError::LockPoisoned)?;
        for id in candidates.iter().filter(|id| !in_use.contains(id)) {
            if let Some(policy) = policies.get_mut(id) {
                policy.enabled = false;
            }
        }
        Ok(())
    }
}
