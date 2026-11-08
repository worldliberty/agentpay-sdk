//! `AgentActivity`: an agent's own spend log entries and approval requests,
//! for the agent itself. Read-only; scoped to the authenticated agent key.

use std::cmp::Reverse;

use agentpay_api::rpc::activity::{
    AgentActivityReport, AgentSpend, DEFAULT_ACTIVITY_LIMIT, MAX_ACTIVITY_LIMIT,
};
use agentpay_domain::{ManualApprovalRequest, ManualApprovalStatus};
use agentpay_signer::VaultSignerBackend;
use time::OffsetDateTime;

use crate::{DaemonError, InMemoryDaemon};
use agentpay_api::AgentAuth;

impl<B> InMemoryDaemon<B>
where
    B: VaultSignerBackend,
{
    pub(crate) fn agent_activity_impl(
        &self,
        auth: &AgentAuth,
        since: Option<OffsetDateTime>,
        limit: Option<u16>,
    ) -> Result<AgentActivityReport, DaemonError> {
        let agent_key = self.authenticate_agent(auth.agent_key_id, &auth.agent_auth_token)?;
        let now = OffsetDateTime::now_utc();
        let limit = usize::from(
            limit
                .unwrap_or(DEFAULT_ACTIVITY_LIMIT)
                .min(MAX_ACTIVITY_LIMIT),
        );
        let after = |at: OffsetDateTime| since.is_none_or(|since| at >= since);
        let retention_start = Self::spend_log_retention_start(now);

        let mut spends: Vec<AgentSpend> = self
            .spend_log
            .read()
            .map_err(|_| DaemonError::LockPoisoned)?
            .iter()
            .filter(|event| {
                event.agent_key_id == agent_key.id
                    && Self::spend_event_is_retained(event, retention_start)
                    && after(event.at)
            })
            .map(|event| AgentSpend {
                chain_id: event.chain_id,
                asset: event.asset.clone(),
                recipient: event.recipient.clone(),
                amount_wei: event.amount_wei,
                at: event.at,
                approval_request_id: event.approval_request_id,
            })
            .collect();
        // The log is in signing order; newest first.
        spends.reverse();
        spends.truncate(limit);

        let (mut pending, mut decided): (Vec<ManualApprovalRequest>, Vec<ManualApprovalRequest>) =
            self.retained_manual_approval_requests_at(now)?
                .into_iter()
                .filter(|request| request.agent_key_id == agent_key.id)
                .partition(|request| request.status == ManualApprovalStatus::Pending);
        pending.sort_by_key(|request| Reverse((request.created_at, request.id)));
        decided.retain(|request| after(request.updated_at));
        decided.sort_by_key(|request| Reverse((request.updated_at, request.id)));
        let mut approvals = pending;
        approvals.extend(decided);
        approvals.truncate(limit);

        Ok(AgentActivityReport {
            agent_key_id: agent_key.id,
            spends,
            approvals,
            as_of: now,
        })
    }
}
