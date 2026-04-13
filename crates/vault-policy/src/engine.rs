use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vault_domain::{
    AgentAction, ApprovalType, PolicyAttachment, PolicyType, SpendEvent, SpendingPolicy,
};

use crate::{PolicyDecision, PolicyError, PolicyEvaluation, PolicyExplanation};

pub(crate) fn increment_counter_or_mark_overflow(counter: &mut u128) -> bool {
    match counter.checked_add(1) {
        Some(next) => {
            *counter = next;
            false
        }
        None => {
            *counter = u128::MAX;
            true
        }
    }
}

pub(crate) fn enforce_priority_fee_limit(
    policy: &SpendingPolicy,
    action: &AgentAction,
) -> Result<(), PolicyError> {
    if let Some(requested_max_priority_fee_per_gas_wei) = action.max_priority_fee_per_gas_wei() {
        let max_priority_fee_per_gas_wei = policy.priority_fee_per_gas_limit().unwrap_or_default();
        if requested_max_priority_fee_per_gas_wei > max_priority_fee_per_gas_wei {
            return Err(PolicyError::PriorityFeePerGasLimitExceeded {
                policy_id: policy.id,
                max_priority_fee_per_gas_wei,
                requested_max_priority_fee_per_gas_wei,
            });
        }
    }

    Ok(())
}

pub(crate) fn enforce_calldata_bytes_limit(
    policy: &SpendingPolicy,
    action: &AgentAction,
) -> Result<(), PolicyError> {
    if let Some(requested_calldata_bytes) = action.calldata_len_bytes() {
        let requested_calldata_bytes = requested_calldata_bytes as u128;
        let max_calldata_bytes = policy.calldata_bytes_limit().unwrap_or_default();
        if requested_calldata_bytes > max_calldata_bytes {
            return Err(PolicyError::CalldataBytesLimitExceeded {
                policy_id: policy.id,
                max_calldata_bytes,
                requested_calldata_bytes,
            });
        }
    }

    Ok(())
}

/// Stateless policy evaluator.
#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    fn default_eip712_manual_approval() -> PolicyError {
        PolicyError::Eip712ManualApprovalRequired {
            policy_id: None,
            policy_suffix: String::new(),
        }
    }

    /// Evaluates all applicable policies.
    ///
    /// A request is approved only if every applicable policy passes.
    pub fn evaluate(
        &self,
        policies: &[SpendingPolicy],
        attachment: &PolicyAttachment,
        action: &AgentAction,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<PolicyEvaluation, PolicyError> {
        let explanation = self.explain(
            policies,
            attachment,
            action,
            spend_history,
            agent_key_id,
            now,
        );
        match explanation.decision {
            PolicyDecision::Allow => Ok(PolicyEvaluation {
                evaluated_policy_ids: explanation.evaluated_policy_ids,
            }),
            PolicyDecision::Deny(err) => Err(err),
        }
    }

    /// Builds a detailed explanation for policy evaluation.
    #[must_use]
    pub fn explain(
        &self,
        policies: &[SpendingPolicy],
        attachment: &PolicyAttachment,
        action: &AgentAction,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        now: OffsetDateTime,
    ) -> PolicyExplanation {
        let mut attached: Vec<&SpendingPolicy> = policies
            .iter()
            .filter(|p| p.enabled && attachment.applies_to(p.id))
            .collect();
        attached.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.id.cmp(&b.id)));
        let attached_policy_ids = attached.iter().map(|p| p.id).collect::<Vec<_>>();
        if attached.is_empty() {
            return PolicyExplanation {
                attached_policy_ids,
                applicable_policy_ids: Vec::new(),
                evaluated_policy_ids: Vec::new(),
                decision: if matches!(attachment, PolicyAttachment::AllPolicies) {
                    PolicyDecision::Allow
                } else if action.requires_eip712_policy() {
                    PolicyDecision::Deny(Self::default_eip712_manual_approval())
                } else {
                    PolicyDecision::Deny(PolicyError::NoAttachedPolicies)
                },
            };
        }

        if action.requires_eip712_policy() {
            let action_chain_id = action.chain_id();
            let applicable: Vec<&SpendingPolicy> = attached
                .into_iter()
                .filter(|p| {
                    p.policy_type == PolicyType::Eip712Signing
                        && p.networks.allows(&action_chain_id)
                })
                .collect();
            let applicable_policy_ids = applicable.iter().map(|p| p.id).collect::<Vec<_>>();
            if applicable.is_empty() {
                return PolicyExplanation {
                    attached_policy_ids,
                    applicable_policy_ids,
                    evaluated_policy_ids: Vec::new(),
                    decision: PolicyDecision::Deny(Self::default_eip712_manual_approval()),
                };
            }

            let mut evaluated_policy_ids = Vec::with_capacity(applicable.len());
            for policy in applicable {
                evaluated_policy_ids.push(policy.id);
                if let Err(err) =
                    self.evaluate_single_policy(policy, action, spend_history, agent_key_id, now)
                {
                    return PolicyExplanation {
                        attached_policy_ids,
                        applicable_policy_ids,
                        evaluated_policy_ids,
                        decision: PolicyDecision::Deny(err),
                    };
                }
            }

            return PolicyExplanation {
                attached_policy_ids,
                applicable_policy_ids,
                evaluated_policy_ids,
                decision: PolicyDecision::Allow,
            };
        }

        let action_asset = action.asset();
        let action_recipient = action.recipient();
        let action_chain_id = action.chain_id();

        let applicable: Vec<&SpendingPolicy> = attached
            .into_iter()
            .filter(|p| {
                p.policy_type != PolicyType::Eip712Signing
                    && p.assets.allows(&action_asset)
                    && p.recipients.allows(&action_recipient)
                    && p.networks.allows(&action_chain_id)
            })
            .collect();
        let applicable_policy_ids = applicable.iter().map(|p| p.id).collect::<Vec<_>>();
        if applicable.is_empty() {
            return PolicyExplanation {
                attached_policy_ids,
                applicable_policy_ids,
                evaluated_policy_ids: Vec::new(),
                decision: PolicyDecision::Deny(PolicyError::NoApplicablePolicies),
            };
        }

        let mut evaluated_policy_ids = Vec::with_capacity(applicable.len());
        for policy in applicable {
            evaluated_policy_ids.push(policy.id);
            if let Err(err) =
                self.evaluate_single_policy(policy, action, spend_history, agent_key_id, now)
            {
                return PolicyExplanation {
                    attached_policy_ids,
                    applicable_policy_ids,
                    evaluated_policy_ids,
                    decision: PolicyDecision::Deny(err),
                };
            }
        }

        PolicyExplanation {
            attached_policy_ids,
            applicable_policy_ids,
            evaluated_policy_ids,
            decision: PolicyDecision::Allow,
        }
    }

    fn evaluate_single_policy(
        &self,
        policy: &SpendingPolicy,
        action: &AgentAction,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<(), PolicyError> {
        let requested_amount_wei = action.amount_wei();

        match policy.policy_type {
            PolicyType::PerTxMaxSpending => {
                if requested_amount_wei > policy.max_amount_wei {
                    return Err(PolicyError::PerTxLimitExceeded {
                        policy_id: policy.id,
                        max_amount_wei: policy.max_amount_wei,
                        requested_amount_wei,
                    });
                }
            }
            PolicyType::PerTxMaxFeePerGas => {
                if let Some(requested_max_fee_per_gas_wei) = action.max_fee_per_gas_wei() {
                    let max_fee_per_gas_wei = policy.fee_per_gas_limit().unwrap_or_default();
                    if requested_max_fee_per_gas_wei > max_fee_per_gas_wei {
                        return Err(PolicyError::MaxFeePerGasLimitExceeded {
                            policy_id: policy.id,
                            max_fee_per_gas_wei,
                            requested_max_fee_per_gas_wei,
                        });
                    }
                }
            }
            PolicyType::PerTxMaxPriorityFeePerGas => {
                enforce_priority_fee_limit(policy, action)?;
            }
            PolicyType::PerTxMaxCalldataBytes => {
                enforce_calldata_bytes_limit(policy, action)?;
            }
            PolicyType::DailyMaxSpending => self.enforce_window_limit(
                policy,
                spend_history,
                agent_key_id,
                now - Duration::days(1),
                now,
                requested_amount_wei,
            )?,
            PolicyType::DailyMaxTxCount => {
                self.enforce_tx_count_window(
                    policy,
                    spend_history,
                    agent_key_id,
                    now - Duration::days(1),
                    now,
                )?;
            }
            PolicyType::WeeklyMaxSpending => self.enforce_window_limit(
                policy,
                spend_history,
                agent_key_id,
                now - Duration::weeks(1),
                now,
                requested_amount_wei,
            )?,
            PolicyType::PerChainMaxGasSpend => {
                if let Some(requested_gas_wei) = action.max_gas_spend_wei() {
                    let max_gas_wei = policy.gas_spend_limit_wei().unwrap_or_default();
                    if requested_gas_wei > max_gas_wei {
                        return Err(PolicyError::GasLimitExceeded {
                            policy_id: policy.id,
                            max_gas_wei,
                            requested_gas_wei,
                        });
                    }
                }
            }
            PolicyType::ManualApproval => {
                let effective_min_amount_wei = policy.min_amount_wei.unwrap_or_default();
                if requested_amount_wei > policy.max_amount_wei {
                    return Err(PolicyError::AmountExceeded {
                        policy_id: policy.id,
                        max_amount_wei: policy.max_amount_wei,
                        requested_amount_wei,
                    });
                }
                if requested_amount_wei >= effective_min_amount_wei {
                    return Err(PolicyError::ManualApprovalRequired {
                        policy_id: policy.id,
                        min_amount_wei: Some(effective_min_amount_wei),
                        max_amount_wei: policy.max_amount_wei,
                        requested_amount_wei,
                    });
                }
            }
            PolicyType::Eip712Signing => {
                match policy.eip712_approval_type().unwrap_or(ApprovalType::Allow) {
                    ApprovalType::Allow => {}
                    ApprovalType::ManualApproval => {
                        return Err(PolicyError::Eip712ManualApprovalRequired {
                            policy_id: Some(policy.id),
                            policy_suffix: format!(" (policy {})", policy.id),
                        });
                    }
                    ApprovalType::Deny => {
                        return Err(PolicyError::Eip712SigningDenied {
                            policy_id: policy.id,
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn enforce_tx_count_window(
        &self,
        policy: &SpendingPolicy,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
    ) -> Result<(), PolicyError> {
        let mut used_tx_count = 0u128;
        let overflowed = spend_history
            .iter()
            .filter(|event| {
                event.agent_key_id == agent_key_id
                    && event.at >= window_start
                    && event.at <= window_end
                    && policy.assets.allows(&event.asset)
                    && policy.recipients.allows(&event.recipient)
                    && policy.networks.allows(&event.chain_id)
            })
            .any(|_| increment_counter_or_mark_overflow(&mut used_tx_count));

        let exceeds_window = overflowed
            || used_tx_count
                .checked_add(1)
                .is_none_or(|total| total > policy.tx_count_limit().unwrap_or_default());
        if exceeds_window {
            return Err(PolicyError::TxCountLimitExceeded {
                policy_id: policy.id,
                used_tx_count,
                max_tx_count: policy.tx_count_limit().unwrap_or_default(),
            });
        }

        Ok(())
    }

    fn enforce_window_limit(
        &self,
        policy: &SpendingPolicy,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        window_start: OffsetDateTime,
        window_end: OffsetDateTime,
        requested_amount_wei: u128,
    ) -> Result<(), PolicyError> {
        let mut used_amount_wei = 0u128;
        let mut overflowed = false;
        for event in spend_history.iter().filter(|event| {
            event.agent_key_id == agent_key_id
                && event.at >= window_start
                && event.at <= window_end
                && policy.assets.allows(&event.asset)
                && policy.recipients.allows(&event.recipient)
                && policy.networks.allows(&event.chain_id)
        }) {
            match used_amount_wei.checked_add(event.amount_wei) {
                Some(next) => used_amount_wei = next,
                None => {
                    // Overflow indicates history already exceeded representable
                    // accounting bounds. Reject instead of undercounting.
                    overflowed = true;
                    used_amount_wei = u128::MAX;
                    break;
                }
            }
        }

        let exceeds_window = overflowed
            || used_amount_wei
                .checked_add(requested_amount_wei)
                .is_none_or(|total| total > policy.max_amount_wei);

        if exceeds_window {
            return Err(PolicyError::WindowLimitExceeded {
                policy_id: policy.id,
                used_amount_wei,
                requested_amount_wei,
                max_amount_wei: policy.max_amount_wei,
            });
        }

        Ok(())
    }
}
