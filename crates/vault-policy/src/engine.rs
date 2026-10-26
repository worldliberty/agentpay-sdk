use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use vault_domain::{
    canonical_policy_chain_id, ActionKind, AgentAction, ApprovalType, EntityScope,
    PolicyAttachment, PolicyType, SpendEvent, SpendingPolicy,
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

fn network_scope_allows(scope: &EntityScope<u64>, chain_id: u64) -> bool {
    let canonical_chain_id = canonical_policy_chain_id(chain_id);
    match scope {
        EntityScope::All => true,
        EntityScope::Set(values) => values
            .iter()
            .any(|value| canonical_policy_chain_id(*value) == canonical_chain_id),
    }
}

/// EIP-712 primary types that move funds or grant allowances when signed.
///
/// A blanket `Eip712Signing = Allow` policy must never sign these through the
/// generic typed-data path: the engine cannot project them onto an
/// amount/asset/recipient, so every spending scope would be bypassed. Callers
/// must use the typed [`AgentAction::Permit2Permit`] /
/// [`AgentAction::Eip3009TransferWithAuthorization`] /
/// [`AgentAction::Eip3009ReceiveWithAuthorization`] variants (which the
/// spending policies evaluate) or an eip712 manual-approval policy.
const VALUE_BEARING_EIP712_PRIMARY_TYPES: &[&str] = &[
    "PermitSingle",
    "PermitBatch",
    "PermitTransferFrom",
    "PermitBatchTransferFrom",
    "Permit",
    "TransferWithAuthorization",
    "ReceiveWithAuthorization",
    "SafeTx",
];

/// Canonical Permit2 deployment address (identical on every EVM chain).
const PERMIT2_CANONICAL_ADDRESS: &str = "0x000000000022d473030f116ddee9f6b43ac78ba3";

/// Railgun's Proof of Innocence "unshield-only standby period" — the wallet
/// must wait this long between a successful shield and any private-transfer
/// or third-party unshield. Default matches the protocol spec; public Waku
/// broadcasters refuse to relay transactions that skip it.
pub const RAILGUN_POI_STANDBY: Duration = Duration::hours(1);

/// Returns the most recent Shield spend event for `agent_key_id` whose
/// timestamp falls within the standby window ending at `now`. Used by the
/// PoI standby gate; pure function so tests can exercise it directly.
fn most_recent_shield_within<'a>(
    spend_history: &'a [SpendEvent],
    agent_key_id: Uuid,
    now: OffsetDateTime,
    standby: Duration,
) -> Option<&'a SpendEvent> {
    let window_start = now - standby;
    spend_history
        .iter()
        .filter(|event| {
            event.agent_key_id == agent_key_id
                && matches!(event.action_kind, ActionKind::Shield)
                && event.at >= window_start
                && event.at <= now
        })
        // Latest shield wins: a fresh shield resets the standby clock for the
        // wallet, so we report time-remaining against the most recent one.
        .max_by_key(|event| event.at)
}

/// Returns `Some(PolicyError::PoiStandbyActive)` when `action` is gated by
/// the standby window and a qualifying shield is on the wallet's history.
pub(crate) fn check_poi_standby(
    action: &AgentAction,
    spend_history: &[SpendEvent],
    agent_key_id: Uuid,
    now: OffsetDateTime,
    standby: Duration,
) -> Option<PolicyError> {
    if !matches!(
        action.action_kind(),
        ActionKind::Unshield | ActionKind::PrivateTransfer
    ) {
        return None;
    }
    let recent = most_recent_shield_within(spend_history, agent_key_id, now, standby)?;
    let elapsed = now - recent.at;
    let remaining = standby - elapsed;
    // `Duration::whole_seconds` returns i64; clamp to u64 for the wire shape.
    let standby_required_seconds = standby.whole_seconds().max(0) as u64;
    let standby_remaining_seconds = remaining.whole_seconds().max(0) as u64;
    Some(PolicyError::PoiStandbyActive {
        standby_remaining_seconds,
        standby_required_seconds,
    })
}

/// Stateless policy evaluator. Pass `poi_standby` to enforce the Railgun PoI
/// unshield-only standby window — daemon callers should construct via
/// [`PolicyEngine::with_poi_standby`]; tests use [`PolicyEngine::default`] to
/// keep historical fixtures unaffected.
#[derive(Debug, Default, Clone)]
pub struct PolicyEngine {
    poi_standby: Option<Duration>,
}

impl PolicyEngine {
    /// Engine that enforces the Railgun PoI standby window on
    /// [`AgentAction::Unshield`] and [`AgentAction::PrivateTransfer`]. Pass
    /// [`RAILGUN_POI_STANDBY`] for the spec default (1 hour); a custom value
    /// is useful for tests or for non-mainnet deployments with different
    /// broadcaster policy.
    #[must_use]
    pub fn with_poi_standby(duration: Duration) -> Self {
        Self {
            poi_standby: Some(duration),
        }
    }
}

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
        if action.is_wallet_maintenance() {
            return PolicyExplanation {
                attached_policy_ids,
                applicable_policy_ids: Vec::new(),
                evaluated_policy_ids: Vec::new(),
                decision: PolicyDecision::Allow,
            };
        }

        // PoI standby check fires before per-policy evaluation so a standby
        // violation always wins regardless of which policies happen to be
        // attached. Only Unshield + PrivateTransfer are gated — shielding
        // back-to-back is fine; the constraint is about post-shield outflow.
        if let Some(standby) = self.poi_standby {
            if let Some(err) = check_poi_standby(action, spend_history, agent_key_id, now, standby)
            {
                return PolicyExplanation {
                    attached_policy_ids,
                    applicable_policy_ids: Vec::new(),
                    evaluated_policy_ids: Vec::new(),
                    decision: PolicyDecision::Deny(err),
                };
            }
        }
        if attached.is_empty() {
            // An agent with no enabled policies is never unrestricted, even
            // under `AllPolicies`: typed-data requests fall back to manual
            // approval and everything else is denied outright.
            return PolicyExplanation {
                attached_policy_ids,
                applicable_policy_ids: Vec::new(),
                evaluated_policy_ids: Vec::new(),
                decision: if action.requires_eip712_policy() {
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
                        && network_scope_allows(&p.networks, action_chain_id)
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

            let (evaluated_policy_ids, decision) =
                self.evaluate_applicable(&applicable, action, spend_history, agent_key_id, now);
            return PolicyExplanation {
                attached_policy_ids,
                applicable_policy_ids,
                evaluated_policy_ids,
                decision,
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
                    && network_scope_allows(&p.networks, action_chain_id)
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

        let (evaluated_policy_ids, decision) =
            self.evaluate_applicable(&applicable, action, spend_history, agent_key_id, now);
        PolicyExplanation {
            attached_policy_ids,
            applicable_policy_ids,
            evaluated_policy_ids,
            decision,
        }
    }

    /// Evaluates every applicable policy in priority order and folds the
    /// outcomes into one decision.
    ///
    /// Manual-approval outcomes are *soft* and never short-circuit: evaluation
    /// continues so a later hard limit (daily cap, per-tx max, gas cap, deny
    /// policy, ...) still rejects the request instead of being masked by the
    /// approval prompt. The first hard denial returns immediately; otherwise
    /// the first soft outcome is returned; otherwise the request is allowed.
    ///
    /// Exception: an allow eip712 policy refusing value-bearing typed data is
    /// not final when an eip712 manual-approval policy also applies. That
    /// denial exists to route such payloads to a human, so the request falls
    /// through to the manual-approval outcome (an eip712 deny policy still
    /// hard-denies).
    fn evaluate_applicable(
        &self,
        applicable: &[&SpendingPolicy],
        action: &AgentAction,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        now: OffsetDateTime,
    ) -> (Vec<Uuid>, PolicyDecision) {
        let eip712_manual_approval_applies = applicable
            .iter()
            .any(|policy| policy.eip712_approval_type() == Some(ApprovalType::ManualApproval));
        let mut evaluated_policy_ids = Vec::with_capacity(applicable.len());
        let mut soft_denial: Option<PolicyError> = None;
        for policy in applicable {
            evaluated_policy_ids.push(policy.id);
            match self.evaluate_single_policy(policy, action, spend_history, agent_key_id, now) {
                Ok(()) => {}
                Err(err) if err.is_manual_approval_required() => {
                    if soft_denial.is_none() {
                        soft_denial = Some(err);
                    }
                }
                Err(PolicyError::Eip712ValueBearingTypeDenied { .. })
                    if eip712_manual_approval_applies => {}
                Err(err) => return (evaluated_policy_ids, PolicyDecision::Deny(err)),
            }
        }

        let decision = match soft_denial {
            Some(err) => PolicyDecision::Deny(err),
            None => PolicyDecision::Allow,
        };
        (evaluated_policy_ids, decision)
    }

    /// Returns the primary type when `action` is a generic typed-data request
    /// whose payload is value-bearing: either its `primaryType` is listed in
    /// [`VALUE_BEARING_EIP712_PRIMARY_TYPES`] or its domain is bound to the
    /// canonical Permit2 contract. Unparseable payloads are treated as
    /// value-bearing so the check fails closed.
    fn eip712_value_bearing_primary_type(action: &AgentAction) -> Option<String> {
        if !action.requires_eip712_policy() {
            return None;
        }
        let primary_type = match action.eip712_primary_type() {
            Ok(Some(primary_type)) => primary_type,
            _ => return Some("<unparseable>".to_string()),
        };
        let listed = VALUE_BEARING_EIP712_PRIMARY_TYPES
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(&primary_type));
        let permit2_domain = match action.eip712_verifying_contract() {
            Ok(Some(contract)) => contract.as_str() == PERMIT2_CANONICAL_ADDRESS,
            Ok(None) => false,
            Err(_) => true,
        };
        (listed || permit2_domain).then_some(primary_type)
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
            // Escrow redistributions (Tempo vouchers) spend funds that were already
            // counted against the windows when the escrow was funded, so window
            // limits skip them. Per-tx caps and manual approval still apply. The
            // daemon rejects vouchers for channels it did not open for the same
            // agent key, or above that agent's deposits, before evaluation.
            PolicyType::DailyMaxSpending
            | PolicyType::WeeklyMaxSpending
            | PolicyType::DailyMaxTxCount
                if action.is_escrow_redistribution() => {}
            PolicyType::DailyMaxSpending => self.enforce_window_limit(
                policy,
                spend_history,
                agent_key_id,
                now - Duration::days(1),
                requested_amount_wei,
            )?,
            PolicyType::DailyMaxTxCount => {
                self.enforce_tx_count_window(
                    policy,
                    spend_history,
                    agent_key_id,
                    now - Duration::days(1),
                )?;
            }
            PolicyType::WeeklyMaxSpending => self.enforce_window_limit(
                policy,
                spend_history,
                agent_key_id,
                now - Duration::weeks(1),
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
                    ApprovalType::Allow => {
                        if let Some(primary_type) = Self::eip712_value_bearing_primary_type(action)
                        {
                            return Err(PolicyError::Eip712ValueBearingTypeDenied {
                                policy_id: policy.id,
                                primary_type,
                            });
                        }
                    }
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
            PolicyType::PerTxMaxShieldAmount => {
                if matches!(action.action_kind(), ActionKind::Shield)
                    && requested_amount_wei > policy.max_amount_wei
                {
                    return Err(PolicyError::PerTxLimitExceeded {
                        policy_id: policy.id,
                        max_amount_wei: policy.max_amount_wei,
                        requested_amount_wei,
                    });
                }
            }
            PolicyType::DailyMaxShieldAmount => {
                if matches!(action.action_kind(), ActionKind::Shield) {
                    self.enforce_window_limit_for_kinds(
                        policy,
                        spend_history,
                        agent_key_id,
                        now - Duration::days(1),
                        requested_amount_wei,
                        &[ActionKind::Shield],
                    )?;
                }
            }
            PolicyType::PerTxMaxUnshieldAmount => {
                if matches!(
                    action.action_kind(),
                    ActionKind::Unshield | ActionKind::PrivateTransfer
                ) && requested_amount_wei > policy.max_amount_wei
                {
                    return Err(PolicyError::PerTxLimitExceeded {
                        policy_id: policy.id,
                        max_amount_wei: policy.max_amount_wei,
                        requested_amount_wei,
                    });
                }
            }
            PolicyType::DailyMaxUnshieldAmount => {
                if matches!(
                    action.action_kind(),
                    ActionKind::Unshield | ActionKind::PrivateTransfer
                ) {
                    self.enforce_window_limit_for_kinds(
                        policy,
                        spend_history,
                        agent_key_id,
                        now - Duration::days(1),
                        requested_amount_wei,
                        &[ActionKind::Unshield, ActionKind::PrivateTransfer],
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Same accumulation logic as [`Self::enforce_window_limit`] but restricts
    /// the considered history to events recorded under one of the listed
    /// [`ActionKind`]s. Used by shield/unshield-scoped daily caps so they do
    /// not double-count generic transfer history.
    fn enforce_window_limit_for_kinds(
        &self,
        policy: &SpendingPolicy,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        window_start: OffsetDateTime,
        requested_amount_wei: u128,
        kinds: &[ActionKind],
    ) -> Result<(), PolicyError> {
        let mut used_amount_wei = 0u128;
        let mut overflowed = false;
        for event in spend_history.iter().filter(|event| {
            event.agent_key_id == agent_key_id
                && event.at >= window_start
                && kinds.contains(&event.action_kind)
                && policy.assets.allows(&event.asset)
                && policy.recipients.allows(&event.recipient)
                && network_scope_allows(&policy.networks, event.chain_id)
        }) {
            match used_amount_wei.checked_add(event.amount_wei) {
                Some(next) => used_amount_wei = next,
                None => {
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

    fn enforce_tx_count_window(
        &self,
        policy: &SpendingPolicy,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        window_start: OffsetDateTime,
    ) -> Result<(), PolicyError> {
        let mut used_tx_count = 0u128;
        let overflowed = spend_history
            .iter()
            .filter(|event| {
                event.agent_key_id == agent_key_id
                    && event.at >= window_start
                    && policy.assets.allows(&event.asset)
                    && policy.recipients.allows(&event.recipient)
                    && network_scope_allows(&policy.networks, event.chain_id)
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

    /// Sums in-scope spend since `window_start` and rejects when adding
    /// `requested_amount_wei` would exceed the policy cap.
    ///
    /// The window deliberately has no upper bound: an event stamped after
    /// `now` (the host clock stepped backwards, or a skewed persisted log) is
    /// clamped to `now` and counted, so a clock step can never reset a
    /// rolling budget. The same applies to the tx-count and kind-scoped
    /// windows.
    fn enforce_window_limit(
        &self,
        policy: &SpendingPolicy,
        spend_history: &[SpendEvent],
        agent_key_id: Uuid,
        window_start: OffsetDateTime,
        requested_amount_wei: u128,
    ) -> Result<(), PolicyError> {
        let mut used_amount_wei = 0u128;
        let mut overflowed = false;
        for event in spend_history.iter().filter(|event| {
            event.agent_key_id == agent_key_id
                && event.at >= window_start
                && policy.assets.allows(&event.asset)
                && policy.recipients.allows(&event.recipient)
                && network_scope_allows(&policy.networks, event.chain_id)
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
