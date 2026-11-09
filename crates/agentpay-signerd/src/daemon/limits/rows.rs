//! Pure translation between spending limit rows and policies: validation,
//! building the policies of a row, reading rows back from policies, and
//! computing usage from the spend log.

use std::collections::{BTreeMap, BTreeSet};

use agentpay_api::rpc::limits::{
    SpendingLimit, SpendingLimitStatus, SpendingUsage, MAX_SPENDING_LIMITS,
};
use agentpay_domain::{
    canonical_policy_chain_id, is_solana_chain_id, AssetId, EntityScope, OverLimit, PolicyType,
    RecipientId, SpendEvent, SpendingPolicy,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::DaemonError;

/// Priority of the first row's policies; each row gets its own block.
const PRIORITY_BASE: u32 = 1_000;
/// Priority distance between consecutive rows.
const PRIORITY_STRIDE: u32 = 100;

fn invalid(reason: String) -> DaemonError {
    DaemonError::InvalidSpendingLimits(reason)
}

/// Validates a complete limit set and returns it with canonical chain ids.
pub(crate) fn validate_limits(
    limits: Vec<SpendingLimit>,
) -> Result<Vec<SpendingLimit>, DaemonError> {
    if limits.is_empty() {
        return Err(invalid(
            "at least one limit is required; to stop an agent from spending, revoke its key"
                .to_string(),
        ));
    }
    if limits.len() > MAX_SPENDING_LIMITS {
        return Err(invalid(format!(
            "at most {MAX_SPENDING_LIMITS} limits are allowed"
        )));
    }
    let mut seen = BTreeSet::new();
    limits
        .into_iter()
        .map(|mut limit| {
            validate_limit(&limit)?;
            limit.chain_id = canonical_policy_chain_id(limit.chain_id);
            if !seen.insert((limit.chain_id, limit.asset.clone())) {
                return Err(invalid(format!(
                    "{} on chain {} is listed twice",
                    limit.asset, limit.chain_id
                )));
            }
            Ok(limit)
        })
        .collect()
}

fn validate_limit(limit: &SpendingLimit) -> Result<(), DaemonError> {
    let label = format!("{} on chain {}", limit.asset, limit.chain_id);
    if limit.chain_id == 0 {
        return Err(invalid("chain_id must not be 0".to_string()));
    }
    let solana_chain = is_solana_chain_id(limit.chain_id);
    let solana_asset = matches!(limit.asset, AssetId::NativeSol | AssetId::SplToken(_));
    if solana_chain != solana_asset {
        return Err(invalid(format!(
            "{label}: the asset does not belong to the chain's family"
        )));
    }
    if limit.per_tx_max_wei == 0 {
        return Err(invalid(format!(
            "{label}: per_tx_max_wei must be greater than zero"
        )));
    }
    if limit.daily_max_wei < limit.per_tx_max_wei {
        return Err(invalid(format!(
            "{label}: daily_max_wei must be at least per_tx_max_wei"
        )));
    }
    if limit.weekly_max_wei < limit.daily_max_wei {
        return Err(invalid(format!(
            "{label}: weekly_max_wei must be at least daily_max_wei"
        )));
    }
    let optional = [
        ("max_gas_per_tx_wei", limit.max_gas_per_tx_wei, true),
        ("max_fee_per_gas_wei", limit.max_fee_per_gas_wei, true),
        (
            "max_priority_fee_per_gas_wei",
            limit.max_priority_fee_per_gas_wei,
            true,
        ),
        ("daily_max_tx_count", limit.daily_max_tx_count, false),
    ];
    for (field, value, evm_only) in optional {
        match value {
            Some(0) => {
                return Err(invalid(format!(
                    "{label}: {field} must be greater than zero when set"
                )))
            }
            Some(_) if evm_only && solana_chain => {
                return Err(invalid(format!(
                    "{label}: {field} applies to EVM chains only"
                )))
            }
            _ => {}
        }
    }
    Ok(())
}

/// Builds the policies of every row: each scoped to all recipients, the
/// row's asset, and the row's network, so no row makes another asset
/// spendable. The per-payment, daily, weekly, and daily-count limits hold a
/// payment beyond them for approval (`over_limit: manual_approval`); the gas
/// and fee caps deny.
pub(crate) fn build_policies(limits: &[SpendingLimit]) -> Result<Vec<SpendingPolicy>, DaemonError> {
    let mut policies = Vec::new();
    for (index, limit) in limits.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| invalid("too many limits".to_string()))?;
        let base = PRIORITY_BASE + index * PRIORITY_STRIDE;
        let assets = EntityScope::Set(BTreeSet::from([limit.asset.clone()]));
        let networks = EntityScope::Set(BTreeSet::from([limit.chain_id]));
        let policy = |priority: u32, policy_type: PolicyType, value: u128| {
            let over_limit = if SpendingPolicy::supports_over_limit_approval(policy_type) {
                OverLimit::ManualApproval
            } else {
                OverLimit::Deny
            };
            SpendingPolicy::new_with_recipient_scope(
                priority,
                policy_type,
                value,
                EntityScope::<RecipientId>::All,
                assets.clone(),
                networks.clone(),
            )
            .and_then(|policy| policy.with_over_limit(over_limit))
            .map_err(|err| {
                invalid(format!(
                    "{} on chain {}: {err}",
                    limit.asset, limit.chain_id
                ))
            })
        };
        policies.push(policy(
            base,
            PolicyType::PerTxMaxSpending,
            limit.per_tx_max_wei,
        )?);
        policies.push(policy(
            base + 1,
            PolicyType::DailyMaxSpending,
            limit.daily_max_wei,
        )?);
        policies.push(policy(
            base + 2,
            PolicyType::WeeklyMaxSpending,
            limit.weekly_max_wei,
        )?);
        let optional = [
            (4, PolicyType::PerChainMaxGasSpend, limit.max_gas_per_tx_wei),
            (5, PolicyType::PerTxMaxFeePerGas, limit.max_fee_per_gas_wei),
            (
                6,
                PolicyType::PerTxMaxPriorityFeePerGas,
                limit.max_priority_fee_per_gas_wei,
            ),
            (7, PolicyType::DailyMaxTxCount, limit.daily_max_tx_count),
        ];
        for (offset, policy_type, value) in optional {
            if let Some(value) = value {
                policies.push(policy(base + offset, policy_type, value)?);
            }
        }
    }
    Ok(policies)
}

/// The network and asset a policy limits as part of a row, if it can be one.
/// A legacy `ManualApproval` range policy (API 1.0 rows) still belongs to
/// its row, so replacing the rows retires it, but sets no row field.
fn row_key(policy: &SpendingPolicy) -> Option<(u64, AssetId)> {
    let row_type = matches!(
        policy.policy_type,
        PolicyType::PerTxMaxSpending
            | PolicyType::DailyMaxSpending
            | PolicyType::WeeklyMaxSpending
            | PolicyType::PerChainMaxGasSpend
            | PolicyType::PerTxMaxFeePerGas
            | PolicyType::PerTxMaxPriorityFeePerGas
            | PolicyType::DailyMaxTxCount
    ) || (policy.policy_type == PolicyType::ManualApproval
        && policy.min_amount_wei.is_some_and(|min| min > 0));
    let (EntityScope::All, EntityScope::Set(assets), EntityScope::Set(networks)) =
        (&policy.recipients, &policy.assets, &policy.networks)
    else {
        return None;
    };
    if !row_type || assets.len() != 1 || networks.len() != 1 {
        return None;
    }
    let asset = assets.iter().next()?.clone();
    let chain_id = canonical_policy_chain_id(*networks.iter().next()?);
    Some((chain_id, asset))
}

fn min_of(current: Option<u128>, value: Option<u128>) -> Option<u128> {
    match (current, value) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Reads rows back from the enabled spending policies that govern an agent.
///
/// Returns the rows (with their policy ids) sorted by network and asset, and
/// the ids of spending policies that are not part of a complete row.
pub(crate) fn derive_rows(
    policies: &[&SpendingPolicy],
) -> (Vec<(SpendingLimit, Vec<Uuid>)>, Vec<Uuid>) {
    let mut groups: BTreeMap<(u64, AssetId), Vec<&SpendingPolicy>> = BTreeMap::new();
    let mut other = Vec::new();
    for policy in policies {
        if policy.policy_type == PolicyType::Eip712Signing {
            continue;
        }
        match row_key(policy) {
            Some(key) => groups.entry(key).or_default().push(policy),
            None => other.push(policy.id),
        }
    }
    let mut rows = Vec::new();
    for ((chain_id, asset), members) in groups {
        let amount = |policy_type: PolicyType| {
            members
                .iter()
                .filter(|policy| policy.policy_type == policy_type)
                .map(|policy| policy.max_amount_wei)
                .min()
        };
        let mut ids: Vec<Uuid> = members.iter().map(|policy| policy.id).collect();
        ids.sort_unstable();
        let (Some(per_tx), Some(daily), Some(weekly)) = (
            amount(PolicyType::PerTxMaxSpending),
            amount(PolicyType::DailyMaxSpending),
            amount(PolicyType::WeeklyMaxSpending),
        ) else {
            other.extend(ids);
            continue;
        };
        let mut limit = SpendingLimit {
            chain_id,
            asset,
            per_tx_max_wei: per_tx,
            daily_max_wei: daily,
            weekly_max_wei: weekly,
            max_gas_per_tx_wei: None,
            max_fee_per_gas_wei: None,
            max_priority_fee_per_gas_wei: None,
            daily_max_tx_count: None,
        };
        for policy in &members {
            match policy.policy_type {
                PolicyType::PerChainMaxGasSpend => {
                    limit.max_gas_per_tx_wei =
                        min_of(limit.max_gas_per_tx_wei, policy.gas_spend_limit_wei());
                }
                PolicyType::PerTxMaxFeePerGas => {
                    limit.max_fee_per_gas_wei =
                        min_of(limit.max_fee_per_gas_wei, policy.fee_per_gas_limit());
                }
                PolicyType::PerTxMaxPriorityFeePerGas => {
                    limit.max_priority_fee_per_gas_wei = min_of(
                        limit.max_priority_fee_per_gas_wei,
                        policy.priority_fee_per_gas_limit(),
                    );
                }
                PolicyType::DailyMaxTxCount => {
                    limit.daily_max_tx_count =
                        min_of(limit.daily_max_tx_count, policy.tx_count_limit());
                }
                _ => {}
            }
        }
        rows.push((limit, ids));
    }
    other.sort_unstable();
    (rows, other)
}

/// How much of `limit` the agent has used, counted as the policy engine counts it.
pub(crate) fn usage(
    limit: &SpendingLimit,
    spend_log: &[SpendEvent],
    agent_key_id: Uuid,
    now: OffsetDateTime,
) -> SpendingUsage {
    let day_start = now - Duration::days(1);
    let week_start = now - Duration::weeks(1);
    let mut spent_24h: u128 = 0;
    let mut spent_7d: u128 = 0;
    let mut tx_count_24h: u64 = 0;
    for event in spend_log.iter().filter(|event| {
        event.agent_key_id == agent_key_id
            && event.asset == limit.asset
            && canonical_policy_chain_id(event.chain_id) == limit.chain_id
    }) {
        // Future-dated spends (the clock stepped back) count, as in the engine.
        if event.at >= week_start {
            spent_7d = spent_7d.saturating_add(event.amount_wei);
        }
        if event.at >= day_start {
            spent_24h = spent_24h.saturating_add(event.amount_wei);
            tx_count_24h = tx_count_24h.saturating_add(1);
        }
    }
    let remaining_24h = limit.daily_max_wei.saturating_sub(spent_24h);
    let remaining_7d = limit.weekly_max_wei.saturating_sub(spent_7d);
    let tx_count_exhausted = limit
        .daily_max_tx_count
        .is_some_and(|max| u128::from(tx_count_24h) >= max);
    let available_now = if tx_count_exhausted {
        0
    } else {
        limit.per_tx_max_wei.min(remaining_24h).min(remaining_7d)
    };
    SpendingUsage {
        spent_24h_wei: spent_24h,
        spent_7d_wei: spent_7d,
        tx_count_24h,
        remaining_24h_wei: remaining_24h,
        remaining_7d_wei: remaining_7d,
        available_now_wei: available_now,
    }
}

/// Rows with usage, in report order.
pub(crate) fn statuses(
    rows: Vec<(SpendingLimit, Vec<Uuid>)>,
    spend_log: &[SpendEvent],
    agent_key_id: Uuid,
    now: OffsetDateTime,
) -> Vec<SpendingLimitStatus> {
    rows.into_iter()
        .map(|(limit, policy_ids)| SpendingLimitStatus {
            usage: usage(&limit, spend_log, agent_key_id, now),
            limit,
            policy_ids,
        })
        .collect()
}
