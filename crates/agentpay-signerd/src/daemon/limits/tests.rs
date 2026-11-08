//! Row validation, policy building, reading rows back, and usage.

use std::collections::BTreeSet;

use agentpay_api::rpc::limits::SpendingLimit;
use agentpay_domain::{
    AssetId, EntityScope, OverLimit, PolicyType, RecipientId, SpendEvent, SpendingPolicy,
    SOLANA_DEVNET_CHAIN_ID, SOLANA_MAINNET_CHAIN_ID,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::rows::{build_policies, derive_rows, usage, validate_limits};
use crate::DaemonError;

fn usd1() -> AssetId {
    AssetId::Erc20(
        "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
            .parse()
            .expect("token"),
    )
}

fn row(chain_id: u64, asset: AssetId) -> SpendingLimit {
    SpendingLimit {
        chain_id,
        asset,
        per_tx_max_wei: 100,
        daily_max_wei: 500,
        weekly_max_wei: 1_000,
        max_gas_per_tx_wei: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        daily_max_tx_count: None,
    }
}

fn full_row() -> SpendingLimit {
    SpendingLimit {
        max_gas_per_tx_wei: Some(7),
        max_fee_per_gas_wei: Some(8),
        max_priority_fee_per_gas_wei: Some(9),
        daily_max_tx_count: Some(10),
        ..row(56, usd1())
    }
}

fn rejects(limits: Vec<SpendingLimit>, needle: &str) {
    match validate_limits(limits) {
        Err(DaemonError::InvalidSpendingLimits(reason)) => {
            assert!(reason.contains(needle), "{reason} should mention {needle}");
        }
        other => panic!("expected InvalidSpendingLimits({needle}), got {other:?}"),
    }
}

#[test]
fn validation_rejects_every_unsafe_or_inconsistent_row() {
    rejects(Vec::new(), "at least one limit");
    rejects(vec![row(56, usd1()); 65], "at most 64");
    rejects(vec![row(0, usd1())], "chain_id");
    rejects(vec![row(56, AssetId::NativeSol)], "family");
    rejects(vec![row(SOLANA_MAINNET_CHAIN_ID, usd1())], "family");
    rejects(
        vec![SpendingLimit {
            per_tx_max_wei: 0,
            ..row(56, usd1())
        }],
        "per_tx_max_wei",
    );
    rejects(
        vec![SpendingLimit {
            daily_max_wei: 99,
            ..row(56, usd1())
        }],
        "daily_max_wei",
    );
    rejects(
        vec![SpendingLimit {
            weekly_max_wei: 499,
            ..row(56, usd1())
        }],
        "weekly_max_wei",
    );
    rejects(
        vec![SpendingLimit {
            daily_max_tx_count: Some(0),
            ..row(56, usd1())
        }],
        "daily_max_tx_count",
    );
    rejects(
        vec![SpendingLimit {
            max_fee_per_gas_wei: Some(1),
            ..row(SOLANA_MAINNET_CHAIN_ID, AssetId::NativeSol)
        }],
        "EVM chains only",
    );
    rejects(vec![row(56, usd1()), row(56, usd1())], "listed twice");
    // Every Solana cluster is one policy network, so these are duplicates too.
    rejects(
        vec![
            row(SOLANA_MAINNET_CHAIN_ID, AssetId::NativeSol),
            row(SOLANA_DEVNET_CHAIN_ID, AssetId::NativeSol),
        ],
        "listed twice",
    );
}

#[test]
fn validation_canonicalizes_solana_networks() {
    let limits =
        validate_limits(vec![row(SOLANA_DEVNET_CHAIN_ID, AssetId::NativeSol)]).expect("valid");
    assert_eq!(limits[0].chain_id, SOLANA_MAINNET_CHAIN_ID);
}

#[test]
fn every_built_policy_is_scoped_to_its_row() {
    let limits = vec![full_row(), row(56, AssetId::NativeEth)];
    let policies = build_policies(&limits).expect("policies");
    assert_eq!(policies.len(), 7 + 3);
    for policy in &policies {
        assert!(matches!(policy.recipients, EntityScope::<RecipientId>::All));
        assert!(matches!(&policy.networks, EntityScope::Set(set) if set == &BTreeSet::from([56])));
        let EntityScope::Set(assets) = &policy.assets else {
            panic!("{:?} is not scoped to one asset", policy.policy_type);
        };
        assert_eq!(assets.len(), 1, "gas caps too are scoped to the asset");
    }
    let types: Vec<(PolicyType, OverLimit)> = policies
        .iter()
        .take(7)
        .map(|p| (p.policy_type, p.over_limit))
        .collect();
    // Going beyond an amount or count limit asks for approval; gas and fee
    // caps deny. No separate `ManualApproval` policy is created.
    assert_eq!(
        types,
        [
            (PolicyType::PerTxMaxSpending, OverLimit::ManualApproval),
            (PolicyType::DailyMaxSpending, OverLimit::ManualApproval),
            (PolicyType::WeeklyMaxSpending, OverLimit::ManualApproval),
            (PolicyType::PerChainMaxGasSpend, OverLimit::Deny),
            (PolicyType::PerTxMaxFeePerGas, OverLimit::Deny),
            (PolicyType::PerTxMaxPriorityFeePerGas, OverLimit::Deny),
            (PolicyType::DailyMaxTxCount, OverLimit::ManualApproval),
        ]
    );
}

#[test]
fn a_legacy_manual_approval_range_belongs_to_its_row_but_sets_nothing() {
    let limits = validate_limits(vec![row(56, usd1())]).expect("valid");
    let mut policies = build_policies(&limits).expect("policies");
    let legacy = SpendingPolicy::new_manual_approval_with_recipient_scope(
        1_003,
        50,
        100,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([usd1()])),
        EntityScope::Set(BTreeSet::from([56])),
    )
    .expect("legacy range");
    policies.push(legacy.clone());
    let refs: Vec<&SpendingPolicy> = policies.iter().collect();
    let (rows, other) = derive_rows(&refs);
    assert!(other.is_empty(), "replacing the rows retires it");
    assert_eq!(rows[0].0, limits[0]);
    assert!(rows[0].1.contains(&legacy.id));
}

#[test]
fn rows_read_back_exactly_and_foreign_policies_are_reported() {
    let limits = validate_limits(vec![full_row(), row(56, AssetId::NativeEth)]).expect("valid");
    let mut policies = build_policies(&limits).expect("policies");
    let global = SpendingPolicy::new_with_recipient_scope(
        1,
        PolicyType::PerTxMaxSpending,
        5,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("global policy");
    // A row without a weekly cap is incomplete: its policies are "other".
    let partial = build_policies(&[row(1, AssetId::NativeEth)]).expect("partial");
    let partial_ids: Vec<Uuid> = partial.iter().take(2).map(|p| p.id).collect();
    policies.push(global.clone());
    policies.extend(partial.into_iter().take(2));
    let refs: Vec<&SpendingPolicy> = policies.iter().collect();
    let (rows, other) = derive_rows(&refs);
    let read_back: Vec<SpendingLimit> = rows.iter().map(|(limit, _)| limit.clone()).collect();
    // Sorted by network, then asset (native before ERC-20).
    assert_eq!(read_back, vec![limits[1].clone(), limits[0].clone()]);
    assert_eq!(rows[1].1.len(), 7);
    let mut expected_other = partial_ids;
    expected_other.push(global.id);
    expected_other.sort_unstable();
    assert_eq!(other, expected_other);
}

#[test]
fn the_strictest_duplicate_cap_is_shown() {
    let mut policies = build_policies(&[row(56, usd1())]).expect("policies");
    policies.extend(
        build_policies(&[SpendingLimit {
            per_tx_max_wei: 40,
            ..row(56, usd1())
        }])
        .expect("stricter"),
    );
    let refs: Vec<&SpendingPolicy> = policies.iter().collect();
    let (rows, other) = derive_rows(&refs);
    assert!(other.is_empty());
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0.per_tx_max_wei, 40);
    assert_eq!(rows[0].1.len(), 6);
}

#[test]
fn usage_counts_windows_like_the_policy_engine() {
    let agent = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let spend =
        |amount: u128, at: OffsetDateTime, asset: AssetId, chain_id: u64, who: Uuid| SpendEvent {
            agent_key_id: who,
            chain_id,
            asset,
            recipient: RecipientId::Evm(
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .expect("recipient"),
            ),
            amount_wei: amount,
            at,
            approval_request_id: None,
        };
    let log = vec![
        spend(30, now - Duration::hours(1), usd1(), 56, agent),
        // A clock step back: future spends count.
        spend(20, now + Duration::hours(1), usd1(), 56, agent),
        spend(400, now - Duration::days(3), usd1(), 56, agent),
        spend(999, now - Duration::days(8), usd1(), 56, agent),
        spend(7, now, AssetId::NativeEth, 56, agent),
        spend(7, now, usd1(), 1, agent),
        spend(7, now, usd1(), 56, Uuid::new_v4()),
    ];
    let limit = SpendingLimit {
        daily_max_tx_count: Some(5),
        ..row(56, usd1())
    };
    let used = usage(&limit, &log, agent, now);
    assert_eq!(used.spent_24h_wei, 50);
    assert_eq!(used.spent_7d_wei, 450);
    assert_eq!(used.tx_count_24h, 2);
    assert_eq!(used.remaining_24h_wei, 450);
    assert_eq!(used.remaining_7d_wei, 550);
    assert_eq!(used.available_now_wei, 100);

    let tight = SpendingLimit {
        weekly_max_wei: 480,
        daily_max_tx_count: Some(2),
        ..row(56, usd1())
    };
    let used = usage(&tight, &log, agent, now);
    assert_eq!(used.remaining_7d_wei, 30);
    assert_eq!(used.available_now_wei, 0, "the tx count is used up");
    let over = SpendingLimit {
        weekly_max_wei: 500,
        daily_max_wei: 500,
        ..row(56, usd1())
    };
    let mut heavy = log.clone();
    heavy.push(spend(u128::MAX, now, usd1(), 56, agent));
    let used = usage(&over, &heavy, agent, now);
    assert_eq!(
        used.spent_24h_wei,
        u128::MAX,
        "sums saturate instead of wrapping"
    );
    assert_eq!((used.remaining_24h_wei, used.available_now_wei), (0, 0));
}
