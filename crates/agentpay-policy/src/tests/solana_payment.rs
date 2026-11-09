//! `SolanaPaymentTransaction`: policies see one payment of the sum of all
//! legs, and recipient scopes must cover every leg.

use agentpay_domain::{
    ApprovalLimit, OverLimit, RecipientId, SolanaPaymentAsset, SolanaPaymentLeg,
    SolanaPaymentTransaction, SolanaTokenProgram,
};

use super::*;

const MINT: &str = "So11111111111111111111111111111111111111112";
const OTHER_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
const PRIMARY: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SPLIT: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

fn leg(recipient: &str, amount_wei: u128) -> SolanaPaymentLeg {
    SolanaPaymentLeg {
        recipient_owner: solana_addr(recipient),
        amount_wei,
        create_ata: false,
        memo: None,
    }
}

fn payment(chain_id: u64, legs: Vec<SolanaPaymentLeg>) -> AgentAction {
    AgentAction::SolanaPaymentTransaction {
        payment: SolanaPaymentTransaction {
            chain_id,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
            fee_payer: solana_addr("11111111111111111111111111111111"),
            asset: SolanaPaymentAsset::SplToken {
                mint: solana_addr(MINT),
                decimals: 6,
                token_program: SolanaTokenProgram::Token,
            },
            transfers: legs,
            memo: Some("order-1".to_string()),
            compute_unit_limit: None,
            compute_unit_price_micro_lamports: None,
        },
    }
}

fn split_payment(primary: u128, split: u128) -> AgentAction {
    payment(
        SOLANA_DEVNET_CHAIN_ID,
        vec![leg(PRIMARY, primary), leg(SPLIT, split)],
    )
}

fn solana_policy(
    policy_type: PolicyType,
    max: u128,
    recipients: EntityScope<RecipientId>,
    assets: EntityScope<AssetId>,
) -> SpendingPolicy {
    SpendingPolicy::new_with_recipient_scope(
        1,
        policy_type,
        max,
        recipients,
        assets,
        EntityScope::Set(BTreeSet::from([SOLANA_MAINNET_CHAIN_ID])),
    )
    .expect("policy")
}

fn recipients(values: &[&str]) -> EntityScope<RecipientId> {
    EntityScope::Set(
        values
            .iter()
            .map(|value| RecipientId::Solana(solana_addr(value)))
            .collect(),
    )
}

fn evaluate(
    policies: &[SpendingPolicy],
    action: &AgentAction,
    history: &[SpendEvent],
    agent_key_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), PolicyError> {
    PolicyEngine
        .evaluate(
            policies,
            &PolicyAttachment::AllPolicies,
            action,
            history,
            agent_key_id,
            now,
        )
        .map(|_| ())
}

#[test]
fn per_tx_limit_checks_the_sum_of_all_legs() {
    let policy = solana_policy(
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
    );
    let now = OffsetDateTime::now_utc();

    evaluate(
        std::slice::from_ref(&policy),
        &split_payment(90, 10),
        &[],
        Uuid::new_v4(),
        now,
    )
    .expect("a total at the limit is allowed");
    let err = evaluate(&[policy], &split_payment(90, 11), &[], Uuid::new_v4(), now)
        .expect_err("a total above the limit is denied");
    assert!(matches!(
        err,
        PolicyError::PerTxLimitExceeded {
            max_amount_wei: 100,
            requested_amount_wei: 101,
            ..
        }
    ));
}

#[test]
fn window_limit_counts_history_on_every_solana_cluster_plus_the_sum() {
    let agent_key_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let policy = solana_policy(
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
    );
    let earlier = split_payment(30, 10);
    let history = vec![SpendEvent {
        agent_key_id,
        chain_id: earlier.chain_id(),
        asset: earlier.asset(),
        recipient: earlier.recipient(),
        amount_wei: earlier.amount_wei(),
        at: now - Duration::hours(1),
        approval_request_id: None,
    }];
    assert_eq!(earlier.chain_id(), SOLANA_MAINNET_CHAIN_ID);

    let err = evaluate(
        &[policy],
        &payment(
            SOLANA_TESTNET_CHAIN_ID,
            vec![leg(PRIMARY, 50), leg(SPLIT, 11)],
        ),
        &history,
        agent_key_id,
        now,
    )
    .expect_err("40 spent + 61 requested is beyond 100");
    assert!(matches!(
        err,
        PolicyError::WindowLimitExceeded {
            used_amount_wei: 40,
            requested_amount_wei: 61,
            max_amount_wei: 100,
            ..
        }
    ));
}

#[test]
fn over_limit_manual_approval_reports_the_sum() {
    let policy = solana_policy(
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
    )
    .with_over_limit(OverLimit::ManualApproval)
    .expect("limit type");
    let explanation = PolicyEngine.explain(
        std::slice::from_ref(&policy),
        &PolicyAttachment::AllPolicies,
        &split_payment(100, 5),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    );
    assert_eq!(
        explanation.decision,
        PolicyDecision::ManualApproval(vec![PolicyError::LimitApprovalRequired {
            policy_id: policy.id,
            limit: ApprovalLimit::PerPayment,
            max: 100,
            used: 0,
            requested_amount_wei: 105,
        }])
    );
}

#[test]
fn asset_scope_is_the_payment_mint() {
    let policy = solana_policy(
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([AssetId::SplToken(solana_addr(OTHER_MINT))])),
    );
    let err = evaluate(
        &[policy],
        &split_payment(1, 1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    )
    .expect_err("a mint outside the asset scope is denied");
    assert!(matches!(err, PolicyError::NoApplicablePolicies));

    let native_only = solana_policy(
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::Set(BTreeSet::from([AssetId::NativeSol])),
    );
    let err = evaluate(
        &[native_only],
        &split_payment(1, 1),
        &[],
        Uuid::new_v4(),
        OffsetDateTime::now_utc(),
    )
    .expect_err("an SPL payment is not native SOL");
    assert!(matches!(err, PolicyError::NoApplicablePolicies));
}

#[test]
fn recipient_scopes_must_cover_every_leg() {
    let now = OffsetDateTime::now_utc();
    let primary_only = solana_policy(
        PolicyType::PerTxMaxSpending,
        1_000,
        recipients(&[PRIMARY]),
        EntityScope::All,
    );
    let err = evaluate(
        std::slice::from_ref(&primary_only),
        &split_payment(10, 1),
        &[],
        Uuid::new_v4(),
        now,
    )
    .expect_err("the split recipient is not covered");
    assert!(matches!(err, PolicyError::NoApplicablePolicies));
    evaluate(
        std::slice::from_ref(&primary_only),
        &payment(SOLANA_DEVNET_CHAIN_ID, vec![leg(PRIMARY, 10)]),
        &[],
        Uuid::new_v4(),
        now,
    )
    .expect("a payment to the primary only is covered");

    let both = solana_policy(
        PolicyType::PerTxMaxSpending,
        1_000,
        recipients(&[PRIMARY, SPLIT]),
        EntityScope::All,
    );
    evaluate(&[both], &split_payment(10, 1), &[], Uuid::new_v4(), now)
        .expect("one policy covering both recipients");

    let split_only = solana_policy(
        PolicyType::PerTxMaxSpending,
        1_000,
        recipients(&[SPLIT]),
        EntityScope::All,
    );
    evaluate(
        &[primary_only, split_only],
        &split_payment(10, 1),
        &[],
        Uuid::new_v4(),
        now,
    )
    .expect("two policies that together cover every recipient");
}

#[test]
fn a_policy_scoped_to_a_split_recipient_still_applies() {
    let now = OffsetDateTime::now_utc();
    let everyone = solana_policy(
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::All,
    );
    let tight_split = solana_policy(
        PolicyType::PerTxMaxSpending,
        50,
        recipients(&[SPLIT]),
        EntityScope::All,
    );
    let explanation = PolicyEngine.explain(
        &[everyone.clone(), tight_split.clone()],
        &PolicyAttachment::AllPolicies,
        &split_payment(60, 1),
        &[],
        Uuid::new_v4(),
        now,
    );
    assert!(explanation.applicable_policy_ids.contains(&tight_split.id));
    assert!(matches!(
        explanation.decision,
        PolicyDecision::Deny(PolicyError::PerTxLimitExceeded {
            max_amount_wei: 50,
            requested_amount_wei: 61,
            ..
        })
    ));
}
