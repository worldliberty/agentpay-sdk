use super::*;

const TEMPO_TOKEN: &str = "0x20c0000000000000000000000000000000000001";
const TEMPO_PAYEE: &str = "0x7777777777777777777777777777777777777777";
const TEMPO_PAYER: &str = "0x1111111111111111111111111111111111111111";

fn tempo_spend_history(
    agent_key_id: Uuid,
    now: OffsetDateTime,
    amount_wei: u128,
) -> Vec<SpendEvent> {
    vec![SpendEvent {
        agent_key_id,
        chain_id: TEMPO_MAINNET_CHAIN_ID,
        asset: AssetId::Erc20(addr(TEMPO_TOKEN)),
        recipient: addr(TEMPO_PAYEE).into(),
        amount_wei,
        at: now - Duration::minutes(5),
        approval_request_id: None,
    }]
}

fn tempo_v2_open_authorization(deposit_wei: u128) -> TempoSessionV2OpenTransaction {
    TempoSessionV2OpenTransaction {
        chain_id: TEMPO_MAINNET_CHAIN_ID,
        token: addr(TEMPO_TOKEN),
        recipient: addr(TEMPO_PAYEE),
        operator: addr("0x0000000000000000000000000000000000000000"),
        payer: addr(TEMPO_PAYER),
        authorized_signer: addr(TEMPO_PAYER),
        salt_hex: format!("0x{}", "5a".repeat(32)),
        deposit_wei,
        tx: TempoTxParams {
            nonce: 0,
            nonce_key: Some(format!("0x{}", "ff".repeat(32))),
            gas_limit: 400_000,
            max_fee_per_gas_wei: 20_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000,
            valid_before: Some(1_900_000_000),
            valid_after: None,
            fee_token: Some(addr(TEMPO_TOKEN)),
            fee_payer: false,
        },
    }
}

fn tempo_v2_voucher_authorization(cumulative_amount_wei: u128) -> TempoSessionV2Voucher {
    let open = tempo_v2_open_authorization(1_000_000);
    let hex32 = |bytes: [u8; 32]| {
        format!(
            "0x{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    };
    TempoSessionV2Voucher {
        chain_id: open.chain_id,
        token: open.token.clone(),
        recipient: open.recipient.clone(),
        operator: open.operator.clone(),
        payer: open.payer.clone(),
        authorized_signer: open.authorized_signer.clone(),
        salt_hex: open.salt_hex.clone(),
        expiring_nonce_hash_hex: hex32(open.expiring_nonce_hash().expect("expiring nonce hash")),
        channel_id_hex: hex32(open.channel_id().expect("channel id")),
        cumulative_amount_wei,
    }
}

fn tempo_v2_voucher_action(cumulative_amount_wei: u128) -> AgentAction {
    AgentAction::TempoSessionV2Voucher {
        authorization: tempo_v2_voucher_authorization(cumulative_amount_wei),
    }
}

#[test]
fn tempo_voucher_per_tx_limit_uses_full_cumulative_amount() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let policies = [policy_all_per_tx(500)];

    let result = engine.evaluate(
        &policies,
        &PolicyAttachment::AllPolicies,
        &tempo_v2_voucher_action(501),
        &[],
        Uuid::new_v4(),
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::PerTxLimitExceeded {
            requested_amount_wei: 501,
            ..
        })
    ));
    assert!(engine
        .evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &tempo_v2_voucher_action(500),
            &[],
            Uuid::new_v4(),
            now,
        )
        .is_ok());
}

#[test]
fn tempo_voucher_skips_window_limits_but_open_does_not() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let policies = [
        SpendingPolicy::new(
            1,
            PolicyType::DailyMaxSpending,
            1_000,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("daily"),
        SpendingPolicy::new(
            2,
            PolicyType::WeeklyMaxSpending,
            1_000,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("weekly"),
        SpendingPolicy::new(
            3,
            PolicyType::DailyMaxTxCount,
            1,
            EntityScope::All,
            EntityScope::All,
            EntityScope::All,
        )
        .expect("count"),
    ];
    // The deposit that funded the channel already used the full window budget.
    let history = tempo_spend_history(agent_key_id, now, 1_000);

    assert!(engine
        .evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &tempo_v2_voucher_action(900),
            &history,
            agent_key_id,
            now,
        )
        .is_ok());

    let open = AgentAction::TempoSessionV2OpenTransaction {
        authorization: tempo_v2_open_authorization(1),
    };
    assert!(matches!(
        engine.evaluate(
            &policies,
            &PolicyAttachment::AllPolicies,
            &open,
            &history,
            agent_key_id,
            now,
        ),
        Err(PolicyError::WindowLimitExceeded { .. })
    ));
}

#[test]
fn tempo_voucher_still_honors_manual_approval() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let manual = SpendingPolicy::new_manual_approval(
        1,
        100,
        u128::MAX,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual");
    let result = engine.evaluate(
        &[manual],
        &PolicyAttachment::AllPolicies,
        &tempo_v2_voucher_action(150),
        &[],
        Uuid::new_v4(),
        now,
    );
    assert!(matches!(
        result,
        Err(PolicyError::ManualApprovalRequired { .. })
    ));
}

#[test]
fn tempo_v2_voucher_and_close_skip_window_limits_but_honor_per_tx_caps() {
    let engine = PolicyEngine;
    let now = OffsetDateTime::now_utc();
    let agent_key_id = Uuid::new_v4();
    let daily = SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("daily");
    let history = tempo_spend_history(agent_key_id, now, 1_000);
    let voucher = AgentAction::TempoSessionV2Voucher {
        authorization: tempo_v2_voucher_authorization(900),
    };
    let close = AgentAction::TempoSessionV2CloseAuthorization {
        authorization: TempoSessionV2CloseAuthorization {
            voucher: tempo_v2_voucher_authorization(900),
        },
    };
    for action in [&voucher, &close] {
        assert!(engine
            .evaluate(
                std::slice::from_ref(&daily),
                &PolicyAttachment::AllPolicies,
                action,
                &history,
                agent_key_id,
                now,
            )
            .is_ok());
        assert!(matches!(
            engine.evaluate(
                &[policy_all_per_tx(500)],
                &PolicyAttachment::AllPolicies,
                action,
                &[],
                agent_key_id,
                now,
            ),
            Err(PolicyError::PerTxLimitExceeded { .. })
        ));
    }

    let open = AgentAction::TempoSessionV2OpenTransaction {
        authorization: tempo_v2_open_authorization(1),
    };
    assert!(matches!(
        engine.evaluate(
            std::slice::from_ref(&daily),
            &PolicyAttachment::AllPolicies,
            &open,
            &history,
            agent_key_id,
            now,
        ),
        Err(PolicyError::WindowLimitExceeded { .. })
    ));
}
