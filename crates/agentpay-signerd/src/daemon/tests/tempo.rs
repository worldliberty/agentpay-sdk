//! Tempo session channel registry.

use agentpay_domain::{AdminAuth, AgentAction, AgentCredentials, PolicyAttachment, VaultKey};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use uuid::Uuid;

use super::support::{policy_all_per_tx, sign_request};
use crate::daemon::signing::ethereum_address_from_public_key_hex;
use crate::daemon::tempo_channels::{
    tempo_channel_action, TempoChannelRecord, TempoChannelRole, MAX_TRACKED_TEMPO_CHANNELS,
};
use crate::persistence::PersistedDaemonState;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

fn tempo_channel_id_hex(open: &agentpay_domain::TempoSessionV2OpenTransaction) -> String {
    format!("0x{}", hex::encode(open.channel_id().expect("channel id")))
}

/// Daemon with one wallet and two agent keys sharing it.
async fn tempo_daemon_with_two_agents() -> (
    InMemoryDaemon<SoftwareSignerBackend>,
    AdminAuth,
    VaultKey,
    AgentCredentials,
    AgentCredentials,
    String,
) {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000))
        .await
        .expect("add policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let first = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("first agent");
    let second = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("second agent");
    let wallet = ethereum_address_from_public_key_hex(&key.public_key_hex).expect("address");
    (daemon, session, key, first, second, wallet)
}

fn assert_invalid_action_contains(err: DaemonError, needle: &str) {
    match err {
        DaemonError::InvalidAction(message) => assert!(
            message.contains(needle),
            "expected `{needle}` in `{message}`"
        ),
        other => panic!("expected InvalidAction containing `{needle}`, got {other:?}"),
    }
}

#[tokio::test]
async fn tempo_voucher_and_top_up_for_unknown_channel_are_rejected() {
    let (daemon, _session, _key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_v2_open_for_payer(&wallet, 0x11, 1_000);

    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_voucher_for_open(&open, 1)))
        .await
        .expect_err("voucher for a channel this daemon never opened must fail");
    assert_invalid_action_contains(err, "unknown to this daemon");

    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_top_up_for_open(&open, 1)))
        .await
        .expect_err("top-up for a channel this daemon never opened must fail");
    assert_invalid_action_contains(err, "unknown to this daemon");

    // Policy previews reject the same way, so explain/evaluate cannot be used
    // to probe a voucher that signing would refuse.
    let err = daemon
        .evaluate_for_agent(sign_request(&agent, tempo_v2_voucher_for_open(&open, 1)))
        .await
        .expect_err("evaluate must reject unknown channel");
    assert_invalid_action_contains(err, "unknown to this daemon");
    assert!(daemon.tempo_channels.read().expect("channels").is_empty());
}

#[tokio::test]
async fn tempo_channel_is_bound_to_the_opening_agent_key() {
    let (daemon, _session, _key, first, second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_v2_open_for_payer(&wallet, 0x22, 1_000);
    daemon
        .sign_for_agent(sign_request(&first, tempo_v2_open_action(&open)))
        .await
        .expect("first agent opens the channel");

    let err = daemon
        .sign_for_agent(sign_request(&second, tempo_v2_voucher_for_open(&open, 10)))
        .await
        .expect_err("another agent key must not vouch for the channel");
    assert_invalid_action_contains(err, "opened by a different agent key");

    let err = daemon
        .sign_for_agent(sign_request(&second, tempo_v2_top_up_for_open(&open, 10)))
        .await
        .expect_err("another agent key must not top up the channel");
    assert_invalid_action_contains(err, "opened by a different agent key");

    let err = daemon
        .sign_for_agent(sign_request(&second, tempo_v2_open_action(&open)))
        .await
        .expect_err("another agent key must not take over the channel");
    assert_invalid_action_contains(err, "registered to a different agent key");

    let record = daemon
        .tempo_channels
        .read()
        .expect("channels")
        .get(&tempo_channel_id_hex(&open))
        .cloned()
        .expect("channel registered");
    assert_eq!(record.agent_key_id, first.agent_key.id);
    assert_eq!(record.deposited_total_wei, 1_000);

    daemon
        .sign_for_agent(sign_request(&first, tempo_v2_voucher_for_open(&open, 10)))
        .await
        .expect("opening agent can vouch");
}

#[tokio::test]
async fn tempo_voucher_is_capped_at_deposited_total_including_top_ups() {
    let (daemon, _session, _key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_v2_open_for_payer(&wallet, 0x33, 1_000);
    daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_open_action(&open)))
        .await
        .expect("open");

    daemon
        .sign_for_agent(sign_request(
            &agent,
            tempo_v2_voucher_for_open(&open, 1_000),
        ))
        .await
        .expect("voucher at the deposit is allowed");
    let err = daemon
        .sign_for_agent(sign_request(
            &agent,
            tempo_v2_voucher_for_open(&open, 1_001),
        ))
        .await
        .expect_err("voucher above the deposit must fail");
    assert_invalid_action_contains(err, "exceeds the 1000 deposited");

    daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_top_up_for_open(&open, 500)))
        .await
        .expect("top-up by the opening agent");
    assert_eq!(
        daemon
            .tempo_channels
            .read()
            .expect("channels")
            .get(&tempo_channel_id_hex(&open))
            .map(|record| record.deposited_total_wei),
        Some(1_500)
    );
    daemon
        .sign_for_agent(sign_request(
            &agent,
            tempo_v2_voucher_for_open(&open, 1_500),
        ))
        .await
        .expect("voucher up to the topped-up total is allowed");
    let err = daemon
        .sign_for_agent(sign_request(
            &agent,
            tempo_v2_voucher_for_open(&open, 1_501),
        ))
        .await
        .expect_err("voucher above the topped-up total must fail");
    assert_invalid_action_contains(err, "exceeds the 1500 deposited");

    // Re-signing the open (e.g. a retried broadcast) must not inflate the total.
    daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_open_action(&open)))
        .await
        .expect("re-signing the open");
    assert_eq!(
        daemon
            .tempo_channels
            .read()
            .expect("channels")
            .get(&tempo_channel_id_hex(&open))
            .map(|record| record.deposited_total_wei),
        Some(1_500)
    );
}

#[tokio::test]
async fn tempo_channel_registry_is_bounded_and_evicts_oldest() {
    let (daemon, _session, _key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;
    let base = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    {
        let mut channels = daemon.tempo_channels.write().expect("channels");
        for index in 0..MAX_TRACKED_TEMPO_CHANNELS {
            channels.insert(
                format!("0x{index:064x}"),
                TempoChannelRecord {
                    agent_key_id: agent.agent_key.id,
                    deposited_total_wei: 1,
                    opened_at: base + time::Duration::seconds(index as i64),
                },
            );
        }
    }

    let open = tempo_v2_open_for_payer(&wallet, 0x44, 1_000);
    daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_open_action(&open)))
        .await
        .expect("open");

    let channels = daemon.tempo_channels.read().expect("channels");
    assert_eq!(channels.len(), MAX_TRACKED_TEMPO_CHANNELS);
    assert!(channels.contains_key(&tempo_channel_id_hex(&open)));
    assert!(
        !channels.contains_key(&format!("0x{:064x}", 0)),
        "the oldest channel must be evicted"
    );
    assert!(channels.contains_key(&format!("0x{:064x}", 1)));
}

#[tokio::test]
async fn revoking_agent_key_drops_its_tempo_channels() {
    let (daemon, session, _key, first, second, wallet) = tempo_daemon_with_two_agents().await;
    let first_open = tempo_v2_open_for_payer(&wallet, 0x55, 1_000);
    let second_open = tempo_v2_open_for_payer(&wallet, 0x66, 1_000);
    daemon
        .sign_for_agent(sign_request(&first, tempo_v2_open_action(&first_open)))
        .await
        .expect("first open");
    daemon
        .sign_for_agent(sign_request(&second, tempo_v2_open_action(&second_open)))
        .await
        .expect("second open");

    daemon
        .revoke_agent_key(&session, first.agent_key.id)
        .await
        .expect("revoke");

    let channels = daemon.tempo_channels.read().expect("channels");
    assert!(!channels.contains_key(&tempo_channel_id_hex(&first_open)));
    assert!(channels.contains_key(&tempo_channel_id_hex(&second_open)));
}

#[test]
fn persisted_state_without_tempo_channels_loads_and_registry_round_trips() {
    let mut legacy = serde_json::to_value(PersistedDaemonState::default()).expect("serialize");
    legacy
        .as_object_mut()
        .expect("state object")
        .remove("tempo_channels")
        .expect("field present in current schema");
    let loaded: PersistedDaemonState = serde_json::from_value(legacy).expect("legacy state loads");
    assert!(loaded.tempo_channels.is_empty());

    let mut state = PersistedDaemonState::default();
    state.tempo_channels.insert(
        format!("0x{}", "ab".repeat(32)),
        TempoChannelRecord {
            agent_key_id: Uuid::new_v4(),
            deposited_total_wei: u128::MAX,
            opened_at: time::OffsetDateTime::UNIX_EPOCH,
        },
    );
    let round_tripped: PersistedDaemonState =
        serde_json::from_slice(&serde_json::to_vec(&state).expect("serialize")).expect("load");
    assert_eq!(round_tripped.tempo_channels, state.tempo_channels);
}

fn tempo_v2_open_for_payer(
    payer: &str,
    salt: u8,
    deposit_wei: u128,
) -> agentpay_domain::TempoSessionV2OpenTransaction {
    agentpay_domain::TempoSessionV2OpenTransaction {
        chain_id: agentpay_domain::TEMPO_MAINNET_CHAIN_ID,
        token: "0x20c0000000000000000000000000000000000001"
            .parse()
            .expect("token"),
        recipient: "0x7777777777777777777777777777777777777777"
            .parse()
            .expect("recipient"),
        operator: "0x0000000000000000000000000000000000000000"
            .parse()
            .expect("operator"),
        payer: payer.parse().expect("payer"),
        authorized_signer: payer.parse().expect("signer"),
        salt_hex: format!("0x{}", hex::encode([salt; 32])),
        deposit_wei,
        tx: agentpay_domain::TempoTxParams {
            nonce: 0,
            nonce_key: Some(format!("0x{}", "ff".repeat(32))),
            gas_limit: 400_000,
            max_fee_per_gas_wei: 20_000_000_000,
            max_priority_fee_per_gas_wei: 1,
            valid_before: Some(1_900_000_000),
            valid_after: None,
            fee_token: None,
            fee_payer: false,
        },
    }
}

fn tempo_v2_voucher_fields(
    open: &agentpay_domain::TempoSessionV2OpenTransaction,
    cumulative_amount_wei: u128,
) -> agentpay_domain::TempoSessionV2Voucher {
    agentpay_domain::TempoSessionV2Voucher {
        chain_id: open.chain_id,
        token: open.token.clone(),
        recipient: open.recipient.clone(),
        operator: open.operator.clone(),
        payer: open.payer.clone(),
        authorized_signer: open.authorized_signer.clone(),
        salt_hex: open.salt_hex.clone(),
        expiring_nonce_hash_hex: format!(
            "0x{}",
            hex::encode(open.expiring_nonce_hash().expect("expiring nonce hash"))
        ),
        channel_id_hex: format!("0x{}", hex::encode(open.channel_id().expect("channel id"))),
        cumulative_amount_wei,
    }
}

fn tempo_v2_voucher_for_open(
    open: &agentpay_domain::TempoSessionV2OpenTransaction,
    cumulative_amount_wei: u128,
) -> AgentAction {
    AgentAction::TempoSessionV2Voucher {
        authorization: tempo_v2_voucher_fields(open, cumulative_amount_wei),
    }
}

fn tempo_v2_close_for_open(
    open: &agentpay_domain::TempoSessionV2OpenTransaction,
    cumulative_amount_wei: u128,
) -> AgentAction {
    AgentAction::TempoSessionV2CloseAuthorization {
        authorization: agentpay_domain::TempoSessionV2CloseAuthorization {
            voucher: tempo_v2_voucher_fields(open, cumulative_amount_wei),
        },
    }
}

fn tempo_v2_top_up_for_open(
    open: &agentpay_domain::TempoSessionV2OpenTransaction,
    additional_deposit_wei: u128,
) -> AgentAction {
    let fields = tempo_v2_voucher_fields(open, additional_deposit_wei);
    AgentAction::TempoSessionV2TopUpTransaction {
        authorization: agentpay_domain::TempoSessionV2TopUpTransaction {
            chain_id: fields.chain_id,
            token: fields.token,
            recipient: fields.recipient,
            operator: fields.operator,
            payer: fields.payer,
            authorized_signer: fields.authorized_signer,
            salt_hex: fields.salt_hex,
            expiring_nonce_hash_hex: fields.expiring_nonce_hash_hex,
            channel_id_hex: fields.channel_id_hex,
            additional_deposit_wei,
            tx: agentpay_domain::TempoTxParams {
                nonce: 3,
                nonce_key: None,
                valid_before: None,
                ..open.tx.clone()
            },
        },
    }
}

fn tempo_v2_open_action(open: &agentpay_domain::TempoSessionV2OpenTransaction) -> AgentAction {
    AgentAction::TempoSessionV2OpenTransaction {
        authorization: open.clone(),
    }
}

#[tokio::test]
async fn tempo_v2_session_requires_wallet_payer_and_signs_recoverable_vouchers() {
    let (daemon, _session, key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;

    let foreign =
        tempo_v2_open_for_payer("0x4000000000000000000000000000000000000000", 0x5a, 1_000);
    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_open_action(&foreign)))
        .await
        .expect_err("foreign payer must be rejected");
    assert_invalid_action_contains(err, "payer must be the signing wallet");

    let open = tempo_v2_open_for_payer(&wallet, 0x5a, 1_000);
    daemon
        .sign_for_agent(sign_request(&agent, tempo_v2_open_action(&open)))
        .await
        .expect("v2 open through the daemon");

    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    for action in [
        tempo_v2_voucher_for_open(&open, 400),
        tempo_v2_close_for_open(&open, 400),
    ] {
        let signature = daemon
            .sign_for_agent(sign_request(&agent, action.clone()))
            .await
            .expect("wallet payer v2 action must sign");
        let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
        let digest = action
            .signing_hash()
            .expect("typed hash")
            .expect("typed action");
        let recovery_id =
            RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
        let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
            .expect("recover verifying key");
        assert_eq!(recovered, expected_verifying_key);
    }
}

#[tokio::test]
async fn tempo_v2_channel_is_bound_to_opening_agent_and_capped_at_deposits() {
    let (daemon, _session, _key, first, second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_v2_open_for_payer(&wallet, 0x44, 1_000);

    let err = daemon
        .sign_for_agent(sign_request(&first, tempo_v2_voucher_for_open(&open, 1)))
        .await
        .expect_err("voucher for a channel this daemon never opened must fail");
    assert_invalid_action_contains(err, "unknown to this daemon");

    daemon
        .sign_for_agent(sign_request(&first, tempo_v2_open_action(&open)))
        .await
        .expect("first agent opens the v2 channel");

    for action in [
        tempo_v2_voucher_for_open(&open, 10),
        tempo_v2_close_for_open(&open, 10),
        tempo_v2_top_up_for_open(&open, 10),
    ] {
        let err = daemon
            .sign_for_agent(sign_request(&second, action))
            .await
            .expect_err("another agent key must not use the channel");
        assert_invalid_action_contains(err, "opened by a different agent key");
    }

    let err = daemon
        .sign_for_agent(sign_request(&first, tempo_v2_close_for_open(&open, 1_001)))
        .await
        .expect_err("close authorization above the deposit must fail");
    assert_invalid_action_contains(err, "exceeds the 1000 deposited");

    daemon
        .sign_for_agent(sign_request(&first, tempo_v2_top_up_for_open(&open, 500)))
        .await
        .expect("top-up by the opening agent");
    daemon
        .sign_for_agent(sign_request(
            &first,
            tempo_v2_voucher_for_open(&open, 1_500),
        ))
        .await
        .expect("voucher up to the topped-up total");
    daemon
        .sign_for_agent(sign_request(&first, tempo_v2_close_for_open(&open, 1_500)))
        .await
        .expect("close up to the topped-up total");
    let err = daemon
        .sign_for_agent(sign_request(
            &first,
            tempo_v2_voucher_for_open(&open, 1_501),
        ))
        .await
        .expect_err("voucher above the topped-up total must fail");
    assert_invalid_action_contains(err, "exceeds the 1500 deposited");
}

#[test]
fn tempo_channel_classification_matches_payer_and_escrow_semantics() {
    let open = tempo_v2_open_for_payer("0x4000000000000000000000000000000000000000", 0x77, 1_000);
    let channel_id_hex = tempo_channel_id_hex(&open);
    let cases = [
        (
            tempo_v2_open_action(&open),
            TempoChannelRole::Open { deposit_wei: 1_000 },
        ),
        (
            tempo_v2_top_up_for_open(&open, 5),
            TempoChannelRole::TopUp {
                additional_deposit_wei: 5,
            },
        ),
        (
            tempo_v2_voucher_for_open(&open, 7),
            TempoChannelRole::Redistribute {
                cumulative_amount_wei: 7,
            },
        ),
        (
            tempo_v2_close_for_open(&open, 9),
            TempoChannelRole::Redistribute {
                cumulative_amount_wei: 9,
            },
        ),
    ];
    for (action, role) in cases {
        let classified = tempo_channel_action(&action)
            .expect("classify")
            .expect("tempo channel action");
        assert_eq!(classified.channel_id_hex, channel_id_hex);
        assert_eq!(classified.role, role);
        assert!(action.tempo_payer().is_some());
        assert_eq!(
            matches!(role, TempoChannelRole::Redistribute { .. }),
            action.is_escrow_redistribution()
        );
    }

    let transfer = AgentAction::TransferNative {
        chain_id: 1,
        to: "0x1111111111111111111111111111111111111111"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };
    assert!(tempo_channel_action(&transfer).expect("classify").is_none());
    assert!(transfer.tempo_payer().is_none());
    assert!(!transfer.is_escrow_redistribution());
}
