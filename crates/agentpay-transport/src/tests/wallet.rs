//! The wallet methods end to end over a real socket: bootstrap under a Touch
//! ID lease, limits, an encrypted backup, and returning a signed nonce.

use std::sync::Arc;

use agentpay_api::rpc::{SpendingLimit, WalletBootstrapMode, WalletBootstrapOutcome};
use agentpay_domain::{
    AgentAction, AssetId, BroadcastTx, NonceReservationRequest, SignRequest,
    SignedNonceReleaseRequest,
};
use agentpay_signer::SoftwareSignerBackend;
use agentpay_signerd::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::client::{lease_over_socket, spawn_daemon_server};

fn native_limit() -> SpendingLimit {
    SpendingLimit {
        chain_id: 56,
        asset: AssetId::NativeEth,
        per_tx_max_wei: 1_000,
        daily_max_wei: 5_000,
        weekly_max_wei: 10_000,
        max_gas_per_tx_wei: Some(1_000_000_000_000_000),
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        daily_max_tx_count: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_methods_round_trip_over_the_socket() {
    let daemon = Arc::new(
        InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
            .expect("daemon"),
    );
    let (client, server_task) = spawn_daemon_server("wallet", daemon.clone()).await;
    let session = lease_over_socket(&daemon, &client).await.auth();

    let bootstrap = client
        .bootstrap_wallet(
            &session,
            WalletBootstrapMode::Create {
                replace_existing: false,
                name: None,
            },
            vec![native_limit()],
        )
        .await
        .expect("bootstrap");
    assert_eq!(bootstrap.outcome, WalletBootstrapOutcome::Created);
    let agent = bootstrap.agent_credentials.clone();
    let err = client
        .bootstrap_wallet(
            &session,
            WalletBootstrapMode::Create {
                replace_existing: false,
                name: None,
            },
            vec![native_limit()],
        )
        .await
        .expect_err("a second create");
    assert!(matches!(err, DaemonError::WalletAlreadyExists { .. }));
    let wallets = client.list_wallets(&session).await.expect("list wallets");
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].vault_key_id, bootstrap.vault_key.id);
    assert_eq!(wallets[0].evm_address, bootstrap.evm_address);
    assert_eq!(
        wallets[0].agent_key_ids,
        vec![bootstrap.agent_credentials.agent_key.id]
    );

    // Sign a broadcast at nonce 3, then hand the nonce back as if the send failed.
    let now = OffsetDateTime::now_utc();
    let reservation = client
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent.agent_key.id,
            agent_auth_token: agent.auth_token.clone(),
            chain_id: 56,
            min_nonce: 3,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + Duration::minutes(2),
        })
        .await
        .expect("reserve");
    let action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 56,
            nonce: reservation.nonce,
            to: "0x2222222222222222222222222222222222222222"
                .parse()
                .expect("to"),
            value_wei: 500,
            data_hex: "0x".to_string(),
            gas_limit: 21_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    let signature = client
        .sign_for_agent(SignRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent.agent_key.id,
            agent_auth_token: agent.auth_token.clone(),
            payload: serde_json::to_vec(&action).expect("payload"),
            action,
            requested_at: now,
            expires_at: now + Duration::minutes(2),
        })
        .await
        .expect("sign");
    client
        .release_signed_nonce(SignedNonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent.agent_key.id,
            agent_auth_token: agent.auth_token.clone(),
            chain_id: 56,
            nonce: 3,
            tx_hash_hex: signature.tx_hash_hex.expect("tx hash"),
            requested_at: now,
            expires_at: now + Duration::minutes(2),
        })
        .await
        .expect("release signed nonce");
    let again = client
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent.agent_key.id,
            agent_auth_token: agent.auth_token.clone(),
            chain_id: 56,
            min_nonce: 3,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + Duration::minutes(2),
        })
        .await
        .expect("reserve again");
    assert_eq!(again.nonce, 3);

    // The spend stays counted.
    let report = client
        .list_spending_limits(&session, agent.agent_key.id)
        .await
        .expect("list");
    assert_eq!(report.limits[0].usage.spent_24h_wei, 500);
    let mut lower = native_limit();
    lower.per_tx_max_wei = 100;
    let report = client
        .set_spending_limits(&session, agent.agent_key.id, vec![lower.clone()])
        .await
        .expect("set");
    assert_eq!(report.limits[0].limit, lower);
    assert_eq!(report.limits[0].usage.available_now_wei, 100);

    let backup = client
        .export_wallet_backup(&session, None, "socket passphrase".to_string().into())
        .await
        .expect("export");
    let summary = client
        .verify_wallet_backup(
            &session,
            backup.backup_json,
            "socket passphrase".to_string().into(),
        )
        .await
        .expect("verify");
    assert_eq!(summary.matching_vault_key_id, Some(bootstrap.vault_key.id));
    assert_eq!(Some(summary.address), bootstrap.evm_address);

    server_task.abort();
    let _ = server_task.await;
}
