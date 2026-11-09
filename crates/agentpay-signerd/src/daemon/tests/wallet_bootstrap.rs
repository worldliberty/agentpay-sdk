//! `BootstrapWallet`: create, reuse, restore, replace, deny by default, and atomicity.

use agentpay_api::rpc::{
    BootstrapWalletParams, SpendingLimit, WalletBootstrap, WalletBootstrapMode,
    WalletBootstrapOutcome,
};
use agentpay_api::{AgentAuth, DaemonRpcRequest};
use agentpay_domain::{
    AdminAuth, AgentAction, AgentCredentials, AssetId, BroadcastTx, PolicyAttachment, Signature,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    admin_public_key_hex, policy_all_per_tx, reserve_nonce_for_agent, sign_admin_challenge,
    sign_request, test_admin_signing_key, test_state_secret, unique_state_path,
};
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
    RequestContext,
};

type Daemon = InMemoryDaemon<SoftwareSignerBackend>;

const ROOT: AdminAuth = AdminAuth::PeerCredentials;
const USD1: &str = "0x8d0d000ee44948fc98c9b98a4fa4921476f08b0d";
const OTHER_TOKEN: &str = "0x55d398326f99059ff775485246999027b3197955";
const RECIPIENT: &str = "0x5aeda56215b167893e80b4fe645ba6d5bab767de";

fn daemon() -> Daemon {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default()).expect("daemon")
}

pub(super) fn usd1_limit(per_tx: u128) -> SpendingLimit {
    SpendingLimit {
        chain_id: 56,
        asset: AssetId::Erc20(USD1.parse().expect("token")),
        per_tx_max_wei: per_tx,
        daily_max_wei: per_tx * 5,
        weekly_max_wei: per_tx * 10,
        max_gas_per_tx_wei: Some(1_000_000_000_000_000),
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        daily_max_tx_count: None,
    }
}

fn create(replace_existing: bool) -> WalletBootstrapMode {
    WalletBootstrapMode::Create {
        replace_existing,
        name: None,
    }
}

pub(super) fn transfer(token: &str, chain_id: u64, amount_wei: u128) -> AgentAction {
    AgentAction::Transfer {
        chain_id,
        token: token.parse().expect("token"),
        to: RECIPIENT.parse().expect("recipient"),
        amount_wei,
    }
}

pub(super) async fn sign(
    daemon: &Daemon,
    credentials: &AgentCredentials,
    action: AgentAction,
) -> Result<Signature, DaemonError> {
    daemon
        .sign_for_agent(sign_request(credentials, action))
        .await
}

pub(super) async fn bootstrap(
    daemon: &Daemon,
    mode: WalletBootstrapMode,
    limits: Vec<SpendingLimit>,
) -> Result<WalletBootstrap, DaemonError> {
    daemon.bootstrap_wallet(&ROOT, mode, limits).await
}

fn assert_no_applicable_policy(result: Result<Signature, DaemonError>) {
    assert!(
        matches!(
            result,
            Err(DaemonError::Policy(PolicyError::NoApplicablePolicies))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn create_gives_an_agent_that_can_spend_only_the_listed_assets() {
    let daemon = daemon();
    // A broad policy added earlier must not leak into the new agent.
    daemon
        .add_policy(&ROOT, policy_all_per_tx(u128::MAX))
        .await
        .expect("broad policy");
    let result = bootstrap(&daemon, create(false), vec![usd1_limit(100)])
        .await
        .expect("bootstrap");
    assert_eq!(result.outcome, WalletBootstrapOutcome::Created);
    assert!(result.evm_address.is_some() && result.solana_address.is_some());
    assert!(result.replaced_vault_key_ids.is_empty());
    let agent = &result.agent_credentials;
    let PolicyAttachment::PolicySet(attached) = &agent.agent_key.policies else {
        panic!("bootstrap must attach a policy set");
    };
    let row = &result.spending_limits.limits[0];
    assert_eq!(attached.iter().copied().collect::<Vec<_>>(), row.policy_ids);
    assert_eq!(row.limit, usd1_limit(100));
    assert_eq!(row.usage.available_now_wei, 100);

    sign(&daemon, agent, transfer(USD1, 56, 100))
        .await
        .expect("listed asset within its cap");
    assert!(matches!(
        sign(&daemon, agent, transfer(USD1, 56, 101)).await,
        Err(DaemonError::ManualApprovalRequired { .. })
    ));
    assert_no_applicable_policy(sign(&daemon, agent, transfer(OTHER_TOKEN, 56, 1)).await);
    assert_no_applicable_policy(sign(&daemon, agent, transfer(USD1, 1, 1)).await);
    assert_no_applicable_policy(
        sign(
            &daemon,
            agent,
            AgentAction::TransferNative {
                chain_id: 56,
                to: RECIPIENT.parse().expect("to"),
                amount_wei: 1,
            },
        )
        .await,
    );
}

#[tokio::test]
async fn a_gas_cap_does_not_make_other_assets_spendable_by_broadcast() {
    let daemon = daemon();
    let result = bootstrap(&daemon, create(false), vec![usd1_limit(100)])
        .await
        .expect("bootstrap");
    let agent = &result.agent_credentials;
    reserve_nonce_for_agent(&daemon, agent, 56, 0).await;
    // An ERC-20 transfer of an unlisted token, with gas well inside the USD1 row's gas cap.
    let data = format!(
        "0xa9059cbb000000000000000000000000{}{:064x}",
        &RECIPIENT[2..],
        1u128
    );
    let tx = BroadcastTx {
        chain_id: 56,
        nonce: 0,
        to: OTHER_TOKEN.parse().expect("token"),
        value_wei: 0,
        data_hex: data,
        gas_limit: 60_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 1_000_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    assert_no_applicable_policy(sign(&daemon, agent, AgentAction::BroadcastTx { tx }).await);
}

#[tokio::test]
async fn create_refuses_an_existing_wallet_unless_replacing_it() {
    let daemon = daemon();
    let first = bootstrap(&daemon, create(false), vec![usd1_limit(100)])
        .await
        .expect("first");
    let err = bootstrap(&daemon, create(false), vec![usd1_limit(100)])
        .await
        .expect_err("second create");
    assert!(matches!(
        err,
        DaemonError::WalletAlreadyExists { ref vault_key_ids } if vault_key_ids == &[first.vault_key.id]
    ));

    let second = bootstrap(&daemon, create(true), vec![usd1_limit(50)])
        .await
        .expect("replace");
    assert_ne!(second.vault_key.id, first.vault_key.id);
    assert_eq!(second.replaced_vault_key_ids, vec![first.vault_key.id]);
    assert!(daemon
        .vault_keys
        .read()
        .expect("keys")
        .keys()
        .eq([&second.vault_key.id]));
    let old_auth = AgentAuth {
        agent_key_id: first.agent_credentials.agent_key.id,
        agent_auth_token: first.agent_credentials.auth_token.clone(),
    };
    assert!(matches!(
        KeyManagerDaemonApi::authenticate_agent(&daemon, &old_auth).await,
        Err(DaemonError::AgentAuthenticationFailed)
    ));
    let policies = daemon.list_policies(&ROOT).await.expect("policies");
    for id in &first.spending_limits.limits[0].policy_ids {
        let policy = policies
            .iter()
            .find(|p| p.id == *id)
            .expect("kept for audit");
        assert!(
            !policy.enabled,
            "the replaced agent's policies are disabled"
        );
    }
}

#[tokio::test]
async fn reuse_keeps_the_key_agent_and_history_and_rotates_the_token() {
    let daemon = daemon();
    let first = bootstrap(&daemon, create(false), vec![usd1_limit(100)])
        .await
        .expect("create");
    sign(&daemon, &first.agent_credentials, transfer(USD1, 56, 30))
        .await
        .expect("spend");

    let reused = bootstrap(
        &daemon,
        WalletBootstrapMode::Reuse {
            vault_key_id: None,
            agent_key_id: None,
        },
        vec![usd1_limit(200)],
    )
    .await
    .expect("reuse");
    assert_eq!(reused.outcome, WalletBootstrapOutcome::Reused);
    assert_eq!(reused.vault_key, first.vault_key);
    assert_eq!(
        reused.agent_credentials.agent_key.id,
        first.agent_credentials.agent_key.id
    );
    assert_ne!(
        reused.agent_credentials.auth_token,
        first.agent_credentials.auth_token
    );
    let usage = &reused.spending_limits.limits[0].usage;
    assert_eq!(usage.spent_24h_wei, 30, "spend history carries over");
    assert!(matches!(
        sign(&daemon, &first.agent_credentials, transfer(USD1, 56, 1)).await,
        Err(DaemonError::AgentAuthenticationFailed)
    ));
    sign(&daemon, &reused.agent_credentials, transfer(USD1, 56, 150))
        .await
        .expect("the new per-tx cap applies");
}

#[tokio::test]
async fn reuse_resolves_the_wallet_and_agent_or_says_why_not() {
    let daemon = daemon();
    let reuse = |vault_key_id, agent_key_id| WalletBootstrapMode::Reuse {
        vault_key_id,
        agent_key_id,
    };
    assert!(matches!(
        bootstrap(&daemon, reuse(None, None), vec![usd1_limit(1)]).await,
        Err(DaemonError::WalletNotFound)
    ));

    // A wallet without an agent key gets one.
    let key = daemon
        .create_vault_key(&ROOT, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let created = bootstrap(&daemon, reuse(None, None), vec![usd1_limit(1)])
        .await
        .expect("reuse creates an agent key");
    assert_eq!(created.agent_credentials.agent_key.vault_key_id, key.id);

    let other_key = daemon
        .create_vault_key(&ROOT, KeyCreateRequest::Generate)
        .await
        .expect("second key");
    assert!(matches!(
        bootstrap(&daemon, reuse(None, None), vec![usd1_limit(1)]).await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));
    assert!(matches!(
        bootstrap(
            &daemon,
            reuse(Some(Uuid::new_v4()), None),
            vec![usd1_limit(1)]
        )
        .await,
        Err(DaemonError::UnknownVaultKey(_))
    ));
    assert!(matches!(
        bootstrap(
            &daemon,
            reuse(
                Some(other_key.id),
                Some(created.agent_credentials.agent_key.id)
            ),
            vec![usd1_limit(1)]
        )
        .await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));
    daemon
        .create_agent_key(&ROOT, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("second agent");
    assert!(matches!(
        bootstrap(&daemon, reuse(Some(key.id), None), vec![usd1_limit(1)]).await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));
    let chosen = bootstrap(
        &daemon,
        reuse(Some(key.id), Some(created.agent_credentials.agent_key.id)),
        vec![usd1_limit(1)],
    )
    .await
    .expect("explicit agent");
    assert_eq!(
        chosen.agent_credentials.agent_key.id,
        created.agent_credentials.agent_key.id
    );
}

#[tokio::test]
async fn restore_imports_the_backed_up_wallet() {
    let source = daemon();
    let original = bootstrap(&source, create(false), vec![usd1_limit(100)])
        .await
        .expect("create");
    let passphrase = "restore me later, please";
    let backup = source
        .export_wallet_backup(&ROOT, None, passphrase.to_string().into())
        .await
        .expect("export");
    let restore = |replace_existing| WalletBootstrapMode::RestoreFromBackup {
        backup_json: backup.backup_json.clone(),
        passphrase: passphrase.to_string().into(),
        replace_existing,
        name: None,
    };

    // The daemon that holds the key refuses to import it a second time.
    assert!(matches!(
        bootstrap(&source, restore(true), vec![usd1_limit(1)]).await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));

    let target = daemon();
    let wrong = WalletBootstrapMode::RestoreFromBackup {
        backup_json: backup.backup_json.clone(),
        passphrase: "not the passphrase".to_string().into(),
        replace_existing: false,
        name: None,
    };
    assert!(matches!(
        bootstrap(&target, wrong, vec![usd1_limit(1)]).await,
        Err(DaemonError::WalletBackupDecryptionFailed)
    ));
    assert!(target.vault_keys.read().expect("keys").is_empty());

    let restored = bootstrap(&target, restore(false), vec![usd1_limit(100)])
        .await
        .expect("restore");
    assert_eq!(restored.outcome, WalletBootstrapOutcome::Restored);
    assert_eq!(restored.evm_address, original.evm_address);
    assert_eq!(restored.solana_address, original.solana_address);
    assert_eq!(
        restored.vault_key.public_key_hex,
        original.vault_key.public_key_hex
    );
    sign(&target, &restored.agent_credentials, transfer(USD1, 56, 1))
        .await
        .expect("the restored wallet signs");
}

#[tokio::test]
async fn invalid_requests_change_nothing() {
    let daemon = daemon();
    let mut bad = usd1_limit(100);
    bad.daily_max_wei = 1;
    assert!(matches!(
        bootstrap(&daemon, create(false), vec![bad]).await,
        Err(DaemonError::InvalidSpendingLimits(_))
    ));
    assert!(matches!(
        bootstrap(&daemon, create(false), Vec::new()).await,
        Err(DaemonError::InvalidSpendingLimits(_))
    ));
    assert!(daemon.vault_keys.read().expect("keys").is_empty());
    assert!(daemon.agent_keys.read().expect("agents").is_empty());
    assert!(daemon.policies.read().expect("policies").is_empty());
}

#[tokio::test]
async fn non_root_peers_need_a_lease() {
    let daemon = daemon();
    let request = || {
        DaemonRpcRequest::BootstrapWallet(BootstrapWalletParams {
            auth: AdminAuth::PeerCredentials,
            mode: create(false),
            limits: vec![usd1_limit(1)],
        })
    };
    let user = RequestContext::peer(501);
    assert!(matches!(
        daemon.handle_rpc(&user, request()).await,
        Err(DaemonError::AdminAuthenticationRequired)
    ));

    let key = test_admin_signing_key();
    let credential = daemon
        .enroll_admin_credential(admin_public_key_hex(&key), "Mac".to_string())
        .await
        .expect("enroll");
    let challenge = daemon
        .begin_admin_challenge_impl(&user, credential.id, "admin-session")
        .expect("challenge");
    let lease = daemon
        .complete_admin_challenge_impl(
            &user,
            challenge.challenge_id,
            &sign_admin_challenge(&key, &challenge),
        )
        .expect("lease");
    let DaemonRpcRequest::BootstrapWallet(mut params) = request() else {
        unreachable!("built above");
    };
    params.auth = lease.auth();
    daemon
        .handle_rpc(&user, DaemonRpcRequest::BootstrapWallet(params))
        .await
        .expect("a Touch ID lease authorizes the bootstrap");
}

#[tokio::test]
async fn a_bootstrapped_wallet_survives_a_restart() {
    let path = unique_state_path("wallet-bootstrap");
    let open = || {
        InMemoryDaemon::new_with_persistent_store(
            &test_state_secret(),
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
            PersistentStoreConfig::new_test(path.clone()),
        )
        .expect("daemon")
    };
    let result = bootstrap(&open(), create(false), vec![usd1_limit(100)])
        .await
        .expect("bootstrap");
    let daemon = open();
    let report = daemon
        .list_spending_limits(&ROOT, result.agent_credentials.agent_key.id)
        .await
        .expect("limits");
    assert_eq!(report.limits, result.spending_limits.limits);
    sign(&daemon, &result.agent_credentials, transfer(USD1, 56, 5))
        .await
        .expect("sign after restart");
    let _ = std::fs::remove_file(&path);
}
