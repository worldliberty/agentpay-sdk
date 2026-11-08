//! Wallet names: validation, `RenameWallet`, persistence, `BootstrapWallet`,
//! and backups that carry the name.

use agentpay_api::rpc::{WalletBootstrap, WalletBootstrapMode};
use agentpay_domain::AdminAuth;
use agentpay_signer::SoftwareSignerBackend;
use uuid::Uuid;

use super::support::{test_state_secret, unique_state_path};
use super::wallet_bootstrap::{bootstrap, usd1_limit};
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
};

type Daemon = InMemoryDaemon<SoftwareSignerBackend>;

const ROOT: AdminAuth = AdminAuth::PeerCredentials;

fn persistent(path: &std::path::Path) -> Daemon {
    InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(path.to_path_buf()),
    )
    .expect("daemon")
}

fn daemon() -> Daemon {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default()).expect("daemon")
}

fn create(name: Option<&str>) -> WalletBootstrapMode {
    WalletBootstrapMode::Create {
        replace_existing: false,
        name: name.map(str::to_string),
    }
}

async fn names(daemon: &Daemon) -> Vec<Option<String>> {
    daemon
        .list_wallets(&ROOT)
        .await
        .expect("list")
        .into_iter()
        .map(|wallet| wallet.name)
        .collect()
}

fn invalid_name(result: Result<impl std::fmt::Debug, DaemonError>) {
    match result {
        Err(DaemonError::InvalidWalletRequest(reason)) => {
            assert!(reason.contains("1 to 32 characters"), "{reason}");
        }
        other => panic!("expected InvalidWalletRequest, got {other:?}"),
    }
}

#[cfg(not(coverage))]
#[tokio::test]
async fn names_are_validated_trimmed_and_survive_a_restart() {
    let path = unique_state_path("wallet-names");
    let daemon = persistent(&path);
    invalid_name(bootstrap(&daemon, create(Some("  ")), vec![usd1_limit(1)]).await);
    assert!(names(&daemon).await.is_empty(), "nothing was created");

    let boot = bootstrap(&daemon, create(Some("  Trading bot ")), vec![usd1_limit(1)])
        .await
        .expect("bootstrap");
    let id = boot.vault_key.id;
    assert_eq!(boot.vault_key.name.as_deref(), Some("Trading bot"));
    assert_eq!(names(&daemon).await, [Some("Trading bot".to_string())]);

    for bad in ["", "   ", &"x".repeat(33), "line\nbreak", "tab\there"] {
        invalid_name(daemon.rename_wallet(&ROOT, id, Some(bad.to_string())).await);
    }
    let unknown = Uuid::new_v4();
    assert!(matches!(
        daemon.rename_wallet(&ROOT, unknown, Some("x".into())).await,
        Err(DaemonError::UnknownVaultKey(found)) if found == unknown
    ));
    let longest = "é".repeat(32);
    let renamed = daemon
        .rename_wallet(&ROOT, id, Some(longest.clone()))
        .await
        .expect("32 characters");
    assert_eq!(renamed.name.as_deref(), Some(longest.as_str()));
    assert_eq!(renamed.vault_key_id, id);
    drop(daemon);

    let restarted = persistent(&path);
    assert_eq!(names(&restarted).await, [Some(longest)]);
    let cleared = restarted
        .rename_wallet(&ROOT, id, None)
        .await
        .expect("clear");
    assert_eq!(cleared.name, None);
    drop(restarted);
    assert_eq!(names(&persistent(&path)).await, [None]);
}

#[tokio::test]
async fn reuse_keeps_the_name() {
    let daemon = daemon();
    bootstrap(&daemon, create(Some("Ops")), vec![usd1_limit(1)])
        .await
        .expect("create");
    let reused = bootstrap(
        &daemon,
        WalletBootstrapMode::Reuse {
            vault_key_id: None,
            agent_key_id: None,
        },
        vec![usd1_limit(2)],
    )
    .await
    .expect("reuse");
    assert_eq!(reused.vault_key.name.as_deref(), Some("Ops"));
}

async fn restore(target: &Daemon, backup_json: &str, name: Option<&str>) -> WalletBootstrap {
    bootstrap(
        target,
        WalletBootstrapMode::RestoreFromBackup {
            backup_json: backup_json.to_string(),
            passphrase: "a passphrase for names".to_string().into(),
            replace_existing: false,
            name: name.map(str::to_string),
        },
        vec![usd1_limit(1)],
    )
    .await
    .expect("restore")
}

#[tokio::test]
async fn backups_carry_the_name_and_a_restore_may_rename() {
    let source = daemon();
    bootstrap(&source, create(Some("Trading bot")), vec![usd1_limit(1)])
        .await
        .expect("create");
    let export = source
        .export_wallet_backup(&ROOT, None, "a passphrase for names".to_string().into())
        .await
        .expect("export");
    assert_eq!(export.summary.name.as_deref(), Some("Trading bot"));
    assert!(
        !export.backup_json.contains("Trading bot"),
        "encrypted only"
    );
    let verified = source
        .verify_wallet_backup(
            &ROOT,
            export.backup_json.clone(),
            "a passphrase for names".to_string().into(),
        )
        .await
        .expect("verify");
    assert_eq!(verified.name.as_deref(), Some("Trading bot"));

    let kept = restore(&daemon(), &export.backup_json, None).await;
    assert_eq!(kept.vault_key.name.as_deref(), Some("Trading bot"));
    let renamed = restore(&daemon(), &export.backup_json, Some(" Cold storage ")).await;
    assert_eq!(renamed.vault_key.name.as_deref(), Some("Cold storage"));
}
