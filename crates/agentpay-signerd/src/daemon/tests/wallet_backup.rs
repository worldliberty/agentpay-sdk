//! `ExportWalletBackup` / `VerifyWalletBackup` through the daemon: passphrase
//! rules, which wallet is exported, non-exportable backends, and that the
//! private key never appears in a response.

use agentpay_api::rpc::{ExportWalletBackupParams, VerifyWalletBackupParams};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};
use agentpay_domain::{AdminAuth, KeyAlgorithm};
use agentpay_signer::{KeyCreateRequest, SignerError, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::TrackingNonExportableSignerBackend;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, RequestContext};

const ROOT: AdminAuth = AdminAuth::PeerCredentials;
const PRIVATE_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const PASSPHRASE: &str = "twelve chars";

fn daemon() -> InMemoryDaemon<SoftwareSignerBackend> {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default()).expect("daemon")
}

async fn import(daemon: &InMemoryDaemon<SoftwareSignerBackend>) -> Uuid {
    daemon
        .create_vault_key(
            &ROOT,
            KeyCreateRequest::Import {
                private_key_hex: PRIVATE_KEY_HEX.to_string().into(),
            },
        )
        .await
        .expect("import")
        .id
}

#[tokio::test]
async fn passphrases_need_twelve_characters() {
    let daemon = daemon();
    import(&daemon).await;
    for weak in ["eleven char", "            ", ""] {
        assert!(matches!(
            daemon
                .export_wallet_backup(&ROOT, None, weak.to_string().into())
                .await,
            Err(DaemonError::WeakBackupPassphrase { min_chars: 12 })
        ));
    }
    // Twelve characters, counted as characters rather than bytes.
    daemon
        .export_wallet_backup(&ROOT, None, "pässwörd-123".to_string().into())
        .await
        .expect("12 characters");
    assert!(matches!(
        daemon
            .export_wallet_backup(&ROOT, None, "x".repeat(16 * 1024 + 1).into())
            .await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));
}

#[tokio::test]
async fn export_resolves_the_wallet() {
    let daemon = daemon();
    assert!(matches!(
        daemon
            .export_wallet_backup(&ROOT, None, PASSPHRASE.to_string().into())
            .await,
        Err(DaemonError::WalletNotFound)
    ));
    let id = import(&daemon).await;
    let ed25519 = daemon
        .create_vault_key(
            &ROOT,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    assert!(matches!(
        daemon
            .export_wallet_backup(&ROOT, None, PASSPHRASE.to_string().into())
            .await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));
    assert!(matches!(
        daemon
            .export_wallet_backup(&ROOT, Some(ed25519.id), PASSPHRASE.to_string().into())
            .await,
        Err(DaemonError::InvalidWalletRequest(_))
    ));
    assert!(matches!(
        daemon
            .export_wallet_backup(&ROOT, Some(Uuid::new_v4()), PASSPHRASE.to_string().into())
            .await,
        Err(DaemonError::UnknownVaultKey(_))
    ));
    let export = daemon
        .export_wallet_backup(&ROOT, Some(id), PASSPHRASE.to_string().into())
        .await
        .expect("export by id");
    assert_eq!(export.summary.matching_vault_key_id, Some(id));
    assert_eq!(export.summary.source_vault_key_id, Some(id.to_string()));
    assert_eq!(
        export.summary.address.to_string(),
        "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
    );
}

#[tokio::test]
async fn the_private_key_never_appears_in_a_response() {
    let daemon = daemon();
    import(&daemon).await;
    let request = DaemonRpcRequest::ExportWalletBackup(ExportWalletBackupParams {
        auth: ROOT,
        vault_key_id: None,
        passphrase: PASSPHRASE.to_string().into(),
    });
    let response = daemon
        .handle_rpc(&RequestContext::peer(0), request)
        .await
        .expect("export over RPC");
    let rendered = serde_json::to_string(&response).expect("encode");
    assert!(!rendered.contains(PRIVATE_KEY_HEX));
    assert!(!rendered.contains(PASSPHRASE));
    let DaemonRpcResponse::WalletBackup(export) = response else {
        panic!("WalletBackup response");
    };

    let verify = DaemonRpcRequest::VerifyWalletBackup(VerifyWalletBackupParams {
        auth: ROOT,
        backup_json: export.backup_json,
        passphrase: PASSPHRASE.to_string().into(),
    });
    let DaemonRpcResponse::WalletBackupSummary(summary) = daemon
        .handle_rpc(&RequestContext::peer(0), verify)
        .await
        .expect("verify over RPC")
    else {
        panic!("WalletBackupSummary response");
    };
    assert_eq!(summary, export.summary);
}

#[tokio::test]
async fn verify_reports_bad_passphrases_and_documents_without_matching_wallets() {
    let source = daemon();
    import(&source).await;
    let export = source
        .export_wallet_backup(&ROOT, None, PASSPHRASE.to_string().into())
        .await
        .expect("export");
    let elsewhere = daemon();
    let summary = elsewhere
        .verify_wallet_backup(
            &ROOT,
            export.backup_json.clone(),
            PASSPHRASE.to_string().into(),
        )
        .await
        .expect("verify on another daemon");
    assert_eq!(summary.matching_vault_key_id, None);
    assert_eq!(summary.address, export.summary.address);
    assert!(matches!(
        elsewhere
            .verify_wallet_backup(
                &ROOT,
                export.backup_json,
                "wrong passphrase".to_string().into()
            )
            .await,
        Err(DaemonError::WalletBackupDecryptionFailed)
    ));
    assert!(matches!(
        elsewhere
            .verify_wallet_backup(&ROOT, "{}".to_string(), PASSPHRASE.to_string().into())
            .await,
        Err(DaemonError::InvalidWalletBackup(_))
    ));
}

#[tokio::test]
async fn non_exportable_backends_refuse() {
    let daemon = InMemoryDaemon::new(
        TrackingNonExportableSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    daemon
        .create_vault_key(&ROOT, KeyCreateRequest::Generate)
        .await
        .expect("key");
    assert!(matches!(
        daemon
            .export_wallet_backup(&ROOT, None, PASSPHRASE.to_string().into())
            .await,
        Err(DaemonError::Signer(SignerError::Unsupported(_)))
    ));
}

#[tokio::test]
async fn non_root_peers_need_a_lease() {
    let daemon = daemon();
    import(&daemon).await;
    let request = DaemonRpcRequest::ExportWalletBackup(ExportWalletBackupParams {
        auth: ROOT,
        vault_key_id: None,
        passphrase: PASSPHRASE.to_string().into(),
    });
    assert!(matches!(
        daemon.handle_rpc(&RequestContext::peer(501), request).await,
        Err(DaemonError::AdminAuthenticationRequired)
    ));
}
