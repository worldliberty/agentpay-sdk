//! `ListWallets` through the daemon: every vault key with its addresses and
//! agent keys, oldest first, without secrets, for admins only.

use agentpay_api::rpc::ListWalletsParams;
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};
use agentpay_domain::{AdminAuth, KeyAlgorithm, KeySource, PolicyAttachment};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};

use super::support::TrackingNonExportableSignerBackend;
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, RequestContext};

const ROOT: AdminAuth = AdminAuth::PeerCredentials;
const PRIVATE_KEY_HEX: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const EXAMPLE_ADDRESS: &str = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23";

fn daemon() -> InMemoryDaemon<SoftwareSignerBackend> {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default()).expect("daemon")
}

#[tokio::test]
async fn an_empty_daemon_lists_no_wallets() {
    assert!(daemon().list_wallets(&ROOT).await.expect("list").is_empty());
}

#[tokio::test]
async fn lists_every_wallet_oldest_first_with_its_agent_keys() {
    let daemon = daemon();
    let imported = daemon
        .create_vault_key(
            &ROOT,
            KeyCreateRequest::Import {
                private_key_hex: PRIVATE_KEY_HEX.to_string().into(),
            },
        )
        .await
        .expect("import");
    let generated = daemon
        .create_vault_key(&ROOT, KeyCreateRequest::Generate)
        .await
        .expect("generate");
    let mut tokens = Vec::new();
    let mut generated_agents = Vec::new();
    for vault_key_id in [generated.id, generated.id, imported.id] {
        let credentials = daemon
            .create_agent_key(&ROOT, vault_key_id, PolicyAttachment::AllPolicies)
            .await
            .expect("agent key");
        if vault_key_id == generated.id {
            generated_agents.push(credentials.agent_key.id);
        }
        tokens.push(credentials.auth_token.to_string());
    }
    generated_agents.sort_unstable();

    let wallets = daemon.list_wallets(&ROOT).await.expect("list");
    let mut expected_order = [&imported, &generated];
    expected_order.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
    assert_eq!(
        wallets.iter().map(|w| w.vault_key_id).collect::<Vec<_>>(),
        expected_order.iter().map(|key| key.id).collect::<Vec<_>>()
    );

    let first = wallets
        .iter()
        .find(|w| w.vault_key_id == imported.id)
        .expect("imported wallet");
    assert_eq!(first.algorithm, KeyAlgorithm::Secp256k1);
    assert_eq!(first.source, KeySource::Imported);
    assert_eq!(first.created_at, imported.created_at);
    assert_eq!(
        first
            .evm_address
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some(EXAMPLE_ADDRESS)
    );
    assert!(first.solana_address.is_some());
    assert_eq!(first.agent_key_ids.len(), 1);

    let second = wallets
        .iter()
        .find(|w| w.vault_key_id == generated.id)
        .expect("generated wallet");
    assert_eq!(second.source, KeySource::Generated);
    assert_eq!(second.agent_key_ids, generated_agents);

    // Public metadata only: no private key, token, or public key material.
    let rendered = serde_json::to_string(&DaemonRpcResponse::Wallets(wallets)).expect("json");
    assert!(!rendered.contains(PRIVATE_KEY_HEX));
    assert!(!rendered.contains(&imported.public_key_hex));
    for token in &tokens {
        assert!(!rendered.contains(token.as_str()));
    }
}

#[tokio::test]
async fn ed25519_keys_have_no_evm_address() {
    let daemon = daemon();
    daemon
        .create_vault_key(
            &ROOT,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let wallets = daemon.list_wallets(&ROOT).await.expect("list");
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].algorithm, KeyAlgorithm::Ed25519);
    assert_eq!(wallets[0].evm_address, None);
    assert!(wallets[0].solana_address.is_some());
    assert!(wallets[0].agent_key_ids.is_empty());
}

#[tokio::test]
async fn backends_without_solana_report_no_solana_address() {
    let daemon = InMemoryDaemon::new(
        TrackingNonExportableSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");
    // The test backend's secp256k1 keys are placeholders; its ed25519 key
    // shows the Solana side, which this backend (like the TPM) cannot sign.
    daemon
        .create_vault_key(
            &ROOT,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("key");
    let wallets = daemon.list_wallets(&ROOT).await.expect("list");
    assert_eq!(wallets.len(), 1);
    assert_eq!(wallets[0].evm_address, None);
    assert_eq!(wallets[0].solana_address, None);
}

#[tokio::test]
async fn needs_admin_authority() {
    let daemon = daemon();
    let request = || DaemonRpcRequest::ListWallets(ListWalletsParams { auth: ROOT });
    assert!(matches!(
        daemon
            .handle_rpc(&RequestContext::peer(501), request())
            .await,
        Err(DaemonError::AdminAuthenticationRequired)
    ));
    assert!(matches!(
        daemon.handle_rpc(&RequestContext::peer(0), request()).await,
        Ok(DaemonRpcResponse::Wallets(wallets)) if wallets.is_empty()
    ));
}
