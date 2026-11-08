//! The `agentpay-api` examples that show daemon output are what this daemon
//! actually produces, so the published contract cannot drift from reality.

use agentpay_api::rpc::{
    AddPolicyParams, AuthenticateAgentParams, BeginAdminChallengeParams, BootstrapWalletParams,
    ExportWalletBackupParams, ListWalletsParams, ReleaseSignedNonceParams, RenameWalletParams,
    SetSpendingLimitsParams, SignForAgentParams, SpendingLimitsReport, VerifyWalletBackupParams,
};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};
use agentpay_domain::{AdminAuth, AdminChallenge, NonceReservationRequest, PolicyAttachment};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::daemon::admin_auth::ChallengeMessage;
use crate::{DaemonConfig, InMemoryDaemon, KeyManagerDaemonApi};

/// The example wallet's private key (the docs' `CreateVaultKey` and
/// `AuthenticateAgent` examples are this key's public key and addresses).
const EXAMPLE_PRIVATE_KEY_HEX: &str =
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

/// Loads `crates/agentpay-api/fixtures/rpc/<method>.<kind>.json`.
fn example(method: &str, kind: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpay-api/fixtures/rpc")
        .join(format!("{method}.{kind}.json"));
    let text = std::fs::read_to_string(&path).expect("example file");
    serde_json::from_str(&text).expect("example JSON")
}

fn request(method: &str) -> DaemonRpcRequest {
    serde_json::from_value(example(method, "request")).expect("request example")
}

fn response(method: &str) -> DaemonRpcResponse {
    serde_json::from_value(example(method, "response")).expect("response example")
}

#[tokio::test]
async fn key_and_signature_examples_are_reproduced_by_the_daemon() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let auth = AdminAuth::PeerCredentials;

    let vault_key = daemon
        .create_vault_key(
            &auth,
            KeyCreateRequest::Import {
                private_key_hex: EXAMPLE_PRIVATE_KEY_HEX.to_string().into(),
            },
        )
        .await
        .expect("import example key");
    let DaemonRpcResponse::VaultKey(documented_key) = response("CreateVaultKey") else {
        panic!("CreateVaultKey example must return a vault key");
    };
    assert_eq!(vault_key.public_key_hex, documented_key.public_key_hex);

    let DaemonRpcResponse::PublicKey(documented_solana_key) = response("SolanaPublicKey") else {
        panic!("SolanaPublicKey example must return a public key");
    };
    let solana_key = daemon
        .solana_public_key_hex(&auth, vault_key.id)
        .await
        .expect("solana key");
    assert_eq!(solana_key, documented_solana_key);

    // Sign the `SignForAgent` example under the `AddPolicy` example policy.
    let DaemonRpcRequest::AddPolicy(AddPolicyParams { policy, .. }) = request("AddPolicy") else {
        panic!("wrong AddPolicy request example");
    };
    daemon.add_policy(&auth, policy).await.expect("add policy");
    let credentials = daemon
        .create_agent_key(&auth, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent key");

    // `AuthenticateAgent` reports the example wallet's addresses.
    let DaemonRpcResponse::AgentIdentity(documented_identity) = response("AuthenticateAgent")
    else {
        panic!("AuthenticateAgent example must return an identity");
    };
    let DaemonRpcRequest::AuthenticateAgent(AuthenticateAgentParams { mut auth }) =
        request("AuthenticateAgent")
    else {
        panic!("wrong AuthenticateAgent request example");
    };
    auth.agent_key_id = credentials.agent_key.id;
    auth.agent_auth_token = credentials.auth_token.clone();
    // The inherent `authenticate_agent` is the token check; call the API method.
    let identity = KeyManagerDaemonApi::authenticate_agent(&daemon, &auth)
        .await
        .expect("authenticate");
    assert_eq!(identity.agent_key, credentials.agent_key);
    assert_eq!(identity.vault_key, vault_key);
    assert_eq!(identity.evm_address, documented_identity.evm_address);
    assert_eq!(identity.solana_address, documented_identity.solana_address);
    assert_eq!(
        documented_identity.vault_key.public_key_hex,
        vault_key.public_key_hex
    );

    let DaemonRpcRequest::SignForAgent(SignForAgentParams { request: mut sign }) =
        request("SignForAgent")
    else {
        panic!("wrong SignForAgent request example");
    };
    let now = OffsetDateTime::now_utc();
    let agentpay_domain::AgentAction::BroadcastTx { tx } = sign.action.clone() else {
        panic!("the SignForAgent example is a broadcast transaction");
    };
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            chain_id: tx.chain_id,
            min_nonce: tx.nonce,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + Duration::minutes(1),
        })
        .await
        .expect("reserve the example nonce");
    assert_eq!(reservation.nonce, tx.nonce);

    sign.agent_key_id = credentials.agent_key.id;
    sign.agent_auth_token = credentials.auth_token.clone();
    sign.requested_at = now;
    sign.expires_at = now + Duration::minutes(1);
    let signature = daemon.sign_for_agent(sign).await.expect("sign example");
    let DaemonRpcResponse::Signature(documented_signature) = response("SignForAgent") else {
        panic!("SignForAgent example must return a signature");
    };
    assert_eq!(signature, documented_signature);

    // `ReleaseSignedNonce` names exactly this transaction, and frees nonce 7 again.
    let DaemonRpcRequest::ReleaseSignedNonce(ReleaseSignedNonceParams {
        request: mut release,
    }) = request("ReleaseSignedNonce")
    else {
        panic!("wrong ReleaseSignedNonce request example");
    };
    assert_eq!(Some(&release.tx_hash_hex), signature.tx_hash_hex.as_ref());
    assert_eq!((release.chain_id, release.nonce), (tx.chain_id, tx.nonce));
    release.agent_key_id = credentials.agent_key.id;
    release.agent_auth_token = credentials.auth_token.clone();
    release.requested_at = now;
    release.expires_at = now + Duration::minutes(1);
    daemon
        .release_signed_nonce(release)
        .await
        .expect("release example");
    let again = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: credentials.agent_key.id,
            agent_auth_token: credentials.auth_token.clone(),
            chain_id: tx.chain_id,
            min_nonce: tx.nonce,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + Duration::minutes(1),
        })
        .await
        .expect("reserve again");
    assert_eq!(again.nonce, tx.nonce);
}

/// The rows of a report without policy ids and timestamps, which are random.
fn rows(report: &SpendingLimitsReport) -> Vec<(Value, Value)> {
    report
        .limits
        .iter()
        .map(|row| {
            (
                serde_json::to_value(&row.limit).expect("limit"),
                serde_json::to_value(row.policy_ids.len()).expect("count"),
            )
        })
        .collect()
}

#[tokio::test]
async fn wallet_and_limit_examples_are_reproduced_by_the_daemon() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    // `BootstrapWallet` turns the example limits into the documented rows.
    let DaemonRpcRequest::BootstrapWallet(BootstrapWalletParams { auth, mode, limits }) =
        request("BootstrapWallet")
    else {
        panic!("wrong BootstrapWallet request example");
    };
    let bootstrap = daemon
        .bootstrap_wallet(&auth, mode, limits)
        .await
        .expect("bootstrap example");
    let DaemonRpcResponse::WalletBootstrap(documented) = response("BootstrapWallet") else {
        panic!("BootstrapWallet example must return a bootstrap");
    };
    assert_eq!(bootstrap.outcome, documented.outcome);
    assert_eq!(
        rows(&bootstrap.spending_limits),
        rows(&documented.spending_limits)
    );
    assert_eq!(
        serde_json::to_value(&bootstrap.spending_limits.limits[0].usage).expect("usage"),
        serde_json::to_value(&documented.spending_limits.limits[0].usage).expect("usage")
    );
    let agent_key_id = bootstrap.agent_credentials.agent_key.id;

    // `SetSpendingLimits` replaces them with the documented row.
    let DaemonRpcRequest::SetSpendingLimits(SetSpendingLimitsParams { limits, .. }) =
        request("SetSpendingLimits")
    else {
        panic!("wrong SetSpendingLimits request example");
    };
    let report = daemon
        .set_spending_limits(&AdminAuth::PeerCredentials, agent_key_id, limits)
        .await
        .expect("set example limits");
    let DaemonRpcResponse::SpendingLimits(documented) = response("SetSpendingLimits") else {
        panic!("SetSpendingLimits example must return limits");
    };
    assert_eq!(rows(&report), rows(&documented));
}

#[tokio::test]
async fn backup_examples_hold_the_example_wallet() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let auth = AdminAuth::PeerCredentials;
    let vault_key = daemon
        .create_vault_key(
            &auth,
            KeyCreateRequest::Import {
                private_key_hex: EXAMPLE_PRIVATE_KEY_HEX.to_string().into(),
            },
        )
        .await
        .expect("import example key");

    // The documented backup (format v2, N = 2^18) decrypts to the example wallet.
    let DaemonRpcRequest::VerifyWalletBackup(VerifyWalletBackupParams {
        backup_json,
        passphrase,
        ..
    }) = request("VerifyWalletBackup")
    else {
        panic!("wrong VerifyWalletBackup request example");
    };
    let summary = daemon
        .verify_wallet_backup(&auth, backup_json.clone(), passphrase.clone())
        .await
        .expect("verify example");
    let DaemonRpcResponse::WalletBackupSummary(mut documented) = response("VerifyWalletBackup")
    else {
        panic!("VerifyWalletBackup example must return a summary");
    };
    assert_eq!(
        documented.matching_vault_key_id,
        documented
            .source_vault_key_id
            .as_deref()
            .map(|id| id.parse().expect("uuid"))
    );
    documented.matching_vault_key_id = Some(vault_key.id);
    assert_eq!(summary, documented);

    // `ExportWalletBackup` documents that same document and summary.
    let DaemonRpcResponse::WalletBackup(export) = response("ExportWalletBackup") else {
        panic!("ExportWalletBackup example must return a backup");
    };
    assert_eq!(export.backup_json, backup_json);
    let DaemonRpcRequest::ExportWalletBackup(ExportWalletBackupParams {
        passphrase: export_passphrase,
        ..
    }) = request("ExportWalletBackup")
    else {
        panic!("wrong ExportWalletBackup request example");
    };
    assert_eq!(export_passphrase, passphrase);

    // A fresh export of the example wallet has the documented summary.
    let fresh = daemon
        .export_wallet_backup(&auth, None, passphrase.clone())
        .await
        .expect("export");
    assert_eq!(fresh.summary.address, export.summary.address);
    assert_eq!(fresh.summary.public_key_hex, export.summary.public_key_hex);
    assert_eq!(fresh.summary.matching_vault_key_id, Some(vault_key.id));
    let verified = daemon
        .verify_wallet_backup(&auth, fresh.backup_json, passphrase)
        .await
        .expect("verify fresh export");
    assert_eq!(verified, fresh.summary);
}

#[tokio::test]
async fn list_wallets_example_is_reproduced_by_the_daemon() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let auth = AdminAuth::PeerCredentials;
    let vault_key = daemon
        .create_vault_key(
            &auth,
            KeyCreateRequest::Import {
                private_key_hex: EXAMPLE_PRIVATE_KEY_HEX.to_string().into(),
            },
        )
        .await
        .expect("import example key");
    let credentials = daemon
        .create_agent_key(&auth, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent key");

    // The example wallet is named with the `RenameWallet` example.
    let DaemonRpcRequest::RenameWallet(RenameWalletParams { name, .. }) = request("RenameWallet")
    else {
        panic!("wrong RenameWallet request example");
    };
    let renamed = daemon
        .rename_wallet(&auth, vault_key.id, name)
        .await
        .expect("rename");

    let DaemonRpcRequest::ListWallets(ListWalletsParams { .. }) = request("ListWallets") else {
        panic!("wrong ListWallets request example");
    };
    let DaemonRpcResponse::Wallets(documented) = response("ListWallets") else {
        panic!("ListWallets example must return wallets");
    };
    let [documented] = documented.as_slice() else {
        panic!("the ListWallets example lists the example wallet");
    };
    // Ids and the creation time are random per daemon; the example's agent key
    // and creation time are the `CreateVaultKey` and `CreateAgentKey` examples.
    let DaemonRpcResponse::VaultKey(documented_key) = response("CreateVaultKey") else {
        panic!("CreateVaultKey example must return a vault key");
    };
    assert_eq!(documented.vault_key_id, documented_key.id);
    assert_eq!(documented.created_at, documented_key.created_at);
    assert_eq!(documented.source, documented_key.source);
    let DaemonRpcResponse::AgentCredentials(documented_agent) = response("CreateAgentKey") else {
        panic!("CreateAgentKey example must return credentials");
    };
    assert_eq!(
        documented.agent_key_ids,
        vec![documented_agent.agent_key.id]
    );
    let mut expected = documented.clone();
    expected.vault_key_id = vault_key.id;
    expected.created_at = vault_key.created_at;
    expected.source = vault_key.source.clone();
    expected.agent_key_ids = vec![credentials.agent_key.id];

    let wallets = daemon.list_wallets(&auth).await.expect("list wallets");
    assert_eq!(wallets, vec![expected.clone()]);
    assert_eq!(renamed, expected);
    let DaemonRpcResponse::Wallet(documented_rename) = response("RenameWallet") else {
        panic!("RenameWallet example must return a wallet");
    };
    assert_eq!(&documented_rename, documented);
}

#[test]
fn challenge_example_message_is_the_daemon_encoding() {
    let DaemonRpcRequest::BeginAdminChallenge(BeginAdminChallengeParams {
        credential_id,
        purpose,
    }) = request("BeginAdminChallenge")
    else {
        panic!("wrong BeginAdminChallenge request example");
    };
    let DaemonRpcResponse::AdminChallenge(AdminChallenge {
        challenge_id,
        message_hex,
        expires_at,
    }) = response("BeginAdminChallenge")
    else {
        panic!("BeginAdminChallenge example must return a challenge");
    };
    let message = hex::decode(&message_hex).expect("hex");
    // Instance id and nonce are random per daemon / challenge; take them from the example.
    let tag_len = agentpay_api::auth::ADMIN_CHALLENGE_DOMAIN_TAG.len() + 1;
    let rebuilt = ChallengeMessage {
        instance_id: Uuid::from_slice(&message[tag_len..tag_len + 16]).expect("instance id"),
        credential_id,
        challenge_id,
        nonce: message[tag_len + 48..tag_len + 80]
            .try_into()
            .expect("nonce"),
        purpose: &purpose,
        expires_at,
    }
    .encode()
    .expect("encode");
    assert_eq!(hex::encode(rebuilt), message_hex);
}
