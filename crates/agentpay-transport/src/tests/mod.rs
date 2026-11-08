//! Unit tests for the unix socket transport, grouped by module under test.
//!
//! Shared fixtures (socket paths, daemon requests, fake one-shot servers) live
//! here; each submodule covers one transport concern.

mod access;
mod client;
mod handshake;
mod server;
mod socket_trust;
mod wallet;
mod wire;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use agentpay_domain::{
    AdminChallenge, AgentAction, AgentCredentials, EntityScope, NonceReleaseRequest,
    NonceReservationRequest, PolicyType, SignRequest, SpendingPolicy,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey};
use serde_json::to_vec;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::wire::{read_frame, write_frame, WireRequest, WireResponse};

/// A socket path in a fresh private (`0700`) temp directory. Not directly in the temp
/// directory: on Linux that is the shared `/tmp` (mode `1777`), which socket trust rejects. The
/// names stay short because socket paths are limited to about 104 bytes.
fn unique_socket_path(label: &str) -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let dir = std::env::temp_dir().join(format!(
        "ap-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("create private temp dir");
    dir.join(format!("{}.sock", &label[..label.len().min(24)]))
}

fn short_test_root(label: &str) -> std::path::PathBuf {
    let base = if Path::new("/private/tmp").is_dir() {
        Path::new("/private/tmp")
    } else {
        Path::new("/tmp")
    };
    base.join(format!(
        "w-{}-{}",
        label,
        &uuid::Uuid::new_v4().simple().to_string()[..6]
    ))
}

fn singleton_allowed_set(euid: u32) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    set.insert(euid);
    set
}

fn dummy_agent_request() -> SignRequest {
    SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "agent-secret".to_string().into(),
        payload: vec![1, 2, 3],
        action: AgentAction::TransferNative {
            chain_id: 1,
            to: "0x2222222222222222222222222222222222222222"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(1),
    }
}

fn policy_all_per_tx(max_amount_wei: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        max_amount_wei,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

/// A P-256 key standing in for the macOS Secure Enclave admin key.
fn admin_signing_key() -> SigningKey {
    SigningKey::from_slice(&[0x42; 32]).expect("p256 signing key")
}

/// Compressed SEC1 public key hex, as the Swift helper exports it.
fn admin_public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_encoded_point(true).as_bytes())
}

/// Signs like CryptoKit's `signature(for:)`: DER ECDSA over SHA-256(message).
fn sign_admin_challenge(key: &SigningKey, challenge: &AdminChallenge) -> String {
    let message = hex::decode(&challenge.message_hex).expect("challenge hex");
    let signature: P256Signature = key.sign(&message);
    hex::encode(signature.to_der().as_bytes())
}

fn sign_request(credentials: &AgentCredentials, amount_wei: u128) -> SignRequest {
    let action = AgentAction::TransferNative {
        chain_id: 1,
        to: "0x2222222222222222222222222222222222222222"
            .parse()
            .expect("recipient"),
        amount_wei,
    };
    let now = OffsetDateTime::now_utc();
    SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        payload: to_vec(&action).expect("serialize action"),
        action,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    }
}

fn nonce_reservation_request(
    credentials: &AgentCredentials,
    min_nonce: u64,
) -> NonceReservationRequest {
    let now = OffsetDateTime::now_utc();
    NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    }
}

fn nonce_release_request(
    credentials: &AgentCredentials,
    reservation_id: Uuid,
) -> NonceReleaseRequest {
    let now = OffsetDateTime::now_utc();
    NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: credentials.auth_token.clone(),
        reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    }
}

async fn spawn_one_shot_server(
    socket_path: std::path::PathBuf,
    response: WireResponse,
) -> tokio::task::JoinHandle<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("create server parent");
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind fake server");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let _: WireRequest = read_frame(&mut stream, Duration::from_secs(2))
            .await
            .expect("read request");
        write_frame(&mut stream, &response, Duration::from_secs(2))
            .await
            .expect("write response");
    })
}

#[cfg(unix)]
fn socket_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777
}
