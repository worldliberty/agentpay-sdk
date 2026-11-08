//! Admin credential enrollment, signed challenges, lockout, and lease lifecycle.

use agentpay_api::rpc::{
    AddPolicyParams, EnrollAdminCredentialParams, ListAdminCredentialsParams, ListPoliciesParams,
    RevokeAdminCredentialParams, RevokeAdminLeaseParams,
};
use agentpay_domain::{AdminAuth, AdminChallenge, AdminLease};
use agentpay_signer::SoftwareSignerBackend;
use uuid::Uuid;

use super::support::{
    admin_public_key_hex, enroll_admin_credential, policy_all_per_tx, sign_admin_challenge,
    test_admin_signing_key, test_state_secret, unique_state_path,
};
use crate::daemon::admin_auth::ChallengeMessage;
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
    RequestContext,
};
use agentpay_api::{DaemonRpcRequest, DaemonRpcResponse};

const USER_EUID: u32 = 501;
const OTHER_EUID: u32 = 502;

type Daemon = InMemoryDaemon<SoftwareSignerBackend>;

fn daemon_with(config: DaemonConfig) -> Daemon {
    InMemoryDaemon::new(SoftwareSignerBackend::default(), config).expect("daemon")
}

fn user() -> RequestContext {
    RequestContext::peer(USER_EUID)
}

fn begin(
    daemon: &Daemon,
    ctx: &RequestContext,
    credential_id: Uuid,
) -> Result<AdminChallenge, DaemonError> {
    daemon.begin_admin_challenge_impl(ctx, credential_id, "admin-session")
}

/// Runs the full challenge flow for `ctx` and returns the lease.
fn obtain_lease(
    daemon: &Daemon,
    ctx: &RequestContext,
    key: &p256::ecdsa::SigningKey,
    credential_id: Uuid,
) -> Result<AdminLease, DaemonError> {
    let challenge = begin(daemon, ctx, credential_id)?;
    daemon.complete_admin_challenge_impl(
        ctx,
        challenge.challenge_id,
        &sign_admin_challenge(key, &challenge),
    )
}

async fn list_policies_as(
    daemon: &Daemon,
    ctx: &RequestContext,
    auth: AdminAuth,
) -> Result<DaemonRpcResponse, DaemonError> {
    daemon
        .handle_rpc(
            ctx,
            DaemonRpcRequest::ListPolicies(ListPoliciesParams { auth }),
        )
        .await
}

#[tokio::test]
async fn signed_challenge_yields_a_lease_bound_to_the_peer() {
    let daemon = daemon_with(DaemonConfig::default());
    let (key, credential) = enroll_admin_credential(&daemon).await;

    let lease = obtain_lease(&daemon, &user(), &key, credential.id).expect("lease");
    assert!(lease.expires_at > lease.issued_at);
    assert!(lease.expires_at - lease.issued_at <= time::Duration::minutes(5));
    assert_eq!(lease.lease_secret.len(), 64);

    list_policies_as(&daemon, &user(), lease.auth())
        .await
        .expect("lease authorizes the peer that obtained it");
    daemon
        .handle_rpc(
            &user(),
            DaemonRpcRequest::AddPolicy(AddPolicyParams {
                auth: lease.auth(),
                policy: policy_all_per_tx(10),
            }),
        )
        .await
        .expect("lease authorizes writes");

    let err = list_policies_as(&daemon, &RequestContext::peer(OTHER_EUID), lease.auth())
        .await
        .expect_err("a lease is bound to the peer euid that completed the challenge");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    let mut forged = lease.session();
    forged.lease_secret = "00".repeat(32).into();
    let err = list_policies_as(&daemon, &user(), AdminAuth::Lease(forged))
        .await
        .expect_err("wrong lease secret");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
    let mut oversized = lease.session();
    oversized.lease_secret = "a".repeat(1024).into();
    let err = list_policies_as(&daemon, &user(), AdminAuth::Lease(oversized))
        .await
        .expect_err("oversized lease secret");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn challenge_message_is_canonical_and_domain_separated() {
    let daemon = daemon_with(DaemonConfig::default());
    let (_, credential) = enroll_admin_credential(&daemon).await;
    let challenge = daemon
        .begin_admin_challenge_impl(&user(), credential.id, "approve:1234")
        .expect("challenge");
    let message = hex::decode(&challenge.message_hex).expect("hex");

    let tag = b"agentpay-admin-challenge-v1\0";
    assert!(message.starts_with(tag));
    let rest = &message[tag.len()..];
    assert_eq!(&rest[..16], daemon.instance_id.as_bytes());
    assert_eq!(&rest[16..32], credential.id.as_bytes());
    assert_eq!(&rest[32..48], challenge.challenge_id.as_bytes());
    let purpose = &rest[48 + 32..];
    assert_eq!(&purpose[..2], &12u16.to_be_bytes());
    assert_eq!(&purpose[2..14], b"approve:1234");
    assert_eq!(
        &purpose[14..],
        &challenge.expires_at.unix_timestamp().to_be_bytes()
    );
    assert!(challenge.expires_at <= time::OffsetDateTime::now_utc() + time::Duration::minutes(2));

    let rebuilt = ChallengeMessage {
        instance_id: daemon.instance_id,
        credential_id: credential.id,
        challenge_id: challenge.challenge_id,
        nonce: rest[48..80].try_into().expect("nonce"),
        purpose: "approve:1234",
        expires_at: challenge.expires_at,
    }
    .encode()
    .expect("encode");
    assert_eq!(rebuilt, message);

    for bad in ["", "has space", "new\nline", &"p".repeat(129)] {
        assert!(matches!(
            daemon.begin_admin_challenge_impl(&user(), credential.id, bad),
            Err(DaemonError::InvalidAdminChallengePurpose(_))
        ));
    }
}

#[tokio::test]
async fn wrong_signatures_fail_and_consume_the_challenge() {
    let daemon = daemon_with(DaemonConfig::default());
    let (key, credential) = enroll_admin_credential(&daemon).await;

    let challenge = begin(&daemon, &user(), credential.id).expect("challenge");
    let impostor = test_admin_signing_key();
    let err = daemon
        .complete_admin_challenge_impl(
            &user(),
            challenge.challenge_id,
            &sign_admin_challenge(&impostor, &challenge),
        )
        .expect_err("signature from another key");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    let err = daemon
        .complete_admin_challenge_impl(
            &user(),
            challenge.challenge_id,
            &sign_admin_challenge(&key, &challenge),
        )
        .expect_err("a failed challenge cannot be retried");
    assert!(matches!(err, DaemonError::InvalidAdminChallenge));

    for garbage in ["zz", "3006020101020101", &"30".repeat(200)] {
        let challenge = begin(&daemon, &user(), credential.id).expect("challenge");
        let err = daemon
            .complete_admin_challenge_impl(&user(), challenge.challenge_id, garbage)
            .expect_err("malformed signature");
        assert!(matches!(err, DaemonError::AuthenticationFailed));
    }
    assert_eq!(daemon.active_admin_lease_count().expect("count"), 0);
}

#[tokio::test]
async fn challenges_are_single_use_peer_bound_and_expire() {
    let daemon = daemon_with(DaemonConfig::default());
    let (key, credential) = enroll_admin_credential(&daemon).await;

    let challenge = begin(&daemon, &user(), credential.id).expect("challenge");
    let signature = sign_admin_challenge(&key, &challenge);
    daemon
        .complete_admin_challenge_impl(&user(), challenge.challenge_id, &signature)
        .expect("first use");
    let err = daemon
        .complete_admin_challenge_impl(&user(), challenge.challenge_id, &signature)
        .expect_err("reuse");
    assert!(matches!(err, DaemonError::InvalidAdminChallenge));

    let challenge = begin(&daemon, &user(), credential.id).expect("challenge");
    let err = daemon
        .complete_admin_challenge_impl(
            &RequestContext::peer(OTHER_EUID),
            challenge.challenge_id,
            &sign_admin_challenge(&key, &challenge),
        )
        .expect_err("completed by another peer");
    assert!(matches!(err, DaemonError::InvalidAdminChallenge));

    let short = daemon_with(DaemonConfig {
        admin_challenge_ttl: time::Duration::milliseconds(20),
        ..DaemonConfig::default()
    });
    let (key, credential) = enroll_admin_credential(&short).await;
    let challenge = begin(&short, &user(), credential.id).expect("challenge");
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let err = short
        .complete_admin_challenge_impl(
            &user(),
            challenge.challenge_id,
            &sign_admin_challenge(&key, &challenge),
        )
        .expect_err("expired");
    assert!(matches!(err, DaemonError::InvalidAdminChallenge));

    let err = begin(&daemon, &user(), Uuid::new_v4()).expect_err("unknown credential");
    assert!(matches!(err, DaemonError::UnknownAdminCredential(_)));
}

#[tokio::test]
async fn pending_challenges_are_bounded() {
    let daemon = daemon_with(DaemonConfig {
        max_pending_admin_challenges: 2,
        ..DaemonConfig::default()
    });
    let (_, credential) = enroll_admin_credential(&daemon).await;
    begin(&daemon, &user(), credential.id).expect("first");
    begin(&daemon, &user(), credential.id).expect("second");
    let err = begin(&daemon, &user(), credential.id).expect_err("bounded");
    assert!(matches!(
        err,
        DaemonError::TooManyPendingAdminChallenges { max: 2 }
    ));
    assert_eq!(daemon.pending_admin_challenge_count().expect("count"), 2);
}

#[tokio::test]
async fn repeated_failures_lock_the_credential_temporarily() {
    let daemon = daemon_with(DaemonConfig {
        max_failed_admin_auth_attempts: 2,
        admin_auth_lockout: time::Duration::milliseconds(150),
        ..DaemonConfig::default()
    });
    let (key, credential) = enroll_admin_credential(&daemon).await;
    let (other_key, other_credential) = enroll_admin_credential(&daemon).await;
    let held_back = begin(&daemon, &user(), credential.id).expect("challenge before lockout");

    for _ in 0..2 {
        let challenge = begin(&daemon, &user(), credential.id).expect("challenge");
        daemon
            .complete_admin_challenge_impl(&user(), challenge.challenge_id, "3000")
            .expect_err("bad signature");
    }

    let err = begin(&daemon, &user(), credential.id).expect_err("locked");
    assert!(
        matches!(err, DaemonError::AdminCredentialLocked { credential_id } if credential_id == credential.id)
    );
    let err = daemon
        .complete_admin_challenge_impl(
            &user(),
            held_back.challenge_id,
            &sign_admin_challenge(&key, &held_back),
        )
        .expect_err("valid signature is refused while locked");
    assert!(matches!(err, DaemonError::AdminCredentialLocked { .. }));
    obtain_lease(&daemon, &user(), &other_key, other_credential.id)
        .expect("lockout is per credential");

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    obtain_lease(&daemon, &user(), &key, credential.id).expect("lockout elapsed");
}

#[tokio::test]
async fn leases_expire_are_capped_and_revocable() {
    let daemon = daemon_with(DaemonConfig {
        lease_ttl: time::Duration::milliseconds(50),
        max_active_leases: 1,
        ..DaemonConfig::default()
    });
    let (key, credential) = enroll_admin_credential(&daemon).await;

    let lease = obtain_lease(&daemon, &user(), &key, credential.id).expect("lease");
    let err = obtain_lease(&daemon, &user(), &key, credential.id).expect_err("capacity");
    assert!(matches!(err, DaemonError::TooManyActiveLeases));

    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    let err = list_policies_as(&daemon, &user(), lease.auth())
        .await
        .expect_err("expired lease");
    assert!(matches!(err, DaemonError::InvalidLease));
    let err = list_policies_as(&daemon, &user(), lease.auth())
        .await
        .expect_err("expired lease is forgotten");
    assert!(matches!(err, DaemonError::UnknownLease));

    let daemon = daemon_with(DaemonConfig::default());
    let (key, credential) = enroll_admin_credential(&daemon).await;
    let lease = obtain_lease(&daemon, &user(), &key, credential.id).expect("lease");
    daemon
        .handle_rpc(
            &user(),
            DaemonRpcRequest::RevokeAdminLease(RevokeAdminLeaseParams {
                auth: lease.auth(),
                lease_id: lease.lease_id,
            }),
        )
        .await
        .expect("revoke own lease");
    let err = list_policies_as(&daemon, &user(), lease.auth())
        .await
        .expect_err("revoked lease");
    assert!(matches!(err, DaemonError::UnknownLease));
    let err = daemon
        .revoke_admin_lease(&AdminAuth::PeerCredentials, lease.lease_id)
        .await
        .expect_err("already revoked");
    assert!(matches!(err, DaemonError::UnknownLease));
}

#[tokio::test]
async fn revoking_a_credential_kills_its_leases_and_challenges() {
    let daemon = daemon_with(DaemonConfig::default());
    let (key, credential) = enroll_admin_credential(&daemon).await;
    let lease = obtain_lease(&daemon, &user(), &key, credential.id).expect("lease");
    let pending = begin(&daemon, &user(), credential.id).expect("pending challenge");

    let response = daemon
        .handle_rpc(
            &user(),
            DaemonRpcRequest::ListAdminCredentials(ListAdminCredentialsParams {
                auth: lease.auth(),
            }),
        )
        .await
        .expect("list with lease");
    assert!(matches!(
        response,
        DaemonRpcResponse::AdminCredentials(credentials) if credentials == vec![credential.clone()]
    ));
    daemon
        .handle_rpc(
            &user(),
            DaemonRpcRequest::RevokeAdminCredential(RevokeAdminCredentialParams {
                auth: lease.auth(),
                id: credential.id,
            }),
        )
        .await
        .expect("revoke with lease");

    let err = list_policies_as(&daemon, &user(), lease.auth())
        .await
        .expect_err("leases die with their credential");
    assert!(matches!(err, DaemonError::UnknownLease));
    let err = daemon
        .complete_admin_challenge_impl(
            &user(),
            pending.challenge_id,
            &sign_admin_challenge(&key, &pending),
        )
        .expect_err("pending challenges die with their credential");
    assert!(matches!(err, DaemonError::InvalidAdminChallenge));
    let err = begin(&daemon, &user(), credential.id).expect_err("revoked credential");
    assert!(matches!(err, DaemonError::UnknownAdminCredential(_)));
    let err = daemon
        .revoke_admin_credential(&AdminAuth::PeerCredentials, credential.id)
        .await
        .expect_err("unknown credential");
    assert!(matches!(err, DaemonError::UnknownAdminCredential(_)));
}

#[tokio::test]
async fn enrollment_is_root_only_and_validated() {
    let daemon = daemon_with(DaemonConfig {
        max_admin_credentials: 2,
        ..DaemonConfig::default()
    });
    let key = test_admin_signing_key();
    let enroll = |public_key_sec1_hex: String, label: &str| {
        DaemonRpcRequest::EnrollAdminCredential(EnrollAdminCredentialParams {
            public_key_sec1_hex,
            label: label.to_string(),
        })
    };

    let err = daemon
        .handle_rpc(&user(), enroll(admin_public_key_hex(&key), "Mac"))
        .await
        .expect_err("non-root peers cannot enroll");
    assert!(matches!(err, DaemonError::RootPeerRequired));

    let response = daemon
        .handle_rpc(
            &RequestContext::peer(0),
            enroll(admin_public_key_hex(&key), "  Mac  "),
        )
        .await
        .expect("root peer enrolls");
    let DaemonRpcResponse::AdminCredential(credential) = response else {
        panic!("unexpected response");
    };
    assert_eq!(credential.label, "Mac");
    assert_eq!(
        credential.public_key_sec1_hex.len(),
        130,
        "stored uncompressed"
    );

    let uncompressed = hex::encode(key.verifying_key().to_encoded_point(false).as_bytes());
    let err = daemon
        .enroll_admin_credential(uncompressed, "Same key".to_string())
        .await
        .expect_err("duplicate key in another encoding");
    assert!(matches!(err, DaemonError::InvalidAdminCredential(msg) if msg.contains("already")));

    for (public_key, label, expected) in [
        ("zz".to_string(), "Mac", "hex"),
        ("06".repeat(33), "Mac", "valid P-256 point"),
        ("04".repeat(100), "Mac", "too long"),
        (
            admin_public_key_hex(&test_admin_signing_key()),
            " ",
            "1 to 64",
        ),
        (
            admin_public_key_hex(&test_admin_signing_key()),
            "a\u{7}b",
            "control",
        ),
    ] {
        let err = daemon
            .enroll_admin_credential(public_key, label.to_string())
            .await
            .expect_err("invalid enrollment");
        assert!(
            matches!(&err, DaemonError::InvalidAdminCredential(msg) if msg.contains(expected)),
            "{err:?} should mention {expected}"
        );
    }

    enroll_admin_credential(&daemon).await;
    let err = daemon
        .enroll_admin_credential(
            admin_public_key_hex(&test_admin_signing_key()),
            "Third".to_string(),
        )
        .await
        .expect_err("credential cap");
    assert!(matches!(
        err,
        DaemonError::TooManyAdminCredentials { max: 2 }
    ));
}

#[tokio::test]
async fn credentials_persist_across_restarts_but_leases_do_not() {
    let state_path = unique_state_path("admin-credentials");
    let open = || {
        InMemoryDaemon::new_with_persistent_store(
            &test_state_secret(),
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
            PersistentStoreConfig::new_test(state_path.clone()),
        )
        .expect("persistent daemon")
    };

    let daemon = open();
    let (key, credential) = enroll_admin_credential(&daemon).await;
    let lease = obtain_lease(&daemon, &user(), &key, credential.id).expect("lease");
    drop(daemon);

    let restarted = open();
    assert_eq!(
        restarted
            .list_admin_credentials(&AdminAuth::PeerCredentials)
            .await
            .expect("list"),
        vec![credential.clone()]
    );
    let err = list_policies_as(&restarted, &user(), lease.auth())
        .await
        .expect_err("leases do not survive a restart");
    assert!(matches!(err, DaemonError::UnknownLease));
    obtain_lease(&restarted, &user(), &key, credential.id).expect("re-authenticate");

    let _ = std::fs::remove_file(&state_path);
}
