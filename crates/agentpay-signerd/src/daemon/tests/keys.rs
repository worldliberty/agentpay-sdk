//! Vault key and agent key lifecycle.

use std::time::{SystemTime, UNIX_EPOCH};

use agentpay_domain::{
    AdminAuth, AgentAction, ManualApprovalStatus, NonceReservationRequest, PolicyAttachment,
};
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use uuid::Uuid;

use super::support::{
    poison_vault_keys_lock, policy_all_per_tx, sample_manual_approval_request, sign_request,
    test_state_secret, unique_state_path, CleanupTrackingSignerBackend,
    TrackingNonExportableSignerBackend,
};
use crate::{
    DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi, PersistentStoreConfig,
};

#[tokio::test]
async fn create_vault_key_cleans_up_backend_key_on_post_create_failure() {
    let signer_backend = TrackingNonExportableSignerBackend::default();
    let daemon =
        InMemoryDaemon::new(signer_backend.clone(), DaemonConfig::default()).expect("daemon");
    let session = AdminAuth::PeerCredentials;

    poison_vault_keys_lock(&daemon);

    let err = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect_err("poisoned vault key state must fail create");
    assert!(matches!(err, DaemonError::LockPoisoned));
    assert_eq!(
        signer_backend.created_key_count(),
        0,
        "backend key material must be cleaned up when daemon commit fails"
    );
    assert!(
        daemon.vault_keys.read().is_err(),
        "the test should fail after backend creation because the vault_keys lock is poisoned"
    );
}

#[tokio::test]
async fn rotate_agent_auth_token_invalidates_previous_token() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let old_token = agent_credentials.auth_token.clone();

    let new_token = daemon
        .rotate_agent_auth_token(&session, agent_credentials.agent_key.id)
        .await
        .expect("rotate token");
    assert_ne!(old_token.as_str(), new_token);

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x3000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x4000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };

    let old_request = sign_request(&agent_credentials, action.clone());
    let err = daemon
        .sign_for_agent(old_request)
        .await
        .expect_err("old token must be rejected after rotation");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    let mut rotated_credentials = agent_credentials;
    rotated_credentials.auth_token = new_token.into();
    let signature = daemon
        .sign_for_agent(sign_request(&rotated_credentials, action))
        .await
        .expect("new token should sign");
    assert!(!signature.bytes.is_empty());
}

#[tokio::test]
async fn revoke_agent_key_blocks_future_signing() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    daemon
        .revoke_agent_key(&session, agent_credentials.agent_key.id)
        .await
        .expect("revoke key");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect_err("revoked key must not sign");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    let err = daemon
        .revoke_agent_key(&session, agent_credentials.agent_key.id)
        .await
        .expect_err("second revoke should report unknown key");
    assert!(matches!(err, DaemonError::UnknownAgentKey(_)));
}

#[tokio::test]
async fn revoke_agent_key_removes_manual_approval_requests_from_persistent_state() {
    let state_path = unique_state_path("revoke-agent-key-manual-approvals");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let reserved = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("reserve nonce before revoke");
    assert_eq!(reserved.nonce, 0);

    let now = time::OffsetDateTime::now_utc();
    let statuses = [
        ManualApprovalStatus::Pending,
        ManualApprovalStatus::Approved,
        ManualApprovalStatus::Rejected,
        ManualApprovalStatus::Completed,
    ];
    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write");
        for status in statuses {
            let mut request = sample_manual_approval_request();
            request.id = Uuid::new_v4();
            request.agent_key_id = agent_credentials.agent_key.id;
            request.vault_key_id = key.id;
            request.created_at = now - time::Duration::days(2);
            request.updated_at = now - time::Duration::hours(1);
            request.status = status;
            request.completed_at = matches!(status, ManualApprovalStatus::Completed)
                .then_some(now - time::Duration::hours(1));
            requests.insert(request.id, request);
        }
    }

    daemon
        .revoke_agent_key(&session, agent_credentials.agent_key.id)
        .await
        .expect("revoke key");
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read")
            .is_empty(),
        "revoke must remove approval requests for the deleted agent"
    );
    assert!(
        daemon
            .nonce_heads
            .read()
            .expect("nonce heads read")
            .get(&key.id)
            .is_none(),
        "revoke must reclaim nonce heads tied only to removed reservations"
    );
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    assert!(
        restarted
            .manual_approval_requests
            .read()
            .expect("manual approval read after restart")
            .is_empty(),
        "restarted daemon must not load orphaned manual approvals"
    );

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn create_vault_key_cleans_up_backend_key_on_persist_failure() {
    use std::os::unix::fs::PermissionsExt;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "agentpay-daemon-create-key-cleanup-{}-{}",
        std::process::id(),
        unique
    ));
    std::fs::create_dir_all(&root).expect("create persistence root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("secure persistence root");
    let state_path = root.join("daemon-state.enc");

    let backend = CleanupTrackingSignerBackend::default();
    let daemon = InMemoryDaemon::new_with_persistent_store(
        &test_state_secret(),
        backend.clone(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path),
    )
    .expect("daemon");
    let session = AdminAuth::PeerCredentials;

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770))
        .expect("make persistence root insecure");

    let err = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect_err("persist failure must roll back backend key creation");
    assert!(matches!(err, DaemonError::Persistence(_)));
    assert_eq!(backend.live_key_count(), 0);
    assert_eq!(backend.deleted_key_ids().len(), 1);
    assert!(daemon
        .snapshot_state()
        .expect("snapshot after cleanup")
        .vault_keys
        .is_empty());

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("restore persistence root permissions");
    std::fs::remove_dir_all(&root).expect("cleanup persistence root");
}

#[tokio::test]
async fn authenticate_agent_reports_identity_and_rejects_bad_credentials() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let admin = AdminAuth::PeerCredentials;
    let vault_key = daemon
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let credentials = daemon
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent key");
    let auth = |token: &str| crate::AgentAuth {
        agent_key_id: credentials.agent_key.id,
        agent_auth_token: token.to_string().into(),
    };

    // The inherent `authenticate_agent` is the token check; call the API method.
    let identity = KeyManagerDaemonApi::authenticate_agent(&daemon, &auth(&credentials.auth_token))
        .await
        .expect("valid token");
    assert_eq!(identity.agent_key, credentials.agent_key);
    assert_eq!(identity.vault_key, vault_key);
    assert!(identity.evm_address.is_some());
    assert!(identity.solana_address.is_some());

    for bad in [
        auth("wrong-token"),
        crate::AgentAuth {
            agent_key_id: Uuid::new_v4(),
            agent_auth_token: credentials.auth_token.clone(),
        },
    ] {
        let err = KeyManagerDaemonApi::authenticate_agent(&daemon, &bad)
            .await
            .expect_err("must fail");
        assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
    }

    // A rotated token stops working at once.
    let rotated = daemon
        .rotate_agent_auth_token(&admin, credentials.agent_key.id)
        .await
        .expect("rotate");
    let err = KeyManagerDaemonApi::authenticate_agent(&daemon, &auth(&credentials.auth_token))
        .await
        .expect_err("old token");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
    KeyManagerDaemonApi::authenticate_agent(&daemon, &auth(&rotated))
        .await
        .expect("rotated token");
}
