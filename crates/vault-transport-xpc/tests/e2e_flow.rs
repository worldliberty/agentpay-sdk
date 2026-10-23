#![cfg(target_os = "macos")]

use std::sync::Arc;
use std::time::Duration;

use serde_json::to_vec;
use time::OffsetDateTime;
use vault_daemon::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};
use vault_domain::{
    AdminSession, AgentAction, BroadcastTx, EntityScope, EvmAddress, NonceReservationRequest,
    PolicyAttachment, PolicyType, SignRequest, SpendingPolicy,
};
use vault_signer::{KeyCreateRequest, SoftwareSignerBackend};
use vault_transport_xpc::{XpcDaemonClient, XpcDaemonServer};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_policy_enforced_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    #[cfg(debug_assertions)]
    let server = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
    )
    .expect("server");
    #[cfg(not(debug_assertions))]
    let server =
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server");
    let client =
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client");

    let lease = client.issue_lease("vault-password").await.expect("lease");
    let admin = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");

    client.add_policy(&admin, policy).await.expect("add_policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("create_vault_key");

    let agent_credentials = client
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("create_agent_key");

    let token: EvmAddress = "0x1000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let to: EvmAddress = "0x2000000000000000000000000000000000000000"
        .parse()
        .expect("recipient");

    let allow_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: to.clone(),
            amount_wei: 100,
        })
        .expect("payload"),
        action: AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: to.clone(),
            amount_wei: 100,
        },
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };
    client
        .reserve_nonce(NonceReservationRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("nonce reservation must pass");

    let signature = client
        .sign_for_agent(allow_request)
        .await
        .expect("signature should pass");
    assert!(!signature.bytes.is_empty());

    let deny_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: to.clone(),
            amount_wei: 101,
        })
        .expect("payload"),
        action: AgentAction::Transfer {
            chain_id: 1,
            token,
            to,
            amount_wei: 101,
        },
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(deny_request)
        .await
        .expect_err("request must be denied by policy");

    assert!(matches!(err, DaemonError::Policy(_)));

    let bad_auth_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: "not-the-issued-token".to_string().into(),
        payload: to_vec(&AgentAction::Transfer {
            chain_id: 1,
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        })
        .expect("payload"),
        action: AgentAction::Transfer {
            chain_id: 1,
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(bad_auth_request)
        .await
        .expect_err("request with bad token must fail");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    let payload_mismatch_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&AgentAction::Transfer {
            chain_id: 1,
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 99,
        })
        .expect("payload"),
        action: AgentAction::Transfer {
            chain_id: 1,
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(payload_mismatch_request)
        .await
        .expect_err("payload/action mismatch must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));

    let malformed_payload_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        payload: b"not-json".to_vec(),
        action: AgentAction::Transfer {
            chain_id: 1,
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(malformed_payload_request)
        .await
        .expect_err("malformed payload must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_broadcast_gas_policy_enforced_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    #[cfg(debug_assertions)]
    let server = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
    )
    .expect("server");
    #[cfg(not(debug_assertions))]
    let server =
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server");
    let client =
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client");

    let lease = client.issue_lease("vault-password").await.expect("lease");
    let admin = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                0,
                PolicyType::PerTxMaxSpending,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::Set(std::collections::BTreeSet::from([1_u64])),
            )
            .expect("per-tx policy"),
        )
        .await
        .expect("add per-tx policy");
    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                1,
                PolicyType::PerChainMaxGasSpend,
                1_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::Set(std::collections::BTreeSet::from([1_u64])),
            )
            .expect("gas policy"),
        )
        .await
        .expect("add gas policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("create_vault_key");
    let agent_credentials = client
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("create_agent_key");

    let allow_action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            value_wei: 0,
            data_hex: "0x".to_string(),
            gas_limit: 200_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    let allow_reservation = client
        .reserve_nonce(NonceReservationRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("reserve nonce for allow broadcast");
    assert_eq!(allow_reservation.nonce, 0);

    let allow_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&allow_action).expect("payload"),
        action: allow_action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let signature = client
        .sign_for_agent(allow_request)
        .await
        .expect("broadcast request should pass");
    assert!(!signature.bytes.is_empty());

    let deny_action = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 1,
            to: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            value_wei: 0,
            data_hex: "0x".to_string(),
            gas_limit: 2_000_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    let deny_reservation = client
        .reserve_nonce(NonceReservationRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 1,
            exact_nonce: false,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("reserve nonce for deny broadcast");
    assert_eq!(deny_reservation.nonce, 1);

    let deny_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&deny_action).expect("payload"),
        action: deny_action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(deny_request)
        .await
        .expect_err("gas policy should reject request");
    assert!(matches!(err, DaemonError::Policy(_)));

    client
        .release_nonce(vault_domain::NonceReleaseRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            reservation_id: deny_reservation.reservation_id,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("release deny reservation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_tx_metadata_policies_skip_non_broadcast_actions_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    #[cfg(debug_assertions)]
    let server = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
    )
    .expect("server");
    #[cfg(not(debug_assertions))]
    let server =
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server");
    let client =
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client");

    let lease = client.issue_lease("vault-password").await.expect("lease");
    let admin = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                0,
                PolicyType::PerTxMaxSpending,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("per-tx policy"),
        )
        .await
        .expect("add spend policy");
    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                1,
                PolicyType::PerChainMaxGasSpend,
                1_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("gas policy"),
        )
        .await
        .expect("add gas policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("create_vault_key");
    let agent_credentials = client
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("create_agent_key");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x6000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };
    let request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        payload: to_vec(&action).expect("payload"),
        action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    client
        .sign_for_agent(request)
        .await
        .expect("non-broadcast action should skip tx metadata policies");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_lifecycle_controls_and_policy_evaluation_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    #[cfg(debug_assertions)]
    let server = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
    )
    .expect("server");
    #[cfg(not(debug_assertions))]
    let server =
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server");
    let client =
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client");

    let lease = client.issue_lease("vault-password").await.expect("lease");
    let admin = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                0,
                PolicyType::PerTxMaxSpending,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("per-tx policy"),
        )
        .await
        .expect("add spend policy");
    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                1,
                PolicyType::DailyMaxTxCount,
                1,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("tx-count policy"),
        )
        .await
        .expect("add tx-count policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("create_vault_key");
    let agent_credentials = client
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("create_agent_key");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x5000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x6000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };
    let request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&action).expect("payload"),
        action: action.clone(),
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let evaluation = client
        .evaluate_for_agent(request.clone())
        .await
        .expect("policy evaluation should pass");
    assert_eq!(evaluation.evaluated_policy_ids.len(), 2);

    let rotated_token = client
        .rotate_agent_auth_token(&admin, agent_credentials.agent_key.id)
        .await
        .expect("rotate token");
    assert_ne!(rotated_token, agent_credentials.auth_token.as_str());

    let err = client
        .sign_for_agent(request.clone())
        .await
        .expect_err("old auth token must fail after rotation");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    let rotated_request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_auth_token: rotated_token.into(),
        ..request
    };
    let signature = client
        .sign_for_agent(rotated_request.clone())
        .await
        .expect("rotated token should sign");
    assert!(!signature.bytes.is_empty());

    let err = client
        .evaluate_for_agent(rotated_request.clone())
        .await
        .expect_err("daily tx count policy should deny second tx after a signed spend");
    assert!(matches!(err, DaemonError::Policy(_)));

    client
        .revoke_agent_key(&admin, agent_credentials.agent_key.id)
        .await
        .expect("revoke key");
    let err = client
        .sign_for_agent(rotated_request)
        .await
        .expect_err("revoked key must not sign");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_disable_policy_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    #[cfg(debug_assertions)]
    let server = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
    )
    .expect("server");
    #[cfg(not(debug_assertions))]
    let server =
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server");
    let client =
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client");

    let lease = client.issue_lease("vault-password").await.expect("lease");
    let admin = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let strict_policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("strict policy");
    client
        .add_policy(&admin, strict_policy.clone())
        .await
        .expect("add strict policy");
    client
        .add_policy(
            &admin,
            SpendingPolicy::new(
                1,
                PolicyType::PerTxMaxSpending,
                1_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("permissive policy"),
        )
        .await
        .expect("add permissive policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("create_vault_key");
    let agent_credentials = client
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("create_agent_key");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x7000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x8000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 500,
    };
    let request = SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        payload: to_vec(&action).expect("payload"),
        action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(request.clone())
        .await
        .expect_err("strict policy should reject");
    assert!(matches!(err, DaemonError::Policy(_)));

    client
        .disable_policy(&admin, strict_policy.id)
        .await
        .expect("disable strict policy");
    let signature = client
        .sign_for_agent(request)
        .await
        .expect("request should pass after strict policy is disabled");
    assert!(!signature.bytes.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_policy_set_agents_do_not_pick_up_policies_added_later_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    #[cfg(debug_assertions)]
    let server = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
    )
    .expect("server");
    #[cfg(not(debug_assertions))]
    let server =
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server");
    let client =
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client");

    let lease = client.issue_lease("vault-password").await.expect("lease");
    let admin = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let permissive_policy = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("permissive policy");
    client
        .add_policy(&admin, permissive_policy.clone())
        .await
        .expect("add permissive policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("create_vault_key");
    let agent_credentials = client
        .create_agent_key(
            &admin,
            vault_key.id,
            PolicyAttachment::PolicySet(std::collections::BTreeSet::from([permissive_policy.id])),
        )
        .await
        .expect("create_agent_key");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x8100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 500,
    };
    let make_request = || SignRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&action).expect("payload"),
        action: action.clone(),
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    client
        .sign_for_agent(make_request())
        .await
        .expect("explicit policy set should allow before adding a new policy");

    let strict_policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("strict policy");
    client
        .add_policy(&admin, strict_policy)
        .await
        .expect("add later strict policy");

    let explanation = client
        .explain_for_agent(make_request())
        .await
        .expect("explain after later policy");
    assert_eq!(explanation.attached_policy_ids, vec![permissive_policy.id]);
    assert_eq!(
        explanation.applicable_policy_ids,
        vec![permissive_policy.id]
    );
    assert_eq!(explanation.evaluated_policy_ids, vec![permissive_policy.id]);

    let signature = client
        .sign_for_agent(make_request())
        .await
        .expect("later policies must not retroactively attach to a policy set");
    assert!(!signature.bytes.is_empty());
}
