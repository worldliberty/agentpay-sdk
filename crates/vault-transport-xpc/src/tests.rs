use super::{
    decode_wire_request, decode_wire_response, encode_wire_request, encode_wire_response,
    enforce_wire_response_limits, extract_safe_request_id, get_dict_bool, get_dict_secret_string,
    get_dict_string, parse_code_sign_requirement, recv_matching_response, release_peer_block,
    retain_peer_block, serialize_wire_daemon_error, set_dict_bool, set_dict_string,
    validate_wire_lengths, IncomingWireMessage, WireDaemonError, WireRequest, WireResponse,
    XpcDaemonClient, XpcDaemonServer, XpcTransportError, MAX_WIRE_BODY_BYTES,
    MAX_WIRE_REQUEST_ID_BYTES,
};
use block::ConcreteBlock;
use std::collections::{BTreeSet, HashMap};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;
use vault_daemon::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};
use vault_domain::{
    AdminSession, AgentAction, AgentCredentials, EntityScope, ManualApprovalDecision,
    ManualApprovalStatus, NonceReleaseRequest, NonceReservationRequest, PolicyAttachment,
    SignRequest, SpendingPolicy,
};
use vault_policy::PolicyError;
use vault_signer::{KeyCreateRequest, SignerError, SoftwareSignerBackend};

fn test_daemon() -> Arc<InMemoryDaemon<SoftwareSignerBackend>> {
    Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    )
}

fn start_test_server(daemon: Arc<InMemoryDaemon<SoftwareSignerBackend>>) -> XpcDaemonServer {
    #[cfg(debug_assertions)]
    {
        XpcDaemonServer::start_inmemory_with_allowed_euid(
            daemon,
            tokio::runtime::Handle::current(),
            unsafe { libc::geteuid() },
        )
        .expect("server")
    }
    #[cfg(not(debug_assertions))]
    {
        XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current()).expect("server")
    }
}

fn connect_test_client(server: &XpcDaemonServer) -> XpcDaemonClient {
    XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client")
}

fn poison_mutex<T>(lock: &Arc<Mutex<T>>) {
    let lock = Arc::clone(lock);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = lock.lock().expect("lock");
        panic!("poison lock");
    }));
}

async fn admin_session(client: &XpcDaemonClient) -> AdminSession {
    let lease = client.issue_lease("vault-password").await.expect("lease");
    AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    }
}

fn transfer_action(amount_wei: u128) -> AgentAction {
    AgentAction::Transfer {
        chain_id: 1,
        token: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x8100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei,
    }
}

fn sign_request(agent_credentials: &AgentCredentials, action: AgentAction) -> SignRequest {
    SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: serde_json::to_vec(&action).expect("payload"),
        action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xpc_round_trip_for_issue_lease() {
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

    let lease = client
        .issue_lease("vault-password")
        .await
        .expect("issue_lease");
    assert!(lease.expires_at > lease.issued_at);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_inmemory_is_root_only_by_default() {
    if unsafe { libc::geteuid() } == 0 {
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

    let result = XpcDaemonServer::start_inmemory(daemon, tokio::runtime::Handle::current());
    assert!(matches!(result, Err(XpcTransportError::RequiresRoot)));
}

#[test]
fn code_sign_requirement_parser_rejects_invalid_syntax() {
    let err = match parse_code_sign_requirement("not valid requirement expression") {
        Ok(_) => panic!("invalid requirement expression must fail"),
        Err(err) => err,
    };
    assert!(matches!(err, XpcTransportError::CodeSigning(_)));
}

#[test]
fn code_sign_requirement_parser_accepts_valid_syntax() {
    parse_code_sign_requirement("anchor apple")
        .expect("well-formed requirement expression should parse");
}

#[test]
fn peer_block_registry_reports_poisoned_mutex() {
    let peer_blocks = Arc::new(Mutex::new(HashMap::new()));
    poison_mutex(&peer_blocks);

    let peer_block = ConcreteBlock::new(|_: super::XpcObject| {}).copy();

    let err = retain_peer_block(&peer_blocks, 7, &peer_block)
        .expect_err("poisoned peer block registry must fail");
    assert!(matches!(
        err,
        XpcTransportError::Internal(message) if message.contains("peer block registry lock poisoned")
    ));

    let err =
        release_peer_block(&peer_blocks, 7).expect_err("poisoned peer block registry must fail");
    assert!(matches!(
        err,
        XpcTransportError::Internal(message) if message.contains("peer block registry lock poisoned")
    ));
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_inmemory_rejects_invalid_code_sign_requirement() {
    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    let result = XpcDaemonServer::start_inmemory_with_allowed_euid_and_code_sign_requirement(
        daemon,
        tokio::runtime::Handle::current(),
        unsafe { libc::geteuid() },
        "this is not a valid requirement expression",
    );
    assert!(matches!(result, Err(XpcTransportError::CodeSigning(_))));
}

#[cfg(debug_assertions)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_inmemory_rejects_mismatched_allowed_euid() {
    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    let current_euid = unsafe { libc::geteuid() };
    let mismatched_euid = if current_euid == 0 { 1 } else { 0 };

    let result = XpcDaemonServer::start_inmemory_with_allowed_euid(
        daemon,
        tokio::runtime::Handle::current(),
        mismatched_euid,
    );
    assert!(matches!(result, Err(XpcTransportError::Internal(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_client_calls_do_not_cross_responses() {
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
    let client = Arc::new(
        XpcDaemonClient::connect(&server.endpoint(), Duration::from_secs(5)).expect("client"),
    );

    let c1 = client.clone();
    let c2 = client.clone();
    let (r1, r2) = tokio::join!(
        c1.issue_lease("vault-password"),
        c2.issue_lease("vault-password")
    );

    let lease1 = r1.expect("lease 1");
    let lease2 = r2.expect("lease 2");
    assert_ne!(lease1.lease_id, lease2.lease_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_error_variants_roundtrip_over_xpc() {
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
    let bad_session = vault_domain::AdminSession {
        vault_password: "wrong-password".to_string().into(),
        lease,
    };

    let err = client
        .list_policies(&bad_session)
        .await
        .expect_err("must return auth failure");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_policy_attachment_roundtrips_over_xpc() {
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
    let admin = vault_domain::AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("vault key");

    let err = client
        .create_agent_key(
            &admin,
            vault_key.id,
            vault_domain::PolicyAttachment::PolicySet(BTreeSet::new()),
        )
        .await
        .expect_err("empty attachment must fail");
    assert!(matches!(err, DaemonError::InvalidPolicyAttachment(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_policy_error_roundtrips_over_xpc() {
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
    let admin = vault_domain::AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let invalid_policy = vault_domain::SpendingPolicy {
        id: uuid::Uuid::new_v4(),
        priority: 0,
        policy_type: vault_domain::PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 0,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: vault_domain::EntityScope::All,
        assets: vault_domain::EntityScope::All,
        networks: vault_domain::EntityScope::All,
        approval_type: None,
        enabled: true,
    };

    let err = client
        .add_policy(&admin, invalid_policy)
        .await
        .expect_err("invalid policy must fail");
    assert!(
        matches!(err, DaemonError::Transport(ref msg) if msg.starts_with("invalid daemon request")),
        "unexpected error: {err:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signer_error_variants_roundtrip_over_xpc() {
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
    let admin = vault_domain::AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let err = client
        .create_vault_key(
            &admin,
            KeyCreateRequest::Import {
                private_key_hex: "0x1234".to_string().into(),
            },
        )
        .await
        .expect_err("invalid import key must fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::InvalidPrivateKey)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_config_error_roundtrips_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let config = DaemonConfig {
        lease_ttl: time::Duration::MAX,
        ..DaemonConfig::default()
    };
    let daemon = Arc::new(
        InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
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

    let err = client
        .issue_lease("vault-password")
        .await
        .expect_err("overflowing ttl must roundtrip as invalid config");
    assert!(matches!(err, DaemonError::InvalidConfig(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_agent_key_is_not_disclosed_over_xpc() {
    use serde_json::to_vec;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use vault_domain::{AgentAction, SignRequest};

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

    let token: vault_domain::EvmAddress = "0x7200000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: vault_domain::EvmAddress = "0x8200000000000000000000000000000000000000"
        .parse()
        .expect("recipient");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 1,
    };
    let request = SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "random-token".to_string().into(),
        payload: to_vec(&action).expect("payload"),
        action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(request)
        .await
        .expect_err("unknown key must not leak key existence");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_and_evaluation_roundtrip_over_xpc() {
    use serde_json::to_vec;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use vault_domain::{AgentAction, EntityScope, PolicyType, SignRequest, SpendingPolicy};

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
    let admin = vault_domain::AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let per_tx_policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    client
        .add_policy(&admin, per_tx_policy.clone())
        .await
        .expect("add policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let agent_credentials = client
        .create_agent_key(
            &admin,
            vault_key.id,
            vault_domain::PolicyAttachment::AllPolicies,
        )
        .await
        .expect("agent key");

    let token: vault_domain::EvmAddress = "0x7400000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: vault_domain::EvmAddress = "0x8400000000000000000000000000000000000000"
        .parse()
        .expect("recipient");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 5,
    };
    let request = SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        payload: to_vec(&action).expect("payload"),
        action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let evaluation = client
        .evaluate_for_agent(request.clone())
        .await
        .expect("evaluate_for_agent must succeed");
    assert_eq!(
        evaluation.evaluated_policy_ids,
        vec![per_tx_policy.id],
        "evaluation should report matched policy ids"
    );

    let rotated_auth_token = client
        .rotate_agent_auth_token(&admin, agent_credentials.agent_key.id)
        .await
        .expect("rotate token");
    assert_ne!(
        rotated_auth_token,
        agent_credentials.auth_token.as_str(),
        "rotation must issue a fresh token"
    );

    let old_token_err = client
        .evaluate_for_agent(request.clone())
        .await
        .expect_err("old token must fail after rotation");
    assert!(matches!(
        old_token_err,
        DaemonError::AgentAuthenticationFailed
    ));

    let mut rotated_request = request.clone();
    rotated_request.agent_auth_token = rotated_auth_token.into();
    client
        .evaluate_for_agent(rotated_request.clone())
        .await
        .expect("rotated token should evaluate");

    client
        .revoke_agent_key(&admin, agent_credentials.agent_key.id)
        .await
        .expect("revoke key");

    let revoked_err = client
        .sign_for_agent(rotated_request)
        .await
        .expect_err("revoked key must not sign");
    assert!(matches!(
        revoked_err,
        DaemonError::AgentAuthenticationFailed
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xpc_policy_set_agents_do_not_pick_up_policies_added_later() {
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

    let admin = admin_session(&client).await;

    let permissive_policy = SpendingPolicy::new(
        1,
        vault_domain::PolicyType::PerTxMaxSpending,
        100,
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
        .expect("vault key");
    let agent_credentials = client
        .create_agent_key(
            &admin,
            vault_key.id,
            PolicyAttachment::policy_set(BTreeSet::from([permissive_policy.id]))
                .expect("policy set"),
        )
        .await
        .expect("agent key");

    let first = client
        .evaluate_for_agent(sign_request(&agent_credentials, transfer_action(50)))
        .await
        .expect("explicit policy set should evaluate the attached policy");
    assert_eq!(first.evaluated_policy_ids, vec![permissive_policy.id]);

    let strict_policy = SpendingPolicy::new(
        0,
        vault_domain::PolicyType::PerTxMaxSpending,
        10,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("strict policy");
    client
        .add_policy(&admin, strict_policy)
        .await
        .expect("add later strict policy");

    let second = client
        .evaluate_for_agent(sign_request(&agent_credentials, transfer_action(50)))
        .await
        .expect("later policies must not retroactively attach");
    assert_eq!(second.evaluated_policy_ids, vec![permissive_policy.id]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_wire_request_body_is_rejected() {
    use serde_json::to_vec;
    use time::OffsetDateTime;
    use uuid::Uuid;
    use vault_domain::{AgentAction, SignRequest};

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

    let token: vault_domain::EvmAddress = "0x7300000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: vault_domain::EvmAddress = "0x8300000000000000000000000000000000000000"
        .parse()
        .expect("recipient");
    let action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 1,
    };
    let request = SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        // Force the serialized wire-body above transport cap.
        agent_auth_token: "a".repeat(MAX_WIRE_BODY_BYTES + 1).into(),
        payload: to_vec(&action).expect("payload"),
        action,
        requested_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = client
        .sign_for_agent(request)
        .await
        .expect_err("oversized wire body must fail");
    match err {
        DaemonError::Transport(msg) => {
            assert!(msg.contains("wire body exceeds max bytes"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_wire_response_body_is_rejected_without_timeout() {
    use vault_domain::{EntityScope, PolicyType, SpendingPolicy};

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

    let lease = daemon
        .issue_lease("vault-password")
        .await
        .expect("issue lease");
    let admin = vault_domain::AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    // Build one oversized policy so list_policies response exceeds the
    // transport body cap and must be downgraded to a bounded error.
    let mut recipients = std::collections::BTreeSet::new();
    for i in 0..8_000_u32 {
        let address = format!("0x{i:040x}").parse().expect("valid address");
        recipients.insert(address);
    }
    let policy = SpendingPolicy::new(
        0,
        PolicyType::PerTxMaxSpending,
        1,
        EntityScope::Set(recipients),
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    daemon.add_policy(&admin, policy).await.expect("add policy");

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

    let err = client
        .list_policies(&admin)
        .await
        .expect_err("oversized wire response must fail without timeout");
    match err {
        DaemonError::Transport(msg) => {
            assert!(msg.contains("wire body exceeds max bytes"));
        }
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn wire_length_validation_rejects_long_request_id() {
    let request_id = "r".repeat(MAX_WIRE_REQUEST_ID_BYTES + 1);
    let err = validate_wire_lengths(&request_id, "{}").expect_err("must reject");
    assert!(matches!(err, XpcTransportError::Protocol(_)));
}

#[test]
fn wire_length_validation_rejects_large_body() {
    let body = "x".repeat(MAX_WIRE_BODY_BYTES + 1);
    let err = validate_wire_lengths("ok-id", &body).expect_err("must reject");
    assert!(matches!(err, XpcTransportError::Protocol(_)));
}

#[test]
fn receive_loop_fails_fast_on_decode_errors() {
    let (tx, rx) = std::sync::mpsc::channel::<IncomingWireMessage>();
    tx.send(IncomingWireMessage::DecodeError(
        XpcTransportError::Protocol("bad response".to_string()),
    ))
    .expect("send");

    let err = recv_matching_response(
        &rx,
        "request-id",
        std::time::Instant::now() + Duration::from_secs(1),
    )
    .expect_err("decode errors must fail fast");

    assert!(matches!(err, XpcTransportError::Protocol(_)));
}

#[test]
fn receive_loop_ignores_stale_mismatched_response_then_accepts_matching() {
    let (tx, rx) = std::sync::mpsc::channel::<IncomingWireMessage>();
    tx.send(IncomingWireMessage::Response(super::WireResponse {
        request_id: "different-id".to_string(),
        ok: true,
        body_json: "{}".to_string().into(),
    }))
    .expect("send");
    tx.send(IncomingWireMessage::Response(super::WireResponse {
        request_id: "expected-id".to_string(),
        ok: true,
        body_json: "{}".to_string().into(),
    }))
    .expect("send");

    let response = recv_matching_response(
        &rx,
        "expected-id",
        std::time::Instant::now() + Duration::from_secs(1),
    )
    .expect("stale mismatched responses should be tolerated");
    assert_eq!(response.request_id, "expected-id");
}

#[test]
fn receive_loop_times_out_when_only_mismatched_responses_arrive() {
    let (tx, rx) = std::sync::mpsc::channel::<IncomingWireMessage>();
    for i in 0..32 {
        tx.send(IncomingWireMessage::Response(super::WireResponse {
            request_id: format!("wrong-{i}"),
            ok: true,
            body_json: "{}".to_string().into(),
        }))
        .expect("send");
    }

    let err = recv_matching_response(
        &rx,
        "expected-id",
        std::time::Instant::now() + Duration::from_secs(1),
    )
    .expect_err("mismatched responses must eventually timeout");
    assert!(matches!(err, XpcTransportError::Timeout));
}

#[test]
fn wire_daemon_error_roundtrip_covers_all_variants() {
    let vault_key_id = Uuid::new_v4();
    let agent_key_id = Uuid::new_v4();
    let policy_id = Uuid::new_v4();
    let approval_request_id = Uuid::new_v4();
    let reservation_id = Uuid::new_v4();

    macro_rules! assert_roundtrip {
        ($err:expr, $pat:pat $(if $guard:expr)? ) => {{
            let roundtrip = WireDaemonError::from($err).into_daemon_error();
            assert!(matches!(roundtrip, $pat $(if $guard)?));
        }};
    }

    assert_roundtrip!(
        DaemonError::AuthenticationFailed,
        DaemonError::AuthenticationFailed
    );
    assert_roundtrip!(DaemonError::UnknownLease, DaemonError::UnknownLease);
    assert_roundtrip!(DaemonError::InvalidLease, DaemonError::InvalidLease);
    assert_roundtrip!(
        DaemonError::TooManyActiveLeases,
        DaemonError::TooManyActiveLeases
    );
    assert_roundtrip!(
        DaemonError::UnknownVaultKey(vault_key_id),
        DaemonError::UnknownVaultKey(id) if id == vault_key_id
    );
    assert_roundtrip!(
        DaemonError::UnknownAgentKey(agent_key_id),
        DaemonError::UnknownAgentKey(id) if id == agent_key_id
    );
    assert_roundtrip!(
        DaemonError::UnknownPolicy(policy_id),
        DaemonError::UnknownPolicy(id) if id == policy_id
    );
    assert_roundtrip!(
        DaemonError::UnknownManualApprovalRequest(approval_request_id),
        DaemonError::UnknownManualApprovalRequest(id) if id == approval_request_id
    );
    assert_roundtrip!(
        DaemonError::AgentAuthenticationFailed,
        DaemonError::AgentAuthenticationFailed
    );
    assert_roundtrip!(
        DaemonError::PayloadActionMismatch,
        DaemonError::PayloadActionMismatch
    );
    assert_roundtrip!(
        DaemonError::PayloadTooLarge { max_bytes: 4096 },
        DaemonError::PayloadTooLarge { max_bytes } if max_bytes == 4096
    );
    assert_roundtrip!(
        DaemonError::InvalidRequestTimestamps,
        DaemonError::InvalidRequestTimestamps
    );
    assert_roundtrip!(DaemonError::RequestExpired, DaemonError::RequestExpired);
    assert_roundtrip!(
        DaemonError::RequestReplayDetected,
        DaemonError::RequestReplayDetected
    );
    assert_roundtrip!(
        DaemonError::TooManyTrackedReplayIds { max_tracked: 32 },
        DaemonError::TooManyTrackedReplayIds { max_tracked } if max_tracked == 32
    );
    assert_roundtrip!(
        DaemonError::InvalidPolicyAttachment("bad attachment".to_string()),
        DaemonError::InvalidPolicyAttachment(ref msg) if msg == "bad attachment"
    );
    assert_roundtrip!(
        DaemonError::InvalidNonceReservation("bad reservation".to_string()),
        DaemonError::InvalidNonceReservation(ref msg) if msg == "bad reservation"
    );
    assert_roundtrip!(
        DaemonError::TooManyActiveNonceReservations { max_active: 64 },
        DaemonError::TooManyActiveNonceReservations { max_active } if max_active == 64
    );
    assert_roundtrip!(
        DaemonError::NonceSkipTooLarge {
            requested_skip: 4096,
            max_skip: 1024,
        },
        DaemonError::NonceSkipTooLarge {
            requested_skip,
            max_skip,
        } if requested_skip == 4096 && max_skip == 1024
    );
    assert_roundtrip!(
        DaemonError::UnknownNonceReservation(reservation_id),
        DaemonError::UnknownNonceReservation(id) if id == reservation_id
    );
    assert_roundtrip!(
        DaemonError::MissingNonceReservation {
            chain_id: 1,
            nonce: 7
        },
        DaemonError::MissingNonceReservation { chain_id, nonce } if chain_id == 1 && nonce == 7
    );
    assert_roundtrip!(
        DaemonError::InvalidPolicy("bad policy".to_string()),
        DaemonError::InvalidPolicy(ref msg) if msg == "bad policy"
    );
    assert_roundtrip!(
        DaemonError::InvalidAction("bad action".to_string()),
        DaemonError::InvalidAction(ref msg) if msg == "bad action"
    );
    assert_roundtrip!(
        DaemonError::InvalidRelayConfig("bad relay".to_string()),
        DaemonError::InvalidRelayConfig(ref msg) if msg == "bad relay"
    );
    assert_roundtrip!(
        DaemonError::ManualApprovalRequired {
            approval_request_id,
            relay_url: Some("https://relay.example".to_string()),
            frontend_url: Some("https://frontend.example".to_string()),
        },
        DaemonError::ManualApprovalRequired {
            approval_request_id: id,
            ref relay_url,
            ref frontend_url,
        } if id == approval_request_id
            && relay_url.as_deref() == Some("https://relay.example")
            && frontend_url.as_deref() == Some("https://frontend.example")
    );
    assert_roundtrip!(
        DaemonError::ManualApprovalRejected { approval_request_id },
        DaemonError::ManualApprovalRejected { approval_request_id: id } if id == approval_request_id
    );
    assert_roundtrip!(
        DaemonError::ManualApprovalRequestNotPending {
            approval_request_id,
            status: ManualApprovalStatus::Completed,
        },
        DaemonError::ManualApprovalRequestNotPending {
            approval_request_id: id,
            status,
        } if id == approval_request_id && status == ManualApprovalStatus::Completed
    );
    assert_roundtrip!(
        DaemonError::TooManyPendingManualApprovalRequests {
            agent_key_id: approval_request_id,
            max_pending: 64,
        },
        DaemonError::TooManyPendingManualApprovalRequests {
            agent_key_id,
            max_pending,
        } if agent_key_id == approval_request_id && max_pending == 64
    );
    assert_roundtrip!(
        DaemonError::Policy(PolicyError::NoAttachedPolicies),
        DaemonError::Policy(PolicyError::NoAttachedPolicies)
    );
    assert_roundtrip!(
        DaemonError::Signer(SignerError::PermissionDenied("no root".to_string())),
        DaemonError::Signer(SignerError::PermissionDenied(ref msg)) if msg == "no root"
    );
    assert_roundtrip!(
        DaemonError::PasswordHash("bad hash".to_string()),
        DaemonError::PasswordHash(ref msg) if msg == "bad hash"
    );
    assert_roundtrip!(
        DaemonError::InvalidConfig("bad config".to_string()),
        DaemonError::InvalidConfig(ref msg) if msg == "bad config"
    );
    assert_roundtrip!(DaemonError::LockPoisoned, DaemonError::LockPoisoned);
    assert_roundtrip!(
        DaemonError::Transport("wire broken".to_string()),
        DaemonError::Transport(ref msg) if msg == "wire broken"
    );
    assert_roundtrip!(
        DaemonError::Persistence("disk full".to_string()),
        DaemonError::Persistence(ref msg) if msg == "disk full"
    );
}

#[test]
fn serialize_wire_daemon_error_and_response_limit_helpers_cover_remaining_paths() {
    let serialized = serialize_wire_daemon_error(DaemonError::Transport("transport".to_string()));
    let parsed: WireDaemonError = serde_json::from_str(&serialized).expect("deserialize");
    assert!(matches!(parsed, WireDaemonError::Transport(msg) if msg == "transport"));

    let passthrough = WireResponse {
        request_id: "ok-id".to_string(),
        ok: true,
        body_json: "{}".to_string().into(),
    };
    let passthrough = enforce_wire_response_limits(passthrough.clone());
    assert_eq!(passthrough.request_id, "ok-id");
    assert!(passthrough.ok);
    assert_eq!(passthrough.body_json.as_str(), "{}");

    let oversized_body = WireResponse {
        request_id: "ok-id".to_string(),
        ok: true,
        body_json: "x".repeat(MAX_WIRE_BODY_BYTES + 1).into(),
    };
    let oversized_body = enforce_wire_response_limits(oversized_body);
    assert_eq!(oversized_body.request_id, "ok-id");
    assert!(!oversized_body.ok);
    assert!(oversized_body
        .body_json
        .contains("wire body exceeds max bytes"));

    let oversized_id = WireResponse {
        request_id: "r".repeat(MAX_WIRE_REQUEST_ID_BYTES + 1),
        ok: true,
        body_json: "{}".to_string().into(),
    };
    let oversized_id = enforce_wire_response_limits(oversized_id);
    assert_eq!(oversized_id.request_id, Uuid::nil().to_string());
    assert!(!oversized_id.ok);
    assert!(oversized_id
        .body_json
        .contains("wire request id exceeds max bytes"));
}

#[test]
fn xpc_dictionary_helpers_roundtrip_and_guard_invalid_fields() {
    let wire_request = WireRequest {
        request_id: "request-1".to_string(),
        body_json: "{\"hello\":true}".to_string().into(),
    };
    let encoded_request = encode_wire_request(&wire_request).expect("encode request");
    let decoded_request = decode_wire_request(encoded_request).expect("decode request");
    assert_eq!(decoded_request.request_id, wire_request.request_id);
    assert_eq!(
        decoded_request.body_json.as_str(),
        wire_request.body_json.as_str()
    );
    unsafe {
        super::xpc_release(encoded_request);
    }

    let wire_response = WireResponse {
        request_id: "response-1".to_string(),
        ok: true,
        body_json: "{\"ok\":true}".to_string().into(),
    };
    let encoded_response = encode_wire_response(&wire_response).expect("encode response");
    let decoded_response = decode_wire_response(encoded_response).expect("decode response");
    assert_eq!(decoded_response.request_id, wire_response.request_id);
    assert!(decoded_response.ok);
    assert_eq!(
        decoded_response.body_json.as_str(),
        wire_response.body_json.as_str()
    );
    unsafe {
        super::xpc_release(encoded_response);
    }

    let dict = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    assert!(!dict.is_null());
    set_dict_string(dict, "agentpay_request_id", "request-2").expect("request id");
    set_dict_string(dict, "agentpay_kind", "response").expect("kind");
    set_dict_bool(dict, "agentpay_ok", false).expect("bool");
    assert_eq!(
        get_dict_string(dict, "agentpay_request_id").expect("read string"),
        "request-2"
    );
    assert_eq!(
        get_dict_secret_string(dict, "agentpay_request_id")
            .expect("read secret string")
            .as_str(),
        "request-2"
    );
    assert!(!get_dict_bool(dict, "agentpay_ok").expect("read bool"));
    assert!(matches!(
        get_dict_string(dict, "missing"),
        Err(XpcTransportError::Protocol(_))
    ));
    unsafe {
        super::xpc_release(dict);
    }

    let wrong_kind = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    assert!(!wrong_kind.is_null());
    set_dict_string(wrong_kind, "agentpay_kind", "wrong").expect("kind");
    set_dict_string(wrong_kind, "agentpay_request_id", "request-3").expect("request id");
    set_dict_string(wrong_kind, "agentpay_body", "{}").expect("body");
    assert!(matches!(
        decode_wire_request(wrong_kind),
        Err(XpcTransportError::Protocol(_))
    ));
    unsafe {
        super::xpc_release(wrong_kind);
    }

    let wrong_response_kind = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    assert!(!wrong_response_kind.is_null());
    set_dict_string(wrong_response_kind, "agentpay_kind", "request").expect("kind");
    set_dict_string(wrong_response_kind, "agentpay_request_id", "request-4").expect("request id");
    set_dict_string(wrong_response_kind, "agentpay_body", "{}").expect("body");
    set_dict_bool(wrong_response_kind, "agentpay_ok", true).expect("bool");
    assert!(matches!(
        decode_wire_response(wrong_response_kind),
        Err(XpcTransportError::Protocol(_))
    ));
    unsafe {
        super::xpc_release(wrong_response_kind);
    }

    let missing_id = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    assert_eq!(extract_safe_request_id(missing_id), Uuid::nil().to_string());
    unsafe {
        super::xpc_release(missing_id);
    }

    let oversized_id = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    set_dict_string(
        oversized_id,
        "agentpay_request_id",
        &"r".repeat(MAX_WIRE_REQUEST_ID_BYTES + 1),
    )
    .expect("oversized id");
    assert_eq!(
        extract_safe_request_id(oversized_id),
        Uuid::nil().to_string()
    );
    unsafe {
        super::xpc_release(oversized_id);
    }

    let valid_id = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    set_dict_string(valid_id, "agentpay_request_id", "request-5").expect("request id");
    assert_eq!(extract_safe_request_id(valid_id), "request-5");
    unsafe {
        super::xpc_release(valid_id);
    }

    let dict = unsafe { super::xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
    assert!(matches!(
        set_dict_string(dict, "bad\0key", "value"),
        Err(XpcTransportError::Protocol(_))
    ));
    assert!(matches!(
        set_dict_string(dict, "ok-key", "bad\0value"),
        Err(XpcTransportError::Protocol(_))
    ));
    assert!(matches!(
        set_dict_bool(dict, "bad\0key", true),
        Err(XpcTransportError::Protocol(_))
    ));
    assert!(matches!(
        get_dict_bool(dict, "bad\0key"),
        Err(XpcTransportError::Protocol(_))
    ));
    unsafe {
        super::xpc_release(dict);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remaining_admin_methods_roundtrip_over_xpc() {
    #[cfg(not(debug_assertions))]
    if unsafe { libc::geteuid() } != 0 {
        return;
    }

    let daemon = test_daemon();
    let server = start_test_server(daemon);
    let client = connect_test_client(&server);
    let admin = admin_session(&client).await;

    let imported_key = client
        .create_vault_key(
            &admin,
            KeyCreateRequest::Import {
                private_key_hex:
                    "0x1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string()
                        .into(),
            },
        )
        .await
        .expect("imported key");
    let exported = client
        .export_vault_private_key(&admin, imported_key.id)
        .await
        .expect("export key");
    assert!(exported.is_some());

    let relay_config = client
        .set_relay_config(
            &admin,
            Some("https://relay.example".to_string()),
            Some("https://frontend.example".to_string()),
        )
        .await
        .expect("set relay config");
    assert_eq!(
        relay_config.relay_url.as_deref(),
        Some("https://relay.example")
    );
    assert_eq!(
        relay_config.frontend_url.as_deref(),
        Some("https://frontend.example")
    );

    let fetched_relay_config = client
        .get_relay_config(&admin)
        .await
        .expect("get relay config");
    assert_eq!(fetched_relay_config, relay_config);

    let manual_policy = SpendingPolicy::new_manual_approval(
        0,
        1,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual policy");
    client
        .add_policy(&admin, manual_policy.clone())
        .await
        .expect("add manual approval policy");

    let vault_key = client
        .create_vault_key(&admin, KeyCreateRequest::Generate)
        .await
        .expect("vault key");
    let agent_credentials = client
        .create_agent_key(&admin, vault_key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent credentials");

    let request = sign_request(&agent_credentials, transfer_action(42));
    let explanation = client
        .explain_for_agent(request.clone())
        .await
        .expect("explain");
    assert!(
        explanation
            .evaluated_policy_ids
            .iter()
            .any(|entry| *entry == manual_policy.id),
        "manual approval policy must be part of explanation"
    );

    let reservation = client
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("reserve nonce");
    client
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: reservation.reservation_id,
            requested_at: OffsetDateTime::now_utc(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("release nonce");

    let approval_request_id = match client.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    let approval_requests = client
        .list_manual_approval_requests(&admin)
        .await
        .expect("list manual approvals");
    assert!(approval_requests
        .iter()
        .any(|item| item.id == approval_request_id));

    let approved = client
        .decide_manual_approval_request(
            &admin,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve manual approval");
    assert_eq!(approved.id, approval_request_id);
    assert_eq!(approved.status, ManualApprovalStatus::Approved);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xpc_endpoint_debug_and_code_sign_server_paths_are_exercised() {
    let daemon = test_daemon();

    let root_gated = XpcDaemonServer::start_inmemory_with_code_sign_requirement(
        daemon.clone(),
        tokio::runtime::Handle::current(),
        "anchor apple",
    );
    if unsafe { libc::geteuid() } != 0 {
        assert!(matches!(root_gated, Err(XpcTransportError::RequiresRoot)));
        return;
    }

    let server = root_gated.expect("root should start code-sign-gated server");
    let endpoint_debug = format!("{:?}", server.endpoint());
    assert!(endpoint_debug.contains("XpcEndpoint"));
}
