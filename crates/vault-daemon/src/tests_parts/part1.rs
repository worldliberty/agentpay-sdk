#[tokio::test]
async fn daemon_enforces_per_tx_limit() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(100))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    assert!(matches!(key.source, KeySource::Generated));

    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let token = "0x1000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x2000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 101,
        },
    );

    let result = daemon.sign_for_agent(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let bad_session = AdminSession {
        vault_password: "wrong".to_string().into(),
        lease,
    };

    let err = daemon
        .add_policy(&bad_session, policy_all_per_tx(100))
        .await
        .expect_err("must reject bad session");

    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn issue_lease_requires_correct_password() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let err = daemon
        .issue_lease("wrong-password")
        .await
        .expect_err("must reject bad password");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn oversized_admin_password_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let err = daemon
        .issue_lease(&"a".repeat((16 * 1024) + 1))
        .await
        .expect_err("must reject oversized password");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn repeated_failed_admin_password_attempts_trigger_temporary_lockout() {
    let config = DaemonConfig {
        max_failed_admin_auth_attempts: 2,
        admin_auth_lockout: time::Duration::hours(1),
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    let first = daemon
        .issue_lease("wrong-password")
        .await
        .expect_err("first bad password must fail");
    assert!(matches!(first, DaemonError::AuthenticationFailed));

    let second = daemon
        .issue_lease("wrong-password")
        .await
        .expect_err("second bad password must fail");
    assert!(matches!(second, DaemonError::AuthenticationFailed));

    let locked = daemon
        .issue_lease("vault-password")
        .await
        .expect_err("lockout should reject even correct password until it expires");
    assert!(matches!(locked, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn successful_admin_auth_resets_failed_password_counter() {
    let config = DaemonConfig {
        max_failed_admin_auth_attempts: 2,
        admin_auth_lockout: time::Duration::hours(1),
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    let first = daemon
        .issue_lease("wrong-password")
        .await
        .expect_err("bad password must fail");
    assert!(matches!(first, DaemonError::AuthenticationFailed));

    daemon
        .issue_lease("vault-password")
        .await
        .expect("correct password should reset failure counter");

    let next = daemon
        .issue_lease("wrong-password")
        .await
        .expect_err("later bad password must still fail without immediate lockout");
    assert!(matches!(next, DaemonError::AuthenticationFailed));

    daemon
        .issue_lease("vault-password")
        .await
        .expect("single later failure should not lock out correct password");
}

#[tokio::test]
async fn create_agent_key_validates_policy_set() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let mut ids = BTreeSet::new();
    ids.insert(Uuid::new_v4());

    let err = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(ids))
        .await
        .expect_err("unknown policy must fail");

    assert!(matches!(err, DaemonError::UnknownPolicy(_)));
}

#[tokio::test]
async fn create_agent_key_rejects_disabled_policy_set_member() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let disabled_policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, disabled_policy.clone())
        .await
        .expect("add policy");
    daemon
        .disable_policy(&session, disabled_policy.id)
        .await
        .expect("disable policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let ids = BTreeSet::from([disabled_policy.id]);
    let err = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(ids))
        .await
        .expect_err("disabled policy must fail");

    assert!(matches!(
        &err,
        DaemonError::InvalidPolicyAttachment(message) if message.contains("disabled")
    ));
}

#[tokio::test]
async fn create_agent_key_accepts_enabled_policy_set_member() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let enabled_policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, enabled_policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let ids = BTreeSet::from([enabled_policy.id]);
    let credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(ids.clone()))
        .await
        .expect("enabled policy set must succeed");

    assert_eq!(credentials.agent_key.vault_key_id, key.id);
    assert_eq!(credentials.agent_key.policies, PolicyAttachment::PolicySet(ids));
    assert!(!credentials.auth_token.is_empty());
}

#[tokio::test]
async fn create_agent_key_rejects_empty_policy_set() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let empty = std::collections::BTreeSet::new();
    let err = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::PolicySet(empty))
        .await
        .expect_err("empty policy set must fail");

    assert!(matches!(err, DaemonError::InvalidPolicyAttachment(_)));
}

#[tokio::test]
async fn disable_policy_prunes_policy_set_attachments() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, policy.clone())
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let credentials = daemon
        .create_agent_key(
            &session,
            key.id,
            PolicyAttachment::PolicySet(BTreeSet::from([policy.id])),
        )
        .await
        .expect("agent");

    daemon
        .disable_policy(&session, policy.id)
        .await
        .expect("disable policy");

    let snapshot = daemon.snapshot_state().expect("snapshot");
    let stored_agent = snapshot
        .agent_keys
        .get(&credentials.agent_key.id)
        .expect("stored agent");
    assert_eq!(stored_agent.policies, PolicyAttachment::PolicySet(BTreeSet::new()));
    validate_loaded_state(&snapshot).expect("pruned snapshot remains loadable");
}

#[tokio::test]
async fn daemon_backfills_default_relay_url() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let relay_config = daemon
        .get_relay_config(&session)
        .await
        .expect("get relay config");

    assert_eq!(
        relay_config.relay_url.as_deref(),
        Some("http://localhost:8787")
    );
    assert_eq!(relay_config.frontend_url, None);
    assert!(!relay_config.daemon_id_hex.trim().is_empty());
    assert!(!relay_config.daemon_public_key_hex.trim().is_empty());
}

#[tokio::test]
async fn set_relay_config_allows_loopback_http_and_remote_https() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let relay_config = daemon
        .set_relay_config(
            &session,
            Some("http://127.0.0.1:8787".to_string()),
            Some("https://relay.example".to_string()),
        )
        .await
        .expect("set relay config");

    assert_eq!(
        relay_config.relay_url.as_deref(),
        Some("http://127.0.0.1:8787")
    );
    assert_eq!(
        relay_config.frontend_url.as_deref(),
        Some("https://relay.example")
    );
}

#[tokio::test]
async fn set_relay_config_rejects_remote_http() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let err = daemon
        .set_relay_config(&session, Some("http://relay.example".to_string()), None)
        .await
        .expect_err("remote http relay URL must fail");

    assert!(
        matches!(err, DaemonError::InvalidRelayConfig(message) if message.contains("must use https unless it targets localhost or a loopback address"))
    );
}

#[tokio::test]
async fn set_relay_config_rejects_userinfo_query_or_fragment() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let userinfo_err = daemon
        .set_relay_config(
            &session,
            Some("https://admin:secret@relay.example".to_string()),
            None,
        )
        .await
        .expect_err("userinfo must fail");
    assert!(
        matches!(userinfo_err, DaemonError::InvalidRelayConfig(message) if message.contains("must not include embedded username or password"))
    );

    let query_err = daemon
        .set_relay_config(
            &session,
            None,
            Some("https://relay.example/ui?debug=1".to_string()),
        )
        .await
        .expect_err("query must fail");
    assert!(
        matches!(query_err, DaemonError::InvalidRelayConfig(message) if message.contains("must not include a query string"))
    );

    let fragment_err = daemon
        .set_relay_config(
            &session,
            None,
            Some("https://relay.example/ui#approval".to_string()),
        )
        .await
        .expect_err("fragment must fail");
    assert!(
        matches!(fragment_err, DaemonError::InvalidRelayConfig(message) if message.contains("must not include a fragment"))
    );
}

#[tokio::test]
async fn rpc_roundtrip_for_issue_lease() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let response = daemon
        .handle_rpc(DaemonRpcRequest::IssueLease {
            vault_password: "vault-password".to_string(),
        })
        .await
        .expect("rpc must succeed");

    match response {
        DaemonRpcResponse::Lease(lease) => {
            assert!(lease.expires_at > lease.issued_at);
        }
        _ => panic!("unexpected rpc response"),
    }
}

#[tokio::test]
async fn list_policies_requires_authenticated_session() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let bad_session = AdminSession {
        vault_password: "wrong".to_string().into(),
        lease,
    };

    let err = daemon
        .list_policies(&bad_session)
        .await
        .expect_err("must reject unauthenticated list request");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}

#[tokio::test]
async fn add_policy_rejects_invalid_policy_payloads() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let zero_max = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 0,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::All,
        assets: EntityScope::All,
        networks: EntityScope::All,
        approval_type: None,
        enabled: true,
    };
    let err = daemon
        .add_policy(&session, zero_max)
        .await
        .expect_err("zero max amount must be rejected");
    assert!(matches!(err, DaemonError::InvalidPolicy(_)));

    let empty_recipient_scope = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 1,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::Set(BTreeSet::new()),
        assets: EntityScope::All,
        networks: EntityScope::All,
        approval_type: None,
        enabled: true,
    };
    let err = daemon
        .add_policy(&session, empty_recipient_scope)
        .await
        .expect_err("empty recipient scope must be rejected");
    assert!(matches!(err, DaemonError::InvalidPolicy(_)));

    let empty_asset_scope = SpendingPolicy {
        id: Uuid::new_v4(),
        priority: 0,
        policy_type: PolicyType::PerTxMaxSpending,
        min_amount_wei: None,
        max_amount_wei: 1,
        max_tx_count: None,
        max_fee_per_gas_wei: None,
        max_priority_fee_per_gas_wei: None,
        max_calldata_bytes: None,
        max_gas_spend_wei: None,
        recipients: EntityScope::All,
        assets: EntityScope::Set(BTreeSet::new()),
        networks: EntityScope::All,
        approval_type: None,
        enabled: true,
    };
    let err = daemon
        .add_policy(&session, empty_asset_scope)
        .await
        .expect_err("empty asset scope must be rejected");
    assert!(matches!(err, DaemonError::InvalidPolicy(_)));
}

#[tokio::test]
async fn add_policy_rejects_duplicate_policy_ids() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let original = policy_all_per_tx(100);
    let mut duplicate = policy_all_per_tx(200);
    duplicate.id = original.id;

    daemon
        .add_policy(&session, original.clone())
        .await
        .expect("add original");

    let err = daemon
        .add_policy(&session, duplicate)
        .await
        .expect_err("duplicate policy id must be rejected");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message)
            if message.contains("already exists")
                && message.contains(&original.id.to_string())
    ));

    let listed = daemon.list_policies(&session).await.expect("list policies");
    let matching: Vec<SpendingPolicy> = listed
        .into_iter()
        .filter(|policy| policy.id == original.id)
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].max_amount_wei, original.max_amount_wei);
}

#[tokio::test]
async fn list_policies_is_deterministic_for_equal_priority() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let mut high_id = policy_all_per_tx(100);
    high_id.priority = 7;
    high_id.id = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").expect("uuid");

    let mut low_id = policy_all_per_tx(100);
    low_id.priority = 7;
    low_id.id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid");

    daemon
        .add_policy(&session, high_id.clone())
        .await
        .expect("add high id");
    daemon
        .add_policy(&session, low_id.clone())
        .await
        .expect("add low id");

    let listed = daemon.list_policies(&session).await.expect("list policies");
    let equal_priority: Vec<Uuid> = listed
        .into_iter()
        .filter(|p| p.priority == 7)
        .map(|p| p.id)
        .collect();
    assert_eq!(equal_priority, vec![low_id.id, high_id.id]);
}

#[tokio::test]
async fn lease_capacity_is_enforced() {
    let config = DaemonConfig {
        max_active_leases: 1,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    daemon
        .issue_lease("vault-password")
        .await
        .expect("first lease");
    let err = daemon
        .issue_lease("vault-password")
        .await
        .expect_err("second lease must fail at capacity");
    assert!(matches!(err, DaemonError::TooManyActiveLeases));
}

#[tokio::test]
async fn expired_leases_are_pruned_before_capacity_check() {
    let config = DaemonConfig {
        max_active_leases: 1,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    let now = time::OffsetDateTime::now_utc();
    let expired_id = Uuid::new_v4();
    daemon.leases.write().expect("leases write").insert(
        expired_id,
        Lease {
            lease_id: expired_id,
            issued_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
        },
    );

    let fresh = daemon
        .issue_lease("vault-password")
        .await
        .expect("must prune and issue");
    assert_eq!(daemon.leases.read().expect("leases read").len(), 1);
    assert_eq!(
        daemon
            .leases
            .read()
            .expect("leases read")
            .keys()
            .next()
            .copied(),
        Some(fresh.lease_id)
    );
}

#[tokio::test]
async fn not_yet_valid_leases_are_pruned_before_capacity_check() {
    let config = DaemonConfig {
        max_active_leases: 1,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    let now = time::OffsetDateTime::now_utc();
    let future_id = Uuid::new_v4();
    daemon.leases.write().expect("leases write").insert(
        future_id,
        Lease {
            lease_id: future_id,
            issued_at: now + time::Duration::hours(2),
            expires_at: now + time::Duration::hours(3),
        },
    );

    let fresh = daemon
        .issue_lease("vault-password")
        .await
        .expect("must prune invalid future lease and issue");
    assert_eq!(daemon.leases.read().expect("leases read").len(), 1);
    assert_eq!(
        daemon
            .leases
            .read()
            .expect("leases read")
            .keys()
            .next()
            .copied(),
        Some(fresh.lease_id)
    );
}

#[test]
fn daemon_new_rejects_invalid_runtime_limits() {
    let config = DaemonConfig {
        max_active_leases: 0,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "zero lease capacity must be rejected"
    );

    let config = DaemonConfig {
        max_sign_payload_bytes: 0,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "zero payload cap must be rejected"
    );

    let config = DaemonConfig {
        max_request_ttl: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive request ttl must be rejected"
    );

    let config = DaemonConfig {
        nonce_reservation_ttl: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive nonce reservation ttl must be rejected"
    );

    let config = DaemonConfig {
        manual_approval_terminal_retention: time::Duration::MAX,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(message)) if message.contains("manual_approval_terminal_retention")),
        "overflowing manual approval retention must be rejected"
    );

    let config = DaemonConfig {
        max_failed_admin_auth_attempts: 0,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "zero admin auth attempt budget must be rejected"
    );

    let config = DaemonConfig {
        admin_auth_lockout: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive admin auth lockout must be rejected"
    );

    let config = DaemonConfig {
        lease_ttl: time::Duration::ZERO,
        ..DaemonConfig::default()
    };
    let result = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config);
    assert!(
        matches!(result, Err(DaemonError::InvalidConfig(_))),
        "non-positive lease ttl must be rejected"
    );
}

#[tokio::test]
async fn issue_lease_fails_closed_when_ttl_overflows_timestamp() {
    let config = DaemonConfig {
        lease_ttl: time::Duration::MAX,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon should construct");

    let err = daemon
        .issue_lease("vault-password")
        .await
        .expect_err("overflowing ttl must fail safely");
    assert!(matches!(err, DaemonError::InvalidConfig(_)));
}

#[tokio::test]
async fn client_requested_at_cannot_bypass_window_limits() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };

    let policy = SpendingPolicy::new(
        0,
        PolicyType::DailyMaxSpending,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy");
    daemon
        .add_policy(&session, policy)
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

    let token = "0x3000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x4000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let mut first = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 60,
        },
    );
    // Intentionally stale; daemon must not trust this for spend accounting.
    first.requested_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(30);
    daemon.sign_for_agent(first).await.expect("first sign");

    let mut second = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 60,
        },
    );
    second.requested_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(30);
    let err = daemon
        .sign_for_agent(second)
        .await
        .expect_err("daily limit must reject second request");

    assert!(matches!(err, DaemonError::Policy(_)));
}

#[tokio::test]
async fn wrong_agent_auth_token_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let mut agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    agent_credentials.auth_token = "wrong-token".to_string().into();

    let token = "0x7000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 1,
            },
        ))
        .await
        .expect_err("must reject bad auth token");

    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test]
async fn oversized_agent_auth_token_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let mut agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    agent_credentials.auth_token = "a".repeat((16 * 1024) + 1).into();

    let token = "0x7000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 1,
            },
        ))
        .await
        .expect_err("must reject oversized auth token");

    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test]
async fn successful_sign_request_is_idempotent_for_same_request_id() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7100000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8100000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    let first = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("first request should pass");
    let second = daemon
        .sign_for_agent(request)
        .await
        .expect("identical replay should recover the original signature");
    assert_eq!(second, first);
}

#[tokio::test]
async fn sign_request_reuse_with_different_payload_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7100000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8100000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    daemon
        .sign_for_agent(request.clone())
        .await
        .expect("first request should pass");

    let mut replay = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7100000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8100000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 2,
        },
    );
    replay.request_id = request.request_id;

    let err = daemon
        .sign_for_agent(replay)
        .await
        .expect_err("mismatched replay must fail");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn signer_failure_does_not_consume_request_id() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        FlakySignerBackend::fail_first_payload(SignerError::Internal(
            "simulated signer timeout".to_string(),
        )),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7400000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8400000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    let err = daemon
        .sign_for_agent(request.clone())
        .await
        .expect_err("first signing attempt should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Internal(message))
            if message == "simulated signer timeout"
    ));

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("same request id should remain retryable after signer failure");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");

    let replay = daemon
        .sign_for_agent(request)
        .await
        .expect("successful request ids should remain idempotent after retry");
    assert_eq!(replay, signature);
}

#[tokio::test]
async fn expired_request_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7200000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8200000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );
    request.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("expired request should fail");
    assert!(matches!(err, DaemonError::RequestExpired));
}

#[tokio::test]
async fn future_requested_at_beyond_allowed_clock_skew_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let now = time::OffsetDateTime::now_utc();
    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7300000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8300000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );
    request.requested_at = now + time::Duration::seconds(31);
    request.expires_at = request.requested_at + time::Duration::minutes(2);

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("future-dated request must fail");
    assert!(matches!(err, DaemonError::InvalidRequestTimestamps));
}

#[tokio::test]
async fn request_ttl_longer_than_max_is_rejected() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(100))
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

    let now = time::OffsetDateTime::now_utc();
    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7400000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8400000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );
    request.requested_at = now;
    request.expires_at = now + time::Duration::minutes(6);

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("overlong request ttl must fail");
    assert!(matches!(err, DaemonError::InvalidRequestTimestamps));
}

#[test]
fn daemon_rejects_blank_admin_passwords_in_core_constructors() {
    let err = match InMemoryDaemon::new(
        " \t\n ",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    ) {
        Ok(_) => panic!("blank admin password must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::InvalidConfig(message) if message.contains("admin_password"))
    );

    let state_path = unique_state_path("blank-admin-password");
    let err = match InMemoryDaemon::new_with_persistent_store(
        "\n\r\t",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new(state_path.clone()),
    ) {
        Ok(_) => panic!("blank persistent-store admin password must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::InvalidConfig(message) if message.contains("admin_password"))
    );
    assert!(
        !state_path.exists(),
        "persistent store must not be created for blank passwords"
    );
}

#[test]
fn daemon_rejects_oversized_admin_passwords_in_core_constructors() {
    let oversized = "a".repeat((16 * 1024) + 1);
    let err = match InMemoryDaemon::new(
        &oversized,
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    ) {
        Ok(_) => panic!("oversized admin password must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::InvalidConfig(message) if message.contains("must not exceed"))
    );

    let state_path = unique_state_path("oversized-admin-password");
    let err = match InMemoryDaemon::new_with_persistent_store(
        &oversized,
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new(state_path.clone()),
    ) {
        Ok(_) => panic!("oversized persistent-store admin password must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::InvalidConfig(message) if message.contains("must not exceed"))
    );
    assert!(
        !state_path.exists(),
        "persistent store must not be created for oversized passwords"
    );
}

#[tokio::test]
async fn privileged_admin_mutators_require_authenticated_session() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string().into(),
        lease: lease.clone(),
    };
    let bad_session = AdminSession {
        vault_password: "wrong".to_string().into(),
        lease,
    };

    let policy = policy_all_per_tx(100);
    daemon
        .add_policy(&session, policy.clone())
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

    let err = daemon
        .disable_policy(&bad_session, policy.id)
        .await
        .expect_err("must reject disable_policy for bad session");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    let err = daemon
        .create_vault_key(&bad_session, KeyCreateRequest::Generate)
        .await
        .expect_err("must reject create_vault_key for bad session");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    let err = daemon
        .create_agent_key(&bad_session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect_err("must reject create_agent_key for bad session");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    let err = daemon
        .rotate_agent_auth_token(&bad_session, agent_credentials.agent_key.id)
        .await
        .expect_err("must reject rotate_agent_auth_token for bad session");
    assert!(matches!(err, DaemonError::AuthenticationFailed));

    let err = daemon
        .revoke_agent_key(&bad_session, agent_credentials.agent_key.id)
        .await
        .expect_err("must reject revoke_agent_key for bad session");
    assert!(matches!(err, DaemonError::AuthenticationFailed));
}
