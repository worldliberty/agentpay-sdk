#[tokio::test]
async fn disable_policy_stops_enforcement() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let mut strict = policy_all_per_tx(100);
    strict.priority = 0;
    let mut permissive = policy_all_per_tx(1_000);
    permissive.priority = 1;
    daemon
        .add_policy(&session, strict.clone())
        .await
        .expect("add strict policy");
    daemon
        .add_policy(&session, permissive)
        .await
        .expect("add permissive policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let deny_action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 500,
    };
    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, deny_action.clone()))
        .await
        .expect_err("strict policy must deny before disable");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::PerTxLimitExceeded { .. })
    ));

    daemon
        .disable_policy(&session, strict.id)
        .await
        .expect("disable strict policy");

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, deny_action))
        .await
        .expect("request should pass after strict policy disable");
    assert!(!signature.bytes.is_empty());
}

#[tokio::test]
async fn policy_set_agents_do_not_pick_up_policies_added_later() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let mut permissive = policy_all_per_tx(1_000);
    permissive.priority = 1;
    daemon
        .add_policy(&session, permissive.clone())
        .await
        .expect("add permissive policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let attached_policy_ids = BTreeSet::from([permissive.id]);
    let agent_credentials = daemon
        .create_agent_key(
            &session,
            key.id,
            PolicyAttachment::policy_set(attached_policy_ids.clone()).expect("policy set"),
        )
        .await
        .expect("agent");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2000000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 500,
    };
    let first = daemon
        .evaluate_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("explicit policy set should evaluate the attached policy");
    assert_eq!(first.evaluated_policy_ids, vec![permissive.id]);

    let mut strict = policy_all_per_tx(100);
    strict.priority = 0;
    daemon
        .add_policy(&session, strict)
        .await
        .expect("add later strict policy");

    let stored_attachment = daemon
        .agent_keys
        .read()
        .expect("agent keys")
        .get(&agent_credentials.agent_key.id)
        .map(|agent| agent.policies.clone())
        .expect("stored agent");
    assert_eq!(
        stored_attachment,
        PolicyAttachment::PolicySet(attached_policy_ids)
    );

    let second = daemon
        .evaluate_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect("later policies must not retroactively attach");
    assert_eq!(second.evaluated_policy_ids, vec![permissive.id]);
}

#[tokio::test]
async fn rotate_agent_auth_token_invalidates_previous_token() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
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
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
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
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
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
    drop(requests);

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
        "vault-password",
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

#[tokio::test]
async fn evaluate_for_agent_has_no_spend_side_effects() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("add spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::DailyMaxTxCount,
                1,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily tx count policy"),
        )
        .await
        .expect("add tx-count policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

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
    let request = sign_request(&agent_credentials, action.clone());

    let first = daemon
        .evaluate_for_agent(request.clone())
        .await
        .expect("first evaluation should pass");
    assert_eq!(first.evaluated_policy_ids.len(), 2);
    assert_eq!(daemon.spend_log.read().expect("log read").len(), 0);

    let second = daemon
        .evaluate_for_agent(request.clone())
        .await
        .expect("second evaluation should also pass (no spend side effects)");
    assert_eq!(first.evaluated_policy_ids, second.evaluated_policy_ids);
    assert_eq!(daemon.spend_log.read().expect("log read").len(), 0);

    daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("sign should pass once");
    let err = daemon
        .evaluate_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("tx-count policy should deny after signed spend is recorded");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::TxCountLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn daily_spend_limit_counts_in_scope_history_across_assets_and_chains() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                0,
                PolicyType::DailyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily spend policy"),
        )
        .await
        .expect("add daily spend policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x5100000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x6100000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 70,
            },
        ))
        .await
        .expect("first spend should pass");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::TransferNative {
                chain_id: 10,
                to: "0x6200000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 20,
            },
        ))
        .await
        .expect("second spend should pass");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 137,
                token: "0x5200000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x6200000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 15,
            },
        ))
        .await
        .expect_err("daily limit should deny after aggregate usage reaches 90");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            ..
        })
    ));
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_restores_policies_and_agent_auth_state() {
    let state_path = unique_state_path("restore");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let policy = policy_all_per_tx(1_000);
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

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1500000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2500000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 1,
    };
    let request = sign_request(&agent_credentials, action);
    daemon
        .evaluate_for_agent(request.clone())
        .await
        .expect("evaluate before restart");
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    let lease = restarted
        .issue_lease("vault-password")
        .await
        .expect("lease after restart");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    let listed = restarted
        .list_policies(&session)
        .await
        .expect("list policies");
    assert!(
        listed.iter().any(|item| item.id == policy.id),
        "policy should persist across restart"
    );
    restarted
        .evaluate_for_agent(request)
        .await
        .expect("evaluate after restart");
    restarted
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x1500000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0x2500000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("sign after restart");

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_restores_reclaimed_nonce_gaps_before_head() {
    let state_path = unique_state_path("nonce-gap-restore");
    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
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
    let first = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve first");
    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve second");
    let third = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve third");
    assert_eq!((first.nonce, second.nonce, third.nonce), (0, 1, 2));

    for reservation_id in [first.reservation_id, third.reservation_id] {
        daemon
            .release_nonce(NonceReleaseRequest {
                request_id: Uuid::new_v4(),
                agent_key_id: agent_credentials.agent_key.id,
                agent_auth_token: agent_credentials.auth_token.clone(),
                reservation_id,
                requested_at: now,
                expires_at: now + time::Duration::minutes(2),
            })
            .await
            .expect("release reclaimed gap");
    }

    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");

    let reclaimed_gap = restarted
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve reclaimed gap after restart");
    assert_eq!(reclaimed_gap.nonce, 0);

    let next_from_head = restarted
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve head after restart");
    assert_eq!(next_from_head.nonce, 2);

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_scrubs_expired_ephemeral_state_on_startup() {
    let state_path = unique_state_path("startup-scrub");
    let config = DaemonConfig {
        manual_approval_active_ttl: time::Duration::minutes(1),
        manual_approval_terminal_retention: time::Duration::minutes(1),
        ..DaemonConfig::default()
    };

    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy.clone())
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

    let mut stale_state = daemon.snapshot_state().expect("snapshot");
    stale_state.leases.clear();
    stale_state.replay_ids.clear();
    stale_state.nonce_heads.clear();
    stale_state.nonce_reservations.clear();
    stale_state.spend_log.clear();
    stale_state.manual_approval_requests.clear();

    let now = time::OffsetDateTime::now_utc();
    let stale_lease_id = Uuid::new_v4();
    stale_state.leases.insert(
        stale_lease_id,
        Lease {
            lease_id: stale_lease_id,
            issued_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
        },
    );

    let stale_replay_id = Uuid::new_v4();
    stale_state
        .replay_ids
        .insert(stale_replay_id, now - time::Duration::seconds(1));

    let mut stale_reservation = sample_nonce_reservation();
    stale_reservation.reservation_id = Uuid::new_v4();
    stale_reservation.agent_key_id = agent_credentials.agent_key.id;
    stale_reservation.vault_key_id = key.id;
    stale_reservation.chain_id = 1;
    stale_reservation.nonce = 0;
    stale_reservation.issued_at = now - time::Duration::minutes(5);
    stale_reservation.expires_at = now - time::Duration::minutes(4);
    let stale_reservation_id = stale_reservation.reservation_id;
    stale_state.nonce_heads.insert(
        key.id,
        std::collections::HashMap::from([(stale_reservation.chain_id, 1)]),
    );
    stale_state
        .nonce_reservations
        .insert(stale_reservation_id, stale_reservation);

    stale_state.spend_log.push(vault_domain::SpendEvent {
        agent_key_id: agent_credentials.agent_key.id,
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: "0x7100000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 7,
        at: now - time::Duration::days(9),
    });

    let mut stale_request = sample_manual_approval_request();
    stale_request.id = Uuid::new_v4();
    stale_request.agent_key_id = agent_credentials.agent_key.id;
    stale_request.vault_key_id = key.id;
    stale_request.created_at = now - time::Duration::minutes(5);
    stale_request.updated_at = now - time::Duration::minutes(5);
    stale_request.status = ManualApprovalStatus::Pending;
    stale_request.triggered_by_policy_ids = vec![manual_policy.id];
    let stale_request_id = stale_request.id;
    stale_state
        .manual_approval_requests
        .insert(stale_request_id, stale_request);

    let (store, _) = EncryptedStateStore::open_or_initialize(
        "vault-password",
        &config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("store");
    store.save(&stale_state).expect("write stale state");

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    assert!(
        !restarted
            .leases
            .read()
            .expect("leases")
            .contains_key(&stale_lease_id),
        "startup scrub must remove expired leases"
    );
    assert!(
        !restarted
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "startup scrub must remove expired replay ids"
    );
    assert!(
        !restarted
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "startup scrub must remove expired nonce reservations"
    );
    assert!(
        restarted
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "startup scrub must reclaim nonce heads tied only to expired reservations"
    );
    assert!(
        restarted.spend_log.read().expect("spend log").is_empty(),
        "startup scrub must remove expired spend history"
    );
    assert!(
        !restarted
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "startup scrub must remove expired manual approvals"
    );
    drop(restarted);

    let reloaded = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("reloaded daemon");
    assert!(
        !reloaded
            .leases
            .read()
            .expect("leases")
            .contains_key(&stale_lease_id),
        "startup scrub must persist cleaned leases"
    );
    assert!(
        !reloaded
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "startup scrub must persist cleaned replay ids"
    );
    assert!(
        !reloaded
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "startup scrub must persist cleaned reservations"
    );
    assert!(
        reloaded
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "startup scrub must persist reclaimed nonce heads"
    );
    assert!(
        reloaded.spend_log.read().expect("spend log").is_empty(),
        "startup scrub must persist cleaned spend history"
    );
    assert!(
        !reloaded
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "startup scrub must persist cleaned manual approvals"
    );
    drop(reloaded);

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn unrelated_persistence_paths_scrub_expired_ephemeral_state_before_save() {
    let state_path = unique_state_path("persist-scrub");
    let config = DaemonConfig {
        manual_approval_active_ttl: time::Duration::minutes(1),
        manual_approval_terminal_retention: time::Duration::minutes(1),
        ..DaemonConfig::default()
    };

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy.clone())
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
    let stale_lease_id = Uuid::new_v4();
    daemon.leases.write().expect("leases").insert(
        stale_lease_id,
        Lease {
            lease_id: stale_lease_id,
            issued_at: now - time::Duration::hours(2),
            expires_at: now - time::Duration::hours(1),
        },
    );

    let stale_replay_id = Uuid::new_v4();
    daemon
        .replay_ids
        .write()
        .expect("replay ids")
        .insert(stale_replay_id, now - time::Duration::seconds(1));

    let mut stale_reservation = sample_nonce_reservation();
    stale_reservation.reservation_id = Uuid::new_v4();
    stale_reservation.agent_key_id = agent_credentials.agent_key.id;
    stale_reservation.vault_key_id = key.id;
    stale_reservation.chain_id = 1;
    stale_reservation.nonce = 0;
    stale_reservation.issued_at = now - time::Duration::minutes(5);
    stale_reservation.expires_at = now - time::Duration::minutes(4);
    let stale_reservation_id = stale_reservation.reservation_id;
    daemon.nonce_heads.write().expect("nonce heads").insert(
        key.id,
        std::collections::HashMap::from([(stale_reservation.chain_id, 1)]),
    );
    daemon
        .nonce_reservations
        .write()
        .expect("nonce reservations")
        .insert(stale_reservation_id, stale_reservation);

    daemon
        .spend_log
        .write()
        .expect("spend log")
        .push(vault_domain::SpendEvent {
            agent_key_id: agent_credentials.agent_key.id,
            chain_id: 1,
            asset: AssetId::NativeEth,
            recipient: "0x7200000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 8,
            at: now - time::Duration::days(9),
        });

    let mut stale_request = sample_manual_approval_request();
    stale_request.id = Uuid::new_v4();
    stale_request.agent_key_id = agent_credentials.agent_key.id;
    stale_request.vault_key_id = key.id;
    stale_request.created_at = now - time::Duration::minutes(5);
    stale_request.updated_at = now - time::Duration::minutes(5);
    stale_request.status = ManualApprovalStatus::Pending;
    stale_request.triggered_by_policy_ids = vec![manual_policy.id];
    let stale_request_id = stale_request.id;
    daemon
        .manual_approval_requests
        .write()
        .expect("manual approvals")
        .insert(stale_request_id, stale_request);

    daemon
        .set_relay_config(
            &session,
            Some("https://relay.example".to_string()),
            Some("https://frontend.example".to_string()),
        )
        .await
        .expect("set relay config");

    assert!(
        !daemon
            .leases
            .read()
            .expect("leases")
            .contains_key(&stale_lease_id),
        "unrelated persistence must prune expired leases"
    );
    assert!(
        !daemon
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "unrelated persistence must prune expired replay ids"
    );
    assert!(
        !daemon
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "unrelated persistence must prune expired nonce reservations"
    );
    assert!(
        daemon
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "unrelated persistence must reclaim nonce heads tied only to expired reservations"
    );
    assert!(
        daemon.spend_log.read().expect("spend log").is_empty(),
        "unrelated persistence must prune expired spend history"
    );
    assert!(
        !daemon
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "unrelated persistence must prune expired manual approvals"
    );
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restarted daemon");
    assert!(
        !restarted
            .leases
            .read()
            .expect("leases")
            .contains_key(&stale_lease_id),
        "cleaned persistence must stay free of expired leases after restart"
    );
    assert!(
        !restarted
            .replay_ids
            .read()
            .expect("replay ids")
            .contains_key(&stale_replay_id),
        "cleaned persistence must stay free of expired replay ids after restart"
    );
    assert!(
        !restarted
            .nonce_reservations
            .read()
            .expect("nonce reservations")
            .contains_key(&stale_reservation_id),
        "cleaned persistence must stay free of expired nonce reservations after restart"
    );
    assert!(
        restarted
            .nonce_heads
            .read()
            .expect("nonce heads")
            .get(&key.id)
            .is_none(),
        "cleaned persistence must keep reclaimed nonce heads removed after restart"
    );
    assert!(
        restarted.spend_log.read().expect("spend log").is_empty(),
        "cleaned persistence must stay free of expired spend history after restart"
    );
    assert!(
        !restarted
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .contains_key(&stale_request_id),
        "cleaned persistence must stay free of expired manual approvals after restart"
    );
    drop(restarted);

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_rejects_wrong_password() {
    let state_path = unique_state_path("wrong-password");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(10))
        .await
        .expect("add policy");
    drop(daemon);

    let err = match InMemoryDaemon::new_with_persistent_store(
        "wrong-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    ) {
        Ok(_) => panic!("wrong password must fail state load"),
        Err(err) => err,
    };
    assert!(matches!(err, DaemonError::Persistence(_)));

    std::fs::remove_file(&state_path).expect("cleanup");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn sign_success_survives_post_sign_persist_failure_and_flushes_later() {
    use std::os::unix::fs::PermissionsExt;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "agentpay-daemon-sign-persist-recovery-{}-{}",
        std::process::id(),
        unique
    ));
    std::fs::create_dir_all(&root).expect("create persistence root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("secure persistence root");
    let state_path = root.join("daemon-state.enc");

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                0,
                PolicyType::DailyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily policy"),
        )
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

    let token = "0x7100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let first = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 40,
        },
    );

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770))
        .expect("make persistence root insecure");

    let signature = daemon
        .sign_for_agent(first.clone())
        .await
        .expect("signature must still be returned when post-sign persistence fails");
    assert!(!signature.bytes.is_empty());

    let recovered = daemon
        .sign_for_agent(first.clone())
        .await
        .expect("same request id must recover the stored signature");
    assert_eq!(recovered, signature);

    let spend_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: recipient.clone(),
                amount_wei: 70,
            },
        ))
        .await
        .expect_err("spend log must remain live in memory");
    assert!(matches!(
        spend_err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 40,
            requested_amount_wei: 70,
            ..
        })
    ));

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("restore persistence root permissions");
    daemon
        .add_policy(&session, policy_all_per_tx(1_000))
        .await
        .expect("later mutation should flush pending signed state");
    drop(daemon);

    let reloaded = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("reload daemon");

    let recovered = reloaded
        .sign_for_agent(first)
        .await
        .expect("persisted recovery cache should return the original signature");
    assert_eq!(recovered, signature);

    let spend_err = reloaded
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 70,
            },
        ))
        .await
        .expect_err("persisted spend log must survive restart");
    assert!(matches!(
        spend_err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 40,
            requested_amount_wei: 70,
            ..
        })
    ));

    drop(reloaded);
    std::fs::remove_dir_all(&root).expect("cleanup persistence root");
}

#[test]
fn validate_loaded_state_rejects_insecure_remote_http_relay_url() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let mut state = daemon.snapshot_state().expect("state snapshot");
    state.relay_config.relay_url = Some("http://relay.example".to_string());

    let err = validate_loaded_state(&state).expect_err("insecure persisted relay URL must fail");
    assert!(
        matches!(err, DaemonError::InvalidRelayConfig(message) if message.contains("must use https unless it targets localhost or a loopback address"))
    );
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_rejects_group_writable_ancestor_directory() {
    use std::os::unix::fs::PermissionsExt;

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "agentpay-daemon-persistence-parent-{}-{}",
        std::process::id(),
        unique
    ));
    let insecure = root.join("insecure");
    let leaf = insecure.join("leaf");
    std::fs::create_dir_all(&leaf).expect("create test directories");
    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o770))
        .expect("set insecure ancestor permissions");

    let err = match InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(leaf.join("daemon-state.enc")),
    ) {
        Ok(_) => panic!("group-writable ancestor must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::Persistence(message) if message.contains("state directory") && message.contains("must not be writable by group/other"))
    );

    std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o700))
        .expect("restore ancestor permissions for cleanup");
    std::fs::remove_dir_all(&root).expect("cleanup directories");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn persistent_store_rejects_group_readable_state_file() {
    use std::os::unix::fs::PermissionsExt;

    let state_path = unique_state_path("group-readable");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(10))
        .await
        .expect("add policy");
    drop(daemon);

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640))
        .expect("set insecure state file permissions");

    let err = match InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    ) {
        Ok(_) => panic!("group-readable state file must be rejected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DaemonError::Persistence(message) if message.contains("state file") && message.contains("must not grant group/other permissions"))
    );

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore state file permissions for cleanup");
    std::fs::remove_file(&state_path).expect("cleanup state file");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn sign_for_agent_recovers_signature_after_post_sign_persist_failure() {
    use std::os::unix::fs::PermissionsExt;

    let state_path = unique_state_path("recover-signature-after-persist-failure");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(10))
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
            token: "0x1600000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2600000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 1,
        },
    );

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o640))
        .expect("make state file unwritable for secure save");

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("signature should still be returned");
    assert!(!signature.bytes.is_empty());
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("snapshot after sign")
            .spend_log
            .len(),
        1
    );

    std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
        .expect("restore state file permissions");

    let recovered = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("retry should recover the original signature");
    assert_eq!(recovered, signature);
    assert_eq!(
        daemon
            .snapshot_state()
            .expect("snapshot after recovery")
            .spend_log
            .len(),
        1
    );

    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restart daemon");
    let recovered = restarted
        .sign_for_agent(request)
        .await
        .expect("restarted daemon should recover the original signature");
    assert_eq!(recovered, signature);

    std::fs::remove_file(&state_path).expect("cleanup state file");
}

#[cfg(unix)]
#[cfg(not(coverage))]
#[tokio::test]
async fn nonce_recovery_results_survive_restart() {
    let state_path = unique_state_path("recover-nonce-results-after-restart");
    let config = DaemonConfig::default();

    let daemon = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };
    daemon
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
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
    let reserve_request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };
    let reservation = daemon
        .reserve_nonce(reserve_request.clone())
        .await
        .expect("reserve");
    drop(daemon);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config.clone(),
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restart daemon");
    let recovered_reservation = restarted
        .reserve_nonce(reserve_request.clone())
        .await
        .expect("restart should recover original reservation");
    assert_eq!(recovered_reservation, reservation);

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: reservation.reservation_id,
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };
    restarted
        .release_nonce(release_request.clone())
        .await
        .expect("release");
    drop(restarted);

    let restarted = InMemoryDaemon::new_with_persistent_store(
        "vault-password",
        SoftwareSignerBackend::default(),
        config,
        PersistentStoreConfig::new_test(state_path.clone()),
    )
    .expect("restart daemon after release");
    restarted
        .release_nonce(release_request)
        .await
        .expect("restart should recover release success");
    assert!(restarted
        .snapshot_state()
        .expect("snapshot after recovered release")
        .nonce_reservations
        .is_empty());

    drop(restarted);
    std::fs::remove_file(&state_path).expect("cleanup state file");
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
        "vault-password",
        backend.clone(),
        DaemonConfig::default(),
        PersistentStoreConfig::new_test(state_path),
    )
    .expect("daemon");
    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

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
async fn manual_approval_requests_cannot_be_decided_after_resolution() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve request");

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Reject,
            Some("late rejection".to_string()),
        )
        .await
        .expect_err("resolved request must reject a second decision");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRequestNotPending {
            approval_request_id: id,
            status: ManualApprovalStatus::Approved,
        } if id == approval_request_id
    ));

    daemon
        .sign_for_agent(request)
        .await
        .expect("approved request should sign");

    let err = daemon
        .apply_relay_manual_approval_decision(
            "vault-password",
            approval_request_id,
            ManualApprovalDecision::Reject,
            Some("too late".to_string()),
        )
        .await
        .expect_err("completed request must reject relay retries");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRequestNotPending {
            approval_request_id: id,
            status: ManualApprovalStatus::Completed,
        } if id == approval_request_id
    ));
}

#[tokio::test]
async fn manual_approval_policy_hard_denies_amounts_above_maximum() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        10,
        100,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy.clone())
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
                amount_wei: 101,
            },
        ))
        .await
        .expect_err("amounts above manual approval max must be denied");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::AmountExceeded {
            policy_id,
            max_amount_wei: 100,
            requested_amount_wei: 101,
        }) if policy_id == manual_policy.id
    ));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .is_empty(),
        "hard-denied requests must not create manual approval entries"
    );
}

#[tokio::test]
async fn poisoned_manual_approval_link_secret_lock_fails_without_creating_request() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
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

    poison_rwlock(&daemon.relay_private_key_hex);

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
                amount_wei: 42,
            },
        ))
        .await
        .expect_err("poisoned relay key lock must fail");
    assert!(matches!(err, DaemonError::LockPoisoned));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests read")
            .is_empty()
    );
}

#[tokio::test]
async fn rejected_manual_approval_requests_block_new_matching_requests_while_retained() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
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
            token: "0x1600000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2600000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );

    let rejected_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            rejected_id,
            ManualApprovalDecision::Reject,
            Some("not approved".to_string()),
        )
        .await
        .expect("reject request");

    let err = daemon
        .sign_for_agent(request.clone())
        .await
        .expect_err("retained rejected approval must block identical payloads");
    assert!(matches!(
        err,
        DaemonError::ManualApprovalRejected {
            approval_request_id
        } if approval_request_id == rejected_id
    ));

    {
        let requests = daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read");
        assert_eq!(
            requests
                .get(&rejected_id)
                .expect("rejected request should remain during retention")
                .status,
            ManualApprovalStatus::Rejected
        );
        assert_eq!(requests.len(), 1);
    }

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write");
        let rejected = requests
            .get_mut(&rejected_id)
            .expect("rejected request to age out");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::days(9);
        rejected.created_at = stale_at;
        rejected.updated_at = stale_at;
    }

    let replacement_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request after retention, got {other:?}"),
    };
    assert_ne!(replacement_id, rejected_id);
}

#[tokio::test]
async fn manual_approval_requests_expire_before_reuse() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            manual_approval_active_ttl: time::Duration::minutes(1),
            ..DaemonConfig::default()
        },
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                1,
                1,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
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

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1700000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2700000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 42,
    };

    let stale_pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write after first pending");
        let stale_pending = requests
            .get_mut(&stale_pending_id)
            .expect("stale pending request");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(2);
        stale_pending.created_at = stale_at;
        stale_pending.updated_at = stale_at;
    }
    assert!(
        daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list stale pending approvals")
            .is_empty(),
        "stale pending approvals must not be listed"
    );
    assert!(
        daemon
            .relay_registration_snapshot()
            .expect("snapshot after pending expiry")
            .manual_approval_requests
            .is_empty(),
        "stale pending approvals must not be included in relay snapshots"
    );

    let fresh_pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request, got {other:?}"),
    };
    assert_ne!(
        fresh_pending_id, stale_pending_id,
        "expired pending approvals must not be reused"
    );
    assert!(
        !daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read after pending expiry")
            .contains_key(&stale_pending_id),
        "creating a fresh approval should prune the stale pending request"
    );

    daemon
        .decide_manual_approval_request(
            &session,
            fresh_pending_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve fresh request");

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write after approval");
        let stale_approved = requests
            .get_mut(&fresh_pending_id)
            .expect("stale approved request");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(2);
        stale_approved.created_at = stale_at;
        stale_approved.updated_at = stale_at;
    }
    assert!(
        daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list stale approved approvals")
            .is_empty(),
        "stale approved approvals must not be listed"
    );

    let replacement_pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected replacement manual approval request, got {other:?}"),
    };
    assert_ne!(
        replacement_pending_id, fresh_pending_id,
        "expired approved approvals must not be reused"
    );

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("manual approval read");
    assert!(
        !requests.contains_key(&fresh_pending_id),
        "creating a replacement approval should prune the stale approved request"
    );
    assert_eq!(
        requests
            .get(&replacement_pending_id)
            .expect("replacement pending request")
            .status,
        ManualApprovalStatus::Pending
    );
}

#[tokio::test]
async fn approving_manual_approval_request_requires_triggering_policy_to_remain_enabled() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    let manual_policy_id = manual_policy.id;
    daemon
        .add_policy(&session, manual_policy)
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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .disable_policy(&session, manual_policy_id)
        .await
        .expect("disable policy");

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect_err("approval must fail when triggering policy is disabled");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message)
            if message.contains("references disabled policy")
                && message.contains(&manual_policy_id.to_string())
    ));

    let request = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .get(&approval_request_id)
        .cloned()
        .expect("request");
    assert_eq!(request.status, ManualApprovalStatus::Pending);
    assert!(request.rejection_reason.is_none());
}

#[tokio::test]
async fn approving_manual_approval_request_requires_triggering_policy_to_still_exist() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    let manual_policy_id = manual_policy.id;
    daemon
        .add_policy(&session, manual_policy)
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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .policies
        .write()
        .expect("policies")
        .remove(&manual_policy_id);

    let err = daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect_err("approval must fail when triggering policy is missing");
    assert!(matches!(err, DaemonError::UnknownPolicy(id) if id == manual_policy_id));

    let request = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .get(&approval_request_id)
        .cloned()
        .expect("request");
    assert_eq!(request.status, ManualApprovalStatus::Pending);
    assert!(request.rejection_reason.is_none());
}

fn assert_solana_transaction_starts_with_nonce_advance(signature: &Signature) {
    let raw_tx_base64 = signature
        .raw_tx_base64
        .as_ref()
        .expect("signed solana transaction");
    let raw_tx = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        raw_tx_base64,
    )
    .expect("decode raw solana tx");
    let tx: solana_sdk::transaction::Transaction =
        bincode::deserialize(&raw_tx).expect("deserialize solana tx");
    let first_instruction = tx
        .message
        .instructions
        .first()
        .expect("nonce advance instruction");
    assert_eq!(first_instruction.data, 4u32.to_le_bytes());
    let program_id = tx.message.account_keys[first_instruction.program_id_index as usize];
    assert_eq!(
        program_id.to_string(),
        "11111111111111111111111111111111"
    );
}

fn assert_solana_nonce_account_create_transaction(signature: &Signature) {
    let raw_tx_base64 = signature
        .raw_tx_base64
        .as_ref()
        .expect("signed solana transaction");
    let raw_tx = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        raw_tx_base64,
    )
    .expect("decode raw solana tx");
    let tx: solana_sdk::transaction::Transaction =
        bincode::deserialize(&raw_tx).expect("deserialize solana tx");
    assert_eq!(tx.message.instructions.len(), 2);

    let create_instruction = &tx.message.instructions[0];
    let initialize_instruction = &tx.message.instructions[1];
    assert_eq!(
        &create_instruction.data[..4],
        &3u32.to_le_bytes(),
        "first instruction must be SystemProgram::CreateAccountWithSeed"
    );
    assert_eq!(
        &initialize_instruction.data[..4],
        &6u32.to_le_bytes(),
        "second instruction must be SystemProgram::InitializeNonceAccount"
    );
    for instruction in [create_instruction, initialize_instruction] {
        let program_id = tx.message.account_keys[instruction.program_id_index as usize];
        assert_eq!(
            program_id.to_string(),
            "11111111111111111111111111111111"
        );
    }
}

#[tokio::test]
async fn solana_nonce_account_create_bypasses_manual_approval_and_spend_log() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let signature = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_solana_nonce_account_create_action(&key),
        ))
        .await
        .expect("nonce account creation should sign without manual approval");

    assert!(!signature.bytes.is_empty());
    assert_solana_nonce_account_create_transaction(&signature);
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests")
            .is_empty(),
        "internal nonce setup must not enqueue manual approval requests"
    );
    assert!(
        daemon.spend_log.read().expect("spend log").is_empty(),
        "internal nonce setup must not count as user spend"
    );
}

#[tokio::test]
async fn solana_spl_transfer_manual_approval_requires_managed_durable_nonce_setup() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_solana_spl_transfer_action(&key),
        ))
        .await
        .expect_err("direct solana manual approval without nonce setup should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Unsupported(message))
            if message.contains("solana manual approval requires AgentPay-managed durable nonce setup")
    ));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests")
            .is_empty(),
        "direct solana manual-approval attempts without nonce setup must not enqueue requests"
    );
}

#[tokio::test]
async fn solana_spl_transfer_manual_approval_signs_with_durable_nonce() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut action = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut action {
        transfer.durable_nonce_account = Some(
            bs58::encode([3u8; 32])
                .into_string()
                .parse()
                .expect("durable nonce account"),
        );
    }
    let approval_request_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected solana manual approval request, got {other:?}"),
    };
    assert_eq!(
        daemon
            .manual_approval_requests
            .read()
            .expect("requests")
            .len(),
        1
    );

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve solana request");

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect("approved solana transfer should sign with durable nonce");
    assert!(!signature.bytes.is_empty());
    assert_solana_transaction_starts_with_nonce_advance(&signature);

    let requests = daemon.manual_approval_requests.read().expect("requests");
    let request = requests
        .get(&approval_request_id)
        .expect("approval request retained");
    assert_eq!(request.status, ManualApprovalStatus::Completed);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn solana_sol_transfer_manual_approval_signs_with_durable_nonce() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy)
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut action = sample_solana_sol_transfer_action(&key);
    if let AgentAction::SolanaSolTransfer { transfer } = &mut action {
        transfer.durable_nonce_account = Some(
            bs58::encode([3u8; 32])
                .into_string()
                .parse()
                .expect("durable nonce account"),
        );
    }
    let approval_request_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected solana manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve solana request");

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect("approved solana transfer should sign with durable nonce");
    assert!(!signature.bytes.is_empty());
    assert_solana_transaction_starts_with_nonce_advance(&signature);

    let requests = daemon.manual_approval_requests.read().expect("requests");
    let request = requests
        .get(&approval_request_id)
        .expect("approval request retained");
    assert_eq!(request.status, ManualApprovalStatus::Completed);
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn solana_spl_transfer_respects_per_tx_spending_policy() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(&session, policy_all_per_tx(10))
        .await
        .expect("add policy");

    let key = daemon
        .create_vault_key(
            &session,
            KeyCreateRequest::GenerateWithAlgorithm {
                algorithm: KeyAlgorithm::Ed25519,
            },
        )
        .await
        .expect("ed25519 key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let mut allowed_action = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut allowed_action {
        transfer.amount_wei = 5;
    }
    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, allowed_action))
        .await
        .expect("solana action within per-tx limit should sign");
    assert!(!signature.bytes.is_empty());

    let mut denied_action = sample_solana_spl_transfer_action(&key);
    if let AgentAction::SolanaSplTransfer { transfer } = &mut denied_action {
        transfer.amount_wei = 11;
    }
    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, denied_action))
        .await
        .expect_err("solana action above per-tx limit should be denied");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::PerTxLimitExceeded {
            max_amount_wei: 10,
            requested_amount_wei: 11,
            ..
        })
    ));
}

#[tokio::test]
async fn approved_manual_approval_is_not_reused_after_triggering_policy_changes() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy_a = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy a");
    let manual_policy_a_id = manual_policy_a.id;
    daemon
        .add_policy(&session, manual_policy_a)
        .await
        .expect("add policy a");

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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let first_approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            first_approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve first request");

    daemon
        .disable_policy(&session, manual_policy_a_id)
        .await
        .expect("disable policy a");

    let manual_policy_b = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy b");
    let manual_policy_b_id = manual_policy_b.id;
    daemon
        .add_policy(&session, manual_policy_b)
        .await
        .expect("add policy b");

    let second_approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request, got {other:?}"),
    };
    assert_ne!(second_approval_request_id, first_approval_request_id);

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .clone();
    let first = requests
        .get(&first_approval_request_id)
        .cloned()
        .expect("first request");
    let second = requests
        .get(&second_approval_request_id)
        .cloned()
        .expect("second request");
    assert_eq!(first.status, ManualApprovalStatus::Approved);
    assert_eq!(first.triggered_by_policy_ids, vec![manual_policy_a_id]);
    assert_eq!(second.status, ManualApprovalStatus::Pending);
    assert_eq!(second.triggered_by_policy_ids, vec![manual_policy_b_id]);
}

#[tokio::test]
async fn rejected_manual_approval_is_not_reused_after_triggering_policy_changes() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy_a = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy a");
    let manual_policy_a_id = manual_policy_a.id;
    daemon
        .add_policy(&session, manual_policy_a)
        .await
        .expect("add policy a");

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
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 42,
        },
    );
    let first_approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            first_approval_request_id,
            ManualApprovalDecision::Reject,
            Some("policy a rejected".to_string()),
        )
        .await
        .expect("reject first request");

    daemon
        .disable_policy(&session, manual_policy_a_id)
        .await
        .expect("disable policy a");

    let manual_policy_b = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy b");
    let manual_policy_b_id = manual_policy_b.id;
    daemon
        .add_policy(&session, manual_policy_b)
        .await
        .expect("add policy b");

    let second_approval_request_id = match daemon.sign_for_agent(request).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected fresh manual approval request, got {other:?}"),
    };
    assert_ne!(second_approval_request_id, first_approval_request_id);

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("requests")
        .clone();
    let first = requests
        .get(&first_approval_request_id)
        .cloned()
        .expect("first request");
    let second = requests
        .get(&second_approval_request_id)
        .cloned()
        .expect("second request");
    assert_eq!(first.status, ManualApprovalStatus::Rejected);
    assert_eq!(first.triggered_by_policy_ids, vec![manual_policy_a_id]);
    assert_eq!(second.status, ManualApprovalStatus::Pending);
    assert_eq!(second.triggered_by_policy_ids, vec![manual_policy_b_id]);
}

#[tokio::test]
async fn add_policy_prioritizes_retained_manual_approval_error_before_duplicate_id_conflict() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            manual_approval_active_ttl: time::Duration::minutes(1),
            ..DaemonConfig::default()
        },
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let manual_policy = SpendingPolicy::new_manual_approval(
        1,
        1,
        1_000_000_000_000_000_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("manual approval policy");
    daemon
        .add_policy(&session, manual_policy.clone())
        .await
        .expect("add manual policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: "0x1800000000000000000000000000000000000000"
            .parse()
            .expect("token"),
        to: "0x2800000000000000000000000000000000000000"
            .parse()
            .expect("recipient"),
        amount_wei: 42,
    };
    let pending_id = match daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
    {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    let mut replacement = policy_all_per_tx(1_000_000_000_000_000_000);
    replacement.id = manual_policy.id;
    let err = daemon
        .add_policy(&session, replacement.clone())
        .await
        .expect_err("non-manual replacement must be blocked while approval is retained");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message)
            if message.contains("cannot change away from manual approval")
    ));
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read after blocked replacement")
            .contains_key(&pending_id),
        "blocked replacement must not discard retained approval requests"
    );

    {
        let mut requests = daemon
            .manual_approval_requests
            .write()
            .expect("manual approval write before successful replacement");
        let stale_pending = requests
            .get_mut(&pending_id)
            .expect("pending request to expire");
        let stale_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(2);
        stale_pending.created_at = stale_at;
        stale_pending.updated_at = stale_at;
    }
    assert!(
        daemon
            .list_manual_approval_requests(&session)
            .await
            .expect("list approvals after active ttl")
            .is_empty(),
        "expired approvals must disappear from admin listings before replacement"
    );

    let err = daemon
        .add_policy(&session, replacement)
        .await
        .expect_err("duplicate policy id should still be rejected after retained approvals expire");
    assert!(matches!(
        err,
        DaemonError::InvalidPolicy(message) if message.contains("already exists")
    ));
    assert_eq!(
        daemon
            .policies
            .read()
            .expect("policy read after replacement")
            .get(&manual_policy.id)
            .expect("manual policy present")
            .policy_type,
        PolicyType::ManualApproval
    );
    assert!(
        !daemon
            .manual_approval_requests
            .read()
            .expect("manual approval read after duplicate rejection")
            .contains_key(&pending_id),
        "duplicate rejection should still prune stale approvals that referenced the manual policy"
    );
}

#[tokio::test]
async fn completed_manual_approval_spend_counts_toward_later_auto_approved_limits() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                0,
                20,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
        .await
        .expect("add manual policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::DailyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("daily spend policy"),
        )
        .await
        .expect("add daily policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let token: EvmAddress = "0x1000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0x2000000000000000000000000000000000000000"
        .parse()
        .expect("recipient");

    for amount in [10_u128, 5, 5] {
        daemon
            .sign_for_agent(sign_request(
                &agent_credentials,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: token.clone(),
                    to: recipient.clone(),
                    amount_wei: amount,
                },
            ))
            .await
            .expect("auto-approved spend should sign");
    }

    for amount in [30_u128, 40] {
        let request = sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: recipient.clone(),
                amount_wei: amount,
            },
        );
        let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
            Err(DaemonError::ManualApprovalRequired {
                approval_request_id,
                ..
            }) => approval_request_id,
            other => panic!("expected manual approval request, got {other:?}"),
        };

        daemon
            .decide_manual_approval_request(
                &session,
                approval_request_id,
                ManualApprovalDecision::Approve,
                None,
            )
            .await
            .expect("approve request");

        daemon
            .sign_for_agent(request)
            .await
            .expect("approved request should sign");
    }

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 15,
            },
        ))
        .await
        .expect_err("later auto-approved spend should be denied after manual usage reaches 90");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            max_amount_wei: 100,
            ..
        })
    ));
}

fn sample_eip712_mail_action(chain_id: u64) -> AgentAction {
    AgentAction::Eip712TypedData {
        typed_data: vault_domain::Eip712TypedData {
            typed_data_json: format!(
                r#"{{
  "types": {{
    "EIP712Domain": [
      {{ "name": "name", "type": "string" }},
      {{ "name": "version", "type": "string" }},
      {{ "name": "chainId", "type": "uint256" }},
      {{ "name": "verifyingContract", "type": "address" }}
    ],
    "Mail": [
      {{ "name": "contents", "type": "string" }}
    ]
  }},
  "primaryType": "Mail",
  "domain": {{
    "name": "AgentPay Test",
    "version": "1",
    "chainId": {chain_id},
    "verifyingContract": "0x1111111111111111111111111111111111111111"
  }},
  "message": {{
    "contents": "hello"
  }}
}}"#
            ),
        },
    }
}

#[tokio::test]
async fn eip712_defaults_to_manual_approval_and_does_not_record_spend() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let request = sign_request(&agent_credentials, sample_eip712_mail_action(1));
    let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
        Err(DaemonError::ManualApprovalRequired {
            approval_request_id,
            ..
        }) => approval_request_id,
        other => panic!("expected manual approval request, got {other:?}"),
    };

    daemon
        .decide_manual_approval_request(
            &session,
            approval_request_id,
            ManualApprovalDecision::Approve,
            None,
        )
        .await
        .expect("approve request");

    daemon
        .sign_for_agent(request)
        .await
        .expect("approved eip712 request should sign");

    assert!(
        daemon
            .spend_log
            .read()
            .expect("spend log")
            .is_empty(),
        "generic eip712 signing must not create spend log entries"
    );
}

#[tokio::test]
async fn eip712_allow_policy_signs_without_manual_approval() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let allow_policy = SpendingPolicy::new_eip712_signing(
        1,
        vault_domain::ApprovalType::Allow,
        EntityScope::All,
    )
    .expect("policy");
    daemon
        .add_policy(&session, allow_policy)
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

    let signature = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_eip712_mail_action(1),
        ))
        .await
        .expect("allow policy should sign");

    assert!(!signature.bytes.is_empty());
    assert!(
        daemon
            .manual_approval_requests
            .read()
            .expect("manual approvals")
            .is_empty()
    );
    assert!(
        daemon
            .spend_log
            .read()
            .expect("spend log")
            .is_empty()
    );
}

#[tokio::test]
async fn eip712_deny_policy_rejects_signing() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    let deny_policy = SpendingPolicy::new_eip712_signing(
        1,
        vault_domain::ApprovalType::Deny,
        EntityScope::All,
    )
    .expect("policy");
    let deny_policy_id = deny_policy.id;
    daemon
        .add_policy(&session, deny_policy)
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
        .sign_for_agent(sign_request(
            &agent_credentials,
            sample_eip712_mail_action(1),
        ))
        .await
        .expect_err("deny policy should reject");

    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::Eip712SigningDenied { policy_id })
            if policy_id == deny_policy_id
    ));
}

#[tokio::test]
async fn completed_manual_approval_spend_counts_toward_later_weekly_limits() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
        lease,
    };

    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_manual_approval(
                0,
                20,
                1_000_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("manual approval policy"),
        )
        .await
        .expect("add manual policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::WeeklyMaxSpending,
                100,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("weekly spend policy"),
        )
        .await
        .expect("add weekly policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let token: EvmAddress = "0x1000000000000000000000000000000000000000"
        .parse()
        .expect("token");
    let recipient: EvmAddress = "0x2000000000000000000000000000000000000000"
        .parse()
        .expect("recipient");

    for amount in [10_u128, 5, 5] {
        daemon
            .sign_for_agent(sign_request(
                &agent_credentials,
                AgentAction::Transfer {
                    chain_id: 1,
                    token: token.clone(),
                    to: recipient.clone(),
                    amount_wei: amount,
                },
            ))
            .await
            .expect("auto-approved spend should sign");
    }

    for amount in [30_u128, 40] {
        let request = sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: token.clone(),
                to: recipient.clone(),
                amount_wei: amount,
            },
        );
        let approval_request_id = match daemon.sign_for_agent(request.clone()).await {
            Err(DaemonError::ManualApprovalRequired {
                approval_request_id,
                ..
            }) => approval_request_id,
            other => panic!("expected manual approval request, got {other:?}"),
        };

        daemon
            .decide_manual_approval_request(
                &session,
                approval_request_id,
                ManualApprovalDecision::Approve,
                None,
            )
            .await
            .expect("approve request");

        daemon
            .sign_for_agent(request)
            .await
            .expect("approved request should sign");
    }

    {
        let mut spend_log = daemon.spend_log.write().expect("log write");
        for event in spend_log.iter_mut() {
            event.at -= time::Duration::days(2);
        }
    }

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token,
                to: recipient,
                amount_wei: 15,
            },
        ))
        .await
        .expect_err("later auto-approved spend should be denied after manual usage reaches the weekly limit");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::WindowLimitExceeded {
            used_amount_wei: 90,
            requested_amount_wei: 15,
            max_amount_wei: 100,
            ..
        })
    ));
}
