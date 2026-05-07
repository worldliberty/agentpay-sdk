#[tokio::test]
async fn broadcast_without_nonce_reservation_is_rejected() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

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
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x9300000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("broadcast signing requires nonce reservation");
    assert!(matches!(
        err,
        DaemonError::MissingNonceReservation {
            chain_id: 1,
            nonce: 0
        }
    ));
}

#[tokio::test]
async fn reserve_nonce_is_monotonic_for_same_agent_and_chain() {
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
            chain_id: 1,
            min_nonce: 7,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reservation");
    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 7,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("second reservation");
    assert_eq!(first.nonce, 7);
    assert_eq!(second.nonce, 8);
}

#[tokio::test]
async fn reserve_nonce_replay_recovers_original_reservation() {
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
    let request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        chain_id: 1,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    let first = daemon
        .reserve_nonce(request.clone())
        .await
        .expect("first reserve");

    let second = daemon
        .reserve_nonce(request)
        .await
        .expect("identical reserve replay should recover the original reservation");
    assert_eq!(second, first);
}

#[tokio::test]
async fn reserve_nonce_replay_is_rejected_after_release() {
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

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release");

    let err = daemon
        .reserve_nonce(reserve_request)
        .await
        .expect_err("released reservation must not be replay-recovered");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn reserve_nonce_replay_is_rejected_after_signed_request_consumes_reservation() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

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
    daemon
        .reserve_nonce(reserve_request.clone())
        .await
        .expect("reserve");

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x9300000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 1_000_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect("consume reservation by signing");

    let err = daemon
        .reserve_nonce(reserve_request)
        .await
        .expect_err("consumed reservation must not be replay-recovered");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn reserve_nonce_replay_is_rejected_after_reservation_expiry() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            nonce_reservation_ttl: time::Duration::milliseconds(5),
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
    let request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        chain_id: 56,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };
    daemon
        .reserve_nonce(request.clone())
        .await
        .expect("reserve");

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let err = daemon
        .reserve_nonce(request)
        .await
        .expect_err("expired reservation must not be replay-recovered");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn reserve_nonce_reuse_with_different_scope_is_rejected() {
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
    let request = NonceReservationRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        chain_id: 1,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .reserve_nonce(request.clone())
        .await
        .expect("first reserve");

    let replay = NonceReservationRequest {
        request_id: request.request_id,
        agent_key_id: request.agent_key_id,
        agent_auth_token: agent_credentials.auth_token,
        chain_id: 10,
        min_nonce: 0,
        exact_nonce: false,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    let err = daemon
        .reserve_nonce(replay)
        .await
        .expect_err("mismatched reserve replay must fail");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn release_nonce_reclaims_latest_unused_nonce() {
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
    let reservation = daemon
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
        .expect("reserve");
    assert_eq!(reservation.nonce, 0);

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release");

    let next = daemon
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
        .expect("reserve after release");
    assert_eq!(next.nonce, 0);
}

#[tokio::test]
async fn reserve_nonce_with_higher_min_preserves_lower_reclaimed_and_skipped_nonces() {
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
    let _second = daemon
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
    assert_eq!((first.nonce, third.nonce), (0, 2));

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

    let raised_min = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 5,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve with raised minimum");
    assert_eq!(raised_min.nonce, 5);

    let reclaimed_lower = daemon
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
        .expect("reserve reclaimed lower nonce");
    assert_eq!(reclaimed_lower.nonce, 0);

    let skipped_lower = daemon
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
        .expect("reserve skipped lower nonce");
    assert_eq!(skipped_lower.nonce, 2);
}

#[tokio::test]
async fn release_nonce_reclaims_out_of_order_gaps_before_head() {
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

    let recycled_gap = daemon
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
        .expect("reserve reclaimed gap");
    assert_eq!(recycled_gap.nonce, 0);

    let next_from_head = daemon
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
        .expect("reserve head after reclaimed gap");
    assert_eq!(next_from_head.nonce, 2);
}

#[tokio::test]
async fn exact_nonce_reserve_consumes_reclaimed_gap() {
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
    let _second = daemon
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

    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve exact reclaimed gap");
    assert_eq!(exact.nonce, 0);

    let next = daemon
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
        .expect("reserve after exact reclaimed gap");
    assert_eq!(next.nonce, 2);
}

#[tokio::test]
async fn exact_nonce_above_head_preserves_skipped_lower_nonces() {
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
    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 5,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve exact above head");
    assert_eq!(exact.nonce, 5);

    let first_lower = daemon
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
        .expect("reserve first skipped lower nonce");
    assert_eq!(first_lower.nonce, 0);

    let second_lower = daemon
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
        .expect("reserve second skipped lower nonce");
    assert_eq!(second_lower.nonce, 1);
}

#[tokio::test]
async fn exact_nonce_can_reuse_chain_nonce_after_signed_request_advances_head() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("add gas policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;
    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x9300000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 1_000_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect("consume first reservation");

    let now = time::OffsetDateTime::now_utc();
    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("exact reserve");
    assert_eq!(exact.nonce, 0);

    let next = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("next reserve");
    assert_eq!(next.nonce, 1);
}

#[tokio::test]
async fn future_issued_nonce_reservation_is_reclaimed_before_exact_reserve() {
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
    let future_reservation = NonceReservation {
        reservation_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        vault_key_id: key.id,
        chain_id: 1,
        nonce: 0,
        issued_at: now + time::Duration::hours(1),
        expires_at: now + time::Duration::hours(2),
    };
    daemon
        .nonce_reservations
        .write()
        .expect("reservations write")
        .insert(
            future_reservation.reservation_id,
            future_reservation.clone(),
        );

    let exact = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: true,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("exact reserve must ignore future reservation");

    assert_eq!(exact.nonce, 0);
    let reservations = daemon.nonce_reservations.read().expect("reservations read");
    assert!(!reservations.contains_key(&future_reservation.reservation_id));
    assert!(reservations.contains_key(&exact.reservation_id));
}

#[tokio::test]
async fn expired_nonce_reservation_is_reclaimed_before_next_reserve() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            nonce_reservation_ttl: time::Duration::milliseconds(5),
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
        .expect("first reserve");
    assert_eq!(first.nonce, 0);

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: time::OffsetDateTime::now_utc(),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
        })
        .await
        .expect("second reserve");
    assert_eq!(second.nonce, 0);
}

#[tokio::test]
async fn expired_nonce_reservations_reclaim_out_of_order_gaps_before_head() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            nonce_reservation_ttl: time::Duration::seconds(1),
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
    let soon = now + time::Duration::milliseconds(5);
    let later = now + time::Duration::seconds(1);
    let first = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: soon,
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
            expires_at: later,
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
            expires_at: soon,
        })
        .await
        .expect("reserve third");
    assert_eq!((first.nonce, second.nonce, third.nonce), (0, 1, 2));

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let refresh_now = time::OffsetDateTime::now_utc();
    let recycled_gap = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: refresh_now,
            expires_at: refresh_now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve reclaimed expired gap");
    assert_eq!(recycled_gap.nonce, 0);

    let next_from_head = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 56,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: refresh_now,
            expires_at: refresh_now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve head after reclaimed expired gap");
    assert_eq!(next_from_head.nonce, 2);
}

#[tokio::test]
async fn reserve_nonce_rejects_zero_chain_id() {
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
    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 0,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect_err("chain_id zero must fail");

    assert!(matches!(
        err,
        DaemonError::InvalidNonceReservation(message)
            if message.contains("chain_id must be greater than zero")
    ));
}

#[tokio::test]
async fn release_nonce_replay_returns_success() {
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
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .release_nonce(release_request.clone())
        .await
        .expect("first release");

    daemon
        .release_nonce(release_request)
        .await
        .expect("identical release replay should be idempotent");
}

#[tokio::test]
async fn release_nonce_reuse_with_different_reservation_is_rejected() {
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
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");
    let other_reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: reservation.nonce + 1,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve other");

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token.clone(),
        reservation_id: reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .release_nonce(release_request.clone())
        .await
        .expect("first release");

    let replay = NonceReleaseRequest {
        request_id: release_request.request_id,
        agent_key_id: release_request.agent_key_id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: other_reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    let err = daemon
        .release_nonce(replay)
        .await
        .expect_err("mismatched release replay must fail");
    assert!(matches!(err, DaemonError::RequestReplayDetected));
}

#[tokio::test]
async fn release_nonce_rejects_non_owner_agent() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");

    let owner_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("owner");
    let attacker_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("attacker");

    let now = time::OffsetDateTime::now_utc();
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: owner_credentials.agent_key.id,
            agent_auth_token: owner_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");

    let err = daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: attacker_credentials.agent_key.id,
            agent_auth_token: attacker_credentials.auth_token,
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect_err("non-owner should not release reservation");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: owner_credentials.agent_key.id,
            agent_auth_token: owner_credentials.auth_token,
            reservation_id: reservation.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("owner must still be able to release");
}

#[tokio::test]
async fn explain_for_agent_returns_denial_without_error() {
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
    let policy = policy_all_per_tx(10);
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

    let request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: "0x7700000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            to: "0x8700000000000000000000000000000000000000"
                .parse()
                .expect("recipient"),
            amount_wei: 11,
        },
    );
    let explanation = daemon
        .explain_for_agent(request)
        .await
        .expect("explain should return payload");
    assert_eq!(explanation.applicable_policy_ids, vec![policy.id]);
    assert_eq!(explanation.evaluated_policy_ids, vec![policy.id]);
    match explanation.decision {
        vault_policy::PolicyDecision::Deny(PolicyError::PerTxLimitExceeded { .. }) => {}
        other => panic!("unexpected explanation decision: {other:?}"),
    }
}

#[tokio::test]
async fn unknown_agent_key_is_not_disclosed_in_sign_api() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig::default(),
    )
    .expect("daemon");

    let token = "0x7100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x8100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let request = SignRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: Uuid::new_v4(),
        agent_auth_token: "random-token".to_string().into(),
        payload: to_vec(&AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 1,
        })
        .expect("payload"),
        action: AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 1,
        },
        requested_at: time::OffsetDateTime::now_utc(),
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(2),
    };

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("unknown key must not leak key existence");
    assert!(matches!(err, DaemonError::AgentAuthenticationFailed));
}

#[tokio::test]
async fn release_nonce_removes_reservation_from_snapshot() {
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
    let reservation = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reserve");

    let release_request = NonceReleaseRequest {
        request_id: Uuid::new_v4(),
        agent_key_id: agent_credentials.agent_key.id,
        agent_auth_token: agent_credentials.auth_token,
        reservation_id: reservation.reservation_id,
        requested_at: now,
        expires_at: now + time::Duration::minutes(2),
    };

    daemon
        .release_nonce(release_request)
        .await
        .expect("release");

    let snapshot = daemon.snapshot_state().expect("snapshot");
    assert!(
        !snapshot
            .nonce_reservations
            .contains_key(&reservation.reservation_id),
        "released reservation must be removed from persisted state snapshot"
    );
}

#[tokio::test]
async fn payload_action_mismatch_is_rejected() {
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

    let token = "0x9000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let declared_action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 10,
    };
    let mut request = sign_request(&agent_credentials, declared_action.clone());
    request.payload = to_vec(&AgentAction::Transfer {
        chain_id: 1,
        token,
        to: recipient,
        amount_wei: 99,
    })
    .expect("payload");
    request.action = declared_action;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("mismatched payload/action must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn malformed_payload_is_rejected() {
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

    let token = "0x9100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 1,
        },
    );
    request.payload = b"not-json".to_vec();

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("malformed payload must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn payload_with_extra_fields_is_rejected() {
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

    let token = "0x9100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let action = AgentAction::Transfer {
        chain_id: 1,
        token: token.clone(),
        to: recipient.clone(),
        amount_wei: 1,
    };
    let mut request = sign_request(&agent_credentials, action.clone());
    request.payload = format!(
        "{{\"kind\":\"Transfer\",\"token\":\"{}\",\"to\":\"{}\",\"amount_wei\":\"1\",\"unexpected\":\"x\"}}",
        token.as_str(),
        recipient.as_str()
    )
    .into_bytes();
    request.action = action;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("non-canonical payload must fail");
    assert!(matches!(err, DaemonError::PayloadActionMismatch));
}

#[tokio::test]
async fn oversized_payload_is_rejected() {
    let config = DaemonConfig {
        max_sign_payload_bytes: 64,
        ..DaemonConfig::default()
    };
    let daemon = InMemoryDaemon::new("vault-password", SoftwareSignerBackend::default(), config)
        .expect("daemon");

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
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

    let token = "0x9100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa100000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let mut request = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 1,
        },
    );
    request.payload = vec![b'a'; 65];

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("oversized payload must fail");
    assert!(matches!(
        err,
        DaemonError::PayloadTooLarge { max_bytes: 64 }
    ));
}

#[tokio::test]
async fn spend_log_retention_prunes_out_of_window_entries() {
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

    let old_token = "0x9200000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let old_recipient = "0xa200000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    let future_token = "0x9400000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let future_recipient = "0xa400000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    daemon
        .spend_log
        .write()
        .expect("log write")
        .extend([
            vault_domain::SpendEvent {
                agent_key_id: agent_credentials.agent_key.id,
                chain_id: 1,
                asset: AssetId::Erc20(old_token),
                recipient: old_recipient.into(),
                amount_wei: 1,
                at: time::OffsetDateTime::now_utc() - time::Duration::days(30),
            },
            vault_domain::SpendEvent {
                agent_key_id: agent_credentials.agent_key.id,
                chain_id: 1,
                asset: AssetId::Erc20(future_token),
                recipient: future_recipient.into(),
                amount_wei: 1,
                at: time::OffsetDateTime::now_utc() + time::Duration::days(30),
            },
        ]);

    let token = "0x9300000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0xa300000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");
    daemon
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
        .expect("sign must pass");

    let log = daemon.spend_log.read().expect("log read");
    let now = time::OffsetDateTime::now_utc();
    assert_eq!(log.len(), 1, "only the newly signed event should remain");
    assert!(log.iter().all(|event| {
        event.at >= now - time::Duration::days(8) && event.at <= now
    }));
}

#[tokio::test]
async fn manual_approval_retention_prunes_only_stale_terminal_entries() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            manual_approval_active_ttl: time::Duration::days(40),
            manual_approval_terminal_retention: time::Duration::days(1),
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
    let stale_completed_id = Uuid::new_v4();
    let stale_rejected_id = Uuid::new_v4();
    let recent_completed_id = Uuid::new_v4();
    let old_pending_id = Uuid::new_v4();
    let old_approved_id = Uuid::new_v4();
    let mut requests = daemon
        .manual_approval_requests
        .write()
        .expect("manual approval write");

    let mut stale_completed = sample_manual_approval_request();
    stale_completed.id = stale_completed_id;
    stale_completed.agent_key_id = agent_credentials.agent_key.id;
    stale_completed.vault_key_id = key.id;
    stale_completed.created_at = now - time::Duration::days(3);
    stale_completed.updated_at = now - time::Duration::days(2);
    stale_completed.status = ManualApprovalStatus::Completed;
    stale_completed.completed_at = Some(now - time::Duration::days(2));
    requests.insert(stale_completed.id, stale_completed);

    let mut stale_rejected = sample_manual_approval_request();
    stale_rejected.id = stale_rejected_id;
    stale_rejected.agent_key_id = agent_credentials.agent_key.id;
    stale_rejected.vault_key_id = key.id;
    stale_rejected.created_at = now - time::Duration::days(3);
    stale_rejected.updated_at = now - time::Duration::days(2);
    stale_rejected.status = ManualApprovalStatus::Rejected;
    stale_rejected.rejection_reason = Some("too risky".to_string());
    requests.insert(stale_rejected.id, stale_rejected);

    let mut recent_completed = sample_manual_approval_request();
    recent_completed.id = recent_completed_id;
    recent_completed.agent_key_id = agent_credentials.agent_key.id;
    recent_completed.vault_key_id = key.id;
    recent_completed.created_at = now - time::Duration::hours(23);
    recent_completed.updated_at = now - time::Duration::hours(12);
    recent_completed.status = ManualApprovalStatus::Completed;
    recent_completed.completed_at = Some(now - time::Duration::hours(12));
    requests.insert(recent_completed.id, recent_completed);

    let mut old_pending = sample_manual_approval_request();
    old_pending.id = old_pending_id;
    old_pending.agent_key_id = agent_credentials.agent_key.id;
    old_pending.vault_key_id = key.id;
    old_pending.created_at = now - time::Duration::days(30);
    old_pending.updated_at = now - time::Duration::days(30);
    old_pending.status = ManualApprovalStatus::Pending;
    requests.insert(old_pending.id, old_pending);

    let mut old_approved = sample_manual_approval_request();
    old_approved.id = old_approved_id;
    old_approved.agent_key_id = agent_credentials.agent_key.id;
    old_approved.vault_key_id = key.id;
    old_approved.created_at = now - time::Duration::days(30);
    old_approved.updated_at = now - time::Duration::days(30);
    old_approved.status = ManualApprovalStatus::Approved;
    requests.insert(old_approved.id, old_approved);
    drop(requests);

    daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::Transfer {
                chain_id: 1,
                token: "0x9400000000000000000000000000000000000000"
                    .parse()
                    .expect("token"),
                to: "0xa400000000000000000000000000000000000000"
                    .parse()
                    .expect("recipient"),
                amount_wei: 1,
            },
        ))
        .await
        .expect("sign must prune stale terminal approvals");

    let requests = daemon
        .manual_approval_requests
        .read()
        .expect("manual approval read");
    assert!(
        !requests.contains_key(&stale_completed_id),
        "stale completed requests must be pruned"
    );
    assert!(
        !requests.contains_key(&stale_rejected_id),
        "stale rejected requests must be pruned"
    );
    assert!(
        requests.contains_key(&recent_completed_id),
        "recent completed requests must remain within retention"
    );
    assert!(
        requests.contains_key(&old_pending_id),
        "pending requests must not be pruned by terminal retention"
    );
    assert!(
        requests.contains_key(&old_approved_id),
        "approved requests must not be pruned by terminal retention"
    );
}

#[tokio::test]
async fn nonce_head_tracking_limit_blocks_new_chains_until_old_heads_are_reclaimed() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_tracked_nonce_chains_per_vault: 1,
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
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reserve");

    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 2,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect_err("second chain should exceed tracking limit");
    assert!(matches!(
        err,
        DaemonError::InvalidNonceReservation(message)
            if message.contains("maximum 1 nonce head chains")
    ));

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: first.reservation_id,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("release first reservation");

    assert!(
        daemon
            .nonce_heads
            .read()
            .expect("nonce heads read")
            .get(&key.id)
            .is_none(),
        "releasing the only tracked head should reclaim the chain entry"
    );

    let second = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 2,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("reclaimed head capacity should allow a new chain");
    assert_eq!(second.nonce, 0);
}

#[tokio::test]
async fn replay_id_tracking_limit_blocks_new_requests_until_expired_entries_are_pruned() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_tracked_replay_ids: 1,
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

    let first_request_id = Uuid::new_v4();
    let now = time::OffsetDateTime::now_utc();
    daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: first_request_id,
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reserve");

    let next_now = time::OffsetDateTime::now_utc();
    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: next_now,
            expires_at: next_now + time::Duration::minutes(2),
        })
        .await
        .expect_err("second request should exceed replay tracking limit");
    assert!(matches!(
        err,
        DaemonError::TooManyTrackedReplayIds { max_tracked: 1 }
    ));

    daemon.replay_ids.write().expect("replay ids write").insert(
        first_request_id,
        time::OffsetDateTime::now_utc() - time::Duration::seconds(1),
    );

    let recovery_now = time::OffsetDateTime::now_utc();
    let recovered = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: recovery_now,
            expires_at: recovery_now + time::Duration::minutes(2),
        })
        .await
        .expect("expired replay entry should free capacity");
    assert_eq!(recovered.nonce, 1);
}

#[tokio::test]
async fn active_nonce_reservation_limit_blocks_new_reservations_until_slots_are_freed() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        SoftwareSignerBackend::default(),
        DaemonConfig {
            max_active_nonce_reservations: 1,
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
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: now,
            expires_at: now + time::Duration::minutes(2),
        })
        .await
        .expect("first reserve");

    let full_now = time::OffsetDateTime::now_utc();
    let err = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: full_now,
            expires_at: full_now + time::Duration::minutes(2),
        })
        .await
        .expect_err("second active reservation should exceed cap");
    assert!(matches!(
        err,
        DaemonError::TooManyActiveNonceReservations { max_active: 1 }
    ));

    daemon
        .release_nonce(NonceReleaseRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token.clone(),
            reservation_id: first.reservation_id,
            requested_at: full_now,
            expires_at: full_now + time::Duration::minutes(2),
        })
        .await
        .expect("release first reservation");

    let recovery_now = time::OffsetDateTime::now_utc();
    let recovered = daemon
        .reserve_nonce(NonceReservationRequest {
            request_id: Uuid::new_v4(),
            agent_key_id: agent_credentials.agent_key.id,
            agent_auth_token: agent_credentials.auth_token,
            chain_id: 1,
            min_nonce: 0,
            exact_nonce: false,
            requested_at: recovery_now,
            expires_at: recovery_now + time::Duration::minutes(2),
        })
        .await
        .expect("released reservation should free capacity");
    assert_eq!(recovered.nonce, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_sign_requests_do_not_race_policy_windows() {
    let daemon = Arc::new(
        InMemoryDaemon::new(
            "vault-password",
            SoftwareSignerBackend::default(),
            DaemonConfig::default(),
        )
        .expect("daemon"),
    );

    let lease = daemon.issue_lease("vault-password").await.expect("lease");
    let session = AdminSession {
        vault_password: "vault-password".to_string(),
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

    let token = "0x5000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("token");
    let recipient = "0x6000000000000000000000000000000000000000"
        .parse::<EvmAddress>()
        .expect("recipient");

    let req1 = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token: token.clone(),
            to: recipient.clone(),
            amount_wei: 60,
        },
    );
    let req2 = sign_request(
        &agent_credentials,
        AgentAction::Transfer {
            chain_id: 1,
            token,
            to: recipient,
            amount_wei: 60,
        },
    );

    let daemon_a = daemon.clone();
    let daemon_b = daemon.clone();
    let (res1, res2) = tokio::join!(daemon_a.sign_for_agent(req1), daemon_b.sign_for_agent(req2));

    let success_count = usize::from(res1.is_ok()) + usize::from(res2.is_ok());
    let failure_count = usize::from(res1.is_err()) + usize::from(res2.is_err());
    assert_eq!(success_count, 1, "exactly one request must pass");
    assert_eq!(failure_count, 1, "exactly one request must fail");
}
