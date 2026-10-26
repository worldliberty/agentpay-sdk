#[tokio::test]
async fn broadcast_unknown_selector_is_rejected_even_when_policies_allow_it() {
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
                to: "0x1000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 1,
                data_hex: "0xdeadbeef".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: false,
            },
        },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    // Unknown selectors are denied by default: permissive spend policies cannot authorize
    // calldata the policy engine is unable to interpret.
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("unrecognized calldata must be rejected");
    match err {
        DaemonError::InvalidAction(message) => {
            assert!(
                message.contains("unrecognized transaction calldata"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn eip1559_broadcast_signature_artifacts_are_consistent() {
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

    let tx = BroadcastTx {
        chain_id: 1,
        nonce: 7,
        to: "0x1000000000000000000000000000000000000000"
            .parse()
            .expect("to"),
        value_wei: 123,
        data_hex: "0x".to_string(),
        gas_limit: 21_000,
        max_fee_per_gas_wei: 1_000_000_000,
        max_priority_fee_per_gas_wei: 100_000_000,
        tx_type: 0x02,
        delegation_enabled: false,
    };
    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx { tx: tx.clone() },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, tx.chain_id, tx.nonce).await;

    let signature = daemon.sign_for_agent(request).await.expect("must sign");
    let r_hex = signature.r_hex.expect("eip1559 r must be present");
    let s_hex = signature.s_hex.expect("eip1559 s must be present");
    let v = signature.v.expect("eip1559 v must be present");
    let raw_tx_hex = signature
        .raw_tx_hex
        .expect("eip1559 raw tx bytes must be present");
    let tx_hash_hex = signature
        .tx_hash_hex
        .expect("eip1559 tx hash must be present");
    assert!(v <= 1, "typed tx y-parity must be 0 or 1");

    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let compact = parsed_der.to_bytes();
    assert_eq!(r_hex, format!("0x{}", hex::encode(&compact[..32])));
    assert_eq!(s_hex, format!("0x{}", hex::encode(&compact[32..])));

    let raw_tx = hex::decode(
        raw_tx_hex
            .strip_prefix("0x")
            .expect("raw tx must be 0x-prefixed"),
    )
    .expect("raw tx hex");
    assert_eq!(raw_tx.first().copied(), Some(0x02));
    assert_eq!(
        tx_hash_hex,
        format!("0x{}", hex::encode(keccak256(&raw_tx).0))
    );

    let signing_message = tx.eip1559_signing_message().expect("signing message");
    let digest = keccak256(&signing_message).0;
    let recovery_id = RecoveryId::from_byte(v as u8).expect("valid recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
}

#[tokio::test]
async fn non_eip1559_broadcast_is_rejected_for_signing() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

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
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x04,
                delegation_enabled: false,
            },
        },
    );
    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("non-eip1559 broadcast tx must be rejected");
    assert!(matches!(
        err,
        DaemonError::Signer(vault_signer::SignerError::Unsupported(message))
            if message.contains("unsupported for signing")
    ));
}

#[tokio::test]
async fn broadcast_signer_failure_preserves_request_id_and_nonce_reservation() {
    let daemon = InMemoryDaemon::new(
        "vault-password",
        FlakySignerBackend::fail_first_digest(SignerError::Internal(
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

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4100000000000000000000000000000000000000"
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
        .sign_for_agent(request.clone())
        .await
        .expect_err("first broadcast signing attempt should fail");
    assert!(matches!(
        err,
        DaemonError::Signer(SignerError::Internal(message))
            if message == "simulated signer timeout"
    ));

    let signature = daemon
        .sign_for_agent(request.clone())
        .await
        .expect("same request id and reservation should remain retryable after signer failure");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");

    let replay = daemon
        .sign_for_agent(request)
        .await
        .expect("successful broadcast retries should remain idempotent");
    assert_eq!(replay, signature);
}

#[tokio::test]
async fn non_eip1559_broadcast_rejection_preserves_nonce_reservation() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let rejected = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x04,
                delegation_enabled: false,
            },
        },
    );
    let err = daemon
        .sign_for_agent(rejected)
        .await
        .expect_err("non-eip1559 broadcast tx must be rejected");
    assert!(matches!(
        err,
        DaemonError::Signer(vault_signer::SignerError::Unsupported(message))
            if message.contains("unsupported for signing")
    ));

    let recovered = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x4000000000000000000000000000000000000000"
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
    let signature = daemon
        .sign_for_agent(recovered)
        .await
        .expect("reserved nonce should remain usable after signing rejection");
    assert!(!signature.bytes.is_empty(), "signature should be non-empty");
}

#[tokio::test]
async fn signer_backend_failure_preserves_broadcast_nonce_reservation() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let detached_backend_key_id = Uuid::new_v4();
    let mut detached_backend_key = key.clone();
    detached_backend_key.id = detached_backend_key_id;
    daemon
        .vault_keys
        .write()
        .expect("vault keys")
        .insert(detached_backend_key_id, detached_backend_key);
    daemon
        .agent_keys
        .write()
        .expect("agent keys")
        .entry(agent_credentials.agent_key.id)
        .and_modify(|agent_key| agent_key.vault_key_id = detached_backend_key_id);

    reserve_nonce_for_agent(&daemon, &agent_credentials, 1, 0).await;

    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x4100000000000000000000000000000000000000"
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
        .expect_err("backend signing failure must reject the request");
    assert!(matches!(
        err,
        DaemonError::Signer(vault_signer::SignerError::UnknownKey(id))
            if id == detached_backend_key_id
    ));

    let reservations = daemon
        .nonce_reservations
        .read()
        .expect("nonce reservations");
    let reservation = reservations
        .values()
        .next()
        .expect("nonce reservation must be preserved after signer failure");
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservation.agent_key_id, agent_credentials.agent_key.id);
    assert_eq!(reservation.vault_key_id, detached_backend_key_id);
    assert_eq!(reservation.chain_id, 1);
    assert_eq!(reservation.nonce, 0);
}

#[tokio::test]
async fn broadcast_with_delegation_is_rejected_even_for_eip7702() {
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

    let request = sign_request(
        &agent_credentials,
        AgentAction::BroadcastTx {
            tx: BroadcastTx {
                chain_id: 1,
                nonce: 0,
                to: "0x2000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 21_000,
                max_fee_per_gas_wei: 1_000_000_000,
                max_priority_fee_per_gas_wei: 1_000_000_000,
                tx_type: 0x02,
                delegation_enabled: true,
            },
        },
    );
    let err = daemon
        .sign_for_agent(request)
        .await
        .expect_err("must reject delegation even for eip-7702");
    assert!(matches!(err, DaemonError::InvalidAction(_)));
}

#[tokio::test]
async fn per_chain_gas_policy_rejects_over_limit_broadcast() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 500_000_000_000_000))
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
                to: "0x3000000000000000000000000000000000000000"
                    .parse()
                    .expect("to"),
                value_wei: 0,
                data_hex: "0x".to_string(),
                gas_limit: 1_000_000,
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
        .expect_err("gas policy must reject oversized tx");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::GasLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn broadcast_fee_and_calldata_policies_are_enforced() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::PerTxMaxFeePerGas,
                1_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add max-fee policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                2,
                PolicyType::PerTxMaxPriorityFeePerGas,
                500_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add priority-fee policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new_calldata_limit(
                3,
                3,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add calldata policy");

    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent_credentials = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let fee_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x3000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 2_000_000_000,
                    max_priority_fee_per_gas_wei: 100_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("max fee per gas must reject request");
    assert!(matches!(
        fee_err,
        DaemonError::Policy(PolicyError::MaxFeePerGasLimitExceeded { .. })
    ));

    let priority_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x3000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    data_hex: "0x".to_string(),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 600_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("max priority fee per gas must reject request");
    assert!(matches!(
        priority_err,
        DaemonError::Policy(PolicyError::PriorityFeePerGasLimitExceeded { .. })
    ));

    let calldata_err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            AgentAction::BroadcastTx {
                tx: BroadcastTx {
                    chain_id: 1,
                    nonce: 0,
                    to: "0x3000000000000000000000000000000000000000"
                        .parse()
                        .expect("to"),
                    value_wei: 0,
                    // Recognized ERC-20 transfer(address,uint256) calldata: 68 bytes > 3-byte limit.
                    data_hex: format!(
                        "0xa9059cbb{:0>64}{:064x}",
                        "2000000000000000000000000000000000000000", 1u8
                    ),
                    gas_limit: 21_000,
                    max_fee_per_gas_wei: 1_000_000_000,
                    max_priority_fee_per_gas_wei: 100_000_000,
                    tx_type: 0x02,
                    delegation_enabled: false,
                },
            },
        ))
        .await
        .expect_err("calldata bytes limit must reject request");
    assert!(matches!(
        calldata_err,
        DaemonError::Policy(PolicyError::CalldataBytesLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn daily_tx_count_policy_is_enforced() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add per-tx spend policy");
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
            .expect("policy"),
        )
        .await
        .expect("add tx count policy");

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
        .expect("first tx should pass");

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
        .expect_err("daily tx count must reject second tx");
    assert!(matches!(
        err,
        DaemonError::Policy(PolicyError::TxCountLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn fee_policy_allows_non_broadcast_actions_without_tx_metadata() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::PerTxMaxFeePerGas,
                1_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
        .await
        .expect("add fee policy");

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
        .expect("non-broadcast action should skip fee metadata policy");
}

#[tokio::test]
async fn gas_policy_allows_non_broadcast_actions_without_tx_metadata() {
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
        .add_policy(&session, policy_all_per_tx(1_000_000_000_000_000_000))
        .await
        .expect("add spend policy");
    daemon
        .add_policy(
            &session,
            SpendingPolicy::new(
                1,
                PolicyType::PerChainMaxGasSpend,
                1_000_000_000_000_000,
                EntityScope::All,
                EntityScope::All,
                EntityScope::All,
            )
            .expect("policy"),
        )
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

    daemon
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
        .expect("non-broadcast action should skip gas metadata policy");
}

#[tokio::test]
async fn permit2_signature_artifacts_are_recoverable() {
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
    let expiration = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(2)).unix_timestamp(),
    )
    .expect("future unix timestamp");
    let sig_deadline = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration,
            nonce: 1,
            sig_deadline,
        },
    };

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("must sign permit2");
    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let digest = action
        .signing_hash()
        .expect("typed hash")
        .expect("typed action");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
    assert!(signature.raw_tx_hex.is_none());
    assert!(signature.tx_hash_hex.is_none());
    assert!(signature.r_hex.is_some());
    assert!(signature.s_hex.is_some());
}

#[tokio::test]
async fn expired_permit2_signature_deadline_is_rejected() {
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
    let expiration = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::hours(2)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration,
            nonce: 1,
            sig_deadline: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired permit2 deadline must be rejected");
    assert!(matches!(err, DaemonError::InvalidAction(_)));
}

#[tokio::test]
async fn expired_permit2_expiration_is_rejected() {
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

    let action = AgentAction::Permit2Permit {
        permit: vault_domain::Permit2Permit {
            chain_id: 1,
            permit2_contract: "0x000000000022d473030f116ddee9f6b43ac78ba3"
                .parse()
                .expect("permit2"),
            token: "0x1000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            spender: "0x2000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            amount_wei: 42,
            expiration: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            nonce: 1,
            sig_deadline: u64::try_from(
                (time::OffsetDateTime::now_utc() + time::Duration::hours(1)).unix_timestamp(),
            )
            .expect("future unix timestamp"),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired permit2 expiration must be rejected");
    assert!(matches!(err, DaemonError::InvalidAction(_)));
}

#[tokio::test]
async fn eip3009_signature_artifacts_are_recoverable() {
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
    let valid_after = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(5)).unix_timestamp(),
    )
    .expect("future unix timestamp");
    let valid_before = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(10)).unix_timestamp(),
    )
    .expect("future unix timestamp");

    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: vault_domain::Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 77,
            valid_after,
            valid_before,
            nonce_hex: format!("0x{}", hex::encode([0x11u8; 32])),
        },
    };

    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("must sign eip3009");
    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let digest = action
        .signing_hash()
        .expect("typed hash")
        .expect("typed action");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
    assert!(signature.raw_tx_hex.is_none());
    assert!(signature.tx_hash_hex.is_none());
    assert!(signature.r_hex.is_some());
    assert!(signature.s_hex.is_some());
}

#[tokio::test]
async fn expired_eip3009_valid_before_is_rejected() {
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

    let action = AgentAction::Eip3009TransferWithAuthorization {
        authorization: vault_domain::Eip3009Transfer {
            chain_id: 1,
            token: "0x3000000000000000000000000000000000000000"
                .parse()
                .expect("token"),
            token_name: "USD Coin".to_string(),
            token_version: Some("2".to_string()),
            from: "0x4000000000000000000000000000000000000000"
                .parse()
                .expect("from"),
            to: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("to"),
            amount_wei: 77,
            valid_after: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::minutes(2)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            valid_before: u64::try_from(
                (time::OffsetDateTime::now_utc() - time::Duration::seconds(1)).unix_timestamp(),
            )
            .expect("past unix timestamp"),
            nonce_hex: format!("0x{}", hex::encode([0x11u8; 32])),
        },
    };

    let err = daemon
        .sign_for_agent(sign_request(&agent_credentials, action))
        .await
        .expect_err("expired eip3009 authorization must be rejected");
    assert!(matches!(err, DaemonError::InvalidAction(_)));
}

use super::{TempoChannelRecord, MAX_TRACKED_TEMPO_CHANNELS};

fn tempo_open_for_payer(
    payer: &str,
    salt: u8,
    deposit_wei: u128,
) -> vault_domain::TempoSessionOpenTransaction {
    vault_domain::TempoSessionOpenTransaction {
        chain_id: vault_domain::TEMPO_MAINNET_CHAIN_ID,
        escrow_contract: vault_domain::TEMPO_MAINNET_ESCROW_CONTRACT
            .parse()
            .expect("escrow"),
        token: "0x20c0000000000000000000000000000000000001"
            .parse()
            .expect("token"),
        recipient: "0x7777777777777777777777777777777777777777"
            .parse()
            .expect("recipient"),
        payer: payer.parse().expect("payer"),
        authorized_signer: payer.parse().expect("signer"),
        salt_hex: format!("0x{}", hex::encode([salt; 32])),
        deposit_wei,
        tx: vault_domain::TempoTxParams {
            nonce: 0,
            nonce_key: None,
            gas_limit: 400_000,
            max_fee_per_gas_wei: 20_000_000_000,
            max_priority_fee_per_gas_wei: 1,
            valid_before: None,
            valid_after: None,
            fee_token: None,
            fee_payer: false,
        },
    }
}

fn tempo_channel_id_hex(open: &vault_domain::TempoSessionOpenTransaction) -> String {
    format!("0x{}", hex::encode(open.channel_id().expect("channel id")))
}

fn tempo_voucher_for_open(
    open: &vault_domain::TempoSessionOpenTransaction,
    cumulative_amount_wei: u128,
) -> AgentAction {
    AgentAction::TempoSessionVoucher {
        authorization: vault_domain::TempoSessionVoucher {
            chain_id: open.chain_id,
            escrow_contract: open.escrow_contract.clone(),
            token: open.token.clone(),
            recipient: open.recipient.clone(),
            payer: open.payer.clone(),
            authorized_signer: open.authorized_signer.clone(),
            salt_hex: open.salt_hex.clone(),
            channel_id_hex: tempo_channel_id_hex(open),
            cumulative_amount_wei,
        },
    }
}

fn tempo_top_up_for_open(
    open: &vault_domain::TempoSessionOpenTransaction,
    additional_deposit_wei: u128,
) -> AgentAction {
    AgentAction::TempoSessionTopUpTransaction {
        authorization: vault_domain::TempoSessionTopUpTransaction {
            chain_id: open.chain_id,
            escrow_contract: open.escrow_contract.clone(),
            token: open.token.clone(),
            recipient: open.recipient.clone(),
            payer: open.payer.clone(),
            authorized_signer: open.authorized_signer.clone(),
            salt_hex: open.salt_hex.clone(),
            channel_id_hex: tempo_channel_id_hex(open),
            additional_deposit_wei,
            tx: open.tx.clone(),
        },
    }
}

fn tempo_open_action(open: &vault_domain::TempoSessionOpenTransaction) -> AgentAction {
    AgentAction::TempoSessionOpenTransaction {
        authorization: open.clone(),
    }
}

/// Daemon with one wallet and two agent keys sharing it.
async fn tempo_daemon_with_two_agents() -> (
    InMemoryDaemon<SoftwareSignerBackend>,
    AdminSession,
    VaultKey,
    AgentCredentials,
    AgentCredentials,
    String,
) {
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
        .add_policy(&session, policy_all_per_tx(1_000_000))
        .await
        .expect("add policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let first = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("first agent");
    let second = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("second agent");
    let wallet = ethereum_address_from_public_key_hex(&key.public_key_hex).expect("address");
    (daemon, session, key, first, second, wallet)
}

fn assert_invalid_action_contains(err: DaemonError, needle: &str) {
    match err {
        DaemonError::InvalidAction(message) => assert!(
            message.contains(needle),
            "expected `{needle}` in `{message}`"
        ),
        other => panic!("expected InvalidAction containing `{needle}`, got {other:?}"),
    }
}

#[tokio::test]
async fn tempo_session_actions_require_payer_to_be_the_wallet() {
    let (daemon, _session, key, agent_credentials, _second, wallet) =
        tempo_daemon_with_two_agents().await;

    let foreign = tempo_open_for_payer("0x4000000000000000000000000000000000000000", 0x5a, 1_000);
    let err = daemon
        .sign_for_agent(sign_request(
            &agent_credentials,
            tempo_voucher_for_open(&foreign, 400),
        ))
        .await
        .expect_err("foreign payer must be rejected");
    assert_invalid_action_contains(err, "payer must be the signing wallet");

    let open = tempo_open_for_payer(&wallet, 0x5a, 1_000);
    daemon
        .sign_for_agent(sign_request(&agent_credentials, tempo_open_action(&open)))
        .await
        .expect("open through the daemon");

    let action = tempo_voucher_for_open(&open, 400);
    let signature = daemon
        .sign_for_agent(sign_request(&agent_credentials, action.clone()))
        .await
        .expect("wallet payer voucher must sign");
    let parsed_der = K256Signature::from_der(&signature.bytes).expect("DER signature");
    let digest = action
        .signing_hash()
        .expect("voucher hash")
        .expect("typed action");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered = VerifyingKey::recover_from_prehash(&digest, &parsed_der, recovery_id)
        .expect("recover verifying key");
    let expected_verifying_key =
        VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("public key hex"))
            .expect("public key bytes");
    assert_eq!(recovered, expected_verifying_key);
}

#[tokio::test]
async fn tempo_voucher_and_top_up_for_unknown_channel_are_rejected() {
    let (daemon, _session, _key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_open_for_payer(&wallet, 0x11, 1_000);

    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_voucher_for_open(&open, 1)))
        .await
        .expect_err("voucher for a channel this daemon never opened must fail");
    assert_invalid_action_contains(err, "unknown to this daemon");

    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_top_up_for_open(&open, 1)))
        .await
        .expect_err("top-up for a channel this daemon never opened must fail");
    assert_invalid_action_contains(err, "unknown to this daemon");

    // Policy previews reject the same way, so explain/evaluate cannot be used
    // to probe a voucher that signing would refuse.
    let err = daemon
        .evaluate_for_agent(sign_request(&agent, tempo_voucher_for_open(&open, 1)))
        .await
        .expect_err("evaluate must reject unknown channel");
    assert_invalid_action_contains(err, "unknown to this daemon");
    assert!(daemon.tempo_channels.read().expect("channels").is_empty());
}

#[tokio::test]
async fn tempo_channel_is_bound_to_the_opening_agent_key() {
    let (daemon, _session, _key, first, second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_open_for_payer(&wallet, 0x22, 1_000);
    daemon
        .sign_for_agent(sign_request(&first, tempo_open_action(&open)))
        .await
        .expect("first agent opens the channel");

    let err = daemon
        .sign_for_agent(sign_request(&second, tempo_voucher_for_open(&open, 10)))
        .await
        .expect_err("another agent key must not vouch for the channel");
    assert_invalid_action_contains(err, "opened by a different agent key");

    let err = daemon
        .sign_for_agent(sign_request(&second, tempo_top_up_for_open(&open, 10)))
        .await
        .expect_err("another agent key must not top up the channel");
    assert_invalid_action_contains(err, "opened by a different agent key");

    let err = daemon
        .sign_for_agent(sign_request(&second, tempo_open_action(&open)))
        .await
        .expect_err("another agent key must not take over the channel");
    assert_invalid_action_contains(err, "registered to a different agent key");

    let record = daemon
        .tempo_channels
        .read()
        .expect("channels")
        .get(&tempo_channel_id_hex(&open))
        .cloned()
        .expect("channel registered");
    assert_eq!(record.agent_key_id, first.agent_key.id);
    assert_eq!(record.deposited_total_wei, 1_000);

    daemon
        .sign_for_agent(sign_request(&first, tempo_voucher_for_open(&open, 10)))
        .await
        .expect("opening agent can vouch");
}

#[tokio::test]
async fn tempo_voucher_is_capped_at_deposited_total_including_top_ups() {
    let (daemon, _session, _key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;
    let open = tempo_open_for_payer(&wallet, 0x33, 1_000);
    daemon
        .sign_for_agent(sign_request(&agent, tempo_open_action(&open)))
        .await
        .expect("open");

    daemon
        .sign_for_agent(sign_request(&agent, tempo_voucher_for_open(&open, 1_000)))
        .await
        .expect("voucher at the deposit is allowed");
    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_voucher_for_open(&open, 1_001)))
        .await
        .expect_err("voucher above the deposit must fail");
    assert_invalid_action_contains(err, "exceeds the 1000 deposited");

    daemon
        .sign_for_agent(sign_request(&agent, tempo_top_up_for_open(&open, 500)))
        .await
        .expect("top-up by the opening agent");
    assert_eq!(
        daemon
            .tempo_channels
            .read()
            .expect("channels")
            .get(&tempo_channel_id_hex(&open))
            .map(|record| record.deposited_total_wei),
        Some(1_500)
    );
    daemon
        .sign_for_agent(sign_request(&agent, tempo_voucher_for_open(&open, 1_500)))
        .await
        .expect("voucher up to the topped-up total is allowed");
    let err = daemon
        .sign_for_agent(sign_request(&agent, tempo_voucher_for_open(&open, 1_501)))
        .await
        .expect_err("voucher above the topped-up total must fail");
    assert_invalid_action_contains(err, "exceeds the 1500 deposited");

    // Re-signing the open (e.g. a retried broadcast) must not inflate the total.
    daemon
        .sign_for_agent(sign_request(&agent, tempo_open_action(&open)))
        .await
        .expect("re-signing the open");
    assert_eq!(
        daemon
            .tempo_channels
            .read()
            .expect("channels")
            .get(&tempo_channel_id_hex(&open))
            .map(|record| record.deposited_total_wei),
        Some(1_500)
    );
}

#[tokio::test]
async fn tempo_channel_registry_is_bounded_and_evicts_oldest() {
    let (daemon, _session, _key, agent, _second, wallet) = tempo_daemon_with_two_agents().await;
    let base = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    {
        let mut channels = daemon.tempo_channels.write().expect("channels");
        for index in 0..MAX_TRACKED_TEMPO_CHANNELS {
            channels.insert(
                format!("0x{index:064x}"),
                TempoChannelRecord {
                    agent_key_id: agent.agent_key.id,
                    deposited_total_wei: 1,
                    opened_at: base + time::Duration::seconds(index as i64),
                },
            );
        }
    }

    let open = tempo_open_for_payer(&wallet, 0x44, 1_000);
    daemon
        .sign_for_agent(sign_request(&agent, tempo_open_action(&open)))
        .await
        .expect("open");

    let channels = daemon.tempo_channels.read().expect("channels");
    assert_eq!(channels.len(), MAX_TRACKED_TEMPO_CHANNELS);
    assert!(channels.contains_key(&tempo_channel_id_hex(&open)));
    assert!(
        !channels.contains_key(&format!("0x{:064x}", 0)),
        "the oldest channel must be evicted"
    );
    assert!(channels.contains_key(&format!("0x{:064x}", 1)));
}

#[tokio::test]
async fn revoking_agent_key_drops_its_tempo_channels() {
    let (daemon, session, _key, first, second, wallet) = tempo_daemon_with_two_agents().await;
    let first_open = tempo_open_for_payer(&wallet, 0x55, 1_000);
    let second_open = tempo_open_for_payer(&wallet, 0x66, 1_000);
    daemon
        .sign_for_agent(sign_request(&first, tempo_open_action(&first_open)))
        .await
        .expect("first open");
    daemon
        .sign_for_agent(sign_request(&second, tempo_open_action(&second_open)))
        .await
        .expect("second open");

    daemon
        .revoke_agent_key(&session, first.agent_key.id)
        .await
        .expect("revoke");

    let channels = daemon.tempo_channels.read().expect("channels");
    assert!(!channels.contains_key(&tempo_channel_id_hex(&first_open)));
    assert!(channels.contains_key(&tempo_channel_id_hex(&second_open)));
}

#[test]
fn persisted_state_without_tempo_channels_loads_and_registry_round_trips() {
    let mut legacy = serde_json::to_value(PersistedDaemonState::default()).expect("serialize");
    legacy
        .as_object_mut()
        .expect("state object")
        .remove("tempo_channels")
        .expect("field present in current schema");
    let loaded: PersistedDaemonState = serde_json::from_value(legacy).expect("legacy state loads");
    assert!(loaded.tempo_channels.is_empty());

    let mut state = PersistedDaemonState::default();
    state.tempo_channels.insert(
        format!("0x{}", "ab".repeat(32)),
        TempoChannelRecord {
            agent_key_id: Uuid::new_v4(),
            deposited_total_wei: u128::MAX,
            opened_at: time::OffsetDateTime::UNIX_EPOCH,
        },
    );
    let round_tripped: PersistedDaemonState =
        serde_json::from_slice(&serde_json::to_vec(&state).expect("serialize")).expect("load");
    assert_eq!(round_tripped.tempo_channels, state.tempo_channels);
}
