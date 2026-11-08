//! Gas, fee, calldata, and transaction-count policies.

use agentpay_domain::{
    AdminAuth, AgentAction, BroadcastTx, EntityScope, PolicyAttachment, PolicyType, SpendingPolicy,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};

use super::support::{policy_all_per_tx, policy_per_chain_gas, sign_request};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

#[tokio::test]
async fn per_chain_gas_policy_rejects_over_limit_broadcast() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

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
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

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
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

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
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

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
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");

    let session = AdminAuth::PeerCredentials;

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
