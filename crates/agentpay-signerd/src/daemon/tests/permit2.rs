//! Permit2 witness permits: signed over their EIP-712 digest and counted as
//! spends; approving the canonical Permit2 is not.

use agentpay_domain::{
    AdminAuth, AgentAction, BroadcastTx, EntityScope, Permit2Permission, Permit2Witness,
    Permit2WitnessTransfer, PolicyAttachment, PolicyType, SpendingPolicy, PERMIT2_ADDRESS,
};
use agentpay_policy::PolicyError;
use agentpay_signer::{KeyCreateRequest, SoftwareSignerBackend};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

use super::support::{policy_per_chain_gas, reserve_nonce_for_agent, sign_request};
use crate::{DaemonConfig, DaemonError, InMemoryDaemon, KeyManagerDaemonApi};

const TOKEN: &str = "0x3000000000000000000000000000000000000000";

fn permit(nonce: &str, amount_wei: u128) -> AgentAction {
    let deadline = u64::try_from(
        (time::OffsetDateTime::now_utc() + time::Duration::minutes(10)).unix_timestamp(),
    )
    .expect("deadline");
    AgentAction::Permit2WitnessTransfer {
        permit: Permit2WitnessTransfer {
            chain_id: 1,
            token: TOKEN.parse().expect("token"),
            permitted: vec![Permit2Permission { amount_wei }],
            spender: "0x5000000000000000000000000000000000000000"
                .parse()
                .expect("spender"),
            nonce: nonce.into(),
            deadline,
            witness: Permit2Witness::ChallengeExternalId {
                challenge_hash: format!("0x{}", "11".repeat(32)),
                external_id: String::new(),
            },
        },
    }
}

fn daily_limit(max: u128) -> SpendingPolicy {
    SpendingPolicy::new(
        1,
        PolicyType::DailyMaxSpending,
        max,
        EntityScope::All,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

#[tokio::test]
async fn a_permit_is_signed_over_its_digest_and_counted_against_the_window() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, daily_limit(100))
        .await
        .expect("policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    let action = permit("1", 60);
    let signature = daemon
        .sign_for_agent(sign_request(&agent, action.clone()))
        .await
        .expect("signed");
    let digest = action.signing_hash().expect("hash").expect("typed");
    let parsed = K256Signature::from_der(&signature.bytes).expect("DER");
    let recovery_id = RecoveryId::from_byte(signature.v.expect("v") as u8).expect("recovery id");
    let recovered =
        VerifyingKey::recover_from_prehash(&digest, &parsed, recovery_id).expect("recover");
    let expected = VerifyingKey::from_sec1_bytes(&hex::decode(&key.public_key_hex).expect("hex"))
        .expect("key");
    assert_eq!(recovered, expected);
    assert!(signature.raw_tx_hex.is_none());

    let err = daemon
        .sign_for_agent(sign_request(&agent, permit("2", 60)))
        .await
        .expect_err("the window holds 60 already");
    assert!(
        matches!(
            err,
            DaemonError::Policy(PolicyError::WindowLimitExceeded {
                used_amount_wei: 60,
                requested_amount_wei: 60,
                ..
            })
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn approving_permit2_needs_no_spending_headroom_and_spends_nothing() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    daemon
        .add_policy(&session, daily_limit(100))
        .await
        .expect("policy");
    daemon
        .add_policy(&session, policy_per_chain_gas(1, 1_000_000_000_000_000))
        .await
        .expect("gas policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");

    // `approve(PERMIT2_ADDRESS, u128::MAX)`.
    let data = format!(
        "095ea7b3{:0>64}{:0>64x}",
        PERMIT2_ADDRESS.trim_start_matches("0x"),
        u128::MAX
    );
    let approval = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: TOKEN.parse().expect("token"),
            value_wei: 0,
            data_hex: format!("0x{data}"),
            gas_limit: 60_000,
            max_fee_per_gas_wei: 1_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    reserve_nonce_for_agent(&daemon, &agent, 1, 0).await;
    daemon
        .sign_for_agent(sign_request(&agent, approval))
        .await
        .expect("an unlimited Permit2 approval is signed under a 100 daily limit");

    // The approval left the whole window for payments.
    daemon
        .sign_for_agent(sign_request(&agent, permit("3", 100)))
        .await
        .expect("the full window is still available");
}

/// Audit regression: a policy for one network does not let the agent get a
/// Permit2 approval signed on another (with fees of its choosing).
#[tokio::test]
async fn a_permit2_approval_on_a_network_no_policy_covers_is_refused() {
    let daemon = InMemoryDaemon::new(SoftwareSignerBackend::default(), DaemonConfig::default())
        .expect("daemon");
    let session = AdminAuth::PeerCredentials;
    let bsc_only = SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        1_000,
        EntityScope::All,
        EntityScope::All,
        EntityScope::Set(std::collections::BTreeSet::from([56u64])),
    )
    .expect("policy");
    daemon.add_policy(&session, bsc_only).await.expect("policy");
    let key = daemon
        .create_vault_key(&session, KeyCreateRequest::Generate)
        .await
        .expect("key");
    let agent = daemon
        .create_agent_key(&session, key.id, PolicyAttachment::AllPolicies)
        .await
        .expect("agent");
    let data = format!(
        "095ea7b3{:0>64}{:0>64x}",
        PERMIT2_ADDRESS.trim_start_matches("0x"),
        1u8
    );
    let approval = AgentAction::BroadcastTx {
        tx: BroadcastTx {
            chain_id: 1,
            nonce: 0,
            to: TOKEN.parse().expect("token"),
            value_wei: 0,
            data_hex: format!("0x{data}"),
            gas_limit: 50_000,
            max_fee_per_gas_wei: 1_000_000_000_000_000_000,
            max_priority_fee_per_gas_wei: 1_000_000_000_000_000_000,
            tx_type: 0x02,
            delegation_enabled: false,
        },
    };
    reserve_nonce_for_agent(&daemon, &agent, 1, 0).await;
    let err = daemon
        .sign_for_agent(sign_request(&agent, approval))
        .await
        .expect_err("no policy covers chain 1");
    assert!(
        matches!(err, DaemonError::Policy(PolicyError::NoApplicablePolicies)),
        "{err:?}"
    );
}
