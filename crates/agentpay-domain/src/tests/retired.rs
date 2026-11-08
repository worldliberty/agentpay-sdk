use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;

#[derive(Debug, Deserialize)]
struct PersistedFixture {
    #[serde(default, deserialize_with = "serde_helpers::retired::policy_map")]
    policies: HashMap<Uuid, SpendingPolicy>,
    #[serde(default, deserialize_with = "serde_helpers::retired::vault_key_map")]
    vault_keys: HashMap<Uuid, VaultKey>,
    #[serde(default, deserialize_with = "serde_helpers::retired::spend_log")]
    spend_log: Vec<SpendEvent>,
    #[serde(
        default,
        deserialize_with = "serde_helpers::retired::manual_approval_map"
    )]
    manual_approval_requests: HashMap<Uuid, ManualApprovalRequest>,
}

fn evm(value: &str) -> EvmAddress {
    value.parse().expect("evm address")
}

fn railgun_recipient() -> Value {
    json!({ "kind": "railgun", "value": format!("0zk1{}", "q".repeat(100)) })
}

fn per_tx_policy(recipients: EntityScope<EvmAddress>) -> SpendingPolicy {
    SpendingPolicy::new(
        1,
        PolicyType::PerTxMaxSpending,
        100,
        recipients,
        EntityScope::All,
        EntityScope::All,
    )
    .expect("policy")
}

fn sample_spend_event() -> SpendEvent {
    SpendEvent {
        agent_key_id: Uuid::nil(),
        chain_id: 1,
        asset: AssetId::NativeEth,
        recipient: RecipientId::Evm(evm("0x1111111111111111111111111111111111111111")),
        amount_wei: 1,
        at: OffsetDateTime::UNIX_EPOCH,
        approval_request_id: None,
    }
}

fn sample_approval(action: AgentAction) -> ManualApprovalRequest {
    ManualApprovalRequest {
        id: Uuid::new_v4(),
        agent_key_id: Uuid::nil(),
        vault_key_id: Uuid::nil(),
        request_payload_hash_hex: "00".repeat(32),
        chain_id: action.chain_id(),
        asset: action.asset(),
        recipient: action.recipient(),
        amount_wei: action.amount_wei(),
        action,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        status: ManualApprovalStatus::Pending,
        triggered_by_policy_ids: Vec::new(),
        reasons: Vec::new(),
        completed_at: None,
        rejection_reason: None,
    }
}

#[test]
fn retired_policies_are_dropped_and_railgun_recipients_stripped() {
    let kept = per_tx_policy(EntityScope::All);
    let scoped = per_tx_policy(EntityScope::Set(BTreeSet::from([evm(
        "0x2222222222222222222222222222222222222222",
    )])));
    let mut scoped_json = serde_json::to_value(&scoped).expect("policy json");
    scoped_json["recipients"]["values"]
        .as_array_mut()
        .expect("recipient set")
        .push(railgun_recipient());
    let mut retired_json = serde_json::to_value(&kept).expect("policy json");
    retired_json["policy_type"] = json!("DailyMaxShieldAmount");
    let retired_id = Uuid::new_v4();

    let fixture: PersistedFixture = serde_json::from_value(json!({
        "policies": {
            kept.id.to_string(): kept,
            scoped.id.to_string(): scoped_json,
            retired_id.to_string(): retired_json,
        }
    }))
    .expect("persisted policies load");

    assert_eq!(fixture.policies.len(), 2);
    assert_eq!(fixture.policies[&kept.id], kept);
    assert_eq!(fixture.policies[&scoped.id], scoped);
    assert!(!fixture.policies.contains_key(&retired_id));
}

#[test]
fn retired_policy_helper_still_rejects_other_malformed_policies() {
    let mut malformed = serde_json::to_value(per_tx_policy(EntityScope::All)).expect("json");
    malformed["policy_type"] = json!("SomethingNew");
    let err = serde_json::from_value::<PersistedFixture>(json!({
        "policies": { Uuid::new_v4().to_string(): malformed }
    }))
    .expect_err("unknown policy types must not be silently dropped");
    assert!(err.to_string().contains("SomethingNew"), "{err}");
}

#[test]
fn retired_vault_keys_spend_events_and_approvals_are_dropped() {
    let key = VaultKey {
        id: Uuid::new_v4(),
        source: KeySource::Generated,
        algorithm: KeyAlgorithm::Secp256k1,
        public_key_hex: "04".to_string(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        name: None,
    };
    let mut railgun_key = serde_json::to_value(&key).expect("key json");
    railgun_key["algorithm"] = json!("railgun_viewing");

    let event = sample_spend_event();
    let mut railgun_event = serde_json::to_value(&event).expect("event json");
    railgun_event["recipient"] = railgun_recipient();

    let approval = sample_approval(AgentAction::TransferNative {
        chain_id: 1,
        to: evm("0x3333333333333333333333333333333333333333"),
        amount_wei: 5,
    });
    let mut shield_approval = serde_json::to_value(&approval).expect("approval json");
    shield_approval["action"] = json!({ "kind": "Shield", "chain_id": 1 });
    let mut voucher_approval = serde_json::to_value(&approval).expect("approval json");
    voucher_approval["action"] = json!({ "kind": "TempoSessionVoucher" });
    voucher_approval["recipient"] = railgun_recipient();

    let fixture: PersistedFixture = serde_json::from_value(json!({
        "vault_keys": {
            key.id.to_string(): key,
            Uuid::new_v4().to_string(): railgun_key,
        },
        "spend_log": [event, railgun_event],
        "manual_approval_requests": {
            approval.id.to_string(): approval,
            Uuid::new_v4().to_string(): shield_approval,
            Uuid::new_v4().to_string(): voucher_approval,
        },
    }))
    .expect("persisted state loads");

    assert_eq!(fixture.vault_keys.len(), 1);
    assert_eq!(fixture.vault_keys[&key.id], key);
    assert_eq!(fixture.spend_log, vec![event]);
    assert_eq!(fixture.manual_approval_requests.len(), 1);
    assert_eq!(fixture.manual_approval_requests[&approval.id], approval);
    assert!(fixture.policies.is_empty());
}
