use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

pub mod zeroizing_string {
    use super::*;

    pub fn serialize<S>(value: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}

pub mod zeroizing_string_map {
    use super::*;

    pub fn serialize<S>(
        values: &HashMap<Uuid, Zeroizing<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let plain = values
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect::<HashMap<_, _>>();
        plain.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<Uuid, Zeroizing<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        HashMap::<Uuid, String>::deserialize(deserializer).map(|values| {
            values
                .into_iter()
                .map(|(key, value)| (key, Zeroizing::new(value)))
                .collect()
        })
    }
}

/// Deserializers for persisted daemon state that drop entries referring to
/// retired features (Railgun, legacy Tempo sessions v1, typed Permit2 permits)
/// instead of failing the whole load.
///
/// Only the exact retired tags listed here are tolerated; any other malformed
/// entry still fails deserialization so corrupted state is never silently
/// loosened. Use with `#[serde(deserialize_with = "...")]` on the matching
/// persisted field; serialization is unchanged.
pub mod retired {
    use std::collections::HashMap;
    use std::hash::Hash;

    use serde::de::{DeserializeOwned, Error as _};
    use serde::{Deserialize, Deserializer};
    use serde_json::Value;
    use uuid::Uuid;

    use crate::{ManualApprovalRequest, SpendEvent, SpendingPolicy, VaultKey};

    const RETIRED_POLICY_TYPES: &[&str] = &[
        "PerTxMaxShieldAmount",
        "DailyMaxShieldAmount",
        "PerTxMaxUnshieldAmount",
        "DailyMaxUnshieldAmount",
    ];
    const RETIRED_KEY_ALGORITHMS: &[&str] = &["railgun_spending", "railgun_viewing"];
    const RETIRED_RECIPIENT_KIND: &str = "railgun";
    const RETIRED_ACTION_KINDS: &[&str] = &[
        "Shield",
        "Unshield",
        "PrivateTransfer",
        "Permit2Permit",
        "TempoSessionOpenTransaction",
        "TempoSessionTopUpTransaction",
        "TempoSessionVoucher",
    ];

    fn tag_in(value: &Value, pointer: &str, retired: &[&str]) -> bool {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|tag| retired.contains(&tag))
    }

    fn is_retired_recipient(value: &Value) -> bool {
        tag_in(value, "/kind", &[RETIRED_RECIPIENT_KIND])
    }

    fn map_without_retired<'de, D, K, T>(
        deserializer: D,
        mut keep: impl FnMut(&mut Value) -> bool,
    ) -> Result<HashMap<K, T>, D::Error>
    where
        D: Deserializer<'de>,
        K: DeserializeOwned + Eq + Hash,
        T: DeserializeOwned,
    {
        HashMap::<K, Value>::deserialize(deserializer)?
            .into_iter()
            .filter_map(|(key, mut value)| keep(&mut value).then_some((key, value)))
            .map(|(key, value)| serde_json::from_value(value).map(|item| (key, item)))
            .collect::<Result<_, _>>()
            .map_err(D::Error::custom)
    }

    /// Drops retired Railgun policy types and strips Railgun recipients from
    /// recipient scopes. A stripped scope keeps matching exactly the
    /// recipients it matched before for every action that can still be signed.
    pub fn policy_map<'de, D>(deserializer: D) -> Result<HashMap<Uuid, SpendingPolicy>, D::Error>
    where
        D: Deserializer<'de>,
    {
        map_without_retired(deserializer, |policy| {
            if tag_in(policy, "/policy_type", RETIRED_POLICY_TYPES) {
                return false;
            }
            if let Some(Value::Array(recipients)) = policy.pointer_mut("/recipients/values") {
                recipients.retain(|recipient| !is_retired_recipient(recipient));
            }
            true
        })
    }

    /// Drops Railgun spending/viewing vault keys.
    pub fn vault_key_map<'de, D>(deserializer: D) -> Result<HashMap<Uuid, VaultKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        map_without_retired(deserializer, |key| {
            !tag_in(key, "/algorithm", RETIRED_KEY_ALGORITHMS)
        })
    }

    /// Drops manual-approval requests for retired actions or Railgun recipients.
    pub fn manual_approval_map<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<Uuid, ManualApprovalRequest>, D::Error>
    where
        D: Deserializer<'de>,
    {
        map_without_retired(deserializer, |request| {
            !tag_in(request, "/action/kind", RETIRED_ACTION_KINDS)
                && !request.get("recipient").is_some_and(is_retired_recipient)
        })
    }

    /// Drops spend events recorded against Railgun recipients.
    pub fn spend_log<'de, D>(deserializer: D) -> Result<Vec<SpendEvent>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<Value>::deserialize(deserializer)?
            .into_iter()
            .filter(|event| !event.get("recipient").is_some_and(is_retired_recipient))
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(D::Error::custom)
    }
}
