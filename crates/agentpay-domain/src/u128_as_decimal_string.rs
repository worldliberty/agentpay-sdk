//! Serde helpers that encode `u128` values as base-10 strings.
//!
//! JSON numbers above 2^53 lose precision in JavaScript, so every wire amount
//! is a decimal string (see [`crate::schema::DecimalU128`]).

use serde::{Deserialize, Deserializer, Serializer};

/// Serializes `value` as a decimal string.
pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string())
}

/// Parses a decimal string into a `u128`.
pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    value.parse::<u128>().map_err(serde::de::Error::custom)
}

/// The same encoding for `Option<u128>` (`None` is `null`).
pub mod option {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes `Some(value)` as a decimal string and `None` as `null`.
    pub fn serialize<S>(value: &Option<u128>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    /// Parses `null` or a decimal string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u128>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        match value {
            Some(value) => value
                .parse::<u128>()
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
