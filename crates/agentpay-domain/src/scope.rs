use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Scope matcher for recipients, assets, and networks.
///
/// JSON: `{"mode": "All"}` or `{"mode": "Set", "values": [...]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, TS)]
#[serde(tag = "mode", content = "values")]
pub enum EntityScope<T: Ord> {
    /// Match all values.
    All,
    /// Match a specific set of values (a JSON array without duplicates).
    Set(BTreeSet<T>),
}

impl<T: Ord> EntityScope<T> {
    /// Returns whether `value` is allowed by this scope.
    #[must_use]
    pub fn allows(&self, value: &T) -> bool {
        match self {
            Self::All => true,
            Self::Set(set) => set.contains(value),
        }
    }
}
