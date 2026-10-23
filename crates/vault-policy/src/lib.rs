//! Policy evaluation engine for agent signing requests.

#![forbid(unsafe_code)]

mod engine;
mod error;
mod report;

pub use engine::{PolicyEngine, RAILGUN_POI_STANDBY};
pub use error::PolicyError;
pub use report::{PolicyDecision, PolicyEvaluation, PolicyExplanation};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests_explain;
