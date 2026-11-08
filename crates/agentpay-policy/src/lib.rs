//! Policy evaluation engine for agent signing requests.

#![forbid(unsafe_code)]

mod engine;
mod error;
mod report;

pub use engine::PolicyEngine;
pub use error::PolicyError;
pub use report::{PolicyDecision, PolicyEvaluation, PolicyExplanation};

#[cfg(test)]
mod tests;
