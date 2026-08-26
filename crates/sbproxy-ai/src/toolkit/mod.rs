//! Bounded, governed production facade for the AI toolkit building blocks.

mod evaluation;
mod rollout;
mod runtime;
mod snapshot;
mod types;
mod validation;
mod workflow;

pub use runtime::{error_metric_outcome, AiToolkitRuntime};
pub use types::*;

#[cfg(test)]
mod tests;
