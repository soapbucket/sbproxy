//! sbproxy-config: Configuration parsing, compilation, and validation.
//!
//! This crate handles:
//! - Parsing YAML config files into typed structs ([`types`])
//! - Intermediate representation ([`raw`])
//! - Compiling configs into immutable, performance-optimized snapshots ([`snapshot`], [`compiler`])

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod compiler;
pub mod duration;
pub mod plan;
pub mod raw;
pub mod snapshot;
pub mod types;
pub mod validate;

pub use compiler::*;
pub use plan::{
    plan, plan_with_options, render_text, BlastRadius, PlanEntry, PlanKind, PlanReport, PlanSummary,
};
pub use raw::*;
pub use snapshot::*;
pub use types::*;
pub use validate::{
    validate, PlanFinding, Severity, ValidationOptions, KNOWN_ACTION_TYPES, KNOWN_AUTH_TYPES,
    KNOWN_POLICY_TYPES, KNOWN_TRANSFORM_TYPES,
};
