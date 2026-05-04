//! sbproxy-config: Configuration parsing, compilation, and validation.
//!
//! This crate handles:
//! - Parsing YAML config files into typed structs ([`types`])
//! - Intermediate representation ([`raw`])
//! - Compiling configs into immutable, performance-optimized snapshots ([`snapshot`], [`compiler`])

#![warn(missing_docs)]

pub mod compiler;
pub mod duration;
pub mod raw;
pub mod snapshot;
pub mod types;

pub use compiler::*;
pub use raw::*;
pub use snapshot::*;
pub use types::*;
