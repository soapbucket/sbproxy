//! sbproxy-extension: Scripting runtimes and policy engines (CEL,
//! Cedar, Lua, JS, WASM).
//!
//! This crate provides expression evaluation and scripting engines used by
//! sbproxy for conditional logic in routing, access control, and policy
//! enforcement.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bundle;
pub mod cedar;
pub mod cel;
pub mod flags;
pub mod js;
pub mod lua;
pub mod mcp;
pub mod rego;
pub mod wasm;
