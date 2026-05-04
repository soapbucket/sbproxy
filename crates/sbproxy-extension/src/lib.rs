//! sbproxy-extension: Scripting runtimes (CEL, Lua, JS, WASM).
//!
//! This crate provides expression evaluation and scripting engines used by
//! sbproxy for conditional logic in routing, access control, and policy
//! enforcement.

#![warn(missing_docs)]

pub mod cel;
pub mod flags;
pub mod js;
pub mod lua;
pub mod mcp;
pub mod wasm;
