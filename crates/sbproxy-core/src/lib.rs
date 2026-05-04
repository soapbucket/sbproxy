//! sbproxy-core: Pingora server, host routing, phase dispatch, and hot reload.
//!
//! This crate provides:
//! - [`context::RequestContext`] - Per-request state threaded through Pingora phases
//! - [`pipeline::CompiledPipeline`] - Config + compiled module instances
//! - [`router::HostRouter`] - Host-based request routing
//! - [`reload`] - ArcSwap-based hot pipeline reload
//! - [`server::SbProxy`] - Pingora `ProxyHttp` implementation
//! - [`server::run`] - Server entry point

#![warn(missing_docs)]

pub mod admin;
/// Agent-class capture seam between the resolver in `sbproxy-modules`
/// and the per-request context. Feature-gated by `agent-class` (G1.4).
#[cfg(feature = "agent-class")]
pub mod agent_class;
pub mod context;
pub mod dispatch;
pub mod hook_registry;
pub mod hooks;
pub mod identity;
pub mod pipeline;
pub mod reload;
pub mod router;
/// WOR-114 Phase 1: per-request feature-flag parsing.
///
/// Parses `x-sb-flags` request header and `?_sb.<key>` query params
/// into a typed `sb_flags::RequestFlags` struct that the request
/// pipeline reads to alter behavior on the current request only.
pub mod sb_flags;
pub mod server;
/// Wave 8 P0 edge capture wired into the request pipeline.
pub mod wave8;

// Re-export the main entry point for convenience.
pub use server::run;
