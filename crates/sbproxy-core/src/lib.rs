//! sbproxy-core: Pingora server, host routing, phase dispatch, and hot reload.
//!
//! This crate provides:
//! - [`context::RequestContext`] - Per-request state threaded through Pingora phases
//! - [`pipeline::CompiledPipeline`] - Config + compiled module instances
//! - [`router::HostRouter`] - Host-based request routing
//! - [`reload`] - ArcSwap-based hot pipeline reload
//! - [`server::SbProxy`] - Pingora `ProxyHttp` implementation
//! - [`server::run`] - Server entry point

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod admin;
/// Stub chat-playground handler mounted on the
/// admin server. Returns 501 today; the follow-up ticket wires it
/// through `proxy_router.oneshot`.
pub mod admin_playground;
/// Static-asset surface for the built-in admin
/// dashboard at `/admin/ui/*`. Embedded via `include_dir!` when the
/// `embed-admin-ui` feature is on; serves a one-line operator hint
/// otherwise.
pub mod admin_ui;
/// Agent-class capture seam between the resolver in `sbproxy-modules`
/// and the per-request context. Feature-gated by `agent-class`.
#[cfg(feature = "agent-class")]
pub mod agent_class;
/// Empty-shell registry for built-in policy
/// enforcer wrappers.
///
/// Holds the eventual single dispatch point that the per-policy
/// ports (1c.1 / 1c.2 / 1c.3) will populate. Today every
/// built-in arm returns `BuiltinEnforcerError::NotYetPorted`; the
/// `check_policies` enum-arm dispatch in `server.rs` is unchanged.
/// See `docs/adr-policy-engine-unification.md`.
pub mod builtin_enforcers;
pub mod context;
pub mod dispatch;
pub mod hook_registry;
pub mod hooks;
pub mod identity;
pub mod pipeline;
/// Policy verdict audit event bus.
///
/// Bounded mpsc channel + drain stub for the OSS scope; enterprise
/// extends the consumer with a NATS-backed audit-chain subscriber
/// that hash-chains and KMS-signs Merkle roots downstream. See
/// `docs/adr-policy-audit-binding.md`.
pub mod policy_bus;
/// Chain reducer + Plugin verdict translation.
///
/// Multi-policy resolution rules from
/// `docs/adr-policy-verdict-shape.md` (Deny wins, first Confirm
/// wins via the OSS bridge, AllowWithHeaders accumulate). Lives
/// in its own module so the helpers can be exercised by
/// integration tests in `crates/sbproxy-core/tests/`.
pub mod policy_dispatch;
pub mod reload;
pub mod router;
/// Phase 1: per-request feature-flag parsing.
///
/// Parses `x-sb-flags` request header and `?_sb.<key>` query params
/// into a typed `sb_flags::RequestFlags` struct that the request
/// pipeline reads to alter behavior on the current request only.
pub mod sb_flags;
pub mod server;
/// Synthetic-transaction probe driver. Background task that
/// fires an in-process request through the compiled handler chain
/// and feeds the verdict into the `/readyz` synthetic probe cache.
pub mod synthetic;
/// P0 edge capture wired into the request pipeline.
pub mod wave8;

// Re-export the main entry point for convenience.
pub use server::{run, GraceConfig};
