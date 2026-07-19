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
/// Cache manager admin API: response-cache stats + purge and key-policy
/// cache eviction (`/admin/cache*`), WOR-1754 / WOR-1755.
pub mod admin_cache;
/// Fleet metrics admin API (`/admin/cluster/metrics`), WOR-1721.
pub mod admin_cluster;
/// Administrative metadata, inspection, and lifecycle controls for external
/// AI compression session state.
pub mod admin_compression;
/// WOR-1553/1554: key + credential lifecycle REST API mounted on the
/// admin server (`/admin/keys`, `/admin/credentials`).
pub mod admin_keys;
/// Model-host status admin API (`/admin/model-host/status`), WOR-1665.
pub mod admin_model_host;
/// Admin chat playground: list configured AI endpoints and run a chat
/// completion against any of them through the production AI dispatch
/// path. Handled in the async admin connection handler.
pub mod admin_playground;
/// Admin browser sessions + operator identity (WOR-1714 / WOR-1716).
pub mod admin_session;
/// Static-asset surface for the built-in admin
/// dashboard at `/admin/ui/*`. Embedded via `include_dir!` when the
/// `embed-admin-ui` feature is on; serves a one-line operator hint
/// otherwise.
pub mod admin_ui;
/// Agent-class capture seam between the resolver in `sbproxy-modules`
/// and the per-request context. Feature-gated by `agent-class`.
#[cfg(feature = "agent-class")]
pub mod agent_class;
/// Boot wiring for the alert evaluation loop (dispatcher + engine + drain).
pub mod alerting;
/// Empty-shell registry for built-in policy
/// enforcer wrappers.
///
/// Holds the eventual single dispatch point that the per-policy
/// ports (1c.1 / 1c.2 / 1c.3) will populate. Today every
/// built-in arm returns `BuiltinEnforcerError::NotYetPorted`; the
/// `check_policies` enum-arm dispatch in `server.rs` is unchanged.
/// See `docs/adr-policy-engine-unification.md`.
pub mod builtin_enforcers;
/// P0 edge capture wired into the request pipeline.
pub mod capture_envelope;
/// Process owner for the shared local or distributed cluster handle.
pub mod cluster;
/// WOR-1721: fleet-wide metric aggregation over the mesh.
pub mod cluster_metrics;
#[doc(hidden)]
pub mod cluster_models;
/// Metrics and content-free summary events for AI context compression.
pub mod compression_metrics;
/// Per-pipeline AI compression dependencies and request execution.
pub mod compression_runtime;
/// External Redis and mesh adapters for AI compression session state.
pub mod compression_store;
pub mod context;
pub mod dispatch;
/// Host capability diagnostics behind `sbproxy doctor`.
pub mod doctor;
/// WOR-1835: disseminate + merge approximate governance counters over the
/// mesh, so cross-node key budgets work without an external database.
pub mod governance_cluster;
/// Drop-safe ownership for accepted governance reservations.
pub mod governance_runtime;
pub mod hook_registry;
pub mod hooks;
pub mod identity;
/// WOR-1546: dynamic key plane assembly + process-global handle.
pub mod key_plane;
/// Canonical, secret-free lowering for governed key policy.
pub mod key_policy;
/// WOR-1562: mesh distributed-cache tier for the key plane.
pub mod mesh_cache;
/// WOR-1563: distributed per-key spend + rate counters via mesh CRDTs.
pub mod mesh_counters;
pub mod model_discovery;
/// Authenticated private model-plane dispatch primitives.
pub mod model_plane;
/// Managed-model runtime integration exposed for lifecycle adapters and
/// black-box reload tests.
#[doc(hidden)]
pub mod model_runtime {
    pub use crate::server::model_host::{
        commit_model_runtime, model_runtime_manager, prepare_model_runtime, validate_model_runtime,
        ManagedModelPermit, PreparedModelRuntime, ProductionModelRuntime,
    };
}
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
/// WOR-1130: workspace rate-limit budget + auto-suspend state machine.
pub mod rate_limit_budget;
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

// Re-export the main entry point for convenience.
pub use server::{run, GraceConfig};
