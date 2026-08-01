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
/// Settlement status and the reconciliation trigger
/// (`/admin/payments/*`), WOR-2100. Compiled unconditionally so the routes
/// answer with a clear reason on a build without the `payments` feature
/// rather than falling through to a bare 404.
pub mod admin_payments;
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
/// Lowering `proxy.attestation` into the metering vocabulary the
/// request path runs on: the resolved role, the two posture axes, the
/// queue and ledger locations, and the operator's complete position on
/// what they charge for.
pub mod attestation;

/// WOR-2100: runtime assembly for authoritative payment settlement.
///
/// Opens the durable settlement store, registers the rail adapters this
/// build compiled, and owns the recovery worker's lifecycle. Feature-gated
/// by `payments`, so a build without settlement carries none of it.
#[cfg(feature = "payments")]
pub mod billing_runtime;
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
/// Success-path bridge for prompt-free, per-lever AI compression value.
pub mod compression_value;
/// Config-authority publisher: validate a configuration the way boot
/// does, sign it, store it under a monotonic revision, and serve it to
/// subscribers on a listener of its own.
pub mod config_authority;
/// What configuration is actually running on this node, which layer owns
/// each part of it, and whether a proposed write to the local file would
/// survive the next poll or be silently swallowed.
pub mod config_effective;
/// Gossip accelerator for config distribution: an authority announces its
/// current revision into typed cluster state, and a mesh-member subscriber
/// pulls on the hint instead of waiting out its poll interval. Never a
/// correctness requirement; polling alone already converges.
pub mod config_gossip;
/// Honouring `source:`: resolve the config document from a git
/// repository (or an overlay chain over one), keep it fresh on a timer,
/// and hand the result to the shared reload transaction.
pub mod config_source;
/// Config-authority subscriber: pull signed configuration from an
/// upstream authority, verify it, merge it over the base document, and
/// apply it through the shared reload transaction.
pub mod config_subscriber;
pub mod content_capture;
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
/// Extraction of a minted virtual key from configured inbound headers.
pub mod inbound_key;
/// Fleet capability gate for record fields older nodes silently drop.
pub mod key_capability;
/// WOR-1546: dynamic key plane assembly + process-global handle.
pub mod key_plane;
/// Canonical, secret-free lowering for governed key policy.
pub mod key_policy;
/// WOR-1562: mesh distributed-cache tier for the key plane.
pub mod mesh_cache;
/// WOR-2130: mesh-wide meter reporting. One receipt chain per node, and a
/// scatter-gather that labels a total assembled from an incomplete set as
/// exactly that. Deliberately not built on `cluster_metrics`; see the
/// module docs for why receipts cannot use a live-view-retaining aggregator.
pub mod meter_cluster;
/// WOR-1563: distributed per-key spend + rate counters via mesh CRDTs.
pub mod model_discovery;
/// Authenticated private model-plane dispatch primitives.
pub mod model_plane;
/// Signs payment requirements into the existing quote JWS.
#[cfg(feature = "payments")]
pub mod payment_signer;
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
/// WOR-1130: module-owned workspace rate-limit budget state machine.
///
/// Re-exported here for admin/runtime compatibility; the implementation
/// lives beside its policy config in `sbproxy-modules`.
pub use sbproxy_modules::policy::rate_limit_budget;
/// WOR-2098: route-scoped RAG runtimes built once per compiled pipeline,
/// keyed by origin and optional forward rule. Feature-gated by `rag`.
#[cfg(feature = "rag")]
pub mod rag_runtime;
pub(crate) mod rate_limit_cluster;
pub mod reload;
pub mod router;
/// Phase 1: per-request feature-flag parsing.
///
/// Parses `x-sb-flags` request header and `?_sb.<key>` query params
/// into a typed `sb_flags::RequestFlags` struct that the request
/// pipeline reads to alter behavior on the current request only.
pub mod sb_flags;
/// WOR-2099: per-action semantic caches built once per compiled pipeline,
/// keyed by origin and optional forward rule. The `backend` field selects
/// memory, Redis, or mesh at runtime; no Cargo feature gates the choice.
pub mod semantic_cache_runtime;
pub mod server;
/// Synthetic-transaction probe driver. Background task that
/// fires an in-process request through the compiled handler chain
/// and feeds the verdict into the `/readyz` synthetic probe cache.
pub mod synthetic;
mod trust_tier;

// Re-export the main entry point for convenience.
pub use server::{run, GraceConfig};
