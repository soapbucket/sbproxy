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
/// OpenID Federation operator surface (`GET /admin/federation`): what
/// this proxy publishes as its entity configuration and what it
/// requires of a peer.
pub mod admin_federation;
/// WOR-1553/1554: key + credential lifecycle REST API mounted on the
/// admin server (`/admin/keys`, `/admin/credentials`).
pub mod admin_keys;
pub mod admin_licensing;
/// Time-boxed MCP grants and gateway-originated approval holds
/// (`/api/mcp/grants`, `/api/mcp/approvals`). A console page is deferred.
/// Time-boxed MCP grant ledger and gateway-originated approval holds
/// (`GET`/`POST /api/mcp/grants`, `GET`/`POST /api/mcp/approvals`).
pub mod admin_mcp_grants;
pub mod admin_mcp_oauth;
/// Attested-metering operator surface (`/api/meter/*`), WOR-2131: units
/// with their provenance, the mesh coverage a total was assembled from,
/// a cursor-paged window on the receipt chain, and chain verification.
/// Every response says whether attestation is off, idle, or reporting
/// before it says a number, because a page of zeros cannot tell those
/// three apart.
pub mod admin_meter;
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
/// Authenticated and tenant-scoped AI toolkit operator routes.
pub mod admin_toolkit;
/// Static-asset surface for the built-in admin
/// dashboard at `/admin/ui/*`. Embedded via `include_dir!` when the
/// `embed-admin-ui` feature is on; serves a one-line operator hint
/// otherwise.
pub mod admin_ui;
/// Agent-class capture seam between the resolver in `sbproxy-modules`
/// and the per-request context. Feature-gated by `agent-class`.
#[cfg(feature = "agent-class")]
pub mod agent_class;
/// Generation-pinned dispatch for provider-neutral AI extension events.
pub mod ai_extensions;
/// Generation-pinned assembly for the bounded AI toolkit runtime.
pub(crate) mod ai_toolkit_runtime;
/// Boot wiring for the alert evaluation loop (dispatcher + engine + drain).
pub mod alerting;
/// WOR-2666: behavioral anomaly detection over the signals the request
/// path already collects, and the agent-class reputation it feeds.
///
/// Not behind `agent-class`: the detector reads the signals it is
/// given and produces nothing when they are absent, so a build without
/// the resolver still detects rate spikes and headless libraries.
pub mod anomaly;
/// Lowering `proxy.attestation` into the metering vocabulary the
/// request path runs on: the resolved role, the two posture axes, the
/// queue and ledger locations, and the operator's complete position on
/// what they charge for.
pub mod attestation;
/// OpenID Federation peer trust on the request path: the compiled
/// `proxy.federation.peer_trust` decision.
pub(crate) mod federation_peer;

/// WOR-2100: runtime assembly for authoritative payment settlement.
///
/// Opens the durable settlement store, registers the rail adapters this
/// build compiled, and owns the recovery worker's lifecycle. Feature-gated
/// by `payments`, so a build without settlement carries none of it.
#[cfg(feature = "payments")]
pub mod billing_runtime;
/// WOR-2573: break-glass emergency access to the key/credential admin API.
pub(crate) mod break_glass;
/// Empty-shell registry for built-in policy
/// enforcer wrappers.
///
/// Holds the eventual single dispatch point that the per-policy
/// ports (1c.1 / 1c.2 / 1c.3) will populate. Today every
/// built-in arm returns `BuiltinEnforcerError::NotYetPorted`; the
/// `check_policies` enum-arm dispatch in `server.rs` is unchanged.
/// See `docs/policy.md`.
pub mod builtin_enforcers;
/// P0 edge capture wired into the request pipeline.
pub mod capture_envelope;
/// Stock classifier-backed intent and quality hooks, including the optional
/// in-process intent fallback adapter used by embedders.
pub mod classifier_hooks;
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
/// The aggregator: fetch every project repository an `origin_sources`
/// block names, compose the `origins:` map from the platform floor and
/// the project profiles, and publish the result through the config
/// authority that already ships.
pub mod config_aggregator;
/// Config-authority publisher: validate a configuration the way boot
/// does, sign it, store it under a monotonic revision, and serve it to
/// subscribers on a listener of its own.
pub mod config_authority;
/// Booting on the last known good config when the document this node was
/// told to boot on does not work: the ring walk, the durable boot
/// counter, and the pin that suspends the local reload triggers while
/// the node is serving a rescued configuration.
pub mod config_boot;
/// What configuration is actually running on this node, which layer owns
/// each part of it, and whether a proposed write to the local file would
/// survive the next poll or be silently swallowed.
pub mod config_effective;
/// Gossip accelerator for config distribution: an authority announces its
/// current revision into typed cluster state, and a mesh-member subscriber
/// pulls on the hint instead of waiting out its poll interval. Never a
/// correctness requirement; polling alone already converges.
pub mod config_gossip;
/// The process-owned handle onto the durable config revision ring:
/// every config this process applies, recorded once by the shared
/// reload transaction, and read back by the admin history surface.
pub mod config_history;
/// Re-applying a stored config revision: the manual rollback the admin
/// route and the CLI drive, and the automatic revert a failed soak arms
/// when `soak.auto_revert` is on (WOR-2460, WOR-2461).
///
/// Crate-visible rather than public for the same reason
/// [`mod@config_soak`] is: the admin surface and the soak supervisor are
/// the only two callers, both inside this crate, and nothing outside it
/// has a reason to move this node's running configuration.
pub(crate) mod config_rollback;
/// The soak window that decides whether an applied config revision
/// becomes this node's last known good (WOR-2458).
///
/// Crate-visible rather than public: every consumer is inside this
/// crate (the reload transaction arms a window, the admin surface
/// closes one), and nothing outside it has a reason to reach a soak
/// verdict on this process's behalf.
pub(crate) mod config_soak;
/// Honoring `source:`: resolve the config document from a git
/// repository (or an overlay chain over one), keep it fresh on a timer,
/// and hand the result to the shared reload transaction.
pub mod config_source;
/// Config-authority subscriber: pull signed configuration from an
/// upstream authority, verify it, merge it over the base document, and
/// apply it through the shared reload transaction.
pub mod config_subscriber;
pub mod content_capture;
pub mod context;
/// Running an operator-authored script for one decision event.
pub(crate) mod decision_script;
pub mod dispatch;
/// Host capability diagnostics behind `sbproxy doctor`.
pub mod doctor;
pub(crate) mod extension_inventory;
pub(crate) mod extension_refresh;
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
/// WOR-2672: port of `sbproxy-enterprise-ai::intent_detection`. Coarse
/// keyword-heuristic prompt classification, dispatched from
/// `server::ai_dispatch` as the fallback when no
/// [`hooks::IntentDetectionHook`] is registered or the registered one
/// declines to decide.
pub mod intent_detection;
/// WOR-2306: resolve one RFC 6901 JSON Pointer against a request body
/// without materializing the document, for body-field route matching.
pub mod json_pointer;
/// Fleet capability gate for record fields older nodes silently drop.
pub mod key_capability;
/// WOR-1546: dynamic key plane assembly + process-global handle.
pub mod key_plane;
/// Canonical, secret-free lowering for governed key policy.
pub mod key_policy;
/// WOR-2568: customer-managed root of trust for the credential envelope.
pub mod key_root_of_trust;
/// WOR-1562: mesh distributed-cache tier for the key plane.
pub mod mesh_cache;
pub mod mesh_keystore;
/// WOR-2130: mesh-wide meter reporting. One receipt chain per node, and a
/// scatter-gather that labels a total assembled from an incomplete set as
/// exactly that. Deliberately not built on `cluster_metrics`; see the
/// module docs for why receipts cannot use a live-view-retaining aggregator.
pub mod meter_cluster;
/// WOR-2145: the seam where a served request becomes a signed, chained
/// receipt. Holds the chain, the sequencing lock that keeps a receipt's
/// sequence equal to the entry carrying it, and the two phases the work is
/// split across: a cheap preflight in `response_filter`, which is the only
/// place a receipt failure can still refuse anything, and the receipt
/// itself in `logging`, where the final status and byte counts are known.
pub mod meter_runtime;
/// WOR-1563: distributed per-key spend + rate counters via mesh CRDTs.
pub mod model_discovery;
/// Authenticated private model-plane dispatch primitives.
pub mod model_plane;
/// Strip the configured config path out of an error string before it
/// reaches an HTTP response or an audit record (WOR-2486 fix round 1,
/// I5). Shared between the admin reload/validate handlers and the
/// non-admin reload paths so both scrub the same way.
pub(crate) mod path_redact;
/// Fail-open delivery for terminal payment extension events.
#[cfg(feature = "payments")]
pub mod payment_extensions;
/// WOR-2317: the durable single-serve ledger settlement burns quote nonces
/// against, in the same database as the settlement it authorizes.
#[cfg(feature = "payments")]
pub mod payment_nonce;
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
/// `docs/events.md`.
pub mod policy_bus;
/// Chain reducer + Plugin verdict translation.
///
/// Multi-policy resolution rules from
/// `docs/policy.md` (Deny wins, first Confirm
/// wins via the OSS bridge, AllowWithHeaders accumulate). Lives
/// in its own module so the helpers can be exercised by
/// integration tests in `crates/sbproxy-core/tests/`.
pub mod policy_dispatch;
/// Bounded observability and fail-closed/degraded decision state for an
/// unavailable `prompt_injection_v2` classifier.
pub(crate) mod prompt_injection_runtime;
mod proxy_wasm_http;
/// WOR-2672: port of `sbproxy-enterprise-ai::quality_routing`. Provider
/// selection by quality score via an optional
/// [`hooks::QualityScoringHook`], falling back to the first candidate on
/// any failure. Dispatched live from `server::ai_dispatch` (see the
/// module docs for exactly where).
pub mod quality_routing;
pub(crate) mod request_body_plan;
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
/// WOR-2143: the settlement origin gate for `ai_crawl_control`. Decides
/// whether an unpaid crawl request reaches the origin, at the
/// `check_policies` call site, from durable settlement state.
#[cfg(feature = "payments")]
pub(crate) mod settlement_gate;
/// Synthetic-transaction probe driver. Background task that
/// fires an in-process request through the compiled handler chain
/// and feeds the verdict into the `/readyz` synthetic probe cache.
pub mod synthetic;
#[cfg(test)]
mod test_env;
mod trust_tier;
/// WOR-2169: the producer that turns a served request into rows in the
/// durable billing queue. Owns the resource and unit mapping, the provider
/// deduplication identifier, and the posture that decides what happens when
/// a billable unit cannot be queued. The reporter, the queue, and the
/// worker that drains it all predate this and none of them had a caller.
pub mod usage_bridge;

// Re-export the main entry point for convenience.
pub use server::{run, GraceConfig};
