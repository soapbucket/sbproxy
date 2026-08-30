// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Every metric SBproxy emits, and what we are willing to promise about it.
//!
//! This table is the metrics half of the executable capability registry. It
//! exists because `docs/metrics-stability.md` was hand-maintained, and a
//! hand-maintained catalog drifts in exactly one direction: toward claiming
//! more than the code does. Eight metrics were published as `stable` while
//! nothing incremented them. A Grafana panel drew a flat zero over a
//! guardrail that had never once been observed. An alert on a queue depth
//! nobody set could not fire.
//!
//! Two fields carry the weight:
//!
//! - `MetricCapability::writer` names the production code that drives the
//!   family. The drift guard resolves that symbol against the source tree and
//!   requires a call site outside `#[cfg(test)]`. A recorder that exists,
//!   compiles, and is called by nobody is the failure mode this catches, and
//!   it is invisible to review because the metric still appears in `/metrics`,
//!   still scrapes, and still renders. It just renders zero.
//! - `MetricCapability::support` is that liveness, made declarable.
//!   `Stable` means something writes it. `ConfigOnly` means nothing does, and
//!   is an honest and permitted state so long as it is *declared*, carries a
//!   `dead_reason`, and no dashboard reads it.
//!
//! `MetricCapability::compat` is a different axis: the promise about the
//! *name*, which is what `docs/metrics-stability.md` publishes. A dead metric
//! cannot carry a `stable` compat tier, because a naming guarantee on a series
//! nobody emits is a guarantee about nothing.
//!
//! Adding a metric to the code without adding it here fails the build.
//!
//! A second, narrower guard lives at the bottom of this file:
//! `TENANT_SCOPED_METRICS` and `tenant_label_gaps` enforce multi-tenant
//! attribution. A metric can have a live writer, a truthful support level,
//! and still merge every tenant's spend, tokens, or security verdicts into
//! one series if nothing on it identifies whose data it is. That is a
//! quieter failure than a metric nobody writes: the numbers are real, the
//! panel draws, and the answer it gives is to a question nobody asked. See
//! `WOR-1896` for the shape of that bug in `snapshot_named`, and the module
//! doc on `tenant_label_gaps` below for the fix.
//!
//! A third guard, `run_scoped_label_gaps`, runs the opposite way. The tenant
//! one requires a label; this one forbids a family of them. Run ids, task
//! ids, context ids, session ids, and trace ids take one distinct value per
//! run, forever, so as label values they mint one time series per run and
//! the series count grows with traffic rather than with the system. That rule
//! was stated in three places and enforced in none before `WOR-2139`:
//! `docs/observability.md` in prose, `A2AContext::task_id` in a doc comment,
//! and `PROMPT_INJECTION_REASON` in
//! `crates/sbproxy-core/src/server/a2a_body_phase.rs`, which honored it only
//! by never passing one. Prose does not fail a build.

use sbproxy_capability::scan::ReferenceExemption;
use sbproxy_capability::{
    CompatTier, MetricCapability, MetricKind, Registry, RegistryError, SupportLevel, Writer,
};

/// Every Prometheus family declared under `crates/`.
///
/// Generated once from the source and maintained by hand thereafter; the
/// drift guard proves the two agree.
pub const METRICS: &[MetricCapability] = &[
    // Mesh (clustering substrate) families. Their writers are the metric
    // statics themselves (crates/sbproxy-mesh/src/metrics.rs); the scanner
    // resolves a SCREAMING_SNAKE_CASE writer as a static identifier. Every
    // mesh_ family carries beta name compatibility while the subsystem is
    // young.
    MetricCapability {
        name: "mesh_addr_map_updates_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_ADDR_MAP_UPDATES"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Peer address map updates driven by gossip learnings, by kind (learned or rewritten).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_anti_entropy_keys_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_ANTI_ENTROPY_KEYS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["direction"],
        description: "Records reconciled by replicated-substrate anti-entropy, by push or pull direction.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_anti_entropy_rounds_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_ANTI_ENTROPY_ROUNDS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Completed replicated-substrate maintenance rounds (handoff, anti-entropy, tombstone GC).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_cold_start_snapshots_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_COLD_START_SNAPSHOTS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Snapshots encountered during cold-start hydration, by outcome (merged, stale, corrupt).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_compression_coordination_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mesh_compression_coordination"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["event"],
        description: "Mesh compression session coordination contention and rejected updates, by closed event (contention, lease_expiry, stale_version, fence_rejection).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_crypto_decrypt_failed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_CRYPTO_DECRYPT_FAILED"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Mesh messages dropped because AEAD decryption failed, by crypto boundary (gossip or transport).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_dead_peers_gc_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_DEAD_PEERS_GC"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Dead peers removed from the peer table by the garbage collector.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_dissemination_updates_applied_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_DISSEMINATION_UPDATES_APPLIED"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transition"],
        description: "Inbound gossip peer updates that changed local peer state, by transition.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_dissemination_updates_ignored_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_DISSEMINATION_UPDATES_IGNORED"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Inbound gossip peer updates dropped without a local state change, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_dissemination_updates_sent_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_DISSEMINATION_UPDATES_SENT"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Peer updates piggybacked onto outgoing gossip messages, by carrier (ping or ack).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_enrollment_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_ENROLLMENT"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome", "reason"],
        description: "One-time cluster enrollment attempts as seen by the enrollment authority, by outcome and bounded failure reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_federation_peers",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("MESH_FEDERATION_PEERS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["state"],
        description: "Known federation peer clusters, by state.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_federation_pull_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_FEDERATION_PULL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Federation peer pull attempts, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_federation_push_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_FEDERATION_PUSH"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Federation leader summary and heartbeat pushes, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_gossip_probe_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("MESH_GOSSIP_LATENCY"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target"],
        description: "Gossip probe round-trip time to a peer, in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_gossip_retry_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_GOSSIP_RETRY"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target"],
        description: "Gossip probe retries against a peer (indirect PING-REQ fan-outs after a direct timeout).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_handoff_keys_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_HANDOFF_KEYS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Replicated records handed off after ring changes, by outcome (moved or retained).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_node_isolated",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("MESH_NODE_ISOLATED"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["node_id"],
        description: "1 while this node is in split-brain quarantine, 0 when healthy.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_owner_route_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_OWNER_ROUTE"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Owner-routed typed-state operations, by routing outcome (local, remote, or unreachable).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_peer_count",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("MESH_PEER_COUNT"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["state"],
        description: "Peer count by membership state, refreshed each SWIM sweep tick.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_peer_evicted_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_PEER_EVICTED"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Peers evicted from the membership list and hash ring, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_peer_state_transitions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_SUSPECT_TRANSITIONS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["from", "to"],
        description: "SWIM peer state transitions observed locally, by prior and new state.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_persistence_bytes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_PERSISTENCE_BYTES"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Bytes of mesh state written in successful Redis snapshots.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_persistence_snapshots_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_PERSISTENCE_SNAPSHOTS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Redis snapshot writes of mesh state, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_probe_direct_success_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_PROBE_DIRECT_SUCCESS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target"],
        description: "Direct SWIM pings whose ACK arrived inside the timeout window.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_probe_direct_timeout_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_PROBE_DIRECT_TIMEOUT"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target"],
        description: "Direct SWIM pings that timed out and triggered the indirect fallback.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_probe_indirect_success_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_PROBE_INDIRECT_SUCCESS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target"],
        description: "Indirect PING-REQ probes that resolved the target alive.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_replica_shard_entries",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("MESH_REPLICA_SHARD_ENTRIES"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Records held by the local replicated-substrate shard, refreshed each maintenance round.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_replication_read_repairs_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_REPLICATION_READ_REPAIRS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Stale replicas repaired in line by quorum reads.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_replication_writes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_REPLICATION_WRITES"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Replicated substrate writes, by coordinator outcome (acked or quorum_failed).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_tombstone_gc_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_TOMBSTONE_GC"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Ack-aware tombstone garbage collection decisions (collected or deferred).",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_transport_inbound_rejected_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_TRANSPORT_INBOUND_REJECTED"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Inbound cache RPC connections refused or torn down by an admission or deadline bound, by reason (connection_limit, handshake_timeout, handshake_failed, idle_timeout, frame_timeout, write_timeout). Any sustained connection_limit rate means peers are being turned away; the peer address is in the log line, never in a label.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_transport_rpc_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("MESH_TRANSPORT_RPC_DURATION"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["op"],
        description: "Successful cross-node cache RPC duration, by operation. Healthy same-zone means sit well under 5ms; a mean near 40ms is the delayed-ACK/Nagle transport stall signature and warrants an alert.",
        dead_reason: None,
    },
    MetricCapability {
        name: "mesh_transport_rpc_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MESH_TRANSPORT_RPC_ERRORS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Cross-node cache RPC failures, by transport phase. The five timeout_ kinds (timeout_lock, timeout_connect, timeout_tls, timeout_write, timeout_read) are the deadline half of the same set: a peer that answered with nothing rather than with a refusal.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_a2a_chain_depth",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_a2a_chain_depth"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["route", "spec"],
        description: "Distribution of A2A chain depth observed at the proxy.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_a2a_denied_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_a2a_denied"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["route", "reason"],
        description: "A2A hops denied by the a2a policy, labeled by route and reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_a2a_hops_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_a2a_hop"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["route", "spec", "decision"],
        description: "A2A hops observed by the proxy, labeled by route, spec, and policy decision.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_a2a_methods_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_a2a_method"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["route", "method"],
        description: "A2A 1.0 JSON-RPC methods observed by the proxy, labeled by route and method.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_registry_entries",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_registry_entries"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["collection"],
        description: "Agents the registry currently knows about, by collection: the verified catalog, or one of the registration queue's four states.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_registry_operations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_registry_op"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["op", "outcome"],
        description: "Agent registry and registration-queue operations by operation and outcome, including every refusal the queue's state machine and the feed verifier produce.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_acme_renewal_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_acme_renewal"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "ACME renewal full-flow duration, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_acme_renewals_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_acme_renewal"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "ACME certificate renewal attempts, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_action_abtest_variant_selected_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_abtest_variant_selected"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["origin", "variant"],
        description: "abtest action variant selections, by origin and configured variant name.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_action_https_proxy_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_https_proxy_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["origin", "decision"],
        description: "https_proxy action allow/deny decisions, by origin and decision.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_active_connections",
        kind: MetricKind::Gauge,
        writer: Writer::Field("active_connections"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &[],
        description: "Current active connections.",
        dead_reason: None,
    },
    // WOR-2578: the admin request-log export is the one route that
    // returns the operational log in bulk, so its rate and its volume
    // are what an operator alerts on for exfiltration.
    MetricCapability {
        name: "sbproxy_admin_request_export_rows_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_admin_request_export"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["format"],
        description: "Rows written by admin request-log exports, by format.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_admin_request_exports_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_admin_request_export"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["format"],
        description: "Admin request-log exports served, by format.",
        dead_reason: None,
    },
    // WOR-2661 / Group F3: the chargeback export is separately paged and
    // byte-admitted, so operators need a bounded counter for refused pages
    // and response budgets rather than inferring it from 4xx volume.
    MetricCapability {
        name: "sbproxy_admin_chargeback_export_refusals_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_admin_chargeback_export_refusal"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["format", "reason"],
        description: "Admin chargeback export refusals, by format and closed reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_budget_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["agent_id", "outcome"],
        description: "agent_budget policy verdicts, labeled by agent and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_detect_inference_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_agent_detect"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &[],
        description: "Agent-detect scorer inference latency in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_detect_score",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_agent_detect"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &[],
        description: "Agent-detect scorer output score, scaled 0-100.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_detect_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_agent_detect"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["agent_id", "provenance"],
        description: "Agent-detect scorer verdicts by agent id and provenance.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_reputation_score",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_agent_reputation_score"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant_id", "agent_class"],
        description: "Agent-class reputation in [0.0, 1.0] over the anomaly detector's rolling window; 1.0 is a class that has produced nothing.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_agent_skill_digest_mismatch_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("agent_skill_digest_mismatch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["skill"],
        description: "Agent Skills artifact digest mismatches detected at serve time.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_aggregate_compose_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_aggregate_compose_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Wall-clock time for one aggregation round, fetches included.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_aggregate_entries",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_aggregate_entries"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "origin_sources entries by the outcome of the last aggregation round.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_aggregate_published_revision",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_aggregate_published_revision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Config-authority revision the aggregator last published.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_aggregate_rounds_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_aggregate_round"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Aggregation rounds by what the round decided to do.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_admission_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_admission_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["surface", "reason", "outcome"],
        description: "Pre-provider AI gateway admission decisions: a request refused at the inbound native-format shim before any provider saw it, by inbound surface and bounded reason code.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_audio_seconds_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_audio_seconds_attributed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model", "surface", "project", "feature", "team", "agent_type", "environment", "tenant_id", "api_key_id"],
        description: "AI audio seconds consumed (realtime + audio surfaces), partitioned by attribution tag.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_budget_utilization_ratio",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_budget_utilization"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["scope"],
        description: "Budget utilization as a fraction of the limit; above 1 is over budget.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cache_results_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache_result"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["provider", "cache_type", "result"],
        description: "AI response cache results.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cascade_tier_outcomes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cascade_tier_outcome"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tier", "outcome"],
        // Comma-separated because this renders into a Markdown table
        // cell in `docs/metrics-stability.md`, where an unescaped pipe
        // opens a new column. WOR-2685 split the pre-dispatch
        // exclusions out of `retry`, which had been carrying five
        // meanings that were never retries.
        description: "Cascade routing tier outcomes (accepted, retry, cost_cap, \
                      credential_lock, data_posture, disabled, not_found, unhealthy).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "lever", "outcome", "backend"],
        description: "AI context compression lever duration in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_lever_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "lever", "outcome", "reason", "backend"],
        description: "AI context compression lever invocations by closed outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_ratio",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "lever"],
        description: "Final-to-initial SBproxy token-estimate ratio for applied AI context compression levers.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_redis_coordination_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_redis_compression_coordination"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["event"],
        description: "Redis compression coordination contention and rejected updates.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_request_levers_run",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "outcome", "backend"],
        description: "Number of context compression levers executed per request.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_request_tokens_saved",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "outcome", "backend"],
        description: "Initial-to-final reduction in SBproxy's model-aware token estimate once per compression request.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "outcome", "backend", "cache_bypass"],
        description: "Requests that executed a non-empty AI context compression pipeline.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_selection_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_selection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "source", "outcome"],
        description: "AI request compression policy resolutions by closed source and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_state_operation_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_compression_state_operation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend", "operation", "outcome"],
        description: "External AI compression state operation duration in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_state_operations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_state_operation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend", "operation", "outcome"],
        description: "External AI compression state operations by backend and closed outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_tokens_saved_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "lever"],
        description: "Reduction in SBproxy's model-aware token estimate from applied AI context compression levers.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_tokens_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_run"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "api_key_id", "lever", "direction"],
        description: "SBproxy model-aware token estimates before and after an applied AI context compression lever.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_value_cost_saved_micros_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_value"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[
            "tenant_id",
            "origin",
            "model",
            "lever",
            "token_count_precision",
        ],
        description: "Gross known-price target-model input cost avoided by successful AI context compression, in micro-USD.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_compression_value_tokens_saved_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_value"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[
            "tenant_id",
            "origin",
            "model",
            "lever",
            "token_count_precision",
        ],
        description: "Estimated target-model input tokens avoided by successful AI context compression.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_chargeback_entries_evicted_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_chargeback_entry_evicted"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin"],
        description: "Raw chargeback entries evicted from bounded in-memory retention, by owning origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_chargeback_rollups_collapsed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_chargeback_rollup_collapsed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["dimension", "origin"],
        description: "Chargeback events folded into a bounded overflow rollup by workspace or team dimension, by owning origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_chargeback_refusals_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_chargeback_refusal"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason", "origin"],
        description: "Chargeback rows refused before exact accounting could commit, by closed reason and owning origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_chargeback_incomplete_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_chargeback_incomplete"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason", "origin"],
        description: "Chargeback incompleteness causes observed on the live record and retention path, by owning origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_context_poisoning_findings_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_context_poisoning_finding"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["rule_id", "action"],
        description: "Context-poisoning guardrail findings.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_context_poisoning_blocked_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_context_poisoning_blocked"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Requests blocked by the context-poisoning guardrail (a finding whose configured action is deny).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cost_dollars_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_request_attributed"),
        support: SupportLevel::Stable,
        // Promoted out of beta. Nobody builds a chargeback report on a
        // series that can be renamed in the next minor, and this is the
        // series a chargeback report is built on: two alert rules and two
        // recording rules already sum it by `tenant_id` and by
        // `api_key_id`. The frozen shape is pinned by
        // STABLE_NAME_CONTRACT in the drift guard.
        compat: CompatTier::Stable,
        registry: Registry::Default,
        // `agent_id` is appended last: this list is positional, so the
        // only safe place for a new label is the end. It is the
        // agent-as-unit dimension, sanitized against the 200-value
        // budget in `crate::cardinality`, never a run or task id.
        labels: &["origin", "provider", "model", "surface", "project", "feature", "team", "agent_type", "environment", "tenant_id", "api_key_id", "agent_id"],
        description: "AI cost in USD, partitioned by attribution tag.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cost_saved_micros_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache_savings"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant", "origin", "model"],
        description: "Micro-USD avoided by a semantic-cache hit.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cost_usd_micros_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_cost_usd_micros"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["provider", "model", "tenant_id"],
        description: "Derived AI request cost in micro-USD.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_data_posture_filter_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_data_posture_filter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["constraint", "outcome", "tenant"],
        description: "AI requests whose provider candidate set the data-posture constraint narrowed (outcome filtered) or refused outright (outcome refused), by resolved tenant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_failovers_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_failover"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["from_provider", "to_provider", "reason"],
        description: "Provider failover events.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_gateway_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_gateway_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["decision", "reason"],
        description: "AI gateway admission decisions, including pre-provider rejections.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_guardrail_blocks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_guardrail_block"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["category"],
        description: "Guardrail block events.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_parallel_moderation_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_parallel_moderation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Inspect-only input hooks that ran alongside the upstream call, by allow, block, cancelled_upstream, or refused.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_safety_guardrail_verdicts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_safety_guardrail_verdict"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["guardrail", "class", "backend", "verdict"],
        description: "Built-in safety guardrail evaluations by class, backend, and verdict.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_external_guardrail_verdicts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_external_guardrail_verdict"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "phase", "outcome"],
        description: "External guardrail evaluations by provider, phase, and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_inter_token_latency_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_inter_token_latency"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model"],
        description: "AI streaming average inter-token latency (TPOT).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_intent_detection_source_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_intent_detection_source"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["source"],
        description: "Intent-detection dispatches by healthy classifier hook, unconfigured heuristic, or degraded heuristic fallback.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_quality_routing_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_quality_routing_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Quality-hook routing decisions by selected or fallback outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_toolkit_operations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_toolkit_operation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["capability", "outcome"],
        description: "AI toolkit operations by capability (workflow, evaluation, prompt_rollout) and terminal outcome (success, invalid, unauthorized, not_found, egress_refused, timeout, body_too_large, response_too_large, busy, agent_failed, internal).",
        dead_reason: None,
    },
    // Rich classifier sidecar metrics. These use the Prometheus default
    // registry inside the standalone `sbproxy-classifier` process, and the
    // writer symbols below live in that binary crate. Keeping them in this
    // workspace-wide capability table lets dashboard drift checks validate
    // the sidecar dashboard just like the main proxy dashboards.
    MetricCapability {
        name: "sbproxy_classifier_admission_queue",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("adjust_admission_queue"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["cmd"],
        description: "Rich-sidecar requests currently waiting for a bounded inference slot, by command.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_admission_refusals_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_admission_refusal"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["cmd", "reason"],
        description: "Rich-sidecar requests refused by bounded admission, by command and closed reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_attempts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_attempt"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transport", "cmd"],
        description: "Rich classifier sidecar request attempts observed at a typed transport boundary.",
        dead_reason: None,
    },
    // Written by `sbproxy-classifier-client`, inside the proxy process, not
    // by the sidecar. It is the one family that answers "are we running on
    // the in-process fallback right now", which no sidecar-side metric can:
    // an unreachable sidecar emits nothing at all.
    MetricCapability {
        name: "sbproxy_classifier_client_fallback_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("note_degrade"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Classifier calls served by the in-process fallback because the configured sidecar did not answer, by closed reason (connect, timeout, rpc, protocol, invalid_request, empty_response).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_completions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_completion"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transport", "cmd"],
        description: "Rich classifier sidecar requests whose successful response reached the transport completion boundary.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transport", "cmd", "reason"],
        description: "Rich classifier sidecar requests that could not complete, by transport, command, and bounded reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_quality_score",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_quality_score"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transport"],
        description: "Heuristic quality scores returned by the rich classifier sidecar, by transport.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_request"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transport", "cmd"],
        description: "Successful rich classifier sidecar requests, by transport and command; an error rate needs `sbproxy_classifier_attempts_total` as its denominator, not this.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_safety_verdicts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_safety_verdict"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["verdict"],
        description: "Per-token streaming safety verdicts emitted by the rich classifier sidecar (`safe`, `blocked`, or `unsafe_continued`).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_startup_owner_info",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_release_startup_owner"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["entrypoint", "owner"],
        description: "Release entrypoint ownership of the prepared rich-classifier runtime capability.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_terminal_outcomes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_terminal_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["transport", "cmd", "stage", "reason"],
        description: "Rich classifier sidecar requests finalized unsuccessfully, by typed transport, command, stage, and bounded reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_classifier_tenants",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_tenant_count"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Tenants currently registered with the rich classifier sidecar.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_key_fallbacks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_key_fallback"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "outcome"],
        description: "AI provider-key fallback decisions, by the provider entry whose own key was refused and the outcome (`engaged` when the operator's `fallback_credential_id` resolved and the retry was queued, `unavailable` when it did not and the provider's rejection stands). `unavailable` is the alertable one: it means the house credential is broken and the only other evidence is a `401` that reads like the tenant's fault.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_lb_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_lb_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["strategy", "provider"],
        description: "AI router provider selections by strategy.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_license_leak_findings_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_license_leak_finding"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["mode", "method"],
        description: "License-leak guardrail confident matches, by the disposition applied (`block`, `redact`, `warn`, `log`) and the detector that fired (`substring`, `heuristic`, `shingle`). Counts every confident match, including the `warn` and `log` dispositions that never reach `sbproxy_ai_guardrail_blocks_total`, so an operator can watch calibration volume on a route before promoting it from `warn` to `block`. Both labels are closed enums, so cardinality is bounded whatever the model returns.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_model_group_selections_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_group_selection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["group", "provider"],
        description: "Named model group member selections: which group a request addressed and which provider's deployment served it. Both labels are operator-declared config names.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_prefix_affinity_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_prefix_affinity_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Prefix-affinity selections by cache-location outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_prefix_affinity_evictions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_prefix_affinity_eviction"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Entries evicted from the bounded prefix-affinity table.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cache_affinity_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache_affinity_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Caller-keyed prompt-cache affinity selections by lease outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_cache_affinity_evictions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache_affinity_eviction"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Leases removed from the bounded prompt-cache affinity table.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_service_tier_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_service_tier_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["disposition"],
        description: "Upstream attempts whose service tier the operator's provider entry decided.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_quota_pool_fail_open_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_quota_pool_fail_open"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["pool"],
        description: "Quota-pool admissions allowed while the shared backend was unavailable.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_quota_pool_overshare_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_quota_pool_overshare"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["pool"],
        description: "Soft quota-pool admissions beyond a member entitlement.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_routing_fallbacks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_routing_fallback"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["strategy", "reason"],
        description: "AI routing selections that used an explicit fallback path.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_routing_policy_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_routing_policy_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome", "reason_code"],
        description: "Operator AI routing-policy decisions by outcome and reason code.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_model_directory_exclusions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_directory_exclusion"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["exclusion_reason"],
        description: "Directory nodes excluded from model routing, by exclusion reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_multipart_inspection_skipped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_multipart_inspection_skipped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["check", "surface"],
        description: "Request-body inspection skipped because the AI request body was multipart, by inspection kind and classified surface.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_native_bypass_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_native_bypass"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["inbound_format", "provider_format"],
        description: "AI requests that bypassed the hub format round-trip when client format matched provider format.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_output_throughput_tokens_per_second",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_output_throughput"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model"],
        description: "AI streaming output throughput (completion tokens / generation duration).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_price_ceiling_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_price_ceiling"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Per-request price-ceiling guard outcomes: `candidate_excluded` (a routing candidate priced over the ceiling and dropped), `refused` (every candidate over it, so the request answered 402), `invalid_header` (an unusable `x-sbproxy-max-price`), and `unsupported_surface` (a header ceiling on a surface the estimate cannot price).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_price_source_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_price_source"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["source"],
        description: "Cost estimates by the price-table layer that produced the price.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_provider_attempts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_provider_attempt"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "outcome"],
        description: "AI provider attempts during failover/selection, by provider and outcome (`success`, `error`, `client_disconnected`, `moderation_cancelled`).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_provider_cooldowns_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_provider_cooldown"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "cause"],
        description: "Providers parked out of rotation by `resilience.cooldown_policy`, by the classified failure that parked them. The circuit breaker's counterpart for the cooldown axis; without it a rotated credential parks the whole pool on a log line nobody can alert on.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_provider_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_provider_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["provider", "error_kind"],
        description: "Per-provider AI error events.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_rag_context_bytes",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_rag_context_bytes"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Bytes of rendered RAG context injected into the request body.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_rag_latency_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_rag_latency"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["stage", "provider"],
        description: "RAG retrieval latency in seconds, by stage (embedding, search, total) and provider.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_rag_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_rag_request"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["embedding", "vector_store", "outcome"],
        description: "AI requests that ran RAG retrieval, by embedding provider, vector store, and closed outcome (retrieved, no_match, stale, continued, error).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_ratelimit_rejected_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ratelimit_rejected"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["axis", "key_hash", "tenant", "model"],
        description: "AI gateway rate-limit rejections, partitioned by axis.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_reasoning_policy_attempts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_reasoning_policy_attempt"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "outcome"],
        description: "AI provider attempts by concise-reasoning policy outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_realtime_audio_seconds_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["provider", "direction"],
        description: "Cumulative audio seconds forwarded over Realtime sessions.",
        dead_reason: Some(
            "nothing calls it outside crates/sbproxy-ai/src/ai_metrics.rs's own tests. The \
             family and its recorder (record_realtime_audio_seconds) are both declared in \
             ai_metrics.rs, which sits outside this lane's file allowlist (metrics.rs, \
             metric_registry.rs, tests only), so this entry can only be confirmed here, not \
             wired or deleted. The natural call site is the frame-relay loop in \
             crates/sbproxy-ai/src/realtime.rs; check first whether \
             sbproxy_ai_audio_seconds_attributed_total (already Stable, richer attribution \
             labels) already covers the same forwarded-audio signal from that same loop, in \
             which case this one should be deleted as a duplicate rather than wired",
        ),
    },
    MetricCapability {
        name: "sbproxy_ai_realtime_frames_forwarded_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["provider", "direction", "kind"],
        description: "Cumulative frames forwarded over Realtime sessions.",
        dead_reason: Some(
            "nothing calls it outside crates/sbproxy-ai/src/ai_metrics.rs's own tests. Same \
             out-of-allowlist situation as sbproxy_ai_realtime_audio_seconds_total above: the \
             family, recorder (record_realtime_frame), and natural call site (the frame-relay \
             loop in crates/sbproxy-ai/src/realtime.rs) all live in crates outside metrics.rs \
             and metric_registry.rs. Wire or delete there under WOR-1898",
        ),
    },
    MetricCapability {
        name: "sbproxy_ai_realtime_session_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_realtime_session_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["provider", "close_reason"],
        description: "Wall-clock duration of a Realtime WebSocket session, recorded on close.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_realtime_sessions_active",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("dec_realtime_sessions_active"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &[],
        description: "Currently open OpenAI Realtime API WebSocket sessions.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_replica_selection_excluded_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_replica_selection_excluded"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["stage"],
        description: "Managed-replica candidates excluded before rendezvous ranking, by stage.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_request_duration_attributed_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_model_latency"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model", "surface", "tenant_id", "api_key_id"],
        description: "AI upstream request latency, partitioned by surface + tenant + credential.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_request_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_model_latency"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model"],
        description: "AI request latency.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_request_timeout_override_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_request_timeout_override"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Per-request `x-sbproxy-timeout-ms` outcomes: `applied` (honored, replacing the provider's `timeout_ms`), `ignored_override_disabled` (the origin has not opted in, so the header was dropped), `over_ceiling` (above `max_request_timeout_ms`, refused with 400 rather than clamped), `invalid_header` (not a positive integer, refused with 400).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_requests_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_outcome_attributed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin", "provider", "model", "surface", "tenant_id", "api_key_id", "outcome"],
        description: "AI requests partitioned by attribution + outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_reversible_redaction_miss_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_reversible_redaction_miss"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["rule"],
        description: "Reversible PII placeholders that appeared in the upstream response but did not match a request-side capture entry.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_semantic_cache_similarity",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_semantic_similarity"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider"],
        description: "Cosine similarity of semantic-cache hits.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_semantic_route_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_semantic_route_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Semantic-route selections by decision outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_semantic_route_similarity",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_semantic_route_similarity"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider"],
        description: "Best exemplar cosine similarity of scored semantic-route requests.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_shadow_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_shadow_dropped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Configured shadow requests skipped or dropped before dispatch, by closed reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_shadow_calls_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_shadow_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target", "status_class", "finish_reason"],
        description: "Completed shadow evaluation calls by target, status class, and finish reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_shadow_latency_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_shadow_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target"],
        description: "Shadow evaluation call latency by target, in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_shadow_inflight",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("dec_shadow_inflight"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Currently in-flight shadow request tasks supervised by the AI client.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_shadow_timeout_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_shadow_timeout"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Shadow tasks canceled after their wall-clock supervisor timeout.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_stream_guardrail_skipped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_stream_guardrail_skipped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["guardrail"],
        description: "Output guardrails skipped on streaming responses via stream_policy: off.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_stream_guardrail_violations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_stream_guardrail_violation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["guardrail"],
        description: "Streaming output guardrail violations, by guardrail type.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_stream_guardrail_decode_fallback_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_stream_guardrail_decode_fallback"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Streaming chunks where guardrails fell back to raw-frame matching because delta decoding failed.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_stream_tool_frames_discarded_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_stream_tool_frames_discarded"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["cause"],
        description: "Tool-call frames an enforcing `ai_tool_call` hook or an agent-alignment guard held back that never reached the client, by cause: `blocked` (a guardrail or extension ended the stream, which drops held frames by design) and `unjudged` (the stream ended with a held call the guard session never returned a verdict for). `unjudged` should be zero; a non-zero rate means a client received an assistant turn whose tool call the gateway silently deleted.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_stream_post_commit_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_stream_post_commit_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["provider", "cause"],
        description: "Streaming responses that failed after the gateway committed to a provider, by cause: `upstream_timeout` (a transport budget cut a running generation), `upstream_error` (a reset or truncated provider stream), `guardrail` (the gateway ended the stream on an output guardrail or stream-safety verdict), `client_disconnected` (the caller hung up and the relay's next write to it failed), `gateway_error` (the relay's own failure, correlating with no provider error), `abandoned` (the request was dropped before the relay reached an ending of its own). An upstream read failure takes precedence over the other causes. Failover is impossible past the commit point, so these are the failures `sbproxy_ai_failovers_total` can never carry.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_surface_request_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_surface_latency"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["surface", "method"],
        description: "AI request latency partitioned by classified surface.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_surface_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_surface_request"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["surface", "method"],
        description: "AI gateway requests partitioned by classified surface.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_token_estimate_error_ratio",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_token_estimate_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["model"],
        description: "Relative error of pre-request token estimate vs upstream usage.prompt_tokens.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_tokens_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_request_attributed"),
        support: SupportLevel::Stable,
        // Promoted with the cost counter it shares a writer with. The two
        // are divided against each other to get a per-attribution unit
        // cost, so promoting one and leaving the other renameable would
        // pin half of an expression. See STABLE_NAME_CONTRACT.
        compat: CompatTier::Stable,
        registry: Registry::Default,
        // See `sbproxy_ai_cost_dollars_attributed_total`: `agent_id`
        // is appended last because the list is positional, and it
        // pairs with the same label on the cost counter so one PromQL
        // sum answers "which agent spent this".
        labels: &["origin", "provider", "model", "surface", "direction", "project", "feature", "team", "agent_type", "environment", "tenant_id", "api_key_id", "agent_id"],
        description: "AI tokens consumed, partitioned by attribution tag.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_tokens_saved_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache_savings"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant", "origin", "model", "kind"],
        description: "Tokens avoided by a semantic-cache hit.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_translation_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_translation_dropped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["surface", "field"],
        description: "Request fields dropped while translating an inbound AI body (Anthropic Messages, OpenAI Responses) to the canonical chat shape, by inbound surface and dropped-field class.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_ttft_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_ttft"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Default,
        labels: &["provider", "model"],
        description: "AI streaming time to first token.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_usage_parse_miss_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_usage_parse_miss"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "surface", "usage_source"],
        description: "2xx AI responses on a token surface that carried no parseable usage block, by what was billed instead: `estimated` (the gateway's own tokenizer count of the delivered text) or `absent` (nothing could be counted, so nothing was billed).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_wasted_cost_dollars_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_waste"),
        support: SupportLevel::Stable,
        // Deliberately left beta when the two attributed-spend counters
        // were promoted. Three things say the shape is not settled. No
        // dashboard, alert, or recording rule reads either wasted family,
        // so nothing has ever exercised it. `docs/observability.md`
        // publishes a `kind` vocabulary
        // (canceled/retried/cached/guardrail_blocked/other) that shares
        // not one value with what `WasteKind` actually emits. And these
        // are the only attributed families carrying neither `tenant_id`
        // nor `api_key_id`, which is why they are absent from
        // TENANT_SCOPED_METRICS below. Fix those, then promote.
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "provider", "model", "surface", "project", "feature", "team", "agent_type", "environment"],
        description: "Estimated USD cost of AI spend classified as wasted.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_wasted_tokens_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_waste"),
        support: SupportLevel::Stable,
        // Left beta for the reasons on its cost sibling above.
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "provider", "model", "surface", "project", "feature", "team", "agent_type", "environment"],
        description: "AI tokens classified as wasted, by waste class.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_anomaly_detected_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_anomaly_detected"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["kind", "severity"],
        description: "Behavioral anomalies flagged by a registered detector hook, by kind and severity.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_anomaly_key_budget_spent_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_anomaly_key_budget_spent"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "Requests that arrived for an agent class the anomaly detector had no tracking slot for. Non-zero means windows are being displaced, which churns the baseline a `reputation.deny_below` floor reads; a key with no window has no score, and no score is admitted.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_anomaly_tracked_keys",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_anomaly_tracked_keys"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "(tenant, agent class) pairs the anomaly detector currently holds a 28-day window for. The detector's resident set is this times the per-key window, so it is the figure to size the process against; the cap is 512.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_audit_chain_read_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_audit_chain_read"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["channel", "outcome"],
        description: "Audit-chain read attempts, by verification outcome (verified, broken, unreadable, denied).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_audit_emit_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_audit_emit_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["channel", "outcome"],
        description: "Wall-clock latency of one audit-channel emission.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_audit_write_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_audit_write_outcome"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["channel"],
        description: "Audit emissions that did not reach a sink they were promised, by audit channel; healthy systems read 0.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_auth_results_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_auth"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin", "auth_type", "result"],
        description: "Auth check results.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_boilerplate_stripped_bytes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_boilerplate_stripped_bytes"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["hostname"],
        description: "Bytes removed by the boilerplate transform, by hostname.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_bot_auth_directory_fetch_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_bot_auth_directory_fetch_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["url"],
        description: "Bot-auth hosted key-directory fetches that failed (the verifier serves stale or fails per nonce_policy).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_bot_auth_nonce_replay_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_bot_auth_nonce_replay"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["policy"],
        description: "Web Bot Auth signatures rejected (or logged) because the nonce was already observed.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_break_glass_grants_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_break_glass"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["event"],
        description: "Break-glass grant transitions, by event (requested, approved, activated, denied, used, expired, reviewed, reviewed_without_roster, refused).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_break_glass_open",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_break_glass_open"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["state"],
        description: "Break-glass grants currently open, by state (pending_approval, active, awaiting_review).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_budget_share_fail_open_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_budget_share_fail_open"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["op"],
        description: "Shared budget store operations that failed and fell open to per-instance enforcement, by operation: `read`, `write`, or `mirror_dropped` (a streamed settlement handed its mirror write to a detached task that never ran, which a shutting-down runtime does).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_budget_share_unavailable",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_budget_share_unavailable"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "1 while shared budget enforcement is degraded to per-instance tracking, 0 when the shared store answered.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_bytes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_request_with_labels"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin", "direction"],
        description: "Bytes transferred.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_degraded",
        kind: MetricKind::Gauge,
        writer: Writer::Field("cache_reserve_degraded"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["backend"],
        description: "Whether the configured Cache Reserve backend is degraded. `backend` is the provider (`memory`, `filesystem`, `redis`, `s3`, `gcs`, `azure`, `local`, or `object_store` for a provider this build does not name), not the client library in front of it.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache_reserve_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "operation"],
        description: "Cache Reserve operations the backend refused, by operation (`put`, `get`, `delete`, `sweep`, `init`); the reserve is best-effort, so this is the only signal a failing cold tier gives. `init` under origin `__init__` means the backend never built, which every other reserve family reports as flat zero.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_evictions_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("cache_reserve_evictions"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin"],
        description: "Cache Reserve explicit deletions.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_health_transitions_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("cache_reserve_health_transitions"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["backend", "state", "reason"],
        description: "Cache Reserve backend health transitions by bounded reason. `backend` carries the same closed provider vocabulary as `sbproxy_cache_reserve_degraded`.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_hits_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("cache_reserve_hits"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin"],
        description: "Cache Reserve hits served after a hot-cache miss.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_misses_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("cache_reserve_misses"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin"],
        description: "Cache Reserve misses (hot + reserve both empty).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_reserve_writes_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("cache_reserve_writes"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin"],
        description: "Cache Reserve writes (admitted entries).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cache_results_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cache"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "result"],
        description: "HTTP response cache outcomes (hit or miss), by origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_capture_budget_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_capture_budget_drop"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["workspace", "dimension"],
        description: "Capture envelope dimensions dropped because the per-workspace budget was exhausted.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_capture_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_capture_drop"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["workspace", "dimension", "reason"],
        description: "Capture envelope dimensions dropped during capture, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cert_expiry_seconds",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_cert_expiry"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Seconds until the active certificate for the host expires; negative when expired.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cert_store_degraded",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_cert_store_degraded"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend"],
        description: "1 when the configured certificate store could not be opened and an in-memory fallback is in use, 0 when the configured backend opened.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_circuit_breaker_transitions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_circuit_breaker"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "from_state", "to_state"],
        description: "Circuit breaker state transitions, by origin and from/to state.",
        dead_reason: None,
    },
    // Found by the drift guard, not by the audit that preceded it: the gauge is
    // set by `ClockSkewMonitor::record_skew`, which is only reachable through
    // `ClockSkewMonitor::run`, and the monitor is never constructed outside its
    // own tests. Two live-looking hops to a type nothing instantiates.
    MetricCapability {
        name: "sbproxy_clock_skew_seconds",
        kind: MetricKind::Gauge,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Proxy,
        labels: &[],
        description: "Local clock offset from the SNTP reference, in seconds.",
        dead_reason: Some(
            "ClockSkewMonitor is never constructed in production, so nothing runs the \
             SNTP probe that sets the gauge; wire or delete under WOR-1898. The monitor, \
             probe, and /readyz Probe impl are fully built in \
             crates/sbproxy-observe/src/clock_skew.rs; what is missing is a \
             `ClockSkewMonitor::new(..)` + `tokio::spawn(monitor.clone().run())` call during \
             server startup, which belongs in the sbproxy binary crate (out of this lane's \
             file allowlist), not in sbproxy-observe. Read the size of that call before \
             reaching for it: it is three lines and a behavior change. ClockSkewConfig \
             defaults to polling pool.ntp.org over UDP every 60s, and registering the Probe \
             makes /readyz report 503 until the first exchange lands, so an unconditional \
             spawn turns egress-restricted and air-gapped deployments (the ones \
             docs/getting-started-sovereign-multicloud.md sells) into hosts that never \
             become ready. Wiring this owes a config gate that defaults off, a \
             config-stability entry, and the docs to go with it, which is why it is a \
             ticket and not a metrics cleanup",
        ),
    },
    MetricCapability {
        name: "sbproxy_comp_marketplace_manifest_serves_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("MANIFEST_SERVES_TOTAL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "IAB CoMP marketplace manifest serves, by outcome. Written by `sbproxy_licensing::comp::serve`, which the proxy request path calls for an origin with a `comp:` block and the crate's own axum router calls for a standalone host; empty on a deployment with neither.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_comp_marketplace_quote_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("QUOTE_REQUESTS_TOTAL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "IAB CoMP marketplace quote outcomes, including the oversize-body refusal. Written by `sbproxy_licensing::comp::serve`, which the proxy request path calls for an origin with a `comp:` block and the crate's own axum router calls for a standalone host; empty on a deployment with neither.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_comp_marketplace_redeem_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("REDEEM_REQUESTS_TOTAL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "IAB CoMP marketplace redeem outcomes, including the oversize-body refusal. Written by `sbproxy_licensing::comp::serve`, which the proxy request path calls for an origin with a `comp:` block and the crate's own axum router calls for a standalone host; empty on a deployment with neither.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_compression_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_compression_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["codec", "result"],
        description: "Compression middleware decisions, by codec and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_compression_ratio",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_compression_ratio"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["codec"],
        description: "Achieved compression ratio (post_size / pre_size) when compression was applied.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_authority_announce_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_authority_announce"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description:
            "Config revision announcements published to the cluster, by result.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_bundle_age_seconds",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_bundle_age_seconds"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Seconds since this node received the config bundle it currently serves.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_bundle_applied_degraded_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_bundle_applied_degraded"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description:
            "Config bundles applied while at least one subsystem stayed on prior state.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_bundle_applied_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_bundle_applied"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Config bundles applied with every subsystem reloaded cleanly.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_bundle_fetch_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_bundle_fetch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "Config bundle fetch cycles, by result.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_bundle_gossip_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_bundle_gossip"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Cluster config-revision announcement probes, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_bundle_revision",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_bundle_revision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Authority revision of the config bundle this node currently serves.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_history_entries",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_history_entries"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Entries currently held in the config revision ring.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_lkg_revision",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_lkg_revision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Config ring revision the last-known-good pointer names, or -1 when it names none.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_soak_verdict_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_soak_verdict"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["verdict", "signal"],
        description: "Config soak outcomes, by verdict and reporting signal.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_apply_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_apply"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Config rollback attempts, by outcome: applied for an operator rollback, \
                      reverted for an automatic one after a failed soak, declined for an \
                      armed node that decided not to revert, rejected for a refusal.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_rejected_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_rejection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Config candidates refused before applying, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_fallback_active",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_fallback_active"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "1 while this node serves a config its boot fallback restored from the revision ring.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_reload_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_reload"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "Config reload attempts, by result.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_revision_info",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_revision_info"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["revision", "digest", "provenance"],
        description: "Current entry in the config revision ring; always 1, the revision/digest/provenance are the labels.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_source_fetch_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_config_source_fetch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "result"],
        description: "Config source resolutions, by source kind and result.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_config_source_revision_info",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_config_source_revision_info"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["sha"],
        description: "Commit the config source resolved to; always 1, the commit is the label.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_cors_refusals_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_cors_refusal"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Responses the CORS middleware refused to add headers to, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_credential_read_audit_records_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_credential_read_audit"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Read-audit detail records for credential resolution, by outcome (emitted, suppressed, failed).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_credential_read_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_credential_read"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Credential resolutions counted for the read audit, by outcome (ok, refused, error). Unconditional; the chained detail record is rate limited.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_credential_resolution_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_credential_resolution"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["cache", "outcome"],
        description: "Wall-clock latency of one bound-credential resolution, by which cache layer answered and the real outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_egress_refused_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_egress_refused"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["purpose", "reason", "tenant", "origin"],
        description: "Outbound dials refused by purpose-scoped egress authorization, by purpose, closed reason, tenant, and origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_embedded_store_operations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_kv_op"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["store", "op", "outcome"],
        description: "Embedded key-value store operations, by store, operation, and outcome (ok, error, or a bounded ephemeral store refusing a write at its cap).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_event_ingest_events_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ingest"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["target", "outcome"],
        description: "Request events handed to an optional ingest sink (NATS or ClickHouse), by target and outcome: published, dropped at a full queue, errored, or reconnected.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("errors_total"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["hostname", "error_type"],
        description: "Total errors.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_events_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_events_dropped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["sink", "reason"],
        description: "Proxy events the events: egress did not deliver, by sink (file or webhook) and closed reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_evidence_seq_tenant_cap_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_evidence_seq_tenant_cap"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Evidence sequence lookups for a tenant past the tracked-tenant cap, sharing the overflow counter.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ext_authz_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ext_authz_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["outcome"],
        description: "External-authorization callout outcomes; `fail_open` counts requests admitted without a decision.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_fallback_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_fallback_served"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["trigger", "origin", "tenant"],
        description: "fallback_origin responses served, by trigger (`status` when the primary answered with a status listed under `on_status`, `error` when it failed outright and `on_error` caught it), origin, and tenant. A fallback is a degraded response by construction, so its rate is the first number worth alerting on when a primary starts failing; before this the only evidence was a boolean on an access-log row.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_federation_entity_statement_verifications_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_entity_statement_verification"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "OpenID Federation entity-statement JWS verification outcomes, covering both self-signed entity configurations and subordinate statements. Written only when proxy.federation.peer_trust is configured; a deployment that publishes its own statement and verifies nobody leaves this empty.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_federation_peer_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_peer_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "OpenID Federation peer-trust admission decisions on the proxy request path: trusted when the caller's named entity chained to a pinned anchor and satisfied every required trust mark, refused otherwise. Empty until proxy.federation.peer_trust is configured.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_federation_trust_chain_resolutions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_trust_chain_resolution"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "OpenID Federation trust-chain resolution outcomes, one per resolver call. Written only when proxy.federation.peer_trust is configured; empty on a deployment that publishes its own statement and verifies nobody.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_federation_trust_mark_verifications_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_trust_mark_verification"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "OpenID Federation trust-mark JWS verification outcomes. Offline signature check only; live revocation status is a separate call this crate does not make. Written only when proxy.federation.peer_trust.required_trust_marks names one; empty otherwise.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_federation_well_known_cache_remaining_seconds",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("WELL_KNOWN_CACHE_REMAINING_SECONDS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Remaining lifetime of the entity configuration most recently served from cache, in seconds, sampled on every successful serve. Pinned near zero means the refresh margin is too close to the lifetime for the request rate.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_federation_well_known_serves_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_well_known_serve"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "GET /.well-known/openid-federation outcomes.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_gateway_reconcile_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_reconcile"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Gateway API reconcile latency in seconds, by the Kubernetes \
             resource kind that triggered the pass. Answers whether a reconcile is \
             outrunning the resync interval.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_gateway_reconcile_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_reconcile"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "result"],
        description: "Gateway API reconcile attempts, by triggering resource kind and \
             outcome. `kind` is one of GatewayClass, Gateway, HTTPRoute, GRPCRoute, or \
             periodic, so cardinality is bounded by a closed set.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_gateway_status_writes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_status_write"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "result"],
        description: "Patches to the `/status` subresource, by resource kind and \
             outcome. A rising error count here is usually RBAC missing the status \
             subresource rather than anything wrong with the reconcile.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_gateway_watch_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_watch_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Watch stream errors, by Kubernetes resource kind. Distinct from a \
             reconcile error: these come from the API server connection itself, so a \
             rising count against a flat reconcile count means the controller has gone \
             blind rather than broken.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_geoip_lookup_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_lookup"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "geoip policy lookups, by outcome (hit, miss, no_database, \
             no_client_ip).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_governance_fail_open_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_governance_fail_open"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["key_id"],
        description: "Governed admissions that bypassed reservation because the governance backend was unavailable and failure_mode is allow_unreserved.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_grpc_status_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_grpc_status"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["code"],
        description: "Observed gRPC status codes, by canonical name.",
        dead_reason: None,
    },
    // Composed at runtime as `sbproxy_{lane}_channel_dropped_total`, so the
    // declaration scan cannot see it: there is no name literal to find. Only
    // the `hooks` lane is instantiated. It is registered on the proxy
    // registry alone; registering it on both was what emitted a duplicate
    // family and broke `/metrics` under precisely the backpressure that
    // creates it.
    MetricCapability {
        name: "sbproxy_hooks_channel_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_channel_drop"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["reason"],
        description: "Bounded channel sends dropped on the hot path, labeled by drop reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_http_framing_blocks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_http_framing_block"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason", "tenant"],
        description: "Requests rejected by the http_framing policy (request smuggling defense).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_idempotency_cache_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_idempotency_cache_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend"],
        description: "Idempotency cache lookup duration, by backend.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_idempotency_cache_results_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_idempotency_cache_result"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend", "result"],
        description: "Idempotency cache outcomes, by backend and result.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_inbound_key_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_inbound_key_request"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["provider", "key_mode", "tenant_id", "api_key_id"],
        description: "Requests partitioned by caller credential mode and recognized provider.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_inference_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_inference"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["kind", "backend", "model"],
        description: "Local inference latency in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_inference_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_inference"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["kind", "backend", "model", "result"],
        description: "Local inference call counts.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_judge_budget_exhausted_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_budget_exhausted"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant"],
        description: "Judge calls denied because the per-tenant budget was empty.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_judge_calls_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_judge_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "verdict", "cached"],
        description: "Judge backend invocations.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_judge_cost_usd",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_judge_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider"],
        description: "Judge backend cost per decision in USD.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_judge_latency_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_judge_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "cached"],
        description: "Judge backend round-trip latency.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_jwks_unknown_kid_refetch_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_jwks_unknown_kid_refetch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "JWKS refreshes triggered by tokens whose kid was absent from the local cache.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_cache_invalidation_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_key_cache_invalidation_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["scope"],
        description: "Keystore cache-tier invalidations that did not reach the shared tier or its peers, by scope (key or all).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_lookup_cache_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_key_lookup_cache"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "outcome"],
        description: "Keystore TTL-cache lookups, by record kind and which layer answered (hit, negative_hit, tier_hit, miss, error).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_operations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_key_operation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["operation", "outcome"],
        description: "Admin key-lifecycle operations, by operation and by what the handler actually returned (ok, refused, error).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_policy_stored_rejections_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_key_policy_stored_rejection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Stored key records rejected while lowering to an effective policy, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_rotation_age_days",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_rotation_age_days"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Days since the oldest record of this kind was minted or rotated, by kind (key, credential).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_store_outage_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_key_store_outage"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["entrypoint", "posture", "outcome"],
        description: "Inbound-key resolutions that could not reach the virtual key store, by entrypoint, configured failure posture, and what the posture decided.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_key_store_unavailable",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_key_store_unavailable"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["posture"],
        description: "1 while the last inbound-key resolution could not reach the virtual key store; the posture label is what that costs.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_kya_verdicts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_kya_verdict"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["verdict"],
        description: "Know Your Agent token verification verdicts; the issuer is deliberately not a label.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_label_cardinality_budget",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("refresh_cardinality_gauges"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["label"],
        description: "Cap the accepted unique values for a label name are counted against. Denominator for sbproxy_label_cardinality_unique_values.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_label_cardinality_overflow_per_tenant_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("counter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["metric", "label", "tenant_id"],
        description: "Per-tenant overflow demotions (`sbproxy_label_cardinality_overflow_total` with the tenant_id label).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_label_cardinality_overflow_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("counter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["metric", "label"],
        description: "Number of label values demoted to __other__ because the per-label budget was exhausted.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_label_cardinality_unique_values",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("refresh_cardinality_gauges"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["label"],
        description: "Unique values a label name has accepted so far. Divided by sbproxy_label_cardinality_budget it gives how close the label is to collapsing new values into __other__, which is a warning the overflow counter can only give after the fact.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_lb_zone_locality_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_zone_locality"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin", "verdict"],
        description: "Load-balancer selections the zone-locality stage shaped, by verdict: local (narrowed to the proxy's own zone) or spilled (no same-zone target was healthy, so selection widened across zones). rate(...{verdict=\"spilled\"}[5m]) > 0 is a cross-zone spill in progress, which the debug log and the admin ring cannot report on a release binary with the admin server off.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ledger_redeem_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_ledger_redeem_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["host", "outcome"],
        description: "Wall-clock latency of a single ledger token redemption.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_managed_replica_attempts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_managed_replica_attempt"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "deployment", "route_class", "outcome"],
        description: "Managed model replica attempts by provider, deployment, route class, and bounded outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_managed_replica_failovers_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_managed_replica_failover"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "deployment", "reason"],
        description: "Safe pre-output managed replica handovers by provider, deployment, and bounded reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_federation_peers_up",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_mcp_federation_peers_up"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Live MCP federation peers as of the last refresh.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_gateway_authorize_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_authorize"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "MCP OAuth broker /authorize outcomes. Coarse by design: the per-rejection reason is in the paired decision-event log line, not a second label.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_gateway_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_broker_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["surface", "decision"],
        description: "MCP OAuth enforcement decisions that no HTTP status alone reports: the resource server's 401, the per-operation scope refusal and its fail-open twin, the /authorize and /par limiter, the session-capacity refusal, the AS-metadata stale fallback, the device-consent CSRF refusal, an unresolvable client-id metadata document on /authorize or /token, and a URL-shaped client_id longer than this broker accepts on either. The unresolvable case answers a fixed string on the wire, because the detail would name the address a client-chosen URL resolved to, so this counter is the only place its rate is visible.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_gateway_dpop_proofs_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_dpop"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "RFC 9449 DPoP proof verification outcomes at the MCP OAuth broker.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_gateway_revocation_introspection_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_revocation_or_introspection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["endpoint", "outcome"],
        description: "MCP OAuth broker /revoke and /introspect outcomes, by endpoint.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_gateway_sessions_active",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_sessions_active"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "In-flight authorization sessions held by the MCP OAuth broker's in-memory session store. A deployment on the storage-backed store leaves this at zero: counting there needs a SCAN.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_gateway_token_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_token"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "MCP OAuth broker /token outcomes. Coarse by design: the per-rejection reason is in the paired decision-event log line, not a second label.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_policy_hook_invocations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_policy_hook_invocation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["verdict", "mcp_server", "tool_name"],
        description: "MCP pre-tool-call policy hook invocations by verdict, upstream MCP server, and tool.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_resource_fetch_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_resource_fetch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "MCP resource-fetch attempts, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_poison_indicators_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_poison_indicator"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["field", "indicator", "kind"],
        description: "Static tool-poisoning indicators in advertised MCP tool text, by field and indicator.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_concealed_text_findings_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_concealed_text_finding"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["field", "class", "kind"],
        description: "Advertised MCP tool text carrying characters hidden from a reader, by field and class.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_tool_compat_verdicts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_tool_compat_verdict"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["grade", "outcome"],
        description: "Tool-versioning oracle verdicts, by computed grade and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_evidence_fail_closed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_evidence_fail_closed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant"],
        description: "MCP tool calls refused because fail-closed evidence delivery failed, by tenant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_argument_policy_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_argument_policy"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant", "rule", "verdict"],
        description: "MCP argument-policy rule triggers, by tenant, rule name, and verdict.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_flow_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_flow"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant", "rule", "verdict"],
        description: "MCP session-flow enforcement triggers, by tenant, rule id, and verdict.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_session_registry_saturated_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_session_registry_saturated"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "MCP session mints refused because the session registry was at capacity, globally or for the caller's tenant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_peer_registry_saturated_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_peer_registry_saturated"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "MCP peer-profile observations that could not be tracked because the peer registry was at capacity, globally or for the caller's tenant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_tool_quota_registry_saturated_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_tool_quota_registry_saturated"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "MCP tools/call refused because the per-tool quota store was at capacity, globally or for the caller's tenant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_content_filter_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_content_filter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant", "category", "verdict"],
        description: "MCP content-filter (secrets/pii) triggers, by tenant, category, and verdict.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_result_policy_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_result_policy"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant", "rule", "verdict"],
        description: "MCP result-policy rule triggers, by tenant, rule name, and verdict.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_grant_expired_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_grant_expired"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant", "policy"],
        description: "MCP tools/call refused because a time-boxed RBAC grant elapsed, by tenant and policy.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_approval_hold_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_approval_hold"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant", "outcome"],
        description: "MCP tools/call parked for operator approval, by tenant and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_tool_cost_usd_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_tool_cost"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tool", "server"],
        description: "MCP tool-call cost in USD, by tool and owning server.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_tool_dispatch_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_mcp_tool_dispatch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tool"],
        description: "MCP tool dispatch duration, by tool name.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_tool_dispatch_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_tool_dispatch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tool", "result"],
        description: "MCP tool dispatch attempts, by tool name and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_tool_version_calls_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_tool_version_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tool", "version", "via", "deprecated"],
        description: "Rollout-plane tool calls, by tool, served version, resolution rung, and deprecation.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mcp_upstream_io_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mcp_upstream_io_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "MCP upstream IO failures absorbed by deadlines and byte caps, by kind.",
        dead_reason: None,
    },
    // Attested metering (WOR-2129, extended by WOR-2211). Seven families
    // under one fresh
    // `sbproxy_meter_` namespace, chosen rather than extending an existing
    // prefix so that none of them can collide with a name an earlier
    // observability wave left behind.
    //
    // None of these is the billing record. The signed chain is. OTLP export
    // drops batches on failure, cumulative counters reset across a restart,
    // and aggregation windows destroy the individual receipts, so a total
    // read here can be short by a deploy's worth of traffic with nothing
    // anywhere saying so. `crates/sbproxy-observe/src/meter_metrics.rs`
    // states that in its module docs and `docs/observability.md` states it
    // to operators, because the failure mode is somebody invoicing off a
    // Grafana panel and being quietly wrong.
    //
    // `route` is absent from every label set below and stays absent.
    // `tenant x route x unit x source x outcome` is a cardinality bomb and
    // route is by far the largest factor in it. Route lives on the receipt,
    // which is reachable from the append histogram's trace exemplar.
    MetricCapability {
        name: "sbproxy_meter_append_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_meter_append_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "Time to append one entry to the meter's signed chain, including lock wait.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_meter_chain_gap_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_meter_chain_gap"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant_id", "failure_mode"],
        description: "Records the meter owed and could not write, by tenant and the posture in force.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_meter_chain_seq",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_meter_chain_seq"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "Head sequence number of the meter's signed chain.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_meter_divergence_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_meter_divergence"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant_id"],
        description: "Windows in which counted units and chained units disagreed, by tenant.",
        dead_reason: None,
    },
    // The odd one out in this block, and the reason it is its own family
    // rather than another `failure_mode` value on the chain gap: every
    // other meter failure is about a record that could not be written, and
    // this one is about a record that was written, is authentically signed,
    // and still cannot be believed. A unit declaring `measured` while
    // carrying an origin header survives the hash chain and the Ed25519
    // signature, because neither of those asks whether a document agrees
    // with itself. The decode paths refuse one; this counts the refusal.
    MetricCapability {
        name: "sbproxy_meter_incoherent_receipts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_meter_incoherent_receipt"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant_id", "failure_mode"],
        description: "Receipts refused on decode because a unit's declared provenance contradicts its evidence, by tenant and the posture in force.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_meter_receipts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_meter_receipt"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant_id", "outcome", "billable"],
        description: "Metered attempts, by tenant, outcome, and the operator's billing answer for it.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_meter_units_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_meter_units"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant_id", "unit", "source"],
        description: "Units the meter counted, by tenant, operator-chosen unit name, and provenance.",
        dead_reason: None,
    },
    // Self-observability. If the scrape body fails to encode, the endpoint
    // serves 200 with an empty payload, which looks exactly like a healthy
    // process emitting nothing. This is the one series that has to survive
    // that, so it is counted on the way out.
    MetricCapability {
        name: "sbproxy_metrics_render_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_render_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["reason"],
        description: "Failures to encode the Prometheus scrape body.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mirror_state_drift_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mirror_state_drift"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "Times the mirror_pending slot was unexpectedly empty when the pipeline tried to fire a shadow request.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_active_requests",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_deployment_requests"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["deployment"],
        description: "Requests holding an active managed-model permit.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_admission_rejections_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_admission_rejection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["deployment", "priority", "reason"],
        description: "Managed-model admission rejections by deployment, priority, and reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_artifact_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_artifact_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["artifact_error_kind"],
        description: "Model artifact acquisition failures by ArtifactError kind.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_deployment_state",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_deployment_state"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["deployment", "engine", "state"],
        description: "One-hot managed-model deployment lifecycle state.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_ensure_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_ensure_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Model ensure-ready failures by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_evictions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_eviction"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Model evictions by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_gpu_memory_occupancy",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_gpu_stats"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["device"],
        description: "GPU occupied-memory fraction (0.0-1.0), by device.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_gpu_utilization",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_gpu_stats"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["device"],
        description: "GPU compute utilization fraction (0.0-1.0), by device.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_gpu_vram_bytes",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_gpu_stats"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["device", "kind"],
        description: "GPU memory in bytes, by device and kind (total/free).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_launches_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_time_to_ready"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["engine", "model", "outcome"],
        description: "Engine launch attempts by engine, model, and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_load_queue_depth",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_load_queue_depth"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["model"],
        description: "Requests queued while a model loads, by model.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_lora_evictions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_lora_eviction"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "LoRA adapters evicted from a base engine's cache to make room.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_lora_loads_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_lora_load"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "LoRA adapters loaded onto a base engine (dynamic-paging cache misses).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_placement_rejections_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_placement_rejection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["deployment", "placement_reason"],
        description: "Placement plan node rejections by deployment and reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_queued_requests",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_deployment_requests"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["deployment"],
        description: "Requests waiting in a managed-model admission queue.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_resident_adapters",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_resident_adapters"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "LoRA adapters currently loaded across all base engines.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_resident_models",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_model_host_resident_models"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "Local models currently loaded and Ready.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_time_to_ready_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_model_host_time_to_ready"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["engine", "model"],
        description: "Time from engine launch to Ready, by engine and model.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_weight_download_bytes_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_weight_download"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "Bytes downloaded by model-host weight pre-fetches.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_weight_download_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_host_weight_download"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "Model-host weight pre-fetches that failed.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_host_weight_download_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_model_host_weight_download"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "Model-host weight pre-fetch duration in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_plane_peer_dispatch_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_model_plane_peer_dispatch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Private model-plane peer dispatch duration to response headers by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_plane_rejections_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_plane_rejection"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["code", "retry_class"],
        description: "Private model-plane request refusals by bounded code and retry class.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_model_plane_stream_cancellations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_model_plane_stream_cancellation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["route_class"],
        description: "Managed response streams dropped before completion by route class.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mtls_cert_cache_evictions_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("counter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "Number of mTLS client cert metadata entries evicted by the LRU bound.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_mtls_handshake_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_mtls_handshake"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "mTLS client-certificate verification outcomes.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_notify_deliveries_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_delivery"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["outcome"],
        description: "Outbound webhook notification deliveries by outcome (delivered, retried, deadlettered, dropped), plus the admin mutations that manage the subscriptions.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_notify_queue",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_deadletters"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["collection"],
        description: "Notifier state by collection: configured webhook subscriptions, and deliveries sitting in the deadletter queue.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_oauth_introspection_results_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_oauth_introspection_result"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["result"],
        description: "RFC 7662 token-introspection results; `cached` is a verdict answered without reaching the authorization server and `no_token` is a request that presented none.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_object_authz_enumeration_tracker_saturated_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_object_authz_tracker_saturated"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Enumeration observations the object_authz policy could not track because the per-principal tracker was at capacity with live windows.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_object_authz_violations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_object_authz_violation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin", "kind", "enforced"],
        description: "Object/function-level authorization violations, by kind (bola, bfla, enumeration) and enforcement disposition (enforced=true refused the request; enforced=false was audited only).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ocsp_fetch_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ocsp_fetch"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "OCSP fetch attempts, by outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ocsp_staple_age_seconds",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_ocsp_staple_age"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["host"],
        description: "Age of the cached OCSP staple for the host, in seconds. Published once \
             a minute by the refresh task; absent until the first successful fetch, so \
             never-stapled is distinguishable from stale.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_olp_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_olp_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["endpoint", "outcome"],
        description: "RSL Open Licensing Protocol endpoint outcomes by endpoint (`token`, `key`, `introspect`, `revoke`) and outcome (`ok`, `rejected`, `rate_limited`, `error`). `rate_limited` is the per-source token budget on `POST /.well-known/olp/token` refusing a mint; it is its own value rather than a `rejected` so an operator can tell a flood from a broken client. Written by the proxy request path for an origin with an `olp:` block; empty on a deployment that configures none.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_operator_leader_is_leader",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_operator_leader_is_leader"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "1 when this operator replica currently holds the leader lease.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_operator_leader_transitions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_operator_leader_transition"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "Leader-election lifecycle events on this replica.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_operator_reconcile_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_operator_reconcile"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind"],
        description: "Operator reconcile duration, by CRD kind.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_operator_reconcile_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_operator_reconcile"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "result"],
        description: "Operator reconcile attempts, by CRD kind and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_origin_active_connections",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("dec_active"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin"],
        description: "In-flight requests per origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_origin_request_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_request_with_labels"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "method", "status"],
        description: "Request latency per origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_origin_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_request_with_labels"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "method", "status"],
        description: "Total HTTP requests per origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_origin_source_entries",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("set_origin_source_entries"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tier", "pinned"],
        description: "Project repositories declared under origin_sources, by runtime tier and whether the entry is pinned to an immutable revision.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_outbound_request_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_outbound_request_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["host", "method", "status"],
        description: "Wall-clock latency of one outbound upstream request.",
        dead_reason: None,
    },
    // Payment settlement families. Every label on all six is a closed enum
    // held in code, not a value copied off a request: `rail` is the
    // settlement rail, `operation` is the settlement or recovery step,
    // `outcome` is what that step concluded, and `provider_class` is the
    // kind of provider rather than the provider.
    // No payer, tenant, quote, challenge, intent, provider reference,
    // credential, or provider error string is reachable from any writer
    // here, which is what keeps a settlement metric from becoming a way to
    // read who paid for what.
    MetricCapability {
        name: "sbproxy_payment_provider_calls_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_payment_provider_call"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["rail", "operation", "provider_class"],
        description: "Payment provider calls that left the process, by rail, operation, and provider class.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_payment_rail_enabled",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_payment_rail_enabled"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["rail"],
        description: "1 for each settlement rail this build compiled and this configuration registered, 0 otherwise.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_payment_recovery_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_payment_recovery"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["operation", "outcome"],
        description: "Durable rows the settlement recovery worker moved, by recovery operation and committed outcome. `outcome=\"failed\"` is the exception and counts sweeps rather than rows: one per sweep of that operation that returned a store error and moved nothing.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_payment_settlement_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_payment_settlement"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["rail", "operation", "outcome"],
        description: "Payment settlement transitions, by rail, deciding step, and outcome. The request-path gate reports `challenge` and `redeem`; the recovery sweep reports the reconciled attempt's own operation.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_payment_worker_drain_clean",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_payment_worker_drain"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "1 when the settlement worker drained inside its shutdown deadline, 0 when it was abandoned mid tick.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_payment_worker_ticks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_payment_worker_ticks"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Completed settlement recovery worker ticks.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_phase_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_phase_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["phase", "origin"],
        description: "Intra-request phase duration, partitioned by phase + origin.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_plugin_init_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_plugin_init"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "plugin", "result"],
        description: "Plugin factory init duration, by kind, plugin name, and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_plugin_init_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_plugin_init"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "plugin", "result"],
        description: "Plugin factory init attempts, by kind, plugin name, and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_plugin_registered_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_plugin_registered"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "plugin"],
        description: "Known plugin registrations, by kind and plugin name.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_policy_audit_events_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_policy_audit_event_dropped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant"],
        description: "Policy verdict audit events dropped because the bus queue was full.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_policy_audit_events_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_policy_audit_emitted"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["verdict", "surface", "policy_id"],
        description: "Policy decisions emitted on the audit event bus, labeled by verdict, surface, and policy_id.",
        dead_reason: None,
    },
    // The decision-audit pair, sitting beside the policy-audit pair it is
    // modeled on rather than being folded into it. Widening
    // sbproxy_policy_audit_events_dropped_total with an `event` label would
    // have changed a Stable family's label set, which every dashboard and
    // alert rule selecting on it would have to be rewritten for. Two new
    // names at Alpha compat is the cheaper half of that trade.
    MetricCapability {
        name: "sbproxy_decision_audit_events_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_decision_audit_dropped"),
        support: SupportLevel::Stable,
        // Alpha, not Beta: the family is new in this release and the
        // decision-audit surface it reports on is still settling, which is
        // where the sibling sbproxy_decision_event_* families sit for the
        // same reason. Beta would promise a name we have not lived with.
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["event", "tenant"],
        description: "Decision audit records dropped before publication, by decision event and tenant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_decision_audit_events_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_decision_audit_emitted"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        // No `tenant`, deliberately, and the asymmetry with the drop
        // counter above is the design. A drop has to be attributable to a
        // tenant or an operator cannot act on it. An emit does not: this
        // counter answers what shape the feed has, the tenant cut is
        // already carried by the drop counter and by
        // sbproxy_decision_event_total, and event x outcome x tenant would
        // multiply the label budget for the dense half of the pair.
        labels: &["event", "outcome"],
        description: "Decision audit records published on the audit bus, by decision event and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_policy_decision_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_policy_decision_latency"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["surface"],
        description: "Wall-clock latency of policy decisions.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_policy_evaluation_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_policy_evaluation_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin", "verdict"],
        description: "Wall-clock latency of one full policy-chain evaluation.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_policy_panic_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_policy_panic"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["policy"],
        description: "Policy enforcer panics contained on the serving path, by policy type.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_policy_triggers_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_policy_with_labels"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["origin", "policy_type", "action", "agent_id", "agent_class"],
        description: "Policy enforcement results.",
        dead_reason: None,
    },
    // Wired from crates/sbproxy-modules/src/projections/. Note what it does
    // not cover, because the description reads wider than the coverage: the
    // pricing-derived renderers (robots, llms, licenses) format strings out of
    // a compiled config and have no failure path at all, so they can never
    // increment this. What can is the agent-skills manifest, where an entry
    // whose artifact will not load or whose archive fails the safety check is
    // dropped from a document that still serves, plus the serialize fallbacks
    // in that manifest and in tdmrep, which substitute an empty document that
    // reads as a deliberate "this origin advertises nothing".
    // WOR-2530. The scan_path label is load-bearing, not decoration. The
    // policy can deny from four places and three of them wrote the operator's
    // configured block body and content type while the fourth wrapped the
    // body in an `{"error": ...}` envelope with a hardcoded
    // `application/json`. With no label there was one merged series, so
    // "which path blocked this" was not a question /metrics could answer and
    // the drift stayed invisible.
    MetricCapability {
        name: "sbproxy_prompt_injection_blocks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_prompt_injection_block"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["scan_path", "tenant"],
        description: "Requests blocked by the prompt_injection_v2 policy, by scan path (header_scan, body_scan, ai_body, a2a).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_prompt_injection_classifier_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_prompt_injection_classifier_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["scan_path", "action", "stage", "reason", "outcome", "tenant"],
        description: "Unavailable prompt-injection classifier stages, with closed failure and policy-outcome labels.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_prompt_injection_v2_results_total",
        kind: MetricKind::Counter,
        // `body_aware_counter`, not the `record_metric` that increments it.
        // Writer matching is textual and unqualified, and `record_metric`
        // is a name a closure parameter in `sbproxy-core`'s
        // `compression_value.rs` also carries, so it counts as a call site
        // for a function that has nothing to do with this family. That is
        // a live-writer guard that stays green after the real writer loses
        // its last caller. `body_aware_counter` is unique in the
        // workspace, is called only from `record_metric`, and builds this
        // exact vec.
        writer: Writer::Recorder("body_aware_counter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        // Registered into the ProxyMetrics registry rather than the global
        // one: the writer above builds the vec by hand and hands it to
        // `metrics().registry`. Written without the trailing parenthesis on
        // purpose. Recorder call sites are counted textually over raw
        // source, comments included, so `name(` written here would count as
        // a call and keep the live-writer check green on its own.
        registry: Registry::Proxy,
        labels: &["action", "label", "detector"],
        description: "Body-aware prompt-injection detector results, by action taken, detection label, and detector name.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_projection_render_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_projection_render_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["projection"],
        description: "Well-known projection render failures, by projection.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_rate_limit_cluster_peer_denials_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_rate_limit_cluster_peer_denial"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "Mesh rate-limit denials that needed peer counts, so the approximation is observable.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_rate_limit_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_rate_limit_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["policy", "result"],
        description: "Rate-limit middleware decisions, by policy and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_rate_limit_suspend_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_rate_limit_suspend"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["workspace"],
        description: "Workspace auto-suspend transitions.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_rate_limit_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_rate_limit"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["workspace", "result"],
        description: "Workspace rate-limit budget outcomes by workspace and result (soft/throttle).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_redis_kv_connections_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("redis_connection_results"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["result"],
        description: "Redis KV connection attempts by result.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_redis_kv_operation_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("redis_operation_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["operation"],
        description: "Redis KV operation duration in seconds.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_redis_kv_operation_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("redis_operation_errors"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["operation", "reason"],
        description: "Redis KV operation failures by operation and reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_request_body_drain_timeout_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_request_body_drain_timeout"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &[],
        description: "Times the post-response drain of a client's request body hit its bound and the connection was closed with bytes unread.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_request_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Field("request_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["hostname"],
        description: "Request latency.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_request_with_labels"),
        support: SupportLevel::Stable,
        compat: CompatTier::Stable,
        registry: Registry::Proxy,
        labels: &["hostname", "method", "status", "agent_id", "agent_class", "agent_vendor", "payment_rail", "content_shape"],
        description: "Total HTTP requests.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_response_body_bytes",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_response_body_bytes"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["direction"],
        description: "Response body size, by compression direction.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_root_of_trust_liveness",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("record_root_of_trust_liveness"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "1 when the last customer-managed root-of-trust probe reached and was authorized by the external key service, 0 otherwise.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_root_of_trust_operations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_root_of_trust_operation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["operation", "outcome"],
        description: "Customer-managed root-of-trust operations, by operation (wrap, unwrap, unwrap_cached) and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_script_compile_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_script_compile"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["engine", "result"],
        description: "Script-engine compile attempts, by engine and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_script_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_script_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["engine"],
        description: "Script-engine invocation duration, by engine.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_script_invocations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_script_invocation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["engine", "result"],
        description: "Script-engine invocations, by engine and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_script_reloads_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["engine", "result"],
        description: "Script-engine hot-reload events, by engine and outcome.",
        dead_reason: Some(
            "nothing calls it, not even a test. The sibling sbproxy_script_compile_total is \
             Stable and called from crates/sbproxy-extension/src/wasm/mod.rs and cel/mod.rs \
             on cold-start compile; this counter is meant to fire on the separate hot-reload \
             path (recompiling a running script on config reload without a restart), which \
             is driven from crates/sbproxy-core/src/reload.rs into those same extension \
             engines. Both are out of this lane's file allowlist; wire the reload call there \
             or delete under WOR-1898",
        ),
    },
    MetricCapability {
        name: "sbproxy_decision_event_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Proxy,
        labels: &["event", "engine", "outcome", "origin", "tenant"],
        description: "Decision events by pipeline point, engine, and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_decision_event_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_decision_duration"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Proxy,
        // No `tenant`: a histogram multiplies its label set by its bucket
        // count, and latency per origin and per engine is the actionable
        // cut. Per-tenant latency, if it is ever needed, arrives as its
        // own opt-in histogram rather than by widening this one.
        labels: &["event", "engine", "origin"],
        description: "Decision event evaluation latency.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_decision_event_fail_open_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_decision_fail_open"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Proxy,
        labels: &["event", "engine", "origin", "tenant"],
        description: "Decision events that proceeded without the decision being made.",
        dead_reason: None,
    },
    // WOR-2565. Zalando rule 188: deprecated-API usage must be
    // monitored, because the whole point of announcing a deprecation
    // is enumerating the callers who have not migrated yet. `route`
    // names which announcement matched (forward-rule id or index,
    // OpenAPI path template, or empty for a whole-origin block),
    // `past_sunset` separates stragglers still calling after the
    // announced retirement instant, and `outcome` separates the ones
    // still being served from the ones refused with 410, which
    // `past_sunset` alone cannot do on a config running both postures.
    MetricCapability {
        name: "sbproxy_deprecated_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_deprecated_request"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "route", "past_sunset", "outcome"],
        description: "Requests that resolved to a deprecated route, by request Host, matched announcement, whether the hit landed after the announced sunset, and whether it was served or refused with 410.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_semantic_cache_results_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_semantic_cache"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tenant", "origin", "source", "result"],
        description: "Semantic-cache hit/miss/error counts.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_serve_lane_admissions_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["priority", "decision"],
        description: "Served-lane admission gate decisions by priority lane.",
        dead_reason: Some(
            "nothing calls it, not even a test. WOR-1679 built this to distinguish \
             admitted/queued_admitted/spilled/timed_out for the interactive/standard/batch \
             priority lanes. The real admission gate is \
             crates/sbproxy-core/src/server/model_host.rs's PriorityClass-based admit() path \
             (see manager.admit(deployment, priority)), which lives in sbproxy-core / \
             sbproxy-model-host, out of this lane's file allowlist; wire the decision call \
             there or delete under WOR-1898",
        ),
    },
    // WOR-2526. A configured Content-Security-Policy that ships nothing reads
    // exactly like a working one from the config file, which is how a dropped
    // CSP survived in a shipped example and in the reference docs. This
    // counter is the difference between "configured" and "delivered": flat at
    // zero on an origin whose config sets content_security_policy is the
    // signal. The mode label carries the second half of that bug, where a
    // report_only policy was emitted as an enforcing one.
    MetricCapability {
        name: "sbproxy_security_headers_csp_emitted_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_security_headers_csp_emitted"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["mode", "tenant"],
        description: "Content-Security-Policy headers emitted by the security_headers policy, by mode (enforce, report_only).",
        dead_reason: None,
    },
    // The deprecation window on the pre-RFC-9421 derivations of
    // `@target-uri` and `@request-target` cannot close on a log line:
    // acceptance is announced once per process, which says a signer
    // somewhere has not moved and nothing about whether that is still
    // true. This is the series an operator watches to zero before the
    // fallback is removed.
    MetricCapability {
        name: "sbproxy_signature_legacy_derivation_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_signature_legacy_derivation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["component"],
        description: "RFC 9421 signatures accepted only against the pre-conformance derivation of a request-target component, by component.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_silent_degradations_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["op"],
        description: "Best-effort operations that failed and were previously dropped silently, by op.",
        dead_reason: Some(
            "nothing calls it, not even a test. WOR-1104 built this so error paths that used \
             to be a silent `let _ = ...` would at least surface as a counter. Candidate call \
             sites already exist: crates/sbproxy-cache/src/store/file.rs:91,109 and \
             store/redis.rs:56,101 each drop a cleanup error with `let _ = ...`. The blocker \
             is not the file allowlist, it is the dependency graph: sbproxy-cache depends on \
             sbproxy-plugin, sbproxy-platform, and sbproxy-security and on no observability \
             crate at all, so wiring those four sites means adding a \
             sbproxy-cache -> sbproxy-observe edge. That edge is sound in principle (the \
             reverse does not exist, so there is no cycle) but it is a graph change, not a \
             four-line patch, and it wants its own review. Add the edge and wire \
             record_silent_degradation(op), or delete the family, under WOR-1898. Nothing \
             recommends this metric today: the alerting advice that used to sit in \
             docs/performance.md was removed once the family was found to be dead",
        ),
    },
    MetricCapability {
        name: "sbproxy_sink_install_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_sink_install_failure"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &[],
        description: "Failed installs of the process-wide telemetry sink dispatcher.",
        dead_reason: None,
    },
    // Both storage families are written by the same `observe_op` wrapper in
    // `crates/sbproxy-storage/src/metrics.rs`, which every RedisStore trait
    // method goes through. They shipped as `storage_op_*`, outside both
    // sanctioned prefixes, which made them invisible twice over: the
    // coverage guard only looked at sanctioned names, and a scrape config
    // built from the prefixes this doc sanctions dropped them at the
    // scrape. Renamed with the registry entries they always owed.
    MetricCapability {
        name: "sbproxy_storage_op_duration_seconds",
        kind: MetricKind::Histogram,
        // The static rather than `observe_op`: the wrapper is generic
        // (`fn observe_op<F, T>(`), so the scanner's `fn observe_op(`
        // definition needle would never match it.
        writer: Writer::Recorder("STORAGE_OP_DURATION_SECONDS"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["op", "backend", "kind"],
        description: "Latency of storage backend operations, by operation, backend, and record kind.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_storage_op_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("STORAGE_OP_ERRORS_TOTAL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["op", "backend", "kind", "error_kind"],
        description: "Errors returned by storage backend operations, by operation, backend, record kind, and error variant.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_synthetic_probe_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Field("synthetic_probe_failures"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["reason"],
        description: "Synthetic readiness probe failures by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_target_health_state",
        kind: MetricKind::Gauge,
        writer: Writer::Recorder("refresh_target_health_gauge"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "target"],
        description: "Per-target tri-state health on LiteLLM's 0/1/2 scale: 0 healthy, 1 degraded (circuit breaker half-open), 2 excluded from selection (probe-unhealthy, outlier-ejected, or breaker open). Sampled at scrape time from the same pipeline walk that renders GET /api/health/targets. `origin` is the configured origin id, not the request Host. `target` is the configured target URL, or the load balancer's own url#index identifier when one origin configures that URL more than once.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_telemetry_dropped_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_telemetry_dropped"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "reason"],
        description: "Telemetry records dropped or sinks that failed to set up, by kind and reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_tokens_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_tokens_attributed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["project", "user", "tag", "direction"],
        description: "AI token usage attributed to a credential's project / user / tag.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_transform_pdf_decode_errors_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_pdf_decode_error"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["error_kind"],
        description: "pdf_markdown transform decode failures, by the stage that failed (`empty_body`, `document_parse`, `content_extract`). `error_kind` is a closed enum and carries nothing read out of the document. Absent until an origin configures a `pdf_markdown` transform, which needs the optional `transform-pdf` build.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_transform_pdf_pages_decoded_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_pdf_pages_decoded"),
        support: SupportLevel::Stable,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &[],
        description: "Pages the pdf_markdown transform successfully projected to Markdown. Unlabeled: `Transform::apply` is handed no origin, and a label that only ever holds one value is worse than none. Absent until an origin configures a `pdf_markdown` transform, which needs the optional `transform-pdf` build.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_transport_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["protocol", "result"],
        description: "Transport-layer request duration, by protocol and outcome.",
        dead_reason: Some(
            "nothing calls it, not even a test. Both this histogram and the sibling counter \
             sbproxy_transport_requests_total are written by the single \
             record_transport_request(protocol, result, duration_secs) helper \
             (crates/sbproxy-observe/src/metrics.rs), meant to give protocol-specific \
             coverage (grpc/grpc_web/graphql/websocket/h3) alongside the already-Stable \
             per-request generic metrics. The dispatch code for those protocols lives in \
             crates/sbproxy-transport/src/grpc/ and the websocket/h3/graphql paths in \
             crates/sbproxy-core/src/server/ (proxy_http.rs, action_dispatch.rs), out of \
             this lane's file allowlist; wire the call at each protocol's completion point \
             or delete both metrics under WOR-1898",
        ),
    },
    MetricCapability {
        name: "sbproxy_transport_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["protocol", "result"],
        description: "Transport-layer requests, by protocol and outcome.",
        dead_reason: Some(
            "nothing calls it, not even a test. Written by the same \
             record_transport_request(...) helper as sbproxy_transport_duration_seconds \
             above; see that entry for the call-site detail. Wire or delete both together \
             under WOR-1898",
        ),
    },
    MetricCapability {
        name: "sbproxy_trust_tier_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_trust_tier"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["tier"],
        description: "Requests partitioned by the conservative trust-tier decision.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_unrouted_requests_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_unrouted_request"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason"],
        description: "Requests rejected before origin resolution, by reason.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_upstream_status_retries_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_upstream_status_retry"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "status"],
        description: "Upstream retries triggered by a configured response status, by origin and matched status.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_upstream_timeout_retries_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_upstream_timeout_retry"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Proxy,
        labels: &["origin", "phase"],
        description: "Upstream retries triggered by a timeout-classed failure, by origin and phase (connect or upstream).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_vault_resolution_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("record_vault_resolution"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend", "result"],
        description: "Vault resolution duration, by backend and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_vault_resolution_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_vault_resolution"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["backend", "result"],
        description: "Vault resolution attempts, by backend and outcome.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_usage_bridge_enqueued_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_usage_bridge_enqueued"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "reporter", "resource_type", "result"],
        description: "Billable units the request path queued for a usage reporter, by tenant, reporter, resource type, and whether the row was new.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_usage_bridge_gap_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_usage_bridge_gap"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "failure_mode"],
        description: "Billable units that could not be queued for a usage reporter, by tenant and the posture in force.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_user_agent_headless_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("HEADLESS_TOTAL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["library"],
        description: "user_agent_parser policy runs where a headless-automation-library \
             token matched (headless_chrome, phantomjs, puppeteer, playwright, selenium).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_user_agent_parse_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("PARSE_TOTAL"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["device_type"],
        description: "user_agent_parser policy runs, by parsed device_type.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_waf_persistent_blocks_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_waf_persistent_block"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin", "tenant", "event", "key_kind"],
        description: "WAF persistent (time-boxed) block actions, by lifecycle event and key kind.",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_websocket_teardowns_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_websocket_teardown"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["reason", "direction", "tenant", "origin"],
        description: "WebSocket upgrades refused or tunnels torn down by the gateway, by closed reason, direction, tenant, and origin. Covers both upgrade surfaces: the `websocket` action and AI realtime.",
        dead_reason: None,
    },
];

/// Dashboards and alert rules that knowingly read a metric nothing writes.
///
/// The escape hatch from the drift guard, and deliberately a narrow one: an
/// entry costs a line in a reviewed table and a ticket number. That is the
/// whole difference between "known dead" as a decision and "known dead" as an
/// accident. Everything here is a panel or rule that draws a flat zero today
/// and will draw real data when its ticket lands.
///
/// Narrow in two ways worth knowing before you reach for it, because neither is
/// visible from the type:
///
/// - It covers the dead-writer case only. The exemption-quality test in
///   `metric_drift.rs` requires the name to be in [`METRICS`], so a query
///   naming a metric no crate declares cannot be exempted. Declare it (with
///   `Writer::Nothing` and a `dead_reason`) or fix the query.
/// - An entry suppresses every check on that metric, in every scanned file, not
///   just the one that prompted it. `sbproxy_requests_total` is read by five
///   dashboards and both rule sets, so exempting it to quiet one bad label
///   would also retire the `status_class` check whose absence pinned the
///   availability SLO at 1.0. Prefer fixing the query.
///
/// Empty because closing `deploy/dashboards/` needed neither: every finding
/// there was an undeclared name or a wrong label, and both were fixed in place.
pub const REFERENCE_EXEMPTIONS: &[ReferenceExemption] = &[];

// --- Tenant-scoping guard (multi-tenant enforcement) ---
//
// The writer-liveness guard above answers "does anything increment this
// metric." This section answers a different question about the same table:
// "if this metric holds one tenant's data, can a query actually pull that
// tenant's slice back out." A counter that mixes every tenant's requests,
// spend, or security verdicts into a single series is not wrong the way a
// zero-writer metric is wrong; it has real numbers in it. Those numbers just
// answer "how much did everyone spend, combined" while sitting under a name
// that promises "how much did this tenant spend." `WOR-1896` was one
// instance of that general failure mode: attribution that was declared but
// not actually reachable through `snapshot_named`. This is the same shape of
// bug, one level up, in the label set itself.

/// Label names this registry accepts as the tenant / customer boundary.
///
/// `tenant_id` and `api_key_id` are the current attribution convention (see
/// `crates/sbproxy-ai/src/ai_metrics.rs`, the WOR-1493..1501 series). `tenant`
/// and `workspace` are two earlier spellings of the same boundary that
/// predate that convention and still back several live counters today.
/// `crate::cardinality::budget_for_label` already treats `tenant_id`,
/// `workspace`, and `workspace_id` as one cardinality-budget class, so this
/// list is the registry side of that same equivalence. A family needs only
/// one of these names on it, not all four.
pub const TENANT_LABEL_NAMES: &[&str] = &["tenant_id", "api_key_id", "tenant", "workspace"];

/// Metric families whose observations belong to one tenant or customer, and
/// therefore must carry a label from [`TENANT_LABEL_NAMES`] naming it, or a
/// reviewed [`TENANT_LABEL_EXEMPTIONS`] entry explaining why not yet.
///
/// This is the opt-in mark `tenant_label_gaps` checks against. It is a
/// claim about a family's *meaning* ("this counts something that belongs to
/// a specific tenant"), which nothing in `labels` alone can prove, so a
/// human asserts it here the same way [`REFERENCE_EXEMPTIONS`] is a human
/// asserting "this dead reference is known and ticketed." Adding a new
/// per-tenant billing, spend, or security counter to [`METRICS`] without
/// also listing it here does not fail the build; dropping the tenant label
/// from one already listed here does.
pub const TENANT_SCOPED_METRICS: &[&str] = &[
    "sbproxy_ai_audio_seconds_attributed_total",
    "sbproxy_ai_compression_duration_seconds",
    "sbproxy_ai_compression_lever_total",
    "sbproxy_ai_compression_ratio",
    "sbproxy_ai_compression_request_levers_run",
    "sbproxy_ai_compression_request_tokens_saved",
    "sbproxy_ai_compression_requests_total",
    "sbproxy_ai_compression_selection_total",
    "sbproxy_ai_compression_tokens_saved_total",
    "sbproxy_ai_compression_tokens_total",
    "sbproxy_ai_compression_value_cost_saved_micros_total",
    "sbproxy_ai_compression_value_tokens_saved_total",
    "sbproxy_ai_cost_dollars_attributed_total",
    "sbproxy_ai_cost_saved_micros_total",
    "sbproxy_ai_cost_usd_micros_total",
    "sbproxy_ai_ratelimit_rejected_total",
    "sbproxy_ai_request_duration_attributed_seconds",
    "sbproxy_ai_requests_attributed_total",
    "sbproxy_ai_tokens_attributed_total",
    "sbproxy_ai_tokens_saved_total",
    "sbproxy_capture_budget_dropped_total",
    "sbproxy_capture_dropped_total",
    // WOR-2405. Same reason as the policy-audit drop counter further
    // down: the question this answers is whose audit trail lost
    // records, and merged across tenants it cannot answer it at all.
    "sbproxy_decision_audit_events_dropped_total",
    // WOR-2165. An egress refusal is a security verdict about one
    // tenant's outbound traffic. Merged across tenants it answers
    // "something was refused somewhere", which is not a question an
    // operator of a multi-tenant deployment can act on.
    "sbproxy_egress_refused_total",
    "sbproxy_http_framing_blocks_total",
    "sbproxy_inbound_key_requests_total",
    "sbproxy_judge_budget_exhausted_total",
    "sbproxy_label_cardinality_overflow_per_tenant_total",
    // WOR-2384. A fail-closed MCP evidence refusal is a security-policy
    // outcome for one tenant's traffic. Merged across tenants it answers
    // "some evidence write failed somewhere", which cannot tell an
    // operator whose governed calls are being blocked.
    "sbproxy_mcp_evidence_fail_closed_total",
    // WOR-2384 (MCP05). An argument-policy trigger is a security-policy
    // outcome for one tenant's tool-call traffic, same reasoning as the
    // evidence fail-closed counter directly above.
    "sbproxy_mcp_argument_policy_total",
    // WOR-2384 (MCP06). A session-flow enforcement trigger is a
    // security-policy outcome for one tenant's tool-call traffic, same
    // reasoning as the argument-policy counter directly above.
    "sbproxy_mcp_flow_total",
    // WOR-2384 (MCP01/MCP10). A content-filter (secrets/pii) trigger and
    // a result-policy trigger are both security-policy outcomes for one
    // tenant's tool-call traffic, same reasoning as the argument-policy
    // and flow counters directly above.
    "sbproxy_mcp_content_filter_total",
    "sbproxy_mcp_result_policy_total",
    // WOR-2386. A time-boxed grant expiry is a security-policy outcome
    // for one tenant's tool-call traffic.
    "sbproxy_mcp_grant_expired_total",
    // WOR-2454. A parked high-risk tool call is a security-policy
    // outcome for one tenant's tool-call traffic.
    "sbproxy_mcp_approval_hold_total",
    // Every meter family with a tenant dimension. Tenant-relevant is not a
    // judgment call here: a metering counter exists to say what one
    // customer owes, and one that merged every customer's units into a
    // single series would answer a question nobody asked while sitting
    // under a name that promises otherwise. `sbproxy_meter_chain_seq` and
    // `sbproxy_meter_append_duration_seconds` are deliberately absent:
    // both describe the chain and the process rather than a customer, and
    // neither carries a tenant label to check.
    "sbproxy_meter_chain_gap_total",
    "sbproxy_meter_divergence_total",
    "sbproxy_meter_incoherent_receipts_total",
    "sbproxy_meter_receipts_total",
    "sbproxy_meter_units_total",
    "sbproxy_policy_audit_events_dropped_total",
    // WOR-2530. A prompt-injection block is a security verdict about one
    // tenant's traffic, the same reasoning as the framing and egress
    // counters above. Merged across tenants it answers "something was
    // blocked somewhere", which no operator of a multi-tenant deployment
    // can act on.
    "sbproxy_prompt_injection_blocks_total",
    "sbproxy_prompt_injection_classifier_failures_total",
    "sbproxy_rate_limit_suspend_total",
    "sbproxy_rate_limit_total",
    // WOR-2526. Whether a browser hardening header actually reached clients
    // is a per-origin, and therefore per-tenant, question. One merged series
    // cannot tell an operator which tenant's origins are serving responses
    // with no CSP.
    "sbproxy_security_headers_csp_emitted_total",
    "sbproxy_semantic_cache_results_total",
    "sbproxy_usage_bridge_enqueued_total",
    "sbproxy_usage_bridge_gap_total",
    "sbproxy_waf_persistent_blocks_total",
    // WOR-2552. A websocket enforcement teardown is a security-policy
    // outcome for one tenant's tunnel traffic, same reasoning as the
    // WAF and egress counters beside it: merged across tenants it
    // answers "some tunnel was torn down somewhere", which cannot tell
    // an operator whose traffic is being refused.
    "sbproxy_websocket_teardowns_total",
];

/// Tenant-scoped families that are known to lack a tenant label today, and
/// the ticket that will add one.
///
/// Empty today; this is the escape hatch, kept ready rather than deleted,
/// mirroring [`REFERENCE_EXEMPTIONS`]. `sbproxy_tokens_attributed_total`
/// (`crates/sbproxy-observe/src/metrics.rs`, `record_tokens_attributed`) is
/// the one live candidate: its own doc comment already says `tenant_id` is
/// deliberately absent pending the credentials epic's origin-to-tenant
/// resolution. It is left out of `TENANT_SCOPED_METRICS` entirely rather
/// than exempted here, because an exemption needs a tracking ticket
/// (mirroring [`REFERENCE_EXEMPTIONS`]'s own rule below) and none exists
/// yet; file one, then move the name across and add the entry in the same
/// commit that adds the label.
pub const TENANT_LABEL_EXEMPTIONS: &[ReferenceExemption] = &[];

/// Enforce that every family named in `tenant_scoped` carries a label from
/// [`TENANT_LABEL_NAMES`], unless `exemptions` names it.
///
/// Three failure modes, all reported so a single run surfaces everything
/// wrong at once:
///
/// - a name in `tenant_scoped` that is not declared in `metrics` at all (a
///   typo, or the metric was renamed here and the rename was not mirrored);
/// - a declared metric whose `labels` carry none of [`TENANT_LABEL_NAMES`]
///   and which `exemptions` does not cover; a per-tenant metric with no
///   tenant dimension silently merges every tenant's data into one series,
///   which is invisible in exactly the way the dead-metric bug was
///   invisible: the family scrapes, the dashboard draws a line, and the
///   line answers a different question than its name claims;
/// - an exemption naming a metric that is not in `tenant_scoped`, which is
///   either stale (the metric was fixed and the entry should have been
///   deleted) or was never a real tenant-scoping gap and should not have
///   been exempted in the first place.
pub fn tenant_label_gaps(
    metrics: &[MetricCapability],
    tenant_scoped: &[&str],
    exemptions: &[ReferenceExemption],
) -> Vec<RegistryError> {
    let mut errors = Vec::new();

    for name in tenant_scoped {
        let Some(metric) = metrics.iter().find(|m| m.name == *name) else {
            errors.push(RegistryError {
                subject: (*name).to_string(),
                message: "is listed in TENANT_SCOPED_METRICS but is not declared in METRICS"
                    .to_string(),
            });
            continue;
        };

        let has_tenant_label = metric
            .labels
            .iter()
            .any(|label| TENANT_LABEL_NAMES.contains(label));
        if has_tenant_label {
            continue;
        }

        if exemptions.iter().any(|exemption| exemption.metric == *name) {
            continue;
        }

        errors.push(RegistryError {
            subject: (*name).to_string(),
            message: format!(
                "is tenant-scoped but its labels {:?} carry none of {TENANT_LABEL_NAMES:?}; a \
                 per-tenant metric with no tenant dimension silently merges every tenant's data \
                 into one series. Add one of those labels, or add a TENANT_LABEL_EXEMPTIONS \
                 entry naming the ticket that will.",
                metric.labels
            ),
        });
    }

    for exemption in exemptions {
        if !tenant_scoped.contains(&exemption.metric) {
            errors.push(RegistryError {
                subject: exemption.metric.to_string(),
                message: "has a TENANT_LABEL_EXEMPTIONS entry but is not listed in \
                          TENANT_SCOPED_METRICS"
                    .to_string(),
            });
        }
    }

    errors
}

// --- Run-scoped label guard (cardinality) ---
//
// The tenant guard above asks whether a label is missing. This one asks
// whether a label should never have been there. They are the two halves of
// the same question about a label set, and the second is the one that takes
// a Prometheus server down: a run id is unbounded by construction, one value
// per run, forever, so the series count tracks traffic rather than the
// system being measured.
//
// This is deliberately a static guard and not a `crate::cardinality` budget
// entry. The runtime limiter caps unique values per label name and demotes
// the overflow to `__other__`; a label it has never heard of falls through
// to the workspace default of 1000. Point that at a run id and you get the
// worst of both: 1000 dead series per process, then a label whose value is
// `__other__` for every subsequent run, which reads as data and is not.
// Adding a budget for `run_id` would be answering "how many run ids may we
// keep" when the answer is "none". Do not resolve a failure here by giving
// the offending label a budget.

/// Label names that carry a run-scoped identifier, which no Prometheus
/// family may use.
///
/// Every entry names one value per run, per task, per session, or per trace.
/// These identifiers are correct and necessary as span attributes and as
/// ledger and audit fields, where the storage cost is one row per event and
/// the lookup is by id. On a metric they are a cardinality bomb: the label
/// mints a fresh time series for a value that will never be observed again,
/// and the series is retained for the whole retention window.
///
/// The list is matched **exactly** (ASCII case-insensitively), not by
/// substring. Substring matching reads as the stronger rule and is the wrong
/// one here: `request` is a substring of `request_class`, `run` is a
/// substring of `runtime` and of `truncated`, and `context` would fail to
/// catch `ctx_id` anyway, so the pattern buys false positives without buying
/// coverage. Label names are a short, closed, reviewed vocabulary (113
/// distinct names across the whole table today), so an exact list is both
/// auditable and greppable, and a name that belongs on it can simply be
/// added. Each identifier is listed under every spelling that has ever shown
/// up in this codebase or in the specs it implements: separated
/// (`run_id`), run together (`runid`), abbreviated (`ctx_id`), and bare
/// (`run`). A bare stem is included because a label named `run` or `session`
/// is an identifier in practice; a bounded dimension has a more specific
/// name, and `request_class` is exactly what that looks like.
///
/// Exact matching alone would still miss a qualified id such as
/// `parent_request_id`, which is a real field name in `A2AContext` today, so
/// [`RUN_SCOPED_LABEL_STEMS`] extends the rule to the one structural case
/// that is safe to generalize.
pub const RUN_SCOPED_LABEL_NAMES: &[&str] = &[
    // Run and task identity (the WOR-2139 subject).
    "run",
    "run_id",
    "runid",
    "task",
    "task_id",
    "taskid",
    // Agent context and conversation identity.
    "context",
    "context_id",
    "contextid",
    "ctx",
    "ctx_id",
    "conversation",
    "conversation_id",
    "conversationid",
    "convo_id",
    // Session identity.
    "session",
    "session_id",
    "sessionid",
    "sess_id",
    // W3C trace context. A span id is worse than a trace id: one value per
    // operation rather than one per request.
    "trace",
    "trace_id",
    "traceid",
    "traceparent",
    "tracestate",
    "span",
    "span_id",
    "spanid",
    // Request and correlation identity.
    "request",
    "request_id",
    "requestid",
    "req",
    "req_id",
    "reqid",
    "correlation",
    "correlation_id",
    "correlationid",
    "corr_id",
];

/// Identifier stems that make a qualified `*_id` label run-scoped.
///
/// The one generalization on top of [`RUN_SCOPED_LABEL_NAMES`], and it is
/// anchored rather than free-floating: a label is run-scoped if it ends in
/// `_id`, `_uuid`, or `_guid` and the underscore-separated segment
/// immediately before that suffix is one of these stems. So `a2a_task_id`,
/// `parent_request_id`, and `agent_run_id` are caught, which matters because
/// run identity is arriving across this codebase and a qualified spelling is
/// the likely one.
///
/// The anchoring is what keeps it safe. `api_key_id`, `agent_id`, `node_id`,
/// `policy_id`, `rule_id`, and `tenant_id` are all live labels today and all
/// pass, because the segment before their suffix is `key`, `agent`, `node`,
/// `policy`, `rule`, or `tenant`. `request_class` and `retry_class` pass too,
/// because the rule only fires on an id suffix.
pub const RUN_SCOPED_LABEL_STEMS: &[&str] = &[
    "run",
    "task",
    "context",
    "ctx",
    "session",
    "sess",
    "trace",
    "span",
    "request",
    "req",
    "correlation",
    "corr",
    "conversation",
    "convo",
];

/// Whether `label` names a run-scoped identifier.
///
/// Exact match against [`RUN_SCOPED_LABEL_NAMES`], plus the anchored
/// `*_<stem>_id` rule described on [`RUN_SCOPED_LABEL_STEMS`]. Both halves
/// are ASCII case-insensitive so `runId` and `RUN_ID` cannot slip past a
/// list written in the lowercase Prometheus convention.
fn is_run_scoped_label(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();

    if RUN_SCOPED_LABEL_NAMES.contains(&lower.as_str()) {
        return true;
    }

    for suffix in ["_id", "_uuid", "_guid"] {
        let Some(head) = lower.strip_suffix(suffix) else {
            continue;
        };
        let stem = head.rsplit('_').next().unwrap_or(head);
        if RUN_SCOPED_LABEL_STEMS.contains(&stem) {
            return true;
        }
    }

    false
}

/// Families that carry a run-scoped label today, and the ticket that removes
/// it.
///
/// Empty today, because the table is clean today. Kept ready rather than
/// deleted, mirroring [`REFERENCE_EXEMPTIONS`] and [`TENANT_LABEL_EXEMPTIONS`],
/// so that a genuine conflict is a reviewed line with a ticket on it rather
/// than a quiet edit to [`RUN_SCOPED_LABEL_NAMES`]. An entry here is the only
/// sanctioned way to keep such a label, and it is meant to be embarrassing
/// enough to be temporary: the series it describes are already being minted
/// while the entry sits here.
pub const RUN_SCOPED_LABEL_EXEMPTIONS: &[ReferenceExemption] = &[];

/// Enforce that no family in `metrics` carries a run-scoped identifier label,
/// unless `exemptions` names it.
///
/// **This scans every entry in `metrics`, with no opt-in list.** That is the
/// deliberate difference from [`tenant_label_gaps`], which only inspects
/// families a human remembered to name in [`TENANT_SCOPED_METRICS`]. An
/// opt-in list works for a guard whose subject is a family's *meaning*, which
/// no table can infer. It does not work here, because the failure mode is
/// somebody adding a label without thinking about it at all, and a person who
/// did not think about the cardinality of `run_id` is not going to think
/// about registering it for the check either. Whitelisting is the escape
/// hatch, and it is an explicit, ticketed one.
///
/// Three failure modes, all collected so a single run surfaces everything
/// wrong at once:
///
/// - a declared metric whose `labels` carry a run-scoped identifier that
///   `exemptions` does not cover; each new value of that label is a new time
///   series that will never be written again and will still be held for the
///   whole retention window, so the cost is paid by the monitoring system
///   rather than by the change that caused it;
/// - an exemption naming a metric that is not declared in `metrics` at all (a
///   typo, or the family was renamed and the rename was not mirrored);
/// - an exemption naming a metric that carries no run-scoped label, which is
///   either stale (the label was removed and the entry should have gone with
///   it) or was never a real violation and should not have been written.
///
/// # Why this is not a cardinality budget
///
/// `crate::cardinality` is the runtime limiter: it caps unique values per
/// label name and demotes the overflow to `__other__`. It is the right tool
/// for a label that is bounded in principle and unbounded in practice, such
/// as `hostname`. It is the wrong tool here, and reaching for it is the
/// tempting mistake. A label the budget table has never heard of falls
/// through to the workspace default of 1000, so a run id would be *admitted*:
/// 1000 write-once series per process, and then a label reading `__other__`
/// for every subsequent run, which looks like data and is not. A budget entry
/// answers "how many run ids may we keep", and the answer is none. Do not
/// resolve a failure from this function by adding the offending label to
/// `crate::cardinality::budget_for_label`.
pub fn run_scoped_label_gaps(
    metrics: &[MetricCapability],
    exemptions: &[ReferenceExemption],
) -> Vec<RegistryError> {
    let mut errors = Vec::new();

    for metric in metrics {
        let offending: Vec<&str> = metric
            .labels
            .iter()
            .copied()
            .filter(|&label| is_run_scoped_label(label))
            .collect();

        if offending.is_empty() {
            continue;
        }

        if exemptions
            .iter()
            .any(|exemption| exemption.metric == metric.name)
        {
            continue;
        }

        errors.push(RegistryError {
            subject: metric.name.to_string(),
            message: format!(
                "carries the run-scoped label(s) {offending:?}. A run, task, context, session, \
                 or trace id takes one distinct value per run, so as a label value it mints one \
                 time series per run and the series count grows with traffic instead of with the \
                 system. Put the identifier on the span and in the ledger, where it is correct, \
                 and partition the metric by a bounded dimension instead (route, outcome, \
                 reason, decision). Do not give the label a cardinality budget: a budget caps \
                 the damage at 1000 dead series and then reports __other__ forever. If the label \
                 genuinely has to stay for now, add a RUN_SCOPED_LABEL_EXEMPTIONS entry naming \
                 the ticket that removes it."
            ),
        });
    }

    for exemption in exemptions {
        let Some(metric) = metrics.iter().find(|m| m.name == exemption.metric) else {
            errors.push(RegistryError {
                subject: exemption.metric.to_string(),
                message: "has a RUN_SCOPED_LABEL_EXEMPTIONS entry but is not declared in METRICS"
                    .to_string(),
            });
            continue;
        };

        if !metric
            .labels
            .iter()
            .any(|&label| is_run_scoped_label(label))
        {
            errors.push(RegistryError {
                subject: exemption.metric.to_string(),
                message: "has a RUN_SCOPED_LABEL_EXEMPTIONS entry but carries no run-scoped \
                          label; the exemption is stale, so delete it"
                    .to_string(),
            });
        }
    }

    errors
}

/// Render the catalog published as `docs/metrics-stability.md`.
///
/// Deterministic and byte-stable: `scripts/check-metrics-stability.sh`
/// regenerates it and diffs, so the committed file cannot drift from the code.
/// Hand-editing it is not so much forbidden as pointless.
pub fn render_markdown() -> String {
    let mut out = String::from(
        "# Metrics stability\n\
         *Last modified: 2026-08-28*\n\n\
         *Generated from the executable metric registry. Do not hand-edit; run \
         `cargo run -q -p sbproxy-observe --bin generate-metrics-stability > \
         docs/metrics-stability.md`.*\n\n\
         Every metric SBproxy emits, what writes it, and what we promise about \
         its name.\n\n",
    );

    out.push_str(
        "## Prefixes\n\n\
         Two name prefixes are sanctioned. `sbproxy_` covers the proxy and its \
         gateway surfaces. `mesh_` covers the clustering substrate (membership, \
         replication, and cross-node transport); every `mesh_` family carries \
         `beta` name compatibility while that subsystem is young.\n\n\
         ## Support\n\n\
         `stable` means production code increments the metric, proven by a drift \
         guard that resolves the writer against the source tree and requires a \
         call site outside tests.\n\n\
         `config_only` means the family is declared and scraped but nothing \
         increments it. It reads zero, always. No dashboard or alert rule may \
         read one.\n\n\
         ## Compatibility\n\n\
         `stable` names will not be renamed or removed without a deprecation \
         period: the replacement ships alongside the original in a minor \
         release, and the original is removed no earlier than the next major. \
         Label sets on stable metrics may gain labels in a minor release; \
         losing one follows the same deprecation path.\n\n\
         `beta` names are functional and may still be renamed or relabeled in a \
         minor release, with a changelog entry.\n\n\
         `alpha` names may be renamed, relabeled, or removed in any release.\n\n",
    );

    // The tiers above are a vocabulary; this is the timetable. A tier with
    // no stated window is not a promise, it is an adjective, and an
    // operator cannot plan a chargeback report around an adjective.
    out.push_str(
        "## Deprecation schedule\n\n\
         The tiers above say what may change. This says when, so a cost report \
         built on a `stable` name can be planned around rather than hoped for.\n\n\
         A `stable` metric name, or a label on one, is retired in four steps, \
         and every step is visible from outside this repository:\n\n\
         1. The replacement family ships in a minor release and writes \
         alongside the original. Both carry the same values for the whole \
         window.\n\
         2. That same release marks the original deprecated here and in its \
         changelog entry, naming the replacement and the earliest release that \
         may remove it.\n\
         3. The window stays open for at least two further minor releases and \
         at least 90 days, whichever ends later.\n\
         4. Removal lands in a major release. Never a minor, never a patch.\n\n\
         Gaining a label is not a deprecation and opens no window: new labels \
         go on the end of the set, every existing query keeps matching, and the \
         release notes it. Removing or reordering one renames every series in \
         the family, so it takes all four steps above.\n\n\
         `beta` and `alpha` names get no window at all. A `beta` name changes \
         with a changelog entry in the release that changes it; an `alpha` name \
         changes without one.\n\n\
         The set of `stable` names, and the label prefix each one carried at \
         promotion, is frozen in a build guard, so a rename, a removal, or a \
         label reorder fails the build rather than waiting on review to notice.\n\n\
         ## Catalog\n\n",
    );

    out.push_str("| Metric | Type | Support | Compat | Labels | Description |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for metric in METRICS {
        let labels = if metric.labels.is_empty() {
            "none".to_string()
        } else {
            metric
                .labels
                .iter()
                .map(|label| format!("`{label}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let support = if metric.dead_reason.is_some() {
            "`config_only` (nothing emits this yet)".to_string()
        } else {
            format!("`{}`", metric.support.as_str())
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | `{}` | {} | {} |\n",
            metric.name,
            metric.kind.as_str(),
            support,
            metric.compat.as_str(),
            labels,
            metric.description,
        ));
    }

    out
}

#[cfg(test)]
mod tenant_label_gap_tests {
    use super::*;

    fn tenant_scoped_metric(
        name: &'static str,
        labels: &'static [&'static str],
    ) -> MetricCapability {
        MetricCapability {
            name,
            kind: MetricKind::Counter,
            writer: Writer::Recorder("record_thing"),
            support: SupportLevel::Stable,
            compat: CompatTier::Beta,
            registry: Registry::Default,
            labels,
            description: "A tenant-attributed thing.",
            dead_reason: None,
        }
    }

    #[test]
    fn a_metric_with_a_recognized_tenant_label_passes() {
        let metrics = [tenant_scoped_metric(
            "sbproxy_thing_total",
            &["tenant_id", "result"],
        )];
        let errors = tenant_label_gaps(&metrics, &["sbproxy_thing_total"], &[]);
        assert_eq!(errors, vec![]);
    }

    #[test]
    fn each_recognized_label_name_satisfies_the_guard_on_its_own() {
        for label in TENANT_LABEL_NAMES {
            let labels = std::slice::from_ref(label);
            let metrics = [tenant_scoped_metric("sbproxy_thing_total", labels)];
            let errors = tenant_label_gaps(&metrics, &["sbproxy_thing_total"], &[]);
            assert_eq!(
                errors,
                vec![],
                "label {label:?} should satisfy the guard on its own"
            );
        }
    }

    #[test]
    fn a_metric_missing_every_tenant_label_fails_the_build() {
        let metrics = [tenant_scoped_metric("sbproxy_thing_total", &["result"])];
        let errors = tenant_label_gaps(&metrics, &["sbproxy_thing_total"], &[]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].message.contains("carry none of"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn a_name_not_declared_in_metrics_is_reported() {
        let metrics: [MetricCapability; 0] = [];
        let errors = tenant_label_gaps(&metrics, &["sbproxy_missing_total"], &[]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].message.contains("not declared in METRICS"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn a_declared_exemption_suppresses_the_missing_label_error() {
        let metrics = [tenant_scoped_metric("sbproxy_thing_total", &["result"])];
        let exemptions = [ReferenceExemption {
            metric: "sbproxy_thing_total",
            reason: "tenant_id lands once the credentials epic ships tenant \
                      resolution for this call site (WOR-9999).",
        }];
        let errors = tenant_label_gaps(&metrics, &["sbproxy_thing_total"], &exemptions);
        assert_eq!(errors, vec![]);
    }

    #[test]
    fn a_stale_exemption_for_an_unlisted_metric_is_reported() {
        let metrics = [tenant_scoped_metric("sbproxy_thing_total", &["tenant_id"])];
        let exemptions = [ReferenceExemption {
            metric: "sbproxy_other_total",
            reason: "some historical reason that no longer names a tenant-scoped metric.",
        }];
        // sbproxy_thing_total already carries tenant_id, so the only
        // expected error is the stale exemption naming a metric that was
        // never (or is no longer) in tenant_scoped.
        let errors = tenant_label_gaps(&metrics, &["sbproxy_thing_total"], &exemptions);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0]
                .message
                .contains("is not listed in TENANT_SCOPED_METRICS"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn the_real_tenant_scoped_metrics_carry_a_real_tenant_label() {
        // The build-time guard: run the actual METRICS table against the
        // actual TENANT_SCOPED_METRICS list. A future edit that drops
        // tenant_id/tenant/workspace/api_key_id from one of these families,
        // or renames the family without updating this list, fails here.
        let errors = tenant_label_gaps(METRICS, TENANT_SCOPED_METRICS, TENANT_LABEL_EXEMPTIONS);
        assert_eq!(errors, vec![], "{errors:?}");
    }
}

#[cfg(test)]
mod run_scoped_label_gap_tests {
    use super::*;

    fn metric(name: &'static str, labels: &'static [&'static str]) -> MetricCapability {
        MetricCapability {
            name,
            kind: MetricKind::Counter,
            writer: Writer::Recorder("record_thing"),
            support: SupportLevel::Stable,
            compat: CompatTier::Beta,
            registry: Registry::Default,
            labels,
            description: "A thing.",
            dead_reason: None,
        }
    }

    #[test]
    fn a_bounded_label_set_passes() {
        let metrics = [metric(
            "sbproxy_thing_total",
            &["route", "outcome", "reason"],
        )];
        assert_eq!(run_scoped_label_gaps(&metrics, &[]), vec![]);
    }

    #[test]
    fn every_forbidden_name_is_caught_on_its_own() {
        for name in RUN_SCOPED_LABEL_NAMES {
            let labels = std::slice::from_ref(name);
            let metrics = [metric("sbproxy_thing_total", labels)];
            let errors = run_scoped_label_gaps(&metrics, &[]);
            assert_eq!(errors.len(), 1, "label {name:?} was not caught: {errors:?}");
        }
    }

    #[test]
    fn a_forbidden_name_is_caught_whatever_its_case() {
        let cases: [&'static [&'static str]; 3] = [&["RUN_ID"], &["RunId"], &["Trace_Id"]];
        for labels in cases {
            let metrics = [metric("sbproxy_thing_total", labels)];
            assert_eq!(
                run_scoped_label_gaps(&metrics, &[]).len(),
                1,
                "label {labels:?} was not caught"
            );
        }
    }

    #[test]
    fn a_qualified_run_scoped_id_is_caught() {
        // The spelling the run-identity rollout is most likely to produce.
        // `parent_request_id` is already a field name on `A2AContext`.
        let cases: [&'static [&'static str]; 5] = [
            &["a2a_task_id"],
            &["parent_request_id"],
            &["agent_run_id"],
            &["upstream_trace_id"],
            &["mcp_session_uuid"],
        ];
        for labels in cases {
            let metrics = [metric("sbproxy_thing_total", labels)];
            let errors = run_scoped_label_gaps(&metrics, &[]);
            assert_eq!(errors.len(), 1, "{labels:?} was not caught: {errors:?}");
        }
    }

    #[test]
    fn bounded_lookalike_labels_are_not_false_positives() {
        // Every one of these is either a live label in METRICS today or the
        // shape a substring match would have wrecked. A guard that cries
        // wolf here gets deleted by the third person who hits it.
        let metrics = [metric(
            "sbproxy_thing_total",
            &[
                "request_class",
                "retry_class",
                "route_class",
                "runtime",
                "truncated",
                "content_shape",
                "api_key_id",
                "key_id",
                "agent_id",
                "node_id",
                "policy_id",
                "rule_id",
                "tenant_id",
                "transition",
                "close_reason",
            ],
        )];
        assert_eq!(run_scoped_label_gaps(&metrics, &[]), vec![]);
    }

    #[test]
    fn the_offending_label_is_named_in_the_error() {
        let metrics = [metric("sbproxy_thing_total", &["route", "run_id"])];
        let errors = run_scoped_label_gaps(&metrics, &[]);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].message.contains("run_id"), "{:?}", errors[0]);
        assert!(
            !errors[0].message.contains("\"route\""),
            "the bounded label should not be blamed: {:?}",
            errors[0]
        );
    }

    #[test]
    fn a_declared_exemption_suppresses_the_violation() {
        let metrics = [metric("sbproxy_thing_total", &["run_id"])];
        let exemptions = [ReferenceExemption {
            metric: "sbproxy_thing_total",
            reason: "the label is read by the migration dashboard until the ledger \
                     view replaces it (WOR-9999).",
        }];
        assert_eq!(run_scoped_label_gaps(&metrics, &exemptions), vec![]);
    }

    #[test]
    fn an_exemption_for_a_metric_that_is_not_in_violation_is_reported() {
        let metrics = [metric("sbproxy_thing_total", &["route"])];
        let exemptions = [ReferenceExemption {
            metric: "sbproxy_thing_total",
            reason: "some historical reason that no longer describes this metric.",
        }];
        let errors = run_scoped_label_gaps(&metrics, &exemptions);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].message.contains("carries no run-scoped"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn an_exemption_for_an_undeclared_metric_is_reported() {
        let metrics: [MetricCapability; 0] = [];
        let exemptions = [ReferenceExemption {
            metric: "sbproxy_missing_total",
            reason: "names a family that no longer exists.",
        }];
        let errors = run_scoped_label_gaps(&metrics, &exemptions);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(
            errors[0].message.contains("not declared in METRICS"),
            "{:?}",
            errors[0]
        );
    }

    #[test]
    fn every_violation_is_reported_in_one_run() {
        let metrics = [
            metric("sbproxy_one_total", &["run_id"]),
            metric("sbproxy_two_total", &["task_id"]),
            metric("sbproxy_three_total", &["route"]),
        ];
        let errors = run_scoped_label_gaps(&metrics, &[]);
        assert_eq!(errors.len(), 2, "{errors:?}");
    }

    #[test]
    fn the_real_metric_table_carries_no_run_scoped_label() {
        // The build-time guard, over the whole table with no opt-in list.
        let errors = run_scoped_label_gaps(METRICS, RUN_SCOPED_LABEL_EXEMPTIONS);
        assert_eq!(errors, vec![], "{errors:?}");
    }
}
