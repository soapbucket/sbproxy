// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Every metric SBproxy emits, and what we are willing to promise about it.
//!
//! This table is the metrics half of the executable capability registry. It
//! exists because `docs/metrics-stability.md` was hand-maintained, and a
//! hand-maintained catalogue drifts in exactly one direction: toward claiming
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
        name: "mesh_transport_rpc_duration_seconds",
        kind: MetricKind::Histogram,
        writer: Writer::Recorder("MESH_TRANSPORT_RPC_DURATION"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["op"],
        description: "Successful cross-node cache RPC duration, by operation.",
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
        description: "Cross-node cache RPC failures, by transport phase.",
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
        description: "A2A hops denied by the a2a policy, labelled by route and reason.",
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
        description: "A2A hops observed by the proxy, labelled by route, spec, and policy decision.",
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
    MetricCapability {
        name: "sbproxy_agent_budget_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_decision"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["agent_id", "outcome"],
        description: "agent_budget policy verdicts, labelled by agent and outcome.",
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
        description: "Budget utilization as ratio 0-1.",
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
        description: "Cascade routing tier outcomes (accepted | retry | cost_cap).",
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
        name: "sbproxy_ai_cost_dollars_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_request_attributed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model", "surface", "project", "feature", "team", "agent_type", "environment", "tenant_id", "api_key_id"],
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
        description: "AI provider attempts during failover/selection, by provider and outcome.",
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
        name: "sbproxy_ai_requests_attributed_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_ai_outcome_attributed"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model", "surface", "tenant_id", "api_key_id", "outcome"],
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
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["provider", "model", "surface", "direction", "project", "feature", "team", "agent_type", "environment", "tenant_id", "api_key_id"],
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
        labels: &["provider", "surface"],
        description: "2xx AI responses on a token surface that carried no parseable usage block (budget debited from an estimate).",
        dead_reason: None,
    },
    MetricCapability {
        name: "sbproxy_ai_wasted_cost_dollars_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_waste"),
        support: SupportLevel::Stable,
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
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["kind", "provider", "model", "surface", "project", "feature", "team", "agent_type", "environment"],
        description: "AI tokens classified as wasted, by waste class.",
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
             file allowlist), not in sbproxy-observe",
        ),
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
    // the `hooks` lane is ever instantiated. It is registered on the proxy
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
        description: "Bounded channel sends dropped on the hot path, labelled by drop reason.",
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
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["model"],
        description: "Requests queued while a model loads, by model.",
        dead_reason: Some(
            "nothing calls it. The setter (set_model_host_load_queue_depth, \
             crates/sbproxy-observe/src/metrics.rs) exists and is unit-tested, but the actual \
             queueing during a cold model load happens in sbproxy-model-host, which WOR-1903 \
             owns exclusively while a scalar-to-set refactor lands there (see the matching \
             REFERENCE_EXEMPTIONS entry below for SBProxyModelHostLoadQueueBackedUp). Do not \
             wire this from this lane; WOR-1898 picks it back up once WOR-1903 clears",
        ),
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
        name: "sbproxy_object_authz_violations_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("record_object_authz_violation"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["origin", "kind"],
        description: "Object/function-level authorization violations, by kind (bola, bfla, enumeration).",
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
        description: "Age of the cached OCSP staple for the host, in seconds.",
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
    MetricCapability {
        name: "sbproxy_outbound_webhook_attempts_total",
        kind: MetricKind::Counter,
        writer: Writer::Recorder("attempts_counter"),
        support: SupportLevel::Stable,
        compat: CompatTier::Beta,
        registry: Registry::Default,
        labels: &["tenant_id", "event_type", "result"],
        description: "Outbound webhook delivery attempts grouped by tenant, event type, and result.",
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
        description: "Policy decisions emitted on the audit event bus, labelled by verdict, surface, and policy_id.",
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
    MetricCapability {
        name: "sbproxy_projection_render_failures_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["projection"],
        description: "Well-known projection render failures, by projection.",
        dead_reason: Some(
            "nothing calls it, not even a test. WOR-1101 built the recorder \
             (record_projection_render_failure, crates/sbproxy-observe/src/metrics.rs) so a \
             failed robots.txt / llms.txt / similar well-known-projection render on config \
             reload would be visible instead of silently serving stale or empty output. The \
             projection renderers live in crates/sbproxy-modules/src/projections/ and \
             crates/sbproxy-modules/src/transform/llms_txt.rs, out of this lane's file \
             allowlist; wire the failure path there or delete under WOR-1898",
        ),
    },
    MetricCapability {
        name: "sbproxy_rate_limit_decisions_total",
        kind: MetricKind::Counter,
        writer: Writer::Nothing,
        support: SupportLevel::ConfigOnly,
        compat: CompatTier::Alpha,
        registry: Registry::Default,
        labels: &["policy", "result"],
        description: "Rate-limit middleware decisions, by policy and outcome.",
        dead_reason: Some(
            "nothing calls it, not even a test. This is a finer-grained view than the \
             already-Stable sbproxy_policy_triggers_total{policy_type=\"rate_limit\"} (which \
             only distinguishes allow/deny): its allow/throttle_route/throttle_tenant/disabled \
             result set requires the per-route rate-limit policy in \
             crates/sbproxy-modules/src/policy/rate_limit.rs (RateLimitPolicy::allow_with_info*) \
             to call it, which is out of this lane's file allowlist. Wire it there or delete \
             under WOR-1898",
        ),
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
             store/redis.rs:56,101 each drop a cleanup error with `let _ = ...`. That crate is \
             out of this lane's file allowlist; wire record_silent_degradation(op) at those \
             sites or delete under WOR-1898",
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
];

/// Dashboards and alert rules that knowingly read a metric nothing writes.
///
/// The escape hatch from the drift guard, and deliberately a narrow one: an
/// entry costs a line in a reviewed table and a ticket number. That is the
/// whole difference between "known dead" as a decision and "known dead" as an
/// accident. Everything here is a panel or rule that draws a flat zero today
/// and will draw real data when its ticket lands.
pub const REFERENCE_EXEMPTIONS: &[ReferenceExemption] = &[ReferenceExemption {
    metric: "sbproxy_model_host_load_queue_depth",
    reason: "SBProxyModelHostLoadQueueBackedUp alerts on a gauge nobody sets, \
                 so it cannot fire. The setter lives in sbproxy-model-host, which \
                 WOR-1903 owns exclusively while the scalar-to-set refactor lands. \
                 Wired by WOR-1898 once that clears.",
}];

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
    "sbproxy_http_framing_blocks_total",
    "sbproxy_judge_budget_exhausted_total",
    "sbproxy_label_cardinality_overflow_per_tenant_total",
    "sbproxy_outbound_webhook_attempts_total",
    "sbproxy_policy_audit_events_dropped_total",
    "sbproxy_rate_limit_suspend_total",
    "sbproxy_rate_limit_total",
    "sbproxy_semantic_cache_results_total",
    "sbproxy_waf_persistent_blocks_total",
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

/// Render the catalogue published as `docs/metrics-stability.md`.
///
/// Deterministic and byte-stable: `scripts/check-metrics-stability.sh`
/// regenerates it and diffs, so the committed file cannot drift from the code.
/// Hand-editing it is not so much forbidden as pointless.
pub fn render_markdown() -> String {
    let mut out = String::from(
        "# Metrics stability\n\
         *Last modified: 2026-07-19*\n\n\
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
         `alpha` names may be renamed, relabeled, or removed in any release.\n\n\
         ## Catalogue\n\n",
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
