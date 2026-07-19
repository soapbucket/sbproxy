//! Prometheus metrics for the mesh crate.
//!
//! All metrics register on the global default Prometheus registry so they
//! flow through the existing enterprise metrics exposition automatically.
//! Names use a `mesh_*` prefix to group them separately from the semantic
//! cache (`semcache_*`) and the AI gateway (`sbproxy_ai_*`).
//!
//! # Cardinality
//!
//! `reason` and `state` labels are drawn from fixed small enums. `target`
//! and `node_id` carry a peer address / node id, so callers must avoid
//! pushing unbounded-cardinality values through this label (in practice
//! peers come from the membership list, which is naturally bounded by
//! cluster size).
//!
//! # Failure policy
//!
//! Registration failures panic on first access via the `LazyLock`
//! initializer, mirroring the enterprise-ai metrics module. A duplicate
//! metric registration is a crate-internal bug that should surface during
//! CI, not silently at runtime.

use std::sync::LazyLock;

use prometheus::{
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts,
};

// --- Eviction / membership counters ---

/// Count of peers evicted from the membership list + hash ring.
///
/// Labels: `reason` (`probe_timeout` | `dead_timeout` | `graceful_leave`).
pub static MESH_PEER_EVICTED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new("mesh_peer_evicted_total", "Peers evicted from the mesh"),
        &["reason"]
    )
    .expect("register mesh_peer_evicted_total")
});

// --- Gossip retry counter ---

/// Number of gossip retries against a peer. Incremented once per retry
/// attempt (not per send).
///
/// Labels: `target` (peer address or node id).
pub static MESH_GOSSIP_RETRY: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_gossip_retry_total",
            "Gossip retries against a specific peer"
        ),
        &["target"]
    )
    .expect("register mesh_gossip_retry_total")
});

// --- Membership gauges ---

/// Number of peers currently in each membership state.
///
/// Labels: `state` (`alive` | `suspect` | `dead`).
pub static MESH_PEER_COUNT: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        Opts::new("mesh_peer_count", "Peer count by state"),
        &["state"]
    )
    .expect("register mesh_peer_count")
});

/// Set to `1` when the local node is in split-brain / quarantine mode
/// (peer count below configured minimum), `0` when healthy.
///
/// Labels: `node_id` (local node identifier).
pub static MESH_NODE_ISOLATED: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        Opts::new(
            "mesh_node_isolated",
            "1 if this node is isolated / in quarantine, 0 otherwise"
        ),
        &["node_id"]
    )
    .expect("register mesh_node_isolated")
});

// --- Crypto ---

/// Count of messages dropped on the receive side due to failed AEAD
/// decryption (tag mismatch or structurally malformed input) on a node
/// that has encryption enabled.
///
/// Labels: `kind` (`gossip` | `transport`). K3 adds these as the only two
/// crypto boundaries in the mesh.
pub static MESH_CRYPTO_DECRYPT_FAILED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_crypto_decrypt_failed_total",
            "Messages dropped due to failed AEAD decrypt"
        ),
        &["kind"]
    )
    .expect("register mesh_crypto_decrypt_failed_total")
});

/// `kind` label for [`MESH_CRYPTO_DECRYPT_FAILED`]: UDP gossip heartbeat
/// failed to decrypt.
pub const CRYPTO_KIND_GOSSIP: &str = "gossip";
/// `kind` label for [`MESH_CRYPTO_DECRYPT_FAILED`]: TCP cache-RPC frame
/// failed to decrypt.
pub const CRYPTO_KIND_TRANSPORT: &str = "transport";

// --- Gossip probe RTT ---

/// Round-trip time for gossip probe messages.
///
/// Labels: `target` (peer address or node id).
pub static MESH_GOSSIP_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        HistogramOpts::new(
            "mesh_gossip_probe_duration_seconds",
            "Gossip probe round-trip time, seconds"
        ),
        &["target"]
    )
    .expect("register mesh_gossip_probe_duration_seconds")
});

// --- SWIM probe outcomes (K4) ---

/// Count of direct `PING` probes whose `ACK` arrived inside the configured
/// `swim_ping_timeout_ms` window.
///
/// Labels: `target` (peer node id or address).
pub static MESH_PROBE_DIRECT_SUCCESS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_probe_direct_success_total",
            "Direct pings with timely ACK"
        ),
        &["target"]
    )
    .expect("register mesh_probe_direct_success_total")
});

/// Count of direct `PING` probes that did NOT receive an `ACK` inside the
/// configured `swim_ping_timeout_ms` window. A direct timeout triggers the
/// indirect (PING-REQ) fallback path.
///
/// Labels: `target` (peer node id or address).
pub static MESH_PROBE_DIRECT_TIMEOUT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_probe_direct_timeout_total",
            "Direct pings without ACK in window"
        ),
        &["target"]
    )
    .expect("register mesh_probe_direct_timeout_total")
});

/// Count of indirect (PING-REQ) probes that eventually resolved with at
/// least one witness reporting the target alive. A successful indirect
/// probe rescues the target from the Suspect transition.
///
/// Labels: `target` (peer node id or address).
pub static MESH_PROBE_INDIRECT_SUCCESS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_probe_indirect_success_total",
            "PING-REQ that eventually resolved alive"
        ),
        &["target"]
    )
    .expect("register mesh_probe_indirect_success_total")
});

/// Count of peer state transitions observed by the SWIM loop.
///
/// Labels: `from` (`alive` | `suspect` | `dead`), `to` (same enum).
pub static MESH_SUSPECT_TRANSITIONS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_peer_state_transitions_total",
            "Alive/Suspect/Dead transitions"
        ),
        &["from", "to"]
    )
    .expect("register mesh_peer_state_transitions_total")
});

// --- Dissemination (L1) ---

/// Count of `PeerUpdate`s stamped onto outgoing PING/ACK messages by the
/// local disseminator. A burst of outgoing updates (self refutation,
/// transitions just observed) is counted once per piggybacked entry, not
/// once per message.
///
/// Labels: `kind` (`ping` | `ack`).
pub static MESH_DISSEMINATION_UPDATES_SENT: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_dissemination_updates_sent_total",
            "PeerUpdates stamped on outgoing messages"
        ),
        &["kind"]
    )
    .expect("register mesh_dissemination_updates_sent_total")
});

/// Count of inbound `PeerUpdate`s that resulted in an observable local
/// state change (Alive -> Suspect, Suspect -> Alive via refutation, etc.).
/// The `transition` label carries a concatenation of the prior and new
/// states (`alive_to_suspect`, `suspect_to_alive`, `alive_to_dead`,
/// `suspect_to_dead`, `dead_to_alive`, `self_refutation`).
///
/// Labels: `transition`.
pub static MESH_DISSEMINATION_UPDATES_APPLIED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_dissemination_updates_applied_total",
            "PeerUpdates that resulted in a local state change"
        ),
        &["transition"]
    )
    .expect("register mesh_dissemination_updates_applied_total")
});

/// Count of inbound `PeerUpdate`s that were dropped without mutating the
/// local peer table. Usually this means the incoming incarnation was
/// stale compared to what we already know, or the peer is unknown to us.
///
/// Labels: `reason` (`stale_incarnation` | `unknown_peer` |
/// `terminal_dead` | `no_change`).
pub static MESH_DISSEMINATION_UPDATES_IGNORED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_dissemination_updates_ignored_total",
            "PeerUpdates dropped due to stale incarnation or no change"
        ),
        &["reason"]
    )
    .expect("register mesh_dissemination_updates_ignored_total")
});

// --- Dissemination label values ---

/// `kind` label for [`MESH_DISSEMINATION_UPDATES_SENT`]: update rode on a
/// PING.
pub const DISSEM_KIND_PING: &str = "ping";
/// `kind` label for [`MESH_DISSEMINATION_UPDATES_SENT`]: update rode on an
/// ACK.
pub const DISSEM_KIND_ACK: &str = "ack";

/// `transition` label: Alive -> Suspect.
pub const DISSEM_TRANS_ALIVE_SUSPECT: &str = "alive_to_suspect";
/// `transition` label: Suspect -> Alive (refutation).
pub const DISSEM_TRANS_SUSPECT_ALIVE: &str = "suspect_to_alive";
/// `transition` label: Alive -> Dead (skipping Suspect).
pub const DISSEM_TRANS_ALIVE_DEAD: &str = "alive_to_dead";
/// `transition` label: Suspect -> Dead.
pub const DISSEM_TRANS_SUSPECT_DEAD: &str = "suspect_to_dead";
/// `transition` label: Dead -> Alive (rejoin).
pub const DISSEM_TRANS_DEAD_ALIVE: &str = "dead_to_alive";
/// `transition` label: local self-refutation (we learned we were Suspect
/// about ourselves, bumped incarnation, and queued a fresh Alive).
pub const DISSEM_TRANS_SELF_REFUTATION: &str = "self_refutation";

/// `reason` label: the incoming incarnation is less than our stored one.
pub const DISSEM_IGNORE_STALE_INCARNATION: &str = "stale_incarnation";
/// `reason` label: the update references a peer not in our table.
pub const DISSEM_IGNORE_UNKNOWN_PEER: &str = "unknown_peer";
/// `reason` label: the local entry is Dead and the update is not a
/// higher-incarnation Alive, so it stays terminal.
pub const DISSEM_IGNORE_TERMINAL_DEAD: &str = "terminal_dead";
/// `reason` label: the update would produce the same observable state as
/// the current entry (common steady-state case).
pub const DISSEM_IGNORE_NO_CHANGE: &str = "no_change";

// --- Dead-peer GC (L2) ---

/// Count of peers removed from the local peer table by the L2 dead-peer
/// garbage collector. One increment per removed entry; a single sweep
/// that GCs N peers bumps this counter by N. Unlabeled because the only
/// dimension (reason) is fixed: the peer had been `Dead` for longer than
/// the configured `dead_peer_gc_secs`.
pub static MESH_DEAD_PEERS_GC: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "mesh_dead_peers_gc_total",
        "Dead peers removed from the peer table by GC"
    )
    .expect("register mesh_dead_peers_gc_total")
});

// --- Address map refresh (L3) ---

/// Count of updates to the shared `node_id -> host:port` peer address map
/// driven by gossip learnings. Every gossip-learned `(node_id, addr)` pair
/// either inserts a fresh mapping (`learned`) or rewrites an existing one
/// whose address changed (`rewritten`).
///
/// Labels: `kind` (`learned` | `rewritten`).
pub static MESH_ADDR_MAP_UPDATES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_addr_map_updates_total",
            "Peer address map updates driven by gossip learnings"
        ),
        &["kind"]
    )
    .expect("register mesh_addr_map_updates_total")
});

/// `kind` label for [`MESH_ADDR_MAP_UPDATES`]: a previously unknown
/// `(node_id, addr)` mapping was inserted by the gossip loop.
pub const ADDR_MAP_KIND_LEARNED: &str = "learned";
/// `kind` label for [`MESH_ADDR_MAP_UPDATES`]: an existing mapping was
/// rewritten because the address changed (e.g. pod restart with a new IP).
pub const ADDR_MAP_KIND_REWRITTEN: &str = "rewritten";

// --- Persistence metrics (Phase 2/3) ---

/// Snapshot write attempts by outcome.
///
/// Labels: `outcome` (`ok` | `fail`).
pub static MESH_PERSISTENCE_SNAPSHOTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_persistence_snapshots_total",
            "Redis snapshot writes by outcome"
        ),
        &["outcome"]
    )
    .expect("register mesh_persistence_snapshots_total")
});

/// Total bytes written in successful snapshots.
pub static MESH_PERSISTENCE_BYTES: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(Opts::new(
        "mesh_persistence_bytes_total",
        "Total bytes of PersistedState written to Redis"
    ))
    .expect("register mesh_persistence_bytes_total")
});

/// Cold-start snapshot load outcomes.
///
/// Labels: `outcome` (`merged` | `stale` | `corrupt`).
pub static MESH_COLD_START_SNAPSHOTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_cold_start_snapshots_total",
            "Snapshots encountered during cold-start hydration, by outcome"
        ),
        &["outcome"]
    )
    .expect("register mesh_cold_start_snapshots_total")
});

// --- Federation metrics (Phase 4/5) ---

/// Federation summary push attempts by outcome.
///
/// Labels: `outcome` (`ok` | `fail`).
pub static MESH_FEDERATION_PUSH: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_federation_push_total",
            "Federation leader summary/heartbeat push by outcome"
        ),
        &["outcome"]
    )
    .expect("register mesh_federation_push_total")
});

/// Federation peer pull attempts by outcome.
///
/// Labels: `outcome` (`ok` | `stale` | `missing` | `fail`).
pub static MESH_FEDERATION_PULL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_federation_pull_total",
            "Federation peer pull attempts by outcome"
        ),
        &["outcome"]
    )
    .expect("register mesh_federation_pull_total")
});

/// Current count of known federation peer clusters.
pub static MESH_FEDERATION_PEERS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        Opts::new(
            "mesh_federation_peers",
            "Number of known peer clusters in the federation, by state"
        ),
        &["state"]
    )
    .expect("register mesh_federation_peers")
});

/// `outcome` label values shared by persistence and federation metrics.
pub const OUTCOME_OK: &str = "ok";
/// `outcome` label for write or pull failure.
pub const OUTCOME_FAIL: &str = "fail";
/// `outcome` label for pull where the peer heartbeat is too old.
pub const OUTCOME_STALE: &str = "stale";
/// `outcome` label for pull where the peer summary or heartbeat key is absent.
pub const OUTCOME_MISSING: &str = "missing";
/// `outcome` label for cold-start snapshots merged into local state.
pub const OUTCOME_MERGED: &str = "merged";
/// `outcome` label for cold-start snapshots too old to merge.
pub const OUTCOME_STALE_SNAPSHOT: &str = "stale";
/// `outcome` label for cold-start snapshots that failed to deserialize.
pub const OUTCOME_CORRUPT: &str = "corrupt";

// --- Replicated substrate (WOR-1947) ---

/// Replicated writes by terminal outcome, as seen by the coordinator.
///
/// Labels: `outcome` (`acked` | `quorum_failed`).
pub static MESH_REPLICATION_WRITES: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_replication_writes_total",
            "Replicated substrate writes by coordinator outcome"
        ),
        &["outcome"]
    )
    .expect("register mesh_replication_writes_total")
});

/// `outcome` label for [`MESH_REPLICATION_WRITES`]: the configured write
/// consistency was met.
pub const REPLICATION_OUTCOME_ACKED: &str = "acked";
/// `outcome` label for [`MESH_REPLICATION_WRITES`]: fewer replicas acked
/// than the consistency level required.
pub const REPLICATION_OUTCOME_QUORUM_FAILED: &str = "quorum_failed";

/// Stale replicas repaired in-line by quorum reads.
pub static MESH_REPLICATION_READ_REPAIRS: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "mesh_replication_read_repairs_total",
        "Stale replicas repaired in-line by replicated reads"
    )
    .expect("register mesh_replication_read_repairs_total")
});

/// Completed maintenance rounds (handoff + anti-entropy + tombstone GC).
pub static MESH_ANTI_ENTROPY_ROUNDS: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "mesh_anti_entropy_rounds_total",
        "Completed replicated-substrate maintenance rounds"
    )
    .expect("register mesh_anti_entropy_rounds_total")
});

/// Records reconciled by anti-entropy, by direction.
///
/// Labels: `direction` (`push` | `pull`).
pub static MESH_ANTI_ENTROPY_KEYS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_anti_entropy_keys_total",
            "Records reconciled by replicated-substrate anti-entropy"
        ),
        &["direction"]
    )
    .expect("register mesh_anti_entropy_keys_total")
});

/// `direction` label for [`MESH_ANTI_ENTROPY_KEYS`]: a newer local record
/// was pushed to a peer.
pub const ANTI_ENTROPY_DIRECTION_PUSH: &str = "push";
/// `direction` label for [`MESH_ANTI_ENTROPY_KEYS`]: a newer peer record
/// was pulled into the local shard.
pub const ANTI_ENTROPY_DIRECTION_PULL: &str = "pull";

/// Tombstone GC decisions.
///
/// Labels: `outcome` (`collected` | `deferred`).
pub static MESH_TOMBSTONE_GC: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_tombstone_gc_total",
            "Ack-aware tombstone garbage collection decisions"
        ),
        &["outcome"]
    )
    .expect("register mesh_tombstone_gc_total")
});

/// `outcome` label for [`MESH_TOMBSTONE_GC`]: every replica confirmed the
/// tombstone past its grace period; it was physically collected.
pub const GC_OUTCOME_COLLECTED: &str = "collected";
/// `outcome` label for [`MESH_TOMBSTONE_GC`]: confirmation is still
/// missing from at least one replica; collection was deferred.
pub const GC_OUTCOME_DEFERRED: &str = "deferred";

/// Ring-change handoff decisions.
///
/// Labels: `outcome` (`moved` | `retained`).
pub static MESH_HANDOFF_KEYS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        Opts::new(
            "mesh_handoff_keys_total",
            "Replicated records handed off after ring changes"
        ),
        &["outcome"]
    )
    .expect("register mesh_handoff_keys_total")
});

/// `outcome` label for [`MESH_HANDOFF_KEYS`]: every current replica acked
/// the record; the local copy was dropped.
pub const HANDOFF_OUTCOME_MOVED: &str = "moved";
/// `outcome` label for [`MESH_HANDOFF_KEYS`]: at least one replica did
/// not ack; the local copy is retained for the next round.
pub const HANDOFF_OUTCOME_RETAINED: &str = "retained";

/// Records currently held by the local replica shard (live plus
/// tombstones). Refreshed once per maintenance round.
pub static MESH_REPLICA_SHARD_ENTRIES: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "mesh_replica_shard_entries",
        "Records held by the local replicated-substrate shard"
    )
    .expect("register mesh_replica_shard_entries")
});

// --- Fixed label values ---

/// `reason` label for [`MESH_PEER_EVICTED`]: exceeded consecutive probe
/// failure threshold.
pub const EVICT_REASON_PROBE_TIMEOUT: &str = "probe_timeout";
/// `reason` label for [`MESH_PEER_EVICTED`]: crossed the SWIM
/// `dead_timeout` without any heartbeat.
pub const EVICT_REASON_DEAD_TIMEOUT: &str = "dead_timeout";
/// `reason` label for [`MESH_PEER_EVICTED`]: peer sent a graceful
/// `LeaveRequest`.
pub const EVICT_REASON_GRACEFUL_LEAVE: &str = "graceful_leave";

/// `state` label for [`MESH_PEER_COUNT`]: peer is alive.
pub const PEER_STATE_ALIVE: &str = "alive";
/// `state` label for [`MESH_PEER_COUNT`]: peer is suspect.
pub const PEER_STATE_SUSPECT: &str = "suspect";
/// `state` label for [`MESH_PEER_COUNT`]: peer is dead.
pub const PEER_STATE_DEAD: &str = "dead";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_evicted_counter_increments() {
        // Use a unique reason value per test to avoid cross-test pollution
        // on the process-global registry.
        let before = MESH_PEER_EVICTED
            .with_label_values(&["unit_test_reason"])
            .get();
        MESH_PEER_EVICTED
            .with_label_values(&["unit_test_reason"])
            .inc();
        let after = MESH_PEER_EVICTED
            .with_label_values(&["unit_test_reason"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn gossip_retry_counter_increments() {
        let before = MESH_GOSSIP_RETRY
            .with_label_values(&["unit-test-target:7946"])
            .get();
        MESH_GOSSIP_RETRY
            .with_label_values(&["unit-test-target:7946"])
            .inc();
        let after = MESH_GOSSIP_RETRY
            .with_label_values(&["unit-test-target:7946"])
            .get();
        assert_eq!(after, before + 1);
    }

    #[test]
    fn peer_count_gauge_set_and_get() {
        MESH_PEER_COUNT.with_label_values(&["alive"]).set(7);
        assert_eq!(MESH_PEER_COUNT.with_label_values(&["alive"]).get(), 7);
        MESH_PEER_COUNT.with_label_values(&["alive"]).set(0);
    }

    #[test]
    fn node_isolated_gauge_toggles() {
        MESH_NODE_ISOLATED
            .with_label_values(&["unit-test-node"])
            .set(1);
        assert_eq!(
            MESH_NODE_ISOLATED
                .with_label_values(&["unit-test-node"])
                .get(),
            1
        );
        MESH_NODE_ISOLATED
            .with_label_values(&["unit-test-node"])
            .set(0);
        assert_eq!(
            MESH_NODE_ISOLATED
                .with_label_values(&["unit-test-node"])
                .get(),
            0
        );
    }

    #[test]
    fn crypto_decrypt_failed_counter_increments_per_kind() {
        // Each `kind` label gets its own counter; bumping one must not
        // affect the other.
        let before_gossip = MESH_CRYPTO_DECRYPT_FAILED
            .with_label_values(&[CRYPTO_KIND_GOSSIP])
            .get();
        let before_transport = MESH_CRYPTO_DECRYPT_FAILED
            .with_label_values(&[CRYPTO_KIND_TRANSPORT])
            .get();
        MESH_CRYPTO_DECRYPT_FAILED
            .with_label_values(&[CRYPTO_KIND_GOSSIP])
            .inc();
        assert_eq!(
            MESH_CRYPTO_DECRYPT_FAILED
                .with_label_values(&[CRYPTO_KIND_GOSSIP])
                .get(),
            before_gossip + 1
        );
        assert_eq!(
            MESH_CRYPTO_DECRYPT_FAILED
                .with_label_values(&[CRYPTO_KIND_TRANSPORT])
                .get(),
            before_transport
        );
    }

    #[test]
    fn dead_peers_gc_counter_increments() {
        let before = MESH_DEAD_PEERS_GC.get();
        MESH_DEAD_PEERS_GC.inc();
        MESH_DEAD_PEERS_GC.inc();
        let after = MESH_DEAD_PEERS_GC.get();
        assert_eq!(after, before + 2);
    }

    #[test]
    fn addr_map_updates_counter_increments_per_kind() {
        // Each `kind` label has its own counter; bumping one must not
        // affect the other.
        let before_learned = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_LEARNED])
            .get();
        let before_rewritten = MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_REWRITTEN])
            .get();
        MESH_ADDR_MAP_UPDATES
            .with_label_values(&[ADDR_MAP_KIND_LEARNED])
            .inc();
        assert_eq!(
            MESH_ADDR_MAP_UPDATES
                .with_label_values(&[ADDR_MAP_KIND_LEARNED])
                .get(),
            before_learned + 1
        );
        assert_eq!(
            MESH_ADDR_MAP_UPDATES
                .with_label_values(&[ADDR_MAP_KIND_REWRITTEN])
                .get(),
            before_rewritten
        );
    }

    #[test]
    fn gossip_latency_histogram_observes() {
        // Just exercise the observation path; prometheus HistogramVec does not
        // expose per-bucket reads directly, so verify via sample count.
        let hist = MESH_GOSSIP_LATENCY.with_label_values(&["unit-test-peer"]);
        let before = hist.get_sample_count();
        hist.observe(0.001);
        hist.observe(0.010);
        let after = hist.get_sample_count();
        assert_eq!(after, before + 2);
    }
}
