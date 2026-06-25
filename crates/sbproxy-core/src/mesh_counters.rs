//! WOR-1563: distributed per-key spend + rate-limit counters via mesh CRDTs.
//!
//! Per-key spend (tokens and cost) is a grow-only [`GCounter`] and per-key
//! request rate is a [`SlidingWindow`], both keyed by virtual-key id. Each node
//! increments its own slot locally; the mesh gossip loop disseminates the CRDT
//! state, and merging is monotone, so a budget cap or a rate ceiling is coherent
//! across the replica fleet (a key spending on replica A is visible to replica
//! B). Without a running mesh the counters are simply local.
//!
//! Reconciles with the multi-window budgets: this is the cross-replica spend
//! substrate the budget windows read so a per-key cap is enforced fleet-wide
//! rather than per-replica.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use sbproxy_mesh::state::counter::GCounter;
use sbproxy_mesh::state::sliding_window::SlidingWindow;

/// Rate-window bucket size: 1 second.
const RATE_BUCKET_SECS: u64 = 1;
/// Rate-window length: 60 buckets = a rolling minute.
const RATE_WINDOW_BUCKETS: usize = 60;

/// Cross-replica per-key counters.
pub struct MeshKeyCounters {
    node_id: String,
    /// key_id -> cumulative tokens spent.
    spend_tokens: Mutex<HashMap<String, GCounter>>,
    /// key_id -> cumulative cost in micro-USD (1e-6 dollars).
    spend_micros: Mutex<HashMap<String, GCounter>>,
    /// key_id -> rolling request count.
    requests: Mutex<HashMap<String, SlidingWindow>>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl MeshKeyCounters {
    /// Build counters that attribute local increments to `node_id`.
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            spend_tokens: Mutex::new(HashMap::new()),
            spend_micros: Mutex::new(HashMap::new()),
            requests: Mutex::new(HashMap::new()),
        }
    }

    /// Record `tokens` and `cost_usd` of spend against a key.
    pub fn record_spend(&self, key_id: &str, tokens: u64, cost_usd: f64) {
        let micros = (cost_usd.max(0.0) * 1_000_000.0) as u64;
        if tokens > 0 {
            self.spend_tokens
                .lock()
                .expect("spend_tokens lock")
                .entry(key_id.to_string())
                .or_default()
                .increment(&self.node_id, tokens);
        }
        if micros > 0 {
            self.spend_micros
                .lock()
                .expect("spend_micros lock")
                .entry(key_id.to_string())
                .or_default()
                .increment(&self.node_id, micros);
        }
    }

    /// Total tokens spent against a key across all merged replicas.
    pub fn spend_tokens(&self, key_id: &str) -> u64 {
        self.spend_tokens
            .lock()
            .expect("spend_tokens lock")
            .get(key_id)
            .map(GCounter::value)
            .unwrap_or(0)
    }

    /// Total cost in USD spent against a key across all merged replicas.
    pub fn spend_usd(&self, key_id: &str) -> f64 {
        let micros = self
            .spend_micros
            .lock()
            .expect("spend_micros lock")
            .get(key_id)
            .map(GCounter::value)
            .unwrap_or(0);
        micros as f64 / 1_000_000.0
    }

    /// Record a single request against a key's rate window.
    pub fn record_request(&self, key_id: &str) {
        let now = unix_now();
        self.requests
            .lock()
            .expect("requests lock")
            .entry(key_id.to_string())
            .or_insert_with(|| SlidingWindow::new(RATE_BUCKET_SECS, RATE_WINDOW_BUCKETS))
            .increment(&self.node_id, now);
    }

    /// Requests against a key in the trailing window across all merged replicas.
    pub fn request_count(&self, key_id: &str) -> u64 {
        let now = unix_now();
        self.requests
            .lock()
            .expect("requests lock")
            .get(key_id)
            .map(|w| w.count(now))
            .unwrap_or(0)
    }

    /// Merge another node's counters into ours (the CRDT merge the gossip loop
    /// applies when a peer's state arrives). Monotone: only grows.
    pub fn merge_peer(&self, other: &MeshKeyCounters) {
        merge_gcounters(&self.spend_tokens, &other.spend_tokens);
        merge_gcounters(&self.spend_micros, &other.spend_micros);
        let mut ours = self.requests.lock().expect("requests lock");
        for (k, w) in other.requests.lock().expect("peer requests lock").iter() {
            ours.entry(k.clone())
                .or_insert_with(|| SlidingWindow::new(RATE_BUCKET_SECS, RATE_WINDOW_BUCKETS))
                .merge(w);
        }
    }
}

fn merge_gcounters(
    ours: &Mutex<HashMap<String, GCounter>>,
    theirs: &Mutex<HashMap<String, GCounter>>,
) {
    let mut ours = ours.lock().expect("gcounter lock");
    for (k, g) in theirs.lock().expect("peer gcounter lock").iter() {
        ours.entry(k.clone()).or_default().merge(g);
    }
}

fn slot() -> &'static ArcSwapOption<MeshKeyCounters> {
    static SLOT: OnceLock<ArcSwapOption<MeshKeyCounters>> = OnceLock::new();
    SLOT.get_or_init(|| ArcSwapOption::from(None))
}

/// The installed cross-replica counters, or `None` when the mesh tier is off.
pub fn current_mesh_counters() -> Option<Arc<MeshKeyCounters>> {
    slot().load_full()
}

/// Install (or replace) the cross-replica counters.
pub fn install_mesh_counters(counters: Arc<MeshKeyCounters>) {
    slot().store(Some(counters));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spend_is_coherent_across_replicas_after_merge() {
        // Two replicas each record spend for the same key against their own
        // node slot; the grow-only counter merges to the combined total.
        let a = MeshKeyCounters::new("node-a");
        let b = MeshKeyCounters::new("node-b");
        a.record_spend("k1", 100, 0.50);
        a.record_spend("k1", 50, 0.25);
        b.record_spend("k1", 200, 1.00);

        assert_eq!(a.spend_tokens("k1"), 150);
        assert_eq!(b.spend_tokens("k1"), 200);

        a.merge_peer(&b);
        assert_eq!(a.spend_tokens("k1"), 350, "merged token spend");
        assert!((a.spend_usd("k1") - 1.75).abs() < 1e-9, "merged usd spend");

        // Merge is idempotent (re-merging the same peer does not double-count).
        a.merge_peer(&b);
        assert_eq!(a.spend_tokens("k1"), 350);
    }

    #[test]
    fn request_rate_merges_across_replicas() {
        let a = MeshKeyCounters::new("node-a");
        let b = MeshKeyCounters::new("node-b");
        a.record_request("k1");
        a.record_request("k1");
        b.record_request("k1");

        assert_eq!(a.request_count("k1"), 2);
        a.merge_peer(&b);
        assert_eq!(a.request_count("k1"), 3, "merged request rate");
    }

    #[test]
    fn unknown_key_reads_zero() {
        let c = MeshKeyCounters::new("n");
        assert_eq!(c.spend_tokens("missing"), 0);
        assert_eq!(c.spend_usd("missing"), 0.0);
        assert_eq!(c.request_count("missing"), 0);
    }
}
