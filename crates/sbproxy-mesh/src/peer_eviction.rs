//! Peer eviction policy + hash-ring signaling.
//!
//! Wraps `PeerHealthMonitor` with a consecutive-probe-failure counter and a
//! pluggable "evict" callback. When a peer crosses the configured threshold
//! (`max_consecutive_failures`, default 3), the callback fires  -  typically
//! removing the peer from the `DistributedCache` consistent hash ring  -  and
//! a `mesh_peer_evicted_total{reason}` metric is incremented.
//!
//! Keeping the eviction logic in a standalone module (rather than embedding
//! it in `PeerHealthMonitor`) lets tests exercise the eviction path without
//! spinning up real gossip transport, and lets future callers (rate-limit
//! sync, CRDT replication) reuse the same pattern with a different
//! callback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;

use crate::metrics;
use crate::state::distributed_cache::DistributedCache;

/// Default threshold: three consecutive probe failures triggers eviction.
/// Matches the SWIM recommendation of ~3 misses before giving up.
pub const DEFAULT_MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Callback invoked when a peer is evicted. The callback receives the
/// peer's node id / address and is responsible for side-effects such as
/// removing the peer from the distributed cache's hash ring.
pub type EvictCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Tracks consecutive probe failures per peer and drives eviction when a
/// peer crosses the configured threshold.
pub struct PeerEvictor {
    failures: Mutex<HashMap<String, u32>>,
    max_consecutive_failures: u32,
    on_evict: EvictCallback,
}

impl PeerEvictor {
    /// Build an evictor with an arbitrary callback. Mostly useful for
    /// tests; production callers should prefer
    /// [`PeerEvictor::for_distributed_cache`] which plugs the hash ring
    /// in directly.
    pub fn new(max_consecutive_failures: u32, on_evict: EvictCallback) -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            max_consecutive_failures: max_consecutive_failures.max(1),
            on_evict,
        }
    }

    /// Build an evictor whose callback removes the peer from the given
    /// distributed cache's consistent hash ring. This is the expected
    /// production wiring: when a peer dies, routing decisions made by
    /// [`DistributedCache::responsible_node`] stop returning it.
    pub fn for_distributed_cache(
        max_consecutive_failures: u32,
        cache: Arc<DistributedCache<Bytes>>,
    ) -> Self {
        let cache_ref = cache.clone();
        let cb: EvictCallback = Arc::new(move |peer: &str| {
            cache_ref.remove_node(peer);
        });
        Self::new(max_consecutive_failures, cb)
    }

    /// Record a successful probe against `peer`. Resets the failure
    /// counter so transient hiccups do not accumulate indefinitely.
    pub fn record_success(&self, peer: &str) {
        let mut map = self.failures.lock().expect("mutex poisoned");
        map.insert(peer.to_string(), 0);
    }

    /// Record a failed probe against `peer`. Returns `true` iff this
    /// failure crossed the threshold and the eviction callback fired.
    /// Subsequent calls after eviction are no-ops until `record_success`
    /// is called (the failure count continues to increment but the
    /// callback is only invoked once per "streak"  -  exactly at the
    /// threshold).
    pub fn record_failure(&self, peer: &str) -> bool {
        let (fired, count) = {
            let mut map = self.failures.lock().expect("mutex poisoned");
            let entry = map.entry(peer.to_string()).or_insert(0);
            let prev = *entry;
            *entry = entry.saturating_add(1);
            let fired =
                prev < self.max_consecutive_failures && *entry >= self.max_consecutive_failures;
            (fired, *entry)
        };

        if fired {
            (self.on_evict)(peer);
            metrics::MESH_PEER_EVICTED
                .with_label_values(&[metrics::EVICT_REASON_PROBE_TIMEOUT])
                .inc();
            tracing::warn!(
                peer = peer,
                consecutive_failures = count,
                threshold = self.max_consecutive_failures,
                "mesh peer evicted after consecutive probe failures"
            );
        }
        fired
    }

    /// Explicitly evict a peer (e.g. on a graceful LeaveRequest or after
    /// a `dead_timeout` in the health monitor). The given `reason` is
    /// used as the `reason` label on the metric.
    pub fn evict(&self, peer: &str, reason: &str) {
        {
            let mut map = self.failures.lock().expect("mutex poisoned");
            map.remove(peer);
        }
        (self.on_evict)(peer);
        metrics::MESH_PEER_EVICTED
            .with_label_values(&[reason])
            .inc();
        tracing::info!(peer = peer, reason = reason, "mesh peer evicted");
    }

    /// Current consecutive-failure count for `peer`. Returns `0` when the
    /// peer has no recorded failures.
    pub fn failure_count(&self, peer: &str) -> u32 {
        self.failures
            .lock()
            .expect("mutex poisoned")
            .get(peer)
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counter_callback() -> (EvictCallback, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_ref = counter.clone();
        let cb: EvictCallback = Arc::new(move |_peer: &str| {
            counter_ref.fetch_add(1, Ordering::SeqCst);
        });
        (cb, counter)
    }

    fn name_capturing_callback() -> (EvictCallback, Arc<Mutex<Vec<String>>>) {
        let names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let names_ref = names.clone();
        let cb: EvictCallback = Arc::new(move |peer: &str| {
            names_ref.lock().unwrap().push(peer.to_string());
        });
        (cb, names)
    }

    #[test]
    fn evicts_after_n_consecutive_failures() {
        let (cb, counter) = counter_callback();
        let evictor = PeerEvictor::new(3, cb);

        assert!(!evictor.record_failure("peer-1"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        assert!(!evictor.record_failure("peer-1"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        assert!(evictor.record_failure("peer-1"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn eviction_fires_exactly_once_per_streak() {
        let (cb, counter) = counter_callback();
        let evictor = PeerEvictor::new(3, cb);

        evictor.record_failure("peer-1");
        evictor.record_failure("peer-1");
        evictor.record_failure("peer-1"); // crosses threshold, fires
        evictor.record_failure("peer-1");
        evictor.record_failure("peer-1");

        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn success_resets_counter() {
        let (cb, counter) = counter_callback();
        let evictor = PeerEvictor::new(3, cb);

        evictor.record_failure("peer-1");
        evictor.record_failure("peer-1");
        evictor.record_success("peer-1");
        // After success, threshold counter is 0 -> two more failures should
        // not cross the 3-failure threshold yet.
        assert!(!evictor.record_failure("peer-1"));
        assert!(!evictor.record_failure("peer-1"));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        // One more crosses it.
        assert!(evictor.record_failure("peer-1"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multiple_peers_tracked_independently() {
        let (cb, names) = name_capturing_callback();
        let evictor = PeerEvictor::new(2, cb);

        evictor.record_failure("peer-a");
        evictor.record_failure("peer-b");
        assert!(names.lock().unwrap().is_empty());

        evictor.record_failure("peer-a"); // crosses
        assert_eq!(names.lock().unwrap().as_slice(), &["peer-a".to_string()]);

        evictor.record_failure("peer-b"); // crosses
        assert_eq!(
            names.lock().unwrap().as_slice(),
            &["peer-a".to_string(), "peer-b".to_string()]
        );
    }

    #[test]
    fn explicit_evict_fires_callback_and_clears_counter() {
        let (cb, counter) = counter_callback();
        let evictor = PeerEvictor::new(5, cb);

        evictor.record_failure("peer-1");
        evictor.record_failure("peer-1");
        assert_eq!(evictor.failure_count("peer-1"), 2);

        evictor.evict("peer-1", metrics::EVICT_REASON_GRACEFUL_LEAVE);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(evictor.failure_count("peer-1"), 0);
    }

    #[test]
    fn zero_threshold_is_clamped_up() {
        let (cb, counter) = counter_callback();
        // 0 threshold would never fire; clamped to 1.
        let evictor = PeerEvictor::new(0, cb);
        assert!(evictor.record_failure("peer-1"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn for_distributed_cache_removes_from_ring() {
        let cache: Arc<DistributedCache<Bytes>> = Arc::new(DistributedCache::new("local", 16));
        cache.add_node("peer-a");
        cache.add_node("peer-b");

        let evictor = PeerEvictor::for_distributed_cache(2, cache.clone());

        // Find a key that routes to peer-a initially.
        let test_key = (0..1000)
            .map(|i| format!("k-{i}"))
            .find(|k| cache.responsible_node(k).as_deref() == Some("peer-a"))
            .expect("at least one key should route to peer-a with 16 vnodes");

        evictor.record_failure("peer-a");
        evictor.record_failure("peer-a"); // crosses

        // After eviction, peer-a should no longer be the owner of that key.
        let new_owner = cache.responsible_node(&test_key);
        assert_ne!(new_owner.as_deref(), Some("peer-a"));
        assert!(
            new_owner.is_some(),
            "ring must still have a responsible node"
        );
    }

    #[test]
    fn failure_count_reflects_state() {
        let (cb, _) = counter_callback();
        let evictor = PeerEvictor::new(10, cb);
        assert_eq!(evictor.failure_count("unknown"), 0);
        evictor.record_failure("p1");
        evictor.record_failure("p1");
        assert_eq!(evictor.failure_count("p1"), 2);
    }
}
