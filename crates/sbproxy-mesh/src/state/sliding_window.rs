//! Time-bucketed distributed sliding window rate limiter.
//!
//! Each node maintains a map of time buckets. Buckets are sized in whole
//! seconds and a configurable number of consecutive buckets form the window.
//! Buckets are keyed by `epoch_secs / bucket_size_secs` so that nodes with
//! slightly different clocks naturally land in the same bucket.
//!
//! The distributed design mirrors the G-Counter pattern used elsewhere in
//! this module: each node writes to its own namespace within a bucket.
//! Merging takes the max per (bucket, node) pair, which is monotone and safe
//! under concurrent updates. Nodes exchange `SlidingWindow` structs via gossip
//! and merge them locally.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Type Aliases ---

/// outer key: time bucket (`epoch_secs / bucket_size_secs`)
/// inner key: node_id
type Buckets = HashMap<u64, HashMap<String, u64>>;

// --- Core Type ---

/// A distributed sliding window counter.
///
/// Tracks request counts across multiple nodes in configurable time buckets.
/// The window spans the most recent `window_size_buckets` buckets, giving an
/// approximate sliding window of `bucket_size_secs * window_size_buckets`
/// seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingWindow {
    /// bucket_key -> node_id -> count
    buckets: Buckets,
    bucket_size_secs: u64,
    window_size_buckets: usize,
}

impl SlidingWindow {
    /// Create a new sliding window.
    ///
    /// - `bucket_size_secs`: width of each time bucket in seconds (e.g. 1).
    /// - `window_size_buckets`: number of consecutive buckets that make up the
    ///   rate-limit window (e.g. 60 for a 60-second window with 1-second buckets).
    pub fn new(bucket_size_secs: u64, window_size_buckets: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            bucket_size_secs,
            window_size_buckets,
        }
    }

    /// Increment the counter for `node_id` at `timestamp_secs`.
    pub fn increment(&mut self, node_id: &str, timestamp_secs: u64) {
        let bucket_key = self.current_bucket(timestamp_secs);
        let node_counts = self.buckets.entry(bucket_key).or_default();
        let count = node_counts.entry(node_id.to_string()).or_insert(0);
        *count += 1;
        self.prune_old_buckets(timestamp_secs);
    }

    /// Return the total count across all nodes within the current window.
    pub fn count(&self, current_time_secs: u64) -> u64 {
        let current_bucket = self.current_bucket(current_time_secs);
        let oldest_bucket = current_bucket.saturating_sub(self.window_size_buckets as u64 - 1);
        self.buckets
            .iter()
            .filter(|(&k, _)| k >= oldest_bucket && k <= current_bucket)
            .flat_map(|(_, node_map)| node_map.values())
            .sum()
    }

    /// Merge another `SlidingWindow` into this one.
    ///
    /// For each (bucket, node) pair, takes the maximum count seen. This is
    /// safe under concurrent updates because counts are monotonically increasing.
    pub fn merge(&mut self, other: &SlidingWindow) {
        for (bucket_key, other_nodes) in &other.buckets {
            let our_nodes = self.buckets.entry(*bucket_key).or_default();
            for (node_id, &other_count) in other_nodes {
                let our_count = our_nodes.entry(node_id.clone()).or_insert(0);
                if other_count > *our_count {
                    *our_count = other_count;
                }
            }
        }
    }

    // --- Helpers ---

    fn current_bucket(&self, timestamp_secs: u64) -> u64 {
        timestamp_secs / self.bucket_size_secs
    }

    /// Remove buckets that fall outside the window relative to `current_time_secs`.
    fn prune_old_buckets(&mut self, current_time_secs: u64) {
        let current_bucket = self.current_bucket(current_time_secs);
        let oldest_bucket = current_bucket.saturating_sub(self.window_size_buckets as u64 - 1);
        self.buckets.retain(|&k, _| k >= oldest_bucket);
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    /// Epoch second that maps to bucket 1000 with bucket_size=1.
    const T0: u64 = 1000;

    #[test]
    fn increment_and_count() {
        let mut sw = SlidingWindow::new(1, 60);
        sw.increment("node-a", T0);
        sw.increment("node-a", T0);
        sw.increment("node-b", T0);
        assert_eq!(sw.count(T0), 3);
    }

    #[test]
    fn window_expiry_excludes_old_buckets() {
        let mut sw = SlidingWindow::new(1, 3); // 3-second window
        sw.increment("node-a", T0); // bucket 1000
        sw.increment("node-a", T0 + 1); // bucket 1001
        sw.increment("node-a", T0 + 2); // bucket 1002

        // At T0+3 the window covers [1001, 1002, 1003]; bucket 1000 is expired.
        let count = sw.count(T0 + 3);
        assert_eq!(count, 2, "bucket at T0 should be outside the window");
    }

    #[test]
    fn prune_old_buckets_removes_expired() {
        let mut sw = SlidingWindow::new(1, 2); // 2-second window
        sw.increment("node-a", T0);
        // Advance time by 10 seconds; bucket at T0 should be pruned.
        sw.increment("node-a", T0 + 10);
        // Only the recent bucket should remain.
        assert!(
            !sw.buckets.contains_key(&T0),
            "old bucket should have been pruned"
        );
    }

    #[test]
    fn merge_across_nodes() {
        let mut a = SlidingWindow::new(1, 60);
        a.increment("node-a", T0);

        let mut b = SlidingWindow::new(1, 60);
        b.increment("node-b", T0);
        b.increment("node-b", T0);

        a.merge(&b);
        assert_eq!(a.count(T0), 3, "merged count should sum all nodes");
    }

    #[test]
    fn merge_takes_max_not_sum_for_same_node() {
        let mut a = SlidingWindow::new(1, 60);
        a.increment("node-a", T0); // count = 1

        let mut b = SlidingWindow::new(1, 60);
        b.increment("node-a", T0);
        b.increment("node-a", T0); // count = 2

        // After merge, node-a bucket should have max(1, 2) = 2, not 3.
        a.merge(&b);
        assert_eq!(a.count(T0), 2, "merge should take max, not add");
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = SlidingWindow::new(1, 60);
        a.increment("node-a", T0);

        let b = a.clone();
        a.merge(&b);
        let once = a.count(T0);
        a.merge(&b);
        let twice = a.count(T0);
        assert_eq!(once, twice, "merge should be idempotent");
    }

    #[test]
    fn count_zero_when_empty() {
        let sw = SlidingWindow::new(1, 60);
        assert_eq!(sw.count(T0), 0);
    }

    #[test]
    fn bucket_size_groups_timestamps() {
        // With 10-second buckets, T=0..9 all land in bucket 0, T=10 in bucket 1.
        let mut sw = SlidingWindow::new(10, 2); // 2 * 10s = 20s window
        sw.increment("node-a", 5); // bucket 0
        sw.increment("node-a", 9); // bucket 0
        sw.increment("node-a", 10); // bucket 1
                                    // At t=10, window covers buckets [0, 1].
        assert_eq!(sw.count(10), 3);
        // At t=20, window covers buckets [1, 2]; bucket 0 is outside.
        assert_eq!(sw.count(20), 1);
    }

    #[test]
    fn serializes_and_deserializes() {
        let mut sw = SlidingWindow::new(1, 60);
        sw.increment("node-a", T0);
        let json = serde_json::to_string(&sw).expect("serialize");
        let back: SlidingWindow = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.count(T0), 1);
    }
}
