//! G-Counter CRDT for distributed counters (e.g., rate limiting).
//!
//! Each node maintains its own counter. The global value is the sum
//! of all node counters. Merging takes the max of each node's count.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A grow-only distributed counter.
///
/// Suitable for distributed rate limiting: each proxy node increments its
/// own slot; the global total is the sum of all slots. Merging two
/// G-Counters takes the max per-node value, so state is always monotone.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GCounter {
    counts: HashMap<String, u64>, // node_id -> count
}

impl GCounter {
    /// Create a new empty counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the counter for a specific node.
    pub fn increment(&mut self, node_id: &str, amount: u64) {
        let entry = self.counts.entry(node_id.to_string()).or_insert(0);
        *entry += amount;
    }

    /// Get the total count across all nodes.
    pub fn value(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Merge with another G-Counter (take max per node).
    ///
    /// This operation is idempotent and commutative.
    pub fn merge(&mut self, other: &GCounter) {
        for (node_id, &count) in &other.counts {
            let entry = self.counts.entry(node_id.clone()).or_insert(0);
            if count > *entry {
                *entry = count;
            }
        }
    }

    /// Get the delta since a previous state (for replication).
    ///
    /// Returns only the nodes whose counts are higher in `self` than in
    /// `previous`, making it cheap to propagate only what changed.
    pub fn delta_since(&self, previous: &GCounter) -> GCounter {
        let mut delta = GCounter::new();
        for (node_id, &count) in &self.counts {
            let prev_count = previous.counts.get(node_id).copied().unwrap_or(0);
            if count > prev_count {
                delta.counts.insert(node_id.clone(), count);
            }
        }
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_counter_is_zero() {
        let c = GCounter::new();
        assert_eq!(c.value(), 0);
    }

    #[test]
    fn increment_single_node() {
        let mut c = GCounter::new();
        c.increment("node-a", 5);
        assert_eq!(c.value(), 5);
    }

    #[test]
    fn increment_multiple_nodes_sums_all() {
        let mut c = GCounter::new();
        c.increment("node-a", 3);
        c.increment("node-b", 7);
        c.increment("node-c", 10);
        assert_eq!(c.value(), 20);
    }

    #[test]
    fn increment_same_node_accumulates() {
        let mut c = GCounter::new();
        c.increment("node-a", 10);
        c.increment("node-a", 5);
        assert_eq!(c.value(), 15);
    }

    #[test]
    fn merge_takes_max_per_node() {
        let mut a = GCounter::new();
        a.increment("node-a", 10);
        a.increment("node-b", 3);

        let mut b = GCounter::new();
        b.increment("node-a", 5); // lower than a's node-a
        b.increment("node-b", 7); // higher than a's node-b
        b.increment("node-c", 2); // only in b

        a.merge(&b);

        // node-a: max(10, 5) = 10
        // node-b: max(3, 7) = 7
        // node-c: max(0, 2) = 2
        assert_eq!(a.value(), 19);
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = GCounter::new();
        a.increment("node-a", 10);

        let mut b = GCounter::new();
        b.increment("node-a", 10);

        a.merge(&b);
        let val_once = a.value();
        a.merge(&b);
        let val_twice = a.value();
        assert_eq!(val_once, val_twice);
    }

    #[test]
    fn delta_since_returns_only_changed_nodes() {
        let mut prev = GCounter::new();
        prev.increment("node-a", 5);
        prev.increment("node-b", 3);

        let mut current = prev.clone();
        current.increment("node-b", 2); // now 5
        current.increment("node-c", 10); // new

        let delta = current.delta_since(&prev);

        // node-a unchanged - should not appear
        assert!(!delta.counts.contains_key("node-a"));
        // node-b and node-c changed
        assert_eq!(delta.counts.get("node-b").copied(), Some(5));
        assert_eq!(delta.counts.get("node-c").copied(), Some(10));
    }

    #[test]
    fn delta_since_empty_when_nothing_changed() {
        let mut c = GCounter::new();
        c.increment("node-a", 5);
        let snapshot = c.clone();
        let delta = c.delta_since(&snapshot);
        assert_eq!(delta.value(), 0);
    }

    #[test]
    fn serializes_and_deserializes() {
        let mut c = GCounter::new();
        c.increment("node-a", 42);
        let json = serde_json::to_string(&c).expect("serialize");
        let back: GCounter = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.value(), 42);
    }
}
