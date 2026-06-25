//! OR-Set (Observed-Remove Set) CRDT.
//!
//! Supports concurrent add/remove without conflicts.
//! Used for: blocked IPs, tripped circuit breakers, etc.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// An observed-remove set that supports concurrent add/remove.
///
/// Each add operation tags the element with a unique (node_id, counter) pair.
/// Removing an element records all current tags as tombstones. Concurrent
/// adds from other nodes are preserved because they carry different tags.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ORSet {
    /// element -> set of (node_id, counter) tags that added it
    elements: HashMap<String, HashSet<(String, u64)>>,
    /// tombstoned tags (removed)
    tombstones: HashMap<String, HashSet<(String, u64)>>,
    /// per-node counter for generating unique tags
    counter: u64,
}

impl ORSet {
    /// Create a new empty OR-Set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an element, tagged with a unique (node_id, counter) pair.
    pub fn add(&mut self, element: &str, node_id: &str) {
        self.counter += 1;
        let tag = (node_id.to_string(), self.counter);
        self.elements
            .entry(element.to_string())
            .or_default()
            .insert(tag);
    }

    /// Remove an element by tombstoning all current tags.
    ///
    /// Concurrent adds from other nodes (carrying different tags) survive.
    pub fn remove(&mut self, element: &str) {
        if let Some(tags) = self.elements.remove(element) {
            self.tombstones
                .entry(element.to_string())
                .or_default()
                .extend(tags);
        }
    }

    /// Check whether the element is currently in the set.
    pub fn contains(&self, element: &str) -> bool {
        match self.elements.get(element) {
            None => false,
            Some(tags) => {
                let tombstoned = self.tombstones.get(element).cloned().unwrap_or_default();
                // Element is present if it has any live (non-tombstoned) tags.
                tags.iter().any(|t| !tombstoned.contains(t))
            }
        }
    }

    /// Return all elements currently in the set.
    pub fn elements(&self) -> Vec<String> {
        self.elements
            .keys()
            .filter(|e| self.contains(e))
            .cloned()
            .collect()
    }

    /// Merge with another OR-Set (union of both elements and tombstones).
    pub fn merge(&mut self, other: &ORSet) {
        // Merge elements: union all tags per element.
        for (element, tags) in &other.elements {
            self.elements
                .entry(element.clone())
                .or_default()
                .extend(tags.iter().cloned());
        }
        // Merge tombstones: union all tombstoned tags.
        for (element, tags) in &other.tombstones {
            self.tombstones
                .entry(element.clone())
                .or_default()
                .extend(tags.iter().cloned());
        }
        // Keep the higher counter.
        if other.counter > self.counter {
            self.counter = other.counter;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_element() {
        let mut s = ORSet::new();
        s.add("192.168.1.1", "node-a");
        assert!(s.contains("192.168.1.1"));
    }

    #[test]
    fn add_then_remove() {
        let mut s = ORSet::new();
        s.add("192.168.1.1", "node-a");
        s.remove("192.168.1.1");
        assert!(!s.contains("192.168.1.1"));
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut s = ORSet::new();
        s.remove("ghost");
        assert!(!s.contains("ghost"));
    }

    #[test]
    fn elements_returns_live_set() {
        let mut s = ORSet::new();
        s.add("a", "n1");
        s.add("b", "n1");
        s.add("c", "n1");
        s.remove("b");

        let mut elems = s.elements();
        elems.sort();
        assert_eq!(elems, vec!["a", "c"]);
    }

    #[test]
    fn concurrent_add_survives_remove() {
        // Simulate: node-a adds element, then removes it.
        // Concurrently, node-b also adds the same element.
        // After merge the element should still be present (node-b's add survives).

        let mut node_a = ORSet::new();
        node_a.add("circuit-breaker-x", "node-a");
        node_a.remove("circuit-breaker-x");

        let mut node_b = ORSet::new();
        node_b.add("circuit-breaker-x", "node-b"); // concurrent add

        // Merge node-b's state into node-a
        node_a.merge(&node_b);

        // node-b's add had a different tag, so it survives
        assert!(node_a.contains("circuit-breaker-x"));
    }

    #[test]
    fn merge_combines_disjoint_sets() {
        let mut a = ORSet::new();
        a.add("ip-1", "node-a");

        let mut b = ORSet::new();
        b.add("ip-2", "node-b");

        a.merge(&b);

        assert!(a.contains("ip-1"));
        assert!(a.contains("ip-2"));
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = ORSet::new();
        a.add("x", "node-a");

        let b = a.clone();
        a.merge(&b);
        a.merge(&b);

        assert!(a.contains("x"));
        assert_eq!(a.elements().len(), 1);
    }

    #[test]
    fn contains_after_re_add() {
        let mut s = ORSet::new();
        s.add("elem", "node-a");
        s.remove("elem");
        assert!(!s.contains("elem"));
        s.add("elem", "node-a");
        assert!(s.contains("elem"));
    }

    #[test]
    fn serializes_and_deserializes() {
        let mut s = ORSet::new();
        s.add("10.0.0.1", "node-a");
        let json = serde_json::to_string(&s).expect("serialize");
        let back: ORSet = serde_json::from_str(&json).expect("deserialize");
        assert!(back.contains("10.0.0.1"));
    }
}
