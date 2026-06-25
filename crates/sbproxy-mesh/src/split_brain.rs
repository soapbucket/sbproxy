//! Split-brain detection for network partitions.
//!
//! A split-brain occurs when the cluster loses quorum: fewer than half the
//! expected nodes are reachable. In that state, taking writes could create
//! divergent data. The detector signals when the proxy should reject mutations
//! or switch to read-only mode.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Detects cluster split-brain conditions.
///
/// When `alive_count < expected_min_nodes / 2` we have lost quorum and the
/// node should stop accepting writes.
pub struct SplitBrainDetector {
    expected_min_nodes: usize,
    current_alive: AtomicUsize,
}

impl SplitBrainDetector {
    /// Create a detector with the expected minimum number of cluster nodes.
    ///
    /// `expected_min_nodes` is typically the initial cluster size or the
    /// minimum size required for quorum.
    pub fn new(expected_min_nodes: usize) -> Self {
        Self {
            expected_min_nodes,
            current_alive: AtomicUsize::new(expected_min_nodes),
        }
    }

    /// Update the count of currently alive/reachable nodes.
    pub fn update_alive_count(&self, count: usize) {
        self.current_alive.store(count, Ordering::Relaxed);
    }

    /// Returns `true` if the cluster has lost quorum (alive < expected / 2).
    pub fn is_split_brain(&self) -> bool {
        let alive = self.current_alive.load(Ordering::Relaxed);
        alive < self.expected_min_nodes / 2
    }

    /// Return the current number of alive nodes.
    pub fn alive_count(&self) -> usize {
        self.current_alive.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_split_brain_when_all_alive() {
        let detector = SplitBrainDetector::new(5);
        detector.update_alive_count(5);
        assert!(!detector.is_split_brain());
    }

    #[test]
    fn no_split_brain_when_majority_alive() {
        let detector = SplitBrainDetector::new(5);
        // 3 alive, expected/2 = 2; 3 >= 2, not split-brain.
        detector.update_alive_count(3);
        assert!(!detector.is_split_brain());
    }

    #[test]
    fn split_brain_when_less_than_half() {
        let detector = SplitBrainDetector::new(5);
        // 2 alive, expected/2 = 2; 2 < 2 is false, so check 1.
        detector.update_alive_count(1);
        assert!(detector.is_split_brain());
    }

    #[test]
    fn split_brain_boundary_even_nodes() {
        // expected = 4, threshold = 2; alive=1 triggers split brain.
        let detector = SplitBrainDetector::new(4);
        detector.update_alive_count(1);
        assert!(detector.is_split_brain());

        // alive=2 is exactly at threshold (not strictly less), so no split brain.
        detector.update_alive_count(2);
        assert!(!detector.is_split_brain());
    }

    #[test]
    fn split_brain_boundary_odd_nodes() {
        // expected = 5, threshold = 2; alive=2 is not less than 2, no split brain.
        let detector = SplitBrainDetector::new(5);
        detector.update_alive_count(2);
        assert!(!detector.is_split_brain());

        // alive=1 is less than 2, split brain.
        detector.update_alive_count(1);
        assert!(detector.is_split_brain());
    }

    #[test]
    fn zero_alive_is_split_brain() {
        let detector = SplitBrainDetector::new(3);
        detector.update_alive_count(0);
        assert!(detector.is_split_brain());
    }

    #[test]
    fn single_node_cluster_never_split_brain() {
        // expected = 1, threshold = 0; alive=1 is never < 0.
        let detector = SplitBrainDetector::new(1);
        detector.update_alive_count(1);
        assert!(!detector.is_split_brain());

        // Even with 0 alive (implausible but safe): 0 < 0 is false.
        detector.update_alive_count(0);
        assert!(!detector.is_split_brain());
    }

    #[test]
    fn alive_count_reflects_update() {
        let detector = SplitBrainDetector::new(10);
        detector.update_alive_count(7);
        assert_eq!(detector.alive_count(), 7);
        detector.update_alive_count(3);
        assert_eq!(detector.alive_count(), 3);
    }
}
