//! Node isolation / quarantine observer.
//!
//! Wraps [`SplitBrainDetector`](crate::split_brain::SplitBrainDetector) and a
//! `min_peers` threshold. Callers (gossip loop, periodic health tick) push
//! the current live-peer count via [`IsolationObserver::update`]; the observer
//! detects transitions in and out of quarantine, logs them once per edge,
//! and drives the `mesh_node_isolated` gauge.
//!
//! When the node is in quarantine, mesh-backed cache reads should treat the
//! cluster as unavailable (force upstream fetch). Consumers consult
//! [`IsolationObserver::is_isolated`] and short-circuit accordingly. The
//! gossip loop ([`crate::gossip_loop`]) drives [`IsolationObserver::update`]
//! every protocol period; downstream cache stores attach the same observer via
//! `with_isolation_observer` and degrade routed reads/writes while the node is
//! quarantined.

use std::sync::Mutex;

use crate::metrics;

/// State of the node with respect to quorum / reachable peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationState {
    /// Healthy: alive-peer count is at or above `min_peers`.
    Healthy,
    /// Quarantined: alive-peer count is below `min_peers`. Mesh-backed
    /// cache reads should be treated as miss; writes suppressed.
    Isolated,
}

struct Inner {
    state: IsolationState,
    last_alive_count: usize,
}

/// Observes cluster health and flips a gauge when the node's reachable
/// peer count crosses the `min_peers` threshold.
pub struct IsolationObserver {
    min_peers: usize,
    node_id: String,
    inner: Mutex<Inner>,
}

impl IsolationObserver {
    /// Build an observer with the local node id (used as a metric label)
    /// and the quorum threshold. `min_peers` counts peers *other than the
    /// local node*: when alive-peer count drops below it, the node is
    /// considered isolated.
    ///
    /// A `min_peers` of 0 means the node is never considered isolated
    /// (single-node cluster).
    pub fn new(node_id: impl Into<String>, min_peers: usize) -> Self {
        let observer = Self {
            min_peers,
            node_id: node_id.into(),
            inner: Mutex::new(Inner {
                state: IsolationState::Healthy,
                last_alive_count: 0,
            }),
        };
        // Publish the initial (healthy) gauge so scrapes see a value
        // immediately rather than waiting for the first update call.
        metrics::MESH_NODE_ISOLATED
            .with_label_values(&[&observer.node_id])
            .set(0);
        observer
    }

    /// Feed the latest alive-peer count. Returns the current state after
    /// applying the update. Logs edge transitions (Healthy -> Isolated and
    /// Isolated -> Healthy) exactly once per crossing.
    pub fn update(&self, alive_peers: usize) -> IsolationState {
        let new_state = if self.min_peers == 0 {
            IsolationState::Healthy
        } else if alive_peers < self.min_peers {
            IsolationState::Isolated
        } else {
            IsolationState::Healthy
        };

        let (prev_state, edge) = {
            let mut inner = self.inner.lock().expect("mutex poisoned");
            let prev = inner.state;
            inner.last_alive_count = alive_peers;
            let edge = prev != new_state;
            inner.state = new_state;
            (prev, edge)
        };

        if edge {
            match new_state {
                IsolationState::Isolated => {
                    tracing::warn!(
                        node_id = %self.node_id,
                        alive_peers = alive_peers,
                        min_peers = self.min_peers,
                        "mesh_split_brain_detected: entering quarantine"
                    );
                    metrics::MESH_NODE_ISOLATED
                        .with_label_values(&[&self.node_id])
                        .set(1);
                }
                IsolationState::Healthy => {
                    tracing::info!(
                        node_id = %self.node_id,
                        alive_peers = alive_peers,
                        min_peers = self.min_peers,
                        prev_state = ?prev_state,
                        "mesh_quarantine_recovered: exiting quarantine"
                    );
                    metrics::MESH_NODE_ISOLATED
                        .with_label_values(&[&self.node_id])
                        .set(0);
                }
            }
        }

        new_state
    }

    /// Returns `true` if the node is currently in the isolated /
    /// quarantine state. Callers (mesh cache store, etc.) consult this
    /// before performing mesh-dependent operations.
    pub fn is_isolated(&self) -> bool {
        self.inner.lock().expect("mutex poisoned").state == IsolationState::Isolated
    }

    /// Current state snapshot.
    pub fn state(&self) -> IsolationState {
        self.inner.lock().expect("mutex poisoned").state
    }

    /// Most recent alive-peer count passed to [`Self::update`].
    pub fn last_alive_count(&self) -> usize {
        self.inner.lock().expect("mutex poisoned").last_alive_count
    }

    /// Configured quorum threshold.
    pub fn min_peers(&self) -> usize {
        self.min_peers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_healthy() {
        let obs = IsolationObserver::new("n-starts-healthy", 2);
        assert_eq!(obs.state(), IsolationState::Healthy);
        assert!(!obs.is_isolated());
    }

    #[test]
    fn isolates_when_below_threshold() {
        let obs = IsolationObserver::new("n-iso-below", 3);
        let s = obs.update(1);
        assert_eq!(s, IsolationState::Isolated);
        assert!(obs.is_isolated());
    }

    #[test]
    fn healthy_at_threshold() {
        let obs = IsolationObserver::new("n-at-threshold", 3);
        // Exactly at the threshold: alive_peers (3) >= min_peers (3).
        assert_eq!(obs.update(3), IsolationState::Healthy);
    }

    #[test]
    fn recovers_when_peers_come_back() {
        let obs = IsolationObserver::new("n-recovers", 2);
        assert_eq!(obs.update(0), IsolationState::Isolated);
        assert_eq!(obs.update(1), IsolationState::Isolated);
        assert_eq!(obs.update(2), IsolationState::Healthy);
        assert!(!obs.is_isolated());
    }

    #[test]
    fn edge_transitions_update_gauge() {
        let label = "n-gauge-edges";
        let obs = IsolationObserver::new(label, 2);
        assert_eq!(
            metrics::MESH_NODE_ISOLATED
                .with_label_values(&[label])
                .get(),
            0
        );
        obs.update(0); // -> Isolated
        assert_eq!(
            metrics::MESH_NODE_ISOLATED
                .with_label_values(&[label])
                .get(),
            1
        );
        obs.update(5); // -> Healthy
        assert_eq!(
            metrics::MESH_NODE_ISOLATED
                .with_label_values(&[label])
                .get(),
            0
        );
    }

    #[test]
    fn min_peers_zero_never_isolates() {
        let obs = IsolationObserver::new("n-zero-min", 0);
        assert_eq!(obs.update(0), IsolationState::Healthy);
        assert_eq!(obs.update(100), IsolationState::Healthy);
        assert!(!obs.is_isolated());
    }

    #[test]
    fn repeated_update_in_same_state_is_idempotent() {
        let obs = IsolationObserver::new("n-idempotent", 2);
        // Enter isolated.
        obs.update(0);
        // Remain isolated on repeated pushes. No panics, no state flip.
        obs.update(0);
        obs.update(1);
        assert!(obs.is_isolated());
        // Each update's alive count is stored.
        assert_eq!(obs.last_alive_count(), 1);
    }

    #[test]
    fn last_alive_count_is_recorded() {
        let obs = IsolationObserver::new("n-last-count", 2);
        obs.update(5);
        assert_eq!(obs.last_alive_count(), 5);
        obs.update(1);
        assert_eq!(obs.last_alive_count(), 1);
    }
}
