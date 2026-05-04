//! Service topology data for visualization.
//!
//! Tracks source -> destination -> protocol edges for mesh visualization.

use std::collections::HashMap;
use std::sync::Mutex;

// --- Edge ---

/// A directed, protocol-specific edge between two services.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Edge {
    /// Origin hostname (traffic source).
    pub source: String,
    /// Upstream address (traffic destination).
    pub destination: String,
    /// Protocol observed on this edge: "http", "https", "grpc", "websocket", or "ai".
    pub protocol: String,
}

// --- EdgeStats ---

/// Aggregated statistics for a topology edge.
#[derive(Debug, Clone)]
pub struct EdgeStats {
    /// Total requests observed on this edge.
    pub request_count: u64,
    /// Total errors observed on this edge.
    pub error_count: u64,
    /// Running average latency in milliseconds.
    pub avg_latency_ms: f64,
}

// --- TopologyTracker ---

/// Tracks service-to-service topology edges with request statistics.
pub struct TopologyTracker {
    edges: Mutex<HashMap<Edge, EdgeStats>>,
}

impl TopologyTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self {
            edges: Mutex::new(HashMap::new()),
        }
    }

    /// Record a single request on a topology edge.
    ///
    /// Creates the edge entry on first observation and updates the running
    /// average latency using Welford's online algorithm.
    pub fn record_edge(
        &self,
        source: &str,
        destination: &str,
        protocol: &str,
        latency_ms: f64,
        is_error: bool,
    ) {
        let edge = Edge {
            source: source.to_string(),
            destination: destination.to_string(),
            protocol: protocol.to_string(),
        };

        let mut edges = self.edges.lock().unwrap();
        let stats = edges.entry(edge).or_insert(EdgeStats {
            request_count: 0,
            error_count: 0,
            avg_latency_ms: 0.0,
        });

        // Welford's incremental mean update.
        stats.request_count += 1;
        if is_error {
            stats.error_count += 1;
        }
        let delta = latency_ms - stats.avg_latency_ms;
        stats.avg_latency_ms += delta / stats.request_count as f64;
    }

    /// Return a snapshot of all edges with their current statistics.
    pub fn get_topology(&self) -> Vec<(Edge, EdgeStats)> {
        self.edges
            .lock()
            .unwrap()
            .iter()
            .map(|(e, s)| (e.clone(), s.clone()))
            .collect()
    }

    /// Clear all tracked edges and statistics.
    pub fn reset(&self) {
        self.edges.lock().unwrap().clear();
    }
}

impl Default for TopologyTracker {
    fn default() -> Self {
        Self::new()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_has_no_edges() {
        let tracker = TopologyTracker::new();
        assert!(tracker.get_topology().is_empty());
    }

    #[test]
    fn record_single_edge_creates_entry() {
        let tracker = TopologyTracker::new();
        tracker.record_edge("api.example.com", "backend:8080", "http", 25.0, false);

        let topology = tracker.get_topology();
        assert_eq!(topology.len(), 1);

        let (edge, stats) = &topology[0];
        assert_eq!(edge.source, "api.example.com");
        assert_eq!(edge.destination, "backend:8080");
        assert_eq!(edge.protocol, "http");
        assert_eq!(stats.request_count, 1);
        assert_eq!(stats.error_count, 0);
        assert!((stats.avg_latency_ms - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn record_multiple_requests_on_same_edge_accumulates() {
        let tracker = TopologyTracker::new();

        tracker.record_edge("origin.com", "upstream:9000", "https", 10.0, false);
        tracker.record_edge("origin.com", "upstream:9000", "https", 20.0, false);
        tracker.record_edge("origin.com", "upstream:9000", "https", 30.0, true);

        let topology = tracker.get_topology();
        assert_eq!(topology.len(), 1);

        let (_, stats) = &topology[0];
        assert_eq!(stats.request_count, 3);
        assert_eq!(stats.error_count, 1);
        // Average of 10, 20, 30 = 20.
        assert!((stats.avg_latency_ms - 20.0).abs() < 1e-9);
    }

    #[test]
    fn different_protocols_create_separate_edges() {
        let tracker = TopologyTracker::new();
        tracker.record_edge("chat.example.com", "ai.provider.com", "ai", 150.0, false);
        tracker.record_edge("chat.example.com", "ai.provider.com", "https", 50.0, false);

        let topology = tracker.get_topology();
        assert_eq!(topology.len(), 2);
    }

    #[test]
    fn different_destinations_create_separate_edges() {
        let tracker = TopologyTracker::new();
        tracker.record_edge("gateway.com", "svc-a:8080", "grpc", 5.0, false);
        tracker.record_edge("gateway.com", "svc-b:8080", "grpc", 8.0, false);

        let topology = tracker.get_topology();
        assert_eq!(topology.len(), 2);
    }

    #[test]
    fn reset_clears_all_edges() {
        let tracker = TopologyTracker::new();
        tracker.record_edge("a.com", "b.com", "http", 10.0, false);
        tracker.record_edge("c.com", "d.com", "websocket", 20.0, false);
        assert_eq!(tracker.get_topology().len(), 2);

        tracker.reset();
        assert!(tracker.get_topology().is_empty());
    }

    #[test]
    fn avg_latency_incremental_correctness() {
        let tracker = TopologyTracker::new();

        // Record 5 samples: 10, 20, 30, 40, 50 -> expected avg = 30.
        for v in [10.0_f64, 20.0, 30.0, 40.0, 50.0] {
            tracker.record_edge("src", "dst", "http", v, false);
        }

        let topology = tracker.get_topology();
        let (_, stats) = &topology[0];
        assert_eq!(stats.request_count, 5);
        assert!((stats.avg_latency_ms - 30.0).abs() < 1e-9);
    }

    #[test]
    fn error_count_accumulates_correctly() {
        let tracker = TopologyTracker::new();

        tracker.record_edge("s", "d", "http", 10.0, true);
        tracker.record_edge("s", "d", "http", 10.0, false);
        tracker.record_edge("s", "d", "http", 10.0, true);
        tracker.record_edge("s", "d", "http", 10.0, true);

        let topology = tracker.get_topology();
        let (_, stats) = &topology[0];
        assert_eq!(stats.request_count, 4);
        assert_eq!(stats.error_count, 3);
    }

    #[test]
    fn default_creates_empty_tracker() {
        let tracker = TopologyTracker::default();
        assert!(tracker.get_topology().is_empty());
    }
}
