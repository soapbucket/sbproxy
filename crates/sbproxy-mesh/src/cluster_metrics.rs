//! Cluster-wide metrics aggregation.
//!
//! Each node periodically publishes its local metrics via gossip. This module
//! aggregates per-node metrics into cluster-wide sums and averages for
//! monitoring, autoscaling, and alerting.

use std::collections::HashMap;
use std::sync::Mutex;

/// Aggregates metrics reported by each node in the cluster.
pub struct ClusterMetrics {
    /// node_id -> (metric_name -> value)
    per_node: Mutex<HashMap<String, HashMap<String, f64>>>,
}

impl ClusterMetrics {
    /// Create an empty metrics store.
    pub fn new() -> Self {
        Self {
            per_node: Mutex::new(HashMap::new()),
        }
    }

    /// Update (replace) the metric set for a single node.
    pub fn update_node(&self, node_id: &str, metrics: HashMap<String, f64>) {
        let mut guard = self.per_node.lock().expect("mutex poisoned");
        guard.insert(node_id.to_string(), metrics);
    }

    /// Sum `metric_name` across all nodes that have reported it.
    pub fn aggregate(&self, metric_name: &str) -> f64 {
        let guard = self.per_node.lock().expect("mutex poisoned");
        guard
            .values()
            .filter_map(|m| m.get(metric_name).copied())
            .sum()
    }

    /// Average `metric_name` across nodes that have reported it.
    ///
    /// Returns `0.0` if no node has reported the metric.
    pub fn average(&self, metric_name: &str) -> f64 {
        let guard = self.per_node.lock().expect("mutex poisoned");
        let values: Vec<f64> = guard
            .values()
            .filter_map(|m| m.get(metric_name).copied())
            .collect();
        if values.is_empty() {
            return 0.0;
        }
        values.iter().sum::<f64>() / values.len() as f64
    }

    /// Return the number of nodes that have reported metrics.
    pub fn node_count(&self) -> usize {
        let guard = self.per_node.lock().expect("mutex poisoned");
        guard.len()
    }
}

impl Default for ClusterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(pairs: &[(&str, f64)]) -> HashMap<String, f64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn single_node_metrics() {
        let cm = ClusterMetrics::new();
        cm.update_node("node-a", metrics(&[("rps", 100.0), ("latency_ms", 42.0)]));

        assert_eq!(cm.aggregate("rps"), 100.0);
        assert_eq!(cm.aggregate("latency_ms"), 42.0);
        assert_eq!(cm.node_count(), 1);
    }

    #[test]
    fn multi_node_aggregation() {
        let cm = ClusterMetrics::new();
        cm.update_node("node-a", metrics(&[("rps", 100.0)]));
        cm.update_node("node-b", metrics(&[("rps", 200.0)]));
        cm.update_node("node-c", metrics(&[("rps", 50.0)]));

        assert_eq!(cm.aggregate("rps"), 350.0);
        assert_eq!(cm.node_count(), 3);
    }

    #[test]
    fn average_calculation() {
        let cm = ClusterMetrics::new();
        cm.update_node("node-a", metrics(&[("cpu", 0.3)]));
        cm.update_node("node-b", metrics(&[("cpu", 0.5)]));
        cm.update_node("node-c", metrics(&[("cpu", 0.7)]));

        let avg = cm.average("cpu");
        assert!((avg - 0.5).abs() < 1e-9, "expected 0.5, got {avg}");
    }

    #[test]
    fn missing_metric_returns_zero() {
        let cm = ClusterMetrics::new();
        cm.update_node("node-a", metrics(&[("rps", 10.0)]));

        assert_eq!(cm.aggregate("nonexistent"), 0.0);
        assert_eq!(cm.average("nonexistent"), 0.0);
    }

    #[test]
    fn partial_metric_reporting() {
        // Only two of three nodes report "error_rate".
        let cm = ClusterMetrics::new();
        cm.update_node("node-a", metrics(&[("error_rate", 0.02)]));
        cm.update_node("node-b", metrics(&[("rps", 500.0)])); // no error_rate
        cm.update_node("node-c", metrics(&[("error_rate", 0.04)]));

        assert_eq!(cm.node_count(), 3);
        assert!((cm.aggregate("error_rate") - 0.06).abs() < 1e-9);
        assert!((cm.average("error_rate") - 0.03).abs() < 1e-9);
    }

    #[test]
    fn update_node_replaces_previous_metrics() {
        let cm = ClusterMetrics::new();
        cm.update_node("node-a", metrics(&[("rps", 100.0)]));
        cm.update_node("node-a", metrics(&[("rps", 999.0)]));

        assert_eq!(cm.aggregate("rps"), 999.0);
        assert_eq!(cm.node_count(), 1);
    }

    #[test]
    fn empty_cluster_returns_zeros() {
        let cm = ClusterMetrics::new();
        assert_eq!(cm.aggregate("rps"), 0.0);
        assert_eq!(cm.average("rps"), 0.0);
        assert_eq!(cm.node_count(), 0);
    }
}
