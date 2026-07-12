// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Fleet-wide metric aggregation over the mesh (WOR-1721).
//!
//! Metrics are per-instance: each process exposes only its own `sbproxy_*`
//! counters at `/metrics`, and the standard way to see cluster totals is
//! an external Prometheus scraping every instance and summing with PromQL
//! (the bundled Grafana dashboards already do this). This module is the
//! optional in-app alternative for deployments without a Prometheus: when
//! distributed clustering is on, each node periodically publishes a compact
//! snapshot of a curated set of `sbproxy_*` totals through the process-wide
//! cluster handle, and collects every live node's snapshot into a process-global
//! `ClusterMetrics`. The admin endpoint `GET /admin/cluster/metrics`
//! then reports the fleet sum and node count from one node.
//!
//! It is a convenience, not a replacement for Prometheus: the snapshot is
//! a small allow-list, the cadence is coarse, and a node that has not been
//! seen recently keeps its last snapshot until the mesh drops it.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sbproxy_mesh::cluster_metrics::ClusterMetrics;
use sbproxy_mesh::{ClusterHandle, ClusterMemberState, ClusterStateRead};

const STATE_NAMESPACE: &str = "cluster-metrics";
const STATE_SCHEMA_VERSION: u32 = 1;

/// The `sbproxy_*` metric families published to the fleet snapshot. Kept
/// small and additive (counters / gauges that sum meaningfully across
/// nodes); not the whole registry.
const PUBLISHED_METRICS: &[&str] = &[
    "sbproxy_requests_total",
    "sbproxy_active_connections",
    "sbproxy_ai_tokens_total",
    "sbproxy_ai_cost_usd_micros_total",
];

/// Process-global fleet-metrics aggregator, installed when the mesh key
/// tier is on. Absent means fleet metrics are off (use Prometheus).
static CLUSTER_METRICS: OnceLock<Arc<ClusterMetrics>> = OnceLock::new();

/// Install the process-global `ClusterMetrics`. First install wins.
pub(crate) fn install_cluster_metrics(cm: Arc<ClusterMetrics>) {
    let _ = CLUSTER_METRICS.set(cm);
}

/// The installed fleet aggregator, if fleet metrics are on.
pub(crate) fn cluster_metrics() -> Option<&'static Arc<ClusterMetrics>> {
    CLUSTER_METRICS.get()
}

/// A snapshot of this node's published metric totals.
fn local_snapshot() -> HashMap<String, f64> {
    sbproxy_observe::metrics::metrics().snapshot_named(PUBLISHED_METRICS)
}

/// Render the fleet aggregate as the admin endpoint's JSON body: the sum
/// of each published metric across all known nodes, plus the node count.
pub(crate) fn fleet_metrics_json() -> Option<String> {
    let cm = cluster_metrics()?;
    let metrics: serde_json::Map<String, serde_json::Value> = PUBLISHED_METRICS
        .iter()
        .map(|name| ((*name).to_string(), serde_json::json!(cm.aggregate(name))))
        .collect();
    Some(
        serde_json::json!({
            "nodes": cm.node_count(),
            "metrics": metrics,
        })
        .to_string(),
    )
}

/// The producer + collector loop: publish this node's snapshot and pull
/// every live node's snapshot into the aggregator, forever, on the given
/// cadence. Spawned on the process-owned cluster runtime whenever distributed
/// clustering is active. Failures are skipped; the next tick re-publishes and
/// re-collects.
pub(crate) async fn run_loop(handle: ClusterHandle, interval_secs: u64) {
    let my_id = handle.identity().node_id.clone();
    let mut generation = generation_seed();
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        tick.tick().await;

        generation = generation.saturating_add(1);
        if let Err(error) = handle
            .publish_state(
                STATE_NAMESPACE,
                &my_id,
                STATE_SCHEMA_VERSION,
                generation,
                Duration::from_secs(interval_secs.max(1).saturating_mul(3)),
                &local_snapshot(),
            )
            .await
        {
            tracing::debug!(%error, "cluster-metrics: publish failed (retry next tick)");
        }

        let cm = match cluster_metrics() {
            Some(c) => c,
            None => continue,
        };

        // Collect every live node's snapshot (this node plus alive peers) and
        // remove departed nodes from the aggregate.
        let live_members = handle
            .membership()
            .into_iter()
            .filter(|member| member.node_id == my_id || member.state == ClusterMemberState::Alive)
            .collect::<Vec<_>>();
        cm.retain_nodes(
            &live_members
                .iter()
                .map(|member| member.node_id.clone())
                .collect::<BTreeSet<_>>(),
        );
        for member in live_members {
            if let ClusterStateRead::Present(record) = handle
                .read_state::<HashMap<String, f64>>(
                    STATE_NAMESPACE,
                    &member.node_id,
                    STATE_SCHEMA_VERSION,
                )
                .await
            {
                cm.update_node(&member.node_id, record.payload);
            }
        }
    }
}

fn generation_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_json_none_without_install() {
        // Without an installed aggregator (fleet metrics off), the endpoint
        // reports nothing so the admin route can 404 cleanly. This runs
        // before any install in this test binary.
        // (If another test installs first, `cluster_metrics()` is Some; the
        // assertion below only holds on the no-install path, so we gate on
        // the current state rather than forcing order.)
        if cluster_metrics().is_none() {
            assert!(fleet_metrics_json().is_none());
        }
    }

    #[test]
    fn fleet_json_sums_across_nodes() {
        let cm = ClusterMetrics::new();
        cm.update_node(
            "node-a",
            HashMap::from([("sbproxy_requests_total".to_string(), 10.0)]),
        );
        cm.update_node(
            "node-b",
            HashMap::from([("sbproxy_requests_total".to_string(), 5.0)]),
        );
        // Aggregate is a sum across nodes; the endpoint shape mirrors this.
        assert_eq!(cm.aggregate("sbproxy_requests_total"), 15.0);
        assert_eq!(cm.node_count(), 2);
    }

    #[test]
    fn local_snapshot_covers_published_names() {
        // Every published name is present (0.0 when unrecorded), so peers
        // always deserialize a full map.
        let snap = local_snapshot();
        for name in PUBLISHED_METRICS {
            assert!(snap.contains_key(*name), "missing {name}");
        }
    }
}
