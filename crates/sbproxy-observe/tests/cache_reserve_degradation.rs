// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Operator-visible Cache Reserve degradation contracts.

use std::path::{Path, PathBuf};

use sbproxy_capability::MetricKind;
use sbproxy_observe::decision::DecisionEvent;

fn workspace_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn cache_reserve_degradation_has_a_typed_emitted_decision() {
    let event = DecisionEvent::from_label("cache.reserve.health")
        .expect("cache reserve health transitions need a typed decision event");

    assert_eq!(event.as_label(), "cache.reserve.health");
    // `has_emitter` reads the same hand-maintained coverage table this
    // change wrote, so it proves the arm is `Emitted`, not that an
    // emitter runs. It stays green if the emitter is deleted. The
    // production emitter is `CacheReserveHealthState::observe_transition`
    // in `sbproxy-core/src/pipeline.rs`, driven by `ObservedCacheReserve`
    // on every reserve operation and covered by that crate's own tests.
    assert!(
        event.has_emitter(),
        "the coverage table must classify this event as one that publishes its own records"
    );
}

#[test]
fn cache_reserve_degradation_metrics_are_registered_with_bounded_labels() {
    let degraded = sbproxy_observe::metric_registry::METRICS
        .iter()
        .find(|metric| metric.name == "sbproxy_cache_reserve_degraded")
        .expect("cache reserve degraded gauge must be centrally registered");
    assert_eq!(degraded.kind, MetricKind::Gauge);
    assert_eq!(degraded.labels, &["backend"]);

    let transitions = sbproxy_observe::metric_registry::METRICS
        .iter()
        .find(|metric| metric.name == "sbproxy_cache_reserve_health_transitions_total")
        .expect("cache reserve health transition counter must be centrally registered");
    assert_eq!(transitions.kind, MetricKind::Counter);
    assert_eq!(transitions.labels, &["backend", "state", "reason"]);
}

#[test]
fn cache_reserve_degradation_is_visible_on_the_storage_dashboard() {
    let bytes = std::fs::read(workspace_file(
        "dashboards/grafana/sbproxy-mesh-storage.json",
    ))
    .expect("read bundled storage dashboard");
    let dashboard: serde_json::Value =
        serde_json::from_slice(&bytes).expect("storage dashboard is valid JSON");
    let panels = dashboard["panels"]
        .as_array()
        .expect("storage dashboard has panels");
    let expressions = panels
        .iter()
        .flat_map(|panel| panel["targets"].as_array().into_iter().flatten())
        .filter_map(|target| target["expr"].as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        expressions.contains("sbproxy_cache_reserve_degraded"),
        "storage dashboard must expose current Cache Reserve degradation"
    );
    assert!(
        expressions.contains("sbproxy_cache_reserve_health_transitions_total"),
        "storage dashboard must expose Cache Reserve health transitions"
    );
}
