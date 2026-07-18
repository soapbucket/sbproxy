//! Contract tests for the bundled AI compression dashboard and rules.

use std::path::{Path, PathBuf};

fn workspace_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn ai_gateway_dashboard_covers_compression_value_and_health() {
    let path = workspace_file("dashboards/grafana/sbproxy-ai-gateway.json");
    let bytes = std::fs::read(&path).expect("read AI gateway dashboard");
    let dashboard: serde_json::Value =
        serde_json::from_slice(&bytes).expect("AI gateway dashboard is valid JSON");
    let panels = dashboard["panels"]
        .as_array()
        .expect("dashboard has panels");
    let titles = panels
        .iter()
        .filter_map(|panel| panel["title"].as_str())
        .collect::<Vec<_>>();
    for title in [
        "Compression Application Rate",
        "Compression Tokens Saved/sec",
        "Per-request Compression Savings",
        "Compression Ratio",
        "Compression Lever Latency P95",
        "Compression Failures",
        "Redis Compression Coordination",
        "Mesh Compression Convergence",
    ] {
        assert!(titles.contains(&title), "missing dashboard panel {title}");
    }

    let expressions = panels
        .iter()
        .flat_map(|panel| panel["targets"].as_array().into_iter().flatten())
        .filter_map(|target| target["expr"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for metric in [
        "sbproxy_ai_compression_lever_total",
        "sbproxy_ai_compression_tokens_saved_total",
        "sbproxy_ai_compression_request_tokens_saved_bucket",
        "sbproxy_ai_compression_ratio_bucket",
        "sbproxy_ai_compression_duration_seconds_bucket",
        "sbproxy_ai_compression_redis_coordination_total",
        "sbproxy_ai_compression_mesh_events_total",
    ] {
        assert!(
            expressions.contains(metric),
            "dashboard does not query {metric}"
        );
    }
}

#[test]
fn prometheus_rules_cover_compression_value_failures_and_coordination() {
    let rules =
        std::fs::read_to_string(workspace_file("dashboards/prometheus/recording-rules.yml"))
            .expect("read recording rules");
    for record in [
        "sbproxy:ai_compression_application_rate_5m",
        "sbproxy:ai_compression_failure_ratio_5m",
        "sbproxy:ai_compression_latency_p95_5m",
        "sbproxy:ai_compression_tokens_saved_rate_5m",
    ] {
        assert!(rules.contains(record), "missing recording rule {record}");
    }

    let alerts = std::fs::read_to_string(workspace_file("dashboards/prometheus/alerts.yml"))
        .expect("read alert rules");
    for alert in [
        "SBProxyAICompressionFailures",
        "SBProxyAICompressionStateRejections",
    ] {
        assert!(alerts.contains(alert), "missing alert {alert}");
    }
    assert!(alerts.contains("sbproxy_ai_compression_state_operations_total"));
    assert!(alerts.contains("sbproxy_ai_compression_redis_coordination_total"));
    assert!(alerts.contains("sbproxy_ai_compression_mesh_events_total"));
}
