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
    ] {
        assert!(titles.contains(&title), "missing dashboard panel {title}");
    }
    let application = panels
        .iter()
        .find(|panel| panel["title"] == "Compression Application Rate")
        .expect("compression application panel");
    assert_eq!(
        application["fieldConfig"]["defaults"]["unit"],
        "percentunit"
    );
    assert_eq!(
        application["targets"][0]["expr"],
        "sbproxy:ai_compression_application_rate_5m"
    );
    let request_rate = panels
        .iter()
        .find(|panel| panel["title"] == "AI Requests/sec by Provider")
        .expect("AI request-rate panel");
    assert_eq!(request_rate["fieldConfig"]["defaults"]["unit"], "reqps");

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
    ] {
        assert!(
            expressions.contains(metric),
            "dashboard does not query {metric}"
        );
    }
}

#[test]
fn ai_value_dashboard_covers_realized_compression_tokens_and_cost() {
    let bytes = std::fs::read(workspace_file("dashboards/grafana/sbproxy-ai-value.json"))
        .expect("read AI value dashboard");
    let dashboard: serde_json::Value =
        serde_json::from_slice(&bytes).expect("AI value dashboard is valid JSON");
    let panels = dashboard["panels"]
        .as_array()
        .expect("dashboard has panels");
    let titles = panels
        .iter()
        .filter_map(|panel| panel["title"].as_str())
        .collect::<Vec<_>>();
    assert!(titles.contains(&"Realized Compression Tokens Saved/sec"));
    assert!(titles.contains(&"Realized Compression Cost Saved ($/hr)"));

    let expressions = panels
        .iter()
        .flat_map(|panel| panel["targets"].as_array().into_iter().flatten())
        .filter_map(|target| target["expr"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for metric in [
        "sbproxy_ai_compression_value_tokens_saved_total",
        "sbproxy_ai_compression_value_cost_saved_micros_total",
    ] {
        assert!(
            expressions.contains(metric),
            "AI value dashboard does not query {metric}"
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
        "sbproxy:ai_compression_value_tokens_saved_by_tenant_model_lever_5m",
        "sbproxy:ai_compression_value_cost_saved_dollars_by_tenant_model_lever_5m",
    ] {
        assert!(rules.contains(record), "missing recording rule {record}");
    }
    assert!(rules.contains("sbproxy_ai_compression_value_tokens_saved_total"));
    assert!(rules.contains("sbproxy_ai_compression_value_cost_saved_micros_total"));

    let alerts = std::fs::read_to_string(workspace_file("dashboards/prometheus/alerts.yml"))
        .expect("read alert rules");
    for alert in [
        "SBProxyAICompressionFailures",
        "SBProxyAICompressionStateRejections",
        "SBProxyAICompressionValueUnpriced",
    ] {
        assert!(alerts.contains(alert), "missing alert {alert}");
    }
    assert!(alerts.contains("sbproxy_ai_compression_state_operations_total"));
    let value_alert = alerts
        .split("- alert: SBProxyAICompressionValueUnpriced")
        .nth(1)
        .expect("unpriced compression value alert")
        .split("- alert:")
        .next()
        .unwrap_or_default();
    assert!(value_alert.contains("sbproxy_ai_compression_value_tokens_saved_total"));
    assert!(value_alert.contains("sbproxy_ai_compression_value_cost_saved_micros_total"));
    let state_alert = alerts
        .split("- alert: SBProxyAICompressionStateRejections")
        .nth(1)
        .expect("compression state rejection alert")
        .split("- alert:")
        .next()
        .unwrap_or_default();
    assert!(
        !state_alert.contains("sbproxy_ai_compression_redis_coordination_total"),
        "state-operation errors and coordination rejections overlap and must not be summed"
    );
}
