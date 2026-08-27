// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Closed observability contract for the live AI toolkit operations.

use sbproxy_capability::{MetricKind, Registry, SupportLevel};
use sbproxy_observe::metric_registry::METRICS;
use sbproxy_observe::{EventType, ALL_EVENT_TYPES};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const TOOLKIT_METRIC: &str = "sbproxy_ai_toolkit_operations_total";

fn workspace_file(relative: impl AsRef<Path>) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("sbproxy-observe -> crates -> workspace")
        .join(relative)
}

#[test]
fn toolkit_metric_is_one_closed_family() {
    let entries: Vec<_> = METRICS
        .iter()
        .filter(|entry| entry.name == TOOLKIT_METRIC)
        .collect();
    assert_eq!(entries.len(), 1, "toolkit metric must be declared once");

    let entry = entries[0];
    assert_eq!(entry.kind, MetricKind::Counter);
    assert_eq!(entry.support, SupportLevel::Stable);
    assert_eq!(entry.registry, Registry::Default);
    assert_eq!(entry.labels, &["capability", "outcome"]);
    assert_eq!(
        entry.writer,
        sbproxy_capability::Writer::Recorder("record_ai_toolkit_operation")
    );
}

#[test]
fn toolkit_events_have_exact_wire_names_and_emitters() {
    for (event_type, wire_name) in [
        (EventType::AiWorkflowOperation, "ai_workflow_operation"),
        (EventType::AiEvaluationOperation, "ai_evaluation_operation"),
        (
            EventType::AiPromptRolloutSelected,
            "ai_prompt_rollout_selected",
        ),
    ] {
        assert_eq!(event_type.as_str(), wire_name);
        assert_eq!(EventType::from_name(wire_name), Some(event_type));
        assert!(ALL_EVENT_TYPES.contains(&event_type));
        assert!(event_type.has_emitter());
    }
}

#[test]
fn ai_gateway_dashboard_has_one_panel_per_toolkit_capability() {
    let path = workspace_file("dashboards/grafana/sbproxy-ai-gateway.json");
    let bytes = std::fs::read(&path).expect("read AI gateway dashboard");
    let dashboard: serde_json::Value =
        serde_json::from_slice(&bytes).expect("AI gateway dashboard is valid JSON");
    let panels = dashboard["panels"]
        .as_array()
        .expect("AI gateway dashboard has panels");

    let titles: BTreeSet<_> = panels
        .iter()
        .filter_map(|panel| panel["title"].as_str())
        .collect();
    for title in [
        "AI Workflow Operations",
        "AI Evaluation Operations",
        "AI Prompt Rollout Selections",
    ] {
        assert!(titles.contains(title), "missing dashboard panel {title}");
    }

    let expressions: Vec<_> = panels
        .iter()
        .flat_map(|panel| panel["targets"].as_array().into_iter().flatten())
        .filter_map(|target| target["expr"].as_str())
        .collect();
    for capability in ["workflow", "evaluation", "prompt_rollout"] {
        assert!(
            expressions.iter().any(|expression| {
                expression.contains(TOOLKIT_METRIC)
                    && expression.contains(&format!("capability=\"{capability}\""))
                    && expression.contains("by (outcome)")
            }),
            "dashboard does not query {TOOLKIT_METRIC} for {capability}"
        );
    }
}
