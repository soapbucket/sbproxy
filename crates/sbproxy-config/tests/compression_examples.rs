//! Shipping contract for the AI compression state-backend examples.

use serde_yaml::Value;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory")
        .parent()
        .expect("workspace directory")
        .to_path_buf()
}

fn example(name: &str) -> (String, String) {
    let directory = workspace_root().join("examples").join(name);
    let yaml = std::fs::read_to_string(directory.join("sb.yml"))
        .unwrap_or_else(|error| panic!("{name}/sb.yml is required: {error}"));
    let readme = std::fs::read_to_string(directory.join("README.md"))
        .unwrap_or_else(|error| panic!("{name}/README.md is required: {error}"));
    (yaml, readme)
}

fn compression_action(yaml: &str) -> Value {
    let parsed = serde_yaml::from_str::<Value>(yaml).expect("example YAML parses");
    parsed["origins"]
        .as_mapping()
        .expect("origins mapping")
        .values()
        .next()
        .expect("one example origin")
        .get("action")
        .expect("AI action")
        .get("compression")
        .expect("compression policy")
        .clone()
}

#[test]
fn external_state_example_compiles_and_selects_redis() {
    std::env::set_var("OPENAI_API_KEY", "sk-test-compression-example");
    std::env::set_var("ADMIN_PASSWORD", "admin-test-compression-example");

    let name = "ai-context-compression-redis";
    let (yaml, _) = example(name);
    sbproxy_config::compile_config(&yaml)
        .unwrap_or_else(|error| panic!("{name}/sb.yml must compile: {error:#}"));
    let compression = compression_action(&yaml);
    assert_eq!(compression["state"]["backend"].as_str(), Some("redis"));
    let levers = compression["levers"]
        .as_sequence()
        .expect("ordered compression levers");
    assert_eq!(levers[0]["type"].as_str(), Some("summary_buffer"));
    assert_eq!(levers[1]["type"].as_str(), Some("window_fit"));

    let compact_levers = compression["profiles"]["compact"]["levers"]
        .as_sequence()
        .expect("ordered compact profile levers");
    assert_eq!(
        compact_levers
            .iter()
            .map(|lever| lever["type"].as_str().expect("lever type"))
            .collect::<Vec<_>>(),
        [
            "rag_select",
            "compact_serialization",
            "position_reorder",
            "window_fit",
        ]
    );
}

#[test]
fn mesh_state_example_compiles_selects_mesh_and_configures_replication() {
    std::env::set_var("OPENAI_API_KEY", "sk-test-compression-example");

    let name = "ai-context-compression-mesh";
    let (yaml, readme) = example(name);
    sbproxy_config::compile_config(&yaml)
        .unwrap_or_else(|error| panic!("{name}/sb.yml must compile: {error:#}"));
    let compression = compression_action(&yaml);
    assert_eq!(compression["state"]["backend"].as_str(), Some("mesh"));

    // The mesh backend is only valid on top of cluster replication; the
    // example must ship the replication block it depends on.
    let parsed = serde_yaml::from_str::<Value>(&yaml).expect("example YAML parses");
    assert!(
        parsed["proxy"]["cluster"]["replication"].is_mapping(),
        "{name}/sb.yml must configure proxy.cluster.replication"
    );

    // The runbook states the backend choice honestly: Redis stays the
    // default recommendation and the contracts differ.
    for required in ["redis", "mesh", "conflict_detected"] {
        assert!(
            readme.to_ascii_lowercase().contains(required),
            "{name}/README.md must mention {required}"
        );
    }
}

#[test]
fn example_runbooks_cover_session_admin_metrics_and_safe_logs() {
    let name = "ai-context-compression-redis";
    let (_, readme) = example(name);
    for required in [
        "x-sb-session-id",
        "/admin/compression/sessions",
        "/admin/compression/sessions/purge",
        "/metrics",
        "sbproxy_ai_compression_tokens_saved_total",
        "sbproxy_ai_compression_request_tokens_saved",
        "ai_compression_summary",
    ] {
        assert!(
            readme.to_ascii_lowercase().contains(required),
            "{name}/README.md must document {required}"
        );
    }
    assert!(
        readme.matches("curl ").count() >= 4,
        "{name} needs runnable curls"
    );

    let legacy = std::fs::read_to_string(
        workspace_root().join("examples/ai-llm-aware-resilience/README.md"),
    )
    .expect("legacy resilience README");
    assert!(legacy.contains("ai-context-compression-redis"));
}
