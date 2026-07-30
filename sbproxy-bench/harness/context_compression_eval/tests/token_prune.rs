use std::fs;
use std::path::Path;

use context_compression_eval::{
    build_stateless_levers, evaluate_cases, load_provenance, parse_cases, render_json,
    render_markdown, verify_fixture_set, EvalConfig, EvalPipelineFile, Recommendation,
};

const FIXTURE: &str = "fixtures/token-prune-smoke.jsonl";
const RECORDED_ENDPOINT: &str = "recorded://token-prune-v1";

fn load_cases(root: &Path) -> Vec<context_compression_eval::EvalCase> {
    let bytes = fs::read(root.join(FIXTURE)).expect("token-prune fixture");
    parse_cases(bytes.as_slice()).expect("valid token-prune cases")
}

fn load_pipeline(root: &Path, name: &str) -> EvalPipelineFile {
    serde_json::from_slice(
        &fs::read(root.join(format!("pipelines/{name}.json"))).expect("token-prune pipeline"),
    )
    .expect("typed token-prune pipeline")
}

#[test]
fn fixture_and_recorded_backend_have_closed_provenance() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases = load_cases(root);
    let manifest = load_provenance(
        fs::read(root.join("fixtures/provenance.json"))
            .expect("provenance manifest")
            .as_slice(),
    )
    .expect("valid provenance manifest");

    verify_fixture_set(root, &manifest).expect("fixture provenance verifies");
    assert_eq!(cases.len(), 2);
    assert!(cases.iter().all(|case| case.acceptance.is_complete()));
    let provenance = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == FIXTURE)
        .expect("token-prune fixture has declared provenance");
    assert_eq!(
        provenance.provenance,
        "independently_authored_recorded_token_prune_smoke"
    );
    assert_eq!(provenance.license, "Apache-2.0");
    assert!(!provenance.contains_customer_data);
    assert!(!provenance.official_benchmark_score);
}

#[test]
fn deterministic_harness_rejects_live_token_prune_endpoints() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut pipeline = load_pipeline(root, "token-prune-retain-smoke");
    let mut serialized = serde_json::to_value(&pipeline.levers[0]).expect("serialize lever");
    assert_eq!(serialized["endpoint"], RECORDED_ENDPOINT);
    serialized["endpoint"] = serde_json::Value::String("http://127.0.0.1:9440".to_string());
    pipeline.levers[0] = serde_json::from_value(serialized).expect("typed live endpoint");

    let error = match build_stateless_levers(&pipeline.levers) {
        Ok(_) => panic!("the harness must never dial a sidecar"),
        Err(error) => error,
    };
    assert!(error.to_string().contains(RECORDED_ENDPOINT));
}

#[tokio::test]
async fn recorded_backend_rejects_unrecorded_marked_spans() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pipeline = load_pipeline(root, "token-prune-retain-smoke");
    let mut case = load_cases(root).remove(0);
    let content = case.messages[1]["content"]
        .as_str()
        .expect("marked content")
        .replace(
            "EVIDENCE::route-owner=cedar.",
            "EVIDENCE::unrecorded-owner=cedar.",
        );
    case.messages[1]["content"] = serde_json::Value::String(content);

    let report = evaluate_cases(
        &[case],
        &EvalConfig {
            profile: pipeline.profile,
            levers: pipeline.levers,
            measure_latency: false,
        },
    )
    .await
    .expect("closed backend result");

    assert_eq!(report.cases[0].outcome, "failed");
    assert_eq!(
        report.cases[0].reason.as_deref(),
        Some("invalid_token_prune_output")
    );
    assert_eq!(report.overall.recommendation, Recommendation::Defer);
}

#[tokio::test]
async fn retain_ratio_and_target_token_modes_save_tokens_with_quality_within_noise() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases = load_cases(root);

    for name in ["token-prune-retain-smoke", "token-prune-target-smoke"] {
        let pipeline = load_pipeline(root, name);
        let report = evaluate_cases(
            &cases,
            &EvalConfig {
                profile: pipeline.profile,
                levers: pipeline.levers,
                measure_latency: false,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{name} failed: {error:#}"));

        assert_eq!(report.overall.recommendation, Recommendation::Build);
        assert!(report.overall.acceptance_passed);
        assert!(report.overall.tokens_saved > 0);
        assert!(report.overall.savings_ratio >= 0.30);
        assert_eq!(report.overall.on_quality_score, Some(1.0));
        assert_eq!(report.overall.quality_delta, Some(0.0));
        assert!(report.cases.iter().all(|case| {
            case.acceptance_passed
                && case.tokens_saved > 0
                && case.on.quality_score == Some(1.0)
                && case.quality_delta.is_some_and(|delta| delta >= -0.02)
                && case.levers.len() == 1
                && case.levers[0].lever == "token_prune"
                && case.levers[0].outcome == "applied"
        }));

        let json = render_json(&report).expect("JSON report");
        assert!(json.contains("\"evaluation_backend\": \"deterministic_recorded_v1\""));
        assert!(json.contains("\"production_backend\": \"llmlingua_2_sidecar\""));
        assert!(json.contains("\"network_access\": false"));
        let markdown = render_markdown(&report);
        assert!(markdown.contains("deterministic recorded backend"));
        assert!(markdown.contains("LLMLingua-2 sidecar"));
    }
}
