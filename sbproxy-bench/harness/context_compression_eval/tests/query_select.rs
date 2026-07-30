use std::fs;
use std::path::Path;

use context_compression_eval::{
    evaluate_cases, load_provenance, parse_cases, verify_fixture_set, EvalConfig, EvalPipelineFile,
    QualitySpec, Recommendation,
};
use sbproxy_ai::compression::inspect_marked_context;

fn load_cases(root: &Path) -> Vec<context_compression_eval::EvalCase> {
    let bytes =
        fs::read(root.join("fixtures/query-select-smoke.jsonl")).expect("query-select fixture");
    parse_cases(bytes.as_slice()).expect("valid query-select cases")
}

#[test]
fn fixture_covers_multi_document_qa_and_missing_query_fallback() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases = load_cases(root);
    let manifest = load_provenance(
        fs::read(root.join("fixtures/provenance.json"))
            .expect("provenance manifest")
            .as_slice(),
    )
    .expect("valid provenance manifest");

    assert_eq!(cases.len(), 2);
    verify_fixture_set(root, &manifest).expect("fixture provenance verifies");
    let provenance = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == "fixtures/query-select-smoke.jsonl")
        .expect("query-select fixture has declared provenance");
    assert_eq!(provenance.corpus, "query_select_smoke");
    assert_eq!(
        provenance.provenance,
        "independently_authored_sanitized_shape"
    );
    assert_eq!(provenance.license, "Apache-2.0");
    assert!(!provenance.contains_customer_data);
    assert!(!provenance.official_benchmark_score);

    let multi_document = cases
        .iter()
        .find(|case| case.id == "query_select_multi_document_qa")
        .expect("multi-document case");
    let snapshot = inspect_marked_context(&multi_document.messages)
        .expect("valid marked context")
        .expect("marked retrieval context");
    assert_eq!(snapshot.blocks.len(), 1);
    assert!(snapshot.blocks[0].chunks.len() >= 5);
    assert!(snapshot.blocks[0]
        .chunks
        .iter()
        .all(|chunk| chunk.format == "text"));
    assert!(matches!(
        &multi_document.quality,
        QualitySpec::EvidenceRetention { required_evidence }
            if required_evidence == &[
                "EVIDENCE::shipment-depot=mistral".to_string(),
                "EVIDENCE::mistral-access=cedar-seven".to_string(),
            ]
    ));
    assert!(multi_document.acceptance.is_complete());

    let fallback = cases
        .iter()
        .find(|case| case.id == "query_select_missing_query_fallback")
        .expect("fallback case");
    assert!(
        inspect_marked_context(&fallback.messages)
            .expect("valid unmarked messages")
            .is_none(),
        "the fallback case must omit marked query context"
    );
    assert!(fallback.acceptance.is_complete());
}

#[tokio::test]
async fn production_pipeline_retains_answers_and_reduces_tokens_with_fallback() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pipeline: EvalPipelineFile = serde_json::from_slice(
        &fs::read(root.join("pipelines/query-select-smoke.json")).expect("query-select pipeline"),
    )
    .expect("typed query-select pipeline");

    let report = evaluate_cases(
        &load_cases(root),
        &EvalConfig {
            profile: pipeline.profile,
            levers: pipeline.levers,
            measure_latency: false,
        },
    )
    .await
    .expect("query-select evaluation");

    assert_eq!(report.overall.recommendation, Recommendation::Build);
    assert!(report.overall.acceptance_passed);
    assert_eq!(report.overall.on_quality_score, Some(1.0));
    assert_eq!(report.overall.quality_delta, Some(0.0));
    assert!(report.overall.tokens_saved > 0);
    assert!(report.overall.savings_ratio >= 0.40);

    let multi_document = report
        .cases
        .iter()
        .find(|case| case.id == "query_select_multi_document_qa")
        .expect("multi-document report");
    assert_eq!(multi_document.off.quality_score, Some(1.0));
    assert_eq!(multi_document.on.quality_score, Some(1.0));
    assert!(multi_document.tokens_saved > 0);
    assert!(multi_document.savings_ratio >= 0.40);
    assert!(multi_document.acceptance_passed);
    assert_eq!(multi_document.levers[0].lever, "query_select");
    assert_eq!(multi_document.levers[0].outcome, "applied");

    let fallback = report
        .cases
        .iter()
        .find(|case| case.id == "query_select_missing_query_fallback")
        .expect("fallback report");
    assert_eq!(fallback.off.quality_score, Some(1.0));
    assert_eq!(fallback.on.quality_score, Some(1.0));
    assert!(fallback.tokens_saved > 0);
    assert!(fallback.acceptance_passed);
    assert_eq!(fallback.levers[0].lever, "query_select");
    assert_eq!(fallback.levers[0].outcome, "skipped");
    assert_eq!(fallback.levers[0].reason.as_deref(), Some("missing_query"));
    assert_eq!(fallback.levers[1].lever, "window_fit");
    assert_eq!(fallback.levers[1].outcome, "applied");
}
