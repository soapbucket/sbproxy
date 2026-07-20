use std::fs;
use std::path::Path;

use context_compression_eval::{
    evaluate_cases, load_provenance, parse_cases, verify_fixture_set, EvalConfig, EvalPipelineFile,
    FixtureArtifact, ProvenanceManifest, QualitySpec, Recommendation,
};
use sbproxy_ai::compression::inspect_marked_context;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn committed_fixtures_have_verified_provenance_checksums_and_privacy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_bytes = fs::read(root.join("fixtures/provenance.json")).expect("provenance file");
    let manifest = load_provenance(manifest_bytes.as_slice()).expect("valid provenance manifest");

    verify_fixture_set(root, &manifest).expect("fixture provenance and privacy verify");

    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.artifacts.len(), 6);
    assert!(manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.corpus == "ruler_smoke"));
    assert!(manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.corpus == "coding_agent_smoke"));
    for corpus in [
        "rag_select_smoke",
        "compact_serialization_smoke",
        "position_reorder_smoke",
        "phase1_pipeline_smoke",
    ] {
        let artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.corpus == corpus)
            .unwrap_or_else(|| panic!("missing provenance for {corpus}"));
        assert_eq!(
            artifact.provenance,
            "independently_authored_sanitized_shape"
        );
        assert_eq!(artifact.license, "Apache-2.0");
        assert!(!artifact.contains_customer_data);
        assert!(!artifact.official_benchmark_score);
        assert_eq!(artifact.sha256.len(), 64);
    }

    let ruler = fs::read_to_string(root.join("fixtures/ruler-smoke.jsonl")).expect("RULER smoke");
    assert!(ruler.contains("ruler_retrieval"));
    assert!(ruler.contains("ruler_multi_hop"));

    let coding = fs::read_to_string(root.join("fixtures/coding-agent-smoke.jsonl"))
        .expect("coding-agent smoke");
    assert!(coding.contains("tool_calls"));
    assert!(coding.contains("diff --git"));
    assert!(coding.contains("rg --line-number"));
    assert!(coding.contains("ERROR request_failed"));
}

#[test]
fn phase1_fixtures_have_the_declared_synthetic_shapes_and_acceptance() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    let rag = load_cases(root, "fixtures/rag-select-smoke.jsonl");
    assert_eq!(rag.len(), 1);
    let rag_snapshot = inspect_marked_context(&rag[0].messages)
        .expect("valid rag markers")
        .expect("rag block");
    assert!(rag_snapshot.blocks[0].chunks.len() >= 5);
    assert!(rag_snapshot.blocks[0]
        .chunks
        .iter()
        .all(|chunk| chunk.score.is_some()));
    assert!(matches!(
        &rag[0].quality,
        QualitySpec::EvidenceRetention { required_evidence }
            if required_evidence.iter().any(|value| value.contains("EVIDENCE::"))
    ));
    assert!(rag[0]
        .acceptance
        .min_savings_ratio
        .is_some_and(|value| value > 0.0));

    let compact = load_cases(root, "fixtures/compact-serialization-smoke.jsonl");
    assert_eq!(compact.len(), 1);
    assert!(matches!(
        compact[0].quality,
        QualitySpec::StructuredEquivalence { .. }
    ));
    assert_eq!(compact[0].acceptance.min_savings_ratio, Some(0.30));
    assert_eq!(compact[0].acceptance.min_on_quality_score, Some(1.0));
    let compact_snapshot = inspect_marked_context(&compact[0].messages)
        .expect("valid compact markers")
        .expect("compact block");
    let rows: Vec<Value> = serde_json::from_str(&compact_snapshot.blocks[0].chunks[0].body)
        .expect("compact fixture contains JSON rows");
    assert_eq!(rows.len(), 200);
    let keys = rows[0]
        .as_object()
        .expect("row object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert!(rows.iter().all(|row| {
        row.as_object()
            .is_some_and(|row| row.keys().cloned().collect::<Vec<_>>() == keys)
    }));

    let position = load_cases(root, "fixtures/position-reorder-smoke.jsonl");
    assert_eq!(position.len(), 1);
    assert!(matches!(
        position[0].quality,
        QualitySpec::EdgePlacement { .. }
    ));
    assert!(position[0].acceptance.require_non_expanding);
    assert!(position[0]
        .acceptance
        .min_quality_delta
        .is_some_and(|value| value > 0.0));

    let combined = load_cases(root, "fixtures/phase1-pipeline-smoke.jsonl");
    assert_eq!(combined.len(), 1);
    assert!(matches!(
        &combined[0].quality,
        QualitySpec::EvidenceRetention { required_evidence }
            if required_evidence.iter().any(|value| value.contains("phase one launch key"))
                && required_evidence.iter().any(|value| value.contains("EVIDENCE::"))
    ));
    assert!(combined[0]
        .acceptance
        .min_savings_ratio
        .is_some_and(|value| value > 0.0));
}

#[tokio::test]
async fn phase1_fixtures_pass_their_production_pipelines() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (pipeline_path, fixture_path) in [
        (
            "pipelines/rag-select-smoke.json",
            "fixtures/rag-select-smoke.jsonl",
        ),
        (
            "pipelines/compact-serialization-smoke.json",
            "fixtures/compact-serialization-smoke.jsonl",
        ),
        (
            "pipelines/position-reorder-smoke.json",
            "fixtures/position-reorder-smoke.jsonl",
        ),
        (
            "pipelines/phase1-pipeline-smoke.json",
            "fixtures/phase1-pipeline-smoke.jsonl",
        ),
    ] {
        let pipeline: EvalPipelineFile =
            serde_json::from_slice(&fs::read(root.join(pipeline_path)).expect("pipeline fixture"))
                .expect("typed pipeline");
        let report = evaluate_cases(
            &load_cases(root, fixture_path),
            &EvalConfig {
                profile: pipeline.profile,
                levers: pipeline.levers,
                measure_latency: false,
            },
        )
        .await
        .unwrap_or_else(|error| panic!("{pipeline_path} failed: {error:#}"));
        assert_eq!(
            report.overall.recommendation,
            Recommendation::Build,
            "{pipeline_path}: {:#?}",
            report.cases
        );
        assert!(report.overall.acceptance_passed, "{pipeline_path}");
        assert!(report.cases.iter().all(|case| case.acceptance_passed));

        let case = &report.cases[0];
        match pipeline_path {
            "pipelines/compact-serialization-smoke.json" => {
                assert!(case.savings_ratio >= 0.30);
                assert_eq!(case.on.quality_score, Some(1.0));
            }
            "pipelines/position-reorder-smoke.json" => {
                assert!(case.on.output_tokens <= case.off.output_tokens);
                assert!(case.quality_delta.is_some_and(|delta| delta > 0.0));
            }
            "pipelines/phase1-pipeline-smoke.json" => {
                assert!(case.tokens_saved > 0);
                assert_eq!(case.on.quality_score, Some(1.0));
            }
            "pipelines/rag-select-smoke.json" => {
                assert!(case.tokens_saved > 0);
                assert_eq!(case.on.quality_score, Some(1.0));
            }
            _ => unreachable!(),
        }
    }
}

fn load_cases(root: &Path, path: &str) -> Vec<context_compression_eval::EvalCase> {
    let bytes = fs::read(root.join(path)).unwrap_or_else(|error| panic!("read {path}: {error}"));
    parse_cases(bytes.as_slice()).unwrap_or_else(|error| panic!("parse {path}: {error:#}"))
}

#[test]
fn operator_supplied_external_data_keeps_its_own_license() {
    let scratch = std::env::temp_dir().join(format!(
        "compression-external-provenance-{}",
        std::process::id()
    ));
    fs::create_dir_all(&scratch).expect("scratch directory");
    let fixture = r#"{"schema_version":1,"id":"external-1","corpus":"nolima_external","target_model":"gpt-4","messages":[{"role":"user","content":"synthetic context"}],"quality":{"kind":"exact_match","reference_answers":["answer"],"off_prediction":"answer","on_prediction":"answer"}}"#;
    fs::write(scratch.join("external.jsonl"), fixture).expect("external fixture");
    let digest = Sha256::digest(fixture.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let manifest = ProvenanceManifest {
        schema_version: 1,
        artifacts: vec![FixtureArtifact {
            path: "external.jsonl".to_string(),
            corpus: "nolima_external".to_string(),
            provenance: "operator_supplied_external".to_string(),
            license: "Adobe Research License, non-commercial".to_string(),
            contains_customer_data: false,
            official_benchmark_score: false,
            sha256: digest,
        }],
    };

    verify_fixture_set(&scratch, &manifest).expect("operator data retains declared license");

    fs::remove_dir_all(scratch).expect("remove scratch directory");
}
