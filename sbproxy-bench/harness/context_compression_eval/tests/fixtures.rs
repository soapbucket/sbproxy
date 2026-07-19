use std::fs;
use std::path::Path;

use context_compression_eval::{load_provenance, verify_fixture_set};
use context_compression_eval::{FixtureArtifact, ProvenanceManifest};
use sha2::{Digest, Sha256};

#[test]
fn committed_fixtures_have_verified_provenance_checksums_and_privacy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest_bytes = fs::read(root.join("fixtures/provenance.json")).expect("provenance file");
    let manifest = load_provenance(manifest_bytes.as_slice()).expect("valid provenance manifest");

    verify_fixture_set(root, &manifest).expect("fixture provenance and privacy verify");

    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.artifacts.len(), 2);
    assert!(manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.corpus == "ruler_smoke"));
    assert!(manifest
        .artifacts
        .iter()
        .any(|artifact| artifact.corpus == "coding_agent_smoke"));

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
