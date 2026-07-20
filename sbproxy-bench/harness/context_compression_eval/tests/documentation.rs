use std::fs;
use std::path::Path;

#[test]
fn readme_and_workflow_cover_reproducibility_and_external_data_boundaries() {
    let harness = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(harness.join("README.md")).expect("harness README");
    for required in [
        "RULER",
        "HELMET",
        "LongBench-v2",
        "NoLiMa",
        "non-commercial",
        "operator-supplied",
        "not an official benchmark score",
        "--measure-latency",
        "--pipeline-config",
        "target-model",
        "coding-agent",
        "import-and-report-only",
        "does not run a target model",
        "does not generate off/on predictions",
        "<sbproxy-retrieval>",
        "<sbproxy-query>",
        "<sbproxy-chunk",
        "CompressionLeverConfig",
        "stateful levers are not supported",
        "structured_equivalence",
        "edge_placement",
        "one-chunk block scores 1",
        "200 uniform rows",
        "rag-select-smoke",
        "compact-serialization-smoke",
        "position-reorder-smoke",
        "phase1-pipeline-smoke",
        "independently authored",
        "contains no customer data",
        "does not claim official benchmark scores",
    ] {
        assert!(readme.contains(required), "README missing `{required}`");
    }
    assert!(!readme.contains("--input-budget-tokens"));
    assert!(!readme.contains("--completion-reserve-tokens"));
    assert!(!readme.contains("WOR-1879"));

    let workflow = fs::read_to_string(
        harness
            .ancestors()
            .nth(3)
            .expect("repository root")
            .join(".github/workflows/context-compression-eval.yml"),
    )
    .expect("context-compression eval workflow");
    assert!(workflow.contains("cargo fmt --manifest-path"));
    assert!(workflow.contains("taiki-e/install-action@nextest"));
    assert!(workflow.contains("cargo nextest run --manifest-path"));
    assert!(workflow.contains("cargo clippy --manifest-path"));
    assert!(workflow.contains("cargo run --manifest-path"));
    assert!(workflow.matches("--locked").count() >= 3);
    assert!(workflow.matches("timeout-minutes: 35").count() >= 2);
    assert!(!workflow.contains("--input-budget-tokens"));
    assert!(!workflow.contains("--completion-reserve-tokens"));
    assert!(workflow.contains(" check"));
    for report in [
        "rag-select-smoke",
        "compact-serialization-smoke",
        "position-reorder-smoke",
        "phase1-pipeline-smoke",
        "window-fit-smoke",
    ] {
        assert!(
            workflow.contains(&format!("pipelines/{report}.json")),
            "workflow missing {report} pipeline"
        );
        assert!(
            workflow.contains(&format!("reports/{report}.json")),
            "workflow missing {report} JSON report"
        );
        assert!(
            workflow.contains(&format!("reports/{report}.md")),
            "workflow missing {report} Markdown report"
        );
    }
    for production_path in [
        "crates/sbproxy-core/src/compression_runtime.rs",
        "crates/sbproxy-core/src/server/ai_dispatch.rs",
        "crates/sbproxy-ai/src/compression/**",
        "crates/sbproxy-ai/src/context_compress.rs",
        "crates/sbproxy-ai/src/context_overflow.rs",
        "crates/sbproxy-ai/src/token_estimate.rs",
        "schemas/ai-compression.schema.json",
        "schemas/sb-config.schema.json",
    ] {
        assert!(
            workflow.matches(production_path).count() >= 2,
            "workflow must run for pull requests and main pushes that change `{production_path}`"
        );
    }
}
