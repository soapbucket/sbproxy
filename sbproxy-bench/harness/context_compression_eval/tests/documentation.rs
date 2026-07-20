use std::fs;
use std::path::Path;

#[test]
fn operator_docs_qualify_retrieval_skip_reasons_and_json_fallbacks() {
    let harness = Path::new(env!("CARGO_MANIFEST_DIR"));
    let docs = fs::read_to_string(
        harness
            .ancestors()
            .nth(3)
            .expect("repository root")
            .join("docs/ai-context-compression.md"),
    )
    .expect("AI context compression docs");
    let normalized = docs.split_whitespace().collect::<Vec<_>>().join(" ");

    for required in [
        "Block- and chunk-local conditions become aggregate skip reasons only when no other block or chunk changes.",
        "If any block or chunk changes, the lever returns the complete candidate with all unchanged local data copied byte-for-byte.",
        "The runner records `applied` when that candidate satisfies the lever's commit rule; otherwise it records `skipped`, `no_savings`.",
        "Invalid JSON in a marked JSON chunk | `skipped`, `unsafe_structured_shape` only when no other chunk changes",
        "Valid nested, heterogeneous, or otherwise table-ineligible JSON | `applied`; `skipped`, `not_needed`; or runner `skipped`, `no_savings`",
        "Still eligible for deterministic JSON minification; shape alone is not unsafe",
    ] {
        assert!(
            normalized.contains(required),
            "operator docs missing `{required}`"
        );
    }
    assert!(
        !normalized.contains(
            "JSON is invalid, nested, heterogeneous, or otherwise unsafe for table encoding | `skipped`, `unsafe_structured_shape`"
        ),
        "valid table-ineligible JSON must not be described as unsafe structured input"
    );
}

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
    let normalized_readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized_readme.contains(
            "On malformed or oversized marked context, the affected retrieval-aware lever leaves its input message list unchanged and exposes only a sanitized closed skip reason."
        ),
        "README must scope marked-context fail-open behavior to the affected retrieval-aware lever"
    );
    assert!(
        !normalized_readme.contains("whole request"),
        "README must not promise that the whole request remains unchanged"
    );
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
