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
        "target-model",
        "coding-agent",
    ] {
        assert!(readme.contains(required), "README missing `{required}`");
    }

    let workflow = fs::read_to_string(
        harness
            .ancestors()
            .nth(3)
            .expect("repository root")
            .join(".github/workflows/context-compression-eval.yml"),
    )
    .expect("context-compression eval workflow");
    assert!(workflow.contains("cargo fmt --manifest-path"));
    assert!(workflow.contains("cargo test --manifest-path"));
    assert!(workflow.contains("cargo clippy --manifest-path"));
    assert!(workflow.contains("cargo run --manifest-path"));
    assert!(workflow.matches("--locked").count() >= 3);
    assert!(workflow.contains(" check"));
}
