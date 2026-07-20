use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "context-compression-eval-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("scratch directory");
    path
}

fn command() -> Command {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_context-compression-eval"));
    command.current_dir(&root);
    command
}

#[test]
fn generate_then_check_detects_report_drift() {
    let scratch = scratch_dir();
    let json_report = scratch.join("report.json");
    let markdown_report = scratch.join("report.md");
    let common = [
        "--pipeline-config",
        "pipelines/window-fit-smoke.json",
        "--input",
        "fixtures/ruler-smoke.jsonl",
        "--input",
        "fixtures/coding-agent-smoke.jsonl",
        "--provenance",
        "fixtures/provenance.json",
        "--json-report",
        json_report.to_str().expect("UTF-8 scratch path"),
        "--markdown-report",
        markdown_report.to_str().expect("UTF-8 scratch path"),
    ];

    let generated = command()
        .arg("generate")
        .args(common)
        .output()
        .expect("run generate");
    assert!(
        generated.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let json = fs::read_to_string(&json_report).expect("JSON report");
    assert!(json.contains("\"ruler_smoke\""));
    assert!(json.contains("\"schema_version\": 3"));
    assert!(json.contains("\"profile\": \"window-fit-smoke-v1\""));
    assert!(json.contains("\"type\": \"window_fit\""));
    assert!(fs::read_to_string(&markdown_report)
        .expect("Markdown report")
        .contains("coding_agent_smoke"));

    let checked = command()
        .arg("check")
        .args(common)
        .output()
        .expect("run check");
    assert!(
        checked.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&checked.stderr)
    );

    fs::write(&json_report, "{}\n").expect("tamper report");
    let drifted = command()
        .arg("check")
        .args(common)
        .output()
        .expect("run drift check");
    assert!(!drifted.status.success());
    assert!(String::from_utf8_lossy(&drifted.stderr).contains("JSON report drift"));

    fs::remove_dir_all(scratch).expect("remove scratch directory");
}

#[test]
fn committed_reports_match_deterministic_regeneration() {
    for (name, input) in [
        ("rag-select-smoke", "fixtures/rag-select-smoke.jsonl"),
        (
            "compact-serialization-smoke",
            "fixtures/compact-serialization-smoke.jsonl",
        ),
        (
            "position-reorder-smoke",
            "fixtures/position-reorder-smoke.jsonl",
        ),
        (
            "phase1-pipeline-smoke",
            "fixtures/phase1-pipeline-smoke.jsonl",
        ),
    ] {
        let pipeline = format!("pipelines/{name}.json");
        let json_report = format!("reports/{name}.json");
        let markdown_report = format!("reports/{name}.md");
        let checked = command()
            .args([
                "check",
                "--pipeline-config",
                &pipeline,
                "--input",
                input,
                "--provenance",
                "fixtures/provenance.json",
                "--json-report",
                &json_report,
                "--markdown-report",
                &markdown_report,
            ])
            .output()
            .expect("run committed report check");
        assert!(
            checked.status.success(),
            "{name} report drifted: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
    }

    let checked = command()
        .args([
            "check",
            "--pipeline-config",
            "pipelines/window-fit-smoke.json",
            "--input",
            "fixtures/ruler-smoke.jsonl",
            "--input",
            "fixtures/coding-agent-smoke.jsonl",
            "--provenance",
            "fixtures/provenance.json",
            "--json-report",
            "reports/window-fit-smoke.json",
            "--markdown-report",
            "reports/window-fit-smoke.md",
        ])
        .output()
        .expect("run committed window-fit report check");
    assert!(
        checked.status.success(),
        "window-fit-smoke report drifted: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
}

#[test]
fn check_rejects_a_byte_stable_non_build_recommendation() {
    let scratch = scratch_dir();
    let pipeline = scratch.join("pipeline.json");
    let json_report = scratch.join("report.json");
    let markdown_report = scratch.join("report.md");
    fs::write(
        &pipeline,
        r#"{
  "schema_version": 1,
  "profile": "non-build-smoke-v1",
  "levers": [
    { "type": "position_reorder", "ranking": "supplied" }
  ]
}
"#,
    )
    .expect("pipeline file");
    let common = [
        "--pipeline-config",
        pipeline.to_str().expect("UTF-8 pipeline path"),
        "--input",
        "fixtures/ruler-smoke.jsonl",
        "--provenance",
        "fixtures/provenance.json",
        "--json-report",
        json_report.to_str().expect("UTF-8 scratch path"),
        "--markdown-report",
        markdown_report.to_str().expect("UTF-8 scratch path"),
    ];

    let generated = command()
        .arg("generate")
        .args(common)
        .output()
        .expect("run generate");
    assert!(
        generated.status.success(),
        "generate failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert!(fs::read_to_string(&json_report)
        .expect("JSON report")
        .contains("\"recommendation\": \"defer\""));

    let checked = command()
        .arg("check")
        .args(common)
        .output()
        .expect("run check");
    assert!(!checked.status.success());
    assert!(String::from_utf8_lossy(&checked.stderr)
        .contains("overall recommendation is defer, expected build"));

    fs::remove_dir_all(scratch).expect("remove scratch directory");
}

#[test]
fn pipeline_schema_version_is_checked_before_evaluation() {
    let scratch = scratch_dir();
    let pipeline = scratch.join("pipeline.json");
    let json_report = scratch.join("report.json");
    let markdown_report = scratch.join("report.md");
    fs::write(
        &pipeline,
        r#"{"schema_version":2,"profile":"future","levers":[]}"#,
    )
    .expect("future pipeline");
    let generated = command()
        .args([
            "generate",
            "--pipeline-config",
            pipeline.to_str().expect("UTF-8 pipeline path"),
            "--input",
            "fixtures/ruler-smoke.jsonl",
            "--provenance",
            "fixtures/provenance.json",
            "--json-report",
            json_report.to_str().expect("UTF-8 scratch path"),
            "--markdown-report",
            markdown_report.to_str().expect("UTF-8 scratch path"),
        ])
        .output()
        .expect("run generate");

    assert!(!generated.status.success());
    assert!(String::from_utf8_lossy(&generated.stderr)
        .contains("unsupported pipeline schema version 2"));
    fs::remove_dir_all(scratch).expect("remove scratch directory");
}

#[test]
fn report_cli_requires_pipeline_and_exposes_no_legacy_budget_or_profile_flags() {
    let help = command()
        .args(["generate", "--help"])
        .output()
        .expect("run help");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    assert!(stdout.contains("--pipeline-config"));
    assert!(!stdout.contains("--input-budget-tokens"));
    assert!(!stdout.contains("--completion-reserve-tokens"));
    assert!(!stdout.contains("--profile"));

    let missing = command()
        .args([
            "generate",
            "--input",
            "fixtures/ruler-smoke.jsonl",
            "--provenance",
            "fixtures/provenance.json",
            "--json-report",
            "/tmp/context-compression-missing-pipeline.json",
            "--markdown-report",
            "/tmp/context-compression-missing-pipeline.md",
        ])
        .output()
        .expect("run missing pipeline command");
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("--pipeline-config"));
}
