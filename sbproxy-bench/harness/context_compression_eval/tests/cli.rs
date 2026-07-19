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
        "--input",
        "fixtures/ruler-smoke.jsonl",
        "--input",
        "fixtures/coding-agent-smoke.jsonl",
        "--provenance",
        "fixtures/provenance.json",
        "--input-budget-tokens",
        "192",
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
    assert!(json.contains("\"input_budget_tokens\": 192"));
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
fn committed_report_matches_deterministic_regeneration() {
    let checked = command()
        .args([
            "check",
            "--input",
            "fixtures/ruler-smoke.jsonl",
            "--input",
            "fixtures/coding-agent-smoke.jsonl",
            "--provenance",
            "fixtures/provenance.json",
            "--input-budget-tokens",
            "192",
            "--json-report",
            "reports/window-fit-smoke.json",
            "--markdown-report",
            "reports/window-fit-smoke.md",
        ])
        .output()
        .expect("run committed report check");

    assert!(
        checked.status.success(),
        "committed report drifted: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
