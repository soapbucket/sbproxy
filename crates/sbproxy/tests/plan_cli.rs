//! Integration tests for the WOR-180 `sbproxy plan` subcommand.
//!
//! These exercise the binary end to end with two YAML fixtures:
//! a `--against` baseline and a proposed config that adds an origin.
//! The text output must surface the added origin with the `+` sigil
//! and the JSON output must conform to the v1 envelope shape.
//!
//! Apply-side integration is not covered here: `apply` calls the
//! global hot-reload primitive, which mutates a process-wide
//! `OnceLock` and would race with any other test running in the same
//! binary. The library-level tests in `crates/sbproxy-config` cover
//! the diff engine; this file owns the CLI surface only.

use std::io::Write;
use std::process::Command;

const BASELINE_YAML: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;

const PROPOSED_YAML: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
  www.example.com:
    action:
      type: static
      body: "hello"
"#;

/// Path to the `sbproxy` binary built by Cargo for this test target.
fn sbproxy_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by Cargo for integration tests in the
    // same package as the binary. See
    // https://doc.rust-lang.org/cargo/reference/environment-variables.html.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_sbproxy"))
}

fn write_fixture(name: &str, body: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("sbproxy-plan-cli-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    let p = dir.join(format!("{name}.yml"));
    let mut f = std::fs::File::create(&p).expect("create yaml fixture");
    f.write_all(body.as_bytes()).expect("write yaml");
    p
}

#[test]
fn plan_against_baseline_emits_added_origin_in_text_output() {
    let baseline = write_fixture("baseline", BASELINE_YAML);
    let proposed = write_fixture("proposed", PROPOSED_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--against")
        .arg(&baseline)
        .arg("--format")
        .arg("text")
        .output()
        .expect("run sbproxy plan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Exit code 2 means changes are present (terraform-style).
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for changes-present plan; stderr was:\n{stderr}"
    );
    assert!(
        stdout.contains("+ origins.www.example.com"),
        "expected '+ origins.www.example.com' in text output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("[reload]"),
        "expected '[reload]' blast-radius badge in text output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("1 added"),
        "expected '1 added' summary line, got:\n{stdout}"
    );
}

#[test]
fn plan_against_baseline_emits_stable_json_envelope() {
    let baseline = write_fixture("baseline", BASELINE_YAML);
    let proposed = write_fixture("proposed", PROPOSED_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--against")
        .arg(&baseline)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run sbproxy plan --format json");

    assert_eq!(out.status.code(), Some(2), "expected exit 2 for json plan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("plan stdout is valid JSON");
    assert_eq!(json["plan_version"], 1);
    assert_eq!(json["max_blast_radius"], "reload");
    let entries = json["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "added");
    assert_eq!(entries[0]["path"], "origins.www.example.com");
    assert_eq!(entries[0]["blast_radius"], "reload");
}

#[test]
fn plan_against_self_is_noop_exit_zero() {
    let proposed = write_fixture("proposed", PROPOSED_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--against")
        .arg(&proposed)
        .output()
        .expect("run sbproxy plan against self");

    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 for no-op plan; stderr was:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No changes"), "got:\n{stdout}");
}
