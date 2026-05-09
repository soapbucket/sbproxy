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

// --- WOR-180 scope-3 plan-time semantic-validation integration tests ---
//
// These exercise the end-to-end CLI: an YAML fixture that triggers a
// rule, an `sbproxy plan` invocation, and the expected exit code 3
// plus the expected finding in the JSON envelope and text output.

const ORPHAN_FALLBACK_YAML: &str = r#"
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    fallback_origin:
      type: proxy
      url: https://undefined.example.com
"#;

const MISSING_SECRET_YAML: &str = r#"
proxy:
  secrets:
    backend: env
    map:
      jwt_signing_key: KV_JWT_KEY
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
    authentication:
      type: jwt
      secret: "secret:wrong_key_name"
"#;

#[test]
fn plan_orphan_fallback_origin_exits_three_with_finding() {
    let proposed = write_fixture("orphan-fallback", ORPHAN_FALLBACK_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run sbproxy plan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        out.status.code(),
        Some(3),
        "expected exit 3 for orphan-fallback-origin; stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("plan stdout is valid JSON");
    let findings = json["findings"]
        .as_array()
        .expect("findings array on plan envelope");
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "orphan-fallback-origin" && f["severity"] == "error"),
        "expected orphan-fallback-origin finding in {findings:?}"
    );
}

#[test]
fn plan_orphan_fallback_origin_text_renders_finding() {
    let proposed = write_fixture("orphan-fallback-text", ORPHAN_FALLBACK_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--format")
        .arg("text")
        .output()
        .expect("run sbproxy plan --format text");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "expected exit 3");
    assert!(
        stdout.contains("Validation:"),
        "expected 'Validation:' header in text output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("orphan-fallback-origin"),
        "expected rule id in text output, got:\n{stdout}"
    );
}

#[test]
fn plan_missing_secret_exits_three_with_finding() {
    let proposed = write_fixture("missing-secret", MISSING_SECRET_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run sbproxy plan");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        out.status.code(),
        Some(3),
        "expected exit 3 for missing-vault-key; stderr:\n{stderr}\nstdout:\n{stdout}"
    );

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("plan stdout is valid JSON");
    let findings = json["findings"]
        .as_array()
        .expect("findings array on plan envelope");
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "missing-vault-key" && f["severity"] == "error"),
        "expected missing-vault-key finding in {findings:?}"
    );
}

#[test]
fn plan_clean_config_has_empty_findings() {
    // The base PROPOSED_YAML uses only well-known module types and
    // has no fallback / forward-rule origin references. The findings
    // array on the plan envelope should be empty.
    let proposed = write_fixture("clean", PROPOSED_YAML);

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--format")
        .arg("json")
        .output()
        .expect("run sbproxy plan");

    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for clean plan with changes"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("plan stdout valid JSON");
    let findings = json["findings"]
        .as_array()
        .expect("findings array on plan envelope");
    assert!(
        findings.is_empty(),
        "expected zero findings on clean config, got: {findings:?}"
    );
}
