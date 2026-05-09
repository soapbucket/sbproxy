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

// --- WOR-180 scope-4-5 plan-file + flock + matrix integration tests ---

const PROXY_BIND_CHANGE_YAML: &str = r#"
proxy:
  http_bind_port: 9090
origins:
  api.example.com:
    action:
      type: proxy
      url: https://upstream.example.com
"#;

#[test]
fn plan_with_out_writes_plan_file_with_baseline_revision() {
    let baseline = write_fixture("baseline-pf", BASELINE_YAML);
    let proposed = write_fixture("proposed-pf", PROPOSED_YAML);
    let plan_dir = std::env::temp_dir().join(format!(
        "sbproxy-plan-out-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&plan_dir).unwrap();
    let plan_file_path = plan_dir.join("plan.json");

    let out = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed)
        .arg("--against")
        .arg(&baseline)
        .arg("--format")
        .arg("text")
        .arg("--out")
        .arg(&plan_file_path)
        .output()
        .expect("run sbproxy plan --out");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for changes-present; stderr:\n{stderr}"
    );
    assert!(
        plan_file_path.exists(),
        "expected plan-file at {plan_file_path:?}"
    );

    // The plan-file is JSON with a stable schema: plan_file_version,
    // baseline_revision (64-hex), report.
    let body = std::fs::read_to_string(&plan_file_path).expect("read plan-file");
    let json: serde_json::Value = serde_json::from_str(&body).expect("plan-file is JSON");
    assert_eq!(json["plan_file_version"], 1);
    let rev = json["baseline_revision"]
        .as_str()
        .expect("baseline_revision string");
    assert_eq!(rev.len(), 64, "expected SHA-256 hex; got {rev}");
    assert!(
        json["report"]["entries"].is_array(),
        "expected nested report.entries array"
    );
}

#[test]
fn apply_p_rejects_stale_plan_with_exit_five() {
    // Generate a plan-file against an empty baseline. Then mutate the
    // SB_APPLY_BASELINE so the live revision differs at apply time;
    // apply -p must exit 5.
    let baseline_yaml = write_fixture("apply-stale-baseline", BASELINE_YAML);
    let proposed_yaml = write_fixture("apply-stale-proposed", PROPOSED_YAML);
    let plan_dir = std::env::temp_dir().join(format!(
        "sbproxy-apply-stale-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&plan_dir).unwrap();
    let plan_file_path = plan_dir.join("plan.json");

    // Step 1: write a plan-file against the (file) baseline.
    let plan_run = Command::new(sbproxy_bin())
        .arg("plan")
        .arg("-f")
        .arg(&proposed_yaml)
        .arg("--against")
        .arg(&baseline_yaml)
        .arg("--out")
        .arg(&plan_file_path)
        .output()
        .expect("run sbproxy plan --out");
    assert!(
        matches!(plan_run.status.code(), Some(0) | Some(2)),
        "plan should succeed; got {:?}",
        plan_run.status.code()
    );
    assert!(plan_file_path.exists());

    // Step 2: invoke apply -p with SB_APPLY_BASELINE pointing at a
    // **different** YAML so the recomputed live revision differs.
    let drifted_baseline = write_fixture("apply-stale-drifted", PROXY_BIND_CHANGE_YAML);
    let apply_run = Command::new(sbproxy_bin())
        .arg("apply")
        .arg("-p")
        .arg(&plan_file_path)
        .env("SB_APPLY_CONFIG", &proposed_yaml)
        .env("SB_APPLY_BASELINE", &drifted_baseline)
        .output()
        .expect("run sbproxy apply -p");

    let stderr = String::from_utf8_lossy(&apply_run.stderr);
    assert_eq!(
        apply_run.status.code(),
        Some(5),
        "expected exit 5 for stale baseline; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("plan-file is stale") || stderr.contains("baseline_revision"),
        "expected staleness message; stderr:\n{stderr}"
    );
}

#[test]
fn apply_lock_rejects_concurrent_apply_with_exit_six() {
    // Take the apply lock manually, then run `sbproxy apply -f` and
    // assert it exits 6 (lock contention). We use the public
    // `<yaml>.applylock` companion file so the held-lock fd in this
    // test process collides with the binary's flock attempt.
    use fs2::FileExt as _;

    let yaml = write_fixture("apply-lock", BASELINE_YAML);
    let lock_path = format!("{}.applylock", yaml.to_string_lossy());

    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open lock file");
    lock_file.try_lock_exclusive().expect("acquire lock");

    let out = Command::new(sbproxy_bin())
        .arg("apply")
        .arg("-f")
        .arg(&yaml)
        .output()
        .expect("run sbproxy apply -f under lock contention");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(6),
        "expected exit 6 for lock contention; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("apply is in progress") || stderr.contains("could not lock"),
        "expected lock contention message; stderr:\n{stderr}"
    );

    // Drop via explicit unlock so the test does not rely on impl
    // details of File::drop.
    let _ = lock_file.unlock();
}

#[test]
fn plan_proxy_bind_port_change_is_restart_in_text_output() {
    // Per WOR-180 step 4: the per-path matrix must flag
    // `proxy.http_bind_port` as Restart-class. The plan entry's
    // blast-radius badge in text output must read [restart].
    let baseline = write_fixture("matrix-baseline", BASELINE_YAML);
    let proposed = write_fixture("matrix-proxy-bind", PROXY_BIND_CHANGE_YAML);

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
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2; stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("[restart]"),
        "expected '[restart]' badge in matrix-driven plan output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("max-blast-radius: restart"),
        "expected restart in summary footer, got:\n{stdout}"
    );
}
