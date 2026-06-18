//! End-to-end coverage for the agent-detect -> CEL binding (WOR-589),
//! exercising the whole detection path landed across WOR-499:
//!
//!   signal extraction -> rule-pack scorer (WOR-706) -> AgentDetection
//!   stored on the request context -> `request.agent.*` CEL binding.
//!
//! With `proxy.extensions.agent_detect` enabled and an ADRF rule pack,
//! the proxy scores each request and exposes the verdict to CEL. This
//! test stacks an `expression` policy that allows only low-score
//! traffic (`request.agent.score < 80`) and confirms a request whose
//! User-Agent matches a high-score rule is blocked while ordinary
//! traffic passes.

use std::io::Write;
use std::path::PathBuf;

use sbproxy_e2e::ProxyHarness;
use tempfile::NamedTempFile;

// ADRF v0 rule pack: a TestBot/* User-Agent scores 95.
const RULE_PACK: &str = r#"version: 0
agents:
  - id: test-bot
    match:
      user_agent_pattern: '^TestBot/'
    provenance: unsigned-named
    score: 95
    confidence: 0.9
"#;

fn config_yaml(rule_pack_path: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  extensions:
    agent_detect:
      enabled: true
      rule_pack_path: "{rule_pack_path}"
origins:
  "detect.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: 'request.agent.score < 80'
        deny_status: 403
        deny_message: "high agent score blocked"
"#
    )
}

fn onnx_only_config_yaml(onnx_model_path: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  extensions:
    agent_detect:
      enabled: true
      onnx_model_path: "{onnx_model_path}"
origins:
  "detect.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
"#
    )
}

fn fixture_model_path() -> String {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate lives under workspace root")
        .to_path_buf();
    workspace_root
        .join("crates/sbproxy-agent-detect/fixtures/ja4_catboost_fixture.onnx")
        .to_str()
        .expect("fixture path is utf8")
        .to_string()
}

fn fetch_metrics(harness: &ProxyHarness) -> String {
    let resp = harness
        .get("/metrics", "detect.localhost")
        .expect("metrics");
    assert_eq!(resp.status, 200);
    resp.text().unwrap_or_default()
}

#[test]
fn high_score_agent_is_blocked_and_ordinary_traffic_passes() {
    // Materialise the rule pack at an absolute path the proxy reads at
    // boot. Keep the temp file alive until after the requests so the
    // loader (and any reload) still sees it on disk.
    let mut rules = NamedTempFile::new().expect("temp rule pack");
    rules.write_all(RULE_PACK.as_bytes()).expect("write rules");
    rules.flush().expect("flush rules");
    let rules_path = rules.path().to_str().expect("utf8 path").to_string();

    let harness = ProxyHarness::start_with_yaml(&config_yaml(&rules_path)).expect("start proxy");

    // TestBot UA matches the rule -> score 95 -> `95 < 80` is false ->
    // the expression policy denies with 403.
    let blocked = harness
        .get_with_headers("/", "detect.localhost", &[("user-agent", "TestBot/1.0")])
        .expect("send blocked request");
    assert_eq!(
        blocked.status, 403,
        "TestBot scores 95 and must be blocked by `request.agent.score < 80`; got {}",
        blocked.status
    );

    // No rule matches -> unscored (score 0) -> `0 < 80` is true ->
    // ordinary traffic passes.
    let allowed = harness
        .get_with_headers("/", "detect.localhost", &[("user-agent", "curl/8.0")])
        .expect("send allowed request");
    assert_eq!(
        allowed.status, 200,
        "ordinary UA scores 0 and must pass `request.agent.score < 80`; got {}",
        allowed.status
    );

    drop(rules);
}

#[test]
fn onnx_agent_detect_populates_metrics_after_traffic() {
    let model_path = fixture_model_path();
    let harness =
        ProxyHarness::start_with_yaml(&onnx_only_config_yaml(&model_path)).expect("start proxy");

    let response = harness
        .get_with_headers("/", "detect.localhost", &[("user-agent", "curl/8.0")])
        .expect("send request");
    assert_eq!(response.status, 200);

    let metrics = fetch_metrics(&harness);
    for series in [
        "sbproxy_agent_detect_total",
        "sbproxy_agent_detect_score_bucket",
        "sbproxy_agent_detect_inference_seconds_bucket",
    ] {
        assert!(
            metrics.contains(series),
            "{series} must be populated after agent-detect traffic; metrics:\n{metrics}"
        );
    }
}
