//! End-to-end coverage for the `semantic_constraint` policy
//! (WOR-203 PR 3b).
//!
//! Stands up a mock judge endpoint and a `static` action behind a
//! `semantic_constraint` policy. The judge mock returns
//! `{"verdict": "deny"}` for one configured response and
//! `{"verdict": "allow"}` for another, so the proxy's deny path is
//! exercised by changing only the prompt template (which is rendered
//! against the request envelope).
//!
//! The harness spins up two mock servers on ephemeral ports. The
//! `semantic_constraint` policy points at the judge endpoint; the
//! origin's `static` action returns 200 directly without an upstream
//! call. The proxy is configured per-test so the judge URL can be
//! plumbed into the YAML before the proxy boots.
//!
//! This is the integration acceptance gate for PR 3b: a proxy with
//! a `semantic_constraint` policy returns 403 on the deny path and
//! 200 on the allow path with no further code wiring beyond the
//! YAML config.

use sbproxy_e2e::{MockUpstream, ProxyHarness};

fn config_yaml(judge_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "sc.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: semantic_constraint
        prompt_template: "evaluate {{{{ request.path }}}}"
        violations_block: true
        judge:
          endpoint: "{judge_url}"
          api_key_env: "SBPROXY_E2E_JUDGE_KEY"
          timeout_ms: 1500
          cache_capacity: 4
          budget_tokens: 100
"#,
        judge_url = judge_url
    )
}

#[test]
fn judge_deny_blocks_request_with_403() {
    let judge = MockUpstream::start(serde_json::json!({
        "verdict": "deny",
        "status": 403,
        "message": "blocked by judge"
    }))
    .expect("start mock judge");
    let judge_url = format!("{}/judge", judge.base_url());
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&judge_url)).expect("start proxy");

    let resp = harness
        .get("/admin/secret", "sc.localhost")
        .expect("request goes through");
    assert_eq!(
        resp.status,
        403,
        "deny verdict must surface as 403, got {} body={:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
}

#[test]
fn judge_allow_lets_request_through_with_200() {
    let judge =
        MockUpstream::start(serde_json::json!({"verdict": "allow"})).expect("start mock judge");
    let judge_url = format!("{}/judge", judge.base_url());
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&judge_url)).expect("start proxy");

    let resp = harness
        .get("/public/index", "sc.localhost")
        .expect("request goes through");
    assert_eq!(
        resp.status, 200,
        "allow verdict must let the static 200 through"
    );
    let body = resp.text().unwrap_or_default();
    assert_eq!(body, "ok", "static body must be served on allow");
}
