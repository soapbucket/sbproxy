//! A2A policy conformance tests (Wave 7 / Q7.3).
//!
//! Boots a harness origin configured with the `a2a` policy and
//! drives detection + denial paths end-to-end. Coverage:
//!
//! * Detection by `Content-Type: application/a2a+json` (Google).
//! * Detection by `MCP-Method: agents.invoke` (Anthropic).
//! * Detection in graceful-degradation mode (parsers off; OSS default).
//! * Chain-depth cap denial (429 with Retry-After: 0 + JSON body).
//! * Cycle detection in the three modes (`strict`, `by_agent_id`,
//!   `by_callable_endpoint`).
//! * Callee allowlist (403).
//! * Caller denylist (403).
//! * Tolerance for partial / missing envelope fields.
//!
//! All envelope fields are passed through `X-A2A-*` headers so the
//! tests do not depend on the feature-flagged body parsers.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

// --- Config helpers ---

fn config_default(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: a2a
        max_chain_depth: 5
        cycle_detection: by_agent_id
"#
    )
}

fn config_strict_cycle(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: a2a
        max_chain_depth: 5
        cycle_detection: strict
"#
    )
}

fn config_by_endpoint(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: a2a
        max_chain_depth: 5
        cycle_detection: by_callable_endpoint
"#
    )
}

fn config_with_allowlist(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: a2a
        max_chain_depth: 5
        callee_allowlist:
          - "agent:openai:gpt-5"
          - "agent:anthropic:claude-4"
"#
    )
}

fn config_with_denylist(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: a2a
        caller_denylist:
          - "agent:bad:actor"
"#
    )
}

fn config_low_depth(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a2a.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: a2a
        max_chain_depth: 2
"#
    )
}

// --- Header helpers ---

fn google_headers() -> Vec<(&'static str, &'static str)> {
    vec![("content-type", "application/a2a+json")]
}

fn anthropic_headers() -> Vec<(&'static str, &'static str)> {
    vec![("mcp-method", "agents.invoke")]
}

// --- Tests ---

#[test]
fn detection_via_content_type_passes_to_upstream() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    // A2A request with depth 1, no callee. The default config has no
    // allowlist / denylist, so it should pass through.
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-task-id", "task-1"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "default config allows depth=1");
}

#[test]
fn detection_via_mcp_method_passes_to_upstream() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/mcp/x",
            "a2a.localhost",
            &[
                ("mcp-method", "agents.invoke"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn graceful_degradation_when_parsers_off() {
    // Parsers are off in the OSS default build. Detection still
    // populates a zero-default A2AContext so the policy can apply
    // route-level limits even without parser data.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_low_depth(&upstream.base_url())).expect("start");

    // Detected as A2A (content-type), no envelope headers => zero
    // default depth = 1, which is below the configured cap of 2 =>
    // request passes.
    let mut headers = google_headers();
    headers.push(("x-a2a-caller-agent-id", "agent:caller"));
    let resp = harness
        .get_with_headers("/", "a2a.localhost", &headers)
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "detection-only path with default depth=1 must pass when limit=2"
    );
}

#[test]
fn chain_depth_exceeded_returns_429() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_low_depth(&upstream.base_url())).expect("start");

    // Limit is 2; we send depth=5 to force a denial.
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-chain-depth", "5"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 429, "depth exceeded must return 429");
    assert_eq!(
        resp.headers.get("retry-after").map(String::as_str),
        Some("0"),
        "depth denial must stamp Retry-After: 0"
    );
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_chain_depth_exceeded");
    assert_eq!(body["limit"], 2);
    assert_eq!(body["depth"], 5);
}

#[test]
fn cycle_by_agent_id_returns_409() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    // Chain already contains agent:b; calling agent:b again is a cycle.
    let chain = json!([
        {"agent_id": "agent:root", "request_id": "r-root", "timestamp_ms": 100},
        {"agent_id": "agent:b", "request_id": "r-b", "timestamp_ms": 200}
    ])
    .to_string();
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-chain-depth", "3"),
                ("x-a2a-chain", &chain),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 409, "cycle must return 409");
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_cycle_detected");
    assert_eq!(body["callee"], "agent:b");
    assert_eq!(body["cycle_position"], 1);
}

#[test]
fn cycle_strict_requires_request_id_match() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_strict_cycle(&upstream.base_url())).expect("start");

    // Strict mode: agent:b appears in chain but with request_id
    // different from parent_request_id. Not a cycle.
    let chain = json!([
        {"agent_id": "agent:b", "request_id": "r-old", "timestamp_ms": 100}
    ])
    .to_string();
    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-parent-request-id", "r-different"),
                ("x-a2a-chain-depth", "2"),
                ("x-a2a-chain", &chain),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "strict mode tolerates same agent with different request_id"
    );

    // Strict mode: agent:b appears with matching request_id => cycle.
    let chain2 = json!([
        {"agent_id": "agent:b", "request_id": "r-parent", "timestamp_ms": 100}
    ])
    .to_string();
    let resp2 = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-parent-request-id", "r-parent"),
                ("x-a2a-chain-depth", "2"),
                ("x-a2a-chain", &chain2),
            ],
        )
        .expect("send");
    assert_eq!(
        resp2.status, 409,
        "strict mode flags cycle on matching request_id"
    );
}

#[test]
fn cycle_by_callable_endpoint_distinguishes_methods() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_by_endpoint(&upstream.base_url())).expect("start");

    // Chain entry agent:b had request_id "/endpoint-list"; now we
    // call agent:b at "/endpoint-create". The mode treats different
    // endpoints as different calls => no cycle. Since the request
    // path becomes the callable_endpoint, the URL needs to differ
    // from the chain entry's request_id.
    let chain = json!([
        {"agent_id": "agent:b", "request_id": "/endpoint-list", "timestamp_ms": 100}
    ])
    .to_string();
    let resp = harness
        .get_with_headers(
            "/endpoint-create",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:b"),
                ("x-a2a-chain-depth", "2"),
                ("x-a2a-chain", &chain),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "by_callable_endpoint allows same agent with different endpoint"
    );
}

#[test]
fn callee_not_on_allowlist_returns_403() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_with_allowlist(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:not-listed"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 403);
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_callee_not_allowed");
    assert_eq!(body["callee"], "agent:not-listed");
}

#[test]
fn callee_on_allowlist_passes() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_with_allowlist(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &[
                ("content-type", "application/a2a+json"),
                ("x-a2a-caller-agent-id", "agent:caller"),
                ("x-a2a-callee-agent-id", "agent:openai:gpt-5"),
                ("x-a2a-chain-depth", "1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn caller_on_denylist_returns_403() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_with_denylist(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/agents/invoke",
            "a2a.localhost",
            &anthropic_headers()
                .into_iter()
                .chain([
                    ("x-a2a-caller-agent-id", "agent:bad:actor"),
                    ("x-a2a-callee-agent-id", "agent:any"),
                    ("x-a2a-chain-depth", "1"),
                ])
                .collect::<Vec<_>>(),
        )
        .expect("send");
    assert_eq!(resp.status, 403);
    let body: serde_json::Value = resp.json().expect("json body");
    assert_eq!(body["error"], "a2a_caller_denied");
    assert_eq!(body["caller"], "agent:bad:actor");
}

#[test]
fn missing_envelope_fields_tolerated() {
    // No X-A2A-* headers at all; detection still fires on
    // content-type and the policy operates on zero-defaults
    // (depth=1, no callee). With the default config (limit 5,
    // no allowlist) the request passes.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_default(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers("/agents/invoke", "a2a.localhost", &google_headers())
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn non_a2a_request_unaffected() {
    // Plain HTTP request with no detection signal must pass through
    // unchanged regardless of the a2a policy.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&config_low_depth(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/some/path",
            "a2a.localhost",
            &[("content-type", "application/json")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "non-A2A requests bypass the policy entirely"
    );
}
