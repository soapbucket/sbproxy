//! WOR-2480: end-to-end proof for the AI gateway policy pack. Each test
//! maps to a row in `docs/ai-gateway-security-coverage.md` and runs the
//! release binary, not a unit seam.
//!
//! Row-to-test mapping:
//!
//! - LLM01 Prompt Injection, "multipart requests are refused on JSON
//!   surfaces so a Content-Type cannot relabel past body inspection" ->
//!   [`multipart_on_chat_completions_is_refused_by_the_release_binary`].
//! - LLM07 Unbounded Consumption, "tenant-keyed request budgets on the
//!   serving path" -> [`tenant_budgets_are_isolated`].
//! - Gateway-layer control 8 ("Change control is tamper-evident") and the
//!   "Audit chain health" signals row have no test in this file. Standing
//!   up a `sink: chain` proxy through this harness needs a Web Bot Auth
//!   signing identity (`audit.sign_with`) that this file does not
//!   otherwise configure, so the tamper-detection proof stays where it
//!   already lives: hash-chain re-derivation and tamper-at-record-N in
//!   `crates/sbproxy-observe/src/audit_chain.rs`'s unit tests, and the
//!   emit-outcome tests in `crates/sbproxy-observe/src/audit.rs`.
//! - Every other row (LLM02-06, LLM08-10, gateway-layer controls 1-7) is
//!   exercised elsewhere in this suite or at the unit level; this file's
//!   scope is the two WOR-2480 seams named above.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-1", "object": "chat.completion", "created": 0,
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn ai_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0

origins:
  "ai.localhost":
    action:
      type: ai_proxy
      allowed_models: [gpt-4o]
      providers:
        - name: fixture
          provider_type: openai
          api_key: fixture-local-token
          base_url: "{upstream_url}"
          allow_private_base_url: true
          models: [gpt-4o]
"#
    )
}

/// WOR-2472 / LLM01: a multipart Content-Type on a classified JSON AI
/// surface (`/v1/chat/completions`) is refused with a 403 before any
/// budget, guardrail, or upstream work happens.
#[test]
fn multipart_on_chat_completions_is_refused_by_the_release_binary() {
    let upstream = MockUpstream::start(chat_reply()).expect("mock upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&ai_config(&upstream.base_url())).expect("start proxy");
    let boundary = "e2eboundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-4o\r\n--{boundary}--\r\n"
    );
    let resp = proxy
        .post_bytes(
            "/v1/chat/completions",
            "ai.localhost",
            &format!("multipart/form-data; boundary={boundary}"),
            body.into_bytes(),
            &[],
        )
        .expect("send");
    let text = resp.text().unwrap_or_default();
    assert_eq!(resp.status, 403, "body: {text}");
    assert!(
        text.contains("multipart/form-data is not accepted on this AI surface"),
        "{text}"
    );
    assert!(
        upstream.captured().is_empty(),
        "upstream must see nothing: {:?}",
        upstream.captured()
    );
}

/// WOR-2477 / LLM07: config for two origins, each pinned to its own
/// tenant, sharing a one-request-burst workspace budget. Mirrors the
/// fixture shape in `rate_limit_budget.rs` (top-level `rate_limits:`,
/// a `policies: [{type: rate_limit_budget}]` origin block), plus
/// `proxy.tenants[]` declarations the compiler requires for every
/// `origins.*.tenant_id` reference.
fn tenant_budget_config() -> String {
    r#"
proxy:
  http_bind_port: 0
  tenants:
    - id: tenant-a
    - id: tenant-b
rate_limits:
  workspace_default:
    http_rps_sustained: 1
    http_rps_burst: 1
origins:
  "a.localhost":
    tenant_id: tenant-a
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limit_budget
  "b.localhost":
    tenant_id: tenant-b
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limit_budget
"#
    .to_string()
}

/// WOR-2477 / LLM07: the serving-path workspace budget keys by the
/// origin's configured tenant, not by a single shared bucket. Saturating
/// `tenant-a`'s one-request burst on `a.localhost` must not throttle a
/// first request to `b.localhost`, whose origin is pinned to `tenant-b`.
#[test]
fn tenant_budgets_are_isolated() {
    let harness = ProxyHarness::start_with_yaml(&tenant_budget_config()).expect("start proxy");

    // Hammer tenant-a's origin until its one-request burst throttles.
    // Mirrors the burst loop in rate_limit_budget.rs's
    // `burst_returns_429_with_full_ratelimit_headers`.
    let mut found_429 = false;
    for _ in 0..100 {
        let resp = harness.get("/anything", "a.localhost").expect("send");
        if resp.status == 429 {
            found_429 = true;
            break;
        }
    }
    assert!(
        found_429,
        "expected tenant-a's one-request budget to throttle"
    );

    // tenant-b's bucket is untouched: its first request is allowed.
    let resp_b = harness.get("/anything", "b.localhost").expect("send");
    assert_eq!(
        resp_b.status, 200,
        "tenant-b's budget must be independent of tenant-a's throttle"
    );
}
