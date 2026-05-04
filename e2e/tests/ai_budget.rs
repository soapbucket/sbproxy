//! End-to-end coverage for AI gateway budget enforcement.
//!
//! `examples/13-ai-budget/sb.yml` documents the contract: a budget
//! limit fires `block`, `log`, or `downgrade` actions when a scope
//! key exceeds its `max_cost_usd` or `max_tokens` cap. Budget
//! tracking lives in `sbproxy-ai/src/budget.rs`; the request path in
//! `crates/sbproxy-core/src/server.rs::handle_ai_proxy` consults the
//! process-wide `BudgetTracker` before each upstream dispatch and
//! records token + cost usage from the response back into it.
//!
//! Each test runs against its own proxy harness process, so the
//! global `BudgetTracker` accumulators start empty for every case.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Build an AI proxy config with the supplied `budget` block. The
/// upstream `base_url` points at the test's mock provider.
fn build_config(upstream_base: &str, budget_yaml: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
          models: [gpt-4o, gpt-4o-mini]
      routing:
        strategy: round_robin
{budget_yaml}
"#
    )
}

/// Standard OpenAI-shaped chat completion reply with a `usage` block
/// reporting one prompt/output token. The proxy reads `usage` to
/// charge the budget; pegging both at 1 keeps the math obvious.
fn reply_with_usage(prompt_tokens: u64, completion_tokens: u64) -> serde_json::Value {
    json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    })
}

#[test]
fn budget_block_returns_402_after_cap_exceeded() {
    // Reply reports 1000 prompt + 1000 completion tokens, well over
    // the 100-token workspace cap configured below.
    let upstream = MockUpstream::start(reply_with_usage(1_000, 1_000)).unwrap();
    let yaml = build_config(
        &upstream.base_url(),
        r#"      budget:
        on_exceed: block
        limits:
          - scope: workspace
            max_tokens: 100
"#,
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    // First request charges usage but isn't itself blocked (cap is
    // checked pre-dispatch and the tracker is empty on the first call).
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(
        resp.status, 200,
        "first request should pass: tracker is empty pre-dispatch"
    );

    // Second request: tracker now holds 2000 tokens, well over the
    // 100-token cap. Pre-dispatch must short-circuit with 402.
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(resp.status, 402, "post-cap request must be blocked");
    let body_text = resp.text().unwrap();
    assert!(
        body_text.contains("budget_exceeded"),
        "error body should name the failure type: {body_text}"
    );
    assert!(
        body_text.contains("workspace"),
        "error body should name the firing scope: {body_text}"
    );
}

#[test]
fn budget_log_warns_but_allows_request() {
    let upstream = MockUpstream::start(reply_with_usage(1_000, 1_000)).unwrap();
    let yaml = build_config(
        &upstream.base_url(),
        r#"      budget:
        on_exceed: log
        limits:
          - scope: workspace
            max_tokens: 100
"#,
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    // Drive the tracker over the cap.
    for _ in 0..3 {
        let resp = harness
            .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
            .unwrap();
        assert_eq!(resp.status, 200, "log mode must not block");
    }

    // Even after the cap is exceeded, requests still complete with
    // 200. We can't easily observe the warn! macro from here, but the
    // contract is that the request flows through.
    assert!(
        upstream.captured().len() >= 3,
        "every request must reach the upstream when on_exceed=log"
    );
}

#[test]
fn budget_downgrade_rewrites_model_to_cheaper_target() {
    let upstream = MockUpstream::start(reply_with_usage(1_000, 1_000)).unwrap();
    let yaml = build_config(
        &upstream.base_url(),
        r#"      budget:
        on_exceed: downgrade
        limits:
          - scope: workspace
            max_tokens: 100
            downgrade_to: gpt-4o-mini
"#,
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    // First request seeds usage in the tracker (passes through with
    // the original model name).
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(resp.status, 200);

    // Second request: tracker is over the cap, the proxy must
    // rewrite `model` to `gpt-4o-mini` before forwarding.
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(resp.status, 200, "downgrade mode must still complete");

    let captured = upstream.captured();
    assert!(captured.len() >= 2, "expected two forwarded requests");
    let last_body = String::from_utf8(captured.last().unwrap().body.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&last_body).unwrap();
    assert_eq!(
        parsed["model"], "gpt-4o-mini",
        "downgrade must rewrite the model field, got body: {last_body}"
    );
}

#[test]
fn budget_downgrade_falls_back_to_cheapest_when_target_unset() {
    // No downgrade_to: the proxy must pick the cheapest of the
    // configured providers' models. With [gpt-4o, gpt-4o-mini] the
    // mini variant wins on the embedded price catalog.
    let upstream = MockUpstream::start(reply_with_usage(1_000, 1_000)).unwrap();
    let yaml = build_config(
        &upstream.base_url(),
        r#"      budget:
        on_exceed: downgrade
        limits:
          - scope: workspace
            max_tokens: 100
"#,
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    let _ = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(resp.status, 200);

    let captured = upstream.captured();
    let last_body = String::from_utf8(captured.last().unwrap().body.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&last_body).unwrap();
    assert_eq!(
        parsed["model"], "gpt-4o-mini",
        "missing downgrade_to should pick the cheapest configured model"
    );
}

#[test]
fn budget_records_usage_from_streaming_response() {
    // The OpenAI SSE convention reports usage on the terminal data
    // frame: a regular content delta, then one chunk carrying the
    // `usage` object with the final totals, then `data: [DONE]`.
    // The proxy's streaming relay scans data frames line by line and
    // hands the final usage tuple to `record_budget_usage`; the next
    // pre-dispatch check must observe the recorded tokens and block.
    //
    // This test wires `on_exceed: block` with a 100-token cap and a
    // mock SSE provider that reports 1000+1000 = 2000 tokens. The
    // first streaming request seeds the tracker. The second request
    // (also streaming) must short-circuit pre-dispatch with 402 and
    // never reach the upstream.
    let events = vec![
        // A normal content delta, no usage. Mimics the real provider
        // shape so the scanner has to skip non-usage frames.
        json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": {"role": "assistant", "content": "ok"},
                "finish_reason": null
            }]
        })
        .to_string(),
        // Terminal usage frame, OpenAI shape. Reports 1000+1000
        // tokens which the proxy must scan and feed to the tracker.
        json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 1_000,
                "completion_tokens": 1_000,
                "total_tokens": 2_000,
            }
        })
        .to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let yaml = build_config(
        &upstream.base_url(),
        r#"      budget:
        on_exceed: block
        limits:
          - scope: workspace
            max_tokens: 100
"#,
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}],
        "stream": true,
    });

    // First streaming request: pre-dispatch sees an empty tracker so
    // it passes through. The relay scans the SSE body, captures
    // `usage`, and feeds 2000 tokens into the tracker on stream end.
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(
        resp.status, 200,
        "first streaming request should pass: tracker is empty pre-dispatch"
    );

    // Second streaming request: the tracker now holds 2000 tokens
    // recorded from the first stream's terminal usage frame, well
    // over the 100-token cap. Pre-dispatch must short-circuit with
    // 402 before any chunk reaches the upstream.
    let upstream_calls_before = upstream.captured().len();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(
        resp.status,
        402,
        "post-cap streaming request must be blocked, got {}: {:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
    let body_text = resp.text().unwrap();
    assert!(
        body_text.contains("budget_exceeded"),
        "error body should name the failure type: {body_text}"
    );
    assert!(
        body_text.contains("workspace"),
        "error body should name the firing scope: {body_text}"
    );
    assert_eq!(
        upstream.captured().len(),
        upstream_calls_before,
        "blocked request must not reach the upstream"
    );
}
