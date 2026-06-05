//! End-to-end coverage for AI gateway OUTPUT guardrail enforcement
//! (WOR-1141).
//!
//! A `guardrails.output:` block must enforce on both paths. Unary: the
//! gateway runs the output guardrails against the materialized response
//! body before caching or sending it, and replaces a blocked response
//! with a 403 `guardrail_violation` error. Streaming: each outbound
//! chunk is checked against the streaming-safe guardrails and a match
//! terminates the stream so the violating content (and everything after
//! it) is withheld.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config(upstream_base: &str) -> String {
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
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
      guardrails:
        output:
          - type: regex
            action: block
            patterns:
              - "FORBIDDEN_CONTENT"
"#
    )
}

fn chat_reply(content: &str) -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn chat() -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
}

#[test]
fn output_guardrail_blocks_violating_response() {
    // The upstream returns a 200 whose assistant content trips the
    // configured output regex. The gateway must withhold it.
    let upstream =
        MockUpstream::start(chat_reply("here is the FORBIDDEN_CONTENT you asked for")).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).unwrap();

    let body = chat();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();

    assert_eq!(
        resp.status,
        403,
        "a violating output must be blocked, got {}: {:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
    let text = resp.text().unwrap_or_default();
    assert!(
        text.contains("guardrail_violation"),
        "block body should name the violation type: {text}"
    );
    // The model's actual response must not be forwarded. (The
    // operator-facing `reason` names the matched pattern, which is
    // operator-configured, not model output.)
    assert!(
        !text.contains("here is the") && !text.contains("you asked for"),
        "the model's response content must not leak into the block response: {text}"
    );
}

#[test]
fn output_guardrail_allows_clean_response() {
    // A clean response on the same origin passes through untouched.
    let upstream = MockUpstream::start(chat_reply("here is a perfectly fine answer")).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).unwrap();

    let body = chat();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();

    assert_eq!(resp.status, 200, "a clean response must pass through");
    let text = resp.text().unwrap_or_default();
    assert!(
        text.contains("perfectly fine answer"),
        "the clean upstream body must reach the client: {text}"
    );
}

#[test]
fn output_guardrail_terminates_streaming_on_violation() {
    // The upstream streams three SSE frames; the second carries the
    // forbidden token. The proxy forwards the first clean frame, then
    // the streaming-safe regex guardrail trips on the second and the
    // stream is terminated, so the violating content never reaches the
    // client. Headers were already sent, so the status stays 200.
    let events = vec![
        json!({"choices":[{"index":0,"delta":{"content":"CLEAN_PREFIX"},"finish_reason":null}]})
            .to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"FORBIDDEN_CONTENT"},"finish_reason":null}]})
            .to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"AFTER"},"finish_reason":"stop"}]})
            .to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(
        resp.status, 200,
        "streaming headers are sent before the block"
    );

    let text = String::from_utf8_lossy(&resp.body);
    assert!(
        !text.contains("FORBIDDEN_CONTENT"),
        "the violating streamed chunk must not reach the client: {text}"
    );
    assert!(
        !text.contains("AFTER"),
        "chunks after the violation must also be withheld: {text}"
    );
}
