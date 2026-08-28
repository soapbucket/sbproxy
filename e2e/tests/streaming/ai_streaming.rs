//! End-to-end coverage for AI gateway SSE streaming pass-through.
//!
//! `examples/ai-streaming/sb.yml` documents the contract: a
//! `stream: true` request to `/v1/chat/completions` yields
//! `text/event-stream` chunks forwarded from the upstream provider
//! verbatim. WOR-1133: `MockUpstream::start_sse` drip-feeds the SSE
//! frames so these tests can assert the proxy preserves the
//! content-type and the frame order.
//!
//! Usage-capture across every provider SSE shape is covered separately
//! in `ai_streaming_usage.rs`; this file pins the client-visible
//! pass-through contract (content-type + ordering).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn streaming_config(upstream_base: &str) -> String {
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
"#
    )
}

fn stream_request() -> serde_json::Value {
    json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    })
}

#[test]
fn streaming_response_uses_event_stream_content_type() {
    // The mock emits `text/event-stream`; the gateway must forward a
    // streaming response with that content-type rather than buffering
    // it into a single JSON body.
    let events = vec![
        json!({"choices":[{"index":0,"delta":{"content":"hel"},"finish_reason":null}]}).to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}]})
            .to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&streaming_config(&upstream.base_url()))
        .expect("start proxy");

    let body = stream_request();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("send");

    assert_eq!(resp.status, 200);
    let content_type = resp
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("");
    assert!(
        content_type.contains("text/event-stream"),
        "streaming response must carry text/event-stream, got {content_type:?}"
    );
}

#[test]
fn sse_chunks_pass_through_in_order() {
    // Three distinct frames; the proxy must forward them to the client
    // in the same order the upstream emitted them, without collapsing
    // them into one reassembled body.
    let events = vec![
        json!({"choices":[{"index":0,"delta":{"content":"FIRST"},"finish_reason":null}]})
            .to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"SECOND"},"finish_reason":null}]})
            .to_string(),
        json!({"choices":[{"index":0,"delta":{"content":"THIRD"},"finish_reason":"stop"}]})
            .to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&streaming_config(&upstream.base_url()))
        .expect("start proxy");

    let request = stream_request();
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &request, &[])
        .expect("send");
    assert_eq!(resp.status, 200);

    let body = String::from_utf8_lossy(&resp.body);
    let first = body.find("FIRST").expect("first frame present");
    let second = body.find("SECOND").expect("second frame present");
    let third = body.find("THIRD").expect("third frame present");
    assert!(
        first < second && second < third,
        "SSE frames must reach the client in emission order; body was:\n{body}"
    );
}
