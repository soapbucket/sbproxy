//! End-to-end coverage for pluggable AI streaming usage parsers.
//!
//! Provider SSE shapes diverge widely (OpenAI's terminal `usage`
//! chunk, Anthropic's `message_start` / `message_delta` split,
//! Vertex's `usageMetadata`, Bedrock's base64 envelope, Cohere's
//! `event-type` taxonomy, Ollama's NDJSON). The streaming relay in
//! `sbproxy-core::server::relay_ai_stream` consults
//! `sbproxy_ai::select_parser` to build the right
//! [`SseUsageParser`](sbproxy_ai::SseUsageParser) for each upstream.
//! These tests pin every shape end-to-end: they spin up a mock
//! upstream that emits provider-shaped SSE / NDJSON, set
//! `usage_parser` explicitly on the AI handler, and verify that the
//! recorded budget tokens match the upstream's reported counts.
//!
//! The pattern: each provider test runs with `budget.on_exceed:
//! block` and a 100-token cap. The first request seeds the tracker
//! (still passes because the cap is checked pre-dispatch and the
//! tracker starts empty); the second request must short-circuit
//! with HTTP 402 because the parser captured > 100 tokens from the
//! first stream's terminal usage frame.
//!
//! Mid-line chunk splitting is covered by the parser unit tests; the
//! e2e here pins the wiring (config -> parser selection -> chunk
//! feed -> snapshot -> budget recording).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Build a minimal AI proxy config that drives the streaming relay
/// against the supplied mock upstream and pins the usage parser to
/// `parser`. Budget is set to `block` at 100 tokens so a stream
/// that records > 100 tokens trips the second request.
fn build_config(upstream_base: &str, parser: &str) -> String {
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
          models: [gpt-4o]
      routing:
        strategy: round_robin
      usage_parser: {parser}
      budget:
        on_exceed: block
        limits:
          - scope: workspace
            max_tokens: 100
"#
    )
}

/// Reusable test body: drive two streaming requests through the
/// proxy. First seeds the tracker; second must be blocked with
/// 402 because the parser captured > 100 tokens from frame one.
fn assert_parser_records_usage(harness: &ProxyHarness, upstream: &MockUpstream) {
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });

    // First streaming request: parser scans the SSE body, records
    // the captured tokens, and the request returns 200 because the
    // cap is checked pre-dispatch on an empty tracker.
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .unwrap();
    assert_eq!(
        resp.status, 200,
        "first streaming request should pass: tracker starts empty"
    );

    // Second request: tracker now holds the captured tokens (well
    // over the 100-token cap). Pre-dispatch must short-circuit
    // before any byte reaches the upstream.
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
    assert_eq!(
        upstream.captured().len(),
        upstream_calls_before,
        "blocked request must not reach upstream"
    );
}

// --- OpenAI ---------------------------------------------------------------

#[test]
fn openai_streaming_usage_recorded() {
    let events = vec![
        json!({
            "id": "chatcmpl-test",
            "choices": [{"index":0,"delta":{"content":"hi"},"finish_reason":null}]
        })
        .to_string(),
        // Terminal usage frame, OpenAI shape.
        json!({
            "id": "chatcmpl-test",
            "choices": [{"index":0,"delta":{},"finish_reason":"stop"}],
            "usage": {"prompt_tokens": 600, "completion_tokens": 400, "total_tokens": 1000},
        })
        .to_string(),
    ];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let yaml = build_config(&upstream.base_url(), "openai");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- Anthropic ------------------------------------------------------------

#[test]
fn anthropic_streaming_usage_recorded() {
    // Anthropic emits `event:` markers plus `data:` payloads.
    // start_sse_raw lets us write the wire format verbatim.
    let frames = vec![
        "event: message_start\ndata: {\"type\":\"message_start\",\"usage\":{\"input_tokens\":700,\"output_tokens\":0}}\n\n"
            .to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n".to_string(),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":350}}\n\n".to_string(),
    ];
    let upstream = MockUpstream::start_sse_raw(frames, "text/event-stream".to_string()).unwrap();
    let yaml = build_config(&upstream.base_url(), "anthropic");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- Vertex / Gemini -----------------------------------------------------

#[test]
fn vertex_streaming_usage_recorded() {
    // Vertex repeats `usageMetadata` on every chunk; values grow
    // until the last one. The parser takes the max.
    let frames = vec![
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}],\"usageMetadata\":{\"promptTokenCount\":500,\"candidatesTokenCount\":200,\"totalTokenCount\":700}}\n\n"
            .to_string(),
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}]}}],\"usageMetadata\":{\"promptTokenCount\":500,\"candidatesTokenCount\":450,\"totalTokenCount\":950}}\n\n"
            .to_string(),
    ];
    let upstream = MockUpstream::start_sse_raw(frames, "text/event-stream".to_string()).unwrap();
    let yaml = build_config(&upstream.base_url(), "vertex");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- Bedrock --------------------------------------------------------------

#[test]
fn bedrock_streaming_usage_recorded() {
    // Bedrock wraps each Anthropic-on-Bedrock chunk in a
    // `{"bytes": "<base64>"}` envelope. Our parser decodes the
    // envelope and delegates to the Anthropic parser internally.
    let inner_start = r#"{"type":"message_start","usage":{"input_tokens":800,"output_tokens":0}}"#;
    let inner_delta = r#"{"type":"message_delta","usage":{"output_tokens":300}}"#;
    let frames = vec![
        format!(
            "data: {{\"bytes\":\"{}\"}}\n\n",
            B64.encode(inner_start.as_bytes())
        ),
        format!(
            "data: {{\"bytes\":\"{}\"}}\n\n",
            B64.encode(inner_delta.as_bytes())
        ),
    ];
    let upstream = MockUpstream::start_sse_raw(frames, "text/event-stream".to_string()).unwrap();
    let yaml = build_config(&upstream.base_url(), "bedrock");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- Cohere ---------------------------------------------------------------

#[test]
fn cohere_streaming_usage_recorded() {
    // Cohere chat stream: text-generation events, then a stream-end
    // event carrying billed_units.
    let frames = vec![
        "data: {\"event_type\":\"text-generation\",\"text\":\"hi\"}\n\n".to_string(),
        "data: {\"event_type\":\"stream-end\",\"finish_reason\":\"COMPLETE\",\"response\":{\"meta\":{\"billed_units\":{\"input_tokens\":750,\"output_tokens\":350}}}}\n\n"
            .to_string(),
    ];
    let upstream = MockUpstream::start_sse_raw(frames, "text/event-stream".to_string()).unwrap();
    let yaml = build_config(&upstream.base_url(), "cohere");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- Ollama ---------------------------------------------------------------

#[test]
fn ollama_streaming_usage_recorded() {
    // Ollama emits NDJSON rather than SSE: each line is a complete
    // JSON object, no `data:` prefix. The terminal line carries
    // prompt_eval_count / eval_count.
    let frames = vec![
        "{\"model\":\"llama3\",\"message\":{\"role\":\"assistant\",\"content\":\"hi\"},\"done\":false}\n"
            .to_string(),
        "{\"model\":\"llama3\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"prompt_eval_count\":600,\"eval_count\":500}\n".to_string(),
    ];
    let upstream = MockUpstream::start_sse_raw(frames, "application/x-ndjson".to_string()).unwrap();
    let yaml = build_config(&upstream.base_url(), "ollama");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- Generic --------------------------------------------------------------

#[test]
fn generic_parser_picks_up_openai_shape_via_auto() {
    // `usage_parser: auto` against a 127.0.0.1 host falls back to
    // the generic parser (no host hint matches a well-known
    // provider). Generic must still pick up OpenAI shape.
    let events = vec![json!({
        "id": "chatcmpl-test",
        "choices": [{"index":0,"delta":{},"finish_reason":"stop"}],
        "usage": {"prompt_tokens": 700, "completion_tokens": 350, "total_tokens": 1050},
    })
    .to_string()];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let yaml = build_config(&upstream.base_url(), "auto");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();
    assert_parser_records_usage(&harness, &upstream);
}

// --- None: parser disabled ----------------------------------------------

#[test]
fn parser_none_skips_budget_recording() {
    // With `usage_parser: none` the relay does not scan the SSE
    // body at all. Even a high-token stream must not bump the
    // tracker; the second request still succeeds.
    let events = vec![json!({
        "id": "chatcmpl-test",
        "choices": [{"index":0,"delta":{},"finish_reason":"stop"}],
        "usage": {"prompt_tokens": 9999, "completion_tokens": 9999},
    })
    .to_string()];
    let upstream = MockUpstream::start_sse(events).unwrap();
    let yaml = build_config(&upstream.base_url(), "none");
    let harness = ProxyHarness::start_with_yaml(&yaml).unwrap();

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });

    for i in 0..3 {
        let resp = harness
            .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
            .unwrap();
        assert_eq!(
            resp.status, 200,
            "request {i} must pass when usage parsing is disabled"
        );
    }
}
