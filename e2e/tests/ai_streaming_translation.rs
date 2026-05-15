//! End-to-end coverage for WOR-226 SSE streaming translation.
//!
//! When an OpenAI client sets `stream: true` against an Anthropic
//! (or Gemini, or Bedrock) upstream, the gateway parses the
//! upstream's native SSE shape into the hub vocabulary and re-emits
//! the chunks as OpenAI Chat Completions SSE so the OpenAI SDK on
//! the client side sees its own wire shape end to end.
//!
//! The tests here run a mock upstream that emits Anthropic-shaped
//! `event: message_start` / `content_block_delta` / `message_stop`
//! frames, point a configured `ai_proxy` origin at it with
//! `provider_type: anthropic`, and assert that the body relayed back
//! to the client contains OpenAI Chat shape (`data: {...}`,
//! `delta.content`, terminal `data: [DONE]`).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Build an AI proxy config that routes a single Anthropic-format
/// provider at `upstream_base`. The provider name is `anthropic` so
/// the catalog resolves `format: anthropic` automatically.
fn build_anthropic_config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: anthropic
          api_key: "stub-key"
          base_url: "{upstream_base}"
          models: [claude-3-5-sonnet]
      routing:
        strategy: round_robin
"#
    )
}

/// Build an AI proxy config that routes a Gemini upstream.
fn build_gemini_config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: gemini
          api_key: "stub-key"
          base_url: "{upstream_base}"
          models: [gemini-1.5-pro]
      routing:
        strategy: round_robin
"#
    )
}

#[test]
fn anthropic_native_stream_emits_openai_chat_sse_to_client() {
    let frames = vec![
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"model\":\"claude-3-5-sonnet\",\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n"
            .to_string(),
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
            .to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"
            .to_string(),
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n"
            .to_string(),
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
            .to_string(),
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n"
            .to_string(),
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
    ];
    let upstream =
        MockUpstream::start_sse_raw(frames, "text/event-stream".to_string()).expect("mock");
    let yaml = build_anthropic_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let body = json!({
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(
        resp.status, 200,
        "stream against anthropic upstream returned {}",
        resp.status
    );
    assert_eq!(
        resp.headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or(""),
        "text/event-stream"
    );

    let body = String::from_utf8_lossy(&resp.body).into_owned();
    // Anthropic wire markers must NOT bleed through.
    assert!(
        !body.contains("event: message_start"),
        "anthropic markers leaked: {}",
        truncate(&body)
    );
    assert!(
        !body.contains("content_block_delta"),
        "anthropic block markers leaked: {}",
        truncate(&body)
    );
    // OpenAI Chat SSE shape must be visible.
    assert!(
        body.contains("\"object\":\"chat.completion.chunk\""),
        "missing chat.completion.chunk in body: {}",
        truncate(&body)
    );
    assert!(
        body.contains("\"role\":\"assistant\""),
        "missing assistant role chunk in body: {}",
        truncate(&body)
    );
    assert!(
        body.contains("\"content\":\"Hello\""),
        "missing Hello delta: {}",
        truncate(&body)
    );
    assert!(
        body.contains("\"content\":\" world\""),
        "missing world delta: {}",
        truncate(&body)
    );
    assert!(
        body.contains("\"finish_reason\":\"stop\""),
        "missing finish_reason stop: {}",
        truncate(&body)
    );
    assert!(
        body.contains("data: [DONE]"),
        "missing OpenAI [DONE] terminator: {}",
        truncate(&body)
    );
}

#[test]
fn gemini_native_stream_emits_openai_chat_sse_to_client() {
    let frames = vec![
        "data: {\"responseId\":\"g_1\",\"modelVersion\":\"gemini-1.5-pro\",\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}]}}]}\n\n"
            .to_string(),
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" again\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":2,\"candidatesTokenCount\":2,\"totalTokenCount\":4}}\n\n"
            .to_string(),
    ];
    let upstream =
        MockUpstream::start_sse_raw(frames, "text/event-stream".to_string()).expect("mock");
    let yaml = build_gemini_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let body = json!({
        "model": "gemini-1.5-pro",
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    assert!(
        body.contains("\"content\":\"hello\""),
        "missing hello delta from gemini translation: {}",
        truncate(&body)
    );
    assert!(
        body.contains("\"content\":\" again\""),
        "missing second delta from gemini translation: {}",
        truncate(&body)
    );
    assert!(
        body.contains("data: [DONE]"),
        "missing [DONE] from gemini translation: {}",
        truncate(&body)
    );
}

fn truncate(s: &str) -> String {
    if s.len() <= 400 {
        s.to_string()
    } else {
        format!("{}... ({} bytes)", &s[..400], s.len())
    }
}
