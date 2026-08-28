//! Streaming for native-inbound surfaces against an OpenAI upstream
//! (WOR-799).
//!
//! Non-streaming `/v1/messages` (Anthropic) and `/v1/responses`
//! (OpenAI Responses) already translate through the hub. This covers
//! the streaming gap: when the client streams one of those surfaces and
//! the upstream is an OpenAI-format provider, the gateway parses the
//! OpenAI Chat SSE back into the hub and re-emits it in the inbound
//! wire shape. An OpenAI-in / OpenAI-out stream still passes through
//! untouched (covered elsewhere).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn truncate(s: &str) -> String {
    s.chars().take(600).collect()
}

/// OpenAI Chat Completions SSE frames the mock upstream emits.
fn openai_chat_sse_frames() -> Vec<String> {
    vec![
        "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n".to_string(),
        "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n".to_string(),
        "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":null}]}\n\n".to_string(),
        "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n".to_string(),
        "data: [DONE]\n\n".to_string(),
    ]
}

fn openai_provider_config(upstream_base: &str) -> String {
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

#[test]
fn messages_stream_against_openai_upstream_emits_anthropic_sse() {
    let upstream =
        MockUpstream::start_sse_raw(openai_chat_sse_frames(), "text/event-stream".to_string())
            .expect("mock");
    let harness = ProxyHarness::start_with_yaml(&openai_provider_config(&upstream.base_url()))
        .expect("proxy");

    // Anthropic Messages inbound shape, streaming.
    let body = json!({
        "model": "gpt-4o",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });
    let resp = harness
        .post_json("/v1/messages", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200, "messages stream returned {}", resp.status);
    assert_eq!(
        resp.headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or(""),
        "text/event-stream"
    );

    let out = String::from_utf8_lossy(&resp.body).into_owned();
    // Anthropic wire shape must be present...
    assert!(
        out.contains("content_block_delta"),
        "expected Anthropic content_block_delta frames; got: {}",
        truncate(&out)
    );
    assert!(
        out.contains("Hello"),
        "expected the translated text delta; got: {}",
        truncate(&out)
    );
    assert!(
        out.contains("message_stop"),
        "expected an Anthropic message_stop terminal; got: {}",
        truncate(&out)
    );
    // ...and the raw OpenAI chunk shape must NOT bleed through.
    assert!(
        !out.contains("chat.completion.chunk"),
        "OpenAI chunk shape leaked into an Anthropic stream: {}",
        truncate(&out)
    );
}

#[test]
fn messages_stream_provider_error_preserves_json_response() {
    let error = json!({
        "error": {
            "type": "invalid_request_error",
            "message": "stream request rejected"
        }
    });
    let expected = serde_json::to_vec(&error).expect("error JSON");
    let upstream = MockUpstream::start_with_status(error, 400).expect("start JSON error upstream");
    let harness = ProxyHarness::start_with_yaml(&openai_provider_config(&upstream.base_url()))
        .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post");

    assert_eq!(response.status, 400);
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        response
            .headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok()),
        Some(expected.len())
    );
    assert_eq!(response.body, expected);
}

#[test]
fn messages_stream_non_sse_success_is_rewrapped_for_anthropic_client() {
    let fallback = json!({
        "id": "chatcmpl-buffered",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "buffered response"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    });
    let upstream = MockUpstream::start(fallback).expect("start JSON upstream");
    let harness = ProxyHarness::start_with_yaml(&openai_provider_config(&upstream.base_url()))
        .expect("proxy");
    let request = json!({
        "model": "gpt-4o",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "hi"}],
        "stream": true,
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        response
            .headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok()),
        Some(response.body.len())
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.body).expect("Anthropic response JSON");
    assert_eq!(body["type"], "message");
    assert_eq!(body["content"][0]["text"], "buffered response");
    assert_eq!(body["usage"]["input_tokens"], 3);
    assert_eq!(body["usage"]["output_tokens"], 2);
    assert!(body.get("choices").is_none(), "{body}");
}

#[test]
fn responses_stream_against_openai_upstream_is_translated() {
    let upstream =
        MockUpstream::start_sse_raw(openai_chat_sse_frames(), "text/event-stream".to_string())
            .expect("mock");
    let harness = ProxyHarness::start_with_yaml(&openai_provider_config(&upstream.base_url()))
        .expect("proxy");

    // OpenAI Responses inbound shape, streaming.
    let body = json!({
        "model": "gpt-4o",
        "input": "hi",
        "stream": true,
    });
    let resp = harness
        .post_json("/v1/responses", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(
        resp.status, 200,
        "responses stream returned {}",
        resp.status
    );
    assert_eq!(
        resp.headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or(""),
        "text/event-stream"
    );

    let out = String::from_utf8_lossy(&resp.body).into_owned();
    // The Responses surface re-frames into its own `response.*` events,
    // so the raw OpenAI Chat chunk object must not pass through verbatim.
    assert!(
        !out.contains("chat.completion.chunk"),
        "OpenAI Chat chunk shape leaked into a Responses stream: {}",
        truncate(&out)
    );
    assert!(
        out.contains("response.") || out.contains("Hello"),
        "expected a translated Responses stream carrying the text; got: {}",
        truncate(&out)
    );
}
