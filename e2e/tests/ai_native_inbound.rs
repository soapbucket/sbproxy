//! End-to-end coverage for the WOR-224 native-format inbound shims.
//!
//! With the hub `ChatFormat` trait wired into `handle_ai_proxy`, an
//! Anthropic Messages client can POST to `/v1/messages` and an OpenAI
//! Responses client can POST to `/v1/responses` against an OpenAI-shaped
//! upstream. The gateway parses the inbound body into the hub, replays
//! it as OpenAI Chat Completions to the configured provider, and
//! rewraps the upstream's OpenAI-shaped response in the client's
//! expected wire format.
//!
//! The asserts pin three things:
//!   * The forwarded body the upstream sees is OpenAI Chat
//!     Completions JSON, not Anthropic Messages or Responses JSON.
//!   * The path the upstream sees is `/v1/chat/completions`, even
//!     though the client hit `/v1/messages` or `/v1/responses`.
//!   * The response body returned to the client is in the
//!     client-expected wire shape (Anthropic Messages or Responses).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn build_config(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
      routing:
        strategy: round_robin
"#
    )
}

#[test]
fn anthropic_messages_inbound_translates_request_and_response() {
    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "hello from upstream"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 4, "completion_tokens": 3, "total_tokens": 7}
    }))
    .expect("start mock");

    let yaml = build_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // An Anthropic-shaped request body. Note the top-level `system`
    // field and the `max_tokens` requirement that Anthropic enforces.
    let body = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 128,
        "system": "you are concise",
        "messages": [
            {"role": "user", "content": "ping"}
        ]
    });
    let resp = harness
        .post_json("/v1/messages", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200, "shim should bridge to upstream and 200");

    // The forwarded body should look like OpenAI Chat Completions.
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "upstream must have seen the bridged request"
    );
    let cap = &captured[0];
    assert_eq!(cap.path, "/v1/chat/completions");
    let fwd: serde_json::Value = serde_json::from_slice(&cap.body).expect("forwarded JSON");
    assert_eq!(fwd["model"], "claude-3-5-sonnet");
    let msgs = fwd["messages"].as_array().expect("messages array");
    // Anthropic's top-level system should land as a system role at
    // index 0 in the OpenAI message list.
    assert_eq!(msgs[0]["role"], "system");
    assert_eq!(msgs[0]["content"], "you are concise");
    assert_eq!(msgs[1]["role"], "user");

    // The client response must be Anthropic-shaped (`type: "message"`,
    // `content[0].text`, `stop_reason`), not OpenAI-shaped.
    let body = resp.text().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("client JSON");
    assert_eq!(parsed["type"], "message");
    assert_eq!(parsed["role"], "assistant");
    assert_eq!(parsed["content"][0]["type"], "text");
    assert_eq!(parsed["content"][0]["text"], "hello from upstream");
    assert_eq!(parsed["stop_reason"], "end_turn");
    assert_eq!(parsed["usage"]["input_tokens"], 4);
    assert_eq!(parsed["usage"]["output_tokens"], 3);
}

#[test]
fn openai_responses_inbound_translates_request_and_response() {
    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-xyz",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "responses world"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 6, "completion_tokens": 2, "total_tokens": 8}
    }))
    .expect("start mock");

    let yaml = build_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // OpenAI Responses-shaped request body: string input, instructions
    // for system, `max_output_tokens`.
    let body = json!({
        "model": "gpt-4o",
        "instructions": "be polite",
        "input": "knock knock",
        "max_output_tokens": 64
    });
    let resp = harness
        .post_json("/v1/responses", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200, "shim should bridge and return 200");

    // Verify upstream saw OpenAI Chat Completions shape.
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "upstream must have seen the bridged request"
    );
    let cap = &captured[0];
    assert_eq!(cap.path, "/v1/chat/completions");
    let fwd: serde_json::Value = serde_json::from_slice(&cap.body).expect("forwarded JSON");
    assert_eq!(fwd["model"], "gpt-4o");
    let msgs = fwd["messages"].as_array().expect("messages array");
    assert_eq!(msgs[0]["role"], "system");
    assert_eq!(msgs[0]["content"], "be polite");
    assert_eq!(msgs[1]["role"], "user");
    assert_eq!(msgs[1]["content"], "knock knock");

    // Verify the client got the Responses-shaped reply.
    let body = resp.text().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("client JSON");
    assert_eq!(parsed["object"], "response");
    assert_eq!(parsed["status"], "completed");
    assert_eq!(parsed["output"][0]["type"], "message");
    assert_eq!(parsed["output"][0]["content"][0]["text"], "responses world");
    assert_eq!(parsed["usage"]["input_tokens"], 6);
    assert_eq!(parsed["usage"]["output_tokens"], 2);
}

#[test]
fn chat_completions_inbound_still_passes_through_unchanged() {
    // Regression guard. The native-shim wiring must not change the
    // existing `/v1/chat/completions` path behaviour for OpenAI clients.
    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-regression",
        "object": "chat.completion",
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "back atcha"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
    .expect("start mock");

    let yaml = build_config(&upstream.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}],
    });
    let resp = harness
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("post");
    assert_eq!(resp.status, 200);

    // The response should be OpenAI Chat Completions shape, not
    // Anthropic Messages or Responses shape.
    let body = resp.text().unwrap_or_default();
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("client JSON");
    assert_eq!(parsed["object"], "chat.completion");
    assert_eq!(parsed["choices"][0]["message"]["content"], "back atcha");
}
