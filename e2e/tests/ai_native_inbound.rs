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
          allow_private_base_url: true
      routing:
        strategy: round_robin
"#
    )
}

fn anthropic_compression_config(upstream_base: &str) -> String {
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
          allow_private_base_url: true
      compression:
        levers:
          - type: window_fit
            completion_reserve_tokens: 0
            input_budget_tokens: 96
      routing:
        strategy: round_robin
"#
    )
}

fn anthropic_native_config(upstream_base: &str) -> String {
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
          provider_type: anthropic
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
      routing:
        strategy: round_robin
"#
    )
}

fn anthropic_native_guardrail_config(upstream_base: &str, phase: &str) -> String {
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
          provider_type: anthropic
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
      guardrails:
        {phase}:
          - type: regex
            action: block
            patterns:
              - "FORBIDDEN_NATIVE_TEXT"
      routing:
        strategy: round_robin
"#
    )
}

fn anthropic_native_reversible_pii_config(upstream_base: &str) -> String {
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
          provider_type: anthropic
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
      pii:
        enabled: true
        defaults: false
        redact_request: true
        rules:
          - name: email
            pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}'
            reversible: true
      routing:
        strategy: round_robin
"#
    )
}

fn anthropic_to_openai_fallback_config(anthropic_base: &str, openai_base: &str) -> String {
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
          provider_type: anthropic
          api_key: "stub-key"
          base_url: "{anthropic_base}"
          allow_private_base_url: true
          priority: 1
        - name: openai
          provider_type: openai
          api_key: "stub-key"
          base_url: "{openai_base}"
          allow_private_base_url: true
          priority: 2
      routing:
        strategy: fallback_chain
"#
    )
}

fn anthropic_native_pii_config(upstream_base: &str, store_path: &std::path::Path) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  key_management:
    enabled: true
    store:
      backend: embedded
      path: "{}"
    crypto:
      pepper: e2e-native-pii-pepper
      master_key: e2e-native-pii-master
    inbound:
      native_key_policy:
        allowed_providers: [anthropic]
        require_pii_redaction: [email]
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      pii:
        enabled: true
      providers:
        - name: anthropic
          provider_type: anthropic
          api_key: "operator-key-must-not-be-used"
          base_url: "{upstream_base}"
          allow_private_base_url: true
          models: [claude-3-5-sonnet]
      routing:
        strategy: round_robin
"#,
        store_path.display()
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
fn anthropic_native_upstream_receives_the_compressed_message_list() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_compressed",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "compressed context received"}],
        "model": "claude-3-5-sonnet",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 8, "output_tokens": 3}
    }))
    .expect("start Anthropic mock");
    let harness =
        ProxyHarness::start_with_yaml(&anthropic_compression_config(&upstream.base_url()))
            .expect("start proxy");
    let messages = (0..8)
        .map(|index| {
            json!({
                "role": if index % 2 == 0 { "user" } else { "assistant" },
                "content": format!("turn {index}: {}", "old context ".repeat(60))
            })
        })
        .chain(std::iter::once(json!({
            "role": "user",
            "content": "answer the newest turn"
        })))
        .collect::<Vec<_>>();
    let body = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 128,
        "system": "be concise",
        "messages": messages
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &body, &[])
        .expect("post compressed Anthropic request");

    assert_eq!(response.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/v1/messages");
    let forwarded: serde_json::Value =
        serde_json::from_slice(&captured[0].body).expect("forwarded Anthropic JSON");
    let forwarded_messages = forwarded["messages"]
        .as_array()
        .expect("forwarded messages");
    assert!(
        forwarded_messages.len() < body["messages"].as_array().unwrap().len(),
        "the native Anthropic provider must receive compressed messages: {forwarded}"
    );
    assert_eq!(
        forwarded_messages.last().unwrap()["content"],
        "answer the newest turn"
    );
}

#[test]
fn anthropic_compression_preserves_provider_error_envelope() {
    let error = json!({
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "message": "compressed request rejected"
        }
    });
    let upstream =
        MockUpstream::start_with_status(error.clone(), 400).expect("start Anthropic mock");
    let harness =
        ProxyHarness::start_with_yaml(&anthropic_compression_config(&upstream.base_url()))
            .expect("start proxy");
    let request = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "ping"}]
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post compressed Anthropic request");

    assert_eq!(response.status, 400);
    assert_eq!(response.json().expect("Anthropic error JSON"), error);
    assert_eq!(upstream.captured()[0].path, "/v1/messages");
}

#[test]
fn anthropic_native_bypass_preserves_native_response_bytes() {
    let native_response = json!({
        "id": "msg_native",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "native response"}],
        "model": "claude-3-5-sonnet",
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens": 4, "output_tokens": 2}
    });
    let expected_bytes = serde_json::to_vec(&native_response).expect("native response JSON");
    let upstream = MockUpstream::start(native_response).expect("start Anthropic mock");
    let harness = ProxyHarness::start_with_yaml(&anthropic_native_config(&upstream.base_url()))
        .expect("start proxy");
    let request = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "ping"}]
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post Anthropic request");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, expected_bytes);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/v1/messages");
}

#[test]
fn anthropic_native_input_with_unrepresented_block_is_not_forwarded_raw() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_governed",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "governed response"}],
        "model": "claude-3-5-sonnet",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 4, "output_tokens": 2}
    }))
    .expect("start Anthropic mock");
    let harness = ProxyHarness::start_with_yaml(&anthropic_native_guardrail_config(
        &upstream.base_url(),
        "input",
    ))
    .expect("start proxy");
    let request = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "summarize the attached document"},
                {
                    "type": "document",
                    "source": {
                        "type": "text",
                        "media_type": "text/plain",
                        "data": "FORBIDDEN_NATIVE_TEXT must stay governed"
                    }
                }
            ]
        }]
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post Anthropic request");

    assert_eq!(response.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/v1/messages");
    let forwarded = String::from_utf8_lossy(&captured[0].body);
    assert!(
        !forwarded.contains("FORBIDDEN_NATIVE_TEXT") && !forwarded.contains("\"document\""),
        "content omitted from the governed canonical tree was forwarded raw: {forwarded}"
    );
}

#[test]
fn anthropic_native_output_guardrail_checks_unsupported_response_blocks() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_guardrail",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": "safe visible answer"},
            {
                "type": "thinking",
                "thinking": "FORBIDDEN_NATIVE_TEXT hidden in a vendor-only block"
            }
        ],
        "model": "claude-3-5-sonnet",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 4, "output_tokens": 2}
    }))
    .expect("start Anthropic mock");
    let harness = ProxyHarness::start_with_yaml(&anthropic_native_guardrail_config(
        &upstream.base_url(),
        "output",
    ))
    .expect("start proxy");
    let request = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "ping"}]
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post Anthropic request");

    assert_eq!(response.status, 403);
    let body = response.text().unwrap_or_default();
    assert!(body.contains("guardrail_violation"), "{body}");
    assert_eq!(upstream.captured().len(), 1);
}

#[test]
fn anthropic_native_pii_redaction_reaches_upstream_and_restores_client_bytes() {
    let raw_email = "alice@example.com";
    let placeholder = "<placeholder:email:0>";
    let upstream = MockUpstream::start(json!({
        "id": "msg_pii",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": format!("Hello {placeholder}")}],
        "model": "claude-3-5-sonnet",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 4, "output_tokens": 2}
    }))
    .expect("start Anthropic mock");
    let harness = ProxyHarness::start_with_yaml(&anthropic_native_reversible_pii_config(
        &upstream.base_url(),
    ))
    .expect("start proxy");
    let request = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": format!("Email {raw_email}")}]
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post Anthropic request");

    assert_eq!(response.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/v1/messages");
    let forwarded = String::from_utf8_lossy(&captured[0].body);
    assert!(
        !forwarded.contains(raw_email),
        "raw PII reached the provider: {forwarded}"
    );
    assert!(
        forwarded.contains(placeholder),
        "redacted placeholder did not reach the provider: {forwarded}"
    );

    let client_body = response.json().expect("Anthropic response JSON");
    assert_eq!(
        client_body["content"][0]["text"],
        format!("Hello {raw_email}")
    );
    assert!(
        !client_body.to_string().contains(placeholder),
        "placeholder leaked to the client: {client_body}"
    );
}

#[test]
fn anthropic_native_failure_falls_back_to_openai_and_rewraps_response() {
    let anthropic = MockUpstream::start_with_status(
        json!({"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}),
        503,
    )
    .expect("start failing Anthropic mock");
    let openai = MockUpstream::start(json!({
        "id": "chatcmpl-fallback",
        "object": "chat.completion",
        "model": "claude-3-5-sonnet",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "fallback response"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}
    }))
    .expect("start OpenAI fallback mock");
    let harness = ProxyHarness::start_with_yaml(&anthropic_to_openai_fallback_config(
        &anthropic.base_url(),
        &openai.base_url(),
    ))
    .expect("start proxy");
    let request = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "ping"}]
    });

    let response = harness
        .post_json("/v1/messages", "ai.localhost", &request, &[])
        .expect("post Anthropic request");

    assert_eq!(response.status, 200);
    let body = response.json().expect("Anthropic response JSON");
    assert_eq!(body["type"], "message");
    assert_eq!(body["content"][0]["text"], "fallback response");
    assert!(body.get("choices").is_none(), "{body}");
    assert_eq!(anthropic.captured()[0].path, "/v1/messages");
    assert_eq!(openai.captured()[0].path, "/v1/chat/completions");
}

#[test]
fn anthropic_native_bypass_never_forwards_pre_redaction_content() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_redacted",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "safe"}],
        "model": "claude-3-5-sonnet",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 8, "output_tokens": 1}
    }))
    .expect("start Anthropic mock");
    let store_dir = tempfile::tempdir().expect("store directory");
    let yaml =
        anthropic_native_pii_config(&upstream.base_url(), &store_dir.path().join("keys.redb"));
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let body = json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 128,
        "messages": [{
            "role": "user",
            "content": "contact alice@example.com"
        }]
    });

    let response = harness
        .post_json(
            "/v1/messages",
            "ai.localhost",
            &body,
            &[("x-api-key", "sk-ant-api03-caller-owned")],
        )
        .expect("post native Anthropic request");
    assert_eq!(response.status, 200);

    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    let forwarded: serde_json::Value =
        serde_json::from_slice(&captured[0].body).expect("forwarded JSON");
    let forwarded_text = forwarded["messages"][0]["content"]
        .as_str()
        .expect("forwarded text");
    assert!(forwarded_text.contains("[REDACTED:EMAIL]"), "{forwarded}");
    assert!(!forwarded_text.contains("alice@example.com"), "{forwarded}");
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
