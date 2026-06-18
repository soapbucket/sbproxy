//! WOR-1439: end-to-end proof that OpenAI-shaped requests are rewritten
//! for native Anthropic, Gemini, and Bedrock upstream providers and that
//! native responses are normalized back to OpenAI Chat Completions shape.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::{json, Value};

fn config_for(provider_name: &str, host: &str, upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{host}":
    action:
      type: ai_proxy
      providers:
        - name: {provider_name}
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
      routing:
        strategy: round_robin
"#
    )
}

fn single_capture_json(upstream: &MockUpstream) -> (String, Value) {
    let captured = upstream.captured();
    assert_eq!(
        captured.len(),
        1,
        "expected exactly one upstream request, got {}",
        captured.len()
    );
    let body: Value = serde_json::from_slice(&captured[0].body).expect("upstream JSON body");
    (captured[0].path.clone(), body)
}

fn assert_absent(obj: &Value, keys: &[&str]) {
    let object = obj.as_object().expect("object body");
    for key in keys {
        assert!(
            !object.contains_key(*key),
            "expected `{key}` to be stripped from forwarded body: {obj}"
        );
    }
}

#[test]
fn anthropic_chat_request_rewrite_and_response_normalization() {
    let upstream = MockUpstream::start(json!({
        "id": "msg_wor1439",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet",
        "content": [{"type": "text", "text": "anthropic ok"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 11, "output_tokens": 4}
    }))
    .expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "anthropic",
        "anthropic.localhost",
        &upstream.base_url(),
    ))
    .expect("proxy");

    let resp = harness
        .post_json(
            "/v1/chat/completions",
            "anthropic.localhost",
            &json!({
                "model": "claude-3-5-sonnet",
                "messages": [
                    {"role": "system", "content": "reply tersely"},
                    {"role": "user", "content": "hi anthropic"}
                ],
                "max_tokens": 64,
                "temperature": 0.2,
                "n": 2,
                "seed": 42,
                "user": "end-user-1",
                "response_format": {"type": "json_object"},
                "presence_penalty": 0.5,
                "frequency_penalty": 0.5,
                "logit_bias": {"123": 1}
            }),
            &[],
        )
        .expect("post");
    assert_eq!(resp.status, 200);

    let (path, forwarded) = single_capture_json(&upstream);
    assert_eq!(path, "/v1/messages");
    assert_eq!(forwarded["system"], "reply tersely");
    assert_eq!(forwarded["max_tokens"], 64);
    assert_eq!(forwarded["temperature"], 0.2);
    assert_eq!(forwarded["messages"].as_array().unwrap().len(), 1);
    assert_eq!(forwarded["messages"][0]["role"], "user");
    assert_eq!(forwarded["messages"][0]["content"], "hi anthropic");
    assert_absent(
        &forwarded,
        &[
            "n",
            "seed",
            "user",
            "response_format",
            "presence_penalty",
            "frequency_penalty",
            "logit_bias",
        ],
    );

    let out = resp.json().expect("client JSON body");
    assert_eq!(out["object"], "chat.completion");
    assert_eq!(out["id"], "msg_wor1439");
    assert_eq!(out["model"], "claude-3-5-sonnet");
    assert_eq!(out["choices"][0]["message"]["role"], "assistant");
    assert_eq!(out["choices"][0]["message"]["content"], "anthropic ok");
    assert_eq!(out["choices"][0]["finish_reason"], "stop");
    assert_eq!(out["usage"]["prompt_tokens"], 11);
    assert_eq!(out["usage"]["completion_tokens"], 4);
    assert_eq!(out["usage"]["total_tokens"], 15);
}

#[test]
fn gemini_chat_request_rewrite_and_response_normalization() {
    let upstream = MockUpstream::start(json!({
        "responseId": "gem_wor1439",
        "modelVersion": "gemini-1.5-pro",
        "candidates": [{
            "content": {
                "role": "model",
                "parts": [{"text": "gemini ok"}]
            },
            "finishReason": "STOP"
        }],
        "usageMetadata": {
            "promptTokenCount": 7,
            "candidatesTokenCount": 3,
            "totalTokenCount": 10
        }
    }))
    .expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "gemini",
        "gemini.localhost",
        &upstream.base_url(),
    ))
    .expect("proxy");

    let resp = harness
        .post_json(
            "/v1/chat/completions",
            "gemini.localhost",
            &json!({
                "model": "gemini-1.5-pro",
                "messages": [
                    {"role": "system", "content": "be concise"},
                    {"role": "user", "content": "hi gemini"}
                ],
                "max_tokens": 128,
                "temperature": 0.4,
                "top_p": 0.8,
                "top_k": 40,
                "stop": ["END"],
                "n": 2,
                "seed": 42,
                "user": "end-user-1",
                "response_format": {"type": "json_object"},
                "presence_penalty": 0.5,
                "frequency_penalty": 0.5,
                "logit_bias": {"123": 1}
            }),
            &[],
        )
        .expect("post");
    assert_eq!(resp.status, 200);

    let (path, forwarded) = single_capture_json(&upstream);
    assert_eq!(path, "/v1beta/models/gemini-1.5-pro:generateContent");
    assert_eq!(
        forwarded["systemInstruction"]["parts"][0]["text"],
        "be concise"
    );
    assert_eq!(forwarded["contents"].as_array().unwrap().len(), 1);
    assert_eq!(forwarded["contents"][0]["role"], "user");
    assert_eq!(forwarded["contents"][0]["parts"][0]["text"], "hi gemini");
    assert_eq!(forwarded["generationConfig"]["maxOutputTokens"], 128);
    assert_eq!(forwarded["generationConfig"]["temperature"], 0.4);
    assert_eq!(forwarded["generationConfig"]["topP"], 0.8);
    assert_eq!(forwarded["generationConfig"]["topK"], 40);
    assert_eq!(forwarded["generationConfig"]["stopSequences"][0], "END");
    assert_absent(
        &forwarded,
        &[
            "model",
            "messages",
            "max_tokens",
            "top_p",
            "top_k",
            "stop",
            "n",
            "seed",
            "user",
            "response_format",
            "presence_penalty",
            "frequency_penalty",
            "logit_bias",
        ],
    );

    let out = resp.json().expect("client JSON body");
    assert_eq!(out["object"], "chat.completion");
    assert_eq!(out["id"], "gem_wor1439");
    assert_eq!(out["model"], "gemini-1.5-pro");
    assert_eq!(out["choices"][0]["message"]["role"], "assistant");
    assert_eq!(out["choices"][0]["message"]["content"], "gemini ok");
    assert_eq!(out["choices"][0]["finish_reason"], "stop");
    assert_eq!(out["usage"]["prompt_tokens"], 7);
    assert_eq!(out["usage"]["completion_tokens"], 3);
    assert_eq!(out["usage"]["total_tokens"], 10);
}

#[test]
fn bedrock_chat_request_rewrite_and_response_normalization() {
    let upstream = MockUpstream::start(json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": [{"text": "bedrock ok"}]
            }
        },
        "stopReason": "end_turn",
        "usage": {"inputTokens": 5, "outputTokens": 6, "totalTokens": 11}
    }))
    .expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "bedrock",
        "bedrock.localhost",
        &upstream.base_url(),
    ))
    .expect("proxy");

    let resp = harness
        .post_json(
            "/v1/chat/completions",
            "bedrock.localhost",
            &json!({
                "model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                "messages": [
                    {"role": "system", "content": "respond from bedrock"},
                    {"role": "user", "content": "hi bedrock"}
                ],
                "max_tokens": 128,
                "temperature": 0.3,
                "top_p": 0.9,
                "top_k": 20,
                "stop": ["END"],
                "n": 2,
                "seed": 42,
                "user": "end-user-1",
                "response_format": {"type": "json_object"},
                "presence_penalty": 0.5,
                "frequency_penalty": 0.5,
                "logit_bias": {"123": 1}
            }),
            &[],
        )
        .expect("post");
    assert_eq!(resp.status, 200);

    let (path, forwarded) = single_capture_json(&upstream);
    assert_eq!(
        path,
        "/model/anthropic.claude-3-5-sonnet-20240620-v1:0/converse"
    );
    assert_eq!(forwarded["system"][0]["text"], "respond from bedrock");
    assert_eq!(forwarded["messages"].as_array().unwrap().len(), 1);
    assert_eq!(forwarded["messages"][0]["role"], "user");
    assert_eq!(forwarded["messages"][0]["content"][0]["text"], "hi bedrock");
    assert_eq!(forwarded["inferenceConfig"]["maxTokens"], 128);
    assert_eq!(forwarded["inferenceConfig"]["temperature"], 0.3);
    assert_eq!(forwarded["inferenceConfig"]["topP"], 0.9);
    assert_eq!(forwarded["inferenceConfig"]["stopSequences"][0], "END");
    assert_absent(
        &forwarded,
        &[
            "model",
            "max_tokens",
            "temperature",
            "top_p",
            "top_k",
            "stop",
            "n",
            "seed",
            "user",
            "response_format",
            "presence_penalty",
            "frequency_penalty",
            "logit_bias",
        ],
    );

    let out = resp.json().expect("client JSON body");
    assert_eq!(out["object"], "chat.completion");
    assert_eq!(out["choices"][0]["message"]["role"], "assistant");
    assert_eq!(out["choices"][0]["message"]["content"], "bedrock ok");
    assert_eq!(out["choices"][0]["finish_reason"], "stop");
    assert_eq!(out["usage"]["prompt_tokens"], 5);
    assert_eq!(out["usage"]["completion_tokens"], 6);
    assert_eq!(out["usage"]["total_tokens"], 11);
}

#[test]
fn native_provider_error_statuses_are_preserved_after_rewrite() {
    let cases = [
        (
            "anthropic",
            "anthropic-error.localhost",
            "claude-3-5-sonnet",
            "/v1/messages",
        ),
        (
            "gemini",
            "gemini-error.localhost",
            "gemini-1.5-pro",
            "/v1beta/models/gemini-1.5-pro:generateContent",
        ),
        (
            "bedrock",
            "bedrock-error.localhost",
            "anthropic.claude-3-5-sonnet-20240620-v1:0",
            "/model/anthropic.claude-3-5-sonnet-20240620-v1:0/converse",
        ),
    ];

    for (provider, host, model, expected_path) in cases {
        let upstream = MockUpstream::start_with_status(
            json!({"error": {"message": "rate limited", "type": "rate_limit"}}),
            429,
        )
        .expect("mock");
        let harness =
            ProxyHarness::start_with_yaml(&config_for(provider, host, &upstream.base_url()))
                .expect("proxy");
        let resp = harness
            .post_json(
                "/v1/chat/completions",
                host,
                &json!({
                    "model": model,
                    "messages": [{"role": "user", "content": "will be rejected"}]
                }),
                &[],
            )
            .expect("post");

        assert_eq!(
            resp.status, 429,
            "{provider} upstream error status should be preserved"
        );
        let (path, forwarded) = single_capture_json(&upstream);
        assert_eq!(
            path, expected_path,
            "{provider} error path should still use the native endpoint"
        );
        assert!(
            forwarded.get("messages").is_some() || forwarded.get("contents").is_some(),
            "{provider} error request should still be provider-shaped: {forwarded}"
        );
    }
}
