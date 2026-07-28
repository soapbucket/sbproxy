//! Process-restart acceptance proof for default Local summary state.

use sbproxy_e2e::{CapturedRequest, MockUpstream, ProxyHarness};
use serde_json::{json, Value};
use std::path::Path;

const HOST: &str = "local-compression.localhost";

fn config(upstream_base: &str, state_path: &Path) -> String {
    let state_path = state_path.to_string_lossy().replace('\'', "''");
    format!(
        r#"
proxy:
  http_bind_port: 0
  compression_state:
    local_path: '{state_path}'
origins:
  "{HOST}":
    action:
      type: ai_proxy
      providers:
        - name: openai
          provider_type: openai
          api_key: stub-key
          base_url: "{upstream_base}"
          allow_private_base_url: true
          default_model: gpt-4o
          models: [gpt-4o, summary-model]
      compression:
        levers:
          - type: summary_buffer
            min_tokens: 100
            retain_recent_messages: 1
            target_summary_tokens: 32
            summarizer:
              provider: openai
              model: summary-model
              timeout: 2s
"#
    )
}

fn chat_reply(id: &str, model: &str, content: &str) -> Value {
    json!({
        "id": id,
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 30, "completion_tokens": 4, "total_tokens": 34}
    })
}

fn request_body() -> Value {
    json!({
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Keep deployment facts accurate."},
            {
                "role": "user",
                "content": "Old incident question about the checkout deployment. ".repeat(100)
            },
            {
                "role": "assistant",
                "content": "Old incident answer naming catalog-v42 in us-west-2. ".repeat(100)
            },
            {"role": "user", "content": "What should we remember now?"}
        ]
    })
}

fn send(harness: &ProxyHarness, session_id: &str) -> Value {
    let response = harness
        .post_json(
            "/v1/chat/completions",
            HOST,
            &request_body(),
            &[("X-Sb-Session-Id", session_id)],
        )
        .expect("send compressed request");
    assert_eq!(
        response.status,
        200,
        "request failed: {}",
        String::from_utf8_lossy(&response.body)
    );
    response.json().expect("target response JSON")
}

fn captured_json(capture: &CapturedRequest) -> Value {
    serde_json::from_slice(&capture.body).expect("captured provider request JSON")
}

#[test]
fn summary_buffer_defaults_local_and_reuses_state_after_process_restart() {
    let upstream = MockUpstream::start_sequence(vec![
        (
            200,
            chat_reply(
                "chatcmpl-summary",
                "summary-model",
                "Checkout depended on catalog-v42 in us-west-2.",
            ),
        ),
        (
            200,
            chat_reply("chatcmpl-target-first", "gpt-4o", "first target response"),
        ),
        (
            200,
            chat_reply(
                "chatcmpl-target-after-restart",
                "gpt-4o",
                "second target response",
            ),
        ),
    ])
    .expect("start sequenced provider");
    let state_directory = tempfile::tempdir().expect("Local state directory");
    let state_path = state_directory.path().join("compression-state.redb");
    let yaml = config(&upstream.base_url(), &state_path);
    let session_id = ulid::Ulid::new().to_string();

    {
        let first =
            ProxyHarness::start_with_yaml(&yaml).expect("start first Local-state proxy process");
        let response = send(&first, &session_id);
        assert_eq!(
            response["choices"][0]["message"]["content"],
            "first target response"
        );
        assert!(
            state_path.is_file(),
            "the omitted action state must create the configured Local database"
        );
    }

    assert_eq!(
        upstream.captured().len(),
        2,
        "the first process must call the summarizer and then the target"
    );

    {
        let restarted =
            ProxyHarness::start_with_yaml(&yaml).expect("restart proxy against the same database");
        let response = send(&restarted, &session_id);
        assert_eq!(
            response["choices"][0]["message"]["content"],
            "second target response"
        );
    }

    let captures = upstream.captured();
    assert_eq!(
        captures.len(),
        3,
        "restart must add only the target call, never a second summarizer call"
    );
    let requests = captures.iter().map(captured_json).collect::<Vec<_>>();
    assert_eq!(
        requests
            .iter()
            .map(|request| request["model"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["summary-model", "gpt-4o", "gpt-4o"]
    );
    assert_eq!(
        requests[1]["messages"], requests[2]["messages"],
        "the restarted process must reconstruct the same compressed target request"
    );
    assert!(
        requests[1]["messages"]
            .to_string()
            .contains("Checkout depended on catalog-v42 in us-west-2."),
        "the target request must contain the durable summary"
    );
}
