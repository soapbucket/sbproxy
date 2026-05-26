//! Large request-body handling in the AI dispatch (WOR-795 body-buffering fix).
//!
//! Pingora delivers the request body one chunk at a time. The AI
//! dispatch previously did a single `read_request_body()`, so a chat
//! prompt large enough to span multiple chunks was truncated to the
//! first chunk and the JSON parse failed with a spurious 400
//! ("invalid JSON body"). The dispatch now drains the full body.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn config(upstream_url: &str) -> String {
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
          provider_type: openai
          api_key: "k"
          base_url: "{upstream_url}"
          allow_private_base_url: true
          models: [gpt-4o]
"#
    )
}

#[test]
fn large_chat_body_is_read_in_full() {
    let upstream = MockUpstream::start(chat_reply()).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    // ~70 KB of user content: comfortably larger than a single body
    // chunk, so the dispatch must drain multiple chunks.
    let big = "the quick brown fox jumps over the lazy dog. ".repeat(1500);
    assert!(
        big.len() > 60_000,
        "prompt must exceed one chunk: {}",
        big.len()
    );
    let body = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": big}]});

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "a large multi-chunk body must be read in full, not truncated to a 400"
    );
    assert!(
        !upstream.captured().is_empty(),
        "the upstream must receive the full request"
    );
}
