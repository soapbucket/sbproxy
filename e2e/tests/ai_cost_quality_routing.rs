//! Cost/quality routing (WOR-797).
//!
//! With `routing.strategy: cost_quality`, the gateway scores the inbound
//! prompt's difficulty and routes a simple prompt to the cheap provider
//! and a hard prompt to the frontier provider, on a `cost_threshold`
//! dial. The scorer is unit-tested in `sbproxy-ai::cost_quality`; this
//! e2e proves the wiring routes by difficulty through the proxy.

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

fn config(cheap_url: &str, frontier_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: cheap
          provider_type: openai
          api_key: "k"
          base_url: "{cheap_url}"
          allow_private_base_url: true
          models: [gpt-4o]
        - name: frontier
          provider_type: openai
          api_key: "k"
          base_url: "{frontier_url}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: cost_quality
        cheap_provider: cheap
        frontier_provider: frontier
        cost_threshold: 0.5
"#
    )
}

fn chat(content: &str) -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": content}]})
}

#[test]
fn simple_prompt_routes_to_cheap_provider() {
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy = ProxyHarness::start_with_yaml(&config(&cheap.base_url(), &frontier.base_url()))
        .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat("hi"), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !cheap.captured().is_empty(),
        "a simple prompt must route to the cheap provider"
    );
    assert!(
        frontier.captured().is_empty(),
        "the frontier provider must be untouched for a simple prompt"
    );
}

#[test]
fn hard_prompt_routes_to_frontier_provider() {
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy = ProxyHarness::start_with_yaml(&config(&cheap.base_url(), &frontier.base_url()))
        .expect("proxy");

    // A short but semantically hard prompt: code + math + multi-step
    // reasoning signals push the difficulty score above the 0.5 dial
    // without relying on length (which would also exercise the
    // unrelated large-body read path).
    let hard = "Prove that the matrix derivative converges. Analyze step by step. \
                ```python\ndef f():\n    pass\n```";
    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat(hard), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !frontier.captured().is_empty(),
        "a hard prompt must route to the frontier provider"
    );
    assert!(
        cheap.captured().is_empty(),
        "the cheap provider must be untouched for a hard prompt"
    );
}
