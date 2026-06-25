//! Content-policy fallback (WOR-1545).
//!
//! A provider may refuse a request on content-policy / safety grounds with a
//! 4xx. With `resilience.content_policy_fallback`, the gateway routes that
//! refusal to the next (more permissive) provider in order instead of
//! returning it. With the flag off (the default), the refusal is returned
//! unchanged.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-permissive",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn refusal() -> serde_json::Value {
    json!({
        "error": {
            "message": "Your request was rejected by our safety system.",
            "type": "content_policy_violation",
            "code": "content_policy_violation"
        }
    })
}

fn config(strict_url: &str, permissive_url: &str, fallback: bool) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: strict
          provider_type: openai
          api_key: "k"
          base_url: "{strict_url}"
          allow_private_base_url: true
          priority: 1
          models: [gpt-4o]
        - name: permissive
          provider_type: openai
          api_key: "k"
          base_url: "{permissive_url}"
          allow_private_base_url: true
          priority: 2
          models: [gpt-4o]
      routing:
        strategy: fallback_chain
      resilience:
        content_policy_fallback: {fallback}
"#
    )
}

fn send(proxy: &ProxyHarness) -> u16 {
    proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
            &[],
        )
        .expect("send")
        .status
}

#[test]
fn content_policy_refusal_fails_over_to_permissive_provider() {
    // `strict` refuses with a 400 content-policy violation; `permissive`
    // would answer 200.
    let strict = MockUpstream::start_with_status(refusal(), 400).expect("strict");
    let permissive = MockUpstream::start(chat_reply()).expect("permissive");
    let proxy =
        ProxyHarness::start_with_yaml(&config(&strict.base_url(), &permissive.base_url(), true))
            .expect("proxy");

    // The refusal is routed past `strict` to `permissive`, so the client
    // sees the 200, not the 400.
    assert_eq!(
        send(&proxy),
        200,
        "content-policy refusal fails over to 200"
    );
    assert!(
        !strict.captured().is_empty() && !permissive.captured().is_empty(),
        "both the strict refuser and the permissive fallback were tried"
    );
}

#[test]
fn content_policy_refusal_returned_when_fallback_disabled() {
    // Default behavior: a 4xx is not retried, so the refusal is returned.
    let strict = MockUpstream::start_with_status(refusal(), 400).expect("strict");
    let permissive = MockUpstream::start(chat_reply()).expect("permissive");
    let proxy =
        ProxyHarness::start_with_yaml(&config(&strict.base_url(), &permissive.base_url(), false))
            .expect("proxy");

    assert_eq!(send(&proxy), 400, "refusal is returned with the flag off");
    assert!(
        permissive.captured().is_empty(),
        "the permissive provider is not tried when the flag is off"
    );
}
