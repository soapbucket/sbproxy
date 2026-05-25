//! disallow_prompt_training routing filter (WOR-799).
//!
//! A request carrying `x-sbproxy-disallow-prompt-training: true` is
//! routed only to providers the operator declared `no_prompt_training`.
//! There is no standardized per-request training opt-out header across
//! providers, so SBproxy enforces the intent at the gateway by filtering
//! the routing set (and failing closed when none qualify).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

// Two providers: `trainer` (priority 0, training-eligible) is preferred
// by the fallback chain; `compliant` (priority 1, no_prompt_training)
// is only reached when the disallow filter removes `trainer`.
fn config(trainer_url: &str, compliant_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: trainer
          provider_type: openai
          api_key: "k"
          base_url: "{trainer_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          priority: 0
        - name: compliant
          provider_type: openai
          api_key: "k"
          base_url: "{compliant_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          priority: 1
          no_prompt_training: true
      routing:
        strategy: fallback_chain
"#
    )
}

fn chat_body() -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
}

#[test]
fn disallow_header_routes_only_to_compliant_provider() {
    let trainer = MockUpstream::start(chat_reply()).expect("trainer");
    let compliant = MockUpstream::start(chat_reply()).expect("compliant");
    let proxy = ProxyHarness::start_with_yaml(&config(&trainer.base_url(), &compliant.base_url()))
        .expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat_body(),
            &[("x-sbproxy-disallow-prompt-training", "true")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !compliant.captured().is_empty(),
        "the compliant provider must receive the request"
    );
    assert!(
        trainer.captured().is_empty(),
        "the training-eligible provider must be skipped under disallow_prompt_training"
    );
}

#[test]
fn without_header_normal_routing_prefers_trainer() {
    let trainer = MockUpstream::start(chat_reply()).expect("trainer");
    let compliant = MockUpstream::start(chat_reply()).expect("compliant");
    let proxy = ProxyHarness::start_with_yaml(&config(&trainer.base_url(), &compliant.base_url()))
        .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat_body(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !trainer.captured().is_empty(),
        "normal routing should hit the priority-0 provider"
    );
}

#[test]
fn disallow_with_no_compliant_provider_fails_closed() {
    // Both providers are training-eligible (neither no_prompt_training).
    let a = MockUpstream::start(chat_reply()).expect("a");
    let b = MockUpstream::start(chat_reply()).expect("b");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: a
          provider_type: openai
          api_key: "k"
          base_url: "{}"
          allow_private_base_url: true
          models: [gpt-4o]
        - name: b
          provider_type: openai
          api_key: "k"
          base_url: "{}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: fallback_chain
"#,
        a.base_url(),
        b.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat_body(),
            &[("x-sbproxy-disallow-prompt-training", "true")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 400,
        "must fail closed when no compliant provider"
    );
    assert!(
        a.captured().is_empty() && b.captured().is_empty(),
        "no upstream should be contacted"
    );
}
