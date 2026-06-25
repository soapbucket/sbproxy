//! Hedged / raced dispatch (WOR-1545).
//!
//! The `race` routing strategy fans a single request out to every eligible
//! provider concurrently and keeps the first 2xx response, dropping the
//! losers. The fan-out itself is the behavior to prove: under `race` a
//! single request reaches every provider (unlike a sequential strategy,
//! which dispatches to one and only fails over on error). The first-2xx
//! preference is proven by racing a 500 against a 200 and asserting the
//! client still sees the 200.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply(tag: &str) -> serde_json::Value {
    json!({
        "id": format!("chatcmpl-{tag}"),
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn config(a_url: &str, b_url: &str) -> String {
    format!(
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
          base_url: "{a_url}"
          allow_private_base_url: true
          models: [gpt-4o]
        - name: b
          provider_type: openai
          api_key: "k"
          base_url: "{b_url}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: race
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
fn race_fans_out_to_every_provider() {
    let a = MockUpstream::start(chat_reply("a")).expect("a");
    let b = MockUpstream::start(chat_reply("b")).expect("b");
    let proxy =
        ProxyHarness::start_with_yaml(&config(&a.base_url(), &b.base_url())).expect("proxy");

    // A single request, served 200.
    assert_eq!(send(&proxy), 200);

    // Under `race` that one request fans out to both providers, so both
    // mock upstreams observed it. A sequential strategy would have hit only
    // one provider on a successful request.
    let a_hits = a.captured().len();
    let b_hits = b.captured().len();
    assert!(
        a_hits != 0 && b_hits != 0,
        "race should fan out to both providers on one request (a={a_hits}, b={b_hits})"
    );
}

#[test]
fn race_keeps_first_2xx_over_an_error() {
    // Provider `a` always errors; `b` succeeds. The raced dispatch must
    // keep b's 200 rather than surface a's 500.
    let a = MockUpstream::start_with_status(json!({"error": "boom"}), 500).expect("a");
    let b = MockUpstream::start(chat_reply("b")).expect("b");
    let proxy =
        ProxyHarness::start_with_yaml(&config(&a.base_url(), &b.base_url())).expect("proxy");

    assert_eq!(send(&proxy), 200, "the 2xx racer wins over the 5xx racer");
    assert!(
        !a.captured().is_empty() && !b.captured().is_empty(),
        "both providers were raced"
    );
}
