//! peak_ewma routing (WOR-798).
//!
//! Power-of-Two-Choices latency-aware LB. Because the per-origin router
//! is now persistent (its per-provider latency state survives across
//! requests) and the dispatch records each upstream's latency, peak_ewma
//! balances traffic across providers over a series of requests. The
//! latency-selection logic itself is unit-tested in
//! `sbproxy-ai::routing`; this e2e proves the strategy is selectable, the
//! persistent router works across requests, and traffic spreads.

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
        strategy: peak_ewma
"#
    )
}

#[test]
fn peak_ewma_distributes_across_providers() {
    let a = MockUpstream::start(chat_reply()).expect("a");
    let b = MockUpstream::start(chat_reply()).expect("b");
    let proxy =
        ProxyHarness::start_with_yaml(&config(&a.base_url(), &b.base_url())).expect("proxy");

    for _ in 0..6 {
        let resp = proxy
            .post_json(
                "/v1/chat/completions",
                "ai.localhost",
                &json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
                &[],
            )
            .expect("send");
        assert_eq!(resp.status, 200);
    }

    // P2C + live-latency balancing, riding the persistent per-origin
    // router, spreads traffic across both providers: once one has a
    // recorded latency, the still-unmeasured (latency 0) peer is
    // preferred on the next pick, so both receive requests.
    let a_hits = a.captured().len();
    let b_hits = b.captured().len();
    assert!(
        a_hits > 0 && b_hits > 0,
        "peak_ewma should distribute across both providers (a={a_hits}, b={b_hits})"
    );
}
