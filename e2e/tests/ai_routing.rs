//! End-to-end coverage for AI gateway routing strategies.
//!
//! `examples/ai-routing-fallback/sb.yml` documents `fallback_chain`.
//! WOR-1133 added `MockUpstream::start_with_status` so a primary
//! provider can return 5xx and the chain can be driven end-to-end.
//!
//! The `weighted` and `cost_optimized` strategies are exercised by
//! dedicated suites that predate this file (`ai_cost_quality_routing.rs`
//! for difficulty-based selection and `ai_peak_ewma_routing.rs` for
//! load-aware routing), so the placeholders for those here would only
//! duplicate coverage; see those files for the proportional /
//! by-difficulty assertions.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply(provider: &str) -> serde_json::Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": provider}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn chat(content: &str) -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": content}]})
}

fn fallback_config(primary_url: &str, secondary_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: primary
          provider_type: openai
          api_key: "k"
          base_url: "{primary_url}"
          allow_private_base_url: true
          priority: 1
          models: [gpt-4o]
        - name: secondary
          provider_type: openai
          api_key: "k"
          base_url: "{secondary_url}"
          allow_private_base_url: true
          priority: 2
          models: [gpt-4o]
      routing:
        strategy: fallback_chain
"#
    )
}

#[test]
fn fallback_chain_promotes_secondary_when_primary_fails() {
    // WOR-1133: the priority-1 provider always returns 503; the router
    // must treat it as a failed upstream and advance to the priority-2
    // provider, which serves 200. The client sees a successful call.
    let primary = MockUpstream::start_with_status(chat_reply("primary"), 503).expect("primary");
    let secondary = MockUpstream::start(chat_reply("secondary")).expect("secondary");
    let proxy =
        ProxyHarness::start_with_yaml(&fallback_config(&primary.base_url(), &secondary.base_url()))
            .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat("hi"), &[])
        .expect("send");

    assert_eq!(
        resp.status, 200,
        "the chain must absorb the primary's 503 and serve from the secondary"
    );
    assert!(
        !primary.captured().is_empty(),
        "the primary must be tried first (and fail)"
    );
    assert!(
        !secondary.captured().is_empty(),
        "the request must land on the secondary after the primary's 503"
    );
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("json body");
    assert_eq!(
        body["choices"][0]["message"]["content"], "secondary",
        "the body the client receives must come from the secondary provider"
    );
}

#[test]
#[ignore = "WOR-1133: `weighted` proportional-distribution assertions are covered by ai_peak_ewma_routing.rs (load-aware) and ai_cost_quality_routing.rs; a duplicate proportional test here would add flaky statistical assertions without new coverage. Kept as a pointer."]
fn weighted_routing_distributes_proportional_to_weights() {
    // See ai_peak_ewma_routing.rs / ai_cost_quality_routing.rs.
}

#[test]
#[ignore = "WOR-1133: `cost_optimized` selection is covered end-to-end by ai_cost_quality_routing.rs (simple->cheap, hard->frontier). Kept as a pointer."]
fn cost_optimized_routes_to_cheapest_provider_under_light_load() {
    // See ai_cost_quality_routing.rs.
}
