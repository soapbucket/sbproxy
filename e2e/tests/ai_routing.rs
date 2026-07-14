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

fn scored_chat_reply(provider: &str, score: f64) -> serde_json::Value {
    let mut reply = chat_reply(provider);
    reply["confidence_score"] = serde_json::json!(score);
    reply
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

fn restricted_fallback_config(primary_url: &str, secondary_url: &str) -> String {
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
    credentials:
      - name: primary-only
        type: ai_provider
        provider: primary
        key: "sk-primary-only"
        policies:
          - type: rate_limit
            rpm: 1
"#
    )
}

fn restricted_discovery_config(primary_url: &str, secondary_url: &str) -> String {
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
          models: [allowed-model, primary-hidden]
        - name: secondary
          provider_type: openai
          api_key: "k"
          base_url: "{secondary_url}"
          allow_private_base_url: true
          models: [secondary-hidden]
    credentials:
      - name: primary-model
        type: ai_provider
        provider: primary
        key: "sk-primary-model"
        models:
          allow: [allowed-model]
        policies:
          - type: rate_limit
            rpm: 1
"#
    )
}

fn restricted_cascade_config(primary_url: &str, secondary_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      routing:
        strategy: cascade
        tiers:
          - provider_id: primary
            model: gpt-4o
            quality_threshold: 0.8
          - provider_id: secondary
            model: gpt-4o
            quality_threshold: 0.8
      providers:
        - name: primary
          provider_type: openai
          api_key: "k"
          base_url: "{primary_url}"
          allow_private_base_url: true
          models: [gpt-4o]
        - name: secondary
          provider_type: openai
          api_key: "k"
          base_url: "{secondary_url}"
          allow_private_base_url: true
          models: [gpt-4o]
    credentials:
      - name: primary-only
        type: ai_provider
        provider: primary
        key: "sk-primary-only"
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
fn fallback_chain_never_crosses_the_credential_provider_allowlist() {
    let primary = MockUpstream::start_with_status(chat_reply("primary"), 503).expect("primary");
    let secondary = MockUpstream::start(chat_reply("secondary")).expect("secondary");
    let proxy = ProxyHarness::start_with_yaml(&restricted_fallback_config(
        &primary.base_url(),
        &secondary.base_url(),
    ))
    .expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("restricted"),
            &[("authorization", "Bearer sk-primary-only")],
        )
        .expect("send");

    assert!(
        !(200..300).contains(&resp.status),
        "the allowed provider's failure must not be hidden by a denied provider"
    );
    assert!(
        !primary.captured().is_empty(),
        "the allowed provider is tried"
    );
    assert!(
        secondary.captured().is_empty(),
        "fallback must not send a prompt to a provider denied by the credential"
    );
}

#[test]
fn multipart_fallback_never_crosses_the_credential_provider_allowlist() {
    let primary = MockUpstream::start_with_status(chat_reply("primary"), 503).expect("primary");
    let secondary = MockUpstream::start(chat_reply("secondary")).expect("secondary");
    let proxy = ProxyHarness::start_with_yaml(&restricted_fallback_config(
        &primary.base_url(),
        &secondary.base_url(),
    ))
    .expect("proxy");
    let boundary = "sbproxy-provider-policy";
    let multipart = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ngpt-4o\r\n--{boundary}--\r\n"
    );
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(format!("{}/v1/chat/completions", proxy.base_url()))
        .header("host", "ai.localhost")
        .header("authorization", "Bearer sk-primary-only")
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(multipart.clone())
        .send()
        .expect("multipart request");

    assert!(!response.status().is_success());
    assert!(
        !primary.captured().is_empty(),
        "the allowed provider is tried"
    );
    assert!(
        secondary.captured().is_empty(),
        "multipart fallback must not reach a credential-denied provider"
    );

    let rate_limited = client
        .post(format!("{}/v1/chat/completions", proxy.base_url()))
        .header("host", "ai.localhost")
        .header("authorization", "Bearer sk-primary-only")
        .header(
            reqwest::header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(multipart)
        .send()
        .expect("second multipart request");
    assert_eq!(
        rate_limited.status().as_u16(),
        429,
        "multipart must apply the credential's common request governance"
    );
    assert_eq!(
        primary.captured().len(),
        1,
        "a credential-rate-limited multipart request must not reach upstream"
    );
}

#[test]
fn logical_model_discovery_applies_credential_provider_and_model_policy() {
    let primary = MockUpstream::start(chat_reply("primary")).expect("primary");
    let secondary = MockUpstream::start(chat_reply("secondary")).expect("secondary");
    let proxy = ProxyHarness::start_with_yaml(&restricted_discovery_config(
        &primary.base_url(),
        &secondary.base_url(),
    ))
    .expect("proxy");

    let response = proxy
        .get_with_headers(
            "/v1/models",
            "ai.localhost",
            &[("authorization", "Bearer sk-primary-model")],
        )
        .expect("models request");
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("models JSON");
    let ids = body["data"]
        .as_array()
        .expect("model data")
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["allowed-model"]);

    let rate_limited = proxy
        .get_with_headers(
            "/v1/models",
            "ai.localhost",
            &[("authorization", "Bearer sk-primary-model")],
        )
        .expect("second models request");
    assert_eq!(
        rate_limited.status, 429,
        "local model discovery must apply the credential's common request governance"
    );
}

#[test]
fn confidence_cascade_never_crosses_the_credential_provider_allowlist() {
    let primary = MockUpstream::start(scored_chat_reply("primary", 0.2)).expect("primary");
    let secondary = MockUpstream::start(scored_chat_reply("secondary", 0.9)).expect("secondary");
    let proxy = ProxyHarness::start_with_yaml(&restricted_cascade_config(
        &primary.base_url(),
        &secondary.base_url(),
    ))
    .expect("proxy");

    let response = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat("restricted cascade"),
            &[("authorization", "Bearer sk-primary-only")],
        )
        .expect("send");
    assert_eq!(response.status, 200);
    assert!(!primary.captured().is_empty(), "the allowed tier is tried");
    assert!(
        secondary.captured().is_empty(),
        "confidence cascade must not reach a credential-denied provider"
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
