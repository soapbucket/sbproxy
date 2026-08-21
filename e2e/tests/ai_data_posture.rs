//! Provider eligibility by data-handling posture (the ZDR /
//! data-retention allow-deny).
//!
//! An origin's `data_posture:` block, or the per-request
//! `x-sbproxy-require-zdr` / `x-sbproxy-disallow-data-collection`
//! headers, constrain the routing candidate set to providers whose
//! declared posture satisfies the constraint, before any routing
//! strategy runs. A request left with no eligible provider fails
//! closed with an error naming the constraint and the excluded
//! providers; an unconstrained request routes exactly as before.

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

fn chat_body() -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
}

// Two providers with explicit posture declarations so the test is
// independent of the shipped catalog's per-vendor seeds: `retainer`
// (priority 0, retains data, no ZDR) is preferred by the fallback
// chain; `zdr` (priority 1) is only reached when the posture filter
// removes `retainer`. `origin_posture` is spliced in as-is.
fn config(retainer_url: &str, zdr_url: &str, origin_posture: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      {origin_posture}
      providers:
        - name: retainer
          provider_type: openai
          api_key: "k"
          base_url: "{retainer_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          priority: 0
          data_posture:
            retains_data: true
            zdr: false
        - name: zdr
          provider_type: openai
          api_key: "k"
          base_url: "{zdr_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          priority: 1
          data_posture:
            zdr: true
      routing:
        strategy: fallback_chain
"#
    )
}

#[test]
fn origin_require_zdr_routes_only_to_zdr_provider() {
    let retainer = MockUpstream::start(chat_reply()).expect("retainer");
    let zdr = MockUpstream::start(chat_reply()).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&config(
        &retainer.base_url(),
        &zdr.base_url(),
        "data_posture:\n        require_zdr: true",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat_body(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !zdr.captured().is_empty(),
        "the ZDR provider must receive the request"
    );
    assert!(
        retainer.captured().is_empty(),
        "a require_zdr origin must never reach a non-ZDR provider"
    );
}

#[test]
fn header_require_zdr_routes_only_to_zdr_provider() {
    let retainer = MockUpstream::start(chat_reply()).expect("retainer");
    let zdr = MockUpstream::start(chat_reply()).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&config(&retainer.base_url(), &zdr.base_url(), ""))
        .expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat_body(),
            &[("x-sbproxy-require-zdr", "true")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !zdr.captured().is_empty(),
        "the ZDR provider must receive the request"
    );
    assert!(
        retainer.captured().is_empty(),
        "a require_zdr request must never reach a non-ZDR provider"
    );
}

#[test]
fn disallow_data_collection_routes_only_to_non_retaining_provider() {
    let retainer = MockUpstream::start(chat_reply()).expect("retainer");
    let zdr = MockUpstream::start(chat_reply()).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&config(
        &retainer.base_url(),
        &zdr.base_url(),
        "data_posture:\n        allow_data_collection: false",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat_body(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !zdr.captured().is_empty(),
        "the non-retaining provider must receive the request"
    );
    assert!(
        retainer.captured().is_empty(),
        "allow_data_collection: false must never reach a retaining provider"
    );
}

#[test]
fn header_constraint_with_no_eligible_provider_fails_closed_naming_it() {
    // An origin whose own `data_posture:` block excludes every provider
    // is refused at config compile (see the handler's
    // `from_config_rejects_a_posture_that_excludes_every_provider`), so
    // the runtime fail-closed path is reached through the per-request
    // header, which no config-time check can see coming.
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
        - name: alpha
          provider_type: openai
          api_key: "k"
          base_url: "{}"
          allow_private_base_url: true
          models: [gpt-4o]
          data_posture:
            retains_data: true
            zdr: false
        - name: beta
          provider_type: openai
          api_key: "k"
          base_url: "{}"
          allow_private_base_url: true
          models: [gpt-4o]
          data_posture:
            retains_data: true
            zdr: false
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
            &[("x-sbproxy-require-zdr", "true")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "must fail closed when no provider satisfies the posture"
    );
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("no_posture_eligible_provider"),
        "refusal must be typed: {body}"
    );
    assert!(
        body.contains("require_zdr"),
        "refusal must name the constraint: {body}"
    );
    assert!(
        body.contains("alpha") && body.contains("beta"),
        "refusal must name the excluded providers: {body}"
    );
    assert!(
        a.captured().is_empty() && b.captured().is_empty(),
        "no upstream should be contacted"
    );
}

#[test]
fn unconstrained_requests_route_unchanged() {
    let retainer = MockUpstream::start(chat_reply()).expect("retainer");
    let zdr = MockUpstream::start(chat_reply()).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&config(&retainer.base_url(), &zdr.base_url(), ""))
        .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat_body(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !retainer.captured().is_empty(),
        "without a constraint the priority-0 provider serves the request"
    );
    assert!(
        zdr.captured().is_empty(),
        "no rerouting without a constraint"
    );
    let served: serde_json::Value = serde_json::from_slice(&resp.body).expect("json body");
    assert_eq!(
        served,
        chat_reply(),
        "an unconstrained response passes through unchanged"
    );
}

// --- The other doors into selection -------------------------------
//
// A gate keyed on the chat path alone would do nothing for an
// Anthropic-SDK caller: `/v1/messages` and `/v1/responses` are
// rewritten into the canonical chat body by the inbound shim and reach
// the same dispatch. And the cascade executor does not route over the
// candidate order at all: each tier names its own provider. Both are
// asserted here against the same two-provider fixture.

#[test]
fn messages_surface_is_gated_by_posture() {
    let retainer = MockUpstream::start(chat_reply()).expect("retainer");
    let zdr = MockUpstream::start(chat_reply()).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&config(
        &retainer.base_url(),
        &zdr.base_url(),
        "data_posture:\n        require_zdr: true",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/messages",
            "ai.localhost",
            &json!({
                "model": "gpt-4o",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "hi"}]
            }),
            &[],
        )
        .expect("send");
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    assert!(
        !zdr.captured().is_empty(),
        "/v1/messages must route to the ZDR provider"
    );
    assert!(
        retainer.captured().is_empty(),
        "/v1/messages must be gated by the posture filter, not only /v1/chat/completions"
    );
}

#[test]
fn responses_surface_is_gated_by_posture() {
    let retainer = MockUpstream::start(chat_reply()).expect("retainer");
    let zdr = MockUpstream::start(chat_reply()).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&config(
        &retainer.base_url(),
        &zdr.base_url(),
        "data_posture:\n        require_zdr: true",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/responses",
            "ai.localhost",
            &json!({"model": "gpt-4o", "input": "hi"}),
            &[],
        )
        .expect("send");
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    assert!(
        !zdr.captured().is_empty(),
        "/v1/responses must route to the ZDR provider"
    );
    assert!(
        retainer.captured().is_empty(),
        "/v1/responses must be gated by the posture filter, not only /v1/chat/completions"
    );
}

fn scored_reply(score: f64) -> serde_json::Value {
    let mut reply = chat_reply();
    reply["confidence_score"] = json!(score);
    reply
}

/// A cascade whose first tier names the retaining provider and whose
/// second names the ZDR one. The cascade executor dispatches tiers by
/// name, so a filter that only narrowed the candidate order would let
/// tier 1 reach the excluded upstream anyway.
fn cascade_config(retainer_url: &str, zdr_url: &str, origin_posture: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      {origin_posture}
      providers:
        - name: retainer
          provider_type: openai
          api_key: "k"
          base_url: "{retainer_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          data_posture:
            retains_data: true
            zdr: false
        - name: zdr
          provider_type: openai
          api_key: "k"
          base_url: "{zdr_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          data_posture:
            zdr: true
      routing:
        strategy: cascade
        tiers:
          - provider_id: retainer
            model: gpt-4o
            quality_threshold: 0.5
          - provider_id: zdr
            model: gpt-4o
            quality_threshold: 0.5
"#
    )
}

#[test]
fn cascade_tiers_are_gated_by_posture() {
    let retainer = MockUpstream::start(scored_reply(0.9)).expect("retainer");
    let zdr = MockUpstream::start(scored_reply(0.9)).expect("zdr");
    let proxy = ProxyHarness::start_with_yaml(&cascade_config(
        &retainer.base_url(),
        &zdr.base_url(),
        "data_posture:\n        require_zdr: true",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat_body(), &[])
        .expect("send");
    assert_eq!(
        resp.status,
        200,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    assert!(
        !zdr.captured().is_empty(),
        "the eligible tier must serve the request"
    );
    assert!(
        retainer.captured().is_empty(),
        "a cascade tier naming an excluded provider must never be dispatched"
    );
}

#[test]
fn cascade_with_every_tier_excluded_fails_closed_naming_the_constraint() {
    // Both tiers name the retaining provider; the header tightens the
    // request so no tier is eligible. Without the tier partition this
    // is a bare 502 from an exhausted cascade, which tells an operator
    // nothing about why.
    let retainer = MockUpstream::start(scored_reply(0.9)).expect("retainer");
    let zdr = MockUpstream::start(scored_reply(0.9)).expect("zdr");
    let yaml = cascade_config(&retainer.base_url(), &zdr.base_url(), "").replace(
        "          - provider_id: zdr\n",
        "          - provider_id: retainer\n",
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("proxy");

    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &chat_body(),
            &[("x-sbproxy-require-zdr", "true")],
        )
        .expect("send");
    assert_eq!(
        resp.status,
        403,
        "body: {}",
        String::from_utf8_lossy(&resp.body)
    );
    let body = String::from_utf8_lossy(&resp.body);
    assert!(
        body.contains("no_posture_eligible_provider") && body.contains("retainer"),
        "cascade refusal must name the constraint and the excluded provider: {body}"
    );
    assert!(
        retainer.captured().is_empty() && zdr.captured().is_empty(),
        "no upstream should be contacted"
    );
}
