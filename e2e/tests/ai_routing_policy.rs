//! Operator-authored AI routing policy (WOR-2366).
//!
//! A CEL `ai_routing_policy` returns a routing plan (an ordered candidate
//! list). This e2e proves the dispatch seam the unit tests cannot: a plan
//! actually reaches the cascade executor and dispatches to the named
//! provider, and a plan naming a model the origin allowlist refuses is
//! blocked before dispatch (the per-key/origin model gate the plan must
//! not route around).

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

/// Two providers behind a round-robin default; a routing policy that plans
/// to `frontier`, and an optional `extra` action block (allowlist rules).
fn config(cheap_url: &str, frontier_url: &str, plan_model: &str, extra: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      routing: round_robin
{extra}      providers:
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
      ai_routing_policy:
        expression: |
          {{"candidates": [{{"provider_id": "frontier", "model": "{plan_model}"}}], "reason": "plan to frontier"}}
"#
    )
}

fn chat() -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
}

fn chat_with(content: &str) -> serde_json::Value {
    json!({"model": "gpt-4o", "messages": [{"role": "user", "content": content}]})
}

/// A routing policy that keys on `ai.prompt.difficulty`: a hard prompt plans
/// to `frontier`, an easy one declines to the `round_robin` default (which,
/// on a fresh proxy's first request, deterministically picks `cheap`, the
/// first provider). This is the operator-authored `cost_quality`.
fn difficulty_config(cheap_url: &str, frontier_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      routing: round_robin
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
      ai_routing_policy:
        expression: |
          ai.prompt.difficulty > 0.3
            ? {{"candidates": [{{"provider_id": "frontier", "model": "gpt-4o"}}], "reason": "hard prompt", "reason_code": "difficulty"}}
            : null
        reason_codes: [difficulty]
"#
    )
}

#[test]
fn a_routing_plan_dispatches_to_the_named_provider() {
    // The default strategy is round_robin, so without the plan the request
    // could land on either provider. The plan names `frontier`, so frontier
    // must serve and cheap must be untouched: proof the plan reached the
    // cascade executor rather than being ignored.
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy = ProxyHarness::start_with_yaml(&config(
        &cheap.base_url(),
        &frontier.base_url(),
        "gpt-4o",
        "",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !frontier.captured().is_empty(),
        "the plan must dispatch to the named provider"
    );
    assert!(
        cheap.captured().is_empty(),
        "the provider the plan did not name must be untouched"
    );
}

#[test]
fn a_plan_naming_a_blocked_model_is_refused_before_dispatch() {
    // The origin blocks `premium`. The request asks for the allowed
    // `gpt-4o` (so it passes the upstream model gate), but the plan routes
    // to `premium`. The plan must not route around the allowlist: the
    // request is refused with 403 and neither provider is called.
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy = ProxyHarness::start_with_yaml(&config(
        &cheap.base_url(),
        &frontier.base_url(),
        "premium",
        "      blocked_models: [premium]\n",
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat(), &[])
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "a plan naming a blocked model must be refused"
    );
    assert!(
        frontier.captured().is_empty() && cheap.captured().is_empty(),
        "no provider may be called when the plan is refused"
    );
}

#[test]
fn prompt_difficulty_routes_hard_prompts_to_frontier() {
    // A hard prompt (code fence + step-by-step reasoning) scores well above
    // 0.3, so the policy plans to `frontier`. Proof that the new
    // `ai.prompt.difficulty` signal reaches the routing view and drives the
    // plan end to end: without it the difficulty reads zero and the policy
    // would always decline.
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy =
        ProxyHarness::start_with_yaml(&difficulty_config(&cheap.base_url(), &frontier.base_url()))
            .expect("proxy");

    let hard =
        chat_with("Write a function and analyze it step by step:\n```\ndef f():\n    pass\n```");
    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &hard, &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !frontier.captured().is_empty(),
        "a hard prompt must plan to the frontier provider"
    );
    assert!(
        cheap.captured().is_empty(),
        "the cheap provider must be untouched for a hard prompt"
    );
}

#[test]
fn prompt_difficulty_lets_easy_prompts_fall_through() {
    // A trivial prompt scores near zero, below the 0.3 threshold, so the
    // policy declines and the configured `round_robin` default runs. On a
    // fresh proxy the first request lands on the first provider (`cheap`).
    // Proof the signal does not spuriously fire the plan on easy prompts.
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy =
        ProxyHarness::start_with_yaml(&difficulty_config(&cheap.base_url(), &frontier.base_url()))
            .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !cheap.captured().is_empty(),
        "an easy prompt must fall through to the round_robin default (cheap)"
    );
    assert!(
        frontier.captured().is_empty(),
        "the frontier provider must be untouched when the policy declines"
    );
}

/// A routing policy that reads `ai.providers`: plan to `frontier` when it is
/// present, healthy, and its circuit is closed. On a fresh proxy every provider
/// is healthy (no probe = unknown = healthy) with a closed circuit, so this
/// deterministically fires. If `ai.providers` were empty (wiring broken) the
/// comprehension would find nobody, the policy would decline, and round_robin
/// would pick `cheap` (index 0) instead.
fn provider_state_config(cheap_url: &str, frontier_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      routing: round_robin
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
      ai_routing_policy:
        expression: |
          ai.providers.exists(x, x.name == "frontier" && x.healthy && x.circuit == "closed")
            ? {{"candidates": [{{"provider_id": "frontier", "model": "gpt-4o"}}], "reason": "frontier healthy", "reason_code": "provider_state"}}
            : null
        reason_codes: [provider_state]
"#
    )
}

#[test]
fn provider_state_is_visible_to_the_routing_policy() {
    // Proves the live `ai.providers` view reaches the routing policy: the
    // comprehension reads each provider's name, health, and circuit state, and
    // plans to the healthy frontier. Without the wiring the list is empty, the
    // policy declines, and cheap (round_robin index 0) would serve instead.
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy = ProxyHarness::start_with_yaml(&provider_state_config(
        &cheap.base_url(),
        &frontier.base_url(),
    ))
    .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !frontier.captured().is_empty(),
        "the policy must read ai.providers and plan to the healthy frontier provider"
    );
    assert!(
        cheap.captured().is_empty(),
        "cheap must be untouched: the plan named frontier"
    );
}

/// A routing policy that keys on `ai.prompt.fingerprint`: plan to `frontier`
/// whenever the fingerprint is present. The fingerprint is salted per process,
/// so the test cannot assert a fixed value, only that it reaches the view: a
/// real request produces a non-empty `pf_...`, so the plan fires; if the wiring
/// were missing the fingerprint would be empty, the policy would decline, and
/// round_robin would serve `cheap` (index 0).
fn fingerprint_config(cheap_url: &str, frontier_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      routing: round_robin
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
      ai_routing_policy:
        expression: |
          ai.prompt.fingerprint != ""
            ? {{"candidates": [{{"provider_id": "frontier", "model": "gpt-4o"}}], "reason": "fingerprinted", "reason_code": "fingerprint"}}
            : null
        reason_codes: [fingerprint]
"#
    )
}

#[test]
fn prompt_fingerprint_is_visible_to_the_routing_policy() {
    // Proves the salted prompt fingerprint reaches the routing view: a real
    // request produces a non-empty `pf_...`, so the policy plans to frontier.
    // Without the wiring the fingerprint is empty, the policy declines, and
    // cheap (round_robin index 0) serves.
    let cheap = MockUpstream::start(chat_reply()).expect("cheap");
    let frontier = MockUpstream::start(chat_reply()).expect("frontier");
    let proxy =
        ProxyHarness::start_with_yaml(&fingerprint_config(&cheap.base_url(), &frontier.base_url()))
            .expect("proxy");

    let resp = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &chat(), &[])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !frontier.captured().is_empty(),
        "a fingerprinted request must plan to frontier"
    );
    assert!(
        cheap.captured().is_empty(),
        "cheap must be untouched when the fingerprint drives the plan"
    );
}
