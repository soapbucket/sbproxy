//! Typed fallback triggers (WOR-2556).
//!
//! `context_window_fallbacks` reroutes a prompt whose pre-flight token
//! estimate overflows the primary model's context window to a provider
//! serving a larger-window model, before anything dispatches.
//! `content_policy_fallbacks` reroutes a content-policy refusal to the
//! trigger's own list rather than to whatever the generic chain had
//! queued next. Each list is aimed: configuring one trigger does not
//! change how the other class of failure is handled.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn chat_reply(id: &str) -> serde_json::Value {
    json!({
        "id": format!("chatcmpl-{id}"),
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn content_policy_refusal() -> serde_json::Value {
    json!({
        "error": {
            "message": "Your request was rejected by our safety system.",
            "type": "content_policy_violation",
            "code": "content_policy_violation"
        }
    })
}

/// A prompt comfortably over gpt-4's 8,192-token window and comfortably
/// under gpt-4-turbo's 128,000.
fn oversized_prompt() -> String {
    "lorem ipsum dolor sit amet ".repeat(3_000)
}

fn send_chat(proxy: &ProxyHarness, content: &str) -> u16 {
    proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &json!({"model": "gpt-4", "messages": [{"role": "user", "content": content}]}),
            &[],
        )
        .expect("send")
        .status
}

#[test]
fn oversized_prompt_reroutes_to_the_context_window_fallback() {
    // `small` serves gpt-4 (8,192-token window); `big` maps gpt-4 to
    // gpt-4-turbo (128,000). The reroute is pre-flight, so `small` must
    // see zero requests: the estimate, not a provider error, fires it.
    let small = MockUpstream::start(chat_reply("small")).expect("small");
    let big = MockUpstream::start(chat_reply("big")).expect("big");
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: small
          provider_type: openai
          api_key: "k"
          base_url: "{small_url}"
          allow_private_base_url: true
          priority: 1
          models: [gpt-4]
        - name: big
          provider_type: openai
          api_key: "k"
          base_url: "{big_url}"
          allow_private_base_url: true
          priority: 2
          models: [gpt-4]
          model_map:
            gpt-4: gpt-4-turbo
      routing:
        strategy: fallback_chain
      context_window_fallbacks: [big]
"#,
        small_url = small.base_url(),
        big_url = big.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&config).expect("proxy");

    assert_eq!(
        send_chat(&proxy, &oversized_prompt()),
        200,
        "the oversized prompt is served by the larger-window fallback"
    );
    assert!(
        small.captured().is_empty(),
        "the pre-flight estimate reroutes before the small-window provider is tried"
    );
    assert!(
        !big.captured().is_empty(),
        "the context_window_fallbacks provider takes the request"
    );

    // A prompt that fits stays on the primary.
    assert_eq!(send_chat(&proxy, "hi"), 200);
    assert!(
        !small.captured().is_empty(),
        "a fitting prompt is not rerouted"
    );
}

#[test]
fn content_policy_refusal_reroutes_to_the_typed_list_not_the_next_in_order() {
    // Generic order is strict(1) -> backup(2) -> permissive(3). The
    // typed list aims the refusal straight at `permissive`; `backup`
    // (the generic next) must never see the request.
    let strict = MockUpstream::start_with_status(content_policy_refusal(), 400).expect("strict");
    let backup = MockUpstream::start(chat_reply("backup")).expect("backup");
    let permissive = MockUpstream::start(chat_reply("permissive")).expect("permissive");
    let config = format!(
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
          models: [gpt-4]
        - name: backup
          provider_type: openai
          api_key: "k"
          base_url: "{backup_url}"
          allow_private_base_url: true
          priority: 2
          models: [gpt-4]
        - name: permissive
          provider_type: openai
          api_key: "k"
          base_url: "{permissive_url}"
          allow_private_base_url: true
          priority: 3
          models: [gpt-4]
      routing:
        strategy: fallback_chain
      content_policy_fallbacks: [permissive]
"#,
        strict_url = strict.base_url(),
        backup_url = backup.base_url(),
        permissive_url = permissive.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&config).expect("proxy");

    assert_eq!(
        send_chat(&proxy, "hi"),
        200,
        "the refusal reroutes to the typed list and succeeds there"
    );
    assert!(
        !strict.captured().is_empty(),
        "the strict provider was tried first"
    );
    assert!(
        backup.captured().is_empty(),
        "the typed list takes over: the generic next-in-order provider is skipped"
    );
    assert!(
        !permissive.captured().is_empty(),
        "the content_policy_fallbacks provider takes the request"
    );
}

#[test]
fn a_trigger_only_reroutes_its_own_failure_class() {
    // Only `context_window_fallbacks` is configured. A content-policy
    // refusal is not that trigger's class, so it is returned to the
    // caller unchanged and the fallback provider is never consulted.
    let strict = MockUpstream::start_with_status(content_policy_refusal(), 400).expect("strict");
    let big = MockUpstream::start(chat_reply("big")).expect("big");
    let config = format!(
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
          models: [gpt-4]
        - name: big
          provider_type: openai
          api_key: "k"
          base_url: "{big_url}"
          allow_private_base_url: true
          priority: 2
          models: [gpt-4]
          model_map:
            gpt-4: gpt-4-turbo
      routing:
        strategy: fallback_chain
      context_window_fallbacks: [big]
"#,
        strict_url = strict.base_url(),
        big_url = big.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&config).expect("proxy");

    assert_eq!(
        send_chat(&proxy, "hi"),
        400,
        "a content-policy refusal is not the context-window trigger's class"
    );
    assert!(
        big.captured().is_empty(),
        "the context-window list is not consulted for a content-policy refusal"
    );
}

#[test]
fn a_classified_failure_cools_the_provider_out_of_the_next_request() {
    // `cooldown_policy` is the provider-level half of the per-error-class
    // pair: `retry_policy` decides whether this request gets another
    // attempt, `cooldown_policy` decides whether the provider keeps
    // taking new ones. The classification feeding it has to run on every
    // failed attempt, including a `4xx` the retry policy itself consumes,
    // so this configures a typed fallback list alongside it: a
    // status-only recording that skipped the whole `4xx` range whenever a
    // fallback list was configured would leave `rate_limit: 60` doing
    // nothing at all.
    //
    // `primary` answers `429` forever. The first request fails over to
    // `backup`; the second must never reach `primary`, because a 60s
    // cooldown is holding it out of rotation.
    let primary = MockUpstream::start_with_status(
        json!({"error": {"message": "rate limited", "type": "rate_limit_error"}}),
        429,
    )
    .expect("primary");
    let backup = MockUpstream::start(chat_reply("backup")).expect("backup");
    let config = format!(
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
          models: [gpt-4]
        - name: backup
          provider_type: openai
          api_key: "k"
          base_url: "{backup_url}"
          allow_private_base_url: true
          priority: 2
          models: [gpt-4]
      routing:
        strategy: fallback_chain
      content_policy_fallbacks: [backup]
      resilience:
        retry_policy:
          rate_limit: 3
        cooldown_policy:
          rate_limit: 60
"#,
        primary_url = primary.base_url(),
        backup_url = backup.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&config).expect("proxy");

    assert_eq!(send_chat(&proxy, "hi"), 200, "the first request fails over");
    assert_eq!(
        primary.captured().len(),
        1,
        "the first request really reached the rate-limited provider"
    );

    assert_eq!(send_chat(&proxy, "hi"), 200, "the second request succeeds");
    assert_eq!(
        primary.captured().len(),
        1,
        "the rate-limit cooldown holds the provider out of the second request"
    );
    assert_eq!(
        backup.captured().len(),
        2,
        "both requests were answered by the provider still in rotation"
    );
}
