//! End-to-end coverage for the RFC 8594 idempotency middleware
//! engaged on AI gateway origins (`action: ai_proxy`).
//!
//! PR C of the idempotency series. PR #136 wired the middleware on
//! general HTTP origins (`action: proxy`); PR #139 added per-request
//! and pool caps; this layer engages the same primitive on AI
//! gateway origins so a Stripe-style retry replay does not
//! double-bill the upstream provider.
//!
//! The engagement runs inside `handle_ai_proxy` after the request
//! body has been buffered (which the AI gateway already does to feed
//! the JSON parser / guardrails / model router). On a cache hit the
//! gateway writes the cached `(status, headers, body)` triple
//! directly to the client with `x-sbproxy-idempotency: HIT` and
//! never contacts the AI provider. On a body conflict the gateway
//! returns 409 `ledger.idempotency_conflict`. On a miss the gateway
//! forwards, then records the post-translation OpenAI-shape bytes
//! the client saw so retries replay byte-identical.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// OpenAI-shaped chat completion reply. Carries a `usage` block so
/// the AI gateway's budget / billing path stays happy; the body
/// itself is what the idempotency cache will record and replay.
fn chat_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-first",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "first response"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

/// AI proxy config carrying an `idempotency:` block pinned to the
/// memory backend.
fn config_for(upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
    idempotency:
      enabled: true
      header_name: Idempotency-Key
      ttl_secs: 60
      methods: [POST, PUT, PATCH]
      backend: memory
"#
    )
}

#[test]
fn ai_second_call_with_same_key_replays_cached_response() {
    let upstream = MockUpstream::start(chat_reply()).expect("start mock provider");
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    });

    // First call: miss, forwarded upstream, response captured.
    let first = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &body,
            &[("Idempotency-Key", "ai-key-1")],
        )
        .expect("first");
    assert_eq!(first.status, 200);
    assert!(
        !first.headers.contains_key("x-sbproxy-idempotency"),
        "first request must not carry HIT marker"
    );
    let first_body = first.json().expect("decode first body");
    assert_eq!(first_body["id"], "chatcmpl-first");
    assert_eq!(
        upstream.captured().len(),
        1,
        "first request reaches the provider"
    );

    // Second call: same key + body. Replay from cache without
    // touching the provider so the AI customer is not double-billed
    // on a Stripe-style retry.
    let second = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &body,
            &[("Idempotency-Key", "ai-key-1")],
        )
        .expect("second");
    assert_eq!(second.status, 200);
    assert_eq!(
        second
            .headers
            .get("x-sbproxy-idempotency")
            .map(|s| s.as_str()),
        Some("HIT"),
        "replay must stamp the HIT marker so logs distinguish it"
    );
    let second_body = second.json().expect("decode second body");
    assert_eq!(
        second_body["id"], "chatcmpl-first",
        "replay must serve the cached body verbatim"
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "cache hit must NOT contact the AI provider; otherwise the customer is double-billed"
    );
}

#[test]
fn ai_different_body_with_same_key_returns_409_conflict() {
    let upstream = MockUpstream::start(chat_reply()).expect("start mock provider");
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    // Prime the cache with body A.
    let first = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "hello world"}]
            }),
            &[("Idempotency-Key", "ai-key-2")],
        )
        .expect("first");
    assert_eq!(first.status, 200);

    // Retry with the same key but a DIFFERENT body: 409 conflict
    // per RFC 8594, body `ledger.idempotency_conflict`.
    let conflict = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &json!({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "goodbye"}]
            }),
            &[("Idempotency-Key", "ai-key-2")],
        )
        .expect("conflict");
    assert_eq!(conflict.status, 409);
    let body = conflict.json().expect("decode conflict body");
    assert_eq!(body["error"], "ledger.idempotency_conflict");
    // Conflict path also must not contact the upstream a second time.
    assert_eq!(
        upstream.captured().len(),
        1,
        "conflict response must NOT contact the AI provider"
    );
}

#[test]
fn ai_request_without_idempotency_key_passes_through() {
    let upstream = MockUpstream::start(chat_reply()).expect("start mock provider");
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "no key"}]
    });

    let r1 = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("first");
    assert_eq!(r1.status, 200);
    assert!(
        !r1.headers.contains_key("x-sbproxy-idempotency"),
        "no key = no replay or skip marker"
    );

    let r2 = proxy
        .post_json("/v1/chat/completions", "ai.localhost", &body, &[])
        .expect("second");
    assert_eq!(r2.status, 200);
    assert!(
        !r2.headers.contains_key("x-sbproxy-idempotency"),
        "second header-less request also bypasses the cache"
    );
    assert_eq!(
        upstream.captured().len(),
        2,
        "header-less requests must bypass the cache entirely"
    );
}

#[test]
fn ai_oversize_request_skips_caching_and_marks_response() {
    // Tiny cap so a normal chat completion payload trips the limit.
    let upstream = MockUpstream::start(chat_reply()).expect("start mock provider");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: "stub-key"
          base_url: "{upstream}"
          allow_private_base_url: true
          models: [gpt-4o]
      routing:
        strategy: round_robin
    idempotency:
      enabled: true
      backend: memory
      max_request_body_bytes: 16
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "a-very-long-prompt-that-exceeds-16-bytes"}]
    });

    let resp = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &body,
            &[("Idempotency-Key", "ai-key-oversize")],
        )
        .expect("oversize");
    assert_eq!(
        resp.status, 200,
        "oversize request must still succeed (graceful degradation)"
    );
    assert_eq!(
        resp.headers
            .get("x-sbproxy-idempotency")
            .map(|s| s.as_str()),
        Some("SKIPPED-OVERSIZE-REQUEST"),
        "oversize body must stamp the skip marker"
    );

    // Retry with the same key + body. Since the first request was
    // not cached (oversize), the retry also reaches the upstream.
    let _ = proxy
        .post_json(
            "/v1/chat/completions",
            "ai.localhost",
            &body,
            &[("Idempotency-Key", "ai-key-oversize")],
        )
        .expect("retry");
    assert_eq!(
        upstream.captured().len(),
        2,
        "oversize requests must NOT be cached; both calls reach the provider"
    );
}
