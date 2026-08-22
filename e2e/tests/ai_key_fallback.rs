//! Tenant provider-key failure fallback (WOR-2655).
//!
//! When an AI provider refuses the request with a `401` or `403`, that is a
//! statement about the credential rather than about the provider. Before this
//! feature the refusal was terminal: it is not retryable, it opens no
//! availability failover, and it reached the caller verbatim. An entry that
//! names an operator-held `fallback_credential_id` now retries the same
//! provider once on that credential instead.
//!
//! Every test here reads the credential the upstream actually received, not
//! only the status the client saw, because "the request succeeded" and "the
//! request succeeded on the key I meant" are different claims.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const TENANT_KEY: &str = "sk-tenant-key-acme";
const HOUSE_KEY: &str = "sk-house-key-operator";

fn chat_reply() -> serde_json::Value {
    json!({
        "id": "chatcmpl-fallback",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

fn rejected() -> serde_json::Value {
    json!({
        "error": {
            "message": "Incorrect API key provided.",
            "type": "invalid_request_error",
            "code": "invalid_api_key"
        }
    })
}

/// One origin taking the default posture with a fallback credential named.
/// `tag` keys the embedded store path, because two harnesses in one test
/// binary must not share a redb file.
fn config(tag: &str, upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  key_management:
    enabled: true
    store:
      backend: embedded
      path: /tmp/sbproxy-e2e-key-fallback-{tag}.redb
    crypto:
      pepper: e2e-pepper-value-not-a-real-secret
      master_key: e2e-master-value-not-a-real-secret
    seed:
      credentials:
        - id: house-openai
          name: house openai account
          provider: openai
          secret: {HOUSE_KEY}
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai-acme
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{upstream_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          fallback_credential_id: house-openai
"#
    )
}

/// The same origin with no key plane at all, which is the deployment where
/// the named credential can never resolve.
fn config_without_a_key_plane(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai-acme
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{upstream_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          fallback_credential_id: house-openai
"#
    )
}

/// One origin per posture, sharing one seeded operator credential. The two
/// entries differ in exactly the key under test.
fn two_posture_config(fallback_url: &str, fail_closed_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  tenants:
    - id: acme
    - id: globex
  key_management:
    enabled: true
    store:
      backend: embedded
      path: /tmp/sbproxy-e2e-key-fallback-postures.redb
    crypto:
      pepper: e2e-pepper-value-not-a-real-secret
      master_key: e2e-master-value-not-a-real-secret
    seed:
      credentials:
        - id: house-openai
          name: house openai account
          provider: openai
          secret: {HOUSE_KEY}
origins:
  "acme.local":
    tenant_id: acme
    action:
      type: ai_proxy
      providers:
        - name: openai-acme
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{fallback_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          fallback_credential_id: house-openai
  "globex.local":
    tenant_id: globex
    action:
      type: ai_proxy
      providers:
        - name: openai-globex
          provider_type: openai
          api_key: {TENANT_KEY}
          base_url: "{fail_closed_url}"
          allow_private_base_url: true
          models: [gpt-4o]
          on_key_failure: fail_closed
"#
    )
}

fn send_to(proxy: &ProxyHarness, host: &str) -> u16 {
    proxy
        .post_json(
            "/v1/chat/completions",
            host,
            &json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}),
            &[],
        )
        .expect("send")
        .status
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

/// The credential each upstream attempt actually presented, in order.
/// OpenAI's wire shape is `authorization: Bearer <key>`, and reading it back
/// off the captured request is what proves `auth_header()` still owns the
/// header name and the scheme after the swap.
fn presented_keys(upstream: &MockUpstream) -> Vec<String> {
    upstream
        .captured()
        .into_iter()
        .map(|request| {
            request
                .headers
                .get("authorization")
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

/// The headline. Red before the change: the `401` was relayed to the client
/// verbatim from the terminal `last_resp = Some(resp)` in the dispatch retry
/// loop, and the upstream saw exactly one request.
#[test]
fn tenant_key_401_is_served_on_the_fallback_credential() {
    let upstream = MockUpstream::start_sequence(vec![(401, rejected()), (200, chat_reply())])
        .expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config("served", &upstream.base_url())).expect("proxy");

    assert_eq!(
        send(&proxy),
        200,
        "the operator's credential answers where the tenant's was refused"
    );
    assert_eq!(
        presented_keys(&upstream),
        vec![
            format!("Bearer {TENANT_KEY}"),
            format!("Bearer {HOUSE_KEY}")
        ],
        "the entry's own key is tried first, then the operator's, both under \
         the vendor's own header and scheme"
    );
}

/// The explicit opt-out, written as a differential rather than as its own
/// assertion, because `fail_closed` is *defined* as the behavior this feature
/// changed away from: on its own it is green before the change too, and a test
/// that passes either way is not evidence. Both postures run against one
/// fixture here, so the claim under test is that they diverge. Red before the
/// change, on the `fallback` half.
#[test]
fn fail_closed_opts_out_where_fallback_opts_in() {
    // Two upstreams so each origin gets its own response sequence, and the
    // 200 sitting behind each 401 is reachable on the operator's key alone.
    let for_fallback = MockUpstream::start_sequence(vec![(401, rejected()), (200, chat_reply())])
        .expect("upstream");
    let for_fail_closed =
        MockUpstream::start_sequence(vec![(401, rejected()), (200, chat_reply())])
            .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&two_posture_config(
        &for_fallback.base_url(),
        &for_fail_closed.base_url(),
    ))
    .expect("proxy");

    assert_eq!(
        send_to(&proxy, "acme.local"),
        200,
        "`fallback` names an operator credential and is served on it"
    );
    assert_eq!(
        send_to(&proxy, "globex.local"),
        401,
        "`fail_closed` returns the provider's rejection: the tenant's own key \
         is the authorization boundary, and a revoked tenant must not keep \
         working on the house account"
    );
    assert_eq!(
        presented_keys(&for_fallback),
        vec![
            format!("Bearer {TENANT_KEY}"),
            format!("Bearer {HOUSE_KEY}")
        ]
    );
    assert_eq!(
        presented_keys(&for_fail_closed),
        vec![format!("Bearer {TENANT_KEY}")],
        "the house credential is never presented, so the 200 in that \
         sequence is never reached"
    );
}

/// The budget. Two refused credentials must terminate rather than queue a
/// third visit to the same provider.
#[test]
fn both_credentials_401_terminates() {
    let upstream = MockUpstream::start_sequence(vec![
        (401, rejected()),
        (401, rejected()),
        // A third response the loop must never reach. Reading it back as a
        // 200 would mean the visit budget failed open.
        (200, chat_reply()),
    ])
    .expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config("bothdead", &upstream.base_url())).expect("proxy");

    assert_eq!(send(&proxy), 401, "both credentials refused is terminal");
    assert_eq!(
        presented_keys(&upstream),
        vec![
            format!("Bearer {TENANT_KEY}"),
            format!("Bearer {HOUSE_KEY}")
        ],
        "exactly one fallback per request"
    );
}

/// The credential cannot resolve, so the provider's own rejection stands.
/// The warn names the credential id and never the material, the same rule
/// the bound-credential resolver in `proxy_http` follows.
#[test]
fn a_credential_that_cannot_resolve_returns_the_original_401() {
    let upstream = MockUpstream::start_sequence(vec![(401, rejected()), (200, chat_reply())])
        .expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_without_a_key_plane(&upstream.base_url()))
        .expect("proxy");

    assert_eq!(
        send(&proxy),
        401,
        "the caller gets the provider's truthful answer, not an invented 503"
    );
    assert_eq!(
        presented_keys(&upstream),
        vec![format!("Bearer {TENANT_KEY}")]
    );

    let logs = proxy.stderr_contents();
    assert!(
        logs.contains("house-openai"),
        "the operator has to be able to tell which credential failed: {logs}"
    );
    assert!(
        !logs.contains(HOUSE_KEY) && !logs.contains(TENANT_KEY),
        "no credential material may reach the log"
    );
}
