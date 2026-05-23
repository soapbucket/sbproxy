//! WOR-752: end-to-end guard for the request-path audit contract.
//!
//! The contract: for a translated provider format (Anthropic, Google),
//! an AI surface is either translated or the gateway returns a clear
//! 4xx/5xx at the gateway. It must never forward an untranslatable path
//! verbatim to an upstream that does not expose it (the #240 / Finding A
//! class, where the client gets a confusing upstream 404).
//!
//! These cases assert the gateway's own response, so the 501 cases do
//! not depend on the mock upstream being hit at all (the gateway rejects
//! before forwarding). The positive control proves a supported surface
//! is still forwarded, so the guard is not just blanket-rejecting.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

// Single-provider ai_proxy origin for `provider_name`, pointed at the
// loopback mock (opt-in past the WOR-603 SSRF guard).
fn config_for(provider_name: &str, host: &str, upstream_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "{host}":
    action:
      type: ai_proxy
      providers:
        - name: {provider_name}
          api_key: "stub-key"
          base_url: "{upstream_base}"
          allow_private_base_url: true
      routing:
        strategy: round_robin
"#
    )
}

// A translated-format provider must 501 a surface it has no translator
// for, rather than forward the path verbatim. (WOR-752 Finding A.)
#[test]
fn gemini_embeddings_returns_501_not_verbatim_forward() {
    let upstream = MockUpstream::start(json!({"unused": true})).expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "gemini",
        "gemini.localhost",
        &upstream.base_url(),
    ))
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/v1/embeddings",
            "gemini.localhost",
            &json!({"model": "text-embedding-004", "input": "hi"}),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 501,
        "gemini has no embeddings translator, so the gateway must 501; got {}",
        resp.status
    );
    // The gateway rejected before forwarding: the upstream saw nothing.
    assert!(
        upstream.captured().is_empty(),
        "a 501'd surface must not reach the upstream"
    );
}

#[test]
fn gemini_audio_speech_returns_501() {
    let upstream = MockUpstream::start(json!({"unused": true})).expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "gemini",
        "gemini.localhost",
        &upstream.base_url(),
    ))
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/v1/audio/speech",
            "gemini.localhost",
            &json!({"model": "tts", "input": "hi", "voice": "alloy"}),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 501,
        "gemini audio/speech must 501; got {}",
        resp.status
    );
    assert!(upstream.captured().is_empty());
}

// Anthropic also 501s embeddings (already correct; regression guard).
#[test]
fn anthropic_embeddings_returns_501() {
    let upstream = MockUpstream::start(json!({"unused": true})).expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "anthropic",
        "claude.localhost",
        &upstream.base_url(),
    ))
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/v1/embeddings",
            "claude.localhost",
            &json!({"model": "claude", "input": "hi"}),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 501,
        "anthropic embeddings must 501; got {}",
        resp.status
    );
    assert!(upstream.captured().is_empty());
}

// Positive control: an OpenAI-format provider DOES forward a supported
// surface (so the contract is not blanket-rejecting). The OpenAI wire
// format is a passthrough, so /v1/embeddings reaches the upstream as-is.
#[test]
fn openai_embeddings_is_forwarded_to_upstream() {
    let upstream = MockUpstream::start(json!({
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
        "model": "text-embedding-3-small",
        "usage": {"prompt_tokens": 1, "total_tokens": 1}
    }))
    .expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "openai",
        "openai.localhost",
        &upstream.base_url(),
    ))
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/v1/embeddings",
            "openai.localhost",
            &json!({"model": "text-embedding-3-small", "input": "hi"}),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 200,
        "openai embeddings should be forwarded; got {}",
        resp.status
    );
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "openai embeddings must reach the upstream"
    );
    assert_eq!(
        captured[0].path, "/v1/embeddings",
        "OpenAI-format embeddings pass through unchanged"
    );
}
