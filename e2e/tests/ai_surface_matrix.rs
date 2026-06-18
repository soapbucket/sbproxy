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

// A translated-format provider must translate a supported surface to the
// upstream's native endpoint, never forward the inbound path verbatim.
// WOR-1127: the Gemini embeddings translator (WOR-824) now handles
// `/v1/embeddings`, so the gateway returns 200 and forwards the translated
// Gemini-native request. This previously asserted 501 (WOR-752 Finding A),
// before the embeddings translator existed.
#[test]
fn gemini_embeddings_translated_not_verbatim_forward() {
    let upstream = MockUpstream::start(json!({
        "embedding": {"values": [0.25, -0.5, 0.75]}
    }))
    .expect("mock");
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
            &json!({
                "model": "text-embedding-004",
                "input": "hi",
                "dimensions": 3,
                "encoding_format": "float",
                "user": "end-user-1"
            }),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 200,
        "gemini embeddings are translated now; gateway returns 200; got {}",
        resp.status
    );
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "the translated embeddings request must reach the upstream"
    );
    let paths: Vec<String> = captured.iter().map(|c| c.path.clone()).collect();
    // The gateway must NOT forward the OpenAI-shaped `/v1/embeddings` path
    // verbatim; it translates to the Gemini native embeddings endpoint.
    assert!(
        paths.iter().all(|p| p != "/v1/embeddings"),
        "upstream must not receive the verbatim /v1/embeddings path; got {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("embedContent")),
        "upstream should receive the translated Gemini native embeddings path; got {paths:?}"
    );
    assert_eq!(
        captured[0].path, "/v1beta/models/text-embedding-004:embedContent",
        "single string embeddings input should use Gemini embedContent"
    );
    let forwarded: serde_json::Value =
        serde_json::from_slice(&captured[0].body).expect("forwarded embeddings JSON");
    assert_eq!(forwarded["model"], "models/text-embedding-004");
    assert_eq!(forwarded["content"]["parts"][0]["text"], "hi");
    assert_eq!(forwarded["outputDimensionality"], 3);
    assert!(
        forwarded.get("input").is_none(),
        "OpenAI input must be translated away"
    );
    assert!(
        forwarded.get("user").is_none(),
        "OpenAI user tag has no Gemini embeddings equivalent"
    );

    let out = resp.json().expect("client embeddings JSON");
    assert_eq!(out["object"], "list");
    assert_eq!(out["data"][0]["object"], "embedding");
    assert_eq!(out["data"][0]["index"], 0);
    assert_eq!(out["data"][0]["embedding"][0], 0.25);
    assert_eq!(out["data"][0]["embedding"][1], -0.5);
    assert_eq!(out["data"][0]["embedding"][2], 0.75);
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

// WOR-752 Finding B: an unrecognized path against a translated-format
// (Anthropic) provider must 501 rather than forward verbatim to an
// upstream that cannot interpret it.
#[test]
fn unknown_path_on_translated_provider_returns_501() {
    let upstream = MockUpstream::start(json!({"unused": true})).expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "anthropic",
        "claude.localhost",
        &upstream.base_url(),
    ))
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/v1/widgets",
            "claude.localhost",
            &json!({"anything": true}),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 501,
        "unknown path on an Anthropic-only origin must 501, not verbatim-forward; got {}",
        resp.status
    );
    assert!(
        upstream.captured().is_empty(),
        "a 501'd unknown path must not reach the upstream"
    );
}

// Forward-compat preserved: an unrecognized path against an OpenAI-format
// provider still passes through verbatim (a new OpenAI path the catalog
// has not learned yet keeps working).
#[test]
fn unknown_path_on_openai_provider_is_forwarded() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("mock");
    let harness = ProxyHarness::start_with_yaml(&config_for(
        "openai",
        "openai.localhost",
        &upstream.base_url(),
    ))
    .expect("start proxy");

    let resp = harness
        .post_json(
            "/v1/widgets",
            "openai.localhost",
            &json!({"anything": true}),
            &[],
        )
        .expect("post");

    assert_eq!(
        resp.status, 200,
        "unknown path on an OpenAI origin should pass through (forward-compat); got {}",
        resp.status
    );
    let captured = upstream.captured();
    assert!(
        !captured.is_empty(),
        "openai unknown path must reach the upstream"
    );
    assert_eq!(
        captured[0].path, "/v1/widgets",
        "OpenAI-format unknown path passes through unchanged"
    );
}
