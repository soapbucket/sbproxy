//! Web Bot Auth publish self-signature (WOR-805 follow-up).
//!
//! When `web_bot_auth_publish.signing_key_hex` is set, both the
//! JWKS directory and the Signature Agent Card responses gain
//! `Content-Digest`, `Signature-Input`, and `Signature` response
//! headers per RFC 9421 over `("content-digest")` with
//! `tag="web-bot-auth"`. Verifiers can then confirm the body they
//! fetched was emitted by the holder of the advertised public key,
//! closing the trust loop without relying solely on TLS.
//!
//! These tests pin:
//!
//! 1. The three signature-related headers appear on the directory
//!    response when `signing_key_hex` is configured, and the
//!    signature round-trips through the shared verifier using the
//!    published JWK as the trust anchor.
//! 2. The same headers appear on the agent-card response.
//! 3. With `signing_key_hex` omitted, the responses still ship
//!    successfully (the field is optional) but carry no signature
//!    headers - a verifier that wants to enforce signed directories
//!    can detect the absence cleanly.

use base64::Engine as _;
use sbproxy_e2e::ProxyHarness;
use sbproxy_middleware::signatures::{
    MessageSignatureConfig, MessageSignatureVerifier, SignatureAlgorithm, VerifyVerdict,
};

// Deterministic Ed25519 seed + matching public key (32 bytes each,
// hex). The public key is the verifying key derived from the seed
// via ed25519-dalek; both halves are pinned in the source so the
// test does not need to compute them at runtime.
const SEED_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn config_signed() -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "agent.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>home</h1>"
    web_bot_auth_publish:
      enabled: true
      key_id: "kid-sbproxy-2026"
      public_key_hex: "{pk}"
      agent_name: "SBproxy"
      directory_url: "https://agent.localhost/.well-known/http-message-signatures-directory"
      signing_key_hex: "{seed}"
"#,
        pk = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&hex_to_seed(SEED_HEX))
                .verifying_key()
                .to_bytes()
        ),
        seed = SEED_HEX,
    )
}

const CONFIG_UNSIGNED: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "agent.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>home</h1>"
    web_bot_auth_publish:
      enabled: true
      key_id: "kid-sbproxy-2026"
      public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
      agent_name: "SBproxy"
      directory_url: "https://agent.localhost/.well-known/http-message-signatures-directory"
"#;

fn hex_to_seed(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// Fetch the directory, then build the round-trip verifier against
/// the public key the directory advertises so the test is fully
/// self-contained (the verifier never has to know the seed).
fn verify_signed_response(body: &[u8], headers: &std::collections::HashMap<String, String>) {
    let content_digest = headers
        .get("content-digest")
        .or_else(|| headers.get("Content-Digest"))
        .expect("content-digest header present");
    assert!(
        content_digest.starts_with("sha-256=:"),
        "expected sha-256 digest, got {content_digest}"
    );
    let signature_input = headers
        .get("signature-input")
        .or_else(|| headers.get("Signature-Input"))
        .expect("signature-input header present");
    assert!(
        signature_input.contains("tag=\"web-bot-auth\""),
        "signature-input must carry the Web Bot Auth tag: {signature_input}"
    );
    let signature = headers
        .get("signature")
        .or_else(|| headers.get("Signature"))
        .expect("signature header present");
    assert!(signature.starts_with("sig1=:"));

    // Use the published JWK as the trust anchor, exactly like an
    // external verifier would.
    let doc: serde_json::Value = serde_json::from_slice(body).expect("body is JSON");
    let x = doc["keys"][0]["x"].as_str().expect("first JWK has x");
    let pk: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .expect("base64url x")
        .try_into()
        .expect("32-byte public key");
    let kid = doc["keys"][0]["kid"].as_str().expect("first JWK has kid");

    // Rehydrate the response as an http::Request so the existing
    // verifier (which only knows about request-shaped messages) can
    // check the signature; the covered set is just content-digest,
    // so the method + URI are inert.
    let mut req = http::Request::builder()
        .method("GET")
        .uri("https://signed-body.invalid/")
        .body(bytes::Bytes::copy_from_slice(body))
        .unwrap();
    for (name, value) in [
        ("content-digest", content_digest.as_str()),
        ("signature-input", signature_input.as_str()),
        ("signature", signature.as_str()),
    ] {
        req.headers_mut().insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
    }

    let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: kid.to_string(),
        key: hex::encode(pk),
        required_components: vec!["content-digest".to_string()],
        clock_skew_seconds: 30,
    })
    .expect("verifier");
    match verifier.verify_request(&req) {
        VerifyVerdict::Ok { .. } => {}
        other => panic!("verifier rejected the published directory: {other:?}"),
    }
}

#[test]
fn directory_response_is_self_signed_when_signing_key_set() {
    let harness = ProxyHarness::start_with_yaml(&config_signed()).expect("start proxy");
    let resp = harness
        .get(
            "/.well-known/http-message-signatures-directory",
            "agent.localhost",
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    verify_signed_response(&resp.body, &resp.headers);
}

#[test]
fn agent_card_response_is_self_signed_when_signing_key_set() {
    let harness = ProxyHarness::start_with_yaml(&config_signed()).expect("start proxy");
    let resp = harness
        .get("/.well-known/web-bot-auth/agent-card", "agent.localhost")
        .expect("send");
    assert_eq!(resp.status, 200);

    // The agent card is a single-document body that does not carry
    // a JWK directly; pull the trust anchor from a sibling directory
    // fetch so the test asserts both bodies were signed by the same
    // configured key.
    let directory = harness
        .get(
            "/.well-known/http-message-signatures-directory",
            "agent.localhost",
        )
        .expect("directory");
    let doc: serde_json::Value =
        serde_json::from_slice(&directory.body).expect("directory body is JSON");
    let x = doc["keys"][0]["x"].as_str().expect("x");
    let pk: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .unwrap()
        .try_into()
        .unwrap();
    let kid = doc["keys"][0]["kid"].as_str().expect("kid");

    let mut req = http::Request::builder()
        .method("GET")
        .uri("https://signed-body.invalid/")
        .body(bytes::Bytes::copy_from_slice(&resp.body))
        .unwrap();
    for name in ["content-digest", "signature-input", "signature"] {
        let v = resp
            .headers
            .get(name)
            .unwrap_or_else(|| panic!("agent-card missing {name}"));
        req.headers_mut().insert(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(v).unwrap(),
        );
    }
    let verifier = MessageSignatureVerifier::new(MessageSignatureConfig {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: kid.to_string(),
        key: hex::encode(pk),
        required_components: vec!["content-digest".to_string()],
        clock_skew_seconds: 30,
    })
    .expect("verifier");
    match verifier.verify_request(&req) {
        VerifyVerdict::Ok { .. } => {}
        other => panic!("agent-card signature did not verify: {other:?}"),
    }
}

#[test]
fn directory_response_unsigned_when_signing_key_absent() {
    let harness = ProxyHarness::start_with_yaml(CONFIG_UNSIGNED).expect("start proxy");
    let resp = harness
        .get(
            "/.well-known/http-message-signatures-directory",
            "agent.localhost",
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    // The publish surface still serves the directory body when no
    // signing key is configured; the three signature-related
    // headers must NOT be present so a verifier that wants to
    // enforce signed directories can fail cleanly.
    for missing in ["content-digest", "signature-input", "signature"] {
        assert!(
            !resp.headers.contains_key(missing)
                && !resp.headers.contains_key(&missing.to_ascii_uppercase()),
            "expected no {missing} header on unsigned directory; got {:?}",
            resp.headers.get(missing)
        );
    }
}
