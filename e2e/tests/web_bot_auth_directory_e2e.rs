//! Web Bot Auth hosted key directory (WOR-805).
//!
//! Verifies SBproxy serves its own Ed25519 public key as an HTTP
//! Message Signatures directory at
//! `/.well-known/http-message-signatures-directory`, and that the
//! published key is the one derived from the configured seed
//! (round-trip self-verify).

use base64::Engine as _;
use sbproxy_e2e::ProxyHarness;

// Fixed 32-byte Ed25519 seed (64 hex chars) for a deterministic test.
const SEED_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  web_bot_auth:
    key_id: sbproxy-test-2026
    ed25519_seed_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
origins:
  "bot.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>home</h1>"
"#;

#[test]
fn serves_signature_directory_with_correct_jwk() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get(
            "/.well-known/http-message-signatures-directory",
            "bot.localhost",
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let ct = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        ct.contains("application/http-message-signatures-directory+json"),
        "unexpected content-type: {ct}"
    );

    let body = String::from_utf8(resp.body).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&body).expect("valid JSON directory");
    let key = &doc["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["kid"], "sbproxy-test-2026");

    // The published `x` must equal the public key derived from the
    // configured seed (round-trip self-verify of the identity).
    let x = key["x"].as_str().expect("x present");
    let published: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .expect("base64url x")
        .try_into()
        .expect("32-byte key");

    let seed: [u8; 32] = hex::decode(SEED_HEX).unwrap().try_into().unwrap();
    let expected = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(published, expected, "published key must match the seed");
}

#[test]
fn directory_absent_when_not_configured() {
    // No web_bot_auth block -> the path is not served by the proxy and
    // falls through (the static origin has no such route, so 404).
    const NO_WBA: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "bot.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>home</h1>"
"#;
    let harness = ProxyHarness::start_with_yaml(NO_WBA).expect("start proxy");
    let resp = harness
        .get(
            "/.well-known/http-message-signatures-directory",
            "bot.localhost",
        )
        .expect("send");
    // The path falls through to the origin (here, the static action),
    // so it must NOT carry the directory content-type or a JWK Set.
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        !ct.contains("http-message-signatures-directory"),
        "directory must not be served without a web_bot_auth identity; got content-type {ct}"
    );
    let body = String::from_utf8(resp.body).unwrap_or_default();
    assert!(
        !body.contains("\"keys\""),
        "fell through to a directory document unexpectedly: {body}"
    );
}
