//! WOR-805 F1.6.1: content-digest body binding on inbound bot_auth.
//!
//! When a Web Bot Auth signature covers `content-digest`, the auth
//! phase verifies the signature header but the body is not yet
//! buffered. The proxy defers a body-vs-digest check to
//! `request_body_filter`: it buffers the request body, computes
//! `SHA-256(body)`, and confirms it matches the `Content-Digest`
//! header value the signature attests to. A mismatch is treated as an
//! authentication failure (the body the client sent does not match
//! the body the client signed), so the response is 401.
//!
//! Pins:
//!
//! 1. POST body that matches the signed `Content-Digest` succeeds and
//!    reaches the upstream.
//! 2. POST body that does NOT match the signed `Content-Digest`
//!    (tampering somewhere between the signer and the proxy) is
//!    rejected 401 and never reaches the upstream.
//! 3. A signature that does NOT cover `content-digest` is unaffected;
//!    the existing fast path keeps working without the body-buffer
//!    overhead.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use sha2::{Digest, Sha256};

fn ed25519_config(upstream_url: &str, verifying_key_hex: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: bot_auth
      clock_skew_seconds: 9999999999
      agents:
        - name: ed25519-bot
          key_id: ed-bot-1
          algorithm: ed25519
          public_key: "{verifying_key_hex}"
          required_components:
            - "@method"
            - "@target-uri"
"#
    )
}

/// Compute the canonical RFC 9421 signature base for a POST that
/// covers @method, @target-uri, and content-digest.
fn build_base_for_post_with_digest(inner_list: &str, params: &str, content_digest: &str) -> String {
    let mut out = String::new();
    out.push_str("\"@method\": POST\n");
    out.push_str("\"@target-uri\": /\n");
    out.push_str("\"content-digest\": ");
    out.push_str(content_digest);
    out.push('\n');
    out.push_str("\"@signature-params\": (");
    out.push_str(inner_list);
    out.push(')');
    if !params.is_empty() {
        out.push(';');
        out.push_str(params);
    }
    out
}

/// Build the RFC 9530 `Content-Digest` header value for a body.
fn content_digest_header(body: &[u8]) -> String {
    let raw = Sha256::digest(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    format!("sha-256=:{}:", b64)
}

fn fresh_keypair() -> SigningKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

#[test]
fn signed_post_with_matching_content_digest_is_accepted() {
    let signing_key = fresh_keypair();
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&ed25519_config(&upstream.base_url(), &verifying_key_hex))
            .expect("start");

    let body: Vec<u8> = br#"{"event":"signed-payload"}"#.to_vec();
    let digest = content_digest_header(&body);

    let inner_list = r#""@method" "@target-uri" "content-digest""#;
    let params = r#"created=1700000000;keyid="ed-bot-1";alg="ed25519""#;
    let base = build_base_for_post_with_digest(inner_list, params, &digest);
    let signature = signing_key.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    let resp = harness
        .post_bytes(
            "/",
            "blog.localhost",
            "application/json",
            body.clone(),
            &[
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
                ("content-digest", digest.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status,
        200,
        "matching content-digest must allow the signed POST; got {}: {:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
    assert!(
        !upstream.captured().is_empty(),
        "request must reach upstream"
    );
}

#[test]
fn signed_post_with_tampered_body_fails_content_digest_binding() {
    let signing_key = fresh_keypair();
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&ed25519_config(&upstream.base_url(), &verifying_key_hex))
            .expect("start");

    // The signer signed THIS body...
    let original_body: Vec<u8> = br#"{"event":"signed-payload"}"#.to_vec();
    let digest = content_digest_header(&original_body);

    let inner_list = r#""@method" "@target-uri" "content-digest""#;
    let params = r#"created=1700000000;keyid="ed-bot-1";alg="ed25519""#;
    let base = build_base_for_post_with_digest(inner_list, params, &digest);
    let signature = signing_key.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    // ...but an intermediary swaps the body before the request hits
    // the gateway. The signature still verifies (the header attests
    // to the original digest) but the body no longer hashes to it.
    let tampered_body: Vec<u8> = br#"{"event":"tampered-payload"}"#.to_vec();

    let resp = harness
        .post_bytes(
            "/",
            "blog.localhost",
            "application/json",
            tampered_body,
            &[
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
                // The header still claims the original digest.
                ("content-digest", digest.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status,
        401,
        "tampered body must be rejected with 401, got {}: {:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
    // The upstream connection may have been opened before the body
    // check fires (Pingora's request_body_filter runs after
    // upstream_peer), but the body bytes must NEVER reach upstream.
    // Confirm by checking that any captured request carries an empty
    // body: Pingora drops the connection on the body filter Err, and
    // the mock upstream's body-read loop exits immediately on the
    // next zero-byte read.
    for captured in upstream.captured() {
        assert!(
            captured.body.is_empty(),
            "tampered body bytes must NOT reach upstream; got {} bytes",
            captured.body.len()
        );
    }
}

#[test]
fn signed_post_without_digest_in_covered_set_skips_body_check() {
    // Sanity: when the signature does NOT cover content-digest, the
    // deferred body-buffer + check path stays off. This confirms the
    // body-binding only activates when the signer opted in, so plain
    // bot_auth on header-only requests pays no body-buffering cost.
    let signing_key = fresh_keypair();
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&ed25519_config(&upstream.base_url(), &verifying_key_hex))
            .expect("start");

    let inner_list = r#""@method" "@target-uri""#;
    let params = r#"created=1700000000;keyid="ed-bot-1";alg="ed25519""#;
    let mut base = String::new();
    base.push_str("\"@method\": POST\n");
    base.push_str("\"@target-uri\": /\n");
    base.push_str("\"@signature-params\": (");
    base.push_str(inner_list);
    base.push(')');
    base.push(';');
    base.push_str(params);

    let signature = signing_key.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    // Send an arbitrary body; the proxy must not enforce a digest
    // because the signature did not cover one.
    let body: Vec<u8> = br#"arbitrary body bytes"#.to_vec();
    let resp = harness
        .post_bytes(
            "/",
            "blog.localhost",
            "application/octet-stream",
            body,
            &[
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status,
        200,
        "non-digest-covering signature must skip the body-binding check; got {}: {:?}",
        resp.status,
        resp.text().unwrap_or_default()
    );
    assert!(!upstream.captured().is_empty());
}
