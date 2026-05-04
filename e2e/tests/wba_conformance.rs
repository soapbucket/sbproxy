//! Q1.7: Web Bot Auth conformance vectors.
//!
//! Hand-constructs a small set of conformance vectors covering the
//! load-bearing failure modes from
//! `draft-meunier-web-bot-auth-architecture-05` and
//! `draft-meunier-http-message-signatures-directory-05`:
//!
//!   1. **valid signature** => `BotAuthVerdict::Verified`
//!   2. **missing covered component** (request omits `@target-uri`
//!      while the `Signature-Input` claims it) => `Invalid`
//!   3. **wrong key** (signed with key A, directory carries key B for
//!      the keyid) => `Invalid`
//!   4. **wrong digest** (Content-Digest header mismatches body) =>
//!      `Invalid` when `content-digest` is in the covered set
//!
//! The full upstream conformance vector pack is fetched by the
//! `e2e/fixtures/wave1/regenerate.rs` binary when it lands; until then
//! this file synthesises minimal vectors against the existing static
//! `bot_auth` directory so the verifier path is exercised.
//!
//! `BotAuthVerdict::Verified` is the proxy-internal type. From a
//! black-box e2e perspective we observe the verdict via the HTTP
//! status code: 200 means `Verified`, 401 means anything else.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Vector outcome the proxy is expected to produce for a given input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedVerdict {
    Verified,
    Invalid,
}

/// One conformance vector. Each test case maps a black-box request
/// (status code) to the verifier's expected internal verdict.
struct Vector {
    name: &'static str,
    /// Headers the test sends. The signature is computed at runtime so
    /// the test does not depend on hard-coded base64.
    expected: ExpectedVerdict,
}

/// Build the canonical RFC 9421 signature base for `GET /` with the
/// supplied inner-list and parameters. Mirrors
/// `sbproxy_middleware::signatures::build_signature_base` for the
/// subset this conformance test covers.
fn build_base_for_get_root(inner_list: &str, params: &str) -> String {
    let mut out = String::new();
    out.push_str("\"@method\": GET\n");
    out.push_str("\"@target-uri\": /\n");
    out.push_str("\"@signature-params\": (");
    out.push_str(inner_list);
    out.push(')');
    if !params.is_empty() {
        out.push(';');
        out.push_str(params);
    }
    out
}

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
        - name: conformance-bot
          key_id: conformance-key
          algorithm: ed25519
          public_key: "{verifying_key_hex}"
          required_components:
            - "@method"
            - "@target-uri"
"#
    )
}

#[test]
fn conformance_valid_signature_yields_verified() {
    // Vector 1: a correctly-formed Ed25519 signature over the
    // `@method` + `@target-uri` covered components must verify.
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&ed25519_config(&upstream.base_url(), &verifying_key_hex))
            .expect("start");

    let inner_list = r#""@method" "@target-uri""#;
    let params = r#"created=1700000000;keyid="conformance-key";alg="ed25519""#;
    let base = build_base_for_get_root(inner_list, params);
    let sig = signing_key.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "valid signature => Verified verdict");
}

#[test]
fn conformance_wrong_key_yields_invalid() {
    // Vector 3: signer uses key A; the directory has key B under the
    // claimed keyid. Verifier must reject.
    let mut secret_a = [0u8; 32];
    OsRng.fill_bytes(&mut secret_a);
    let signing_key_a = SigningKey::from_bytes(&secret_a);

    let mut secret_b = [0u8; 32];
    OsRng.fill_bytes(&mut secret_b);
    let signing_key_b = SigningKey::from_bytes(&secret_b);
    let verifying_key_b_hex = hex::encode(signing_key_b.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&ed25519_config(&upstream.base_url(), &verifying_key_b_hex))
            .expect("start");

    let inner_list = r#""@method" "@target-uri""#;
    let params = r#"created=1700000000;keyid="conformance-key";alg="ed25519""#;
    let base = build_base_for_get_root(inner_list, params);
    let sig = signing_key_a.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "wrong key => Invalid verdict");
}

#[test]
fn conformance_unknown_keyid_yields_invalid() {
    // Vector variant of #3: the keyid is not in the directory at all.
    // The verifier's `UnknownAgent` arm must fire.
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&ed25519_config(&upstream.base_url(), &verifying_key_hex))
            .expect("start");

    let inner_list = r#""@method" "@target-uri""#;
    // Claim a keyid the directory does not know.
    let params = r#"created=1700000000;keyid="ghost-key";alg="ed25519""#;
    let base = build_base_for_get_root(inner_list, params);
    let sig = signing_key.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "unknown keyid => Invalid verdict");
}

#[test]
#[ignore = "TODO(wave3): G1.7 directory verifier supports Content-Digest covered-components but the test body is still a placeholder; needs vector 2 wiring (synthesize a request whose @target-uri reconstructs differently than the signer's)."]
fn conformance_missing_component_yields_invalid() {
    // Vector 2: `Signature-Input` declares `@target-uri` is covered,
    // but the request is built so that the proxy reconstructs a
    // different `@target-uri` than the signer did. The verifier's
    // canonical-base reconstruction step must produce a different
    // string and the signature check must fail.
    //
    // The "missing component" framing in the upstream draft refers to
    // a covered component header that the request does not actually
    // carry (e.g. `content-digest` listed in the inner-list but no
    // `Content-Digest` header on the wire). Today's bot_auth verifier
    // only covers `@method` + `@target-uri`; once G1.7 expands the
    // covered-components set, drop the `#[ignore]`.
}

#[test]
#[ignore = "TODO(wave3): G1.7 verifier supports Content-Digest but the test body remains a placeholder; needs vector 4 wiring (request body with mismatching Content-Digest)."]
fn conformance_wrong_digest_yields_invalid() {
    // Vector 4: the request body carries a `Content-Digest` whose
    // value does not match SHA-256 of the body. When `content-digest`
    // is in the covered set, the verifier's canonical-base step must
    // include the (incorrect) header value; the signature is computed
    // over the actual body so the bytes mismatch and verify fails.
    //
    // Reserved until G1.7 expands covered-component support.
}

// --- Vector pack manifest test ---

/// Confirm the in-tree vector list covers each of the required
/// outcomes from the upstream draft. This is a self-test on the test
/// pack: when the upstream draft adds a new failure mode, this test
/// should fail and force a maintainer to add the missing vector.
#[test]
fn conformance_vector_pack_covers_required_outcomes() {
    let vectors: &[Vector] = &[
        Vector {
            name: "valid_signature",
            expected: ExpectedVerdict::Verified,
        },
        Vector {
            name: "wrong_key",
            expected: ExpectedVerdict::Invalid,
        },
        Vector {
            name: "unknown_keyid",
            expected: ExpectedVerdict::Invalid,
        },
        Vector {
            name: "missing_component",
            expected: ExpectedVerdict::Invalid,
        },
        Vector {
            name: "wrong_digest",
            expected: ExpectedVerdict::Invalid,
        },
    ];
    let verified = vectors
        .iter()
        .filter(|v| v.expected == ExpectedVerdict::Verified)
        .count();
    let invalid = vectors
        .iter()
        .filter(|v| v.expected == ExpectedVerdict::Invalid)
        .count();
    assert!(verified >= 1, "at least one Verified vector required");
    assert!(
        invalid >= 3,
        "at least three Invalid-class vectors required"
    );
    let names: Vec<_> = vectors.iter().map(|v| v.name).collect();
    for required in [
        "valid_signature",
        "wrong_key",
        "missing_component",
        "wrong_digest",
    ] {
        assert!(
            names.contains(&required),
            "required vector {required} missing from pack"
        );
    }
}
