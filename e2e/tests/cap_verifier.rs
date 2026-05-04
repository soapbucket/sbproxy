//! CAP token verifier (Wave 6 / R6.1) end-to-end tests.
//!
//! Boots a harness origin configured with `authentication.type: cap`
//! and a static JWKS holding one Ed25519 key, then mints CAP tokens
//! locally and asserts the request lifecycle:
//!
//! * No `CAP-Token` header     -> 401
//! * Tampered signature        -> 401
//! * Wrong audience            -> 403
//! * Path outside the glob     -> 403
//! * Valid token, glob match   -> 200 and the upstream sees the request
//!
//! The verifier itself is unit-tested in
//! `crates/sbproxy-modules/src/auth/cap.rs`; this suite proves that
//! the dispatch wiring (compile_auth -> Auth::Cap -> auth_check) works
//! end-to-end through the proxy.

use base64::Engine;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const KID: &str = "cap-e2e-001";

// --- Keypair helpers ---

/// Build a fresh Ed25519 signing key together with a base64url-no-pad
/// encoded public-key string suitable for embedding in a JWK `x` field.
fn fresh_keypair() -> (SigningKey, String) {
    let signing = SigningKey::generate(&mut OsRng);
    let public = signing.verifying_key().to_bytes();
    let public_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
    (signing, public_b64url)
}

/// Mint a CAP-shaped JWT signed by `signing` with the canonical Wave
/// 6 claim shape. `overrides` lets a test mutate the claims map before
/// signing so each test case can stress one failure mode.
fn mint_cap(signing: &SigningKey, overrides: impl FnOnce(&mut serde_json::Value)) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": "issuer.example.com",
        "sub": "agent_acme_e2e",
        "aud": "cap.localhost",
        "cap_v": 1,
        "rps": 2.0,
        "bytes": 10_737_418_240u64,
        "glob": "/blog/**",
        "exp": now + 3600,
        "iat": now,
        "jti": "01J7HZ8X9R3CAPE2E",
    });
    overrides(&mut claims);

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KID.to_string());
    header.typ = Some("cap+jwt".to_string());

    // jsonwebtoken's Ed25519 EncodingKey wants a PKCS8 DER blob.
    let pkcs8 = signing
        .to_pkcs8_der()
        .expect("encode pkcs8")
        .as_bytes()
        .to_vec();
    let key = EncodingKey::from_ed_der(&pkcs8);
    encode(&header, &claims, &key).expect("sign cap token")
}

// --- Configs ---

/// Build a `cap.localhost` origin config that requires CAP and uses a
/// static JWKS containing the supplied public key. The static-JWKS
/// path keeps the test offline (no JWKS HTTP fetch).
fn cap_config(upstream_url: &str, pubkey_b64url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cap.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: cap
      jwks_static:
        keys:
          - kty: OKP
            crv: Ed25519
            kid: {KID}
            alg: EdDSA
            x: {pubkey_b64url}
"#
    )
}

// --- Tests ---

#[test]
fn missing_cap_token_returns_401() {
    let (_signing, pubkey) = fresh_keypair();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&cap_config(&upstream.base_url(), &pubkey)).expect("start");

    let resp = harness.get("/blog/article", "cap.localhost").expect("send");
    assert_eq!(resp.status, 401);
    assert!(
        upstream.captured().is_empty(),
        "no upstream call should have happened on a 401"
    );
}

#[test]
fn valid_cap_token_returns_200() {
    let (signing, pubkey) = fresh_keypair();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&cap_config(&upstream.base_url(), &pubkey)).expect("start");

    let token = mint_cap(&signing, |_| {});
    let resp = harness
        .get_with_headers("/blog/article", "cap.localhost", &[("cap-token", &token)])
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !upstream.captured().is_empty(),
        "the upstream must see the proxied request"
    );
}

#[test]
fn cap_token_via_authorization_scheme_returns_200() {
    let (signing, pubkey) = fresh_keypair();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&cap_config(&upstream.base_url(), &pubkey)).expect("start");

    let token = mint_cap(&signing, |_| {});
    let bearer = format!("CAP {token}");
    let resp = harness
        .get_with_headers(
            "/blog/article",
            "cap.localhost",
            &[("authorization", &bearer)],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn tampered_signature_returns_401() {
    let (signing, pubkey) = fresh_keypair();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&cap_config(&upstream.base_url(), &pubkey)).expect("start");

    // Tamper with the signature by rewriting the last segment.
    let token = mint_cap(&signing, |_| {});
    let mut parts: Vec<&str> = token.split('.').collect();
    let bogus = "AAAAtamperedSignatureBytesAreNotARealEd25519Signature";
    parts[2] = bogus;
    let tampered = parts.join(".");

    let resp = harness
        .get_with_headers(
            "/blog/article",
            "cap.localhost",
            &[("cap-token", &tampered)],
        )
        .expect("send");
    assert_eq!(resp.status, 401);
}

#[test]
fn path_outside_glob_returns_403() {
    let (signing, pubkey) = fresh_keypair();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&cap_config(&upstream.base_url(), &pubkey)).expect("start");

    // Token authorises /blog/** but request hits /api/private.
    let token = mint_cap(&signing, |_| {});
    let resp = harness
        .get_with_headers("/api/private", "cap.localhost", &[("cap-token", &token)])
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "path outside the glob must surface as path_not_authorized"
    );
}

#[test]
fn wrong_audience_returns_403() {
    let (signing, pubkey) = fresh_keypair();
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&cap_config(&upstream.base_url(), &pubkey)).expect("start");

    let token = mint_cap(&signing, |c| {
        c["aud"] = json!("api.different.com");
    });
    let resp = harness
        .get_with_headers("/blog/article", "cap.localhost", &[("cap-token", &token)])
        .expect("send");
    assert_eq!(resp.status, 403);
}
