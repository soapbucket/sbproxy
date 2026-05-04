//! JWT authentication (HS256).
//!
//! Validates HS256-signed JWTs against a shared secret and the
//! configured `issuer`, `audience`, and required-claim constraints.
//! The proxy uses the `jsonwebtoken` crate internally; this suite
//! mints tokens at runtime via the same crate so failure modes show
//! up as typed errors rather than mismatched constants.
//!
//! Test matrix:
//! - valid token, far-future `exp`         -> 200
//! - expired token (`exp` in the past)     -> 401
//! - wrong issuer                          -> 401
//! - missing required claim                -> 401
//! - unsigned / wrong-secret token         -> 401
//! - missing `Authorization` header        -> 401

use jsonwebtoken::{encode, EncodingKey, Header};
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde::Serialize;
use serde_json::json;

const SHARED_SECRET: &str = "shared-secret-abc";

// --- Token minting helpers ---
//
// We define one struct per claim shape. `serde(skip_serializing_if =
// "Option::is_none")` keeps optional claims out of the encoded payload
// when they're None, which matches the "no required claim" test case
// (the `role` field is genuinely absent rather than serialized as
// `"role": null`, which the verifier treats as present).

#[derive(Serialize)]
struct BasicClaims {
    sub: String,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

/// Mint an HS256 token signed with `secret` and the supplied claims.
fn mint(secret: &str, claims: &BasicClaims) -> String {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("jwt encode")
}

/// Far-future expiry (year 2286) so the test never starts flaking on
/// a long-lived release branch.
const FAR_FUTURE_EXP: i64 = 9_999_999_999;

fn token_valid() -> String {
    mint(
        SHARED_SECRET,
        &BasicClaims {
            sub: "alice".into(),
            exp: FAR_FUTURE_EXP,
            iss: None,
            aud: None,
            role: None,
        },
    )
}

fn token_expired() -> String {
    mint(
        SHARED_SECRET,
        &BasicClaims {
            sub: "alice".into(),
            exp: 1_000,
            iss: None,
            aud: None,
            role: None,
        },
    )
}

fn token_wrong_issuer() -> String {
    mint(
        SHARED_SECRET,
        &BasicClaims {
            sub: "alice".into(),
            exp: FAR_FUTURE_EXP,
            iss: Some("wrong-issuer".into()),
            aud: None,
            role: None,
        },
    )
}

fn token_correct_issuer_audience() -> String {
    mint(
        SHARED_SECRET,
        &BasicClaims {
            sub: "alice".into(),
            exp: FAR_FUTURE_EXP,
            iss: Some("expected-issuer".into()),
            aud: Some("my-api".into()),
            role: None,
        },
    )
}

fn token_with_role() -> String {
    mint(
        SHARED_SECRET,
        &BasicClaims {
            sub: "alice".into(),
            exp: FAR_FUTURE_EXP,
            iss: None,
            aud: None,
            role: Some("admin".into()),
        },
    )
}

fn token_wrong_secret() -> String {
    mint(
        "attacker-secret",
        &BasicClaims {
            sub: "alice".into(),
            exp: FAR_FUTURE_EXP,
            iss: None,
            aud: None,
            role: None,
        },
    )
}

// --- Configs ---

fn basic_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "jwt.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: jwt
      secret: shared-secret-abc
      algorithms: [HS256]
"#
    )
}

fn issuer_audience_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "jwt.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: jwt
      secret: shared-secret-abc
      algorithms: [HS256]
      issuer: expected-issuer
      audience: my-api
"#
    )
}

fn required_claims_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "jwt.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: jwt
      secret: shared-secret-abc
      algorithms: [HS256]
      required_claims:
        role: admin
"#
    )
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

// --- Tests ---

#[test]
fn valid_token_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&basic_config(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_valid()))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(!upstream.captured().is_empty());
}

#[test]
fn missing_credential_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&basic_config(&upstream.base_url())).expect("start");

    let resp = harness.get("/get", "jwt.localhost").expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn malformed_token_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&basic_config(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", "Bearer not.a.valid.jwt")],
        )
        .expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn expired_token_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&basic_config(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_expired()))],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "expired tokens must be rejected");
}

#[test]
fn wrong_issuer_returns_401() {
    // Configured issuer is `expected-issuer`; the token claims
    // `wrong-issuer`. jsonwebtoken's `Validation::set_issuer` enforces
    // the equality check, so this must fail.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&issuer_audience_config(&upstream.base_url()))
        .expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_wrong_issuer()))],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "wrong issuer must be rejected");
}

#[test]
fn correct_issuer_and_audience_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&issuer_audience_config(&upstream.base_url()))
        .expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_correct_issuer_audience()))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn missing_required_claim_returns_401() {
    // Configured: required role=admin. The token has no `role` claim.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&required_claims_config(&upstream.base_url()))
        .expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_valid()))],
        )
        .expect("send");
    assert_eq!(resp.status, 401, "missing required claim must be rejected");
}

#[test]
fn matching_required_claim_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&required_claims_config(&upstream.base_url()))
        .expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_with_role()))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn token_signed_with_wrong_secret_returns_401() {
    // Catches the most common MITM-style mistake: a forged token with
    // valid claim shape but signed with a key the server does not hold.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&basic_config(&upstream.base_url())).expect("start");

    let resp = harness
        .get_with_headers(
            "/get",
            "jwt.localhost",
            &[("authorization", &bearer(&token_wrong_secret()))],
        )
        .expect("send");
    assert_eq!(resp.status, 401);
}
