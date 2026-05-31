//! End-to-end coverage for the WOR-808 PR7 OLP endpoints.
//!
//! Stands up an origin with `olp: { enabled: true, ... }` and drives
//! the two well-known endpoints:
//!
//! * `GET /.well-known/olp/key` -> JWK Set body carrying the
//!   verification key (RFC 7517).
//! * `POST /.well-known/olp/token` -> RFC 6749 §5.1 token response
//!   with `token_type: "License"` (RSL 1.0 OLP).
//!
//! Verifies the issued token round-trips through the in-process
//! verifier using the published JWK.

use base64::Engine as _;
use sbproxy_e2e::ProxyHarness;

/// Deterministic Ed25519 seed (64-char hex). Lab use only.
const TEST_KEY_HEX: &str = "0001020304050607080900010203040506070809000102030405060708090001";
const TEST_KID: &str = "olp-test-1";

fn olp_config() -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "olp.localhost":
    olp:
      enabled: true
      signing_key: "{TEST_KEY_HEX}"
      key_id: "{TEST_KID}"
      issuer: "https://olp.localhost"
      default_scope: "ai-input search"
      default_ttl_secs: 1800
    action:
      type: static
      status_code: 200
      body: "olp origin"
"#
    )
}

fn jwk_set_returns_publishable_ed25519_key_inner() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .get("/.well-known/olp/key", "olp.localhost")
        .expect("GET key");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or("");
    assert!(
        ct.contains("jwk-set+json"),
        "JWK Set content-type; got: {ct}"
    );
    let v: serde_json::Value = serde_json::from_slice(&resp.body).expect("JWK Set JSON");
    let keys = v["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["kid"], TEST_KID);
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["use"], "verify");
    // The public-key bytes are base64url no-pad, 32 raw -> 43 chars.
    let x = key["x"].as_str().expect("x present");
    assert_eq!(x.len(), 43);
}

#[test]
fn jwk_set_returns_publishable_ed25519_key() {
    jwk_set_returns_publishable_ed25519_key_inner();
}

#[test]
fn token_endpoint_returns_signed_jws_with_license_token_type() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_json(
            "/.well-known/olp/token",
            "olp.localhost",
            &serde_json::json!({}),
            &[],
        )
        .expect("POST token");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("token response JSON");
    // RFC 6749 §5.1 shape with the RSL 1.0 token_type.
    let token = body["access_token"].as_str().expect("access_token");
    assert_eq!(body["token_type"], "License");
    assert_eq!(body["expires_in"], 1800);
    assert_eq!(body["scope"], "ai-input search");
    // The token is a compact JWS: three base64url segments separated
    // by `.`. The header carries the configured kid and the
    // OLP-mandated typ.
    let mut parts = token.split('.');
    let header_b64 = parts.next().expect("header");
    let _payload_b64 = parts.next().expect("payload");
    let _sig_b64 = parts.next().expect("sig");
    assert!(parts.next().is_none(), "exactly three JWS segments");
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .expect("header b64");
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("header JSON");
    assert_eq!(header["typ"], "olp-license+jws");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], TEST_KID);
}

#[test]
fn issued_token_verifies_against_published_jwk() {
    // End-to-end composition: pull the JWK, then verify a freshly-
    // issued token against it using the in-process verifier. Pins
    // the contract that the published key actually matches the
    // signer the issuer used.
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let jwk_resp = harness
        .get("/.well-known/olp/key", "olp.localhost")
        .expect("GET key");
    let jwk_set: serde_json::Value = serde_json::from_slice(&jwk_resp.body).expect("JWK Set");
    let x_b64 = jwk_set["keys"][0]["x"].as_str().expect("x").to_string();
    let kid = jwk_set["keys"][0]["kid"].as_str().expect("kid").to_string();
    let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64.as_bytes())
        .expect("x b64");
    let x_arr: [u8; 32] = x_bytes.as_slice().try_into().expect("32-byte key");
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&x_arr).expect("Ed25519 verifying key");
    let verifier = sbproxy_modules::olp::OlpTokenVerifier::new(verifying_key, &kid);

    let token_resp = harness
        .post_json(
            "/.well-known/olp/token",
            "olp.localhost",
            &serde_json::json!({}),
            &[],
        )
        .expect("POST token");
    let token_body: serde_json::Value =
        serde_json::from_slice(&token_resp.body).expect("token JSON");
    let token = token_body["access_token"].as_str().expect("access_token");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = verifier.verify(token, now).expect("token verifies");
    assert_eq!(claims.iss, "https://olp.localhost");
    assert_eq!(claims.aud, "olp.localhost");
    assert_eq!(claims.scope, "ai-input search");
    assert!(claims.exp - claims.iat == 1800);
}

#[test]
fn key_endpoint_405_on_post() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_json(
            "/.well-known/olp/key",
            "olp.localhost",
            &serde_json::json!({}),
            &[],
        )
        .expect("POST key");
    assert_eq!(resp.status, 405, "key endpoint is GET only");
}

#[test]
fn token_endpoint_405_on_get() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .get("/.well-known/olp/token", "olp.localhost")
        .expect("GET token");
    assert_eq!(resp.status, 405, "token endpoint is POST only");
}

#[test]
fn ems_content_key_is_bound_to_token_when_seed_configured() {
    // WOR-808 PR8: when the operator declares `content_key_seed`
    // on the origin's OLP config, every issued token carries an
    // RFC 7800 `cnf.jwk` claim with a per-token AES-256-GCM key
    // (HKDF-derived from the seed + the token's jti). Pins the
    // claim shape and that two issuances under the same seed get
    // distinct keys.
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "ems.localhost":
    olp:
      enabled: true
      signing_key: "{TEST_KEY_HEX}"
      key_id: "{TEST_KID}"
      issuer: "https://ems.localhost"
      default_scope: "ai-input"
      default_ttl_secs: 60
      content_key_seed: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    action:
      type: static
      status_code: 200
      body: "ems origin"
"#
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start");

    // Pull the verification key.
    let jwk_resp = harness
        .get("/.well-known/olp/key", "ems.localhost")
        .expect("GET key");
    let jwk_set: serde_json::Value = serde_json::from_slice(&jwk_resp.body).expect("JWK Set");
    let x_b64 = jwk_set["keys"][0]["x"].as_str().expect("x").to_string();
    let kid = jwk_set["keys"][0]["kid"].as_str().expect("kid").to_string();
    let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x_b64.as_bytes())
        .unwrap();
    let x_arr: [u8; 32] = x_bytes.as_slice().try_into().unwrap();
    let verifier = sbproxy_modules::olp::OlpTokenVerifier::new(
        ed25519_dalek::VerifyingKey::from_bytes(&x_arr).unwrap(),
        &kid,
    );

    // Issue two tokens.
    let mint = || -> sbproxy_modules::olp::OlpLicenseClaims {
        let resp = harness
            .post_json(
                "/.well-known/olp/token",
                "ems.localhost",
                &serde_json::json!({}),
                &[],
            )
            .expect("POST token");
        assert_eq!(resp.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        let token = body["access_token"].as_str().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        verifier.verify(token, now).expect("verify")
    };
    let claims_a = mint();
    let claims_b = mint();

    // Both tokens MUST carry a cnf claim; both shapes must be the
    // documented oct/A256GCM/enc combo.
    let cnf_a = claims_a.cnf.as_ref().expect("cnf on first token");
    let cnf_b = claims_b.cnf.as_ref().expect("cnf on second token");
    assert_eq!(cnf_a.jwk.kty, "oct");
    assert_eq!(cnf_a.jwk.alg, "A256GCM");
    assert_eq!(cnf_a.jwk.use_, "enc");
    // Per-token jtis differ -> per-token keys differ. A regression
    // here would let token A's key decrypt token B's content.
    assert_ne!(cnf_a.jwk.k, cnf_b.jwk.k, "EMS keys MUST differ per token");
    // Extract returns the 32-byte raw key.
    let raw = sbproxy_modules::olp::extract_ems_content_key(&claims_a).expect("extract");
    assert_eq!(raw.len(), 32);
}

/// Decode an OLP JWS payload (the middle compact segment) so a test
/// can assert claim fields without the verifier ceremony.
fn decode_jws_payload(token: &str) -> serde_json::Value {
    let payload_b64 = token.split('.').nth(1).expect("middle segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64.as_bytes())
        .expect("payload b64");
    serde_json::from_slice(&bytes).expect("payload JSON")
}

#[test]
fn token_endpoint_binds_subject_from_form_body_client_id() {
    // RFC 6749 §4.4 client_credentials grant: the resolved client_id
    // becomes the issued token's `sub` claim. Pins that the form
    // path actually rebinds away from the legacy anonymous default.
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_bytes(
            "/.well-known/olp/token",
            "olp.localhost",
            "application/x-www-form-urlencoded",
            b"grant_type=client_credentials&client_id=acme-publisher".to_vec(),
            &[],
        )
        .expect("POST token");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("body");
    let token = body["access_token"].as_str().expect("token");
    let payload = decode_jws_payload(token);
    assert_eq!(payload["sub"], "acme-publisher");
}

#[test]
fn token_endpoint_rejects_form_body_missing_grant_type() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_bytes(
            "/.well-known/olp/token",
            "olp.localhost",
            "application/x-www-form-urlencoded",
            b"client_id=acme".to_vec(),
            &[],
        )
        .expect("POST token");
    assert_eq!(resp.status, 400);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("error body");
    assert_eq!(body["error"], "invalid_request");
}

#[test]
fn token_endpoint_rejects_form_body_with_unsupported_grant_type() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_bytes(
            "/.well-known/olp/token",
            "olp.localhost",
            "application/x-www-form-urlencoded",
            b"grant_type=password&client_id=acme".to_vec(),
            &[],
        )
        .expect("POST token");
    assert_eq!(resp.status, 400);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("error body");
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[test]
fn token_endpoint_rejects_form_body_with_blank_client_id() {
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_bytes(
            "/.well-known/olp/token",
            "olp.localhost",
            "application/x-www-form-urlencoded",
            b"grant_type=client_credentials&client_id=".to_vec(),
            &[],
        )
        .expect("POST token");
    assert_eq!(resp.status, 400);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("error body");
    assert_eq!(body["error"], "invalid_request");
}

#[test]
fn token_endpoint_keeps_anonymous_subject_on_non_form_post() {
    // Backward compat: existing automation that POSTs an empty JSON
    // body keeps minting tokens, and they still carry sub=anonymous.
    let harness = ProxyHarness::start_with_yaml(&olp_config()).expect("start");
    let resp = harness
        .post_json(
            "/.well-known/olp/token",
            "olp.localhost",
            &serde_json::json!({}),
            &[],
        )
        .expect("POST token");
    assert_eq!(resp.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&resp.body).expect("body");
    let token = body["access_token"].as_str().expect("token");
    let payload = decode_jws_payload(token);
    assert_eq!(payload["sub"], "anonymous");
}

#[test]
fn well_known_olp_404s_when_origin_has_no_olp_block() {
    // Origin without an olp: block must 404 the well-known paths
    // rather than letting them fall through to the upstream / static
    // action.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "no-olp.localhost":
    action:
      type: static
      status_code: 200
      body: "no olp"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start");
    let resp = harness
        .get("/.well-known/olp/key", "no-olp.localhost")
        .expect("GET");
    assert_eq!(resp.status, 404);
    let resp = harness
        .post_json(
            "/.well-known/olp/token",
            "no-olp.localhost",
            &serde_json::json!({}),
            &[],
        )
        .expect("POST");
    assert_eq!(resp.status, 404);
}
