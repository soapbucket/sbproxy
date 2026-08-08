//! HTTP Digest authentication (RFC 7616).
//!
//! Validates a deterministic Digest response computed from
//! `HA1 = H(username:realm:password)`,
//! `HA2 = H(method:uri)`,
//! `response = H(HA1:nonce:nc:cnonce:qop:HA2)`.
//!
//! `H` is SHA-256 by default and MD5 when the origin pins
//! `algorithm: MD5`. RFC 7616 §3.3 deprecates MD5, so both lanes are
//! covered here: the default one an operator gets, and the legacy one a
//! stubborn upstream still needs.
//!
//! The provider also enforces the RFC 7616 §3.4 requirement that `nc`
//! strictly increases per nonce, so a captured `Authorization` header
//! cannot be replayed against the same proxy instance.
//!
//! We pre-compute both hash chains offline so the e2e crate does not
//! need an `md5` or `sha2` dependency. The test fixture is:
//!
//! ```text
//!   username  = testuser
//!   password  = testpass
//!   realm     = test-realm
//!   method    = GET
//!   uri       = /echo
//!   nonce     = testnonce123
//!   nc        = 00000001
//!   cnonce    = clientnonce
//!
//!   MD5 HA1      = MD5("testuser:test-realm:testpass")
//!                = a08a2d645fc2bc82dfd69fd8b9c41f79
//!   MD5 HA2      = MD5("GET:/echo")
//!                = 2976710a4f71e6099cf2c091923a85b5
//!   MD5 response = MD5("<HA1>:testnonce123:00000001:clientnonce:auth:<HA2>")
//!                = 5e711110ec6d8136d8ab0965427fd94f
//!
//!   SHA-256 HA1      = SHA-256("testuser:test-realm:testpass")
//!                    = 66e3cb6e0ad45f0c5df2ab838fa03f0d914a5d427879e0603383f548b047b4e2
//!   SHA-256 HA2      = SHA-256("GET:/echo")
//!                    = c592f0f82474740484648ad029120bfba8076355fa39801517fa744687f7155e
//!   SHA-256 response = SHA-256("<HA1>:testnonce123:00000001:clientnonce:auth:<HA2>")
//!                    = c289a27d541b77f105a1f7455df866aa392f23baf3071178502a487f7aff58db
//! ```
//!
//! The proxy's `digest` config stores the HA1 hash directly under the
//! `password` field (Go-compat: a map of `username -> ha1`), so the
//! plain password never appears on disk.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const MD5_HA1_TESTUSER: &str = "a08a2d645fc2bc82dfd69fd8b9c41f79";
const MD5_VALID_RESPONSE: &str = "5e711110ec6d8136d8ab0965427fd94f";

const SHA256_HA1_TESTUSER: &str =
    "66e3cb6e0ad45f0c5df2ab838fa03f0d914a5d427879e0603383f548b047b4e2";
const SHA256_VALID_RESPONSE: &str =
    "c289a27d541b77f105a1f7455df866aa392f23baf3071178502a487f7aff58db";

/// The default (SHA-256) origin. `algorithm:` is deliberately omitted so
/// the test pins what a config that says nothing actually gets.
fn sha256_config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "digest.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: digest
      realm: test-realm
      users:
        - username: testuser
          password: {SHA256_HA1_TESTUSER}
"#
    )
}

/// The legacy origin: MD5 pinned, with an MD5 HA1 table to match.
fn md5_config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "digest.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: digest
      realm: test-realm
      algorithm: MD5
      users:
        - username: testuser
          password: {MD5_HA1_TESTUSER}
"#
    )
}

fn digest_header(algorithm: &str, nc: &str, response: &str) -> String {
    format!(
        "Digest username=\"testuser\", realm=\"test-realm\", algorithm={algorithm}, \
         nonce=\"testnonce123\", uri=\"/echo\", qop=auth, \
         nc={nc}, cnonce=\"clientnonce\", response=\"{response}\""
    )
}

#[test]
fn valid_sha256_digest_response_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&sha256_config_yaml(&upstream.base_url())).expect("start");

    let header = digest_header("SHA-256", "00000001", SHA256_VALID_RESPONSE);
    let resp = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "a valid SHA-256 digest response should authorize"
    );
    assert!(!upstream.captured().is_empty());
}

#[test]
fn sha256_origin_refuses_an_md5_downgrade() {
    // RFC 7616 §3.3: the algorithm is negotiated in the challenge. A
    // client that answers a SHA-256 realm with MD5 must not be let in.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&sha256_config_yaml(&upstream.base_url())).expect("start");

    let header = digest_header("MD5", "00000001", MD5_VALID_RESPONSE);
    let resp = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(resp.status, 401, "an MD5 answer must not satisfy SHA-256");
    assert!(upstream.captured().is_empty());
}

#[test]
fn default_challenge_advertises_sha256() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&sha256_config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/echo", "digest.localhost").expect("send");
    assert_eq!(resp.status, 401);
    let challenge = resp
        .headers
        .get("www-authenticate")
        .map(String::as_str)
        .unwrap_or("");
    assert!(
        challenge.contains("algorithm=SHA-256"),
        "a config that omits `algorithm` must challenge with SHA-256: {challenge:?}"
    );
}

#[test]
fn valid_md5_digest_response_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&md5_config_yaml(&upstream.base_url())).expect("start");

    let header = digest_header("MD5", "00000001", MD5_VALID_RESPONSE);
    let resp = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "the pinned MD5 lane must keep authorizing"
    );
    assert!(!upstream.captured().is_empty());
}

#[test]
fn missing_credential_returns_401_with_challenge() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&md5_config_yaml(&upstream.base_url())).expect("start");

    let resp = harness.get("/echo", "digest.localhost").expect("send");
    assert_eq!(resp.status, 401);
    let challenge = resp
        .headers
        .get("www-authenticate")
        .map(String::as_str)
        .unwrap_or("");
    assert!(
        challenge.starts_with("Digest"),
        "expected Digest challenge, got: {challenge:?}"
    );
    assert!(
        challenge.contains("realm=\"test-realm\""),
        "challenge should advertise realm: {challenge:?}"
    );
    assert!(
        upstream.captured().is_empty(),
        "upstream must not see unauthenticated requests"
    );
}

#[test]
fn malformed_digest_response_returns_401() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&md5_config_yaml(&upstream.base_url())).expect("start");

    // Right shape, wrong response value.
    let header = digest_header("MD5", "00000001", "0000000000000000000000000000dead");
    let resp = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(resp.status, 401);
    assert!(upstream.captured().is_empty());
}

#[test]
fn replay_of_same_nonce_nc_is_rejected() {
    // RFC 7616 §3.4: replaying the same (nonce, nc) is a replay attack
    // and must be rejected. The provider tracks the high-water mark per
    // nonce and rejects any nc <= the seen value.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness =
        ProxyHarness::start_with_yaml(&sha256_config_yaml(&upstream.base_url())).expect("start");

    let header = digest_header("SHA-256", "00000001", SHA256_VALID_RESPONSE);

    // First submission: accepted.
    let first = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(first.status, 200, "first submission should be accepted");

    // Same (nonce, nc) replayed: must be rejected with 401.
    let replay = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(
        replay.status, 401,
        "replay of (nonce, nc) must be rejected per RFC 7616 §3.4"
    );
}
