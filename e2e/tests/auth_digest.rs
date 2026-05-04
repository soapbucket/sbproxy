//! HTTP Digest authentication (RFC 7616).
//!
//! Validates a deterministic Digest response computed from
//! `HA1 = MD5(username:realm:password)`,
//! `HA2 = MD5(method:uri)`,
//! `response = MD5(HA1:nonce:nc:cnonce:qop:HA2)`.
//!
//! The provider also enforces the RFC 7616 §3.4 requirement that `nc`
//! strictly increases per nonce, so a captured `Authorization` header
//! cannot be replayed against the same proxy instance.
//!
//! We pre-compute the MD5 chain offline so the e2e crate does not
//! need an `md5` dependency. The test fixture is:
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
//!   HA1       = MD5("testuser:test-realm:testpass")
//!             = a08a2d645fc2bc82dfd69fd8b9c41f79
//!   HA2       = MD5("GET:/echo")
//!             = 2976710a4f71e6099cf2c091923a85b5
//!   response  = MD5("<HA1>:testnonce123:00000001:clientnonce:auth:<HA2>")
//!             = 5e711110ec6d8136d8ab0965427fd94f
//! ```
//!
//! The proxy's `digest` config stores the HA1 hash directly under the
//! `password` field (Go-compat: a map of `username -> ha1`), so the
//! plain password never appears on disk.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const HA1_TESTUSER: &str = "a08a2d645fc2bc82dfd69fd8b9c41f79";
const VALID_RESPONSE: &str = "5e711110ec6d8136d8ab0965427fd94f";

fn config_yaml(upstream_url: &str) -> String {
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
          password: {HA1_TESTUSER}
"#
    )
}

fn digest_header(nc: &str, response: &str) -> String {
    format!(
        "Digest username=\"testuser\", realm=\"test-realm\", \
         nonce=\"testnonce123\", uri=\"/echo\", qop=auth, \
         nc={nc}, cnonce=\"clientnonce\", response=\"{response}\""
    )
}

#[test]
fn valid_digest_response_returns_200() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let header = digest_header("00000001", VALID_RESPONSE);
    let resp = harness
        .get_with_headers("/echo", "digest.localhost", &[("authorization", &header)])
        .expect("send");
    assert_eq!(resp.status, 200, "valid digest response should authorize");
    assert!(!upstream.captured().is_empty());
}

#[test]
fn missing_credential_returns_401_with_challenge() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

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
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    // Right shape, wrong response value.
    let header = digest_header("00000001", "0000000000000000000000000000dead");
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
    let harness = ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start");

    let header = digest_header("00000001", VALID_RESPONSE);

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
