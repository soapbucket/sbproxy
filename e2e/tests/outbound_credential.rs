//! Outbound credential resolver wiring (WOR-802 PR2).
//!
//! Verifies the proxy mints/resolves a per-upstream credential and
//! stamps it on the request it sends upstream, with no client-side
//! credential handling:
//! - two origins with `vault_secret` credentials send distinct headers
//!   to their respective upstreams (request to A gets cred A, B gets B);
//! - a `token_exchange` origin exchanges the inbound bearer at a token
//!   endpoint and forwards the minted token, not the inbound one.

use base64::Engine as _;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

const VAULT_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "a.localhost":
    action:
      type: proxy
      url: "UPSTREAM_A"
    outbound_credential:
      type: vault_secret
      secret: "secret-for-A"
      header: "x-api-key"
      scheme: ""
  "b.localhost":
    action:
      type: proxy
      url: "UPSTREAM_B"
    outbound_credential:
      type: vault_secret
      secret: "secret-for-B"
      header: "x-api-key"
      scheme: ""
"#;

#[test]
fn per_upstream_credentials_are_distinct() {
    let upstream_a = MockUpstream::start(json!({"ok": "a"})).expect("upstream a");
    let upstream_b = MockUpstream::start(json!({"ok": "b"})).expect("upstream b");
    let yaml = VAULT_CONFIG
        .replace("UPSTREAM_A", &upstream_a.base_url())
        .replace("UPSTREAM_B", &upstream_b.base_url());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let ra = proxy.get("/", "a.localhost").expect("call a");
    assert_eq!(ra.status, 200);
    let rb = proxy.get("/", "b.localhost").expect("call b");
    assert_eq!(rb.status, 200);

    let seen_a = upstream_a.captured();
    let seen_b = upstream_b.captured();
    assert!(!seen_a.is_empty() && !seen_b.is_empty());
    assert_eq!(
        seen_a[0].headers.get("x-api-key").map(String::as_str),
        Some("secret-for-A"),
        "upstream A must receive credential A; got {:?}",
        seen_a[0].headers.get("x-api-key")
    );
    assert_eq!(
        seen_b[0].headers.get("x-api-key").map(String::as_str),
        Some("secret-for-B"),
        "upstream B must receive credential B; got {:?}",
        seen_b[0].headers.get("x-api-key")
    );
}

fn jwt(claims: serde_json::Value) -> String {
    let b64 = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    format!(
        "{}.{}.sig",
        b64(&json!({"alg": "none", "typ": "JWT"})),
        b64(&claims)
    )
}

#[test]
fn token_exchange_mints_and_replaces_inbound_token() {
    // The token endpoint returns a minted access token; the app
    // upstream must receive that minted token, not the inbound bearer.
    let token_endpoint = MockUpstream::start(json!({
        "access_token": "minted-token-xyz",
        "token_type": "Bearer",
        "expires_in": 3600
    }))
    .expect("token endpoint");
    let app = MockUpstream::start(json!({"ok": true})).expect("app upstream");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "api.localhost":
    action:
      type: proxy
      url: "{app}"
    outbound_credential:
      type: token_exchange
      token_endpoint: "{token}"
      audience: "https://api.example.com"
      allowed_audiences: ["https://api.example.com"]
"#,
        app = app.base_url(),
        token = token_endpoint.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let subject = jwt(json!({"iss": "https://issuer", "sub": "user-1"}));
    let resp = proxy
        .get_with_headers(
            "/data",
            "api.localhost",
            &[("authorization", &format!("Bearer {subject}"))],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let seen = app.captured();
    assert!(!seen.is_empty(), "app upstream should be called");
    assert_eq!(
        seen[0].headers.get("authorization").map(String::as_str),
        Some("Bearer minted-token-xyz"),
        "app upstream must receive the minted token, not the inbound one; got {:?}",
        seen[0].headers.get("authorization")
    );
    // The token endpoint was actually called to mint.
    assert!(
        !token_endpoint.captured().is_empty(),
        "token endpoint should be called for the exchange"
    );
}
