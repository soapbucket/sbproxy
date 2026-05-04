//! End-to-end coverage for the quote-token JWKS endpoint added in
//! `0bb1758` (Wave 3.1 closeout).
//!
//! The admin server publishes the public Ed25519 keys covering every
//! origin's `ai_crawl_control` quote-token signer at
//! `/.well-known/sbproxy/quote-keys.json`. External verifiers (the
//! ledger client and any agent SDK that wants to check a quote
//! before paying) fetch this document. Pinned by
//! `docs/adr-quote-token-jws.md` § "Key publication".
//!
//! Test cases:
//!   1. `jwks_endpoint_returns_200_with_unioned_kids` - two origins
//!      with distinct kids; assert both kids show up in the unioned
//!      JWKS body.
//!   2. `jwks_endpoint_skips_basic_auth_check` - admin server has
//!      basic-auth configured; the JWKS path is reached without
//!      credentials and still returns 200.
//!   3. `jwks_endpoint_returns_empty_when_no_ai_crawl_origins` -
//!      static-only config; assert `{"keys":[]}` (not 404).
//!   4. `jwks_endpoint_kids_change_on_reload` - reload swaps the
//!      signing key; assert the new kid appears in the JWKS.

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

// --- Helpers ---

fn pick_admin_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn admin_get(port: u16, path: &str, auth: Option<&str>) -> (u16, String) {
    let mut req = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
        .get(format!("http://127.0.0.1:{}{}", port, path));
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = req.send().expect("admin GET");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

/// Tiny base64 encoder so the test does not pull in an extra dep.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };
        out.push(ALPH[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPH[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(ALPH[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(ALPH[(b2 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

// --- Config builders ---

/// Two origins, each with a distinct quote-token signer. Used by the
/// "unions kids" test.
fn config_two_origins(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "alpha.test.sbproxy.dev":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "alpha"
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        valid_tokens: []
        rails:
          x402:
            chain: base
            facilitator: https://facilitator.example
            asset: USDC
            pay_to: "0xabc"
        quote_token:
          key_id: kid-alpha-2026
          seed_hex: "0001020304050607080910111213141516171819202122232425262728293031"
          issuer: "https://alpha.test.sbproxy.dev"
          default_ttl_seconds: 300
  "beta.test.sbproxy.dev":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "beta"
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        valid_tokens: []
        rails:
          x402:
            chain: base
            facilitator: https://facilitator.example
            asset: USDC
            pay_to: "0xdef"
        quote_token:
          key_id: kid-beta-2026
          seed_hex: "1112131415161718192021222324252627282930313233343536373839404142"
          issuer: "https://beta.test.sbproxy.dev"
          default_ttl_seconds: 300
"#
    )
}

/// Static-only config with no `ai_crawl_control` origins. Used by the
/// "empty body" test to assert the JWKS endpoint returns `{"keys":[]}`
/// rather than 404 when nothing has a signer.
fn config_no_ai_crawl(admin_port: u16) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "static.test.sbproxy.dev":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "static"
"#
    )
}

/// Single-origin config used by the reload test. `kid` is the kid we
/// expect in the JWKS document.
fn config_single_kid(admin_port: u16, kid: &str, seed_hex: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
origins:
  "alpha.test.sbproxy.dev":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "alpha"
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        valid_tokens: []
        rails:
          x402:
            chain: base
            facilitator: https://facilitator.example
            asset: USDC
            pay_to: "0xabc"
        quote_token:
          key_id: {kid}
          seed_hex: "{seed_hex}"
          issuer: "https://alpha.test.sbproxy.dev"
          default_ttl_seconds: 300
"#
    )
}

// --- Tests ---

#[test]
fn jwks_endpoint_returns_200_with_unioned_kids() {
    // Boot the proxy with two `ai_crawl_control` origins, each with a
    // distinct signing key. The admin JWKS endpoint must return both
    // kids in the unioned response.
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_two_origins(admin_port)).expect("start");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");

    let (status, body) = admin_get(admin_port, "/.well-known/sbproxy/quote-keys.json", None);
    assert_eq!(status, 200, "JWKS body: {body}");

    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JWKS parses as JSON");
    let keys = parsed
        .get("keys")
        .and_then(|v| v.as_array())
        .expect("`keys` array in body");
    let kids: BTreeSet<String> = keys
        .iter()
        .filter_map(|k| k.get("kid").and_then(|v| v.as_str()).map(String::from))
        .collect();
    assert!(
        kids.contains("kid-alpha-2026"),
        "alpha kid missing from {kids:?}"
    );
    assert!(
        kids.contains("kid-beta-2026"),
        "beta kid missing from {kids:?}"
    );

    // Pin the JWK shape the document advertises (see
    // adr-quote-token-jws.md § Key publication).
    for k in keys.iter() {
        assert_eq!(
            k.get("kty").and_then(|v| v.as_str()),
            Some("OKP"),
            "kty pin"
        );
        assert_eq!(
            k.get("crv").and_then(|v| v.as_str()),
            Some("Ed25519"),
            "crv pin"
        );
        assert_eq!(
            k.get("alg").and_then(|v| v.as_str()),
            Some("EdDSA"),
            "alg pin"
        );
        assert!(
            k.get("x").and_then(|v| v.as_str()).is_some(),
            "missing public-key bytes in entry: {k}"
        );
    }
}

#[test]
fn jwks_endpoint_skips_basic_auth_check() {
    // The admin server has basic-auth configured; the JWKS path must
    // bypass the auth gate because the public keys themselves are
    // public. A request without an Authorization header must NOT
    // receive 401.
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_two_origins(admin_port)).expect("start");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");

    // Probe other admin routes first to confirm the auth gate is wired:
    // an unauthenticated GET on `/api/health` must return 401. This
    // distinguishes "auth gate is off entirely" (which would be a
    // misconfig of the test, not a feature) from "auth gate is on but
    // JWKS bypasses it" (the wired behaviour).
    let (status_health_no_auth, _) = admin_get(admin_port, "/api/health", None);
    assert_eq!(
        status_health_no_auth, 401,
        "auth gate must reject /api/health without creds"
    );
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let (status_health_with_auth, _) = admin_get(admin_port, "/api/health", Some(&auth));
    assert_eq!(
        status_health_with_auth, 200,
        "auth gate must accept /api/health with creds"
    );

    // Now the actual assertion: JWKS path must answer without auth.
    let (status_jwks_no_auth, body) =
        admin_get(admin_port, "/.well-known/sbproxy/quote-keys.json", None);
    assert_ne!(
        status_jwks_no_auth, 401,
        "JWKS route must not require basic-auth credentials; body: {body}"
    );
    assert_eq!(status_jwks_no_auth, 200, "JWKS path returned: {body}");
}

#[test]
fn jwks_endpoint_returns_empty_when_no_ai_crawl_origins() {
    // Boot with a static-only config (no `ai_crawl_control` origins)
    // and assert the JWKS endpoint returns `{"keys":[]}` rather than
    // 404. The endpoint always exists; an empty body is the
    // correct shape for a deployment that does not (yet) sign quote
    // tokens.
    let admin_port = pick_admin_port();
    let _proxy = ProxyHarness::start_with_yaml(&config_no_ai_crawl(admin_port)).expect("start");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");

    let (status, body) = admin_get(admin_port, "/.well-known/sbproxy/quote-keys.json", None);
    assert_eq!(status, 200, "JWKS body: {body}");

    let parsed: serde_json::Value = serde_json::from_str(&body).expect("JWKS parses as JSON");
    let keys = parsed
        .get("keys")
        .and_then(|v| v.as_array())
        .expect("`keys` array present");
    assert!(
        keys.is_empty(),
        "expected empty keys array, got {} entries: {body}",
        keys.len()
    );
}

#[test]
fn jwks_endpoint_kids_change_on_reload() {
    // Boot with one signing key, capture the kid in the JWKS, then
    // reload the proxy with a different signing key and observe the
    // new kid in the JWKS document. The reload pattern is the same one
    // the admin_reload e2e test uses (rewrite_config + POST
    // /admin/reload).
    let admin_port = pick_admin_port();
    let proxy = ProxyHarness::start_with_yaml(&config_single_kid(
        admin_port,
        "kid-before-reload",
        "0001020304050607080910111213141516171819202122232425262728293031",
    ))
    .expect("start");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");

    // --- Capture pre-reload kid ---
    let (status, body) = admin_get(admin_port, "/.well-known/sbproxy/quote-keys.json", None);
    assert_eq!(status, 200, "pre-reload JWKS: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("pre-reload parses");
    let pre_kids: BTreeSet<String> = parsed
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|k| k.get("kid").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        pre_kids.contains("kid-before-reload"),
        "pre-reload missing kid: {pre_kids:?}"
    );

    // --- Trigger reload with a new signing key ---
    proxy
        .rewrite_config(&config_single_kid(
            admin_port,
            "kid-after-reload",
            "1112131415161718192021222324252627282930313233343536373839404142",
        ))
        .expect("rewrite config");

    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
        .post(format!("http://127.0.0.1:{}/admin/reload", admin_port))
        .header("authorization", auth.as_str())
        .send()
        .expect("POST /admin/reload");
    let reload_status = resp.status().as_u16();
    let reload_body = resp.text().unwrap_or_default();
    assert_eq!(reload_status, 200, "reload body: {reload_body}");

    // --- Capture post-reload kid ---
    let (status, body) = admin_get(admin_port, "/.well-known/sbproxy/quote-keys.json", None);
    assert_eq!(status, 200, "post-reload JWKS: {body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("post-reload parses");
    let post_kids: BTreeSet<String> = parsed
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|k| k.get("kid").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        post_kids.contains("kid-after-reload"),
        "post-reload missing new kid: {post_kids:?}"
    );
    assert!(
        !post_kids.contains("kid-before-reload"),
        "post-reload still carrying old kid: {post_kids:?}"
    );
}
