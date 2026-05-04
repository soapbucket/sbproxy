//! Per-JWT-claim rate limiting (F1.3).
//!
//! Confirms that two requests bearing JWTs that differ only in the
//! `tenant_id` claim land in separate token buckets, so tenant A's
//! traffic does not drain tenant B's budget.

use base64::Engine;
use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "api.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limiting
        requests_per_second: 5
        burst: 5
        key: "jwt.claims.tenant_id"
        headers:
          enabled: true
          include_retry_after: true
"#;

fn stub_jwt(tenant_id: &str) -> String {
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload = format!(r#"{{"sub":"alice","tenant_id":"{tenant_id}"}}"#);
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    format!("{header}.{body}.x")
}

#[test]
fn distinct_tenants_have_independent_buckets() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let auth_a = format!("Bearer {}", stub_jwt("tenant-a"));
    let auth_b = format!("Bearer {}", stub_jwt("tenant-b"));

    // Drain tenant A's bucket. burst=5 so >5 calls should reach 429.
    let mut saw_429_for_a = false;
    for _ in 0..30 {
        let resp = harness
            .get_with_headers("/", "api.localhost", &[("authorization", &auth_a)])
            .expect("send");
        if resp.status == 429 {
            saw_429_for_a = true;
            break;
        }
    }
    assert!(
        saw_429_for_a,
        "tenant A should be rate-limited after the burst"
    );

    // Tenant B's first request must still pass.
    let resp = harness
        .get_with_headers("/", "api.localhost", &[("authorization", &auth_b)])
        .expect("tenant b first");
    assert_eq!(
        resp.status, 200,
        "tenant B should not see tenant A's rate-limit"
    );
}

#[test]
fn missing_jwt_falls_back_to_client_ip_key() {
    // No Authorization header means jwt.claims.tenant_id evaluates to
    // empty / null, and the policy falls back to the default IP-based
    // key. This is the existing behavior we want to preserve.
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let mut saw_429 = false;
    for _ in 0..30 {
        let resp = harness.get("/", "api.localhost").expect("send");
        if resp.status == 429 {
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "fallback key path should still rate-limit");
}
