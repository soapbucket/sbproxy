//! OIDC/JWT claim -> dynamic virtual-key mapping (WOR-1560).
//!
//! Local only; not in the required CI gate (project e2e policy). Boots the
//! release binary with `proxy.key_management.oidc_claim_map` and a `jwt` auth
//! provider on an AI origin whose upstream is a dead loopback port. A request
//! carrying a validated JWT (no `sk-` bearer) resolves its per-key policy
//! through the configured claim, so the mapped key's limits apply to the
//! verified identity. The dead upstream lets auth + key resolution be tested
//! without a real LLM: a request that resolves and passes the gate fails later
//! at the dead upstream, while a denied request never reaches it.

use std::net::TcpListener;
use std::time::Duration;

use jsonwebtoken::{encode, EncodingKey, Header};
use sbproxy_e2e::ProxyHarness;
use serde::Serialize;

const JWT_SECRET: &str = "shared-secret-abc";

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(admin_port: u16, dead_port: u16, store_path: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
  key_management:
    enabled: true
    store:
      backend: embedded
      path: {store_path}
    cache:
      ttl_secs: 60
    crypto:
      pepper: e2e-oidc-pepper
      master_key: e2e-oidc-master
    failure_mode_allow: false
    oidc_claim_map:
      claim_field: key_ref
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: sk-dummy
          base_url: "http://127.0.0.1:{dead_port}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini
    authentication:
      type: jwt
      secret: {JWT_SECRET}
      algorithms: [HS256]
"#
    )
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn admin_post(port: u16, path: &str, auth: &str, body: Option<&str>) -> (u16, String) {
    let mut req = client()
        .post(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", auth);
    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let resp = req.send().expect("admin POST");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: i64,
    key_ref: String,
}

/// Mint an HS256 JWT whose `key_ref` claim names `key_id`, signed with the
/// secret the proxy is configured to trust.
fn jwt_for(secret: &str, key_id: &str) -> String {
    encode(
        &Header::default(),
        &Claims {
            sub: "alice".to_string(),
            // Year 2286, so the token never starts flaking on a long-lived
            // release branch.
            exp: 9_999_999_999,
            key_ref: key_id.to_string(),
        },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .expect("jwt encode")
}

/// Send an AI request carrying `jwt` as the bearer and return the HTTP status.
fn ai_request(base_url: &str, jwt: &str) -> u16 {
    client()
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", "ai.localhost")
        .header("authorization", format!("Bearer {jwt}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .expect("ai request")
        .status()
        .as_u16()
}

#[test]
fn jwt_claim_resolves_a_key_and_enforces_its_rate_limit() {
    let admin_port = pick_port();
    let dead_port = pick_port();
    let store_path = format!(
        "{}/sbproxy_e2e_oidc_{}.redb",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&store_path);

    let proxy = ProxyHarness::start_with_yaml(&config(admin_port, dead_port, &store_path))
        .expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let base = proxy.base_url();

    // Mint a key capped at one request per minute.
    let (status, body) = admin_post(
        admin_port,
        "/admin/keys",
        &auth,
        Some(r#"{"name":"oidc","max_requests_per_minute":1}"#),
    );
    assert_eq!(status, 201, "mint key: {body}");
    let key_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["key"]["key_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A JWT whose `key_ref` claim names that key resolves to it (no `sk-`
    // bearer is sent), so the key's per-minute cap governs the JWT identity:
    // the first request passes the gate, the second is rate limited.
    let jwt = jwt_for(JWT_SECRET, &key_id);
    let first = ai_request(&base, &jwt);
    assert!(
        first != 401 && first != 429,
        "a valid JWT mapped to the key must pass the gate (got {first})"
    );
    assert_eq!(
        ai_request(&base, &jwt),
        429,
        "the OIDC-mapped key's rpm:1 limit must fire on the second request"
    );

    // A token signed with the wrong secret is rejected at the JWT gate before
    // any key resolution.
    let forged = jwt_for("attacker-secret", &key_id);
    assert_eq!(
        ai_request(&base, &forged),
        401,
        "a JWT signed with an untrusted secret must be 401"
    );

    let _ = std::fs::remove_file(&store_path);
}

/// Minimal standard base64 (avoids a crate dep), matching admin_endpoints.rs.
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
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPH[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(ALPH[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(ALPH[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}
