//! End-to-end coverage for the dynamic key lifecycle (WOR-1560).
//!
//! Local only; never added to the required CI gate (see the project policy on
//! e2e). Boots the release binary with `proxy.key_management:` enabled and an
//! AI origin whose upstream is a dead loopback port, so auth resolution can be
//! tested without a real LLM: a request that passes the virtual-key gate fails
//! later at the dead upstream (a 5xx), while a denied key is a 401/403 before
//! the upstream is ever called.

use std::net::TcpListener;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

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
      pepper: e2e-test-pepper
      master_key: e2e-test-master
    failure_mode_allow: false
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

/// Send an AI request carrying `token` and return the HTTP status.
fn ai_request(base_url: &str, token: &str) -> u16 {
    let resp = client()
        .post(format!("{base_url}/v1/chat/completions"))
        .header("host", "ai.localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .expect("ai request");
    resp.status().as_u16()
}

fn denied(status: u16) -> bool {
    status == 401 || status == 403
}

#[test]
fn key_lifecycle_mint_use_revoke_rotate() {
    let admin_port = pick_port();
    let dead_port = pick_port(); // closed -> upstream connection refused
    let store_path = format!(
        "{}/sbproxy_e2e_keymgmt_{}.redb",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&store_path);

    let proxy = ProxyHarness::start_with_yaml(&config(admin_port, dead_port, &store_path))
        .expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let base = proxy.base_url();

    // Mint a key; the plaintext token is returned exactly once.
    let (status, body) = admin_post(
        admin_port,
        "/admin/keys",
        &auth,
        Some(r#"{"name":"e2e","max_requests_per_minute":1000}"#),
    );
    assert_eq!(status, 201, "mint key: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let token = v["token"].as_str().unwrap().to_string();
    let key_id = v["key"]["key_id"].as_str().unwrap().to_string();
    assert!(token.starts_with("sk-"));
    assert!(
        !body.contains("secret_hash"),
        "response must not leak the hash"
    );

    // A valid key passes the virtual-key gate (then fails at the dead upstream).
    assert!(
        !denied(ai_request(&base, &token)),
        "a valid minted key must pass auth"
    );

    // A bogus virtual-key-shaped token is rejected at the gate.
    assert_eq!(
        ai_request(&base, "sk-bogus-secretsecret"),
        401,
        "an unknown key must be 401"
    );

    // Revoke -> the next request with that key is denied (instant revoke).
    let (status, body) = admin_post(
        admin_port,
        &format!("/admin/keys/{key_id}/revoke"),
        &auth,
        None,
    );
    assert_eq!(status, 200, "revoke: {body}");
    assert_eq!(
        ai_request(&base, &token),
        403,
        "a revoked key must be 403 on the next request"
    );

    // Rotate a fresh key: both the old and new tokens pass the gate during the
    // grace window.
    let (status, body) = admin_post(admin_port, "/admin/keys", &auth, Some(r#"{"name":"rot"}"#));
    assert_eq!(status, 201, "mint rotate key: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let old_token = v["token"].as_str().unwrap().to_string();
    let rot_id = v["key"]["key_id"].as_str().unwrap().to_string();

    let (status, body) = admin_post(
        admin_port,
        &format!("/admin/keys/{rot_id}/rotate"),
        &auth,
        Some(r#"{"grace_secs":300}"#),
    );
    assert_eq!(status, 200, "rotate: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let new_token = v["token"].as_str().unwrap().to_string();

    assert!(
        !denied(ai_request(&base, &old_token)),
        "the prior token must still pass auth inside the grace window"
    );
    assert!(
        !denied(ai_request(&base, &new_token)),
        "the rotated token must pass auth"
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
