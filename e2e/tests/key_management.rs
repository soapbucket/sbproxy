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

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

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
    // grace window; once the window closes only the new token works. The grace
    // is deliberately short (2 s) so the post-grace half of the contract is
    // covered without slowing the suite.
    let (status, body) = admin_post(admin_port, "/admin/keys", &auth, Some(r#"{"name":"rot"}"#));
    assert_eq!(status, 201, "mint rotate key: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let old_token = v["token"].as_str().unwrap().to_string();
    let rot_id = v["key"]["key_id"].as_str().unwrap().to_string();

    let (status, body) = admin_post(
        admin_port,
        &format!("/admin/keys/{rot_id}/rotate"),
        &auth,
        Some(r#"{"grace_secs":2}"#),
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

    // Let the grace window lapse: the prior secret's hash is still stored but
    // past prev_hash_expires_at, so it must verify-fail like a wrong secret.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        ai_request(&base, &old_token),
        401,
        "the prior token must be rejected once the grace window closes"
    );
    assert!(
        !denied(ai_request(&base, &new_token)),
        "the rotated token must keep passing after the grace window closes"
    );

    let _ = std::fs::remove_file(&store_path);
}

/// Expiry, block/unblock, and per-key rate limiting all gate at auth time,
/// before the dead upstream is reached.
#[test]
fn key_expiry_block_and_rate_limit() {
    let admin_port = pick_port();
    let dead_port = pick_port();
    let store_path = format!(
        "{}/sbproxy_e2e_keymgmt_gate_{}.redb",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&store_path);

    let proxy = ProxyHarness::start_with_yaml(&config(admin_port, dead_port, &store_path))
        .expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let base = proxy.base_url();

    // Expiry: a key whose expires_at is in the past is denied immediately.
    let (status, body) = admin_post(
        admin_port,
        "/admin/keys",
        &auth,
        Some(r#"{"name":"expired","expires_at":"2020-01-01T00:00:00Z"}"#),
    );
    assert_eq!(status, 201, "mint expired key: {body}");
    let exp_token = serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        denied(ai_request(&base, &exp_token)),
        "a key past its expires_at must be denied"
    );

    // Block / unblock: a blocked key is denied; unblocking restores access.
    let (status, body) = admin_post(admin_port, "/admin/keys", &auth, Some(r#"{"name":"blk"}"#));
    assert_eq!(status, 201, "mint block key: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let blk_token = v["token"].as_str().unwrap().to_string();
    let blk_id = v["key"]["key_id"].as_str().unwrap().to_string();
    assert!(
        !denied(ai_request(&base, &blk_token)),
        "a fresh key must pass auth"
    );
    let (status, body) = admin_post(
        admin_port,
        &format!("/admin/keys/{blk_id}/block"),
        &auth,
        None,
    );
    assert_eq!(status, 200, "block: {body}");
    assert_eq!(
        ai_request(&base, &blk_token),
        403,
        "a blocked key must be 403"
    );
    let (status, body) = admin_post(
        admin_port,
        &format!("/admin/keys/{blk_id}/unblock"),
        &auth,
        None,
    );
    assert_eq!(status, 200, "unblock: {body}");
    assert!(
        !denied(ai_request(&base, &blk_token)),
        "an unblocked key must pass auth again"
    );

    // Rate limit: a key capped at 1 request/minute returns 429 on the second
    // call within the window (the gate runs before the upstream).
    let (status, body) = admin_post(
        admin_port,
        "/admin/keys",
        &auth,
        Some(r#"{"name":"rl","max_requests_per_minute":1}"#),
    );
    assert_eq!(status, 201, "mint rate-limited key: {body}");
    let rl_token = serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let first = ai_request(&base, &rl_token);
    assert!(
        !denied(first) && first != 429,
        "the first request must pass the gate (got {first})"
    );
    assert_eq!(
        ai_request(&base, &rl_token),
        429,
        "the second request within the minute must be 429"
    );

    let _ = std::fs::remove_file(&store_path);
}

/// Per-key budget: spend recorded from upstream `usage` blocks accrues against
/// the `api_key` budget scope, and once the cap is crossed the next request on
/// the same key blocks with 402 while a different key's bucket stays clean.
#[test]
fn key_budget_spend_accrues_and_cap_blocks() {
    let admin_port = pick_port();
    let store_path = format!(
        "{}/sbproxy_e2e_keymgmt_budget_{}.redb",
        std::env::temp_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_file(&store_path);

    // A live mock provider reporting 1000+1000 tokens per call, far over the
    // 100-token per-key cap below, so one successful call exhausts a bucket.
    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 1000,
            "total_tokens": 2000,
        }
    }))
    .unwrap();

    let yaml = format!(
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
      pepper: e2e-budget-pepper
      master_key: e2e-budget-master
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: sk-dummy
          base_url: "{upstream_base}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini
      budget:
        on_exceed: block
        limits:
          - scope: api_key
            max_tokens: 100
"#,
        upstream_base = upstream.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port to bind");
    let auth = format!("Basic {}", base64_encode("admin:secret"));
    let base = proxy.base_url();

    let mint = |name: &str| -> String {
        let (status, body) = admin_post(
            admin_port,
            "/admin/keys",
            &auth,
            Some(&format!(r#"{{"name":"{name}"}}"#)),
        );
        assert_eq!(status, 201, "mint {name}: {body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let token_a = mint("budget-a");
    let token_b = mint("budget-b");

    // First request on key A passes (its bucket starts empty) and the mock's
    // usage block debits 2000 tokens against key A's scope.
    assert_eq!(
        ai_request(&base, &token_a),
        200,
        "the first request on key A must pass and record spend"
    );

    // Second request on key A: its bucket is over the 100-token cap, so the
    // pre-dispatch gate must block with 402 before the upstream is reached.
    let calls_before = upstream.captured().len();
    assert_eq!(
        ai_request(&base, &token_a),
        402,
        "key A must be blocked once its budget cap is exceeded"
    );
    assert_eq!(
        upstream.captured().len(),
        calls_before,
        "a budget-blocked request must not reach the upstream"
    );

    // Key B holds its own bucket: the cap firing on A must not bleed over.
    assert_eq!(
        ai_request(&base, &token_b),
        200,
        "key B's budget bucket must be independent of key A's"
    );

    let _ = std::fs::remove_file(&store_path);
}

/// Build a config whose key store is a Redis backend pointing at a dead
/// loopback port, so every store lookup errors. `failure_mode_allow` decides
/// whether a virtual-key-shaped token is denied (fail-closed default) or the
/// request degrades through to the upstream.
fn store_outage_config(dead_redis_port: u16, upstream_base: &str, allow: bool) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  key_management:
    enabled: true
    store:
      backend: redis
      url: "redis://127.0.0.1:{dead_redis_port}"
    cache:
      ttl_secs: 60
    crypto:
      pepper: e2e-outage-pepper
      master_key: e2e-outage-master
    failure_mode_allow: {allow}
origins:
  "ai.localhost":
    action:
      type: ai_proxy
      providers:
        - name: openai
          api_key: sk-dummy
          base_url: "{upstream_base}"
          allow_private_base_url: true
          default_model: gpt-4o-mini
          models:
            - gpt-4o-mini
"#
    )
}

/// Fail-closed (the default): with the store unreachable, a virtual-key-shaped
/// bearer is denied with 503 before the upstream is reached.
#[test]
fn store_outage_fails_closed_by_default() {
    let dead_redis_port = pick_port(); // nothing listens here
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();

    let proxy = ProxyHarness::start_with_yaml(&store_outage_config(
        dead_redis_port,
        &upstream.base_url(),
        false,
    ))
    .expect("start proxy");
    let base = proxy.base_url();

    assert_eq!(
        ai_request(&base, "sk-unknown-secretsecret"),
        503,
        "an unresolvable key must be denied when the store is down (fail-closed)"
    );
    assert!(
        upstream.captured().is_empty(),
        "a fail-closed denial must not reach the upstream"
    );
}

/// `failure_mode_allow: true`: the same outage lets the request through in
/// degraded mode (no per-key policy) instead of denying.
#[test]
fn store_outage_failure_mode_allow_passes_through() {
    let dead_redis_port = pick_port();
    let upstream = MockUpstream::start(json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o-mini",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    }))
    .unwrap();

    let proxy = ProxyHarness::start_with_yaml(&store_outage_config(
        dead_redis_port,
        &upstream.base_url(),
        true,
    ))
    .expect("start proxy");
    let base = proxy.base_url();

    assert_eq!(
        ai_request(&base, "sk-unknown-secretsecret"),
        200,
        "failure_mode_allow must let the request through during a store outage"
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "the degraded request must reach the upstream"
    );
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
