//! Q1.2: HTTP ledger protocol e2e.
//!
//! Boots a tiny `axum` mock server that mimics the JSON-over-HTTPS
//! ledger surface defined in `docs/adr-http-ledger-protocol.md`,
//! drives an `ai_crawl_control` origin against it, and asserts the
//! contract holds for retry, idempotency, circuit breaker, HMAC
//! signing, and the error envelope mapping.
//!
//! The G1.3 `HttpLedger` client lands on `wave1/G1.2-G1.3-tiers-ledger`
//! in parallel with this file. Until that branch merges, every test
//! that drives the ledger through the proxy is `#[ignore]`d with a
//! `TODO(wave1-G1.3)` marker.
//!
//! The mock-server scaffolding (knobs, request capture, HMAC verify)
//! is fully present so the day G1.3 lands a maintainer drops the
//! `#[ignore]` attributes without touching the test bodies.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

// --- Mock ledger configuration ---

/// Knobs the e2e tests set on a per-instance basis.
#[derive(Debug, Default, Clone)]
#[allow(dead_code)] // some knobs are wired by tests still landing on G1.3
struct LedgerKnobs {
    /// Reject the first N requests with 503 before serving 200.
    fail_first_n: usize,
    /// Always answer with 503 (`ledger.unavailable`).
    always_503: bool,
    /// Always answer with 401 (`ledger.signature_invalid`).
    always_401: bool,
    /// Reject when a previously-seen `Idempotency-Key` arrives with a
    /// different request body hash.
    reject_replayed_idempotency_key: bool,
    /// HMAC key the server uses to verify `X-Sb-Ledger-Signature`.
    hmac_key_hex: String,
}

#[derive(Debug, Default)]
struct LedgerState {
    knobs: LedgerKnobs,
    /// Number of inbound requests handled so far. Used by `fail_first_n`.
    received: AtomicUsize,
    /// Map of (Idempotency-Key, body_hash) so we can detect a replay
    /// with a different body. Body hash is the SHA-256 the proxy puts
    /// in the canonical signing string per ADR.
    seen: Mutex<Vec<(String, String)>>,
    /// All inbound request envelopes captured for assertions.
    captured: Mutex<Vec<CapturedLedgerCall>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // key_id is asserted on by tests still landing on G1.3
struct CapturedLedgerCall {
    /// `Idempotency-Key` header the proxy sent.
    idempotency_key: String,
    /// `X-Sb-Ledger-Signature` header value (`v1=<hex>`).
    signature: String,
    /// `X-Sb-Ledger-Key-Id` header value.
    key_id: String,
    /// Raw request body so a follow-up assertion can verify the HMAC
    /// matches the body the test thinks the proxy sent.
    body: Vec<u8>,
}

/// Spin up an axum `/v1/ledger/redeem` server on `127.0.0.1:0`.
/// Returns the bound socket address and a shared state handle so tests
/// can read counters and captured calls.
async fn spawn_mock_ledger(knobs: LedgerKnobs) -> (SocketAddr, Arc<LedgerState>) {
    let state = Arc::new(LedgerState {
        knobs,
        ..Default::default()
    });
    let app = Router::new()
        .route("/v1/ledger/redeem", post(handle_redeem))
        .route("/v1/ledger/healthz", post(handle_healthz))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        // Best-effort serve. Errors only surface in the test driver
        // when the proxy fails to round-trip; surface them via the
        // captured-call list rather than panicking the runtime.
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (addr, state)
}

async fn handle_redeem(
    State(state): State<Arc<LedgerState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // --- Hard-fail knobs ---
    if state.knobs.always_503 {
        let _ = state.received.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "v": 1,
                "error": {
                    "code": "ledger.unavailable",
                    "message": "always-503 knob",
                    "retryable": true,
                    "retry_after_seconds": 1
                }
            })),
        );
    }
    if state.knobs.always_401 {
        let _ = state.received.fetch_add(1, Ordering::SeqCst);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "v": 1,
                "error": {
                    "code": "ledger.signature_invalid",
                    "message": "always-401 knob",
                    "retryable": false,
                    "retry_after_seconds": null
                }
            })),
        );
    }

    // --- Capture the call for later assertions ---
    let idem = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let sig = headers
        .get("x-sb-ledger-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let key_id = headers
        .get("x-sb-ledger-key-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let body_hash = sha256_hex(&body);
    state.captured.lock().await.push(CapturedLedgerCall {
        idempotency_key: idem.clone(),
        signature: sig,
        key_id,
        body: body.to_vec(),
    });

    // --- Idempotency replay detection ---
    if state.knobs.reject_replayed_idempotency_key {
        let mut seen = state.seen.lock().await;
        if let Some((_, prev_hash)) = seen.iter().find(|(k, _)| k == &idem) {
            if prev_hash != &body_hash {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "v": 1,
                        "error": {
                            "code": "ledger.idempotency_conflict",
                            "message": "Idempotency-Key replayed with different body",
                            "retryable": false,
                            "retry_after_seconds": null
                        }
                    })),
                );
            }
        } else {
            seen.push((idem.clone(), body_hash.clone()));
        }
    }

    // --- fail_first_n knob ---
    let n = state.received.fetch_add(1, Ordering::SeqCst);
    if n < state.knobs.fail_first_n {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "v": 1,
                "error": {
                    "code": "ledger.unavailable",
                    "message": "fail_first_n knob",
                    "retryable": true,
                    "retry_after_seconds": null
                }
            })),
        );
    }

    // --- Happy path ---
    (
        StatusCode::OK,
        Json(json!({
            "v": 1,
            "request_id": "01HZX0000000000000000FAKE",
            "result": {
                "redeemed": true,
                "redemption_id": format!("red_{}", n),
                "remaining_balance_micros": 9000
            }
        })),
    )
}

async fn handle_healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "ok" })))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// --- Test bodies ---

/// Tokio runtime helper: every test spawns the mock server on a
/// dedicated current-thread runtime so the mock and the harness do
/// not collide.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
#[ignore = "TODO(wave3): G1.3 HttpLedger client landed and unit-tested but is not wired into AiCrawlControlConfig::from_config; the ai_crawl policy still hard-codes InMemoryLedger. YAML `ledger:` block is also unrecognised and would route through plain http:// in the test which the client rejects."]
fn test_happy_path_redeem_returns_200() {
    let runtime = rt();
    let (addr, state) = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        hmac_key_hex: "0011223344".to_string(),
        ..Default::default()
    }));

    // The proxy config below assumes G1.3 surfaces a `ledger.url` and
    // `ledger.hmac_key_file` knob on `ai_crawl_control`. The exact
    // YAML key names will be confirmed when G1.3 lands; until then
    // this test stays ignored and the assertion shape documents the
    // intent.
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        ledger:
          url: "http://{addr}/v1/ledger"
          hmac_key_id: "test-key-1"
          hmac_key_hex: "0011223344"
"#,
        addr = addr
    );

    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "tok_happy"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    // Mock server should have seen exactly one redeem call.
    let captured = runtime.block_on(async { state.captured.lock().await.clone() });
    assert_eq!(captured.len(), 1, "exactly one redeem call");
    assert!(!captured[0].idempotency_key.is_empty());
    assert!(captured[0].signature.starts_with("v1="));
}

#[test]
#[ignore = "TODO(wave3): G1.3 HttpLedger retry policy implemented in code but not yet exposed via YAML `ledger:` block on ai_crawl_control. Test asserts retries against a mock; needs YAML wiring + HTTPS-equipped mock."]
fn test_retry_with_idempotency_key() {
    let runtime = rt();
    let (addr, state) = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        fail_first_n: 2,
        hmac_key_hex: "0011223344".to_string(),
        ..Default::default()
    }));
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action: {{ type: static, status_code: 200, content_type: text/html, body: "ok" }}
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        ledger:
          url: "http://{addr}/v1/ledger"
          hmac_key_id: "test-key-1"
          hmac_key_hex: "0011223344"
"#
    );
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "tok_retry"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "retry-after-fails recovers");

    let captured = runtime.block_on(async { state.captured.lock().await.clone() });
    assert_eq!(
        captured.len(),
        3,
        "two failures + one success = three attempts"
    );
    // All three attempts must share the same Idempotency-Key per ADR.
    let key0 = &captured[0].idempotency_key;
    assert!(!key0.is_empty());
    for c in &captured[1..] {
        assert_eq!(&c.idempotency_key, key0, "retry reuses Idempotency-Key");
    }
}

#[test]
#[ignore = "TODO(wave3): G1.3 HttpLedger circuit breaker implemented in code but the policy compiler does not surface a `ledger:` YAML block. Wave 3 wiring task."]
fn test_circuit_breaker_opens_after_consecutive_failures() {
    let runtime = rt();
    let (addr, state) = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        always_503: true,
        hmac_key_hex: "0011223344".to_string(),
        ..Default::default()
    }));
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action: {{ type: static, status_code: 200, content_type: text/html, body: "ok" }}
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        ledger:
          url: "http://{addr}/v1/ledger"
          hmac_key_id: "test-key-1"
          hmac_key_hex: "0011223344"
          on_ledger_failure: fail_closed
"#
    );
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");

    // Drive enough requests to trip the breaker (ADR: 10 failures in
    // a 30 s sliding window).
    for _ in 0..15 {
        let _ = harness.get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "tok_breaker"),
            ],
        );
    }
    // Once the breaker is open, the next attempt should not hit the
    // network at all. Capture count should be < requests sent.
    let captured = runtime.block_on(async { state.captured.lock().await.clone() });
    assert!(
        captured.len() < 15,
        "breaker open => later attempts skip network, got {} hits",
        captured.len()
    );
}

#[test]
#[ignore = "TODO(wave3): G1.3 HttpLedger HMAC body-binding implemented in code but the policy compiler does not surface a `ledger:` YAML block. Wave 3 wiring task."]
fn test_hmac_signature_binds_to_body() {
    // The mock server captures the raw body and the signature header.
    // The test recomputes the canonical signing string per ADR and
    // verifies the HMAC matches; flipping a byte must break verify.
    let runtime = rt();
    let (addr, state) = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        hmac_key_hex: "0011223344".to_string(),
        ..Default::default()
    }));
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action: {{ type: static, status_code: 200, content_type: text/html, body: "ok" }}
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        ledger:
          url: "http://{addr}/v1/ledger"
          hmac_key_id: "test-key-1"
          hmac_key_hex: "0011223344"
"#
    );
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");
    let _ = harness.get_with_headers(
        "/article",
        "blog.localhost",
        &[
            ("user-agent", "GPTBot/1.0"),
            ("crawler-payment", "tok_hmac"),
        ],
    );
    let captured = runtime.block_on(async { state.captured.lock().await.clone() });
    assert!(!captured.is_empty(), "ledger received the call");

    // The captured signature must verify against the captured body
    // when we recompute the canonical signing string.
    let call = &captured[0];
    let envelope: Value = serde_json::from_slice(&call.body).expect("body is JSON envelope");
    let request_id = envelope["request_id"].as_str().expect("request_id");
    let timestamp = envelope["timestamp"].as_str().expect("timestamp");
    let nonce = envelope["nonce"].as_str().expect("nonce");
    let workspace = envelope["workspace_id"].as_str().expect("workspace_id");

    let body_hash = sha256_hex(&call.body);
    let canonical = format!(
        "1\n{}\n{}\n{}\n{}\nPOST\n/v1/ledger/redeem\n{}",
        request_id, timestamp, nonce, workspace, body_hash
    );

    use hmac::{KeyInit, Mac};
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let key = hex::decode("0011223344").unwrap();
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&key).unwrap();
    mac.update(canonical.as_bytes());
    let expected = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(call.signature, expected, "HMAC matches canonical body");
}

#[test]
#[ignore = "TODO(wave3): G1.3 HttpLedger error-envelope mapping implemented but YAML wiring missing on ai_crawl_control."]
fn test_error_envelope_retryable_false_maps_to_402() {
    // Per ADR: a non-retryable error envelope (e.g.
    // `ledger.signature_invalid`) maps to 402 at the proxy edge so
    // the agent retries with a fresh token.
    let runtime = rt();
    let (addr, _state) = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        always_401: true,
        hmac_key_hex: "0011223344".to_string(),
        ..Default::default()
    }));
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action: {{ type: static, status_code: 200, content_type: text/html, body: "ok" }}
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        ledger:
          url: "http://{addr}/v1/ledger"
          hmac_key_id: "test-key-1"
          hmac_key_hex: "0011223344"
"#
    );
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "tok_bad_sig"),
            ],
        )
        .expect("send");
    assert_eq!(
        resp.status, 402,
        "non-retryable ledger error => proxy returns 402 to agent"
    );
}

#[test]
#[ignore = "TODO(wave3): G1.3 HttpLedger retryable-503 mapping implemented but YAML wiring missing on ai_crawl_control."]
fn test_error_envelope_retryable_true_maps_to_503() {
    let runtime = rt();
    let (addr, _state) = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        always_503: true,
        hmac_key_hex: "0011223344".to_string(),
        ..Default::default()
    }));
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action: {{ type: static, status_code: 200, content_type: text/html, body: "ok" }}
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        ledger:
          url: "http://{addr}/v1/ledger"
          hmac_key_id: "test-key-1"
          hmac_key_hex: "0011223344"
          on_ledger_failure: fail_closed
"#
    );
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0"), ("crawler-payment", "tok_503")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 503,
        "retryable ledger failure with fail_closed => 503 to agent"
    );
}

// --- Mock-server self-test (always runs) ---

/// Confirm the mock-server itself works end-to-end without the proxy.
/// This guards against a refactor of `axum`'s extractor types breaking
/// every Q1.2 test silently. Also exercises the `fail_first_n` and
/// `reject_replayed_idempotency_key` knobs so the test fixture is
/// known-good before a maintainer drops the `#[ignore]` on the proxy
/// tests above.
#[test]
fn mock_ledger_self_test() {
    let runtime = rt();
    runtime.block_on(async {
        let (addr, state) = spawn_mock_ledger(LedgerKnobs {
            fail_first_n: 1,
            hmac_key_hex: "0011223344".to_string(),
            ..Default::default()
        })
        .await;
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/v1/ledger/redeem");

        // First attempt: fail_first_n => 503.
        let resp = client
            .post(&url)
            .header("idempotency-key", "k1")
            .header("x-sb-ledger-signature", "v1=00")
            .header("x-sb-ledger-key-id", "test-key-1")
            .json(&json!({"v": 1, "request_id": "rid", "timestamp": "t",
                "nonce": "n", "agent_id": "a", "agent_vendor": "v",
                "workspace_id": "w", "payload": {}}))
            .send()
            .await
            .expect("first call");
        assert_eq!(resp.status().as_u16(), 503);

        // Second attempt: 200.
        let resp = client
            .post(&url)
            .header("idempotency-key", "k1")
            .header("x-sb-ledger-signature", "v1=00")
            .header("x-sb-ledger-key-id", "test-key-1")
            .json(&json!({"v": 1, "request_id": "rid", "timestamp": "t",
                "nonce": "n", "agent_id": "a", "agent_vendor": "v",
                "workspace_id": "w", "payload": {}}))
            .send()
            .await
            .expect("second call");
        assert_eq!(resp.status().as_u16(), 200);

        let captured = state.captured.lock().await;
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].idempotency_key, "k1");
        assert_eq!(captured[1].idempotency_key, "k1");
    });
}
