//! Q1.2: HTTP ledger protocol e2e.
//!
//! Boots a tiny `axum` mock server that mimics the JSON-over-HTTPS
//! ledger protocol,
//! drives an `ai_crawl_control` origin against it, and asserts the
//! contract holds for retry, idempotency, circuit breaker, HMAC
//! signing, and the error envelope mapping.
//!
//! Each mock owns an ephemeral private CA and a CA-signed server
//! certificate whose SAN covers `127.0.0.1`. The proxy receives that CA
//! through `ledger.trust_roots`, exercising the same certificate
//! verification path private production ledgers use.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

// --- Mock ledger configuration ---

/// Knobs the e2e tests set on a per-instance basis.
#[derive(Debug, Default, Clone)]
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

/// Handle to an HTTPS mock ledger and its private trust root.
struct MockLedger {
    addr: SocketAddr,
    state: Arc<LedgerState>,
    root_pem: String,
}

/// Spin up an HTTPS axum `/v1/ledger/redeem` server on
/// `127.0.0.1:0`. The leaf is signed by a fresh private CA and carries
/// an IP SAN for the exact address used by the tests.
async fn spawn_mock_ledger(knobs: LedgerKnobs) -> MockLedger {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let state = Arc::new(LedgerState {
        knobs,
        ..Default::default()
    });
    let app = Router::new()
        .route("/v1/ledger/redeem", post(handle_redeem))
        .route("/v1/ledger/healthz", post(handle_healthz))
        .with_state(state.clone());

    let ca_key = KeyPair::generate().expect("generate ledger test CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ledger CA params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "sbproxy ledger test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign test CA");

    let leaf_key = KeyPair::generate().expect("generate ledger TLS key");
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).expect("ledger leaf params");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "sbproxy ledger test server");
    leaf_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("sign ledger TLS certificate");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let tls_config = RustlsConfig::from_pem(
        leaf_cert.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("ledger rustls config");
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls_config)
            .serve(app.into_make_service())
            .await;
    });

    let root_pem = ca_cert.pem();
    let root = reqwest::Certificate::from_pem(root_pem.as_bytes()).expect("parse test CA");
    let probe_client = reqwest::Client::builder()
        .add_root_certificate(root)
        .build()
        .expect("build ledger readiness client");
    let health_url = format!("https://{addr}/v1/ledger/healthz");
    let mut ready = false;
    for _ in 0..100 {
        if probe_client
            .post(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(ready, "HTTPS mock ledger did not become ready");

    MockLedger {
        addr,
        state,
        root_pem,
    }
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

/// Tokio runtime helper. The TLS accept loop must keep making progress
/// while the test thread blocks in the synchronous proxy harness.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn proxy_config(mock_ledger: &MockLedger) -> String {
    let indented_root = mock_ledger
        .root_pem
        .lines()
        .map(|line| format!("              {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
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
          url: "https://127.0.0.1:{port}"
          key_id: "test-key-1"
          key_hex: "0011223344"
          timeout_ms: 1000
          trust_roots:
            - |
{indented_root}
"#,
        port = mock_ledger.addr.port()
    )
}

fn breaker_proxy_config(mock_ledger: &MockLedger) -> String {
    let mut config = proxy_config(mock_ledger);
    config.push_str(
        r#"          retry:
            max_attempts: 1
          breaker:
            failure_threshold: 2
            success_threshold: 1
            open_duration_ms: 60000
"#,
    );
    config
}

#[test]
fn test_happy_path_redeem_returns_200() {
    let runtime = rt();
    let mock = runtime.block_on(spawn_mock_ledger(LedgerKnobs::default()));
    let config = proxy_config(&mock);

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
    let captured = runtime.block_on(async { mock.state.captured.lock().await.clone() });
    assert_eq!(captured.len(), 1, "exactly one redeem call");
    assert!(!captured[0].idempotency_key.is_empty());
    assert!(captured[0].signature.starts_with("v1="));
    assert_eq!(captured[0].key_id, "test-key-1");
}

#[test]
fn test_retry_with_idempotency_key() {
    let runtime = rt();
    let mock = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        fail_first_n: 2,
        reject_replayed_idempotency_key: true,
        ..Default::default()
    }));
    let config = proxy_config(&mock);
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

    let captured = runtime.block_on(async { mock.state.captured.lock().await.clone() });
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
fn test_circuit_breaker_opens_after_consecutive_failures() {
    let runtime = rt();
    let mock = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        always_503: true,
        ..Default::default()
    }));
    let config = breaker_proxy_config(&mock);
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");

    // The first two logical requests fail at the ledger and trip the
    // explicitly configured threshold. The remaining three must be
    // rejected by the open breaker without another network call.
    for _ in 0..5 {
        let _ = harness.get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "tok_breaker"),
            ],
        );
    }
    // Once the breaker is open, later logical requests do not hit the
    // network. The always-503 branch intentionally returns before
    // request capture, so use its dedicated network-hit counter.
    let received = mock.state.received.load(Ordering::SeqCst);
    assert_eq!(
        received, 2,
        "breaker should stop network calls after its second consecutive failure"
    );
}

#[test]
fn test_hmac_signature_binds_to_body() {
    // The mock server captures the raw body and the signature header.
    // The test recomputes the canonical signing string per ADR and
    // verifies the HMAC matches; flipping a byte must break verify.
    let runtime = rt();
    let mock = runtime.block_on(spawn_mock_ledger(LedgerKnobs::default()));
    let config = proxy_config(&mock);
    let harness = sbproxy_e2e::ProxyHarness::start_with_yaml(&config).expect("start proxy");
    let _ = harness.get_with_headers(
        "/article",
        "blog.localhost",
        &[
            ("user-agent", "GPTBot/1.0"),
            ("crawler-payment", "tok_hmac"),
        ],
    );
    let captured = runtime.block_on(async { mock.state.captured.lock().await.clone() });
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

    let mut tampered_body = call.body.clone();
    *tampered_body.last_mut().expect("nonempty body") ^= 1;
    let tampered_canonical = format!(
        "1\n{}\n{}\n{}\n{}\nPOST\n/v1/ledger/redeem\n{}",
        request_id,
        timestamp,
        nonce,
        workspace,
        sha256_hex(&tampered_body)
    );
    let mut tampered_mac = <HmacSha256 as KeyInit>::new_from_slice(&key).unwrap();
    tampered_mac.update(tampered_canonical.as_bytes());
    let tampered_signature = format!("v1={}", hex::encode(tampered_mac.finalize().into_bytes()));
    assert_ne!(
        call.signature, tampered_signature,
        "changing the body invalidates the signature"
    );
}

#[test]
fn test_error_envelope_retryable_false_maps_to_402() {
    // Per ADR: a non-retryable error envelope (e.g.
    // `ledger.signature_invalid`) maps to 402 at the proxy edge so
    // the agent retries with a fresh token.
    let runtime = rt();
    let mock = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        always_401: true,
        ..Default::default()
    }));
    let config = proxy_config(&mock);
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
fn test_error_envelope_retryable_true_maps_to_503() {
    let runtime = rt();
    let mock = runtime.block_on(spawn_mock_ledger(LedgerKnobs {
        always_503: true,
        ..Default::default()
    }));
    let config = proxy_config(&mock);
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
        "retryable ledger failure fails closed with 503"
    );
}

// --- Mock-server self-test (always runs) ---

/// Confirm the mock-server itself works end-to-end without the proxy.
/// This guards against a refactor of `axum`'s extractor types breaking
/// every Q1.2 test silently. Also exercises the TLS listener and
/// `fail_first_n` knob independently of the proxy.
#[test]
fn mock_ledger_self_test() {
    let runtime = rt();
    runtime.block_on(async {
        let mock = spawn_mock_ledger(LedgerKnobs {
            fail_first_n: 1,
            ..Default::default()
        })
        .await;
        let root = reqwest::Certificate::from_pem(mock.root_pem.as_bytes()).expect("parse test CA");
        let client = reqwest::Client::builder()
            .add_root_certificate(root)
            .build()
            .expect("build trusted client");
        let url = format!("https://{}/v1/ledger/redeem", mock.addr);

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

        let captured = mock.state.captured.lock().await;
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].idempotency_key, "k1");
        assert_eq!(captured[1].idempotency_key, "k1");
    });
}
