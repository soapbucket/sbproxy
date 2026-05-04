//! Wave 2 cross-pillar e2e (Q2.11) : `wave2_billing_audit`.
//!
//! One inbound 402 request that exercises every Wave 2 substrate
//! pillar at once: agent_class resolution (G1.4), tier pricing
//! (G1.2), ledger redemption (G1.3), wallet debit (G2.4), audit
//! emission (E2.2 / A2.3), outbound webhook delivery (E2.4 / R1.4),
//! and per-agent metric updates (G1.6).
//!
//! Mirrors `smoke_substrate.rs` (Q1.8) in shape and pace. Where
//! Q1.8 covered the substrate, this test covers the join between
//! the substrate and the Wave 2 money / audit / webhook pillars.
//! Failures here mean a Wave 2 contract drifted; per-pillar tests
//! cover the depth, this one covers the seam.
//!
//! Authoritative inputs:
//! - `docs/AIGOVERNANCE-BUILD.md` § 5.5 (Q2.11) and § 17 cross-pillar matrix.
//! - `docs/adr-audit-log-v0.md` (A2.3) : `target_kind=wallet`,
//!   `action=debit`, `before/after` populated for the debit row.
//! - `docs/adr-wallet-model.md` : wallet adapter debit semantics.
//! - `docs/adr-webhook-security.md` : outbound webhook signature
//!   contract; here we only assert the wallet event lands at the
//!   customer URL with the right `event_type`.
//! - `docs/adr-metric-cardinality.md` (A1.1) : `agent_class` is a
//!   permitted label on `sbproxy_requests_total`.
//!
//! Many assertions depend on Wave 2 implementation lanes still
//! landing (G2.3 Stripe adapter, G2.4 wallet, E2.2 audit v0,
//! E2.4 outbound webhooks). The test body is locked today so
//! the contract is reviewable before the implementations land;
//! the assertions that depend on unmerged work are guarded with
//! `#[ignore]` and a TODO referencing the unblocking task.
//!
//! Wave 5 KYA-token integration is deliberately out of scope here
//! (the cross-pillar matrix in § 17 lists `wave5_*` for that join).

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::{json, Value};
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::Mutex as TokioMutex;

// --- Mock customer webhook endpoint ---

/// State the customer-side webhook receiver exposes back to the
/// test driver. Every inbound POST is captured so the test can
/// assert on `event_type`, signature presence, and ordering.
#[derive(Default)]
struct WebhookState {
    /// Raw inbound payloads. Order is reception order.
    deliveries: TokioMutex<Vec<CapturedWebhook>>,
}

/// One inbound webhook delivery, decoded enough for assertions.
#[derive(Debug, Clone)]
#[allow(dead_code)] // signature is only checked by the stretch path
struct CapturedWebhook {
    /// `Sb-Signature` (or whichever header E2.4 standardises on)
    /// captured verbatim. Empty when the sender did not sign.
    signature: String,
    /// Decoded JSON body. The Wave 2 outbound envelope ships
    /// `event_type` and a typed payload object.
    body: Value,
}

/// Spawn a tiny `axum` webhook receiver on `127.0.0.1:0`. Returns
/// the bound base URL the proxy should POST to and a shared
/// state handle the test can poll for deliveries.
async fn spawn_customer_webhook() -> (String, Arc<WebhookState>) {
    let state = Arc::new(WebhookState::default());
    let app = Router::new()
        .route("/webhook", post(handle_webhook))
        .with_state(state.clone());

    let listener = TokioTcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    (format!("http://{}/webhook", addr), state)
}

async fn handle_webhook(
    State(state): State<Arc<WebhookState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let signature = headers
        .get("sb-signature")
        .or_else(|| headers.get("x-sb-signature"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Try to decode JSON. Bodies that fail to parse still get
    // captured (with `body = null`) so a contract-mismatch test
    // can fail loudly rather than silently drop the delivery.
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    state.deliveries.lock().await.push(CapturedWebhook {
        signature,
        body: parsed,
    });
    StatusCode::OK
}

// --- Mock ledger ---

/// Minimal mock ledger that always approves redemptions. The
/// per-pillar `http_ledger.rs` test owns the deep contract; here
/// we just need the redeem leg to succeed so the wallet debit
/// has something to charge against.
async fn spawn_mock_ledger() -> String {
    let state = Arc::new(LedgerState::default());
    let app = Router::new()
        .route("/v1/ledger/redeem", post(handle_redeem))
        .with_state(state);
    let listener = TokioTcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    format!("http://{}", addr)
}

#[derive(Default)]
struct LedgerState {
    /// Counter so the test can assert the proxy hit the ledger at
    /// least once.
    redeems: AtomicUsize,
}

async fn handle_redeem(
    State(state): State<Arc<LedgerState>>,
    _headers: HeaderMap,
    _body: axum::body::Bytes,
) -> impl IntoResponse {
    state.redeems.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::OK,
        Json(json!({
            "v": 1,
            "approved": true,
            "receipt": "rcpt_w2_billing_audit_0001",
            "tier": "premium",
            "amount_micros": 50_000u64,
            "currency": "USD",
        })),
    )
}

// --- Test harness ---

/// Pick an ephemeral port for the admin sidecar. Same pattern as
/// `smoke_substrate.rs`.
fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Build the cross-pillar config. Wires:
///
/// - One paywalled origin running `ai_crawl_control` with one
///   `premium` tier ($0.05 USD).
/// - The mock ledger as the redemption endpoint.
/// - The Wave 2 wallet adapter in its in-memory mode (chosen
///   because containerless tests must run on every contributor's
///   laptop).
/// - The Wave 2 audit emitter in its in-memory adapter, with the
///   admin debug endpoints surfaced for assertion-side reads.
/// - One outbound webhook subscription pointing at the test's
///   customer endpoint.
/// - Tracing on (stdout exporter) and per-agent metrics enabled.
///
/// Field names mirror the Wave 1 smoke config plus the Wave 2
/// additions documented in the relevant ADRs. Where a key is
/// disputed across in-flight lanes, the comment cites the lane.
fn wave2_billing_audit_config(
    admin_port: u16,
    ledger_base: &str,
    origin_base: &str,
    customer_webhook_url: &str,
) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: w2-billing
observability:
  tracing:
    enabled: true
    exporter: stdout
    service_name: "sbproxy-w2-billing-audit"
    sampling:
      parent_based: true
      head_rate: 1.0
      always_sample_errors: true
  log:
    sinks:
      - name: stdout
        format: json
        profile: internal
  metrics:
    enabled: true
billing:
  # G2.4 in-memory wallet. Containerless because every contributor
  # needs to be able to run this test without standing up a Postgres
  # or a Redis side-car. The Postgres-backed integration lives in
  # the per-pillar wallet test (Q2.2).
  wallet:
    backend: memory
    starting_balance_micros: 1000000   # $1.00 seed
audit:
  # E2.2 / A2.3 in-memory adapter. Surfaced via the admin endpoint
  # at `/api/audit/recent`. The signed-batch persistence path is
  # exercised by Q2.7; here we only need the envelope.
  sink: memory
webhooks:
  outbound:
    subscriptions:
      - workspace_id: default
        url: "{customer_webhook_url}"
        event_types:
          - "wallet.debit_succeeded"
          - "wallet.topup_succeeded"
        signing_secret_env: SBPROXY_WEBHOOK_SECRET
origins:
  "paywalled.localhost":
    policies:
      - type: ai_crawl_control
        ledger:
          endpoint: "{ledger_base}"
          hmac_key_env: SBPROXY_LEDGER_HMAC_KEY
        pricing:
          tier_default: "premium"
          tiers:
            - name: "premium"
              price_micros: 50000
              currency: "USD"
        agent_class:
          ua_catalog:
            - pattern: "GPTBot/*"
              agent_id: "openai-gptbot"
              agent_class: "vendor:openai"
              agent_vendor: "OpenAI"
    action:
      type: proxy
      url: "{origin_base}"
"#
    )
}

/// Single test. One paywalled request issued without a receipt
/// returns 402, the test redeems through the mock ledger, replays
/// the request with the receipt, asserts wallet + audit + webhook
/// + metrics all line up.
///
/// `#[ignore]` until G2.3, G2.4, E2.2, and E2.4 land. The shape of
/// the assertions is fixed today so reviewers can lock the
/// contract before the implementations ship.
#[test]
#[ignore = "TODO(wave3): G2.3 Stripe rail / G2.4 wallet / E2.2 audit / E2.4 outbound webhooks landed in sbproxy-enterprise but the OSS proxy in this repo has no enterprise crate dep. Cross-pillar smoke must move to the enterprise e2e suite or wait for an OSS-side enterprise plugin shim."]
fn wave2_billing_audit_402_redeem_debit_audit_webhook() {
    // axum mock servers run on tokio so we need a runtime. The
    // proxy harness itself is sync (blocking reqwest), and its
    // wait-for-port probe is runtime-free, so spawning the
    // harness inside `block_on` is safe.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let admin_port = pick_port();
    let ledger_base = rt.block_on(spawn_mock_ledger());
    let (webhook_url, webhook_state) = rt.block_on(spawn_customer_webhook());
    let origin = MockUpstream::start(json!({"ok": true})).expect("start origin mock");
    let origin_base = origin.base_url();

    let yaml = wave2_billing_audit_config(admin_port, &ledger_base, &origin_base, &webhook_url);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // --- Leg 1: unpaid request returns 402 with the premium price ---
    let unpaid = harness
        .get_with_headers(
            "/article",
            "paywalled.localhost",
            &[("user-agent", "GPTBot/2.1")],
        )
        .expect("unpaid leg");
    assert_eq!(unpaid.status, 402, "expected 402: {:?}", unpaid);
    let challenge: Value = unpaid.json().expect("402 body is JSON");
    assert_eq!(challenge["tier"], "premium");
    assert_eq!(challenge["amount_micros"], 50_000u64);
    assert_eq!(challenge["currency"], "USD");
    let challenge_id = challenge["challenge_id"]
        .as_str()
        .expect("challenge_id present in 402 body");

    // --- Leg 2: replay with redeemed receipt ---
    let paid = harness
        .get_with_headers(
            "/article",
            "paywalled.localhost",
            &[
                ("user-agent", "GPTBot/2.1"),
                ("x-sb-receipt", "rcpt_w2_billing_audit_0001"),
                ("x-sb-challenge-id", challenge_id),
            ],
        )
        .expect("paid leg");
    assert_eq!(paid.status, 200, "expected 200 after redeem: {:?}", paid);

    // --- Assertion: agent_class was resolved to the GPTBot entry ---
    let last = admin_get(admin_port, "/api/last-request", "admin", "w2-billing");
    assert_eq!(last.0, 200, "admin last-request lookup");
    let last_json: Value = serde_json::from_str(&last.1).expect("last-request JSON");
    assert_eq!(last_json["agent_class"], "vendor:openai");
    assert_eq!(last_json["agent_id"], "openai-gptbot");
    assert_eq!(last_json["agent_vendor"], "OpenAI");

    // --- Assertion: wallet debited by exactly the tier price ---
    // The admin endpoint surfaces the in-memory wallet balance per
    // workspace so the test does not need a SQL client. Starting
    // balance was $1.00 (1_000_000 micros); after one $0.05 debit
    // we expect 950_000 micros remaining.
    let wallet = admin_get(admin_port, "/api/wallet/default", "admin", "w2-billing");
    assert_eq!(wallet.0, 200, "wallet lookup");
    let wallet_json: Value = serde_json::from_str(&wallet.1).expect("wallet JSON");
    assert_eq!(
        wallet_json["balance_micros"], 950_000u64,
        "wallet should be debited by 50_000 micros: {wallet_json:?}"
    );

    // --- Assertion: audit entry for the debit ---
    // Per A2.3 / E2.2 the wallet debit emits an `AdminAuditEvent`
    // with `action=debit`, `target_kind=wallet`, plus `before` and
    // `after` balance fields populated.
    let audit = admin_get(
        admin_port,
        "/api/audit/recent?limit=20",
        "admin",
        "w2-billing",
    );
    assert_eq!(audit.0, 200, "audit recent");
    let entries: Value = serde_json::from_str(&audit.1).expect("audit JSON");
    let arr = entries.as_array().expect("audit entries array");
    let debit_row = arr
        .iter()
        .find(|e| e["action"] == "debit" && e["target_kind"] == "wallet")
        .unwrap_or_else(|| panic!("expected wallet debit audit row, got {arr:?}"));
    assert_eq!(
        debit_row["before"]["balance_micros"], 1_000_000u64,
        "audit before-state must capture pre-debit balance"
    );
    assert_eq!(
        debit_row["after"]["balance_micros"], 950_000u64,
        "audit after-state must capture post-debit balance"
    );
    assert_eq!(debit_row["amount_micros"], 50_000u64);
    assert_eq!(debit_row["currency"], "USD");

    // --- Assertion: outbound webhook delivered to the customer ---
    // The webhook receiver is async; poll up to 5s for the delivery
    // to land. The Wave 2 sampling/flush interval is configurable
    // but defaults to <1s for a single in-memory subscription.
    let deliveries = poll_for_webhook(&rt, &webhook_state, Duration::from_secs(5));
    assert!(
        !deliveries.is_empty(),
        "expected at least one webhook delivery to {webhook_url}"
    );
    let debit_event = deliveries
        .iter()
        .find(|d| d.body["event_type"] == "wallet.debit_succeeded")
        .unwrap_or_else(|| panic!("expected wallet.debit_succeeded delivery, got {deliveries:?}"));
    assert_eq!(debit_event.body["payload"]["amount_micros"], 50_000u64);
    assert_eq!(debit_event.body["payload"]["agent_class"], "vendor:openai");
    assert!(
        !debit_event.signature.is_empty(),
        "outbound webhook MUST be signed (per adr-webhook-security.md)"
    );

    // --- Assertion: per-agent metrics incremented ---
    let metrics = admin_get(admin_port, "/metrics", "admin", "w2-billing");
    assert_eq!(metrics.0, 200, "metrics scrape");
    let body = metrics.1;
    assert!(
        body.contains("sbproxy_requests_total{") && body.contains("agent_class=\"vendor:openai\""),
        "expected per-agent label on requests_total: {body}"
    );
    assert!(
        body.contains("sbproxy_wallet_debit_total{") && body.contains("result=\"success\""),
        "expected wallet debit counter incremented: {body}"
    );
    assert!(
        body.contains("sbproxy_outbound_webhook_delivered_total{"),
        "expected outbound webhook delivery counter: {body}"
    );

    // --- Stretch: trace span chain captured ---
    // The in-memory OTLP exporter exposes the spans collected since
    // the last reset. For Wave 2 we expect the Wave 1 chain plus a
    // wallet-debit span and an outbound-webhook span.
    let spans = admin_get(admin_port, "/api/spans/recent", "admin", "w2-billing");
    assert_eq!(spans.0, 200);
    let span_doc: Value = serde_json::from_str(&spans.1).expect("spans JSON");
    let span_names: Vec<&str> = span_doc["spans"]
        .as_array()
        .expect("spans array")
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    let expected = [
        "sbproxy.intake.accept",
        "sbproxy.policy.enforce",
        "sbproxy.action.redeem",
        "sbproxy.ledger.redeem",
        "sbproxy.wallet.debit",
        "sbproxy.audit.emit",
        "sbproxy.webhook.outbound",
    ];
    for name in expected.iter() {
        assert!(
            span_names.contains(name),
            "expected span {name} in chain, got {span_names:?}"
        );
    }

    drop(harness);
    drop(origin);
    // rt drops last; tokio servers shut down with it.
    drop(rt);
}

/// Compile-time shape lock. Asserts the cross-pillar config builder
/// and the webhook-mock helpers can be constructed without booting
/// the proxy. Cheap enough to run unconditionally so a maintainer
/// who breaks the YAML field names sees a red signal before the
/// ignored test ever runs.
#[test]
fn wave2_billing_audit_config_compiles() {
    let yaml = wave2_billing_audit_config(
        9999,
        "http://127.0.0.1:1",
        "http://127.0.0.1:2",
        "http://127.0.0.1:3/webhook",
    );
    assert!(yaml.contains("ai_crawl_control"));
    assert!(yaml.contains("backend: memory"));
    assert!(yaml.contains("wallet.debit_succeeded"));
    assert!(yaml.contains("agent_id: \"openai-gptbot\""));
}

// --- Helpers ---

/// Snapshot the captured webhook deliveries with a short polling
/// loop. Returns whatever has accumulated within the timeout
/// window. The mock receiver is async; the test driver is sync;
/// `block_on` here is safe because the webhook task lives on the
/// supplied runtime, not the current thread.
fn poll_for_webhook(
    rt: &tokio::runtime::Runtime,
    state: &Arc<WebhookState>,
    timeout: Duration,
) -> Vec<CapturedWebhook> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let snap = rt.block_on(async { state.deliveries.lock().await.clone() });
        if !snap.is_empty() {
            return snap;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    rt.block_on(async { state.deliveries.lock().await.clone() })
}

/// Issue a Basic-auth GET against the admin port. Same shape as
/// the helper in `smoke_substrate.rs` so the assertion idiom is
/// uniform across Wave 1 and Wave 2 cross-pillar tests.
fn admin_get(port: u16, path: &str, user: &str, pass: &str) -> (u16, String) {
    let auth = format!("Basic {}", base64_encode(&format!("{user}:{pass}")));
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", auth)
        .send()
        .expect("admin GET");
    let status = resp.status().as_u16();
    let body = resp.text().unwrap_or_default();
    (status, body)
}

/// Tiny base64 encoder used only by the admin Basic auth helper.
/// Inlined so the test does not depend on the workspace's
/// `base64` major bumping.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPH[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}
