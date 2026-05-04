//! Cross-pillar smoke e2e (Wave 1 / Q1.8).
//!
//! One inbound 402 request that exercises every Wave 1 substrate pillar
//! at once: agent_class resolution, tier pricing, ledger redemption,
//! per-agent metrics, audit-log entry, structured-log line, and the full
//! trace span chain from intake to ledger and back.
//!
//! This is the wave's "does the substrate compose" test. Failures here
//! mean a pillar is missing or a contract drifted; per-pillar tests
//! cover the depth, this one covers the join.
//!
//! Authoritative inputs:
//! - `docs/adr-observability.md` (A1.4) - span-chain length >= 5,
//!   `sbproxy.intake.accept` -> `sbproxy.policy.enforce` ->
//!   `sbproxy.action.challenge|redeem` -> `sbproxy.ledger.redeem`.
//! - `docs/adr-log-schema-redaction.md` (A1.5) - every log line carries
//!   `request_id`, `trace_id`, `span_id`, `tenant_id`, `agent_id`.
//! - `docs/adr-admin-action-audit.md` (A1.7) - redemption emits an
//!   `audit_emit` envelope with `action: Redeem|Approve` and a typed
//!   target.
//! - `docs/adr-metric-cardinality.md` (A1.1) - `sbproxy_requests_total`
//!   carries `agent_id` (registry-bounded), `agent_class`, `payment_rail`.
//!
//! Many assertions depend on R1.1, R1.2, E1.1, G1.2-G1.7 landing. The
//! ones that do are guarded with `#[ignore]` and a TODO pointing at the
//! task that unblocks them. The shape of the test is locked today so
//! the contract is reviewable before the implementations land.

use std::net::TcpListener;
use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Pick an ephemeral port. Used for the admin-side debug port that
/// surfaces the resolved `agent_class` and the in-memory audit log.
fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Build the smoke-substrate config: one paywalled origin that runs the
/// AI crawl policy with tier pricing, an in-memory ledger configured
/// with a known HMAC key, and observability fully wired (tracing on,
/// stdout exporter, structured-log audit sink, metrics enabled).
///
/// `ledger_base` is the `MockUpstream` that stands in for the real
/// ledger so the test owns the redemption side of the wire.
/// `origin_base` is the upstream the proxy talks to once redemption
/// succeeds.
fn smoke_config(admin_port: u16, ledger_base: &str, origin_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: smoke
observability:
  tracing:
    enabled: true
    exporter: stdout
    service_name: "sbproxy-smoke"
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
origins:
  "paywalled.localhost":
    policies:
      - type: ai_crawl
        ledger:
          endpoint: "{ledger_base}"
          hmac_key_env: SBPROXY_LEDGER_HMAC_KEY
        pricing:
          tier_default: "premium"
          tiers:
            - name: "premium"
              cents: 50
              currency: "USD"
        agent_class:
          # G1.4 resolver. We stub a ua-only catalog entry so the smoke
          # request lands on a known class without requiring the bot-auth
          # directory to be live in this test.
          ua_catalog:
            - pattern: "smoke-bot/*"
              agent_id: "smoke-bot"
              agent_class: "vendor:test"
              agent_vendor: "smoke-bot-vendor"
    action:
      type: proxy
      url: "{origin_base}"
"#
    )
}

/// One request, end to end. Issued without a payment receipt so the
/// proxy returns 402 with a tier-priced challenge; the test then calls
/// the mock ledger to mint a redemption envelope and replays the
/// request with the receipt header attached. Both legs share one
/// `request_id` so audit/log/metrics correlate.
#[test]
#[ignore = "TODO(wave3): G1.2-G1.7 substrate landed but YAML wiring for HttpLedger and agent_class policy still missing; R1.1 burn-rate engine not yet built; cross-cutting smoke awaits Wave 3 wiring task."]
fn smoke_substrate_402_then_redeem() {
    let admin_port = pick_port();

    // Mock ledger: replies `{"approved": true, "receipt": "...", ...}`
    // to any POST. The real ledger HMAC-signs the body; we let the
    // proxy verify against the configured env key.
    let ledger = MockUpstream::start(json!({
        "approved": true,
        "receipt": "rcpt_smoke_0001",
        "tier": "premium",
        "amount_cents": 50,
        "currency": "USD",
    }))
    .expect("start ledger mock");

    // Mock origin: returns 200 once redemption succeeds.
    let origin = MockUpstream::start(json!({"ok": true})).expect("start origin mock");

    let yaml = smoke_config(admin_port, &ledger.base_url(), &origin.base_url());
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // --- Leg 1: unpaid request returns 402 with tier price ---
    let unpaid = harness
        .get_with_headers(
            "/article",
            "paywalled.localhost",
            &[("user-agent", "smoke-bot/1.0")],
        )
        .expect("unpaid leg");
    assert_eq!(unpaid.status, 402, "expected 402 challenge: {:?}", unpaid);
    let challenge = unpaid.json().expect("402 body is JSON");
    assert_eq!(challenge["tier"], "premium");
    assert_eq!(challenge["amount_cents"], 50);
    let challenge_id = challenge["challenge_id"]
        .as_str()
        .expect("challenge_id present in 402 body");

    // --- Leg 2: replay with redeemed receipt ---
    // The real flow drives this through the X-Sb-Receipt header per the
    // ledger protocol ADR.
    let paid = harness
        .get_with_headers(
            "/article",
            "paywalled.localhost",
            &[
                ("user-agent", "smoke-bot/1.0"),
                ("x-sb-receipt", "rcpt_smoke_0001"),
                ("x-sb-challenge-id", challenge_id),
            ],
        )
        .expect("paid leg");
    assert_eq!(
        paid.status, 200,
        "expected 200 after redemption: {:?}",
        paid
    );

    // --- Assertion: agent_class was resolved on both legs ---
    // The admin debug endpoint at /api/last-request returns the cached
    // resolution for the most recently observed request_id.
    let last = admin_get(admin_port, "/api/last-request", "admin", "smoke");
    assert_eq!(last.0, 200, "admin last-request lookup");
    let last_json: serde_json::Value =
        serde_json::from_str(&last.1).expect("last-request JSON body");
    assert_eq!(last_json["agent_class"], "vendor:test");
    assert_eq!(last_json["agent_id"], "smoke-bot");
    assert_eq!(last_json["agent_vendor"], "smoke-bot-vendor");

    // --- Assertion: per-agent metrics incremented ---
    let metrics = admin_get(admin_port, "/metrics", "admin", "smoke");
    assert_eq!(metrics.0, 200, "metrics scrape");
    let body = metrics.1;
    assert!(
        body.contains("sbproxy_requests_total{") && body.contains("agent_class=\"vendor:test\""),
        "expected per-agent label on requests_total: {body}"
    );
    assert!(
        body.contains("sbproxy_ledger_redeem_total{") && body.contains("result=\"approved\""),
        "expected ledger redeem counter incremented: {body}"
    );

    // --- Assertion: audit log captured the redemption ---
    // OSS-path audit lands in the in-memory adapter exposed via the
    // admin endpoint. Enterprise replaces the adapter with Postgres;
    // the envelope shape is identical.
    let audit = admin_get(admin_port, "/api/audit/recent?limit=10", "admin", "smoke");
    assert_eq!(audit.0, 200);
    let entries: serde_json::Value = serde_json::from_str(&audit.1).expect("audit JSON");
    let arr = entries.as_array().expect("audit entries array");
    assert!(
        arr.iter().any(|e| {
            e["event_type"] == "audit_emit" && (e["action"] == "Redeem" || e["action"] == "Approve")
        }),
        "expected redemption audit entry, got {arr:?}"
    );

    // --- Assertion: structured log line for the request ---
    // The log capture endpoint returns the most recent N JSON lines
    // emitted to the stdout sink in the test harness.
    let logs = admin_get(admin_port, "/api/logs/recent?limit=20", "admin", "smoke");
    assert_eq!(logs.0, 200);
    let lines: Vec<serde_json::Value> = logs
        .1
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let req_line = lines
        .iter()
        .find(|l| l["event_type"] == "request_completed")
        .expect("request_completed line present");
    assert!(req_line["request_id"].is_string(), "request_id present");
    assert!(req_line["trace_id"].is_string(), "trace_id present");
    assert!(req_line["span_id"].is_string(), "span_id present");
    assert!(req_line["agent_id"].is_string(), "agent_id present");
    assert_eq!(req_line["tenant_id"], "default");

    // --- Assertion: trace span chain is captured ---
    // The in-memory OTLP exporter exposes a `/api/spans/recent` endpoint
    // that dumps the spans collected since the last reset. Per A1.4 the
    // chain for a 402 + redeem is at minimum:
    //   sbproxy.intake.accept ->
    //   sbproxy.policy.enforce ->
    //   sbproxy.action.challenge -> (leg 1)
    //   sbproxy.intake.accept ->
    //   sbproxy.policy.enforce ->
    //   sbproxy.action.redeem ->
    //   sbproxy.ledger.redeem -> (outbound HTTP)
    let spans = admin_get(admin_port, "/api/spans/recent", "admin", "smoke");
    assert_eq!(spans.0, 200);
    let span_doc: serde_json::Value = serde_json::from_str(&spans.1).expect("spans JSON");
    let span_names: Vec<&str> = span_doc["spans"]
        .as_array()
        .expect("spans array")
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    let expected = [
        "sbproxy.intake.accept",
        "sbproxy.policy.enforce",
        "sbproxy.action.challenge",
        "sbproxy.action.redeem",
        "sbproxy.ledger.redeem",
    ];
    for name in expected.iter() {
        assert!(
            span_names.contains(name),
            "expected span {name} in chain, got {span_names:?}"
        );
    }

    // Mock-side checks: the ledger received the redeem POST.
    let captured = ledger.captured();
    assert!(
        captured.iter().any(|c| c.method == "POST"),
        "ledger should have observed at least one POST"
    );

    // Hold these so the harness drops cleanly.
    drop(harness);
    drop(origin);
    drop(ledger);
}

/// Compile-time shape lock. Asserts the smoke harness can be built and
/// teardown is clean even when no implementations have landed. This
/// catches "the e2e crate doesn't compile" before R1.* lands. Cheap
/// (no proxy boot, no upstream).
#[test]
fn smoke_substrate_harness_compiles() {
    // The lib API surface we depend on for Q1.8.
    let _ = pick_port;
    let _ = smoke_config;
    // Round-trip a fixture so the JSON helper doesn't bit-rot under
    // serde-yaml renames.
    let yaml = smoke_config(0, "http://127.0.0.1:1", "http://127.0.0.1:2");
    assert!(yaml.contains("smoke-bot"));
    assert!(yaml.contains("ai_crawl"));
}

// --- Helpers ---

/// Issue a Basic-auth GET against the admin port. Tiny and dep-free
/// (matches the `admin_endpoints.rs` style).
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
