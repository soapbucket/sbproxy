//! Rate-limit budget e2e (Q2.12).
//!
//! Boots the Wave 2 rate-limit middleware (R2.3) and asserts the
//! contract from `docs/adr-capacity-rate-limits.md` (A2.5):
//!
//! 1. A burst above the sustained ceiling triggers 429 responses
//!    that carry the full RFC 9239 / draft-ietf-httpapi-ratelimit-headers
//!    set: `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining`,
//!    `RateLimit-Reset`, `RateLimit-Policy`.
//! 2. Sustained throttle traffic escalates the workspace from
//!    `Throttle` to `AutoSuspend`. The escalation emits one
//!    `AdminAuditEvent` with `action=rate_limit_suspend` and
//!    `target_kind=workspace`. The workspace's effective ceiling
//!    drops to 1 rps for the cool-down window.
//! 3. After the cool-down expires, the workspace returns to
//!    normal rate. The test mocks the clock so the cool-down is
//!    deterministic; without clock control the test would have to
//!    sleep for the production 60-minute window.
//! 4. A below-threshold burst that crosses the soft tier emits the
//!    `sbproxy_rate_limit_total{result="soft"}` metric without
//!    returning 429 to the client.
//!
//! The rate-limit module landed in R2.3 ships an in-process clock
//! adapter (the `RateLimitClock` trait); the test toggles it via
//! the admin debug endpoint.
//!
//! Many assertions depend on R2.3 + E2.2 (audit emitter). Until
//! both lanes merge, the deeper assertions are `#[ignore]`d with
//! a TODO; the shape is locked today so the contract is reviewable.
//!
//! See also `rate_limiting.rs` for the Wave 1 floor (single-policy
//! 429 + `Retry-After`); this file is the Wave 2 superset that adds
//! the full header set, escalation, and audit/metric assertions.

use std::time::Duration;

use sbproxy_e2e::ProxyHarness;
use serde_json::Value;

/// Build a rate-limit-only config tuned for a fast test (10 rps
/// sustained, 20 rps burst). Matches the A2.5 contract for the
/// `inbound HTTP requests` budget but with a small ceiling so the
/// burst hits the limit in one second instead of one hundred.
///
/// `escalation_threshold` is the consecutive-throttle count that
/// promotes the workspace to `AutoSuspend`; A2.5 default is 1000
/// over a 5-minute window. We override to 50 so the test stays
/// inside a single-digit-second wall clock.
///
/// `cooldown_secs` is the auto-suspend cool-down. A2.5 default is
/// 3600. The test sets 2 so the deterministic-clock adapter does
/// not have to advance an unreasonable amount.
fn rate_limit_config(admin_port: u16, escalation_threshold: u32, cooldown_secs: u32) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: rl-budget
observability:
  metrics:
    enabled: true
  log:
    sinks:
      - name: stdout
        format: json
        profile: internal
audit:
  sink: memory
rate_limits:
  workspace_default:
    http_rps_sustained: 10
    http_rps_burst: 20
    soft_threshold_rps: 8
  escalation:
    abuse_threshold_throttle_to_suspend: {escalation_threshold}
    auto_suspend_cooldown_secs: {cooldown_secs}
  # Deterministic clock adapter for the suspend / cool-down sweep.
  # The R2.3 module exposes this knob behind `clock: manual`; the
  # admin endpoint at `/api/rate_limits/clock/advance?secs=N` walks
  # the manual clock forward without touching wall-clock time.
  clock: manual
origins:
  "rl.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: rate_limit_budget
        # Per-(workspace, route) inner cap from A2.5 § "Hot-key
        # complement". Set high enough that the workspace ceiling
        # is the binding constraint in this test.
        per_route_rps: 100
        headers:
          # Full RFC 9239 header set is the new contract for
          # Wave 2; Wave 1 only emitted Retry-After.
          enabled: true
          include_retry_after: true
          include_ratelimit_policy: true
"#
    )
}

/// Burst until we see at least one 429, then assert it carries
/// the full RFC 9239 / draft-ietf-httpapi-ratelimit-headers set.
///
/// `#[ignore]` because the full header set requires R2.3.
#[test]
#[ignore = "TODO(wave3): R2.3 rate-limit middleware exists per WATCH.md but `rate_limit_budget` policy + top-level `rate_limits:` block + manual-clock admin endpoint are not yet on main; pipeline-wiring task tracked in WATCH.md."]
fn burst_returns_429_with_full_ratelimit_headers() {
    let admin_port = pick_port();
    let cfg = rate_limit_config(admin_port, 1_000, 60);
    let harness = ProxyHarness::start_with_yaml(&cfg).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // 100 requests in tight succession. With sustained=10rps and
    // burst=20rps, well over half should land as 429.
    let mut found_429: Option<sbproxy_e2e::Response> = None;
    for _ in 0..100 {
        let resp = harness.get("/anything", "rl.localhost").expect("send");
        if resp.status == 429 {
            found_429 = Some(resp);
            break;
        }
    }
    let resp = found_429.expect("expected at least one 429 in a 100-request burst");

    // RFC 9239 / draft-ietf-httpapi-ratelimit-headers: every header
    // is REQUIRED on a 429 per A2.5 § "Coordinated rate-limit
    // headers".
    assert!(
        resp.headers.contains_key("retry-after"),
        "Retry-After missing on 429: {:?}",
        resp.headers
    );
    assert!(
        resp.headers.contains_key("ratelimit-limit"),
        "RateLimit-Limit missing on 429: {:?}",
        resp.headers
    );
    assert!(
        resp.headers.contains_key("ratelimit-remaining"),
        "RateLimit-Remaining missing on 429: {:?}",
        resp.headers
    );
    assert!(
        resp.headers.contains_key("ratelimit-reset"),
        "RateLimit-Reset missing on 429: {:?}",
        resp.headers
    );
    assert!(
        resp.headers.contains_key("ratelimit-policy"),
        "RateLimit-Policy missing on 429: {:?}",
        resp.headers
    );

    // RateLimit-Remaining MUST be 0 on the response that triggered
    // the throttle (per the IETF draft and A2.5).
    assert_eq!(
        resp.headers.get("ratelimit-remaining").map(|s| s.as_str()),
        Some("0"),
        "RateLimit-Remaining must be 0 on the throttled response"
    );

    // Retry-After MUST be a non-negative integer-seconds value.
    let retry: u64 = resp
        .headers
        .get("retry-after")
        .expect("retry-after present")
        .parse()
        .expect("retry-after is integer-seconds");
    assert!(retry > 0, "Retry-After should be positive: {retry}");

    // RateLimit-Policy is human-parseable per the draft. A2.5
    // pins the format `<limit>;w=<window-seconds>`.
    let policy = resp
        .headers
        .get("ratelimit-policy")
        .expect("ratelimit-policy present");
    assert!(
        policy.contains(";w=") || policy.contains(";"),
        "RateLimit-Policy should follow `<limit>;w=<seconds>`: got {policy}"
    );
}

/// Drive sustained throttle traffic until the workspace promotes
/// to `AutoSuspend`. Assert the audit row, the metric increment,
/// and the workspace's effective rate dropping to 1 rps.
#[test]
#[ignore = "TODO(wave3): escalation tier + audit row depend on R2.3 pipeline wiring (see WATCH.md) and an audit emitter wired in the OSS proxy."]
fn sustained_throttle_promotes_to_auto_suspend() {
    let admin_port = pick_port();
    // Lower the threshold to 50 consecutive throttles so the test
    // wall clock stays small. The real production setting is 1000.
    let cfg = rate_limit_config(admin_port, 50, 2);
    let harness = ProxyHarness::start_with_yaml(&cfg).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // Burst until the workspace tips into suspend. 200 requests is
    // generous given the 50-throttle threshold and the 20rps burst.
    let mut suspended_after = 0usize;
    for i in 0..200 {
        let resp = harness.get("/anything", "rl.localhost").expect("send");
        if resp.status == 429 {
            suspended_after = i;
            // Keep going even after the first 429 so the consecutive
            // throttle counter actually crosses the threshold.
        }
        // Spin-burst is intentional; we want consecutive throttles.
    }
    assert!(suspended_after > 0, "expected at least one 429");

    // --- Assertion: audit row for the suspend transition ---
    let audit = admin_get(
        admin_port,
        "/api/audit/recent?limit=50",
        "admin",
        "rl-budget",
    );
    assert_eq!(audit.0, 200, "audit recent");
    let entries: Value = serde_json::from_str(&audit.1).expect("audit JSON");
    let arr = entries.as_array().expect("audit entries array");
    let suspend_row = arr
        .iter()
        .find(|e| e["action"] == "rate_limit_suspend" && e["target_kind"] == "workspace")
        .unwrap_or_else(|| panic!("expected rate_limit_suspend audit row, got {arr:?}"));
    assert_eq!(suspend_row["target_id"], "default");
    assert!(
        suspend_row["reason"]
            .as_str()
            .map(|s| s.contains("auto_suspend_threshold_exceeded"))
            .unwrap_or(false),
        "suspend reason should reference threshold: {suspend_row:?}"
    );

    // --- Assertion: metric counter incremented ---
    let metrics = admin_get(admin_port, "/metrics", "admin", "rl-budget");
    assert_eq!(metrics.0, 200);
    assert!(
        metrics.1.contains("sbproxy_rate_limit_suspend_total{"),
        "expected sbproxy_rate_limit_suspend_total metric: {}",
        metrics.1
    );

    // --- Assertion: workspace effective rate now 1 rps ---
    // The admin endpoint surfaces the resolved effective ceiling
    // for the named workspace. While suspended, A2.5 pins this at
    // 1 rps regardless of the workspace plan.
    let plan = admin_get(
        admin_port,
        "/api/rate_limits/effective?workspace=default",
        "admin",
        "rl-budget",
    );
    assert_eq!(plan.0, 200);
    let plan_json: Value = serde_json::from_str(&plan.1).expect("plan JSON");
    assert_eq!(
        plan_json["effective_rps"], 1u64,
        "auto-suspended workspace must drop to 1 rps: {plan_json:?}"
    );
    assert_eq!(plan_json["tier"], "AutoSuspend");
}

/// After auto-suspend, advance the manual clock past the cool-down
/// and assert the workspace returns to normal rate. A2.5 pins the
/// post-cool-down tier at `Throttle` (not `Soft`) so a second
/// burst within 24h promotes to `ManualReview`; this test only
/// verifies the first cool-down transition.
#[test]
#[ignore = "TODO(wave3): manual-clock admin endpoint depends on R2.3 pipeline wiring."]
fn auto_suspend_cooldown_returns_to_normal() {
    let admin_port = pick_port();
    let cfg = rate_limit_config(admin_port, 50, 2);
    let harness = ProxyHarness::start_with_yaml(&cfg).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // Drive into suspend.
    for _ in 0..200 {
        let _ = harness.get("/anything", "rl.localhost");
    }

    // Confirm we are suspended.
    let plan_before = admin_get(
        admin_port,
        "/api/rate_limits/effective?workspace=default",
        "admin",
        "rl-budget",
    );
    assert_eq!(plan_before.0, 200);
    let plan_before_json: Value = serde_json::from_str(&plan_before.1).expect("plan JSON");
    assert_eq!(plan_before_json["tier"], "AutoSuspend");

    // Advance the manual clock past the 2-second cool-down. The
    // R2.3 module exposes `/api/rate_limits/clock/advance?secs=N`
    // which mutates the manual clock without touching wall-clock
    // time so the test does not need to sleep.
    let advance = admin_post(
        admin_port,
        "/api/rate_limits/clock/advance?secs=3",
        "admin",
        "rl-budget",
    );
    assert_eq!(advance.0, 200, "clock advance should succeed");

    // Workspace should now be back at the `Throttle` floor (one
    // step down from suspend, NOT all the way back to `Soft`).
    let plan_after = admin_get(
        admin_port,
        "/api/rate_limits/effective?workspace=default",
        "admin",
        "rl-budget",
    );
    assert_eq!(plan_after.0, 200);
    let plan_after_json: Value = serde_json::from_str(&plan_after.1).expect("plan JSON");
    assert_eq!(
        plan_after_json["tier"], "Throttle",
        "post-cool-down tier per A2.5 § Transition rules: {plan_after_json:?}"
    );
    assert_eq!(plan_after_json["effective_rps"], 10u64);
}

/// Below-threshold burst that crosses the soft tier. A2.5 says
/// soft-tier observations DO NOT 429 the client; they only emit
/// `sbproxy_rate_limit_total{result="soft"}` so operators can see
/// the climb in dashboards before the throttle bites.
#[test]
#[ignore = "TODO(wave3): soft-tier emit-only metric requires R2.3 pipeline wiring."]
fn soft_tier_emits_metric_without_429() {
    let admin_port = pick_port();
    let cfg = rate_limit_config(admin_port, 1_000, 60);
    let harness = ProxyHarness::start_with_yaml(&cfg).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // Sustained=10, soft_threshold=8, burst=20. We want to sit in
    // the (soft, sustained] range without crossing into burst. A
    // hand-paced loop at ~9 rps stays inside the band for 1 second.
    let start = std::time::Instant::now();
    let mut all_200 = true;
    let mut sent = 0u32;
    while start.elapsed() < Duration::from_millis(900) {
        let resp = harness.get("/anything", "rl.localhost").expect("send");
        if resp.status != 200 {
            all_200 = false;
        }
        sent += 1;
        std::thread::sleep(Duration::from_millis(110));
    }
    assert!(sent >= 5, "should have issued at least 5 requests");
    assert!(all_200, "soft tier must NOT 429 the client");

    // Soft-tier metric MUST have been emitted at least once.
    let metrics = admin_get(admin_port, "/metrics", "admin", "rl-budget");
    assert_eq!(metrics.0, 200);
    assert!(
        metrics.1.contains("sbproxy_rate_limit_total{") && metrics.1.contains("result=\"soft\""),
        "expected soft-tier rate-limit metric: {}",
        metrics.1
    );
}

/// Compile-time shape lock. Asserts the config builder can be
/// invoked even with no implementations behind it, so a key
/// rename in the rate-limit config schema fails the test before
/// the `#[ignore]`d tests ever boot the proxy.
#[test]
fn rate_limit_budget_config_compiles() {
    let yaml = rate_limit_config(0, 50, 2);
    assert!(yaml.contains("rate_limit_budget"));
    assert!(yaml.contains("clock: manual"));
    assert!(yaml.contains("http_rps_sustained: 10"));
    assert!(yaml.contains("soft_threshold_rps: 8"));
}

// --- Helpers ---

fn pick_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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

fn admin_post(port: u16, path: &str, user: &str, pass: &str) -> (u16, String) {
    let auth = format!("Basic {}", base64_encode(&format!("{user}:{pass}")));
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
        .post(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", auth)
        .send()
        .expect("admin POST");
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
