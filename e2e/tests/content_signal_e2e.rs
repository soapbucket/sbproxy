//! Q4.3: `Content-Signal` response header e2e suite.
//!
//! Pins the contract from `docs/adr-content-negotiation-and-pricing.md`
//! § "Content-Signal response header" (G4.1) and ADR A4.1's value set:
//! the proxy stamps `Content-Signal: <value>` on 200 responses when
//! the origin's `content_signal` config key is set. Closed enum:
//! `ai-train`, `search`, `ai-input`. Any other value fails config
//! compilation per A1.8 closed-enum rules.
//!
//! These tests exercise the implementation that lands via the rust-A
//! branch (G4.5 `Content-Signal` header). Until that work is merged
//! to main, every test here is `#[ignore]`d with a `TODO(wave4-G4.5)`
//! marker so CI's `cargo test --workspace` stays green while the
//! suite still type-checks.

use sbproxy_e2e::ProxyHarness;

// --- Helpers ---

/// YAML fixture with a `content_signal` value at the origin level and
/// an `ai_crawl_control` policy that authorises the test token. The
/// signal value is parameterised so each test pins exactly one value.
fn fixture_with_signal(signal: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "signal.local":
    content_signal: {signal}
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - good-token-1
"#
    )
}

/// Same fixture without `content_signal` set at all so the proxy
/// emits no header.
const FIXTURE_NO_SIGNAL: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "signal.local":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - good-token-1
"#;

/// Issue a request that returns 200 (valid token) and snapshot the
/// `Content-Signal` header (lowercased keys per the harness).
fn fetch_signal(yaml: &str) -> (u16, Option<String>) {
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "signal.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/html"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");
    let header = resp.headers.get("content-signal").cloned();
    (resp.status, header)
}

// --- Test 1: ai-train ---

#[test]
fn content_signal_ai_train_stamped_when_configured() {
    let yaml = fixture_with_signal("ai-train");
    let (status, signal) = fetch_signal(&yaml);
    assert_eq!(status, 200, "valid token => 200");
    assert_eq!(
        signal.as_deref(),
        Some("ai-train"),
        "Content-Signal: ai-train when configured at origin level"
    );
}

// --- Test 2: search ---

#[test]
fn content_signal_search_stamped() {
    let yaml = fixture_with_signal("search");
    let (status, signal) = fetch_signal(&yaml);
    assert_eq!(status, 200);
    assert_eq!(signal.as_deref(), Some("search"));
}

// --- Test 3: ai-input ---

#[test]
fn content_signal_ai_input_stamped() {
    let yaml = fixture_with_signal("ai-input");
    let (status, signal) = fetch_signal(&yaml);
    assert_eq!(status, 200);
    assert_eq!(signal.as_deref(), Some("ai-input"));
}

// --- Test 4: header absent when not configured ---

#[test]
fn content_signal_absent_when_not_configured() {
    let (status, signal) = fetch_signal(FIXTURE_NO_SIGNAL);
    assert_eq!(status, 200);
    assert!(
        signal.is_none(),
        "no Content-Signal header when content_signal is unset, got: {signal:?}"
    );
}

// --- Test 5: invalid value rejected at config load ---

#[test]
fn content_signal_invalid_value_rejected_at_config_load() {
    // Per A1.8, `content_signal` is a closed enum. A YAML value
    // outside `{ai-train, search, ai-input}` must fail to compile and
    // the harness's `start_with_yaml` returns Err (the proxy refuses
    // to bind on a malformed config).
    let yaml = fixture_with_signal("junk");
    let result = ProxyHarness::start_with_yaml(&yaml);
    assert!(
        result.is_err(),
        "config compile must reject content_signal: junk (closed enum)"
    );
}

// --- Smoke: signal fixture compiles when value is valid ---

/// Sanity check: a known-good `content_signal` value compiles
/// without error. Runs by default; the rest are `#[ignore]`d until
/// G4.5 lands.
#[test]
fn signal_fixture_yaml_compiles() {
    let yaml = fixture_with_signal("ai-train");
    let _harness = ProxyHarness::start_with_yaml(&yaml).expect("fixture sb.yml must compile");
}
