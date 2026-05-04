//! Wave 5 / Q5.5 (partial): TLS / UA spoof detection via the CEL helper
//! `tls_fingerprint_matches(ja4, agent_class_id)`.
//!
//! Pins the contract from `docs/adr-tls-fingerprint-pipeline.md` § "Worked
//! example: GPTBot UA-spoof detection" and § "Use cases for the
//! fingerprint". The CEL helper looks up the operator-vendored catalogue
//! at `crates/sbproxy-classifiers/data/tls-fingerprints.json` and returns
//! `true` if the supplied JA4 is in the catalogue's set for the supplied
//! `agent_class_id`. It returns `true` when the catalogue has no entry
//! for that class so uncatalogued agents are not penalised.
//!
//! The Q5.5 builder lane is `wave5/G5.5-anomaly-baselines`, but the helper
//! itself ships alongside G5.3 (`wave5/G5.3-tls-fingerprint-capture`) per
//! the ADR's § "Scripting surface". These tests reactivate when both
//! G5.3 and the catalogue update land.

use sbproxy_e2e::ProxyHarness;

// --- Test 1: GPTBot UA + Puppeteer JA4 -> helper returns false ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn gptbot_ua_with_puppeteer_ja4_does_not_match() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
origins:
  "spoof.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-ja4-matches"] = string(
            request.tls.ja4 != null
              ? tls_fingerprint_matches(request.tls.ja4, "openai-gptbot")
              : true
          )
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers("/", "spoof.localhost", &[("user-agent", "GPTBot/1.0")])
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4-matches").map(String::as_str),
        Some("false"),
        "Puppeteer JA4 against `openai-gptbot` catalogue entry must return false"
    );
}

// --- Test 2: operator policy fires 403 on UA-JA4 mismatch ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn operator_policy_403_on_ua_ja4_mismatch() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
origins:
  "spoof.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: expression
        expression: |
          !(request.agent_class == "openai-gptbot"
            && request.tls.trustworthy
            && request.tls.ja4 != null
            && !tls_fingerprint_matches(request.tls.ja4, "openai-gptbot"))
        deny_status: 403
        deny_message: "UA-JA4 mismatch: potential GPTBot spoof"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers("/", "spoof.localhost", &[("user-agent", "GPTBot/1.0")])
        .expect("GET");
    assert_eq!(
        resp.status, 403,
        "GPTBot UA + Puppeteer JA4 must be denied 403 by the spoof-detection policy"
    );
}

// --- Test 3: catalogue gap -> helper returns true (do-not-penalise) ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn uncatalogued_agent_class_returns_true() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
origins:
  "spoof.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-ja4-matches"] = string(
            tls_fingerprint_matches(
              request.tls.ja4 != null ? request.tls.ja4 : "t13d0000_000000000000",
              "definitely-not-in-catalogue"
            )
          )
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness.get("/", "spoof.localhost").expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4-matches").map(String::as_str),
        Some("true"),
        "uncatalogued agent_class must return true (do-not-penalise) per A5.1"
    );
}

// --- Test 4: matching catalogue entry returns true ---

#[test]
#[ignore = "TODO(wave5-day6+): day-5 landed the type: cel transform (Item 4) and the harness loopback trust-CIDR default (Item 5). Reactivation blocks on (1) the test must inject sidecar headers like x-sbproxy-tls-ja4 via get_with_headers so the JA4 actually populates request.tls.ja4, and (2) the day-5 CEL transform writes to the response BODY, not response HEADERS as these tests expect; the tests need to be rewritten to assert against the body."]
fn matching_ja4_returns_true() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 127.0.0.0/8
origins:
  "spoof.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: cel
        on_response: |
          resp.headers["x-ja4-matches"] = string(
            request.tls.ja4 != null
              ? tls_fingerprint_matches(request.tls.ja4, "openai-gptbot")
              : false
          )
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers("/", "spoof.localhost", &[("user-agent", "GPTBot/1.0")])
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4-matches").map(String::as_str),
        Some("true"),
        "real GPTBot JA4 must match the `openai-gptbot` catalogue entry"
    );
}
