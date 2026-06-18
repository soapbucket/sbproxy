//! Wave 5 / Q5.5 (partial): TLS / UA spoof detection via the CEL helper
//! `tls_fingerprint_matches(ja4, agent_class_id)`.
//!
//! Pins the contract from  § "Worked
//! example: GPTBot UA-spoof detection" and § "Use cases for the
//! fingerprint". The CEL helper looks up the operator-vendored catalogue
//! at `crates/sbproxy-classifiers/data/tls-fingerprints.json` and returns
//! `true` if the supplied JA4 is in the catalogue's set for the supplied
//! `agent_class_id`. It returns `true` when the catalogue has no entry
//! for that class so uncatalogued agents are not penalised.
//!
//! The active tests use trusted sidecar JA4 injection because the e2e
//! harness is plaintext. Native TLS ClientHello coverage is tracked by
//! WOR-1444.

use sbproxy_e2e::ProxyHarness;

const GPTBOT_JA4: &str = "t13d1715h2_5b57614c22b0_3d5424432f57";
const PUPPETEER_JA4: &str = "t13d1516h2_8daaf6152771_b1ff8ab2d16f";
const UNKNOWN_JA4: &str = "t13d0000h2_000000000000_000000000000";

// --- Test 1: GPTBot UA + Puppeteer JA4 -> helper returns false ---

#[test]
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
        headers:
          - op: set
            name: x-ja4-matches
            value_expr: 'size(request.tls.ja4) > 0 ? (tls_fingerprint_matches(request.tls.ja4, "openai-gptbot") ? "true" : "false") : "missing"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "spoof.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("x-sbproxy-tls-ja4", PUPPETEER_JA4),
            ],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4-matches").map(String::as_str),
        Some("false"),
        "Puppeteer JA4 against `openai-gptbot` catalogue entry must return false"
    );
}

// --- Test 2: operator policy fires 403 on UA-JA4 mismatch ---

#[test]
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
            && size(request.tls.ja4) > 0
            && !tls_fingerprint_matches(request.tls.ja4, "openai-gptbot"))
        deny_status: 403
        deny_message: "UA-JA4 mismatch: potential GPTBot spoof"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "spoof.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("x-sbproxy-tls-ja4", PUPPETEER_JA4),
            ],
        )
        .expect("GET");
    assert_eq!(
        resp.status, 403,
        "GPTBot UA + Puppeteer JA4 must be denied 403 by the spoof-detection policy"
    );
}

// --- Test 3: untrustworthy sidecar source does not fire hard policy ---

#[test]
fn operator_policy_allows_untrustworthy_ua_ja4_mismatch() {
    let yaml = r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    trustworthy_client_cidrs:
      - 203.0.113.0/24
    untrusted_client_cidrs:
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
            && size(request.tls.ja4) > 0
            && !tls_fingerprint_matches(request.tls.ja4, "openai-gptbot"))
        deny_status: 403
        deny_message: "UA-JA4 mismatch: potential GPTBot spoof"
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "spoof.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("x-sbproxy-tls-ja4", PUPPETEER_JA4),
            ],
        )
        .expect("GET");
    assert_eq!(
        resp.status, 200,
        "untrustworthy sidecar fingerprints must not trigger the hard spoof policy"
    );
}

// --- Test 4: catalogue gap -> helper returns true (do-not-penalise) ---

#[test]
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
        headers:
          - op: set
            name: x-ja4-matches
            value_expr: 'tls_fingerprint_matches(request.tls.ja4, "definitely-not-in-catalogue") ? "true" : "false"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "spoof.localhost",
            &[("x-sbproxy-tls-ja4", UNKNOWN_JA4)],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4-matches").map(String::as_str),
        Some("true"),
        "uncatalogued agent_class must return true (do-not-penalise) per A5.1"
    );
}

// --- Test 5: matching catalogue entry returns true ---

#[test]
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
        headers:
          - op: set
            name: x-ja4-matches
            value_expr: 'size(request.tls.ja4) > 0 ? (tls_fingerprint_matches(request.tls.ja4, "openai-gptbot") ? "true" : "false") : "missing"'
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/",
            "spoof.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("x-sbproxy-tls-ja4", GPTBOT_JA4),
            ],
        )
        .expect("GET");
    assert_eq!(
        resp.headers.get("x-ja4-matches").map(String::as_str),
        Some("true"),
        "real GPTBot JA4 must match the `openai-gptbot` catalogue entry"
    );
}
