//! Wave 5 / Q5.5 (partial): TLS / UA spoof detection via the CEL helper
//! `tls_fingerprint_matches(ja4, agent_class_id)`.
//!
//! Pins the contract from  § "Worked
//! example: GPTBot UA-spoof detection" and § "Use cases for the
//! fingerprint". The CEL helper returns `true` if the supplied JA4 is in
//! the catalogue's set for the supplied `agent_class_id`, and `true` when
//! the catalogue has no entry for that class so uncatalogued agents are
//! not penalised.
//!
//! Each test writes its own catalogue and points
//! `tls_fingerprint.catalog_file` at it. The embedded default carries no
//! fingerprints (WOR-2296), and since an absent class answers `true`, a
//! test about spoof detection has to populate both sides itself.
//!
//! The active tests use trusted sidecar JA4 injection because the e2e
//! harness is plaintext. Native TLS ClientHello coverage is tracked by
//! WOR-1444.

use sbproxy_e2e::ProxyHarness;

/// Synthetic JA4 values standing in for two catalogued agent classes.
///
/// Synthetic on purpose. The shipped catalogue carries no fingerprints,
/// because a real JA4 is a measurement of one client build and the
/// published collections of them are separately licensed (WOR-2296).
/// What these tests exercise is the matcher, and a made-up pair
/// exercises it exactly as well as a real one.
const GPTBOT_JA4: &str = "t13d1715h2_bbbbbbbbbbbb_bbbbbbbbbbbb";
const PUPPETEER_JA4: &str = "t13d1517h2_aaaaaaaaaaaa_aaaaaaaaaaaa";
const UNKNOWN_JA4: &str = "t13d0000h2_000000000000_000000000000";

/// Write a catalogue naming both classes, each with its own fingerprint,
/// and return its path.
///
/// Both have to be populated for the spoofing assertions to mean
/// anything: `matches` answers `true` for a class it has no entry for, so
/// against an empty `openai-gptbot` a Puppeteer JA4 would read as a
/// legitimate GPTBot rather than as a mismatch. That conservative
/// direction is the point of the empty default, and it is also why a
/// test about detecting mismatches has to supply its own catalogue.
fn spoof_catalog() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("tls-fingerprints.json");
    std::fs::write(
        &path,
        format!(
            r#"{{
  "version": 2,
  "updated_at": "2026-08-04T00:00:00Z",
  "entries": [
    {{ "agent_class": "openai-gptbot", "ja4": ["{GPTBOT_JA4}"] }},
    {{ "agent_class": "headless-puppeteer", "ja4": ["{PUPPETEER_JA4}"] }}
  ]
}}"#
        ),
    )
    .expect("write catalogue");
    let rendered = path.display().to_string();
    (dir, rendered)
}

// --- Test 1: GPTBot UA + Puppeteer JA4 -> helper returns false ---

#[test]
fn gptbot_ua_with_puppeteer_ja4_does_not_match() {
    let (_catalog_dir, catalog_file) = spoof_catalog();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    catalog_file: '{catalog_file}'
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
"#
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
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
    let (_catalog_dir, catalog_file) = spoof_catalog();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    catalog_file: '{catalog_file}'
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
"#
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
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
    let (_catalog_dir, catalog_file) = spoof_catalog();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    catalog_file: '{catalog_file}'
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
"#
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
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
    let (_catalog_dir, catalog_file) = spoof_catalog();
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
features:
  tls_fingerprint:
    enabled: true
    catalog_file: '{catalog_file}'
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
"#
    );
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
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
