//! End-to-end coverage for the `waf` policy.
//!
//! Exercises the documented behaviour from `examples/31-waf/sb.yml`:
//! the OWASP-lite ruleset blocks SQLi, XSS, and path-traversal
//! patterns in the request URI when `owasp_crs.enabled: true`.
//!
//! The bundled patterns live in
//! `crates/sbproxy-modules/src/policy/mod.rs` (SQLI_PATTERN,
//! XSS_PATTERN, PATH_TRAVERSAL_PATTERN, SQLI_STRICT_PATTERN). The
//! proxy URL-decodes the URI before matching so percent-encoded
//! payloads still trigger. Each built-in pattern carries an OWASP
//! CRS-style paranoia tag and is gated on the policy's `paranoia`
//! level.

use sbproxy_e2e::ProxyHarness;

fn config(action_on_match: &str, test_mode: bool) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "waf.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        owasp_crs:
          enabled: true
        action_on_match: {action}
        test_mode: {test_mode}
        fail_open: false
"#,
        action = action_on_match,
        test_mode = test_mode,
    )
}

fn config_with_paranoia(paranoia: u8) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "waf.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: waf
        owasp_crs:
          enabled: true
        paranoia: {paranoia}
        action_on_match: block
        test_mode: false
        fail_open: false
"#,
        paranoia = paranoia,
    )
}

#[test]
fn benign_request_passes_through() {
    let harness = ProxyHarness::start_with_yaml(&config("block", false)).expect("start proxy");

    let resp = harness
        .get("/healthz?ok=1", "waf.localhost")
        .expect("benign GET");
    assert_eq!(
        resp.status,
        200,
        "benign request must pass; body = {:?}",
        resp.text().ok()
    );
}

#[test]
fn sqli_payload_in_query_is_blocked_with_403() {
    let harness = ProxyHarness::start_with_yaml(&config("block", false)).expect("start proxy");

    // `'\s*or\s*'` matches one of the SQLI_PATTERN alternations after
    // percent-decoding. This mirrors the curl command in the example.
    let resp = harness
        .get("/get?id=1%27%20OR%20%271%27=%271", "waf.localhost")
        .expect("SQLi request");
    assert_eq!(
        resp.status,
        403,
        "SQLi pattern should be blocked; got {} body = {:?}",
        resp.status,
        resp.text().ok()
    );
}

#[test]
fn xss_payload_in_query_is_blocked_with_403() {
    let harness = ProxyHarness::start_with_yaml(&config("block", false)).expect("start proxy");

    // `<script` matches the XSS_PATTERN. URL-encode the angle brackets.
    let resp = harness
        .get(
            "/page?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "waf.localhost",
        )
        .expect("XSS request");
    assert_eq!(
        resp.status, 403,
        "XSS pattern should be blocked; got {}",
        resp.status
    );
}

#[test]
fn path_traversal_payload_is_blocked_with_403() {
    let harness = ProxyHarness::start_with_yaml(&config("block", false)).expect("start proxy");

    // `etc/passwd` matches PATH_TRAVERSAL_PATTERN.
    let resp = harness
        .get("/files?p=etc/passwd", "waf.localhost")
        .expect("traversal request");
    assert_eq!(
        resp.status, 403,
        "path traversal pattern should be blocked; got {}",
        resp.status
    );
}

#[test]
fn sqli_in_log_mode_is_not_blocked() {
    // `action_on_match: log` should record the match but let the
    // request through. This is the closest analogue to a "lower
    // paranoia" mode the OSS WAF exposes today.
    let harness = ProxyHarness::start_with_yaml(&config("log", false)).expect("start proxy");

    let resp = harness
        .get("/get?id=1%27%20OR%20%271%27=%271", "waf.localhost")
        .expect("SQLi request in log mode");
    assert_eq!(
        resp.status, 200,
        "SQLi in log mode must NOT block; got {}",
        resp.status
    );
}

#[test]
fn test_mode_logs_but_does_not_block_even_when_action_is_block() {
    // `test_mode: true` overrides `action_on_match: block` and must
    // never block the request, only log a warning.
    let harness = ProxyHarness::start_with_yaml(&config("block", true)).expect("start proxy");

    let resp = harness
        .get("/get?id=1%27%20OR%20%271%27=%271", "waf.localhost")
        .expect("SQLi request in test_mode");
    assert_eq!(
        resp.status, 200,
        "test_mode=true must short-circuit block decision; got {}",
        resp.status
    );
}

// --- Paranoia level coverage ---
//
// Built-in `SQLI_STRICT_PATTERN` is tagged paranoia=2 and only runs when
// the policy's `paranoia` level is raised to 2 or above. The baseline
// SQLi/XSS/path-traversal patterns are paranoia=1 and always run. The
// tests below pin both directions of that contract end-to-end.

#[test]
fn paranoia_one_skips_strict_only_sqli_payload() {
    // `information_schema` is a metadata-table reconnaissance signature
    // that only matches the strict (paranoia=2) corpus, not the
    // baseline. With the default paranoia=1 the request must pass.
    let harness = ProxyHarness::start_with_yaml(&config_with_paranoia(1)).expect("start proxy");

    let resp = harness
        .get("/api?table=information_schema", "waf.localhost")
        .expect("strict-only SQLi payload at paranoia=1");
    assert_eq!(
        resp.status,
        200,
        "paranoia=1 must skip strict-only signatures; got {} body={:?}",
        resp.status,
        resp.text().ok()
    );
}

#[test]
fn paranoia_two_blocks_strict_only_sqli_payload() {
    // Same payload, paranoia raised to 2: the strict SQLi rule fires.
    let harness = ProxyHarness::start_with_yaml(&config_with_paranoia(2)).expect("start proxy");

    let resp = harness
        .get("/api?table=information_schema", "waf.localhost")
        .expect("strict-only SQLi payload at paranoia=2");
    assert_eq!(
        resp.status,
        403,
        "paranoia=2 must run strict signatures; got {} body={:?}",
        resp.status,
        resp.text().ok()
    );
}

#[test]
fn paranoia_one_still_blocks_baseline_sqli_payload() {
    // Sanity check: paranoia=1 keeps blocking the baseline corpus so
    // raising the field is a strict superset, not a mode change.
    let harness = ProxyHarness::start_with_yaml(&config_with_paranoia(1)).expect("start proxy");

    let resp = harness
        .get("/get?id=1%27%20OR%20%271%27=%271", "waf.localhost")
        .expect("baseline SQLi payload at paranoia=1");
    assert_eq!(
        resp.status, 403,
        "paranoia=1 must still block baseline signatures; got {}",
        resp.status
    );
}
