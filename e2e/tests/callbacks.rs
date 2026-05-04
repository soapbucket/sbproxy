//! End-to-end coverage for `on_request` / `on_response` webhook
//! callbacks.
//!
//! `examples/79-webhook-signing/sb.yml` documents the contract:
//! configured `on_request` and `on_response` URLs receive a signed
//! POST with the request envelope. Callbacks default to audit-only
//! (fire-and-forget) so the request path is not gated on the
//! receiver. Setting `enrich: true` on a callback switches it to
//! enrichment mode: the proxy awaits the response and injects any
//! `X-Inject-*` headers from the reply into the upstream request
//! (`on_request`) or the client-facing response (`on_response`).

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;
use std::time::{Duration, Instant};

#[test]
fn on_request_callback_fires_for_each_request() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let cb = MockUpstream::start(json!({"ack": true})).expect("callback receiver");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cb.localhost":
    action:
      type: proxy
      url: "{}"
    on_request:
      - url: "{}/hook"
        method: POST
        timeout: 5
"#,
        upstream.base_url(),
        cb.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let _ = proxy.get("/path-a", "cb.localhost").expect("req a");
    let _ = proxy.get("/path-b", "cb.localhost").expect("req b");

    // Webhooks are fire-and-forget on a background task. Poll for
    // up to two seconds before giving up. The webhook helper has
    // its own per-call timeout, so we don't need to be precise.
    let deadline = Instant::now() + Duration::from_secs(2);
    while cb.captured().len() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }

    let cb_calls = cb.captured();
    assert_eq!(
        cb_calls.len(),
        2,
        "expected one webhook per request, got {}",
        cb_calls.len()
    );
    for call in &cb_calls {
        assert_eq!(call.method, "POST");
        assert!(
            call.headers
                .get("x-sbproxy-event")
                .is_some_and(|v| v == "on_request"),
            "missing x-sbproxy-event header on callback"
        );
        let body = std::str::from_utf8(&call.body).expect("utf8");
        assert!(
            body.contains("\"event\":\"on_request\""),
            "callback envelope must carry event field, got: {body}"
        );
    }
}

#[test]
fn on_response_callback_fires_after_request_completes() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let cb = MockUpstream::start(json!({"ack": true})).expect("callback receiver");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cb.localhost":
    action:
      type: proxy
      url: "{}"
    on_response:
      - url: "{}/hook"
        method: POST
        timeout: 5
"#,
        upstream.base_url(),
        cb.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let _ = proxy.get("/done", "cb.localhost").expect("req");

    let deadline = Instant::now() + Duration::from_secs(2);
    while cb.captured().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }

    let calls = cb.captured();
    assert!(!calls.is_empty(), "on_response callback must fire");
    let body = std::str::from_utf8(&calls[0].body).expect("utf8");
    assert!(
        body.contains("\"event\":\"on_response\""),
        "envelope must carry on_response event: {body}"
    );
    assert!(
        body.contains("\"status\""),
        "on_response envelope must carry the upstream status: {body}"
    );
}

#[test]
fn callback_signature_header_present_when_secret_configured() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let cb = MockUpstream::start(json!({"ack": true})).expect("callback receiver");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cb.localhost":
    action:
      type: proxy
      url: "{}"
    on_request:
      - url: "{}/hook"
        method: POST
        secret: shared-secret-test
        timeout: 5
"#,
        upstream.base_url(),
        cb.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let _ = proxy.get("/signed", "cb.localhost").expect("req");

    let deadline = Instant::now() + Duration::from_secs(2);
    while cb.captured().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }

    let calls = cb.captured();
    assert!(!calls.is_empty(), "callback must fire");
    assert!(
        calls[0].headers.contains_key("x-sbproxy-signature"),
        "signed callback must include x-sbproxy-signature header, got headers: {:?}",
        calls[0].headers.keys().collect::<Vec<_>>()
    );
}

// --- Synchronous enrichment behaviours (`enrich: true`) ---

#[test]
fn on_request_enrichment_injects_headers_into_upstream() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    // The callback receiver responds with `X-Inject-User-Id: 42`.
    // The proxy must strip the `X-Inject-` prefix and add
    // `User-Id: 42` to the upstream request.
    let cb = MockUpstream::start_with_response_headers(
        json!({"ack": true}),
        vec![
            ("X-Inject-User-Id".into(), "42".into()),
            ("X-Inject-Tenant".into(), "acme".into()),
        ],
    )
    .expect("callback receiver");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cb.localhost":
    action:
      type: proxy
      url: "{}"
    on_request:
      - url: "{}/hook"
        method: POST
        enrich: true
        timeout: 5
"#,
        upstream.base_url(),
        cb.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let _ = proxy.get("/enrich", "cb.localhost").expect("req");

    let upstream_calls = upstream.captured();
    assert_eq!(
        upstream_calls.len(),
        1,
        "upstream must see exactly one call"
    );
    let hdrs = &upstream_calls[0].headers;
    assert_eq!(
        hdrs.get("user-id").map(String::as_str),
        Some("42"),
        "upstream did not see X-Inject-User-Id stripped to User-Id; headers: {:?}",
        hdrs.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        hdrs.get("tenant").map(String::as_str),
        Some("acme"),
        "upstream did not see X-Inject-Tenant stripped to Tenant"
    );
}

#[test]
fn on_response_callback_injects_audit_header() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    // The callback receiver responds with `X-Inject-X-Audit-Id`.
    // The proxy must strip the `X-Inject-` prefix and add
    // `X-Audit-Id` to the client-facing response.
    let cb = MockUpstream::start_with_response_headers(
        json!({"ack": true}),
        vec![("X-Inject-X-Audit-Id".into(), "audit-12345".into())],
    )
    .expect("callback receiver");

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cb.localhost":
    action:
      type: proxy
      url: "{}"
    on_response:
      - url: "{}/hook"
        method: POST
        enrich: true
        timeout: 5
"#,
        upstream.base_url(),
        cb.base_url()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy.get("/audited", "cb.localhost").expect("req");
    let audit = resp.headers.get("x-audit-id").cloned();
    assert_eq!(
        audit.as_deref(),
        Some("audit-12345"),
        "client response missing X-Audit-Id header injected by enrichment callback; got headers: {:?}",
        resp.headers
    );
}

#[test]
fn callback_timeout_falls_back_without_blocking() {
    // No callback receiver: the URL points at an unused port. The
    // enrichment callback will time out (timeout: 1) but must not
    // fail the request. The upstream still sees the call; the
    // injected headers are simply absent.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");

    // Bind+drop a listener to find a free port that won't accept.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("dead port bind");
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cb.localhost":
    action:
      type: proxy
      url: "{}"
    on_request:
      - url: "http://127.0.0.1:{}/hook"
        method: POST
        enrich: true
        timeout: 1
"#,
        upstream.base_url(),
        dead_port
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let start = Instant::now();
    let resp = proxy.get("/timeout", "cb.localhost").expect("req");
    let elapsed = start.elapsed();
    assert!(
        (200..300).contains(&resp.status),
        "request must still succeed despite enrichment timeout: status {}",
        resp.status
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "enrichment timeout must not block forever (elapsed {:?})",
        elapsed
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "upstream still received the call after the failed enrichment"
    );
}
