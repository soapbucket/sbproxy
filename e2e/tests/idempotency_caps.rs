//! Coverage for the per-request and pool caps on the idempotency
//! middleware. The middleware bounds memory via three knobs on the
//! `idempotency:` block:
//!
//! - `max_request_body_bytes`: per-request cap on buffered body
//! - `max_response_body_bytes`: per-response cap on cached body
//! - `max_concurrent_buffers`: per-origin pool of buffered requests
//!
//! When any cap is exceeded, the middleware *gracefully degrades*:
//! it skips caching for that specific request and stamps an
//! `x-sbproxy-idempotency: SKIPPED-...` marker on the response so
//! operators can spot pool pressure or oversize bodies in their logs.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

#[test]
fn oversize_request_body_skips_caching_and_marks_response() {
    // Tiny cap so a small JSON payload trips the limit.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cap.localhost":
    action:
      type: proxy
      url: {url}
    idempotency:
      enabled: true
      max_request_body_bytes: 16
      backend: memory
"#,
        url = upstream.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Body is 40 bytes, well past the 16-byte cap.
    let body = json!({"sku": "a-very-long-product-identifier", "qty": 1});
    let resp = proxy
        .post_json(
            "/orders",
            "cap.localhost",
            &body,
            &[("Idempotency-Key", "key-cap")],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "oversize request must still succeed");
    assert_eq!(
        resp.headers
            .get("x-sbproxy-idempotency")
            .map(|s| s.as_str()),
        Some("SKIPPED-OVERSIZE-REQUEST"),
        "oversize body must stamp the skip marker"
    );
    // Retry with the same key + body. Since the first request was
    // not cached, the retry hits the upstream too. Both requests
    // reach the upstream.
    let _ = proxy
        .post_json(
            "/orders",
            "cap.localhost",
            &body,
            &[("Idempotency-Key", "key-cap")],
        )
        .expect("send");
    assert_eq!(
        upstream.captured().len(),
        2,
        "oversize requests must NOT be cached; both calls reach upstream"
    );
}

#[test]
fn small_request_under_cap_still_caches_normally() {
    let upstream = MockUpstream::start(json!({"ok": true, "id": "first"})).expect("start mock");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cap.localhost":
    action:
      type: proxy
      url: {url}
    idempotency:
      enabled: true
      max_request_body_bytes: 4096
      backend: memory
"#,
        url = upstream.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let body = json!({"x": 1});
    let first = proxy
        .post_json(
            "/orders",
            "cap.localhost",
            &body,
            &[("Idempotency-Key", "key-small")],
        )
        .expect("first");
    assert_eq!(first.status, 200);
    assert!(
        !first.headers.contains_key("x-sbproxy-idempotency"),
        "first call must not stamp a marker"
    );

    let second = proxy
        .post_json(
            "/orders",
            "cap.localhost",
            &body,
            &[("Idempotency-Key", "key-small")],
        )
        .expect("second");
    assert_eq!(
        second
            .headers
            .get("x-sbproxy-idempotency")
            .map(|s| s.as_str()),
        Some("HIT"),
        "small body must still replay from cache when under cap"
    );
}

#[test]
fn pool_exhaustion_skips_caching_and_marks_response() {
    // max_concurrent_buffers: 0 means EVERY incoming request finds
    // the pool exhausted. The middleware should disengage and stamp
    // the SKIPPED-POOL-FULL marker rather than holding the request.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "pool.localhost":
    action:
      type: proxy
      url: {url}
    idempotency:
      enabled: true
      max_concurrent_buffers: 0
      backend: memory
"#,
        url = upstream.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy
        .post_json(
            "/orders",
            "pool.localhost",
            &json!({"x": 1}),
            &[("Idempotency-Key", "key-pool")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers
            .get("x-sbproxy-idempotency")
            .map(|s| s.as_str()),
        Some("SKIPPED-POOL-FULL"),
        "pool exhaustion must stamp the skip marker"
    );
}
