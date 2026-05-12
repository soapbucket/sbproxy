//! End-to-end coverage for RFC 8594 idempotency middleware.
//!
//! `examples/idempotency/sb.yml` documents the contract: a per-origin
//! `idempotency:` block engages on POST / PUT / PATCH carrying the
//! configured header (default `Idempotency-Key`). Cache hits replay
//! the cached `(status, headers, body)` verbatim with
//! `x-sbproxy-idempotency: HIT`; body hash conflicts return 409 with
//! the `ledger.idempotency_conflict` body per RFC 8594.
//!
//! These tests verify the **client-visible** semantics. The middleware
//! engages in `request_body_filter` (after Pingora has already opened
//! the upstream connection), which means the upstream may observe one
//! aborted partial request per cache hit. Production deployments
//! should either route through sticky upstream connections (so the
//! upstream sees one full request and one aborted handshake), or
//! place the idempotency-enabled origin in front of an upstream that
//! tolerates aborted requests. Future work covers `request_filter`
//! body buffering to eliminate the upstream contact entirely.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_for(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "idem.localhost":
    action:
      type: proxy
      url: {upstream_url}
    idempotency:
      enabled: true
      header_name: Idempotency-Key
      ttl_secs: 60
      methods: [POST, PUT, PATCH]
      backend: memory
"#
    )
}

#[test]
fn second_call_with_same_key_and_body_returns_hit_marker() {
    let upstream = MockUpstream::start(json!({"ok": true, "id": "first"})).expect("start mock");
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    // First call: miss, forwarded.
    let first = proxy
        .post_json(
            "/orders",
            "idem.localhost",
            &json!({"sku":"abc","qty":1}),
            &[("Idempotency-Key", "key-1")],
        )
        .expect("first");
    assert_eq!(first.status, 200);
    assert!(
        !first.headers.contains_key("x-sbproxy-idempotency"),
        "first request must not carry HIT marker"
    );

    // Second call: same key + body. Replay from cache.
    let second = proxy
        .post_json(
            "/orders",
            "idem.localhost",
            &json!({"sku":"abc","qty":1}),
            &[("Idempotency-Key", "key-1")],
        )
        .expect("second");
    assert_eq!(
        second.status, 200,
        "cache hit must replay the cached status"
    );
    assert_eq!(
        second
            .headers
            .get("x-sbproxy-idempotency")
            .map(|s| s.as_str()),
        Some("HIT"),
        "replay must stamp the HIT marker so logs distinguish it"
    );
    let body = second.json().expect("decode body");
    assert_eq!(
        body["id"], "first",
        "replay must serve the cached body verbatim, not a fresh upstream call"
    );
}

#[test]
fn different_body_with_same_key_returns_409_conflict() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock");
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    // Prime the cache with body A.
    let first = proxy
        .post_json(
            "/orders",
            "idem.localhost",
            &json!({"sku":"abc","qty":1}),
            &[("Idempotency-Key", "key-2")],
        )
        .expect("first");
    assert_eq!(first.status, 200);

    // Retry with same key but DIFFERENT body: 409 conflict per RFC.
    let conflict = proxy
        .post_json(
            "/orders",
            "idem.localhost",
            &json!({"sku":"xyz","qty":99}),
            &[("Idempotency-Key", "key-2")],
        )
        .expect("second");
    assert_eq!(conflict.status, 409);
    let body = conflict.json().expect("decode JSON");
    assert_eq!(body["error"], "ledger.idempotency_conflict");
}

#[test]
fn request_without_idempotency_key_passes_through_untouched() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("start mock");
    let proxy =
        ProxyHarness::start_with_yaml(&config_for(&upstream.base_url())).expect("start proxy");

    let resp = proxy
        .post_json(
            "/orders",
            "idem.localhost",
            &json!({"sku":"abc","qty":1}),
            &[],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(
        !resp.headers.contains_key("x-sbproxy-idempotency"),
        "no key = no replay marker stamped"
    );
    // Without the header, every request flows to the upstream.
    let _ = proxy
        .post_json(
            "/orders",
            "idem.localhost",
            &json!({"sku":"abc","qty":1}),
            &[],
        )
        .expect("send");
    assert_eq!(
        upstream.captured().len(),
        2,
        "header-less requests must bypass the cache entirely"
    );
}

#[test]
fn workspace_isolation_keeps_keys_scoped() {
    let upstream_a = MockUpstream::start(json!({"workspace": "A"})).expect("start mock A");
    let upstream_b = MockUpstream::start(json!({"workspace": "B"})).expect("start mock B");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a.localhost":
    action:
      type: proxy
      url: {url_a}
    idempotency:
      enabled: true
      backend: memory
  "b.localhost":
    action:
      type: proxy
      url: {url_b}
    idempotency:
      enabled: true
      backend: memory
"#,
        url_a = upstream_a.base_url(),
        url_b = upstream_b.base_url(),
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Prime origin A with key "shared". The replay body would say `workspace: A`.
    let resp_a = proxy
        .post_json(
            "/x",
            "a.localhost",
            &json!({"v":1}),
            &[("Idempotency-Key", "shared")],
        )
        .expect("A first");
    assert_eq!(resp_a.status, 200);
    let body_a = resp_a.json().expect("A body");
    assert_eq!(body_a["workspace"], "A");

    // Origin B with the SAME key: must NOT be served from A's cache.
    // If isolation breaks, B would see `workspace: A` from origin A's
    // cached body (along with a HIT marker).
    let resp_b = proxy
        .post_json(
            "/x",
            "b.localhost",
            &json!({"v":1}),
            &[("Idempotency-Key", "shared")],
        )
        .expect("B first");
    assert_eq!(resp_b.status, 200);
    assert!(
        !resp_b.headers.contains_key("x-sbproxy-idempotency"),
        "cross-workspace key collision would have stamped HIT; isolation broken"
    );
    let body_b = resp_b.json().expect("B body");
    assert_eq!(
        body_b["workspace"], "B",
        "origin B must get its own upstream response, not A's cached body"
    );
}
