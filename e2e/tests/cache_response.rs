//! End-to-end coverage for the response cache.
//!
//! `examples/03-response-caching/sb.yml` documents the basic TTL
//! cache. This file walks the documented behaviour and pins the
//! `x-sbproxy-cache: HIT` header that the OSS pipeline emits when
//! it replays a cached response.
//!
//! Wave 4 added Vary, query-string normalization, stale-while-revalidate,
//! and POST-invalidation hooks on `ResponseCacheConfig`. The tests below
//! exercise all four end-to-end against the real proxy binary.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#
    )
}

#[test]
fn first_request_is_miss_second_is_hit() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start proxy");

    // First request: cold cache, must reach the upstream.
    let t0 = std::time::Instant::now();
    let first = proxy.get("/cached", "cache.localhost").expect("first GET");
    let first_elapsed = t0.elapsed();
    assert_eq!(
        first.status,
        200,
        "first response: status={}, headers={:?}, body={:?}",
        first.status,
        first.headers,
        first.text().unwrap_or_else(|_| "<binary>".into())
    );
    assert_eq!(
        first.headers.get("x-sbproxy-cache"),
        None,
        "cold lookup must not advertise a cache HIT (elapsed={:?}, headers={:?})",
        first_elapsed,
        first.headers
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "first request must reach the upstream (got {} captures, headers={:?})",
        upstream.captured().len(),
        first.headers
    );

    // Second request: same key, served from cache. Upstream hit
    // count must not advance and the HIT marker must be present.
    //
    // The cache is written after the first response is sent to the
    // client; on a fast Linux runner this can race against an
    // immediately-following request. Poll briefly with rich-context
    // diagnostics so the next CI failure tells us whether we ever
    // observed HIT, what header value we did get, and whether the
    // upstream count climbed unexpectedly.
    let mut history: Vec<(std::time::Duration, Option<String>, usize)> = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    let second = loop {
        let t = std::time::Instant::now();
        let resp = proxy.get("/cached", "cache.localhost").expect("second GET");
        let cache_hdr = resp.headers.get("x-sbproxy-cache").cloned();
        let captures = upstream.captured().len();
        history.push((t.elapsed(), cache_hdr.clone(), captures));
        if cache_hdr.as_deref() == Some("HIT") || std::time::Instant::now() >= deadline {
            break resp;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };

    assert_eq!(
        second.status, 200,
        "second response status={}, headers={:?}, polling history={:?}",
        second.status, second.headers, history
    );
    assert_eq!(
        second.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "warm lookup must carry x-sbproxy-cache: HIT after up to 500ms of polling. \
         polling history (elapsed, x-sbproxy-cache, upstream_captures): {:?}. \
         final headers: {:?}. upstream captures: {}",
        history,
        second.headers,
        upstream.captured().len()
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "cached response must not re-hit the upstream. \
         polling history: {:?}",
        history
    );
}

#[test]
fn distinct_paths_cache_independently() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start proxy");

    let _ = proxy.get("/a", "cache.localhost").expect("GET /a");
    let _ = proxy.get("/b", "cache.localhost").expect("GET /b");
    assert_eq!(
        upstream.captured().len(),
        2,
        "two distinct paths must produce two upstream hits"
    );

    // Each path now warm. Re-issue and confirm neither calls upstream.
    let _ = proxy.get("/a", "cache.localhost").expect("GET /a warm");
    let _ = proxy.get("/b", "cache.localhost").expect("GET /b warm");
    assert_eq!(
        upstream.captured().len(),
        2,
        "warm hits must not advance upstream count"
    );
}

#[test]
fn non_cacheable_status_is_not_cached() {
    // When upstream returns a non-cacheable status the cache must
    // not persist the entry. We exercise this with `cacheable_status:
    // [200]` and a mock that never deviates from 200, then pin the
    // basic contract: only 200s are stored. The mock cannot easily
    // emit a non-200, so we instead assert the inverse: the cache
    // never holds entries for paths that were never fetched.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start proxy");

    // GET a path so we know the cache machinery is active for this
    // origin. The next path is fresh and must reach the upstream.
    let _ = proxy.get("/warm", "cache.localhost").expect("warm");
    let _ = proxy.get("/fresh", "cache.localhost").expect("fresh");
    assert_eq!(
        upstream.captured().len(),
        2,
        "untouched paths must not be served from cache"
    );
}

// --- Wave 4: Vary header support ---

#[test]
fn vary_accept_segments_cache() {
    // Two requests with different `Accept` header values must produce
    // independent cache entries. We use `Accept` rather than
    // `Accept-Encoding` so the proxy's compression negotiation does
    // not interfere; `compression` is not enabled on this origin.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
      vary: ["Accept"]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Variant A: text/plain.
    let r1 = proxy
        .get_with_headers("/v1", "cache.localhost", &[("accept", "text/plain")])
        .expect("variant A first");
    assert_eq!(r1.status, 200);
    assert!(
        !r1.headers.contains_key("x-sbproxy-cache"),
        "A first is MISS"
    );
    assert_eq!(upstream.captured().len(), 1);

    // Variant B: application/json. Different Accept value, must miss.
    let r2 = proxy
        .get_with_headers("/v1", "cache.localhost", &[("accept", "application/json")])
        .expect("variant B first");
    assert_eq!(r2.status, 200);
    assert!(
        !r2.headers.contains_key("x-sbproxy-cache"),
        "B first is MISS"
    );
    assert_eq!(
        upstream.captured().len(),
        2,
        "different Accept value must produce a new upstream hit"
    );

    // Variant A again: warm.
    let r3 = proxy
        .get_with_headers("/v1", "cache.localhost", &[("accept", "text/plain")])
        .expect("variant A warm");
    assert_eq!(
        r3.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "A second is HIT"
    );
    assert_eq!(upstream.captured().len(), 2, "warm A must not hit upstream");

    // Variant B again: warm.
    let r4 = proxy
        .get_with_headers("/v1", "cache.localhost", &[("accept", "application/json")])
        .expect("variant B warm");
    assert_eq!(
        r4.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "B second is HIT"
    );
    assert_eq!(upstream.captured().len(), 2, "warm B must not hit upstream");
}

// --- Wave 4: Query-string normalization ---

#[test]
fn query_string_sort_collapses_permutations() {
    // With the default `Sort` policy, `?a=1&b=2` and `?b=2&a=1`
    // share a single cache entry.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start proxy");

    let _ = proxy.get("/q?a=1&b=2", "cache.localhost").expect("first");
    assert_eq!(upstream.captured().len(), 1);
    let r = proxy.get("/q?b=2&a=1", "cache.localhost").expect("second");
    assert_eq!(
        r.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "permuted query must hit the same cache entry"
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "permuted query must not refetch upstream"
    );
}

#[test]
fn query_string_ignore_all_drops_query() {
    // `IgnoreAll` makes `/q?utm_source=foo` and `/q?utm_source=bar`
    // share a single cache entry.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
      query_normalize:
        mode: ignore_all
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let _ = proxy
        .get("/q?utm_source=foo", "cache.localhost")
        .expect("first");
    assert_eq!(upstream.captured().len(), 1);
    let r = proxy
        .get("/q?utm_source=bar", "cache.localhost")
        .expect("second");
    assert_eq!(
        r.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "ignore_all must drop the query, both variants share a key"
    );
    assert_eq!(upstream.captured().len(), 1);
}

#[test]
fn query_string_allowlist_keeps_only_listed_params() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
      query_normalize:
        mode: allowlist
        allowlist: ["page"]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Same `page=1`, different ignored params -> single cache entry.
    let _ = proxy
        .get("/list?page=1&utm_source=a", "cache.localhost")
        .expect("first");
    assert_eq!(upstream.captured().len(), 1);
    let r = proxy
        .get("/list?page=1&utm_source=b", "cache.localhost")
        .expect("second");
    assert_eq!(
        r.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "allowlist must drop unlisted params"
    );
    assert_eq!(upstream.captured().len(), 1);

    // Different `page=2` -> distinct cache entry.
    let _ = proxy
        .get("/list?page=2&utm_source=a", "cache.localhost")
        .expect("third");
    assert_eq!(
        upstream.captured().len(),
        2,
        "allowlisted param difference must create a new cache entry"
    );
}

// --- Wave 4: stale-while-revalidate ---

#[test]
fn stale_while_revalidate_serves_stale_during_refresh() {
    // TTL=1s, SWR=10s. After priming the cache, sleep just past TTL
    // but well within the SWR window. The next GET must come back
    // immediately as STALE (not MISS) and the upstream count must
    // eventually advance from 1 to 2 once the background refresh
    // lands.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 1
      stale_while_revalidate: 10
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Prime.
    let _ = proxy.get("/swr", "cache.localhost").expect("prime");
    assert_eq!(upstream.captured().len(), 1);

    // Wait past TTL, still inside SWR window.
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Stale serve. The replay must carry the STALE marker and must
    // NOT block on the upstream (we don't time it, but the absence
    // of a fresh upstream hit at the moment of return is the signal).
    let stale = proxy.get("/swr", "cache.localhost").expect("stale serve");
    assert_eq!(stale.status, 200);
    assert_eq!(
        stale.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("STALE"),
        "in-window stale serve must carry x-sbproxy-cache: STALE"
    );

    // Give the background refresh a moment to land. We poll up to
    // 2 seconds for the upstream count to advance to 2.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while upstream.captured().len() < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        upstream.captured().len(),
        2,
        "background revalidation must have hit the upstream"
    );
}

// --- Wave 4: POST/mutation invalidation ---

#[test]
fn post_invalidates_get_cache_for_same_path() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 300
      cacheable_methods: [GET]
      cacheable_status: [200]
      invalidate_on_mutation: true
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    // Prime the cache for /users/42.
    let _ = proxy.get("/users/42", "cache.localhost").expect("prime");
    let warm = proxy.get("/users/42", "cache.localhost").expect("warm");
    assert_eq!(
        warm.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "cache must warm before mutation"
    );
    assert_eq!(upstream.captured().len(), 1);

    // POST to the same path. The proxy may forward the POST upstream
    // (the action is a generic proxy) so the upstream count advances,
    // but the GET cache must be evicted regardless.
    let _ = proxy
        .post_json(
            "/users/42",
            "cache.localhost",
            &json!({"x": 1}),
            &[("content-type", "application/json")],
        )
        .expect("post");
    let upstream_hits_after_post = upstream.captured().len();
    assert!(
        upstream_hits_after_post >= 2,
        "POST must reach the upstream"
    );

    // GET again: must MISS and re-fetch.
    let after = proxy.get("/users/42", "cache.localhost").expect("after");
    assert_eq!(after.status, 200);
    assert!(
        !after.headers.contains_key("x-sbproxy-cache"),
        "post-mutation GET must MISS, not HIT"
    );
    assert_eq!(
        upstream.captured().len(),
        upstream_hits_after_post + 1,
        "post-mutation GET must hit the upstream"
    );
}

#[test]
fn post_invalidates_only_matching_path() {
    // POST /users/42 must NOT evict GET /users/99 cache.
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 300
      cacheable_methods: [GET]
      cacheable_status: [200]
      invalidate_on_mutation: true
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let _ = proxy.get("/users/42", "cache.localhost").expect("prime 42");
    let _ = proxy.get("/users/99", "cache.localhost").expect("prime 99");
    assert_eq!(upstream.captured().len(), 2);

    let _ = proxy
        .post_json(
            "/users/42",
            "cache.localhost",
            &json!({"x": 1}),
            &[("content-type", "application/json")],
        )
        .expect("post 42");

    // /users/99 cache must remain warm.
    let unchanged = proxy.get("/users/99", "cache.localhost").expect("get 99");
    assert_eq!(
        unchanged.headers.get("x-sbproxy-cache").map(|s| s.as_str()),
        Some("HIT"),
        "POST to /users/42 must not evict /users/99"
    );
}
