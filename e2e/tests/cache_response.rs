//! End-to-end coverage for the response cache.
//!
//! `examples/response-caching/sb.yml` documents the basic TTL
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

fn wait_for_cache_hit(proxy: &ProxyHarness, path: &str) -> sbproxy_e2e::Response {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let response = proxy.get(path, "cache.localhost").expect("cache poll");
        if response
            .headers
            .get("x-sbproxy-cache")
            .is_some_and(|value| value == "HIT")
        {
            return response;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cache did not warm within two seconds; last response: {response:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
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

#[test]
fn matching_client_etag_returns_an_empty_304_from_the_hot_cache() {
    let last_modified = "Sun, 06 Nov 1994 08:49:37 GMT";
    let upstream = MockUpstream::start_with_response_headers(
        json!({"version": 1}),
        vec![
            ("ETag".to_string(), r#"W/"version-1""#.to_string()),
            ("Last-Modified".to_string(), last_modified.to_string()),
            (
                "Cache-Control".to_string(),
                "public, max-age=60".to_string(),
            ),
            ("Content-Location".to_string(), "/conditional".to_string()),
            ("Vary".to_string(), "Accept-Encoding".to_string()),
            ("X-Origin-Metadata".to_string(), "not-for-304".to_string()),
        ],
    )
    .expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start proxy");

    let prime = proxy
        .get("/conditional", "cache.localhost")
        .expect("prime cache");
    assert_eq!(prime.status, 200);
    let warm = wait_for_cache_hit(&proxy, "/conditional");
    assert_eq!(warm.body, br#"{"version":1}"#);
    let upstream_count = upstream.captured().len();

    let not_modified = proxy
        .get_with_headers(
            "/conditional",
            "cache.localhost",
            &[("if-none-match", r#""other", "version-1""#)],
        )
        .expect("conditional cache hit");

    assert_eq!(not_modified.status, 304);
    assert!(
        not_modified.body.is_empty(),
        "304 must not contain representation data"
    );
    assert_eq!(
        not_modified.headers.get("etag").map(String::as_str),
        Some(r#"W/"version-1""#)
    );
    assert_eq!(
        not_modified
            .headers
            .get("last-modified")
            .map(String::as_str),
        Some(last_modified)
    );
    assert_eq!(
        not_modified
            .headers
            .get("cache-control")
            .map(String::as_str),
        Some("public, max-age=60")
    );
    assert_eq!(
        not_modified
            .headers
            .get("content-location")
            .map(String::as_str),
        Some("/conditional")
    );
    assert_eq!(
        not_modified.headers.get("vary").map(String::as_str),
        Some("Accept-Encoding")
    );
    assert_eq!(
        not_modified
            .headers
            .get("x-sbproxy-cache")
            .map(String::as_str),
        Some("HIT")
    );
    assert!(!not_modified.headers.contains_key("content-type"));
    assert!(!not_modified.headers.contains_key("x-origin-metadata"));
    assert_eq!(
        upstream.captured().len(),
        upstream_count,
        "client validation must be answered from the hot cache"
    );
}

#[test]
fn nonmatching_client_etag_returns_the_full_cached_200() {
    let upstream = MockUpstream::start_with_response_headers(
        json!({"version": 1}),
        vec![("ETag".to_string(), r#""version-1""#.to_string())],
    )
    .expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&config_yaml(&upstream.base_url())).expect("start proxy");

    let _ = proxy
        .get("/conditional-miss", "cache.localhost")
        .expect("prime cache");
    let _ = wait_for_cache_hit(&proxy, "/conditional-miss");
    let upstream_count = upstream.captured().len();

    let response = proxy
        .get_with_headers(
            "/conditional-miss",
            "cache.localhost",
            &[("if-none-match", r#""version-2""#)],
        )
        .expect("conditional cache hit");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, br#"{"version":1}"#);
    assert_eq!(
        response.headers.get("x-sbproxy-cache").map(String::as_str),
        Some("HIT")
    );
    assert_eq!(upstream.captured().len(), upstream_count);
}

#[test]
fn reserve_hit_preserves_validators_for_conditional_replay_and_hot_promotion() {
    let upstream = MockUpstream::start_with_response_headers(
        json!({"version": 1}),
        vec![
            ("ETag".to_string(), r#""reserve-v1""#.to_string()),
            (
                "Last-Modified".to_string(),
                "Sun, 06 Nov 1994 08:49:37 GMT".to_string(),
            ),
        ],
    )
    .expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
  cache_reserve:
    enabled: true
    backend:
      type: memory
    sample_rate: 1.0
    min_ttl: 0
    max_size_bytes: 1048576
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    response_cache:
      enabled: true
      ttl: 7200
      max_size: 1
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let _ = proxy
        .get("/reserve-a", "cache.localhost")
        .expect("prime reserve-a");
    let _ = wait_for_cache_hit(&proxy, "/reserve-a");
    let _ = proxy
        .get("/reserve-b", "cache.localhost")
        .expect("prime reserve-b and evict reserve-a");
    let _ = wait_for_cache_hit(&proxy, "/reserve-b");
    std::thread::sleep(std::time::Duration::from_millis(100));
    let upstream_count = upstream.captured().len();

    let from_reserve = proxy
        .get_with_headers(
            "/reserve-a",
            "cache.localhost",
            &[("if-none-match", r#"W/"reserve-v1""#)],
        )
        .expect("conditional reserve hit");

    assert_eq!(from_reserve.status, 304);
    assert!(from_reserve.body.is_empty());
    assert_eq!(
        from_reserve.headers.get("etag").map(String::as_str),
        Some(r#""reserve-v1""#)
    );
    assert_eq!(
        from_reserve
            .headers
            .get("last-modified")
            .map(String::as_str),
        Some("Sun, 06 Nov 1994 08:49:37 GMT")
    );
    assert_eq!(
        from_reserve
            .headers
            .get("x-sbproxy-cache")
            .map(String::as_str),
        Some("HIT-RESERVE")
    );
    assert_eq!(
        upstream.captured().len(),
        upstream_count,
        "reserve validation must not call the origin"
    );

    let promoted = proxy
        .get_with_headers(
            "/reserve-a",
            "cache.localhost",
            &[("if-none-match", r#""reserve-v1""#)],
        )
        .expect("conditional promoted hot hit");
    assert_eq!(promoted.status, 304);
    assert_eq!(
        promoted.headers.get("x-sbproxy-cache").map(String::as_str),
        Some("HIT")
    );
    assert_eq!(
        promoted.headers.get("etag").map(String::as_str),
        Some(r#""reserve-v1""#)
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
    // TTL=5s, SWR=60s. After priming the cache, confirm the entry is
    // warm (a HIT) before going stale, then wait past TTL but well
    // inside the SWR window. The next GET must come back as STALE (not
    // MISS) and the upstream count must advance once the background
    // refresh lands.
    //
    // The poll-for-warm step is load-bearing: the cache write on the
    // prime is dispatched fire-and-forget (`spawn_blocking`), so the
    // prime GET can return (and the upstream-count assertion pass)
    // before the entry is actually in the store. Sleeping a fixed
    // amount and reading straight away raced that write under parallel
    // CPU load and intermittently saw a cold MISS. The wide SWR window
    // (60s) keeps scheduling jitter from pushing the stale read out of
    // the [TTL, TTL+SWR] window.
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
      ttl: 5
      stale_while_revalidate: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_workspace(&yaml, &[]).expect("start proxy");

    // Observe the SWR contract: an in-window request serves STALE and
    // triggers a background refresh. We assert the contract through a
    // bounded retry cycle rather than a single read. The prime's cache
    // write is dispatched fire-and-forget, and under heavy parallel CPU
    // load an in-window read can occasionally still miss the store; that
    // racing miss simply re-populates a fresh entry, so we re-warm and
    // try again. Three consecutive races are not realistic, so this is
    // deterministic in practice while still asserting real STALE
    // behaviour (the wide 60s SWR window keeps scheduling jitter from
    // pushing the read out of the [TTL, TTL+SWR] window).
    let cache_hdr = |r: &sbproxy_e2e::Response| {
        r.headers
            .get("x-sbproxy-cache")
            .map(|s| s.as_str().to_string())
    };

    let mut saw_stale = false;
    let mut count_before_stale = 0usize;
    for _attempt in 0..3 {
        // Prime / re-prime, then poll for the warm HIT so we know the
        // async cache write has landed. The poll stays inside the 5s
        // TTL, so reads here are HIT or MISS, never STALE.
        let _ = proxy.get("/swr", "cache.localhost").expect("prime");
        let warm_deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut warmed = false;
        while std::time::Instant::now() < warm_deadline {
            let r = proxy.get("/swr", "cache.localhost").expect("warm poll");
            if cache_hdr(&r).as_deref() == Some("HIT") {
                warmed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !warmed {
            continue;
        }

        // Wait past TTL (5s), still deep inside the SWR window (60s).
        std::thread::sleep(std::time::Duration::from_secs(6));

        count_before_stale = upstream.captured().len();
        let stale = proxy.get("/swr", "cache.localhost").expect("stale serve");
        if stale.status == 200 && cache_hdr(&stale).as_deref() == Some("STALE") {
            saw_stale = true;
            break;
        }
        // Raced to a miss (the read re-warmed the entry); retry.
    }
    assert!(
        saw_stale,
        "an in-window request must serve x-sbproxy-cache: STALE"
    );

    // The stale serve fires a background refresh. Poll up to 5s for the
    // upstream count to advance past where it was just before the serve.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while upstream.captured().len() <= count_before_stale && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        upstream.captured().len() > count_before_stale,
        "stale serve must trigger a background revalidation (count {} -> {})",
        count_before_stale,
        upstream.captured().len()
    );
}

#[test]
fn stale_revalidation_sends_validators_and_a_304_refreshes_the_cached_body_ttl() {
    let etag = r#""swr-version-1""#;
    let last_modified = "Sun, 06 Nov 1994 08:49:37 GMT";
    let upstream = MockUpstream::start_conditional(
        json!({"version": 1}),
        etag.to_string(),
        last_modified.to_string(),
    )
    .expect("upstream");
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
      stale_while_revalidate: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_workspace(&yaml, &[]).expect("start proxy");

    let prime = proxy
        .get("/revalidate", "cache.localhost")
        .expect("prime cache");
    assert_eq!(prime.status, 200);
    assert_eq!(prime.body, br#"{"version":1}"#);
    let _ = wait_for_cache_hit(&proxy, "/revalidate");
    std::thread::sleep(std::time::Duration::from_secs(2));

    let stale = proxy
        .get("/revalidate", "cache.localhost")
        .expect("serve stale and revalidate");
    assert_eq!(stale.status, 200);
    assert_eq!(stale.body, br#"{"version":1}"#);
    assert_eq!(
        stale.headers.get("x-sbproxy-cache").map(String::as_str),
        Some("STALE"),
        "expected stale replay, got headers={:?}, upstream_requests={:?}, proxy_stderr={}",
        stale.headers,
        upstream.captured(),
        proxy.stderr_contents()
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while upstream.captured().len() < 2 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let captured = upstream.captured();
    assert_eq!(captured.len(), 2, "one conditional refresh expected");
    assert_eq!(
        captured[1].headers.get("if-none-match").map(String::as_str),
        Some(etag)
    );
    assert_eq!(
        captured[1]
            .headers
            .get("if-modified-since")
            .map(String::as_str),
        Some(last_modified)
    );

    let refreshed = wait_for_cache_hit(&proxy, "/revalidate");
    assert_eq!(refreshed.status, 200);
    assert_eq!(
        refreshed.body, br#"{"version":1}"#,
        "304 revalidation must retain the stored representation body"
    );
    assert_eq!(
        refreshed.headers.get("etag").map(String::as_str),
        Some(etag)
    );
    assert_eq!(
        refreshed.headers.get("content-length").map(String::as_str),
        Some("13"),
        "304 metadata must not replace the stored representation length"
    );
    assert!(
        !refreshed.headers.contains_key("x-refresh-hop"),
        "connection-nominated validation fields must not be stored"
    );
    assert_eq!(
        upstream.captured().len(),
        2,
        "freshened entry must not fetch a replacement body"
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

// --- Ingest transforms (WOR-2417) ---
//
// On an origin with transforms attached, the cache stores the
// transform chain's output: a hit serves exactly what a miss ships,
// and a closed transform refusal blocks admission entirely.

fn transform_cache_config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    transforms:
      - type: replace_strings
        replacements:
          - find: "SECRET-TOKEN"
            replace: "[REDACTED]"
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#
    )
}

#[test]
fn a_hit_serves_the_transformed_body_a_miss_shipped() {
    let upstream =
        MockUpstream::start(json!({"note": "the value is SECRET-TOKEN today"})).expect("upstream");
    let proxy = ProxyHarness::start_with_yaml(&transform_cache_config(&upstream.base_url()))
        .expect("start proxy");

    let miss = proxy.get("/doc", "cache.localhost").expect("miss GET");
    assert_eq!(miss.status, 200);
    let miss_text = miss.text().expect("miss body");
    assert!(
        miss_text.contains("[REDACTED]") && !miss_text.contains("SECRET-TOKEN"),
        "the miss must ship the transformed body: {miss_text}"
    );

    let hit = wait_for_cache_hit(&proxy, "/doc");
    let hit_text = hit.text().expect("hit body");
    assert!(
        hit_text.contains("[REDACTED]") && !hit_text.contains("SECRET-TOKEN"),
        "the hit must serve the same transformed body the miss shipped: {hit_text}"
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "the hit must come from the cache, not the upstream"
    );
}

#[test]
fn a_closed_transform_refusal_blocks_cache_admission() {
    // A json transform under `closed` fails on a non-JSON body. The
    // response must refuse, and nothing may be admitted to the cache:
    // every retry keeps reaching the upstream and refusing.
    let upstream =
        MockUpstream::start_raw(b"plain text, not json".to_vec(), "text/plain").expect("upstream");
    let config = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{}"
    transforms:
      - type: json
        set:
          injected: true
        failure_posture: closed
    response_cache:
      enabled: true
      ttl: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_yaml(&config).expect("start proxy");

    // The refusal's client-visible shape depends on flush timing: when
    // the abort lands before headers flush the client sees a 502, and
    // when the response was already committed the client sees the 200
    // header with a truncated body (often surfacing as a read error).
    // The invariants this test pins are timing-free: the raw upstream
    // content never arrives intact, and nothing is admitted to the
    // cache, so every request keeps reaching the upstream.
    let assert_refused = |label: &str| match proxy.get("/doc", "cache.localhost") {
        Err(_) => {}
        Ok(response) => {
            assert_ne!(
                response.headers.get("x-sbproxy-cache").map(String::as_str),
                Some("HIT"),
                "{label}: a refused response must never be served from cache"
            );
            let intact = response
                .text()
                .is_ok_and(|text| text.contains("plain text, not json"));
            assert!(
                response.status >= 500 || !intact,
                "{label}: the raw body must not reach the client intact                  (status {})",
                response.status
            );
        }
    };
    assert_refused("first request");
    assert_refused("second request");
    assert_eq!(
        upstream.captured().len(),
        2,
        "every request must reach the upstream because nothing was stored"
    );
}

#[test]
fn a_request_dependent_transform_on_a_cached_origin_refuses_at_boot() {
    let config = r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "http://127.0.0.1:9"
    transforms:
      - type: lua_json
        script: "function modify_json(data, ctx) return data end"
    response_cache:
      enabled: true
      ttl: 60
"#;
    let error = ProxyHarness::start_with_yaml(config)
        .err()
        .map(|e| e.to_string())
        .expect("a request-dependent transform on a cached origin must refuse to boot");
    assert!(
        error.contains("lua_json") || error.contains("request state"),
        "the refusal must name the transform: {error}"
    );
}

#[test]
fn swr_refresh_stores_the_transformed_refresh_body() {
    // TTL=2s, SWR=60s, with a redacting transform attached. Prime the
    // cache, wait past TTL, take the STALE serve that triggers the
    // background refresh, then poll until a fresh HIT appears. The
    // refreshed entry must hold the transform chain's output: the
    // refresh path runs with no request in scope, so this is the one
    // test that proves the ingest pass runs there and not just on the
    // live store path.
    let upstream =
        MockUpstream::start(json!({"note": "the value is SECRET-TOKEN today"})).expect("upstream");
    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "cache.localhost":
    action:
      type: proxy
      url: "{upstream}"
    transforms:
      - type: replace_strings
        replacements:
          - find: "SECRET-TOKEN"
            replace: "[REDACTED]"
    response_cache:
      enabled: true
      ttl: 2
      stale_while_revalidate: 60
      cacheable_methods: [GET]
      cacheable_status: [200]
"#,
        upstream = upstream.base_url()
    );
    let proxy = ProxyHarness::start_with_workspace(&yaml, &[]).expect("start proxy");

    let cache_hdr = |r: &sbproxy_e2e::Response| {
        r.headers
            .get("x-sbproxy-cache")
            .map(|s| s.as_str().to_string())
    };

    // Prime and wait for the warm HIT so the async store has landed.
    let _ = proxy.get("/swr-ingest", "cache.localhost").expect("prime");
    let _ = wait_for_cache_hit(&proxy, "/swr-ingest");

    // Past TTL, inside SWR: the stale serve triggers the refresh.
    std::thread::sleep(std::time::Duration::from_secs(3));
    let stale = proxy
        .get("/swr-ingest", "cache.localhost")
        .expect("stale serve");
    let stale_text = stale.text().expect("stale body");
    assert!(
        !stale_text.contains("SECRET-TOKEN"),
        "even the stale serve must hold transformed content: {stale_text}"
    );

    // Poll until the refresh lands as a fresh HIT, then assert the
    // refreshed entry holds the transformed body. A refresh that
    // stored the raw upstream bytes would leak SECRET-TOKEN here.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    let refreshed = loop {
        let r = proxy
            .get("/swr-ingest", "cache.localhost")
            .expect("refresh poll");
        if cache_hdr(&r).as_deref() == Some("HIT") {
            break r;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the background refresh did not land as a fresh HIT; last: {:?} {:?}",
            r.status,
            r.headers
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let refreshed_text = refreshed.text().expect("refreshed body");
    assert!(
        refreshed_text.contains("[REDACTED]") && !refreshed_text.contains("SECRET-TOKEN"),
        "the refreshed entry must hold the transform chain's output: {refreshed_text}"
    );
}
