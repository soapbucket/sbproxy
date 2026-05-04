//! End-to-end coverage for WOR-114 Phase 1 per-request feature flags.
//!
//! Pins the three acceptance bullets from the ticket:
//!
//! 1. `x-sb-flags: debug` makes the response carry
//!    `x-sbproxy-debug-request-id` and `x-sbproxy-debug-config-rev`
//!    headers.
//! 2. `?_sb.no-cache` on a normally-cacheable origin produces no
//!    `x-sbproxy-cache: HIT` even on a warm cache.
//! 3. With `--disable-sb-flags` (or `SB_DISABLE_SB_FLAGS=1`) on, both
//!    surfaces are silently ignored. (The CLI gate is verified by the
//!    `sb_flags::tests::disabled_kill_switch_returns_empty` unit test
//!    in sbproxy-core; this file covers the wire path with the gate
//!    OFF, since the harness runs the proxy in-process and toggling
//!    the gate would leak across other tests in the same binary.)

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn cache_yaml(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "flags.localhost":
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
fn debug_flag_stamps_response_markers() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&cache_yaml(&upstream.base_url())).expect("start proxy");

    let resp = proxy
        .get_with_headers("/anywhere", "flags.localhost", &[("x-sb-flags", "debug")])
        .expect("debug flag GET");

    assert_eq!(resp.status, 200, "headers={:?}", resp.headers);
    let req_id_marker = resp
        .headers
        .get("x-sbproxy-debug-request-id")
        .cloned()
        .unwrap_or_default();
    let cfg_rev_marker = resp
        .headers
        .get("x-sbproxy-debug-config-rev")
        .cloned()
        .unwrap_or_default();
    assert!(
        !req_id_marker.is_empty(),
        "x-sbproxy-debug-request-id must be present, headers={:?}",
        resp.headers
    );
    assert!(
        !cfg_rev_marker.is_empty(),
        "x-sbproxy-debug-config-rev must be present, headers={:?}",
        resp.headers
    );
    // The debug request id should match the proxy's own x-sb-request-id
    // header so an operator can find the request in the log file.
    if let Some(req_id) = resp.headers.get("x-sb-request-id") {
        assert_eq!(
            &req_id_marker, req_id,
            "debug-request-id must mirror x-sb-request-id"
        );
    }
}

#[test]
fn no_debug_flag_skips_response_markers() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&cache_yaml(&upstream.base_url())).expect("start proxy");

    let resp = proxy
        .get("/anywhere", "flags.localhost")
        .expect("plain GET");
    assert_eq!(resp.status, 200);
    assert!(
        !resp.headers.contains_key("x-sbproxy-debug-request-id"),
        "no debug flag => no debug header. headers={:?}",
        resp.headers
    );
    assert!(
        !resp.headers.contains_key("x-sbproxy-debug-config-rev"),
        "no debug flag => no debug header. headers={:?}",
        resp.headers
    );
}

#[test]
fn no_cache_flag_via_header_bypasses_warm_cache() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&cache_yaml(&upstream.base_url())).expect("start proxy");

    // Warm the cache with a normal GET.
    let _ = proxy.get("/warm", "flags.localhost").expect("warm GET");

    // Poll briefly until the second GET reports HIT, mirroring the
    // pattern in cache_response.rs (the cache write happens after
    // the response is sent to the client, so a fast follow-up can
    // race the writer).
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    loop {
        let r = proxy.get("/warm", "flags.localhost").expect("hit GET");
        if r.headers.get("x-sbproxy-cache").map(String::as_str) == Some("HIT") {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "cache never reported HIT within 500ms; headers={:?}",
                r.headers
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let warmed_count = upstream.captured().len();

    // Same key, with `x-sb-flags: no-cache`. Must reach upstream and
    // must NOT carry an `x-sbproxy-cache: HIT` marker.
    let bypass = proxy
        .get_with_headers("/warm", "flags.localhost", &[("x-sb-flags", "no-cache")])
        .expect("bypass GET");
    assert_eq!(bypass.status, 200);
    assert_ne!(
        bypass.headers.get("x-sbproxy-cache").map(String::as_str),
        Some("HIT"),
        "no-cache flag must bypass warm cache. headers={:?}",
        bypass.headers
    );
    assert_eq!(
        upstream.captured().len(),
        warmed_count + 1,
        "no-cache flag must reach the upstream"
    );
}

#[test]
fn no_cache_flag_via_query_bypasses_warm_cache() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let proxy =
        ProxyHarness::start_with_yaml(&cache_yaml(&upstream.base_url())).expect("start proxy");

    let _ = proxy.get("/warm-q", "flags.localhost").expect("warm GET");
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    loop {
        let r = proxy.get("/warm-q", "flags.localhost").expect("hit GET");
        if r.headers.get("x-sbproxy-cache").map(String::as_str) == Some("HIT") {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "cache never reported HIT within 500ms; headers={:?}",
                r.headers
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let warmed_count = upstream.captured().len();

    // Add `?_sb.no-cache`. The cache key would include the query
    // string by default, so a different path is what would normally
    // bypass; we want the no-cache *flag* to be the bypass, not a
    // cache miss because the key changed. So we issue the same path
    // but with the magic query suffix and assert upstream count rose.
    let bypass = proxy
        .get("/warm-q?_sb.no-cache", "flags.localhost")
        .expect("bypass GET");
    assert_eq!(bypass.status, 200);
    assert_ne!(
        bypass.headers.get("x-sbproxy-cache").map(String::as_str),
        Some("HIT"),
        "?_sb.no-cache must bypass warm cache. headers={:?}",
        bypass.headers
    );
    assert_eq!(
        upstream.captured().len(),
        warmed_count + 1,
        "?_sb.no-cache must reach the upstream"
    );
}
