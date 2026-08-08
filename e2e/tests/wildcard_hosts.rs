//! End-to-end coverage for wildcard origin keys.
//!
//! An `origins:` key starting with `*.` matches one or more leading
//! labels of the inbound `Host`: `*.tenant.localhost` covers
//! `a.tenant.localhost` and `a.b.tenant.localhost`, never
//! `tenant.localhost` itself. Exact keys always beat wildcards, and
//! between wildcards the longest matching suffix wins, so a fleet of
//! per-customer subdomains can share one origin block while single
//! hostnames keep their own.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config_yaml(wild_url: &str, exact_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "*.tenant.localhost":
    action:
      type: proxy
      url: "{wild_url}"
  "app.tenant.localhost":
    action:
      type: proxy
      url: "{exact_url}"
"#
    )
}

#[test]
fn wildcard_host_routes_to_wildcard_origin() {
    let wild = MockUpstream::start(json!({"origin": "wild"})).expect("wild upstream");
    let exact = MockUpstream::start(json!({"origin": "exact"})).expect("exact upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(&wild.base_url(), &exact.base_url()))
        .expect("start proxy");

    // One leading label.
    let one = proxy.get("/", "acme.tenant.localhost").expect("one label");
    assert_eq!(one.status, 200);
    assert_eq!(one.json().expect("one-label json")["origin"], "wild");

    // Multiple leading labels are covered by the same key.
    let two = proxy
        .get("/", "eu.acme.tenant.localhost")
        .expect("two labels");
    assert_eq!(two.status, 200);
    assert_eq!(two.json().expect("two-label json")["origin"], "wild");

    assert_eq!(
        wild.captured().len(),
        2,
        "both wildcard-matched hosts must reach the wildcard upstream"
    );
}

#[test]
fn exact_host_beats_wildcard() {
    let wild = MockUpstream::start(json!({"origin": "wild"})).expect("wild upstream");
    let exact = MockUpstream::start(json!({"origin": "exact"})).expect("exact upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(&wild.base_url(), &exact.base_url()))
        .expect("start proxy");

    let resp = proxy.get("/", "app.tenant.localhost").expect("exact host");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json().expect("exact json")["origin"], "exact");

    assert!(
        wild.captured().is_empty(),
        "the exact key must shadow the wildcard for its own hostname"
    );
}

#[test]
fn bare_suffix_and_unrelated_hosts_are_unrouted() {
    let wild = MockUpstream::start(json!({"origin": "wild"})).expect("wild upstream");
    let exact = MockUpstream::start(json!({"origin": "exact"})).expect("exact upstream");
    let proxy = ProxyHarness::start_with_yaml(&config_yaml(&wild.base_url(), &exact.base_url()))
        .expect("start proxy");

    // `*.` requires at least one label; the suffix alone stays a 404.
    let bare = proxy.get("/", "tenant.localhost").expect("bare suffix");
    assert_eq!(bare.status, 404, "bare suffix must not match the wildcard");

    let other = proxy.get("/", "acme.other.localhost").expect("other host");
    assert_eq!(other.status, 404, "unrelated host must stay unrouted");

    assert!(wild.captured().is_empty());
    assert!(exact.captured().is_empty());
}
