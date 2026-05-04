//! End-to-end coverage for the `ip_filter` policy.
//!
//! Exercises the documented behaviour from `examples/30-ip-filter/sb.yml`.
//! Tests run from 127.0.0.1, so we use `proxy.trusted_proxies: [127.0.0.1/32]`
//! plus an `X-Forwarded-For` header to simulate a real client IP. The
//! proxy treats 127.0.0.1 as a trusted hop and uses the leftmost
//! untrusted IP in `X-Forwarded-For` as the client IP for policy
//! evaluation. See `crates/sbproxy-core/src/server.rs` around the
//! `peer_trusted` block.

use sbproxy_e2e::ProxyHarness;

const WHITELIST_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  trusted_proxies:
    - 127.0.0.1/32
origins:
  "ipfilter.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: ip_filter
        whitelist:
          - 10.0.0.0/8
          - 192.168.5.42/32
"#;

const BLACKLIST_CONFIG: &str = r#"
proxy:
  http_bind_port: 0
  trusted_proxies:
    - 127.0.0.1/32
origins:
  "ipfilter.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    policies:
      - type: ip_filter
        blacklist:
          - 203.0.113.0/24
"#;

#[test]
fn whitelist_allows_matching_cidr() {
    let harness = ProxyHarness::start_with_yaml(WHITELIST_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "ipfilter.localhost",
            &[("x-forwarded-for", "10.0.0.7")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "10.0.0.7 falls inside 10.0.0.0/8 and must be allowed; got {}",
        resp.status
    );
}

#[test]
fn whitelist_denies_non_matching_cidr() {
    let harness = ProxyHarness::start_with_yaml(WHITELIST_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "ipfilter.localhost",
            &[("x-forwarded-for", "8.8.8.8")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "8.8.8.8 is outside the whitelist and must be denied with 403; got {}",
        resp.status
    );
}

#[test]
fn whitelist_single_host_cidr_allows_only_that_address() {
    let harness = ProxyHarness::start_with_yaml(WHITELIST_CONFIG).expect("start proxy");

    // The /32 in the whitelist matches only 192.168.5.42 exactly.
    let exact = harness
        .get_with_headers(
            "/anything",
            "ipfilter.localhost",
            &[("x-forwarded-for", "192.168.5.42")],
        )
        .expect("send exact");
    assert_eq!(exact.status, 200, "192.168.5.42/32 exact match must pass");

    let neighbour = harness
        .get_with_headers(
            "/anything",
            "ipfilter.localhost",
            &[("x-forwarded-for", "192.168.5.43")],
        )
        .expect("send neighbour");
    assert_eq!(
        neighbour.status, 403,
        "192.168.5.43 is one IP off and must NOT match a /32 whitelist entry"
    );
}

#[test]
fn blacklist_denies_matching_cidr() {
    let harness = ProxyHarness::start_with_yaml(BLACKLIST_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "ipfilter.localhost",
            &[("x-forwarded-for", "203.0.113.7")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 403,
        "203.0.113.7 is inside the blacklist and must be denied; got {}",
        resp.status
    );
}

#[test]
fn blacklist_allows_non_matching_cidr() {
    let harness = ProxyHarness::start_with_yaml(BLACKLIST_CONFIG).expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/anything",
            "ipfilter.localhost",
            &[("x-forwarded-for", "198.51.100.4")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 200,
        "198.51.100.4 is outside the blacklist and must be allowed; got {}",
        resp.status
    );
}
