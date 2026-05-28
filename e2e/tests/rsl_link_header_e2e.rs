//! RSL `Link: rel="license"` discovery header (WOR-808).
//!
//! An origin that publishes an RSL document (it has an `ai_crawl_control`
//! policy) advertises `/licenses.xml` on every proxied response via an
//! RFC 8288 `Link` header, so a crawler discovers the license without
//! already knowing the well-known path. An origin with no licensing does
//! not get the header.

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

fn config(upstream_url: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        crawler_user_agents: ["GPTBot"]
  "plain.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
"#
    )
}

#[test]
fn rsl_origin_proxied_response_carries_link_license_header() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    // A non-crawler UA passes ai_crawl_control (crawler signature is
    // GPTBot only) and proxies through, so response_filter runs.
    let resp = harness
        .get_with_headers(
            "/some-article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (Macintosh) Chrome/120")],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "non-crawler request proxies through");
    let link = resp.headers.get("link").map(|s| s.as_str()).unwrap_or("");
    assert!(
        link.contains("rel=\"license\"") && link.contains("/licenses.xml"),
        "RSL origin advertises its license via Link; got: {link:?}"
    );
}

#[test]
fn non_rsl_origin_has_no_link_license_header() {
    let upstream = MockUpstream::start(json!({"ok": true})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    let resp = harness
        .get_with_headers(
            "/x",
            "plain.localhost",
            &[("user-agent", "Mozilla/5.0 (Macintosh) Chrome/120")],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    let link = resp.headers.get("link").cloned().unwrap_or_default();
    assert!(
        !link.contains("rel=\"license\""),
        "an origin without licensing must not advertise a license; got: {link:?}"
    );
}
