//! AI-crawler tarpit (WOR-810).
//!
//! With `tarpit: true` on `ai_crawl_control`, an unauthorized/unpaid AI
//! crawler is served a deceptive maze (HTTP 200, `text/html`) instead of
//! a 402/block, short-circuiting before the upstream. A paid crawler and
//! a regular browser are unaffected and reach the upstream normally.

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
        tarpit: true
        valid_tokens:
          - good-token-1
"#
    )
}

#[test]
fn unauthorized_crawler_gets_tarpit_maze() {
    let upstream = MockUpstream::start(json!({"real": "content"})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0")],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "the tarpit serves 200, not a 402/block");
    let ct = resp
        .headers
        .get("content-type")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert!(ct.contains("text/html"), "tarpit served as html, got {ct}");
    let body = String::from_utf8(resp.body).unwrap();
    assert!(
        body.contains("rel=\"nofollow\"") && body.contains("href=\"/article/p"),
        "expected a maze of relative nofollow links, got: {body}"
    );
    assert!(
        upstream.captured().is_empty(),
        "the tarpit must short-circuit before contacting the upstream"
    );
}

#[test]
fn paid_crawler_reaches_upstream() {
    let upstream = MockUpstream::start(json!({"real": "content"})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    assert!(
        !upstream.captured().is_empty(),
        "a paid crawler must reach the upstream, not the tarpit"
    );
}

#[test]
fn regular_browser_reaches_upstream() {
    let upstream = MockUpstream::start(json!({"real": "content"})).unwrap();
    let harness = ProxyHarness::start_with_yaml(&config(&upstream.base_url())).expect("proxy");

    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (Macintosh) Chrome/120")],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    assert!(
        !upstream.captured().is_empty(),
        "a non-crawler must reach the upstream"
    );
}
