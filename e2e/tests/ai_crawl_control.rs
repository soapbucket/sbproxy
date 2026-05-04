//! AI Crawl Control + Pay Per Crawl (F1.7).

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "blog.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        valid_tokens:
          - good-token-1
          - good-token-2
"#;

#[test]
fn crawler_without_token_gets_402_challenge() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (compatible; GPTBot/1.0)")],
        )
        .expect("send");
    assert_eq!(resp.status, 402);
    let challenge = resp
        .headers
        .get("crawler-payment")
        .expect("challenge header");
    assert!(challenge.contains("Crawler-Payment"));
    assert!(challenge.contains("USD"));
    let body = String::from_utf8(resp.body).unwrap();
    assert!(body.contains("\"price\""));
}

#[test]
fn crawler_with_valid_token_passes_once_then_402s() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // First redemption: token spends, request passes through.
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("first call");
    assert_eq!(resp.status, 200);

    // Second redemption with the same token: ledger has emptied it.
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("second call");
    assert_eq!(resp.status, 402);
}

#[test]
fn human_browser_passes_without_payment() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 Chrome/120")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}

#[test]
fn unknown_token_still_gets_402() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "ClaudeBot/1.0"),
                ("crawler-payment", "no-such-token"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 402);
}
