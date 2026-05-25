//! WOR-803: Cloudflare Pay Per Crawl exact wire-contract interop.
//!
//! Covers the full crawl-pay-serve loop using Cloudflare's exact
//! headers (`crawler-price` on the 402, `crawler-max-price` /
//! `crawler-exact-price` on the retry, `crawler-charged` on the served
//! 200) plus the always-free path allowlist that is never charged.

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
        price: 0.01
        currency: USD
        cloudflare_compat: true
        free_paths:
          - "/feed/*"
        valid_tokens:
          - ppc-token-1
"#;

#[test]
fn ppc_crawler_without_token_gets_402_with_crawler_price() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (compatible; GPTBot/1.0)")],
        )
        .expect("send");
    assert_eq!(resp.status, 402);
    // Cloudflare's exact wire header carries `<currency> <amount>`.
    let price = resp
        .headers
        .get("crawler-price")
        .expect("crawler-price header");
    assert_eq!(price, "USD 0.01");
    let body = String::from_utf8(resp.body).unwrap();
    assert!(body.contains("\"crawler_price\":\"USD 0.01\""));
}

#[test]
fn ppc_crawl_pay_serve_loop_settles_and_returns_crawler_charged() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");

    // 1. The crawler pre-authorizes a cap above the quote and presents
    //    a self-hosted token. The proxy settles via the ledger, serves
    //    the content, and tells the crawler what it paid.
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-max-price", "USD 0.05"),
                ("crawler-payment", "ppc-token-1"),
            ],
        )
        .expect("paid call");
    assert_eq!(resp.status, 200);
    let charged = resp
        .headers
        .get("crawler-charged")
        .expect("crawler-charged header");
    assert_eq!(charged, "USD 0.01");

    // 2. The token is single-use: replaying it re-quotes with a 402.
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("crawler-max-price", "USD 0.05"),
                ("crawler-payment", "ppc-token-1"),
            ],
        )
        .expect("replay call");
    assert_eq!(resp.status, 402);
    assert_eq!(
        resp.headers.get("crawler-price").map(String::as_str),
        Some("USD 0.01")
    );
}

#[test]
fn ppc_exact_price_preauth_settles() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "ClaudeBot/1.0"),
                ("crawler-exact-price", "USD 0.01"),
                ("crawler-payment", "ppc-token-1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.headers.get("crawler-charged").map(String::as_str),
        Some("USD 0.01")
    );
}

#[test]
fn ppc_always_free_path_is_never_charged() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    // Built-in allowlist: robots.txt is served without payment and
    // carries no charge header.
    let resp = harness
        .get_with_headers(
            "/robots.txt",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0")],
        )
        .expect("robots");
    assert_eq!(resp.status, 200);
    assert!(!resp.headers.contains_key("crawler-price"));
    assert!(!resp.headers.contains_key("crawler-charged"));

    // Operator free path: /feed/* is also never charged.
    let resp = harness
        .get_with_headers(
            "/feed/latest",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0")],
        )
        .expect("feed");
    assert_eq!(resp.status, 200);
    assert!(!resp.headers.contains_key("crawler-price"));
}

#[test]
fn ppc_human_browser_passes_without_payment_or_charge() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 Chrome/120")],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    assert!(!resp.headers.contains_key("crawler-charged"));
}
