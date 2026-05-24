//! Content Signals emitter + enforcer (WOR-804).
//!
//! Verifies the Cloudflare Content Signals layer end to end:
//! - `/robots.txt` carries the `Content-Signal:` directive from config.
//! - A training crawler is blocked (403) when `ai_train` is disallowed,
//!   even if it presents a payment token (the signal gate precedes
//!   payment).
//! - A search crawler is allowed under `search: true` and passes with a
//!   valid token.

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
        crawler_user_agents:
          - ClaudeBot
          - Googlebot
        valid_tokens:
          - good-token-1
          - good-token-2
        content_signals:
          search: true
          ai_train: false
"#;

#[test]
fn robots_txt_includes_content_signal_directive() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness.get("/robots.txt", "blog.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let body = String::from_utf8(resp.body).unwrap();
    assert!(
        body.contains("User-agent: *"),
        "robots.txt must have a wildcard group; got:\n{body}"
    );
    assert!(
        body.contains("Content-Signal: search=yes, ai-train=no"),
        "robots.txt must carry the Content-Signal directive; got:\n{body}"
    );
}

#[test]
fn training_bot_blocked_when_ai_train_disallowed() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (compatible; ClaudeBot/1.0)")],
        )
        .expect("send");
    assert_eq!(resp.status, 403, "training bot must be signal-blocked");
    let body = String::from_utf8(resp.body).unwrap();
    assert!(
        body.contains("content_signal_disallowed"),
        "403 body should explain the block; got:\n{body}"
    );
}

#[test]
fn training_bot_blocked_even_with_valid_token() {
    // The signal gate runs before payment redemption, so a disallowed
    // training crawler cannot buy its way past an `ai_train: false`.
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "ClaudeBot/1.0"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 403);
}

#[test]
fn search_bot_allowed_under_search_signal() {
    // search: true means the search crawler is not signal-blocked; with
    // a valid token it passes through to the origin (200).
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1)"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "search bot must pass under search=yes");
}

#[test]
fn search_bot_without_token_sees_normal_pricing_not_block() {
    // Not signal-blocked: it gets the normal 402 pay-per-crawl
    // challenge, not the 403 signal block.
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")],
        )
        .expect("send");
    assert_eq!(resp.status, 402, "search bot falls through to pricing");
}

#[test]
fn human_browser_unaffected() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[(
                "user-agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            )],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
}
