//! Tests for the AI Crawl Control policy. Relocated from ai_crawl.rs.

use super::*;

fn ua_headers(ua: &str) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    h.insert("user-agent", ua.parse().unwrap());
    h
}

fn payment_headers(ua: &str, header: &str, token: &str) -> http::HeaderMap {
    let mut h = ua_headers(ua);
    h.insert(
        http::HeaderName::from_bytes(header.as_bytes()).unwrap(),
        token.parse().unwrap(),
    );
    h
}

#[test]
fn human_browser_ua_passes_without_payment() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["t1"],
    }))
    .unwrap();
    let h = ua_headers("Mozilla/5.0");
    assert_eq!(
        policy.check("GET", "x.com", "/article", &h, None),
        AiCrawlDecision::Allow
    );
}

#[test]
fn known_crawler_without_token_gets_402_challenge() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": ["t1"],
    }))
    .unwrap();
    let h = ua_headers("Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)");
    match policy.check("GET", "x.com", "/article", &h, None) {
        AiCrawlDecision::Charge { body, challenge } => {
            assert!(body.contains("\"price\":\"0.001000\""));
            assert!(body.contains("\"amount_micros\":1000"));
            assert!(challenge.contains("Crawler-Payment"));
        }
        other => panic!("expected Charge, got {:?}", other),
    }
}

#[test]
fn crawler_with_valid_token_passes_once_then_402s() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["good-token"],
    }))
    .unwrap();
    let h1 = payment_headers("GPTBot/1.0", "crawler-payment", "good-token");
    assert_eq!(
        policy.check("GET", "x.com", "/", &h1, None),
        AiCrawlDecision::Allow
    );
    // Same token cannot redeem again - single-use ledger.
    let h2 = payment_headers("GPTBot/1.0", "crawler-payment", "good-token");
    assert!(matches!(
        policy.check("GET", "x.com", "/", &h2, None),
        AiCrawlDecision::Charge { .. }
    ));
}

#[test]
fn crawler_with_unknown_token_gets_402() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["good-token"],
    }))
    .unwrap();
    let h = payment_headers("ClaudeBot/1.0", "crawler-payment", "wrong-token");
    assert!(matches!(
        policy.check("GET", "x.com", "/", &h, None),
        AiCrawlDecision::Charge { .. }
    ));
}

#[test]
fn post_requests_are_not_charged() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": [],
    }))
    .unwrap();
    let h = ua_headers("GPTBot/1.0");
    assert_eq!(
        policy.check("POST", "x.com", "/", &h, None),
        AiCrawlDecision::Allow
    );
}

#[test]
fn zero_price_free_preview_tier_allows_without_payment() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/preview/*",
                "price": { "amount_micros": 0, "currency": "USD" },
                "free_preview_bytes": 4096
            },
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 1000, "currency": "USD" },
                "content_shape": "html"
            }
        ]
    }))
    .unwrap();
    let h = ua_headers("GPTBot/1.0");
    assert_eq!(
        policy.check("GET", "x.com", "/preview/snippet", &h, None),
        AiCrawlDecision::Allow
    );
}

// --- Tier resolution ---

#[test]
fn tier_prefix_pattern_matches_path_subtree() {
    let tier = Tier {
        route_pattern: "/articles/*".to_string(),
        price: Money::from_units(0.01, "USD"),
        content_shape: Some(ContentShape::Markdown),
        agent_id: None,
        free_preview_bytes: Some(2048),
        paywall_position: Some(PaywallPosition::Inline),
        rails: None,
        citation_required: false,
    };
    assert!(tier.matches_path("/articles/foo"));
    assert!(tier.matches_path("/articles/foo/bar"));
    assert!(!tier.matches_path("/blog/post"));
}

#[test]
fn tier_agent_id_selector_filters_per_vendor() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/articles/*",
                "price": { "amount_micros": 50000, "currency": "USD" },
                "agent_id": "openai-gptbot"
            },
            {
                "route_pattern": "/articles/*",
                "price": { "amount_micros": 10000, "currency": "USD" }
            }
        ]
    }))
    .expect("compile policy");
    let openai_price = policy.resolve_price_for("/articles/x", "openai-gptbot");
    assert_eq!(openai_price.amount_micros, 50_000, "vendor tier wins");
    let other_price = policy.resolve_price_for("/articles/x", "anthropic-claudebot");
    assert_eq!(other_price.amount_micros, 10_000, "fallback tier wins");
    let no_agent = policy.resolve_price_for("/articles/x", "");
    assert_eq!(no_agent.amount_micros, 10_000, "wildcard hits fallback");
}

#[test]
fn first_matching_tier_wins() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            { "route_pattern": "/articles/*",
              "price": { "amount_micros": 5000, "currency": "USD" } },
            { "route_pattern": "/*",
              "price": { "amount_micros": 100, "currency": "USD" } }
        ]
    }))
    .unwrap();
    let resolved = policy.resolve_price("/articles/foo");
    assert_eq!(resolved.amount_micros, 5000);
    let fallback = policy.resolve_price("/whatever");
    assert_eq!(fallback.amount_micros, 100);
}

#[test]
fn accept_header_steers_per_shape_tier() {
    // Tiers in order: markdown ($0.005) then html ($0.001). The
    // markdown tier sits first to prove the shape selector (not
    // tier order) is what picks the right price.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 5000, "currency": "USD" },
                "content_shape": "markdown"
            },
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 1000, "currency": "USD" },
                "content_shape": "html"
            }
        ]
    }))
    .unwrap();

    // Markdown Accept selects the markdown tier ($0.005).
    let md = policy.resolve_price_for_request("/article", "", Some("text/markdown"));
    assert_eq!(md.amount_micros, 5000, "markdown Accept => markdown tier");

    // HTML Accept selects the html tier ($0.001) even though it's
    // listed second.
    let html = policy.resolve_price_for_request("/article", "", Some("text/html"));
    assert_eq!(html.amount_micros, 1000, "html Accept => html tier");
}

#[test]
fn missing_accept_falls_through_shape_selector() {
    // When no Accept header is present, neither shape-specific tier
    // matches, so the top-level fallback price applies.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.0007,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 5000, "currency": "USD" },
                "content_shape": "markdown"
            }
        ]
    }))
    .unwrap();
    let none_accept = policy.resolve_price_for_request("/article", "", None);
    assert_eq!(
        none_accept.amount_micros, 700,
        "no Accept => fallback to top-level price"
    );
}

#[test]
fn malformed_accept_silently_falls_through() {
    // A nonsense Accept value (no recognised media type) doesn't
    // match any shape; tiers without `content_shape` still apply.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 9000, "currency": "USD" }
            }
        ]
    }))
    .unwrap();
    let bad = policy.resolve_price_for_request("/article", "", Some("not-a-type;;;"));
    assert_eq!(
        bad.amount_micros, 9000,
        "malformed Accept matches catch-all tier"
    );
}

#[test]
fn content_shape_from_accept_handles_common_types() {
    assert_eq!(
        ContentShape::from_accept("text/html"),
        Some(ContentShape::Html)
    );
    assert_eq!(
        ContentShape::from_accept("application/xhtml+xml"),
        Some(ContentShape::Html)
    );
    assert_eq!(
        ContentShape::from_accept("text/markdown"),
        Some(ContentShape::Markdown)
    );
    assert_eq!(
        ContentShape::from_accept("application/json;charset=utf-8"),
        Some(ContentShape::Json)
    );
    assert_eq!(
        ContentShape::from_accept("application/pdf"),
        Some(ContentShape::Pdf)
    );
    // First match wins across a comma-separated list.
    assert_eq!(
        ContentShape::from_accept("text/markdown, text/html;q=0.5"),
        Some(ContentShape::Markdown)
    );
    // Quality factors do not steer ordering for the simple parser.
    assert_eq!(
        ContentShape::from_accept("application/octet-stream"),
        None,
        "unrecognised types yield None"
    );
    assert_eq!(ContentShape::from_accept(""), None);
}

#[test]
fn no_matching_tier_falls_back_to_top_level_price() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.0005,
        "valid_tokens": [],
        "tiers": [
            { "route_pattern": "/premium/*",
              "price": { "amount_micros": 5000, "currency": "USD" } }
        ]
    }))
    .unwrap();
    let resolved = policy.resolve_price("/free/post");
    assert_eq!(resolved.amount_micros, 500);
    assert_eq!(resolved.currency, "USD");
}

#[test]
fn challenge_body_includes_tier_metadata() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/articles/*",
                "price": { "amount_micros": 1500, "currency": "USD" },
                "content_shape": "markdown",
                "free_preview_bytes": 2048,
                "paywall_position": "inline"
            }
        ]
    }))
    .unwrap();
    // The tier's `content_shape: markdown` selector now requires the
    // request `Accept` header to negotiate that shape (G1.2 wire).
    let mut h = ua_headers("GPTBot/1.0");
    h.insert(http::header::ACCEPT, "text/markdown".parse().unwrap());
    match policy.check("GET", "x.com", "/articles/foo", &h, None) {
        AiCrawlDecision::Charge { body, .. } => {
            assert!(body.contains("\"amount_micros\":1500"));
            assert!(body.contains("\"content_shape\":\"markdown\""));
            assert!(body.contains("\"free_preview_bytes\":2048"));
            assert!(body.contains("\"paywall_position\":\"inline\""));
        }
        other => panic!("expected Charge, got {:?}", other),
    }
}

// --- Ledger trait Result widening ---

#[derive(Debug)]
struct AlwaysTransient;
impl Ledger for AlwaysTransient {
    fn redeem(
        &self,
        _t: &str,
        _h: &str,
        _p: &str,
        _a: u64,
        _c: &str,
    ) -> Result<RedeemResult, LedgerError> {
        Err(LedgerError::transient("ledger.unavailable", "down").with_retry_after(7))
    }
}

#[derive(Debug)]
struct AlwaysHard;
impl Ledger for AlwaysHard {
    fn redeem(
        &self,
        _t: &str,
        _h: &str,
        _p: &str,
        _a: u64,
        _c: &str,
    ) -> Result<RedeemResult, LedgerError> {
        Err(LedgerError::hard(
            "ledger.token_already_spent",
            "spent already",
        ))
    }
}

#[derive(Debug)]
struct AlwaysHappy;
impl Ledger for AlwaysHappy {
    fn redeem(
        &self,
        t: &str,
        _h: &str,
        _p: &str,
        a: u64,
        c: &str,
    ) -> Result<RedeemResult, LedgerError> {
        Ok(RedeemResult {
            token_id: t.to_string(),
            amount_micros: a,
            currency: c.to_string(),
            txhash: Some("0xdeadbeef".to_string()),
        })
    }
}

#[test]
fn ledger_transient_error_yields_503_with_retry_after() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
    }))
    .unwrap()
    .with_ledger(Arc::new(AlwaysTransient));
    let h = payment_headers("GPTBot/1.0", "crawler-payment", "any-token");
    match policy.check("GET", "x.com", "/article", &h, None) {
        AiCrawlDecision::LedgerUnavailable {
            retry_after_seconds,
            body,
        } => {
            assert_eq!(retry_after_seconds, 7);
            assert!(body.contains("ledger_unavailable"));
        }
        other => panic!("expected LedgerUnavailable, got {:?}", other),
    }
}

#[test]
fn ledger_hard_error_falls_through_to_402() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
    }))
    .unwrap()
    .with_ledger(Arc::new(AlwaysHard));
    let h = payment_headers("GPTBot/1.0", "crawler-payment", "any-token");
    assert!(matches!(
        policy.check("GET", "x.com", "/article", &h, None),
        AiCrawlDecision::Charge { .. }
    ));
}

#[test]
fn ledger_happy_path_passes_request() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
    }))
    .unwrap()
    .with_ledger(Arc::new(AlwaysHappy));
    let h = payment_headers("GPTBot/1.0", "crawler-payment", "tok-abc");
    assert_eq!(
        policy.check("GET", "x.com", "/article", &h, None),
        AiCrawlDecision::Allow
    );
}

#[test]
fn money_from_units_rounds_to_micros() {
    let m = Money::from_units(0.001234567, "USD");
    assert_eq!(m.amount_micros, 1235);
    assert_eq!(m.currency, "USD");
}

#[cfg(feature = "http-ledger")]
#[test]
fn http_ledger_rejects_plain_http_endpoint() {
    let cfg = HttpLedgerConfig::with_defaults(
        "http://insecure.example.com",
        "k1",
        b"secret-key".to_vec(),
    );
    let err = HttpLedger::new(cfg).unwrap_err();
    assert!(err.to_string().contains("https://"));
}

#[cfg(feature = "http-ledger")]
#[test]
fn ledger_yaml_block_constructs_http_ledger() {
    // YAML wiring: when the operator authors a `ledger:`
    // block on `ai_crawl_control`, `from_config` must swap the
    // bundled InMemoryLedger for an HttpLedger pointing at the
    // configured https endpoint. Plain http:// rejects with the
    // ADR's "must be https://" message.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "ledger": {
            "url": "https://ledger.internal/v1/ledger",
            "key_id": "test-key-1",
            "key_hex": "0011223344",
            "workspace_id": "default",
            "timeout_ms": 1000,
        }
    }))
    .expect("policy compiles with https ledger");
    // The dyn ledger debug stamp surfaces the configured endpoint.
    let dbg = format!("{:?}", policy);
    assert!(dbg.contains("ledger.internal"), "{dbg}");
}

#[cfg(feature = "http-ledger")]
#[test]
fn ledger_yaml_block_rejects_plain_http() {
    let err = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "ledger": {
            "url": "http://ledger.internal",
            "key_id": "k1",
            "key_hex": "00",
        }
    }))
    .expect_err("plain http should be rejected");
    assert!(
        err.to_string().contains("https://"),
        "error mentions https requirement: {err}"
    );
}

#[cfg(feature = "http-ledger")]
#[test]
fn ledger_yaml_block_resolves_secret_ref_env() {
    std::env::set_var("SBPROXY_TEST_LEDGER_HMAC", "deadbeef");
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "ledger": {
            "url": "https://ledger.internal/v1/ledger",
            "key_id": "k2",
            "secret_ref": { "env": "SBPROXY_TEST_LEDGER_HMAC" },
        }
    }))
    .expect("policy compiles with secret_ref.env");
    let dbg = format!("{:?}", policy);
    assert!(dbg.contains("ledger.internal"), "{dbg}");
    std::env::remove_var("SBPROXY_TEST_LEDGER_HMAC");
}

// --- G3.4 / G3.5 multi-rail challenge tests ---

/// Build a multi-rail-enabled policy for tests. Uses a deterministic
/// 32-byte hex seed so token signatures are reproducible across runs.
fn multi_rail_policy(price_micros: u64) -> AiCrawlControlPolicy {
    AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": (price_micros as f64) / 1_000_000.0,
        "valid_tokens": [],
        "rails": {
            "x402": {
                "chain": "base",
                "facilitator": "https://facilitator-base.x402.org",
                "asset": "USDC",
                "pay_to": "0xabc",
            },
            "mpp": {}
        },
        "quote_token": {
            "key_id": "test-kid",
            "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
            "issuer": "https://api.example.com",
            "default_ttl_seconds": 300,
        }
    }))
    .expect("multi-rail policy compiles")
}

fn multi_rail_headers(
    ua: &str,
    accept_payment: Option<&str>,
    accept: Option<&str>,
) -> http::HeaderMap {
    let mut h = ua_headers(ua);
    if let Some(ap) = accept_payment {
        h.insert("accept-payment", ap.parse().unwrap());
    }
    if let Some(a) = accept {
        h.insert(http::header::ACCEPT, a.parse().unwrap());
    }
    h
}

#[test]
fn multi_rail_challenge_emits_x402_and_mpp_when_accept_matches() {
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", Some("x402;q=1, mpp;q=0.9"), Some("text/html"));
    let decision = policy.check("GET", "x.com", "/articles/foo", &headers, None);
    match decision {
        AiCrawlDecision::MultiRail { body, content_type } => {
            assert_eq!(content_type, MULTI_RAIL_CONTENT_TYPE);
            let parsed: MultiRailChallenge =
                serde_json::from_str(&body).expect("multi-rail body parses");
            assert_eq!(parsed.rails.len(), 2, "both rails emitted");
            assert_eq!(parsed.rails[0].rail(), Rail::X402);
            assert_eq!(parsed.rails[1].rail(), Rail::Mpp);
            assert_eq!(parsed.agent_choice_method, "header_negotiation");
            assert_eq!(parsed.policy, "first_match_wins");
        }
        other => panic!("expected MultiRail, got {other:?}"),
    }
}

#[test]
fn multi_rail_challenge_falls_back_to_single_rail_for_legacy_agent() {
    // No Accept-Payment header, no multi-rail Accept MIME type -> the
    // policy emits the Wave 1 Crawler-Payment single-rail body even
    // though a multi-rail plan is configured.
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", None, Some("text/html"));
    let decision = policy.check("GET", "x.com", "/articles/foo", &headers, None);
    match decision {
        AiCrawlDecision::Charge { challenge, body } => {
            assert!(
                challenge.contains("Crawler-Payment"),
                "single-rail challenge header"
            );
            assert!(
                body.contains("\"amount_micros\":1000"),
                "single-rail body carries price"
            );
        }
        other => panic!("expected single-rail Charge, got {other:?}"),
    }
}

#[test]
fn multi_rail_challenge_each_rail_has_distinct_nonce() {
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", Some("x402, mpp"), Some("text/html"));
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/articles/foo", &headers, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.rails.len(), 2);
    // Each rail's quote token claims should carry a distinct nonce. We
    // re-decode without verifying because verification consumes the
    // nonce; a base64url-decode of the payload segment is enough.
    let nonces: Vec<String> = parsed
        .rails
        .iter()
        .map(|r| extract_nonce_from_token(r.quote_token()))
        .collect();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1], "each rail has its own nonce");
}

#[test]
fn multi_rail_x402_only_filter_drops_mpp_entry() {
    // Agent only accepts x402; the MPP entry must be filtered.
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", Some("x402"), None);
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/articles/foo", &headers, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.rails.len(), 1);
    assert_eq!(parsed.rails[0].rail(), Rail::X402);
}

#[test]
fn multi_rail_no_acceptable_rail_yields_406() {
    // Agent only accepts a rail the operator does not configure.
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", Some("lightning"), None);
    let decision = policy.check("GET", "x.com", "/articles/foo", &headers, None);
    match decision {
        AiCrawlDecision::NoAcceptableRail { body } => {
            assert!(body.contains("\"error\":\"no_acceptable_rail\""));
            assert!(body.contains("\"x402\""));
            assert!(body.contains("\"mpp\""));
        }
        other => panic!("expected NoAcceptableRail, got {other:?}"),
    }
}

#[test]
fn multi_rail_accept_application_x402_json_opts_in() {
    // Per A3.1: `Accept: application/x402+json` opts the agent in even
    // without an `Accept-Payment` header. The body is filtered to x402
    // because the Accept-derived preference set lists only x402.
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", None, Some("application/x402+json"));
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/articles/foo", &headers, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.rails.len(), 1);
    assert_eq!(parsed.rails[0].rail(), Rail::X402);
}

// --- G3.5 per-shape pricing thread verification ---

#[test]
fn per_shape_pricing_threads_shape_claim_into_quote_token() {
    // G3.5 acceptance criterion: the matched tier's `content_shape`
    // must flow end-to-end from the request `Accept` header through
    // tier matching into the quote-token JWS `shape` claim. This
    // test pins the wiring so a future refactor that breaks the
    // thread (e.g. accidentally hard-coding `Other` in
    // `emit_multi_rail`) fails loudly instead of corrupting the
    // audit log.
    //
    // The tier list orders markdown ahead of html so the test
    // proves the shape selector (not declaration order) picks the
    // right tier. The two prices are deliberately distinct so a
    // mistuned matcher would surface as the wrong amount_micros.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 5000, "currency": "USD" },
                "content_shape": "markdown"
            },
            {
                "route_pattern": "/*",
                "price": { "amount_micros": 1000, "currency": "USD" },
                "content_shape": "html"
            }
        ],
        "rails": { "x402": {
            "chain": "base",
            "facilitator": "https://facilitator-base.x402.org",
            "asset": "USDC",
            "pay_to": "0xabc",
        }},
        "quote_token": {
            "key_id": "test-kid",
            "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
            "issuer": "https://api.example.com",
            "default_ttl_seconds": 300,
        }
    }))
    .unwrap();

    // Markdown agent.
    let h_md = multi_rail_headers("GPTBot/1.0", Some("x402"), Some("text/markdown"));
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/article", &h_md, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    let claims = decode_token_claims(parsed.rails[0].quote_token());
    assert_eq!(claims.shape, "markdown");
    assert_eq!(claims.price.amount_micros, 5_000);
    assert_eq!(claims.route, "/article");
    assert_eq!(claims.rail, "x402");

    // HTML agent.
    let h_html = multi_rail_headers("GPTBot/1.0", Some("x402"), Some("text/html"));
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/article", &h_html, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    let claims = decode_token_claims(parsed.rails[0].quote_token());
    assert_eq!(claims.shape, "html");
    assert_eq!(claims.price.amount_micros, 1_000);
}

// --- Wave 3 closeout: G1.4 -> G3.6 agent_id threading ---

#[test]
fn check_threads_agent_id_into_quote_token_sub_claim() {
    // Wave 3 closeout: when the caller passes a resolved agent_id
    // (G1.4 stamps it onto RequestContext upstream of the AiCrawl
    // policy), the JWS `sub` claim must be the resolved id, not the
    // Wave 1 `"unknown"` placeholder.
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", Some("x402"), None);
    let AiCrawlDecision::MultiRail { body, .. } = policy.check(
        "GET",
        "x.com",
        "/articles/foo",
        &headers,
        Some("openai-gptbot"),
    ) else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    let claims = decode_token_claims(parsed.rails[0].quote_token());
    assert_eq!(
        claims.sub, "openai-gptbot",
        "sub claim must carry the resolved agent_id"
    );
}

#[test]
fn check_falls_back_to_unknown_when_agent_id_is_none() {
    // Backward-compat: pre-G1.4 callers (and OSS-default builds that
    // ship without the agent-class feature) pass None and the policy
    // stamps the Wave 1 `"unknown"` placeholder so the JWS issue path
    // never signs an empty sub.
    let policy = multi_rail_policy(1000);
    let headers = multi_rail_headers("GPTBot/1.0", Some("x402"), None);
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/articles/foo", &headers, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    let claims = decode_token_claims(parsed.rails[0].quote_token());
    assert_eq!(claims.sub, "unknown");
}

#[test]
fn parse_accept_payment_q_value_ordering() {
    // q-value desc, then declaration order on ties.
    let prefs = parse_accept_payment(Some("mpp;q=0.5, x402;q=0.9")).unwrap();
    assert_eq!(prefs.accepted, vec![Rail::X402, Rail::Mpp]);
    let prefs = parse_accept_payment(Some("x402, mpp")).unwrap();
    assert_eq!(prefs.accepted, vec![Rail::X402, Rail::Mpp]);
    // Wave 7: `lightning` is a known rail and parses; `quux` stands in
    // as the unknown-token guard for the 406 fallback path.
    let prefs = parse_accept_payment(Some("quux, x402")).unwrap();
    assert_eq!(prefs.accepted, vec![Rail::X402]);
    assert!(prefs.had_unknown);
    assert!(parse_accept_payment(None).is_none());
    assert!(parse_accept_payment(Some("")).is_none());
}

#[test]
fn rail_lightning_serde_roundtrips_lowercase_token() {
    // The enterprise-side Lightning BillingRail registers itself as
    // `"lightning"`. The OSS Rail enum's wire form must match exactly
    // so multi-rail negotiation and `Accept-Payment` parsing line up.
    let serialised = serde_json::to_string(&Rail::Lightning).unwrap();
    assert_eq!(serialised, "\"lightning\"");
    let parsed: Rail = serde_json::from_str("\"lightning\"").unwrap();
    assert_eq!(parsed, Rail::Lightning);
    assert_eq!(Rail::Lightning.as_str(), "lightning");
    assert_eq!(Rail::parse("lightning"), Some(Rail::Lightning));
    assert_eq!(Rail::parse("LIGHTNING"), Some(Rail::Lightning));
}

#[test]
fn per_tier_rails_override_filters_emitted_rails() {
    // Tier with `rails: [mpp]` should drop the x402 entry even when
    // the agent and policy both list x402 as acceptable.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "tiers": [
            {
                "route_pattern": "/preview/*",
                "price": { "amount_micros": 100, "currency": "USD" },
                "rails": ["mpp"]
            }
        ],
        "rails": {
            "x402": {
                "chain": "base",
                "facilitator": "https://facilitator-base.x402.org",
                "asset": "USDC",
                "pay_to": "0xabc",
            },
            "mpp": {}
        },
        "quote_token": {
            "key_id": "test-kid",
            "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
            "issuer": "https://api.example.com",
            "default_ttl_seconds": 300,
        }
    }))
    .unwrap();
    let headers = multi_rail_headers("GPTBot/1.0", Some("x402, mpp"), None);
    let AiCrawlDecision::MultiRail { body, .. } =
        policy.check("GET", "x.com", "/preview/foo", &headers, None)
    else {
        panic!("expected MultiRail");
    };
    let parsed: MultiRailChallenge = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.rails.len(), 1);
    assert_eq!(parsed.rails[0].rail(), Rail::Mpp);
}

#[test]
fn jwks_endpoint_publishes_active_kid() {
    let policy = multi_rail_policy(1000);
    let jwks = policy.quote_token_jwks().expect("jwks");
    let keys = jwks.get("keys").and_then(|v| v.as_array()).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].get("kid").and_then(|v| v.as_str()),
        Some("test-kid")
    );
}

#[test]
fn quote_token_yaml_resolves_secret_ref_secret_via_env_fallback() {
    std::env::set_var(
        "SBPROXY_TEST_QUOTE_SEED",
        "0001020304050607080910111213141516171819202122232425262728293031",
    );
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "rails": {
            "x402": {
                "chain": "base",
                "facilitator": "https://facilitator-base.x402.org",
                "asset": "USDC",
                "pay_to": "0xabc"
            }
        },
        "quote_token": {
            "key_id": "quote-kid",
            "secret_ref": { "secret": "SBPROXY_TEST_QUOTE_SEED" }
        }
    }))
    .expect("policy compiles with secret_ref.secret");

    let jwks = policy.quote_token_jwks().expect("jwks");
    assert_eq!(jwks["keys"][0]["kid"], "quote-kid");
    std::env::remove_var("SBPROXY_TEST_QUOTE_SEED");
}

#[test]
fn quote_token_yaml_without_rails_is_a_config_error() {
    let err = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "quote_token": {
            "key_id": "test-kid",
            "seed_hex": "0001020304050607080910111213141516171819202122232425262728293031",
        }
    }))
    .expect_err("quote_token without rails should fail");
    assert!(err.to_string().contains("rails"), "{err}");
}

#[test]
fn rails_yaml_without_quote_token_is_a_config_error() {
    let err = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": [],
        "rails": { "mpp": {} }
    }))
    .expect_err("rails without quote_token should fail");
    assert!(err.to_string().contains("quote_token"), "{err}");
}

// --- WOR-804: Content Signals enforcement ---

#[test]
fn content_signal_blocks_disallowed_training_bot() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["t1"],
        "crawler_user_agents": ["ClaudeBot", "Googlebot"],
        "content_signals": { "search": true, "ai_train": false },
    }))
    .unwrap();
    let h = ua_headers("Mozilla/5.0 (compatible; ClaudeBot/1.0)");
    match policy.check("GET", "x.com", "/article", &h, None) {
        AiCrawlDecision::SignalBlocked { body } => {
            assert!(body.contains("\"signal\":\"ai-train\""));
        }
        other => panic!("expected SignalBlocked, got {:?}", other),
    }
}

#[test]
fn content_signal_block_precedes_payment() {
    // A disallowed training bot is blocked even when it presents an
    // otherwise-valid token: the signal gate runs before redemption.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["good-token"],
        "crawler_user_agents": ["ClaudeBot"],
        "content_signals": { "ai_train": false },
    }))
    .unwrap();
    let h = payment_headers("ClaudeBot/1.0", "crawler-payment", "good-token");
    assert!(matches!(
        policy.check("GET", "x.com", "/", &h, None),
        AiCrawlDecision::SignalBlocked { .. }
    ));
}

#[test]
fn content_signal_allows_search_bot_through_to_pricing() {
    // search=yes means the search bot is not signal-blocked; it still
    // pays through the normal path (402 here, since it has no token).
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": ["t1"],
        "crawler_user_agents": ["ClaudeBot", "Googlebot"],
        "content_signals": { "search": true, "ai_train": false },
    }))
    .unwrap();
    let h = ua_headers("Mozilla/5.0 (compatible; Googlebot/2.1)");
    assert!(
        matches!(
            policy.check("GET", "x.com", "/article", &h, None),
            AiCrawlDecision::Charge { .. }
        ),
        "search bot under search=yes must not be signal-blocked"
    );
}

#[test]
fn search_bot_with_valid_token_passes() {
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["good-token"],
        "crawler_user_agents": ["ClaudeBot", "Googlebot"],
        "content_signals": { "search": true, "ai_train": false },
    }))
    .unwrap();
    let h = payment_headers("Googlebot/2.1", "crawler-payment", "good-token");
    assert_eq!(
        policy.check("GET", "x.com", "/", &h, None),
        AiCrawlDecision::Allow
    );
}

#[test]
fn unclassifiable_crawler_is_not_signal_blocked() {
    // A crawler we cannot place by user-agent falls through to the
    // pricing path rather than being signal-blocked.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "valid_tokens": ["t1"],
        "crawler_user_agents": ["MysteryScraper"],
        "content_signals": { "ai_train": false },
    }))
    .unwrap();
    let h = ua_headers("MysteryScraper/1.0");
    assert!(!matches!(
        policy.check("GET", "x.com", "/", &h, None),
        AiCrawlDecision::SignalBlocked { .. }
    ));
}

#[test]
fn no_content_signals_keeps_legacy_behavior() {
    // Without a content_signals block a training bot sees the normal
    // 402 challenge, unchanged from before WOR-804.
    let policy = AiCrawlControlPolicy::from_config(serde_json::json!({
        "price": 0.001,
        "valid_tokens": ["t1"],
    }))
    .unwrap();
    let h = ua_headers("Mozilla/5.0 (compatible; GPTBot/1.0)");
    assert!(matches!(
        policy.check("GET", "x.com", "/article", &h, None),
        AiCrawlDecision::Charge { .. }
    ));
}

// --- Helpers for the multi-rail tests above ---

fn decode_token_claims(token: &str) -> crate::policy::quote_token::QuoteClaims {
    use base64::Engine as _;
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload b64");
    serde_json::from_slice(&payload).expect("claims decode")
}

fn extract_nonce_from_token(token: &str) -> String {
    decode_token_claims(token).nonce
}
