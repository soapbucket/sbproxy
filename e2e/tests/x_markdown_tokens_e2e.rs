//! Q4.2: `x-markdown-tokens` response header e2e suite.
//!
//! Pins the contract from `docs/adr-json-envelope-schema.md` § "x-markdown-tokens
//! header relationship": the proxy stamps `x-markdown-tokens: <n>` on
//! Markdown and JSON envelope responses, and the value matches the
//! envelope's `token_estimate` field exactly. The estimate is computed
//! once per response from the Markdown body length using a configurable
//! tokens-per-byte ratio (defaulting to 0.25 tokens/byte for English
//! prose).
//!
//! Wave 4 day-5 wires the response pipeline against the default
//! `0.25` tokens/byte ratio; three of four tests below pass on the
//! day-5 wiring and the fourth (per-origin `token_bytes_ratio:`
//! override) still waits for the small RawOriginConfig follow-up.
//!
//! `tiktoken-rs` is not in the workspace, so the assertions use the
//! body-bytes-times-ratio formula. Tolerance: ±20%.

use sbproxy_e2e::ProxyHarness;

// --- Helpers ---

/// Default tokens-per-byte ratio per A4.2's open question 3 and the
/// G4.5 implementation: 0.25 tokens/byte for English prose.
const DEFAULT_TOKEN_RATIO: f64 = 0.25;

/// Estimate tokens from a body length using the configured ratio.
fn estimate_tokens(body_len: usize, ratio: f64) -> u64 {
    ((body_len as f64) * ratio).round() as u64
}

/// Build a YAML fixture with a static action whose body is exactly
/// `body_len` bytes of `a` characters (so the Markdown projection
/// passes through unchanged) and an `ai_crawl_control` policy that
/// authorises the test token.
fn fixture_with_body(body: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "tokens.local":
    action:
      type: static
      status_code: 200
      content_type: text/markdown
      body: "{body}"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - good-token-1
"#
    )
}

/// Same as `fixture_with_body` but pins a per-origin
/// `token_bytes_ratio` so the estimator scales differently.
fn fixture_with_ratio(body: &str, ratio: f64) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "tokens.local":
    token_bytes_ratio: {ratio}
    action:
      type: static
      status_code: 200
      content_type: text/markdown
      body: "{body}"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - good-token-1
"#
    )
}

// --- Test 1: header present with non-zero integer ---

#[test]
fn markdown_response_carries_x_markdown_tokens_header() {
    let body = "a".repeat(100);
    let yaml = fixture_with_body(&body);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "tokens.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/markdown"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    let header = resp
        .headers
        .get("x-markdown-tokens")
        .expect("x-markdown-tokens header present");
    let n: u64 = header.parse().expect("header is a non-negative integer");
    assert!(n > 0, "non-zero token count for a 100-byte body, got {n}");
}

// --- Test 2: header equals envelope token_estimate ---

#[test]
fn x_markdown_tokens_matches_envelope_token_estimate() {
    let body = "a".repeat(400);
    let yaml = fixture_with_body(&body);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "tokens.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "application/json"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200);

    let header_value: u64 = resp
        .headers
        .get("x-markdown-tokens")
        .expect("x-markdown-tokens header on JSON envelope responses too")
        .parse()
        .expect("integer header");

    let body_json = resp.json().expect("envelope parses as JSON");
    let envelope_estimate = body_json
        .get("token_estimate")
        .and_then(|v| v.as_u64())
        .expect("envelope carries token_estimate");

    assert_eq!(
        header_value, envelope_estimate,
        "x-markdown-tokens header must equal envelope.token_estimate \
         (per A4.2; both read from the same pipeline value)"
    );
}

// --- Test 3: scales linearly with body length ---

#[test]
fn x_markdown_tokens_scales_with_body_length() {
    fn count_for(len: usize) -> u64 {
        let body = "a".repeat(len);
        let yaml = fixture_with_body(&body);
        let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
        let resp = harness
            .get_with_headers(
                "/article",
                "tokens.local",
                &[
                    ("user-agent", "GPTBot/1.0"),
                    ("accept", "text/markdown"),
                    ("crawler-payment", "good-token-1"),
                ],
            )
            .expect("send");
        assert_eq!(resp.status, 200);
        resp.headers
            .get("x-markdown-tokens")
            .expect("header present")
            .parse()
            .expect("integer")
    }

    let small = count_for(100);
    let large = count_for(1000);

    assert!(small > 0, "non-zero count for 100-byte body");
    assert!(large > 0, "non-zero count for 1000-byte body");

    // Ratio should be roughly 10x. Tolerance ±20% per the prompt to
    // accommodate Markdown projection overhead, rounding, and any
    // proxy-added preface (e.g. heading from H1 extraction).
    let ratio = large as f64 / small as f64;
    assert!(
        (8.0..=12.0).contains(&ratio),
        "1000-byte / 100-byte ratio should be ~10x, got {ratio} (small={small}, large={large})"
    );
}

// --- Test 4: configured ratio doubles the count ---

#[test]
fn x_markdown_tokens_uses_configured_ratio() {
    let body = "a".repeat(400);

    // Default ratio (0.25 tokens/byte).
    let yaml_default = fixture_with_body(&body);
    let harness_default = ProxyHarness::start_with_yaml(&yaml_default).expect("start proxy");
    let resp_default = harness_default
        .get_with_headers(
            "/article",
            "tokens.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/markdown"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");
    let default_count: u64 = resp_default
        .headers
        .get("x-markdown-tokens")
        .expect("header")
        .parse()
        .expect("integer");

    // Doubled ratio (0.5 tokens/byte) => roughly twice the count.
    let yaml_doubled = fixture_with_ratio(&body, 0.5);
    let harness_doubled = ProxyHarness::start_with_yaml(&yaml_doubled).expect("start proxy");
    let resp_doubled = harness_doubled
        .get_with_headers(
            "/article",
            "tokens.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/markdown"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");
    let doubled_count: u64 = resp_doubled
        .headers
        .get("x-markdown-tokens")
        .expect("header")
        .parse()
        .expect("integer");

    assert!(
        default_count > 0 && doubled_count > 0,
        "counts must be non-zero (default={default_count}, doubled={doubled_count})"
    );

    // Sanity: the doubled-ratio count is also within ±20% of the
    // formula-predicted value for the 400-byte body so a regression in
    // the estimator surfaces here (not just in the ratio assertion).
    let expected_default = estimate_tokens(body.len(), DEFAULT_TOKEN_RATIO);
    let lower = (expected_default as f64 * 0.8) as u64;
    let upper = (expected_default as f64 * 1.2) as u64;
    assert!(
        (lower..=upper).contains(&default_count),
        "default count for {}-byte body should be ~{} (±20%), got {}",
        body.len(),
        expected_default,
        default_count
    );

    let ratio = doubled_count as f64 / default_count as f64;
    assert!(
        (1.7..=2.3).contains(&ratio),
        "0.5 / 0.25 ratio should be ~2x, got {ratio} (default={default_count}, doubled={doubled_count})"
    );
}

// --- Smoke: token-estimate fixture compiles ---

/// Sanity check: the per-body fixture is at least syntactically valid
/// YAML so a future fixture edit cannot silently break every test in
/// this file.
#[test]
fn token_fixture_yaml_compiles() {
    let yaml = fixture_with_body("hello world");
    let _harness = ProxyHarness::start_with_yaml(&yaml).expect("fixture sb.yml must compile");
}
