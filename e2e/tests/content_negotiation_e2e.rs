//! Q4.1: content negotiation e2e suite.
//!
//! Pins the contract from `docs/adr-content-negotiation-and-pricing.md`
//! (G4.1): the same URL serves HTML, Markdown, or a JSON envelope based
//! on the agent's `Accept` header, and the resolved shape drives both
//! the response body and the price advertised in the 402 challenge.
//!
//! These tests exercise the implementation that lands via the rust-A
//! branch (G4.2 content-shape handler, G4.3 Markdown projection, G4.4
//! JSON envelope, G4.5 `Content-Signal` header). The Wave 4 day-5
//! response-pipeline wiring (`stamp_content_negotiation`,
//! `apply_transform_with_ctx`, `JsonEnvelopeTransform::apply` typed
//! dispatch, Content-Type rewrite) reactivates every test in this
//! file. The suite must continue to pass on every CI run.
//!
//! Wave-4 reference for the JSON envelope schema: `docs/adr-json-envelope-schema.md`.

use sbproxy_e2e::ProxyHarness;

// --- Shared fixture ---

/// YAML fixture that defines two pricing tiers (Markdown and HTML)
/// for the same path so the proxy can negotiate content shape per
/// request. The static-action body is HTML; the proxy's transformer
/// projects it to Markdown when the agent asks for it (G4.3) and
/// wraps it in a JSON envelope when the agent asks for that (G4.4).
const FIXTURE_TIERS: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "negotiate.local":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<html><head><title>Article Title</title></head><body><h1>Article Title</h1><p>Body in prose.</p></body></html>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        tiers:
          - route_pattern: /*
            price:
              amount_micros: 5000
              currency: USD
            content_shape: markdown
          - route_pattern: /*
            price:
              amount_micros: 1000
              currency: USD
            content_shape: html
        valid_tokens:
          - good-token-1
"#;

/// Same fixture with `default_content_shape: markdown` configured at
/// the origin level so wildcard `Accept: */*` resolves to the
/// configured default per G4.1's wildcard rule.
const FIXTURE_DEFAULT_MARKDOWN: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "negotiate.local":
    default_content_shape: markdown
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<html><head><title>Article Title</title></head><body><h1>Article Title</h1><p>Body in prose.</p></body></html>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - good-token-1
"#;

/// Fixture with no `default_content_shape` so wildcard `Accept: */*`
/// falls back to HTML per G4.1.
const FIXTURE_NO_DEFAULT: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "negotiate.local":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<html><head><title>Article Title</title></head><body><h1>Article Title</h1><p>Body in prose.</p></body></html>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        valid_tokens:
          - good-token-1
"#;

// --- Test 1: HTML negotiation ---

#[test]
fn same_url_returns_html_for_accept_text_html() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_TIERS).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/html"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "valid token + HTML accept => 200");
    let content_type = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        content_type.starts_with("text/html"),
        "Accept: text/html => Content-Type: text/html, got: {content_type}"
    );

    let body = resp.text().unwrap_or_default();
    assert!(
        body.contains("<h1>") || body.contains("<html"),
        "HTML body passes through: {body}"
    );
}

// --- Test 2: Markdown negotiation ---

#[test]
fn same_url_returns_markdown_for_accept_text_markdown() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_TIERS).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/markdown"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "valid token + Markdown accept => 200");
    let content_type = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        content_type.starts_with("text/markdown"),
        "Accept: text/markdown => Content-Type: text/markdown, got: {content_type}"
    );

    let body = resp.text().unwrap_or_default();
    // Markdown body starts with a `#` heading derived from the H1.
    assert!(
        body.trim_start().starts_with('#'),
        "Markdown body starts with a heading: {body}"
    );
}

// --- Test 3: JSON envelope negotiation (A4.2 v1 schema) ---

#[test]
fn same_url_returns_json_envelope_for_accept_application_json() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_TIERS).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "application/json"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "valid token + JSON accept => 200");

    // Per A4.2: Content-Type with profile parameter pointing at the v1
    // schema URL. Both substrings must be present; we do not pin the
    // exact spacing or quoting.
    let content_type = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        content_type.contains("application/json"),
        "Content-Type advertises application/json: {content_type}"
    );
    assert!(
        content_type.contains("profile=")
            && content_type.contains("https://sbproxy.dev/schema/json-envelope/v1"),
        "Content-Type carries profile parameter pointing at v1 schema: {content_type}"
    );

    // Body parses as JSON and matches the v1 schema's required fields.
    let body = resp.json().expect("body parses as JSON");
    let obj = body.as_object().expect("envelope is a JSON object");

    assert_eq!(
        obj.get("schema_version").and_then(|v| v.as_str()),
        Some("1"),
        "schema_version is the string \"1\" per A1.8 convention"
    );
    assert!(
        obj.get("content_md").and_then(|v| v.as_str()).is_some(),
        "content_md is present and a string"
    );
    assert!(
        obj.get("title").and_then(|v| v.as_str()).is_some(),
        "title is present and a string"
    );
    assert!(
        obj.get("license").and_then(|v| v.as_str()).is_some(),
        "license is present and a string (RSL URN or all-rights-reserved)"
    );
    assert!(
        obj.get("token_estimate").and_then(|v| v.as_u64()).is_some(),
        "token_estimate is present and an integer"
    );
    assert!(
        obj.get("url").and_then(|v| v.as_str()).is_some(),
        "url is present and a string"
    );
    assert!(
        obj.get("fetched_at").and_then(|v| v.as_str()).is_some(),
        "fetched_at is present (RFC 3339 string)"
    );
    assert!(
        obj.get("citation_required")
            .and_then(|v| v.as_bool())
            .is_some(),
        "citation_required is present and a bool"
    );
}

// --- Test 4: q-value tie-break prefers Markdown ---

#[test]
fn q_value_tie_break_prefers_markdown() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_TIERS).expect("start proxy");
    // Both shapes carry the same q-value. Per G4.1's canonical
    // preference order (Markdown rank 1, Json rank 2, Html rank 3),
    // Markdown wins the tie-break.
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/markdown;q=0.9, text/html;q=0.9"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    let content_type = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        content_type.starts_with("text/markdown"),
        "tie at q=0.9 resolves to Markdown per canonical preference order: {content_type}"
    );
}

// --- Test 5: q-value resolution + pricing (HTML wins both passes) ---

#[test]
fn q_value_pricing_uses_first_match_per_tier() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_TIERS).expect("start proxy");
    // Accept: text/html;q=1.0, text/markdown;q=0.9
    // Pass 1 (pricing): first recognised MIME is text/html => HTML tier price.
    // Pass 2 (transformation): q=1.0 wins => HTML body.
    // Both passes agree; assert via the price in the 402 challenge body
    // (no token, so the proxy returns the challenge).
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/html;q=1.0, text/markdown;q=0.9"),
            ],
        )
        .expect("send");

    assert_eq!(
        resp.status, 402,
        "no token but a chargeable shape => 402 challenge"
    );
    let challenge = resp
        .headers
        .get("crawler-payment")
        .expect("crawler-payment challenge header");
    // HTML-tier price is 1000 micros / $0.001 (see FIXTURE_TIERS).
    assert!(
        challenge.contains("0.001") || challenge.contains("1000"),
        "HTML tier price advertised because text/html is the first recognised MIME: {challenge}"
    );
}

// --- Test 6: wildcard Accept honors default_content_shape ---

#[test]
fn wildcard_accept_falls_back_to_default_content_shape() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_DEFAULT_MARKDOWN).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "*/*"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    let content_type = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        content_type.starts_with("text/markdown"),
        "*/* with default_content_shape: markdown => Markdown response: {content_type}"
    );
}

// --- Test 7: wildcard Accept with no default => HTML ---

#[test]
fn wildcard_accept_with_no_default_serves_html() {
    let harness = ProxyHarness::start_with_yaml(FIXTURE_NO_DEFAULT).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "negotiate.local",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "*/*"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200);
    let content_type = resp
        .headers
        .get("content-type")
        .expect("content-type header");
    assert!(
        content_type.starts_with("text/html"),
        "*/* with no default_content_shape => HTML response: {content_type}"
    );
}

// --- Smoke: fixture compiles ---

/// Sanity check: the negotiation fixture is at least syntactically
/// valid YAML so a future fixture edit cannot silently break every
/// test in this file. The proxy refuses to start on an invalid
/// config, so a successful start proves the fixture compiles.
#[test]
fn negotiation_fixture_yaml_compiles() {
    let _harness =
        ProxyHarness::start_with_yaml(FIXTURE_TIERS).expect("fixture sb.yml must compile");
}
