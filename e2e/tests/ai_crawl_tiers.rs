//! Q1.1: multi-tier pricing for `ai_crawl_control`.
//!
//! Exercises the three-tier shape from
//! `e2e/fixtures/wave1/tiers/sb.yml`:
//!   - `free-preview` (zero price, capped at 4 KiB on a `/preview/` path)
//!   - `markdown-shape` (charges when `Accept: text/markdown`)
//!   - `html-default` (charges otherwise)
//!
//! Implementation is landing in parallel via the G1.2 branch (see
//! `wave1/G1.2-G1.3-tiers-ledger`). Until those keys land in
//! `crates/sbproxy-modules/src/policy/ai_crawl.rs`, every test in this
//! file is `#[ignore]`d with a `TODO(wave1-G1.2)` marker so CI's
//! `cargo test --workspace` stays green while the suite still
//! type-checks.
//!
//! When the implementation lands, drop the `#[ignore]` attributes and
//! the existing `cargo test -p sbproxy-e2e --test ai_crawl_tiers`
//! invocation will exercise the full path.

use sbproxy_e2e::ProxyHarness;

/// Static fixture body. The path is hard-wired so a fixture refresh
/// (Q2.13 cadence) is a one-line diff in this file.
const FIXTURE: &str = include_str!("../fixtures/wave1/tiers/sb.yml");

/// Helper: spin up the proxy with the tier fixture. Returns the running
/// harness or an error containing the proxy stderr captured by the
/// harness wrapper. Centralised so a fixture-shape change only edits
/// one site.
fn start_tiers() -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_yaml(FIXTURE)
}

// --- Test 1: 402 carries the matched tier price ---

#[test]
fn test_402_response_carries_html_tier_price() {
    let harness = start_tiers().expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "Mozilla/5.0 (compatible; GPTBot/1.0)"),
                ("accept", "text/html"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 402, "no token, no preview path => 402");

    // The challenge header must surface the matched tier's price.
    // Per ADR shape, `Crawler-Payment` carries `price=<USD>` and
    // `currency=USD`. Once G1.2 lands the asserted tier name should
    // also appear (`tier=html-default`).
    let challenge = resp
        .headers
        .get("crawler-payment")
        .expect("crawler-payment challenge header");
    assert!(challenge.contains("USD"), "currency in challenge");
    assert!(
        challenge.contains("0.001") || challenge.contains("1000"),
        "html-default tier price ($0.001 or 1000 micros) in challenge: {challenge}"
    );
}

// --- Test 2: redemption returns 200 + body ---

#[test]
fn test_redemption_returns_200_and_body() {
    let harness = start_tiers().expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[
                ("user-agent", "GPTBot/1.0"),
                ("accept", "text/html"),
                ("crawler-payment", "good-token-1"),
            ],
        )
        .expect("send");

    assert_eq!(resp.status, 200, "valid token + HTML accept => 200");
    let body = resp.text().unwrap_or_default();
    assert!(body.contains("article"), "body proxied through: {body}");
}

// --- Test 3: free-preview window flips at the byte threshold ---

#[test]
#[ignore = "TODO(wave3): free-preview tier matches on /preview/* and zero price, but the proxy chargeable check still triggers a 402 because the static action serves a body; the tier resolver does not yet skip the challenge based on `free_preview_bytes`. Resolution lives in G1.2 but byte-budget enforcement is not wired."]
fn test_free_preview_under_limit_returns_200() {
    let harness = start_tiers().expect("start proxy");
    // /preview/* is the free-preview tier when the response is under
    // 4 KiB. The static-action body in the fixture is well under the
    // cap so the request should pass without payment.
    let resp = harness
        .get_with_headers(
            "/preview/snippet",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0"), ("accept", "text/html")],
        )
        .expect("send");
    assert_eq!(resp.status, 200, "free-preview under 4 KiB => 200");
}

#[test]
fn test_free_preview_over_limit_returns_402() {
    let harness = start_tiers().expect("start proxy");
    // The fixture's static body is small, but a real implementation
    // computes the response byte length and falls through to the
    // first chargeable tier when the preview budget is exhausted.
    // This test reserves the assertion shape; the fixture body needs
    // to grow to >4 KiB once G1.2 surfaces a way to vary the body
    // length. Until then we skip.
    let resp = harness
        .get_with_headers(
            "/preview/long-article-over-the-budget",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0"), ("accept", "text/html")],
        )
        .expect("send");
    assert_eq!(
        resp.status, 402,
        "free-preview over 4 KiB falls through to html-default tier => 402"
    );
}

// --- Test 4: per-shape routing (Markdown vs HTML) ---

#[test]
fn test_per_shape_routing_markdown_price() {
    let harness = start_tiers().expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0"), ("accept", "text/markdown")],
        )
        .expect("send");
    assert_eq!(resp.status, 402);
    let challenge = resp
        .headers
        .get("crawler-payment")
        .expect("challenge header");
    // Markdown tier is $0.005 / 5000 micros.
    assert!(
        challenge.contains("0.005") || challenge.contains("5000"),
        "markdown tier price in challenge: {challenge}"
    );
}

#[test]
fn test_per_shape_routing_html_price() {
    let harness = start_tiers().expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.localhost",
            &[("user-agent", "GPTBot/1.0"), ("accept", "text/html")],
        )
        .expect("send");
    assert_eq!(resp.status, 402);
    let challenge = resp
        .headers
        .get("crawler-payment")
        .expect("challenge header");
    assert!(
        challenge.contains("0.001") || challenge.contains("1000"),
        "html tier price in challenge: {challenge}"
    );
}

// --- Smoke test that does NOT depend on tier shape ---

/// Sanity check the fixture is at least syntactically valid YAML so a
/// future fixture edit cannot silently break every test in this file.
/// The proxy refuses to start on an invalid config, so a successful
/// `start_tiers()` proves the fixture compiles. This test runs by
/// default; the rest are ignored until G1.2 lands.
#[test]
fn fixture_yaml_compiles() {
    let _harness = start_tiers().expect("fixture sb.yml must compile");
}
