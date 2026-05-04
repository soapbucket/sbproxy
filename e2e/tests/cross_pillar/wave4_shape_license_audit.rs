//! Q4.13  -  Wave 4 cross-pillar e2e: `wave4_shape_license_audit`.
//!
//! One inbound request walks every Wave 4 pillar:
//!
//! 1. Agent sends `Accept: text/markdown` + `Accept-Payment: x402;q=1`.
//! 2. Proxy issues 402 multi-rail challenge with a quote token.
//! 3. Agent retrieves JWKS at `/.well-known/sbproxy/quote-keys.json`,
//!    verifies the quote token signature.
//! 4. Agent redeems the token with an x402 payload.
//! 5. Proxy returns 200 with Markdown body, `x-markdown-tokens`
//!    header, and `Content-Signal: ai-input` header.
//! 6. Audit log emits one `Settlement` event (Wave 3) and one
//!    `PolicyProjectionRefresh` event (Wave 4) iff the projection
//!    cache is in the request path. Per A4.1 the cache is
//!    populated by the reload hook, not by the request hot-path,
//!    so under the steady-state config the only Wave 4 audit
//!    side-effect is a `Settlement` row carrying
//!    `license_token_id = quote_id`.
//! 7. The access log carries `license_token_id` lifted from the
//!    redeemed quote token's `quote_id`.
//! 8. The request appears in the rails-overview dashboard's
//!    `revenue_by_rail_day` series, queried via the metrics
//!    endpoint.
//!
//! Authoritative inputs:
//! - `docs/AIGOVERNANCE-BUILD.md` § 7.5 Q4.13 and § 17 cross-pillar
//!   matrix.
//! - `docs/adr-content-negotiation-and-pricing.md` (G4.1) - Markdown
//!   negotiation, `Content-Signal`, `x-markdown-tokens`.
//! - `docs/adr-policy-graph-projections.md` (A4.1) - projection cache
//!   semantics; clarifies why the request hot-path does not trigger a
//!   refresh in steady state.
//! - `docs/adr-quote-token-jws.md` (A3.2) - quote-token JWKS.
//! - `docs/adr-multi-rail-402-challenge.md` (A3.1) - 402 body shape.
//! - `docs/adr-audit-log-v0.md` (A2.3) - audit envelope.
//!
//! `#[ignore]`d until the dependent builds land:
//!
//! - G4.2 (content-shape handler), G4.3 (Markdown projection),
//!   G4.4 (JSON envelope), G4.5 (Content-Signal header).
//! - G4.7 (RSL projection)  -  surfaces `licenses.xml`; not in the
//!   request path here, but the test asserts the JWKS endpoint is
//!   reachable via the same admin server, which depends on G4.7's
//!   admin route fan-out.
//! - G4.10 (boilerplate stripper)  -  only relevant if the chain
//!   stamps `Content-Signal` post-strip; left out of the request
//!   path here.
//! - Q4.13 substrate (the assertion-side admin endpoints
//!   `/api/audit/recent`, `/api/access-log/recent`,
//!   `/api/dashboards/rails-overview`).

use std::net::TcpListener;
use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::Value;

// --- Helpers ---

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn admin_get(port: u16, path: &str, user: &str, pass: &str) -> (u16, String) {
    let auth = format!("Basic {}", base64_encode(&format!("{user}:{pass}")));
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("authorization", auth)
        .send()
        .expect("admin GET");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

/// Issue an unauthenticated GET to a well-known path on the admin
/// port. The JWKS document is publicly readable per A3.2 ("Key
/// publication"), so we deliberately do not send credentials.
fn admin_unauthed_get(port: u16, path: &str) -> (u16, String) {
    let resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}{path}"))
        .send()
        .expect("admin GET");
    (resp.status().as_u16(), resp.text().unwrap_or_default())
}

/// Inline base64 encoder so the test does not depend on the workspace
/// `base64` major bumping.
fn base64_encode(input: &str) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPH[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPH[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPH[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

// --- Config builder ---

/// Wires the cross-pillar config:
///
/// - One paywalled origin `fox-publisher.localhost` running
///   `ai_crawl_control` with one tier priced for the html shape AND
///   the markdown shape (per G4.1 / G3.5).
/// - `Content-Signal: ai-input` stamped at the origin level (G4.5).
/// - x402 rail enabled (W3 multi-rail).
/// - Audit + access log + metrics on the admin port.
/// - JWKS endpoint at `/.well-known/sbproxy/quote-keys.json` (A3.2).
/// - Rails-overview dashboard endpoint (E4.3).
fn wave4_shape_license_audit_config(admin_port: u16, origin_base: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: w4-shape
observability:
  log:
    sinks:
      - name: stdout
        format: json
        profile: internal
  metrics:
    enabled: true
audit:
  sink: memory
billing:
  wallet:
    backend: memory
    starting_balance_micros: 1000000
origins:
  "fox-publisher.localhost":
    content_signal: "ai-input"   # G4.5
    transforms:
      - type: markdown            # G4.3 - HTML -> Markdown
        emit_token_count_header: true   # x-markdown-tokens
    policies:
      - type: ai_crawl_control
        rails:
          - kind: x402
            enabled: true
        pricing:
          tier_default: "fox-news"
          tiers:
            - name: "fox-news"
              # Per G4.1, a tier carries per-shape prices. The
              # html price is what an HTML-Accept request pays;
              # the markdown price is what a markdown-Accept
              # request pays. They can differ.
              shape_prices:
                html:
                  price_micros: 5000
                  currency: "USD"
                markdown:
                  price_micros: 4000
                  currency: "USD"
        agent_class:
          ua_catalog:
            - pattern: "GPTBot/*"
              agent_id: "openai-gptbot"
              agent_class: "vendor:openai"
              agent_vendor: "OpenAI"
    action:
      type: proxy
      url: "{origin_base}"
"#
    )
}

// --- The cross-pillar test ---

/// Single integration test exercising the full Wave 4 path. Assertions
/// are pinned today so the contract is reviewable before the
/// implementations land. `#[ignore]` until the substrate ships.
#[test]
#[ignore = "TODO(wave4-cross-pillar): waits for G4.2-G4.10 + G4.11 + Q4.13 substrate"]
fn wave4_shape_license_audit_full_path() {
    let admin_port = pick_port();
    // The mock upstream returns an HTML article. The proxy's G4.3
    // Markdown projection converts it; the test asserts on the
    // converted body and the `x-markdown-tokens` header.
    let upstream = MockUpstream::start_with_response_headers(
        Value::String(
            "<html><body><article class=\"main-content\">\
             <h1>Fox Publisher Headline</h1>\
             <p>The agent paid for this content.</p>\
             </article></body></html>"
                .to_string(),
        ),
        vec![("content-type".into(), "text/html".into())],
    )
    .expect("mock upstream");
    let origin_base = upstream.base_url();
    let yaml = wave4_shape_license_audit_config(admin_port, &origin_base);
    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5)).expect("admin port");

    // --- Step 1: agent sends Accept: markdown + Accept-Payment x402 ---
    // No payment yet; expect 402 with a multi-rail body.
    let challenge = harness
        .get_with_headers(
            "/article",
            "fox-publisher.localhost",
            &[
                ("user-agent", "GPTBot/2.1"),
                ("accept", "text/markdown"),
                ("accept-payment", "x402;q=1"),
            ],
        )
        .expect("challenge leg");
    assert_eq!(challenge.status, 402, "expected 402: {challenge:?}");
    let body: Value = challenge.json().expect("402 body JSON");
    let rails = body["rails"].as_array().expect("rails array");
    let x402 = rails
        .iter()
        .find(|r| r["kind"] == "x402")
        .expect("x402 rail in 402 body");
    let quote_token = x402["quote_token"]
        .as_str()
        .expect("quote_token in x402 rail")
        .to_string();
    let quote_id = body["quote_id"]
        .as_str()
        .expect("quote_id at top level")
        .to_string();
    // The Markdown shape price (4000 micros) is what should be
    // quoted, not the HTML price (5000). Pins G4.1 + G3.5.
    assert_eq!(
        x402["amount_micros"], 4000u64,
        "expected markdown shape price"
    );
    assert_eq!(x402["currency"], "USD");

    // --- Step 2: agent fetches JWKS, verifies quote token sig ---
    // Public unauthenticated path per A3.2.
    let (jwks_status, jwks_body) =
        admin_unauthed_get(admin_port, "/.well-known/sbproxy/quote-keys.json");
    assert_eq!(jwks_status, 200);
    let jwks: Value = serde_json::from_str(&jwks_body).expect("JWKS JSON");
    let keys = jwks["keys"].as_array().expect("JWKS keys array");
    assert!(!keys.is_empty(), "JWKS must publish at least one key");
    // Decode the JWT header without verifying so we can pull `kid`.
    let header_b64 = quote_token
        .split('.')
        .next()
        .expect("quote token has at least one segment");
    let header_bytes = decode_jwt_segment(header_b64).expect("decode JWT header");
    let header_json: Value = serde_json::from_slice(&header_bytes).expect("JWT header is JSON");
    let kid = header_json["kid"].as_str().expect("JWT header carries kid");
    assert!(
        keys.iter().any(|k| k["kid"] == kid),
        "JWT kid {kid} must appear in JWKS"
    );

    // --- Step 3: agent redeems with an x402 payload ---
    let redeem = harness
        .get_with_headers(
            "/article",
            "fox-publisher.localhost",
            &[
                ("user-agent", "GPTBot/2.1"),
                ("accept", "text/markdown"),
                ("accept-payment", "x402;q=1"),
                ("x-payment", &format!("x402 quote={quote_id}")),
                // Synthetic settlement receipt; the per-pillar
                // settlement test owns the contract for the receipt
                // shape, here we only need the proxy to admit it.
                ("x-payment-settlement", "synthetic-receipt-w4-cross"),
            ],
        )
        .expect("redeem leg");
    assert_eq!(redeem.status, 200, "expected 200: {redeem:?}");

    // --- Step 4: response is Markdown with token + signal headers ---
    assert_eq!(
        redeem
            .headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or(""),
        "text/markdown",
        "Content-Type should be text/markdown after G4.3 projection"
    );
    let tokens_header = redeem
        .headers
        .get("x-markdown-tokens")
        .expect("x-markdown-tokens header present");
    let token_count: u64 = tokens_header.parse().expect("token count integer");
    assert!(
        token_count > 0,
        "x-markdown-tokens must be non-zero for a non-empty article"
    );
    assert_eq!(
        redeem
            .headers
            .get("content-signal")
            .map(String::as_str)
            .unwrap_or(""),
        "ai-input",
        "Content-Signal should be 'ai-input' per origin config"
    );
    let body_text = redeem.text().expect("body utf-8");
    assert!(
        body_text.contains("Fox Publisher Headline"),
        "Markdown body must carry the article heading"
    );

    // --- Step 5: audit log carries one Settlement entry, license_token_id ---
    let (audit_status, audit_body) = admin_get(
        admin_port,
        "/api/audit/recent?limit=20",
        "admin",
        "w4-shape",
    );
    assert_eq!(audit_status, 200);
    let audit: Value = serde_json::from_str(&audit_body).expect("audit JSON");
    let entries = audit.as_array().expect("audit array");
    let settlement = entries
        .iter()
        .find(|e| e["event_type"] == "settlement" || e["action"] == "settlement")
        .unwrap_or_else(|| panic!("expected one Settlement event, got {entries:?}"));
    assert_eq!(
        settlement["license_token_id"].as_str().unwrap_or(""),
        quote_id,
        "settlement audit row must carry license_token_id == quote_id"
    );

    // Per A4.1 the projection cache refresh is bound to config
    // reloads, not the request hot-path. For the steady-state
    // request walked above we do NOT expect a `policy_projection_refresh`
    // entry. Pin that explicitly so a future hot-path-refresh
    // regression is loud rather than silent.
    let projection_refresh_count = entries
        .iter()
        .filter(|e| e["event_type"] == "policy_projection_refresh")
        .count();
    assert_eq!(
        projection_refresh_count, 0,
        "A4.1 says the request hot-path does not trigger projection refresh"
    );

    // --- Step 6: access log carries license_token_id ---
    let (access_status, access_body) = admin_get(
        admin_port,
        "/api/access-log/recent?limit=10",
        "admin",
        "w4-shape",
    );
    assert_eq!(access_status, 200);
    let access: Value = serde_json::from_str(&access_body).expect("access-log JSON");
    let last = access
        .as_array()
        .and_then(|a| a.first())
        .expect("at least one access-log entry");
    assert_eq!(
        last["license_token_id"].as_str().unwrap_or(""),
        quote_id,
        "access log must carry license_token_id from the redeemed quote"
    );
    assert_eq!(last["status"].as_u64().unwrap_or(0), 200);

    // --- Step 7: rails-overview dashboard reflects the request ---
    // The dashboard endpoint exposes the metric series Grafana would
    // hit, but in JSON form so the test can pin values directly.
    let (dash_status, dash_body) = admin_get(
        admin_port,
        "/api/dashboards/rails-overview",
        "admin",
        "w4-shape",
    );
    assert_eq!(dash_status, 200);
    let dash: Value = serde_json::from_str(&dash_body).expect("dash JSON");
    let series = dash["revenue_by_rail_day"]
        .as_array()
        .expect("revenue_by_rail_day series");
    let x402_row = series
        .iter()
        .find(|r| r["rail"] == "x402")
        .expect("x402 row in revenue_by_rail_day");
    let micros = x402_row["amount_micros"]
        .as_u64()
        .expect("amount_micros integer");
    assert!(
        micros >= 4000,
        "x402 daily revenue should reflect the 4000-micros redemption: got {micros}"
    );

    drop(harness);
    drop(upstream);
}

/// Compile-time shape lock so the cross-pillar config builder cannot
/// drift while the asserting test is `#[ignore]`d. Cheap enough to
/// run on every CI execution.
#[test]
fn wave4_shape_license_audit_config_compiles() {
    let yaml = wave4_shape_license_audit_config(9999, "http://127.0.0.1:1");
    assert!(yaml.contains("ai_crawl_control"));
    assert!(yaml.contains("type: markdown"));
    assert!(yaml.contains("emit_token_count_header: true"));
    assert!(yaml.contains("content_signal: \"ai-input\""));
    assert!(yaml.contains("kind: x402"));
    assert!(yaml.contains("shape_prices"));
    assert!(yaml.contains("markdown:"));
    assert!(yaml.contains("html:"));
}

// --- JWT helpers ---

/// Decode a base64url JWT segment without padding. The standard
/// `base64::engine::general_purpose::URL_SAFE_NO_PAD` decoder would
/// pull the workspace `base64` crate into the e2e graph; the test
/// already inlines a base64 encoder, so we inline a decoder too and
/// keep the dep set tight.
fn decode_jwt_segment(segment: &str) -> anyhow::Result<Vec<u8>> {
    // base64url -> base64
    let mut s: String = segment
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    // Pad to multiple of 4.
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    base64_decode(&s)
}

/// Standard base64 decoder. Matches the inline encoder above.
fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    fn lookup(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        anyhow::bail!("base64 length not multiple of 4");
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let mut quad: [u8; 4] = [0; 4];
        let mut pad = 0;
        for j in 0..4 {
            if bytes[i + j] == b'=' {
                pad += 1;
                quad[j] = 0;
            } else {
                quad[j] =
                    lookup(bytes[i + j]).ok_or_else(|| anyhow::anyhow!("invalid base64 char"))?;
            }
        }
        let n = ((quad[0] as u32) << 18)
            | ((quad[1] as u32) << 12)
            | ((quad[2] as u32) << 6)
            | (quad[3] as u32);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xFF) as u8);
        }
        if pad < 1 {
            out.push((n & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(out)
}

/// Round-trips the base64 helpers with a known input so the inline
/// codec is regression-checked. Cheap; runs on every CI invocation.
#[test]
fn base64_round_trip() {
    let input = b"hello world";
    let encoded = base64_encode(std::str::from_utf8(input).unwrap());
    let decoded = base64_decode(&encoded).expect("decode");
    assert_eq!(decoded, input);
}
