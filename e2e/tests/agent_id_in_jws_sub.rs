//! End-to-end coverage for the agent_id thread into the JWS `sub`
//! claim added in `d3f5653` (Wave 3.1 closeout).
//!
//! G1.4 resolves an `agent_id` from the request (User-Agent regex,
//! reverse-DNS, anonymous bot-auth, or human fallback). G3.6 / A3.2
//! threads that resolved id into every quote-token JWS as the `sub`
//! claim, so the wallet redeem path can audit which agent paid.
//!
//! Test cases:
//!   1. `jws_sub_carries_resolved_agent_id_for_known_agent` -
//!      `User-Agent: GPTBot/1.0` resolves to the catalog id
//!      `openai-gptbot`; the `sub` claim carries that id.
//!   2. `jws_sub_falls_back_to_human_for_unrecognized_agent` -
//!      `User-Agent: Mozilla/5.0 ...` falls through every signal in
//!      the resolver chain and lands on the `human` sentinel; the
//!      `sub` claim is `human`.
//!   3. `jws_sub_uses_human_when_no_user_agent` - the request omits
//!      the User-Agent header. With no UA, no rDNS, and no bot-auth,
//!      the resolver still falls through to `human`. The test
//!      documents the actual behaviour rather than the hypothetical
//!      `anonymous` sentinel (which is reserved for the Web Bot Auth
//!      path with an unknown keyid).
//!
//! All three tests boot a single-rail (x402) policy so the body
//! shape is predictable: one entry in `rails[]` whose `quote_token`
//! is the JWS we decode.

use sbproxy_e2e::ProxyHarness;

// --- Helpers ---

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "blog.test.sbproxy.dev":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        price: 0.001
        currency: USD
        valid_tokens: []
        # Crawler list pins both bot UA tests + the Mozilla fall-back
        # test. With `crawler_user_agents: []` the policy treats every
        # GET as a crawler candidate, which is what makes the no-UA
        # case interesting (the policy still 402s, the resolver still
        # produces a sub claim).
        crawler_user_agents: []
        rails:
          x402:
            chain: base
            facilitator: https://facilitator.example
            asset: USDC
            pay_to: "0xabc"
        quote_token:
          key_id: kid-sub-claim-2026
          seed_hex: "0001020304050607080910111213141516171819202122232425262728293031"
          issuer: "https://blog.test.sbproxy.dev"
          default_ttl_seconds: 300
"#;

/// Decode a base64url segment without padding back to JSON. The JWS
/// segments use the URL-safe alphabet and omit padding per RFC 7515.
fn b64url_decode_to_json(seg: &str) -> serde_json::Value {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD
        .decode(seg.as_bytes())
        .expect("base64url decodes");
    serde_json::from_slice(&bytes).expect("JSON parses")
}

/// Pull the first `quote_token` JWS out of a multi-rail 402 body and
/// return its decoded claim payload as a JSON value. Panics with an
/// informative message if the body shape does not match.
fn extract_jws_payload(body_bytes: &[u8]) -> serde_json::Value {
    let body: serde_json::Value =
        serde_json::from_slice(body_bytes).expect("multi-rail body is JSON");
    let token = body
        .get("rails")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("quote_token"))
        .and_then(|v| v.as_str())
        .expect("missing quote_token in body");
    let mut parts = token.split('.');
    let _hdr = parts.next().expect("header segment");
    let payload = parts.next().expect("payload segment");
    let _sig = parts.next().expect("signature segment");
    b64url_decode_to_json(payload)
}

// --- Tests ---

#[test]
fn jws_sub_carries_resolved_agent_id_for_known_agent() {
    // GPTBot/1.0 matches the embedded catalog regex
    // `(?i)\bGPTBot/\d` and resolves to the catalog id
    // `openai-gptbot`. Per G3.6 the proxy threads that id into the
    // JWS `sub` claim instead of the Wave 1 `"unknown"` placeholder.
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.test.sbproxy.dev",
            &[("user-agent", "GPTBot/1.0"), ("accept-payment", "x402")],
        )
        .expect("send GET");
    assert_eq!(resp.status, 402, "expected 402, got {}", resp.status);

    let payload = extract_jws_payload(&resp.body);
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .expect("sub claim present");
    // The Wave 3.1 build with the `agent-class` cargo feature on
    // (binary default) resolves GPTBot/1.0 to the catalog id
    // `openai-gptbot`. A build with `agent-class` off threads `None`
    // into the policy and the policy stamps `unknown`. We accept
    // either so the test stays green across feature configurations
    // while still pinning the new, non-`unknown` id when the feature
    // is on (which is the build the e2e suite runs).
    assert!(
        sub == "openai-gptbot" || sub == "unknown",
        "GPTBot/1.0 should resolve to `openai-gptbot` (agent-class on) \
         or `unknown` (agent-class off); got `{sub}`",
    );
    // The default build of `sbproxy` enables `agent-class` (see
    // crates/sbproxy/Cargo.toml). Pin the typical case so a
    // regression on the resolver thread surfaces here, even if the
    // looser assertion above would let it slide.
    assert_eq!(
        sub, "openai-gptbot",
        "default build should resolve GPTBot/1.0 to `openai-gptbot`"
    );
}

#[test]
fn jws_sub_falls_back_to_human_for_unrecognized_agent() {
    // A standard browser UA does not match any catalog regex and
    // falls through every other resolver step. The chain lands on
    // the `human` sentinel per G1.1's taxonomy. The JWS `sub` claim
    // should mirror that.
    //
    // Note: the prompt for this slice asked for `human` here; the
    // resolver chain in
    // `sbproxy-modules::policy::agent_class::resolve` confirms
    // (Step 6: fallthrough -> Resolved::human()).
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.test.sbproxy.dev",
            &[
                (
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                     AppleWebKit/537.36 (KHTML, like Gecko) \
                     Chrome/123.0.0.0 Safari/537.36",
                ),
                ("accept-payment", "x402"),
            ],
        )
        .expect("send GET");
    assert_eq!(resp.status, 402, "expected 402, got {}", resp.status);

    let payload = extract_jws_payload(&resp.body);
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .expect("sub claim present");
    // Default build (agent-class on) -> `human`. agent-class off ->
    // `unknown`. Either is acceptable; pin the typical case below.
    assert!(
        sub == "human" || sub == "unknown",
        "Mozilla UA should resolve to `human` (agent-class on) or \
         `unknown` (agent-class off); got `{sub}`",
    );
    assert_eq!(sub, "human", "default build should resolve to `human`");
}

#[test]
fn jws_sub_uses_human_when_no_user_agent() {
    // No User-Agent at all. The resolver chain has no signal at any
    // step; the fallthrough produces `human` per G1.1. (The
    // `anonymous` sentinel is reserved for the Web Bot Auth path
    // with an unknown keyid; without bot-auth the resolver does not
    // reach that step.)
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness
        .get_with_headers(
            "/article",
            "blog.test.sbproxy.dev",
            &[("accept-payment", "x402")],
        )
        .expect("send GET");
    assert_eq!(resp.status, 402, "expected 402, got {}", resp.status);

    let payload = extract_jws_payload(&resp.body);
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .expect("sub claim present");
    // Default build -> `human` (resolver fallthrough). agent-class
    // off -> `unknown`.
    assert!(
        sub == "human" || sub == "unknown",
        "no-UA request should resolve to `human` (agent-class on) or \
         `unknown` (agent-class off); got `{sub}`",
    );
    assert_eq!(
        sub, "human",
        "default build should resolve no-UA request to `human`"
    );
}
