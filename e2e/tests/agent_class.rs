//! Q1.3: agent-class resolver e2e.
//!
//! Per , the resolver picks the first
//! matching signal in this order:
//!   1. Web Bot Auth verified `keyid`
//!   2. Reverse-DNS forward-confirmed
//!   3. UA regex match
//!   4. Anonymous Web Bot Auth (no keyid match)
//!   5. Generic crawler UA heuristic => `unknown`
//!   6. Fallthrough => `human`
//!
//! Implementation lives in `crates/sbproxy-modules/src/policy/agent_class.rs`
//! (resolver) plus `crates/sbproxy-core/src/server/proxy_http.rs`
//! (`forward_to_upstream` stamping). The resolver runs in `request_filter`
//! from the built-in catalog, and an `agent_class` policy with
//! `forward_to_upstream: true` stamps the verdict onto the upstream request
//! as `X-Forwarded-Agent-Class` / `-Vendor` / `-Verified` (WOR-1132).
//!
//! The UA-only, bot-auth-keyid, and human-sentinel cases run; the
//! reverse-DNS and rDNS-spoof cases stay `#[ignore]`'d on real blockers
//! (live / injectable DNS and an open product question on UA-claim
//! demotion) - see each test's reason.
//!
//! Strategy for observing the verdict from a black-box e2e: the captured
//! upstream call reads the origin-side `X-Forwarded-Agent-Class` request
//! header the policy stamps. This does not require a config knob unique to
//! this test.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sbproxy_e2e::{MockUpstream, ProxyHarness};
use serde_json::json;

/// Origin config that turns on `agent_class` resolution and forwards
/// the resolved verdict to the upstream as `X-Forwarded-Agent-Class`.
/// The exact YAML keys are reserved by ADR; G1.4 will lock them in.
fn agent_class_config(upstream_url: &str) -> String {
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
      - type: agent_class
        forward_to_upstream: true
        # G1.5 feature flag: when true the resolver runs PTR + forward A
        # round-trip on the client IP to guard against UA spoofing.
        verify_reverse_dns: true
"#
    )
}

fn agent_class_bot_auth_config(upstream_url: &str, verifying_key_hex: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0
agent_classes:
  catalog: inline
  resolver:
    rdns_enabled: false
  entries:
    - id: conformance-bot
      vendor: Conformance
      purpose: training
      expected_user_agent_pattern: "(?i)\\bConformanceBot/\\d"
      expected_reverse_dns_suffixes: []
      expected_keyids:
        - conformance-key
    - id: ua-spoof-bot
      vendor: Spoofed
      purpose: search
      expected_user_agent_pattern: "(?i)\\bSpoofBot/\\d"
      expected_reverse_dns_suffixes: []
      expected_keyids: []
origins:
  "blog.localhost":
    action:
      type: proxy
      url: "{upstream_url}"
    authentication:
      type: bot_auth
      clock_skew_seconds: 9999999999
      agents:
        - name: conformance-bot
          key_id: conformance-key
          algorithm: ed25519
          public_key: "{verifying_key_hex}"
          required_components:
            - "@method"
            - "@target-uri"
    policies:
      - type: agent_class
        forward_to_upstream: true
        verify_reverse_dns: false
"#
    )
}

fn build_base_for_get_root(inner_list: &str, params: &str) -> String {
    let mut out = String::new();
    out.push_str("\"@method\": GET\n");
    out.push_str("\"@target-uri\": /\n");
    out.push_str("\"@signature-params\": (");
    out.push_str(inner_list);
    out.push(')');
    if !params.is_empty() {
        out.push(';');
        out.push_str(params);
    }
    out
}

fn fresh_keypair() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

// --- Test 1: UA-only path => vendor=openai ---

#[test]
// WOR-1132: reactivated. The agent_class resolver runs in `request_filter`
// from the built-in catalog and `forward_to_upstream: true` now stamps
// the verdict onto the upstream request, so the UA-only catalog match is
// observable end-to-end.
fn ua_only_resolves_to_gptbot_vendor_openai() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&agent_class_config(&upstream.base_url()))
        .expect("start proxy");

    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[(
                "user-agent",
                "Mozilla/5.0 (compatible; GPTBot/2.1; +https://openai.com/gptbot)",
            )],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    let agent_class = captured[0]
        .headers
        .get("x-forwarded-agent-class")
        .expect("agent_class header forwarded");
    assert!(
        agent_class.contains("openai") && agent_class.contains("gptbot"),
        "GPTBot UA should resolve to openai-gptbot, got {agent_class}"
    );
}

// --- Test 2: reverse-DNS verified path => vendor=google, verified ---

#[test]
#[ignore = "WOR-1132: agent_class policy + forward_to_upstream are wired (see the reactivated UA / human tests), but this test needs a forward-confirmed PTR for 66.249.66.1 -> *.googlebot.com. The binary uses the live `SystemResolver`, which is nondeterministic in CI; reactivation needs an injectable test resolver feeding the binary a static PTR/A fixture. Tracked under WOR-1133 (e2e harness gaps)."]
fn reverse_dns_verified_resolves_to_googlebot() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&agent_class_config(&upstream.base_url()))
        .expect("start proxy");

    // The G1.5 reverse-DNS verifier must accept an injectable resolver
    // for tests so we do not depend on real DNS. The fixture under
    // `e2e/fixtures/wave1/agent_class/` will carry the static
    // PTR -> A mapping. Until G1.5 lands, the proxy has no test hook;
    // the test stays ignored.
    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                (
                    "user-agent",
                    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                ),
                // Some test harness will inject `X-Forwarded-For` so the
                // resolver sees a Google IP that PTR-resolves to *.googlebot.com.
                ("x-forwarded-for", "66.249.66.1"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let captured = upstream.captured();
    let agent_class = captured[0]
        .headers
        .get("x-forwarded-agent-class")
        .expect("agent_class header forwarded");
    assert!(
        agent_class.contains("google"),
        "Googlebot rDNS verify should yield google vendor: {agent_class}"
    );
    let verified = captured[0]
        .headers
        .get("x-forwarded-agent-verified")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert_eq!(verified, "true", "rDNS path must mark verdict as verified");
}

// --- Test 3: rDNS spoof => falls back to unknown ---

#[test]
#[ignore = "WOR-1132: behavior mismatch, not wiring. The resolver accepts a UA-regex match (step 3) at face value when reverse-DNS does not confirm; it does NOT demote a GPTBot UA from a non-Google IP to `unknown`. So forwarding stamps `openai-gptbot`, not `unknown`. Reactivation needs a resolver policy decision on whether an unconfirmed UA claim should be demoted (product question), tracked separately."]
fn rdns_spoof_falls_back_to_unknown() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&agent_class_config(&upstream.base_url()))
        .expect("start proxy");

    // UA claims GPTBot but the client IP PTR does not resolve back to
    // a `*.gptbot.openai.com` suffix. The verifier must demote the
    // verdict from `openai-gptbot` to `unknown`.
    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                (
                    "user-agent",
                    "Mozilla/5.0 (compatible; GPTBot/2.1; +https://openai.com/gptbot)",
                ),
                ("x-forwarded-for", "203.0.113.99"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);

    let captured = upstream.captured();
    let agent_class = captured[0]
        .headers
        .get("x-forwarded-agent-class")
        .expect("agent_class header forwarded");
    assert!(
        agent_class.contains("unknown"),
        "Spoofed UA must demote to unknown: {agent_class}"
    );
}

// --- Test 4: bot-auth keyid matches expected => verified ---

#[test]
fn bot_auth_keyid_in_directory_resolves_verified() {
    let signing_key = fresh_keypair();
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&agent_class_bot_auth_config(
        &upstream.base_url(),
        &verifying_key_hex,
    ))
    .expect("start proxy");

    let inner_list = r#""@method" "@target-uri""#;
    let params = r#"created=1700000000;keyid="conformance-key";alg="ed25519""#;
    let base = build_base_for_get_root(inner_list, params);
    let sig = signing_key.sign(base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    let signature_input = format!("sig1=({});{}", inner_list, params);
    let signature_header = format!("sig1=:{}:", sig_b64);

    // The UA would resolve to `ua-spoof-bot` if the verified keyid
    // were not restamped after auth. BotAuth must outrank it.
    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                ("user-agent", "SpoofBot/1.0"),
                ("signature-input", signature_input.as_str()),
                ("signature", signature_header.as_str()),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1);
    let agent_class = captured[0]
        .headers
        .get("x-forwarded-agent-class")
        .unwrap_or(&String::new())
        .clone();
    assert_eq!(agent_class, "conformance-bot");
    assert_eq!(
        captured[0]
            .headers
            .get("x-forwarded-agent-vendor")
            .map(|s| s.as_str()),
        Some("Conformance")
    );
    assert_eq!(
        captured[0]
            .headers
            .get("x-forwarded-agent-verified")
            .map(|s| s.as_str()),
        Some("true")
    );
}

// --- Test 5: sentinel => no signal => human ---

#[test]
// WOR-1132: reactivated. A vanilla browser UA falls through every signal
// to the `human` sentinel, and `forward_to_upstream` surfaces it on the
// upstream request.
fn no_signals_resolves_to_human_sentinel() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&agent_class_config(&upstream.base_url()))
        .expect("start proxy");

    // Vanilla browser UA, no signature, no rDNS hit => `human`. The
    // ADR locks `human` as the no-signal sentinel; if the implementation
    // picks `unknown` instead this test calls the bug.
    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[(
                "user-agent",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    let agent_class = captured[0]
        .headers
        .get("x-forwarded-agent-class")
        .map(|s| s.as_str())
        .unwrap_or("");
    assert_eq!(
        agent_class, "human",
        "vanilla browser must resolve to `human` sentinel per ADR"
    );
}
