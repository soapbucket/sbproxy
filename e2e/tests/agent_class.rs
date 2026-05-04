//! Q1.3: agent-class resolver e2e.
//!
//! Per `docs/adr-agent-class-taxonomy.md`, the resolver picks the first
//! matching signal in this order:
//!   1. Web Bot Auth verified `keyid`
//!   2. Reverse-DNS forward-confirmed
//!   3. UA regex match
//!   4. Anonymous Web Bot Auth (no keyid match)
//!   5. Generic crawler UA heuristic => `unknown`
//!   6. Fallthrough => `human`
//!
//! Implementation lives in `crates/sbproxy-modules/src/policy/agent_class.rs`
//! per the ADR; the resolver lands on `wave1/G1.4-G1.5-agent-class`. Until
//! that branch merges, the assertions in this file are gated behind
//! `#[ignore]` markers because the proxy does not yet emit an
//! `X-Sb-Agent-Class`-style header (or carry the resolver result onto an
//! observable surface) for tests to read.
//!
//! Strategy for observing the verdict from a black-box e2e: the resolver
//! is expected to surface its decision via either (a) a response header
//! the proxy adds when an `enrich_response` flag is set, or (b) an
//! origin-side `X-Forwarded-Agent-Class` request header so a captured
//! upstream call can read it. We mirror (b) here because it does not
//! require a config knob unique to this test.

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

// --- Test 1: UA-only path => vendor=openai ---

#[test]
#[ignore = "TODO(wave2): G1.4 resolver landed (`crates/sbproxy-modules/src/policy/agent_class.rs::AgentClassResolver`), but the binary does not yet construct a resolver from `sb.yml` (no `agent_classes:` block + `policies: - type: agent_class` not registered). See WATCH.md \"AgentClassResolver instantiation deferred to config wiring\"."]
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
#[ignore = "TODO(wave2): G1.5 reverse-DNS verifier landed but agent_class policy is not wired (see WATCH.md). Live PTR resolver (`SystemResolver::reverse`) returns typed error today."]
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
#[ignore = "TODO(wave2): G1.5 forward-confirm step landed in `sbproxy-security::agent_verify::verify_reverse_dns`; agent_class policy not yet wired in config compiler (see WATCH.md)."]
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
#[ignore = "TODO(wave2): G1.4 resolver + bot_auth directory both landed; agent_class policy not yet wired in config compiler (see WATCH.md)."]
fn bot_auth_keyid_in_directory_resolves_verified() {
    let upstream = MockUpstream::start(json!({"ok": true})).expect("upstream");
    let harness = ProxyHarness::start_with_yaml(&agent_class_config(&upstream.base_url()))
        .expect("start proxy");

    // The fixture's static directory holds an OpenAI-owned keyid. The
    // request signs RFC 9421 components with the matching key, the
    // resolver picks the bot-auth path (highest precedence), and the
    // verdict is verified with vendor=openai.
    let signature_input = r#"sig1=("@method" "@target-uri");created=1700000000;keyid="openai-gptbot-key-1";alg="ed25519""#;
    let resp = harness
        .get_with_headers(
            "/",
            "blog.localhost",
            &[
                ("signature-input", signature_input),
                // Real signature is produced by the regen binary; until
                // it lands the test stays ignored.
                ("signature", "sig1=:AAAA:"),
            ],
        )
        .expect("send");
    assert_eq!(resp.status, 200);
    let captured = upstream.captured();
    let agent_class = captured[0]
        .headers
        .get("x-forwarded-agent-class")
        .unwrap_or(&String::new())
        .clone();
    assert!(agent_class.contains("openai"));
}

// --- Test 5: sentinel => no signal => human ---

#[test]
#[ignore = "TODO(wave2): G1.4 resolver emits `human` sentinel; agent_class policy not yet wired in config compiler (see WATCH.md)."]
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
