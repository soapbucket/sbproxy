// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Red-first live-refusal proof for the `owasp_api_top10` pack's
//! `api4`/`api5`/`api8` synthesis (WOR-2491).
//!
//! `sbproxy-config` (which owns `ITEM_TABLE` and the synthesis
//! functions) cannot construct a policy enforcer itself: the module
//! structs (`RequestLimitPolicy`, `RateLimitPolicy`, ...) live in this
//! crate, one dependency layer up. This file closes that loop. Every
//! test here compiles a real `sb.yml` through the crate's own
//! `sbproxy_config::compile_config` - so the JSON under test is
//! whatever `ITEM_TABLE`'s synthesis functions actually produce, not a
//! hand-copied literal that could drift out of sync with them - then
//! builds the real module struct from the synthesized entry and drives
//! a request through that struct's own check method: the same idiom
//! each policy's own unit tests already use (`RequestLimitPolicy`'s
//! `check_request`, `RateLimitPolicy`'s `allow`, `ConcurrentLimitPolicy`'s
//! `try_acquire`, `DdosPolicy`'s `check`, `HttpFramingPolicy`'s
//! `check_request`, `ObjectAuthzPolicy`'s `decide`).
//!
//! Every refusal assertion cites the exact line of the policy's own
//! check logic it exercises, so a reviewer can see the refusal
//! boundary directly rather than trust a description of it. `api1` is
//! not retested here: its live-refusal behavior (none, by design,
//! until an operator adds `object_rules`) is unchanged from the first
//! cut of this pack and already covered by `sbproxy-config`'s own
//! tests. `api7` is not retested here either: it is not policy-gated,
//! so nothing this pack does changes its behavior - the refusal it
//! relies on is already proven by
//! `sbproxy-security::ssrf::tests::validate_url_resolved_blocks_private_ip`.

use std::net::IpAddr;

use sbproxy_config::compile_config;
use sbproxy_modules::policy::{ConcurrentLimitPolicy, HttpFramingPolicy, RequestLimitPolicy};
use sbproxy_modules::{DdosCheckResult, DdosPolicy, ObjectAuthzPolicy, ObjectAuthzPrincipal};
use sbproxy_modules::{RateLimitPolicy, SecHeadersPolicy};

/// Compiles one origin with the given `policies:` YAML block (indented
/// as a `policies:` list body) and returns the synthesized JSON entry
/// of type `wanted_type`.
fn synthesized_policy(policies_yaml: &str, wanted_type: &str) -> serde_json::Value {
    let yaml = format!(
        "origins:\n  api.example.com:\n    action:\n      type: proxy\n      \
         url: https://test.sbproxy.dev\n    policies:\n{policies_yaml}"
    );
    let compiled = compile_config(&yaml).expect("owasp pack config must compile");
    let origin = compiled
        .resolve_origin("api.example.com")
        .expect("origin present");
    origin
        .policy_configs
        .iter()
        .find(|p| p.get("type").and_then(|v| v.as_str()) == Some(wanted_type))
        .unwrap_or_else(|| {
            panic!(
                "synthesized {wanted_type} present among: {:?}",
                origin.policy_configs
            )
        })
        .clone()
}

fn api4_yaml() -> &'static str {
    "      - type: owasp_api_top10\n        enable: [api4]\n"
}

fn api5_yaml() -> &'static str {
    "      - type: owasp_api_top10\n        enable: [api5]\n"
}

fn api1_and_api5_yaml() -> &'static str {
    "      - type: owasp_api_top10\n        enable: [api1, api5]\n"
}

fn api8_yaml() -> &'static str {
    "      - type: owasp_api_top10\n        enable: [api8]\n"
}

// --- api4: Unrestricted Resource Consumption ---

#[test]
fn api4_request_limit_default_refuses_a_body_over_one_mebibyte() {
    // request_limit.rs `check_request`: `if body_size > max { return
    // Err(...) }` (strictly greater). The pack's default max_body_size
    // is 1_048_576 bytes: exactly that size passes, one byte over
    // refuses.
    let json = synthesized_policy(api4_yaml(), "request_limit");
    let policy = RequestLimitPolicy::from_config(json).expect("valid request_limit config");

    assert!(
        policy.check_request(1_048_576, 1, 1, 1, 0).is_ok(),
        "exactly the configured limit must pass"
    );
    let result = policy.check_request(1_048_577, 1, 1, 1, 0);
    assert!(
        result.is_err(),
        "one byte over the pack's default must be refused"
    );
    assert!(result.unwrap_err().contains("body size"));
}

#[test]
fn api4_rate_limiting_default_refuses_past_its_configured_burst() {
    // rate_limit.rs's token bucket: `burst` tokens are available up
    // front; the next call after they are consumed returns `allowed:
    // false` until the bucket refills. Read the pack's own burst value
    // out of the synthesized JSON rather than hard-coding it, so this
    // test tracks ITEM_TABLE's default if it ever changes.
    let json = synthesized_policy(api4_yaml(), "rate_limiting");
    let burst = json
        .get("burst")
        .and_then(|v| v.as_u64())
        .expect("pack sets an explicit burst") as usize;
    let policy = RateLimitPolicy::from_config(json).expect("valid rate_limiting config");

    for n in 0..burst {
        assert!(
            policy.allow(),
            "request {n} within the configured burst of {burst} must pass"
        );
    }
    assert!(
        !policy.allow(),
        "one request past the configured burst must be refused"
    );
}

#[test]
fn api4_concurrent_limit_default_refuses_past_its_configured_max() {
    // concurrent_limit.rs's `try_acquire`: returns `None` once `max`
    // permits are outstanding for the key. Read the pack's own `max`
    // out of the synthesized JSON rather than hard-coding it.
    let json = synthesized_policy(api4_yaml(), "concurrent_limit");
    let max = json
        .get("max")
        .and_then(|v| v.as_u64())
        .expect("pack sets an explicit max") as usize;
    let policy = ConcurrentLimitPolicy::from_config(json).expect("valid concurrent_limit config");

    let mut guards = Vec::with_capacity(max);
    for n in 0..max {
        guards.push(
            policy
                .try_acquire("global")
                .unwrap_or_else(|| panic!("permit {n} within the configured max must be issued")),
        );
    }
    assert!(
        policy.try_acquire("global").is_none(),
        "one request past the configured max must be refused"
    );
    drop(guards);
}

#[test]
fn api4_ddos_default_blocks_after_its_built_in_per_ip_threshold() {
    // The pack synthesizes an empty `{"type": "ddos_protection"}`,
    // relying entirely on ddos.rs's own defaults:
    // `default_ddos_threshold()` is 100 requests/second per IP in a
    // sliding 1-second window.
    let json = synthesized_policy(api4_yaml(), "ddos_protection");
    let policy = DdosPolicy::from_config(json).expect("valid ddos_protection config");
    let ip: IpAddr = "203.0.113.7".parse().expect("valid test IP");

    for n in 0..100 {
        assert_eq!(
            policy.check(ip),
            DdosCheckResult::Allow,
            "request {n} within the built-in 100/s threshold must pass"
        );
    }
    assert!(
        matches!(policy.check(ip), DdosCheckResult::Block { .. }),
        "the 101st request within the same second must be blocked"
    );
}

// --- api5: Broken Function Level Authorization ---

#[test]
fn api5_alone_never_refuses_because_function_rules_stays_empty() {
    // Documents the module-verified finding behind api5's manifest
    // state (needs_operator_input, not enforced): with `function_rules`
    // empty, `ObjectAuthzPolicy::decide`'s BFLA loop
    // (`for rule in &self.function_rules`) iterates zero times, so
    // nothing is ever refused regardless of `test_mode`. This is a
    // green, not red, proof: api5 alone has no context-free BFLA
    // fallback the way api1's (object_rules-gated) enumeration check
    // does.
    let json = synthesized_policy(api5_yaml(), "object_authz");
    assert_eq!(
        json.get("function_rules")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(0)
    );
    let policy = ObjectAuthzPolicy::from_config(json).expect("valid object_authz config");
    let caller = ObjectAuthzPrincipal {
        owner: Some("tenant-a".to_string()),
        roles: Vec::new(),
    };
    assert_eq!(
        policy.decide(&caller, "DELETE", "/admin/anything"),
        None,
        "no function_rules means nothing is privileged, so nothing is refused"
    );
}

#[test]
fn api1_and_api5_share_one_object_authz_entry_that_still_refuses_nothing_blind() {
    // Companion to `api5_alone_never_refuses_because_function_rules_stays_empty`:
    // when api1 and api5 are both enabled, they share one object_authz
    // entry rather than adding two. That shared entry has both
    // object_rules and function_rules empty, so - per the same
    // decide() trace - neither BOLA, BFLA, nor enumeration has
    // anything to evaluate. This is intentionally a green proof, not a
    // red one: there is no context-free fallback in this entry today.
    let json = synthesized_policy(api1_and_api5_yaml(), "object_authz");
    assert_eq!(
        json.get("function_rules")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        0
    );
    let policy = ObjectAuthzPolicy::from_config(json).expect("valid object_authz config");
    let caller = ObjectAuthzPrincipal {
        owner: Some("tenant-a".to_string()),
        roles: Vec::new(),
    };
    for id in 1..=25 {
        assert_eq!(
            policy.decide(&caller, "GET", &format!("/orders/{id}")),
            None,
            "id {id}: no object_rules means nothing to enumerate either"
        );
    }
}

// --- api8: Security Misconfiguration ---

#[test]
fn api8_http_framing_default_refuses_dual_content_length_and_transfer_encoding() {
    // http_framing.rs `check_request`: "1. Dual CL+TE ... return
    // Err(FramingViolation::DualClTe)" when both Content-Length and
    // Transfer-Encoding headers are present, per RFC 9112 6.1. The
    // synthesized entry has no fields (the module's defense set is
    // hard-coded), so this exercises the module's unconditional
    // default.
    let json = synthesized_policy(api8_yaml(), "http_framing");
    let policy = HttpFramingPolicy::from_config(json).expect("valid http_framing config");

    let mut clean = http::HeaderMap::new();
    clean.insert(http::header::CONTENT_LENGTH, "5".parse().unwrap());
    assert!(
        policy.check_request(&clean).is_ok(),
        "Content-Length alone must pass"
    );

    let mut smuggling = http::HeaderMap::new();
    smuggling.insert(http::header::CONTENT_LENGTH, "5".parse().unwrap());
    smuggling.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
    let violation = policy
        .check_request(&smuggling)
        .expect_err("dual Content-Length/Transfer-Encoding must be refused");
    assert_eq!(
        violation,
        sbproxy_modules::policy::FramingViolation::DualClTe
    );
}

#[test]
fn api8_security_headers_default_injects_a_safe_baseline() {
    // security_headers has no refusal semantics (it always injects
    // configured headers into the response), so this is a presence
    // proof rather than a refusal proof: it confirms the pack's
    // default is not an empty `headers: []` that would silently do
    // nothing (sec_headers.rs's `resolved_headers` falls back to
    // legacy flat fields only when the canonical array is empty).
    let json = synthesized_policy(api8_yaml(), "security_headers");
    let policy = SecHeadersPolicy::from_config(json).expect("valid security_headers config");
    let (headers, _nonce) = policy.resolved_headers_for_request("/anything");
    let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"x-content-type-options"), "{names:?}");
    assert!(names.contains(&"x-frame-options"), "{names:?}");
    assert!(names.contains(&"referrer-policy"), "{names:?}");
}
