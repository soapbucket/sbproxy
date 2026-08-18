// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Red-first live-refusal proof for the `owasp_api_top10` pack's
//! `api4`/`api5`/`api8` synthesis (WOR-2491), plus `api3`'s response
//! half (WOR-2491 task 3).
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
//! `check_request`, `ObjectAuthzPolicy`'s `decide`). `api3`'s response
//! half follows the same idiom one level down: it is a *transform*,
//! not a policy, so its test drives a real JSON response body through
//! `sbproxy_modules::compile_transform`'s dispatch and
//! `Transform::apply`, the same entry point the compiled pipeline uses
//! at `response_body_filter` time.
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
//! `api3`'s request half is not retested here either: the pack never
//! synthesizes anything for it (both `openapi_validation` and
//! `request_validator` require operator-supplied content), so there is
//! no pack-added behavior to drive live traffic through - the manifest
//! state/reason proof lives in `sbproxy-config`'s own tests instead.
//! `api9` is not retested here either: its control is a plain origin
//! field (`expose_openapi`), not a module this crate compiles.

use std::net::IpAddr;

use sbproxy_config::compile_config;
use sbproxy_config::types::FailureMode;
use sbproxy_modules::policy::{ConcurrentLimitPolicy, HttpFramingPolicy, RequestLimitPolicy};
use sbproxy_modules::{DdosCheckResult, DdosPolicy, ObjectAuthzPolicy, ObjectAuthzPrincipal};
use sbproxy_modules::{RateLimitPolicy, SecHeadersPolicy, TransformConfig};

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

/// Compiles one origin with the given `policies:` YAML block and
/// returns the synthesized JSON *transform* entry of type
/// `wanted_type` from `transform_configs` - `api3`'s response half
/// lands there, not on `policy_configs`.
fn synthesized_transform(policies_yaml: &str, wanted_type: &str) -> serde_json::Value {
    let yaml = format!(
        "origins:\n  api.example.com:\n    action:\n      type: proxy\n      \
         url: https://test.sbproxy.dev\n    policies:\n{policies_yaml}"
    );
    let compiled = compile_config(&yaml).expect("owasp pack config must compile");
    let origin = compiled
        .resolve_origin("api.example.com")
        .expect("origin present");
    origin
        .transform_configs
        .iter()
        .find(|t| t.get("type").and_then(|v| v.as_str()) == Some(wanted_type))
        .unwrap_or_else(|| {
            panic!(
                "synthesized {wanted_type} present among: {:?}",
                origin.transform_configs
            )
        })
        .clone()
}

fn api3_response_exclude_yaml() -> &'static str {
    "      - type: owasp_api_top10\n        enable: [api3]\n        per_item:\n          \
     api3:\n            response_exclude_fields: [ssn, internal_notes]\n"
}

fn api4_yaml() -> &'static str {
    // WOR-2491 review round, B1: rate_limiting and ddos_protection
    // both key on caller IP by default and are only synthesized when
    // the operator supplies per_item.api4.rps (the pack no longer
    // guesses a blind default - see owasp_api_pack.rs's own unit
    // tests for the outage class this avoids). rps: 100 gives
    // burst: 200 (rate_limit_burst_from_rps) and ddos threshold: 300
    // (ddos_threshold_from_burst, headroom above the burst ceiling -
    // a second review-round fix: the threshold used to be `rps`
    // itself, which let a client bursting within rate_limiting's own
    // tolerance trip a five-minute ddos block instead of an ordinary
    // 429). Both tests below read their expected numbers back out of
    // the synthesized JSON rather than hard-coding them.
    "      - type: owasp_api_top10\n        enable: [api4]\n        per_item:\n          \
     api4:\n            rps: 100\n"
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
    // WOR-2491 review round: the pack synthesizes
    // `{"type": "ddos_protection", "requests_per_second": <threshold>}`
    // where `<threshold>` is `ddos_threshold_from_burst`'s headroom
    // above `rate_limiting`'s own burst ceiling for the same
    // `per_item.api4.rps`, not the raw rps value - a real interaction
    // bug caught in review (a burst inside rate_limiting's own
    // tolerance used to trip a five-minute ddos block instead of an
    // ordinary 429). Read the pack's own threshold out of the
    // synthesized JSON rather than hard-coding it, so this test
    // tracks the formula if it ever changes. `block_duration_secs`
    // and the sliding-window width stay at ddos.rs's own module
    // defaults.
    let json = synthesized_policy(api4_yaml(), "ddos_protection");
    let threshold = json
        .get("requests_per_second")
        .and_then(|v| v.as_u64())
        .expect("pack sets an explicit requests_per_second") as usize;
    let policy = DdosPolicy::from_config(json).expect("valid ddos_protection config");
    let ip: IpAddr = "203.0.113.7".parse().expect("valid test IP");

    for n in 0..threshold {
        assert_eq!(
            policy.check(ip),
            DdosCheckResult::Allow,
            "request {n} within the configured {threshold}/s threshold must pass"
        );
    }
    assert!(
        matches!(policy.check(ip), DdosCheckResult::Block { .. }),
        "one request past the configured threshold must be blocked"
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

// --- api3: Broken Object Property Level Authorization (response half) ---

#[test]
fn api3_response_projection_strips_the_declared_fields_through_the_real_transform_chain() {
    // The plan ledger's 2026-08-18 CORRECTION, proven end to end: the
    // synthesized `json_projection` transform is not a hand-copied
    // literal here - it is read back off the compiled origin's own
    // `transform_configs`, then run through
    // `sbproxy_modules::compile_transform`, the same dispatcher
    // `sbproxy-core`'s pipeline uses to build the real
    // `CompiledTransform` chain, and `Transform::apply`, the same
    // entry point `response_body_filter` calls per chunk
    // (`transform/mod.rs`). A real JSON response body loses the two
    // declared fields and keeps everything else.
    let json = synthesized_transform(api3_response_exclude_yaml(), "json_projection");
    assert_eq!(
        json.get("exclude").and_then(|v| v.as_bool()),
        Some(true),
        "must exclude the listed fields, not include only them"
    );

    let transform =
        sbproxy_modules::compile_transform(&json).expect("valid json_projection config");

    let mut body = bytes::BytesMut::from(
        &br#"{"id":"42","ssn":"000-00-0000","internal_notes":"flagged","name":"ok"}"#[..],
    );
    transform
        .apply(&mut body, Some("application/json"))
        .expect("json_projection apply must succeed");

    let after: serde_json::Value =
        serde_json::from_slice(&body).expect("transform output must still be valid JSON");
    assert!(
        after.get("ssn").is_none(),
        "ssn must be stripped from the response body: {after}"
    );
    assert!(
        after.get("internal_notes").is_none(),
        "internal_notes must be stripped from the response body: {after}"
    );
    assert_eq!(
        after.get("id").and_then(|v| v.as_str()),
        Some("42"),
        "fields outside the exclude list must survive: {after}"
    );
    assert_eq!(
        after.get("name").and_then(|v| v.as_str()),
        Some("ok"),
        "fields outside the exclude list must survive: {after}"
    );
}

#[test]
fn api3_response_projection_leaves_an_array_body_unchanged() {
    // WOR-2491 review round, B2: `JsonProjectionTransform::apply`
    // filters top-level *object* keys only; a JSON array response
    // body - a very common real API shape - passes through
    // unfiltered even when it contains the exact field names the
    // pack was told to strip. This is the honest boundary
    // `expand_api3_entry`'s doc comment and every doc surface now
    // name explicitly, proven here through the real synthesized entry
    // and the real dispatcher, not a hand-copied transform.
    let json = synthesized_transform(api3_response_exclude_yaml(), "json_projection");
    let transform =
        sbproxy_modules::compile_transform(&json).expect("valid json_projection config");

    let original = br#"[{"id":"42","ssn":"000-00-0000","internal_notes":"flagged"}]"#;
    let mut body = bytes::BytesMut::from(&original[..]);
    transform
        .apply(&mut body, Some("application/json"))
        .expect("json_projection apply must succeed even though it does nothing here");

    let before: serde_json::Value = serde_json::from_slice(original).expect("valid JSON fixture");
    let after: serde_json::Value =
        serde_json::from_slice(&body).expect("transform output must still be valid JSON");
    assert_eq!(
        after, before,
        "an array response body is out of scope for json_projection and must pass through byte \
         for byte, ssn and internal_notes included: {after}"
    );
}

#[test]
fn api3_response_projection_synthesizes_closed_failure_posture() {
    // WOR-2491 review round, B2: without an explicit `failure_posture`
    // key, `TransformConfig`'s own default is `open` (a body that is
    // oversized or fails to parse ships raw and unfiltered - exactly
    // the leak this pack piece exists to prevent). Parses the
    // synthesized entry through the same `TransformConfig` wrapper
    // `sbproxy-core`'s pipeline uses to resolve the failure axis
    // (`server/proxy_http.rs`'s pre-capture size refusal and
    // `action_dispatch.rs`'s plugin-action path both key off
    // `TransformConfig::failure_posture()`), so this is a real proof
    // the wire value round-trips to `Closed`, not an assertion against
    // a hand-copied literal. Fails red without the `"failure_posture":
    // "closed"` key `expand_api3_entry` now sets.
    let json = synthesized_transform(api3_response_exclude_yaml(), "json_projection");
    let wrapper: TransformConfig =
        serde_json::from_value(json).expect("synthesized entry parses as a TransformConfig");
    assert_eq!(
        wrapper.failure_posture(),
        FailureMode::Closed,
        "an oversized or unparseable response body must be refused, not shipped raw"
    );
}
