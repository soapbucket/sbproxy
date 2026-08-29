//! The seam every new module type has to cross: its `type:` string.
//!
//! A policy, transform, or action reaches an operator only if
//! `compile_policy` / `compile_transform` / `compile_action` recognizes
//! the string in its config block. Everything else in a module type can
//! be written and unit tested and still be unreachable, because the
//! compiler's fallthrough arm hands an unknown string to the plugin
//! registry and, finding no plugin, returns an error. That is the shape
//! a missing match arm has: not a compile failure, a config that an
//! operator writes and the proxy refuses at load.
//!
//! Each test here names one type string and asserts it compiles to the
//! variant it is supposed to. Every one of them fails on a tree without
//! its match arm, which is what makes them the red-first coverage for
//! WOR-2668, WOR-2670, and WOR-2671 rather than a restatement of the
//! per-module unit tests. They deliberately use only the crate's public
//! API, so the file compiles unchanged against a tree that has none of
//! these types and fails there at the assertion rather than at the
//! `use` line.

use sbproxy_modules::{compile_action, compile_policy, compile_transform};

// --- WOR-2668: enrichment producers ---------------------------------------

#[test]
fn geoip_policy_type_string_compiles_to_the_geoip_variant() {
    let policy = compile_policy(&serde_json::json!({
        "type": "geoip",
        "inject_headers": false,
    }))
    .expect("`type: geoip` is a known policy type");
    assert_eq!(policy.policy_type(), "geoip");
}

#[test]
fn geoip_policy_type_string_compiles_with_no_keys_set() {
    // `database_path` and `inject_headers` both default, so an operator
    // can turn the policy on without deciding either.
    let policy = compile_policy(&serde_json::json!({ "type": "geoip" }))
        .expect("`type: geoip` compiles with every key defaulted");
    assert_eq!(policy.policy_type(), "geoip");
}

#[test]
fn user_agent_parser_policy_type_string_compiles_to_the_user_agent_variant() {
    let policy = compile_policy(&serde_json::json!({
        "type": "user_agent_parser",
        "inject_header": "x-ua-info",
    }))
    .expect("`type: user_agent_parser` is a known policy type");
    assert_eq!(policy.policy_type(), "user_agent_parser");
}

#[test]
fn user_agent_parser_policy_type_string_compiles_with_no_keys_set() {
    let policy = compile_policy(&serde_json::json!({ "type": "user_agent_parser" }))
        .expect("`type: user_agent_parser` compiles with every key defaulted");
    assert_eq!(policy.policy_type(), "user_agent_parser");
}

// --- WOR-2670: transform types --------------------------------------------

#[test]
fn ai_schema_transform_type_string_compiles_to_the_ai_schema_variant() {
    let transform = compile_transform(&serde_json::json!({
        "type": "ai_schema",
        "schema": { "type": "object", "required": ["answer"] },
        "on_failure": "warn",
    }))
    .expect("`type: ai_schema` is a known transform type");
    assert_eq!(transform.transform_type(), "ai_schema");
}

/// `pdf_markdown` lives behind the optional `transform-pdf` feature, so
/// the type string is only expected to resolve when that feature is on.
/// Without it the arm must still be absent rather than compiling to
/// something else.
#[cfg(feature = "transform-pdf")]
#[test]
fn pdf_markdown_transform_type_string_compiles_to_the_pdf_variant() {
    let transform = compile_transform(&serde_json::json!({ "type": "pdf_markdown" }))
        .expect("`type: pdf_markdown` is a known transform type under transform-pdf");
    assert_eq!(transform.transform_type(), "pdf_markdown");
}

// --- WOR-2671: action types -----------------------------------------------

#[test]
fn abtest_action_type_string_compiles_to_the_abtest_variant() {
    let action = compile_action(&serde_json::json!({
        "type": "abtest",
        "variants": [
            { "name": "control", "url": "https://a.example.com", "weight": 50 },
            { "name": "experiment", "url": "https://b.example.com", "weight": 50 },
        ],
    }))
    .expect("`type: abtest` is a known action type");
    assert_eq!(action.action_type(), "abtest");
}

#[test]
fn https_proxy_action_type_string_compiles_to_the_https_proxy_variant() {
    let action = compile_action(&serde_json::json!({
        "type": "https_proxy",
        "allowed_hosts": ["api.example.com", "*.internal.io"],
    }))
    .expect("`type: https_proxy` is a known action type");
    assert_eq!(action.action_type(), "https_proxy");
}

// --- The types this port deliberately did not add -------------------------

/// WOR-2670 and WOR-2671 each asked for a decision on two types rather
/// than a port. All four were dropped, and this pins that: a config
/// naming one of them is refused at load rather than silently accepted.
///
/// The reasoning is in the PR body. In short: `ai_cache` and
/// `token_count` duplicate shipped work (`sbproxy-ai`'s semantic cache
/// and its usage/cost accounting) and both carry defects;
/// `loadbalancer_adv` and `orchestration` are declarations whose
/// implementations degrade to a constant, a round-robin, or nothing at
/// all. If a later ticket ports any of them, this test is the one that
/// goes red and asks whether the decision was revisited on purpose.
#[test]
fn the_four_declined_module_types_are_not_config_surface() {
    for declined in ["ai_cache", "token_count"] {
        let result = compile_transform(&serde_json::json!({ "type": declined }));
        assert!(
            result.is_err(),
            "`{declined}` was declined in WOR-2670 but compiles as a transform"
        );
    }
    for declined in ["loadbalancer_adv", "advanced_lb", "orchestration"] {
        let result = compile_action(&serde_json::json!({ "type": declined }));
        assert!(
            result.is_err(),
            "`{declined}` was declined in WOR-2671 but compiles as an action"
        );
    }
}
