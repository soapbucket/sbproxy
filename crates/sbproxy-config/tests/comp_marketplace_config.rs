//! Config contract for `origins.<host>.comp` (WOR-2673).
//!
//! The refusals here exist because the CoMP bridge holds an invariant
//! its runtime cannot re-derive: `redeem` mints for one OLP tier, and
//! nothing in a redeem request names which tier the buyer paid for. A
//! catalog with two of them is a catalog where a buyer quoting the
//! cheap tier receives the expensive tier's license. Config load is the
//! only place that can be refused, so it is refused here rather than
//! disclosed in prose.

use sbproxy_config::compile_config;

/// A complete config whose one origin carries `olp:` plus `comp_block`.
fn config_with_comp(comp_block: &str) -> String {
    format!(
        "proxy:\n  http_bind_port: 8080\n\
         origins:\n  \"licensing.test\":\n    action:\n      type: static\n      \
         status_code: 200\n      content_type: text/plain\n      body: ok\n    \
         olp:\n      enabled: true\n      \
         signing_key: \"1122334455667788990011223344556677889900112233445566778899001122\"\n      \
         key_id: 2026-q3\n      issuer: https://licensing.test\n{comp_block}"
    )
}

/// One tier block, at the given id and authorization.
fn tier(id: &str, authorization: &str) -> String {
    format!(
        "        - id: {id}\n          name: {id}\n          description: a tier\n          \
         license: urn:rsl:{id}:default\n          shape: json-envelope\n          \
         authorization: {authorization}\n          route_glob: \"/**\"\n          \
         pricing:\n            model: per_request\n            currency: USD\n            \
         amount_micros: 2500\n"
    )
}

/// The `comp:` block wrapping `tiers`.
fn comp_block(tiers: &str) -> String {
    format!(
        "    comp:\n      enabled: true\n      \
         master_key: \"a-master-key-of-at-least-thirty-two-bytes\"\n      \
         rotation_id: 2026-q3-001\n      publisher:\n        name: Example Co.\n        \
         contact: licensing@example.test\n      tiers:\n{tiers}      buyer_keys:\n        \
         - kid: buyer-1\n          \
         public_key: \"DXVQdU4IAKXSN-71gmA1dmubPloVhoqUCrKJlYeI47A\"\n"
    )
}

#[test]
fn one_olp_tier_compiles() {
    let yaml = config_with_comp(&comp_block(&tier("tier_snippets", "olp")));
    compile_config(&yaml).expect("a single-OLP-tier catalog is the supported shape");
}

#[test]
fn an_olp_tier_beside_cap_and_public_tiers_compiles() {
    // Only the OLP ones are ambiguous. A catalog advertising free and
    // CAP tiers alongside its one redeemable tier is the shipped
    // example's shape and must keep compiling.
    let tiers = format!(
        "{}{}{}",
        tier("tier_free", "public"),
        tier("tier_search", "cap"),
        tier("tier_snippets", "olp")
    );
    let yaml = config_with_comp(&comp_block(&tiers));
    compile_config(&yaml).expect("cap and public tiers are not ambiguous");
}

#[test]
fn a_second_olp_tier_is_refused_because_redeem_cannot_tell_them_apart() {
    // The failure this prevents: a buyer quotes the $0.0025 tier,
    // redeems with a correct acceptance hash, and receives the license
    // and route glob of whichever OLP tier the manifest lists first.
    let tiers = format!(
        "{}{}",
        tier("tier_bulk_archive", "olp"),
        tier("tier_snippets", "olp")
    );
    let yaml = config_with_comp(&comp_block(&tiers));
    let Err(error) = compile_config(&yaml) else {
        panic!("a catalog with two OLP tiers must not compile");
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("authorization: olp"),
        "the refusal must name the field: {message}"
    );
    assert!(
        message.contains("tier_bulk_archive") && message.contains("tier_snippets"),
        "the refusal must name both tiers so the operator knows which to remove: {message}"
    );
}

#[test]
fn a_catalog_with_no_olp_tier_is_still_refused() {
    // The pre-existing half of the same invariant: `redeem` can only
    // mint for an OLP tier, so zero of them is an endpoint that refuses
    // everything it is given.
    let yaml = config_with_comp(&comp_block(&tier("tier_search", "cap")));
    let Err(error) = compile_config(&yaml) else {
        panic!("a catalog with no OLP tier must not compile");
    };
    assert!(
        format!("{error:#}").contains("authorization: olp"),
        "{error:#}"
    );
}
