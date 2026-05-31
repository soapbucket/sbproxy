//! WOR-808 two-license-tier vocabulary e2e: a single origin
//! declaring `ai_crawl_control.license_tiers` projects multiple
//! `<license>` elements under one `<content>`, each priced
//! independently and carrying its own URN fragment.
//!
//! Mirrors the TollBit marketplace model where a buyer picks the
//! cheap tier for snippets and the expensive tier for full-page
//! reuse.

use sbproxy_e2e::ProxyHarness;

const FIXTURE: &str = include_str!("../fixtures/wave4/license-tiers/sb.yml");

fn start_tiered() -> ProxyHarness {
    ProxyHarness::start_with_yaml(FIXTURE).expect("start proxy with license-tiers fixture")
}

#[test]
fn licenses_xml_emits_one_license_per_declared_tier() {
    let harness = start_tiered();
    let resp = harness
        .get("/licenses.xml", "tiered.localhost")
        .expect("GET /licenses.xml");
    assert_eq!(resp.status, 200);
    let body = String::from_utf8_lossy(&resp.body);
    // One <content> wraps both tiers (the marketplace gets the whole
    // tier set in one round-trip).
    assert_eq!(
        body.matches("<content ").count(),
        1,
        "should be one <content> element; body:\n{body}"
    );
    assert_eq!(
        body.matches("<license ").count(),
        2,
        "should be one <license> element per tier; body:\n{body}"
    );
}

#[test]
fn licenses_xml_tier_urns_carry_fragments() {
    let harness = start_tiered();
    let body = harness
        .get("/licenses.xml", "tiered.localhost")
        .expect("GET")
        .body;
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains(r#"urn="urn:rsl:1.0:tiered.localhost:"#),
        "primary URN prefix missing; body:\n{body}"
    );
    assert!(
        body.contains("#summarize\""),
        "summarize tier URN fragment missing; body:\n{body}"
    );
    assert!(
        body.contains("#full-display\""),
        "full-display tier URN fragment missing; body:\n{body}"
    );
}

#[test]
fn licenses_xml_per_tier_payment_amounts_render_independently() {
    let harness = start_tiered();
    let body = harness
        .get("/licenses.xml", "tiered.localhost")
        .expect("GET")
        .body;
    let body = String::from_utf8_lossy(&body);
    // Each tier carries its own <payment> with the declared amount.
    assert!(
        body.contains(r#"amount="0.002""#),
        "summarize tier price missing; body:\n{body}"
    );
    assert!(
        body.contains(r#"amount="0.01""#),
        "full-display tier price missing; body:\n{body}"
    );
}

#[test]
fn licenses_xml_per_tier_signals_render_inside_their_own_license() {
    let harness = start_tiered();
    let body = harness
        .get("/licenses.xml", "tiered.localhost")
        .expect("GET")
        .body;
    let body = String::from_utf8_lossy(&body);
    // Split the body at the first </license> close. The first half
    // is the summarize tier's body; the second half is the
    // full-display tier's body.
    let first_close = body.find("</license>").expect("first close");
    let first_body = &body[..first_close];
    let after_first = &body[first_close + "</license>".len()..];
    let second_open = after_first.find("<license ").expect("second open");
    let second_body = &after_first[second_open..];
    // Summarize tier permits search + ai-input but NOT ai-train.
    assert!(
        first_body.contains("search ai-input"),
        "summarize body missing usage permits; body:\n{first_body}"
    );
    assert!(
        !first_body.contains("ai-train"),
        "summarize body must not contain ai-train; body:\n{first_body}"
    );
    // Full-display tier permits all three including ai-train.
    assert!(
        second_body.contains("search ai-input ai-train"),
        "full-display body missing ai-train; body:\n{second_body}"
    );
}
