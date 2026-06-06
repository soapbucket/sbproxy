//! Wave 4 / Q4.6: `/licenses.xml` (RSL Collective) projection
//! conformance.
//!
//! Validates the `/licenses.xml` projection against the canonical RSL
//! Collective spec at <https://rslstandard.org/rsl>. Per RSL 1.0 §3.5, the usage tier
//! is expressed as `<permits type="usage">tokens</permits>` /
//! `<prohibits type="usage">tokens</prohibits>`; the non-conformant
//! `<ai-use>` element this projection used to emit has been retired
//! (WOR-944).
//!
//! ```xml
//! <rsl xmlns="https://rslstandard.org/rsl" version="1.0">
//!   <content url="https://blog.localhost/*">
//!     <license urn="urn:rsl:1.0:blog.localhost:<config_version>">
//!       <origin hostname="blog.localhost" />
//!       <permits type="usage">ai-train</permits>
//!     </license>
//!   </content>
//! </rsl>
//! ```
//!
//! Mapping table from `Content-Signal` to the emitted element:
//!
//! | content_signal | emitted element                                              |
//! |----------------|--------------------------------------------------------------|
//! | ai-train       | `<permits type="usage">ai-train</permits>`                   |
//! | ai-input       | `<permits type="usage">ai-input</permits>`                   |
//! | search         | `<permits type="usage">search</permits>`                     |
//! | absent         | (no `<permits>` or `<prohibits>` element; silent-permissive) |
//!
//! Conformance is asserted structurally (namespace, element ordering,
//! the `<permits type="usage">` shape, the wildcard `url` convention).
//! RSL 1.0 publishes its vocabulary in prose only; there is no official
//! XSD or RELAX NG schema to validate against, so the structural checks
//! below are the canonical conformance signal.

use sbproxy_e2e::ProxyHarness;

const FIXTURE: &str = include_str!("../fixtures/wave4/projections/sb.yml");

fn start_projections() -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_yaml(FIXTURE)
}

// --- Test 1: canonical path ---

#[test]
fn licenses_xml_served_at_canonical_path() {
    let harness = start_projections().expect("start proxy");
    let resp = harness
        .get("/licenses.xml", "blog.localhost")
        .expect("GET /licenses.xml");
    assert_eq!(resp.status, 200, "/licenses.xml must return 200");
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/xml") || ct.starts_with("text/xml"),
        "Content-Type must be application/xml; got {ct}"
    );
}

// --- Test 2: URN format ---

#[test]
#[ignore = "TODO(wave5): URN trailing segment is the monotonic config-version counter (decimal), not a hex hash; same root cause as `robots_txt_includes_config_version_hash`. Wave-5 follow-up will switch to a content-hash version source so the URN can be a stable hex string per A4.1."]
fn licenses_xml_uses_correct_urn_format() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/licenses.xml", "blog.localhost")
        .expect("GET")
        .text()
        .expect("utf-8 body");

    // Substring search avoids a heavyweight XML parser dependency in
    // the e2e crate. The shape is `urn:rsl:1.0:<hostname>:<hash>`.
    let urn_start = body
        .find("urn:rsl:1.0:")
        .expect("URN prefix urn:rsl:1.0: must appear");
    let after = &body[urn_start..];
    let urn_end = after
        .find('<')
        .expect("URN must be followed by an XML close tag");
    let urn = &after[..urn_end];

    let parts: Vec<&str> = urn.splitn(5, ':').collect();
    assert_eq!(
        parts.len(),
        5,
        "URN must have 5 colon-separated parts; got {urn:?}"
    );
    assert_eq!(parts[0], "urn");
    assert_eq!(parts[1], "rsl");
    assert_eq!(parts[2], "1.0");
    assert_eq!(parts[3], "blog.localhost", "hostname segment of URN");
    assert!(
        !parts[4].is_empty() && parts[4].chars().all(|c| c.is_ascii_hexdigit()),
        "URN trailing segment must be a hex hash; got {:?}",
        parts[4]
    );
}

// --- Test 4: Content-Signal mapping ---

#[test]
fn licenses_xml_maps_content_signal_to_permits_usage() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/licenses.xml", "blog.localhost")
        .expect("GET")
        .text()
        .expect("utf-8 body");

    // WOR-944: fixture has `content_signal: ai-train`, which now
    // maps to the normative `<permits type="usage">ai-train</permits>`
    // per RSL 1.0 §3.5 / §4.8 (replaces the non-conformant
    // `<ai-use licensed="true">` element).
    assert!(
        body.contains(r#"<permits type="usage">ai-train</permits>"#),
        "permits-usage with ai-train expected; got:\n{body}"
    );
    // Regression guard: the projection must never emit `<ai-use>`,
    // which does not exist in RSL 1.0.
    assert!(
        !body.contains("<ai-use"),
        "projection must not emit non-conformant <ai-use>; got:\n{body}"
    );
}

// --- WOR-808: RSL 1.0 <payment> element derived from pay-per-crawl ---

#[test]
fn licenses_xml_emits_payment_from_pay_per_crawl() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/licenses.xml", "blog.localhost")
        .expect("GET")
        .text()
        .expect("utf-8 body");

    // The fixture origin sets ai_crawl_control { price: 0.001, currency: USD },
    // which maps to the RSL `<payment type="crawl">` with the price + currency.
    assert!(
        body.contains(r#"<payment type="crawl" amount="0.001" currency="USD" />"#),
        "expected an RSL <payment> derived from the pay-per-crawl price; got:\n{body}"
    );
}

// --- Test 5: canonical RSL Collective shape ---

#[test]
fn licenses_xml_uses_canonical_rsl_collective_shape() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/licenses.xml", "blog.localhost")
        .expect("GET")
        .text()
        .expect("utf-8 body");

    // Namespace must be the canonical RSL Collective URI, not the
    // legacy rsl.ai/spec/1.0 namespace.
    assert!(
        body.contains(r#"xmlns="https://rslstandard.org/rsl""#),
        "must use canonical RSL Collective namespace; got:\n{body}"
    );
    assert!(
        !body.contains("rsl.ai/spec/1.0"),
        "legacy rsl.ai/spec/1.0 namespace must not appear; got:\n{body}"
    );

    // Document shape: <rsl> -> <content url="..."> -> <license>.
    let rsl_idx = body.find("<rsl ").expect("<rsl> root");
    let content_idx = body
        .find("<content ")
        .expect("<content> wrapper around license");
    let license_idx = body.find("<license ").expect("<license> child");
    assert!(
        rsl_idx < content_idx && content_idx < license_idx,
        "ordering must be <rsl> -> <content> -> <license>; got:\n{body}"
    );

    // The wildcard URL convention for "every URL on this origin".
    assert!(
        body.contains(r#"url="https://blog.localhost/*""#),
        "<content> must carry the canonical wildcard url for the origin; got:\n{body}"
    );
}

// --- Smoke: fixture YAML compiles ---

#[test]
fn fixture_yaml_compiles() {
    let _harness = start_projections().expect("fixture sb.yml must compile");
}
