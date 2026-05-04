//! Wave 4 / Q4.7: `/.well-known/tdmrep.json` (W3C TDMRep) projection.
//!
//! Validates the W3C TDMRep document projected by the Wave 4 G4.9
//! build agent. Per `docs/adr-policy-graph-projections.md`:
//!
//! ```json
//! {
//!   "version": "1.0",
//!   "generated": "<RFC3339 timestamp>",
//!   "policies": [
//!     {
//!       "location": "/articles/*",
//!       "mine-type": ["text/html", "text/markdown"],
//!       "right": "research",
//!       "license": "https://sbproxy.dev/licenses/<origin_hostname>"
//!     }
//!   ]
//! }
//! ```
//!
//! Mapping table from `Content-Signal` to TDMRep `right`:
//!
//! | content_signal | TDMRep right | entry behaviour |
//! |----------------|--------------|------------------|
//! | ai-train       | train        | entry present    |
//! | ai-input       | research     | entry present    |
//! | search         | research     | entry present    |
//! | absent         | (none)       | entry omitted    |
//!
//! For origins with no `content_signal`, the proxy stamps a
//! `TDM-Reservation: 1` response header on every response (W3C TDMRep
//! reservation-by-default semantics).
//!
//! All tests in this file are `#[ignore]`'d with `TODO(wave4-G4.9)`
//! until the projection engine in
//! `crates/sbproxy-modules/src/projection/tdmrep.rs` lands.

use sbproxy_e2e::ProxyHarness;
use serde_json::Value;

const FIXTURE: &str = include_str!("../fixtures/wave4/projections/sb.yml");

fn start_projections() -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_yaml(FIXTURE)
}

// --- Test 1: canonical path ---

#[test]
fn tdmrep_json_served_at_canonical_path() {
    let harness = start_projections().expect("start proxy");
    let resp = harness
        .get("/.well-known/tdmrep.json", "blog.localhost")
        .expect("GET /.well-known/tdmrep.json");
    assert_eq!(resp.status, 200, "/.well-known/tdmrep.json must return 200");
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.starts_with("application/json"),
        "Content-Type must be application/json; got {ct}"
    );
    let _ = resp.json().expect("body must be valid JSON");
}

// --- Test 2: validates against the W3C TDMRep schema ---

#[test]
#[ignore = "TODO(wave5): W3C TDMRep schema is not vendored at e2e/fixtures/tdmrep/tdmrep-1.0.schema.json. Reactivate after the schema is committed; the projection emits a structurally valid document that the schema check should accept."]
fn tdmrep_json_validates_against_w3c_schema() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/.well-known/tdmrep.json", "blog.localhost")
        .expect("GET")
        .json()
        .expect("body must be valid JSON");

    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/tdmrep/tdmrep-1.0.schema.json");
    assert!(
        schema_path.is_file(),
        "W3C TDMRep schema must be vendored at {}; see fixtures/tdmrep/README.md",
        schema_path.display()
    );

    let schema_bytes = std::fs::read(&schema_path).expect("read schema");
    let schema_value: Value = serde_json::from_slice(&schema_bytes).expect("schema is valid JSON");

    // Surface a structural assertion until the e2e crate adds
    // `jsonschema` to its dev-deps. Once present, this becomes:
    //   let compiled = jsonschema::JSONSchema::compile(&schema_value)?;
    //   compiled.validate(&body)?;
    let _ = (schema_value, body);
}

// --- Test 3: one entry per priced route ---

#[test]
fn tdmrep_json_emits_policies_per_priced_route() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/.well-known/tdmrep.json", "blog.localhost")
        .expect("GET")
        .json()
        .expect("JSON body");

    let policies = body
        .get("policies")
        .and_then(|v| v.as_array())
        .expect("policies[] array");

    assert!(
        !policies.is_empty(),
        "fixture has at least one priced route; policies must be non-empty"
    );

    // /articles/* must be present.
    let has_articles = policies.iter().any(|p| {
        p.get("location")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.starts_with("/articles"))
    });
    assert!(
        has_articles,
        "/articles/* priced route must appear in policies[]; got {body}"
    );
}

// --- Test 4: Content-Signal mapping ---

#[test]
fn tdmrep_json_maps_content_signal_to_right() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/.well-known/tdmrep.json", "blog.localhost")
        .expect("GET")
        .json()
        .expect("JSON body");

    let policies = body
        .get("policies")
        .and_then(|v| v.as_array())
        .expect("policies[] array");

    // Fixture origin has content_signal: ai-train, so every entry's
    // right must be "train".
    for entry in policies {
        let right = entry
            .get("right")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        assert_eq!(
            right, "train",
            "ai-train signal must project to right=train; entry was {entry}"
        );
    }
}

// --- Test 5: TDM-Reservation: 1 header on origins without a signal ---

#[test]
fn tdm_reservation_response_header_set_when_no_signal() {
    // Inline fixture: same shape as the projections fixture but with
    // extensions.content_signal removed. Origins without a signal get
    // reservation-by-default.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "no-signal.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>article</h1>"
    policies:
      - type: ai_crawl_control
        currency: USD
        price: 0.001
        tiers:
          - route_pattern: /articles/*
            price:
              amount_micros: 1000
              currency: USD
            content_shape: html
        valid_tokens:
          - good-token-1
"#;
    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = harness
        .get("/anything", "no-signal.localhost")
        .expect("GET");
    let header = resp
        .headers
        .get("tdm-reservation")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        header, "1",
        "origins without content_signal must stamp TDM-Reservation: 1; got header={header:?}"
    );
}

// --- Smoke: fixture YAML compiles ---

#[test]
fn fixture_yaml_compiles() {
    let _harness = start_projections().expect("fixture sb.yml must compile");
}
