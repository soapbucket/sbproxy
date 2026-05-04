//! Wave 4 / Q4.5: `/llms.txt` and `/llms-full.txt` projection conformance.
//!
//! Validates the Anthropic / Mistral convention projected by the
//! Wave 4 G4.7 build agent. Per `docs/adr-policy-graph-projections.md`:
//!
//! ```text
//! # sitename: blog.localhost
//! # version: <hash>
//! # payment: pay-per-request
//! # shapes: html, markdown
//!
//! <Markdown body listing priced routes>
//! ```
//!
//! Two endpoints:
//!   - `/llms.txt` is the concise summary; no per-route table.
//!   - `/llms-full.txt` includes the full priced-route table.
//!
//! All tests in this file are `#[ignore]`'d with a
//! `TODO(wave4-G4.7)` marker until the projection engine in
//! `crates/sbproxy-modules/src/projection/llms.rs` lands.

use sbproxy_e2e::ProxyHarness;

/// Static fixture body. Same shape as the robots.txt suite (see
/// `e2e/fixtures/wave4/projections/sb.yml`).
const FIXTURE: &str = include_str!("../fixtures/wave4/projections/sb.yml");

fn start_projections() -> anyhow::Result<ProxyHarness> {
    ProxyHarness::start_with_yaml(FIXTURE)
}

// --- Test 1: /llms.txt canonical path ---

#[test]
fn llms_txt_served_at_canonical_path() {
    let harness = start_projections().expect("start proxy");
    let resp = harness
        .get("/llms.txt", "blog.localhost")
        .expect("GET /llms.txt");
    assert_eq!(resp.status, 200, "/llms.txt must return 200");
}

// --- Test 2: /llms-full.txt canonical path ---

#[test]
fn llms_full_txt_served_at_canonical_path() {
    let harness = start_projections().expect("start proxy");
    let resp = harness
        .get("/llms-full.txt", "blog.localhost")
        .expect("GET /llms-full.txt");
    assert_eq!(resp.status, 200, "/llms-full.txt must return 200");
}

// --- Test 3: header includes sitename, version, payment, shapes ---

#[test]
fn llms_txt_header_includes_sitename_version_payment_shapes() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/llms.txt", "blog.localhost")
        .expect("GET")
        .text()
        .expect("utf-8 body");

    for header in ["# sitename:", "# version:", "# payment:", "# shapes:"] {
        assert!(
            body.contains(header),
            "llms.txt header missing {header:?}; got:\n{body}"
        );
    }

    // sitename must be the origin hostname.
    assert!(
        body.lines()
            .any(|l| l.starts_with("# sitename:") && l.contains("blog.localhost")),
        "# sitename: must point at blog.localhost; got:\n{body}"
    );

    // shapes must list at least html and markdown (fixture covers both).
    let shapes_line = body
        .lines()
        .find(|l| l.starts_with("# shapes:"))
        .expect("# shapes: line present");
    assert!(
        shapes_line.contains("html") && shapes_line.contains("markdown"),
        "# shapes: must list html and markdown; got {shapes_line:?}"
    );
}

// --- Test 4: priced-route listing in /llms-full.txt only ---

#[test]
fn llms_full_txt_includes_priced_route_listing() {
    let harness = start_projections().expect("start proxy");

    let summary = harness
        .get("/llms.txt", "blog.localhost")
        .expect("GET summary")
        .text()
        .expect("utf-8 body");
    let full = harness
        .get("/llms-full.txt", "blog.localhost")
        .expect("GET full")
        .text()
        .expect("utf-8 body");

    // Full version must enumerate priced routes; the fixture has /articles/*.
    assert!(
        full.contains("/articles/"),
        "/llms-full.txt must list /articles/* priced route; got:\n{full}"
    );

    // Summary should NOT include the per-route pricing detail (it
    // surfaces only the aggregate `# payment:` line).
    assert!(
        !summary.contains("amount_micros") && !summary.contains("/articles/*"),
        "/llms.txt summary must not embed the per-route price table; got:\n{summary}"
    );
}

// --- Test 5: snapshot equality against policy-graph source of truth ---

#[test]
fn llms_txt_matches_policy_graph_source_of_truth() {
    let harness = start_projections().expect("start proxy");
    let body = harness
        .get("/llms.txt", "blog.localhost")
        .expect("GET")
        .text()
        .expect("utf-8 body");

    // Inline string comparison: the leading four header lines are the
    // deterministic part. The first line is fixed; later lines depend
    // on config-version hash so we only assert structural equality.
    let lines: Vec<&str> = body.lines().take(4).collect();
    assert_eq!(lines.len(), 4, "header block must have 4 lines");
    assert!(
        lines[0].starts_with("# sitename: blog.localhost"),
        "line 1 = # sitename: blog.localhost; got {:?}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("# version:"),
        "line 2 = # version: <hash>; got {:?}",
        lines[1]
    );
    assert!(
        lines[2].starts_with("# payment:"),
        "line 3 = # payment: ...; got {:?}",
        lines[2]
    );
    assert!(
        lines[3].starts_with("# shapes:"),
        "line 4 = # shapes: ...; got {:?}",
        lines[3]
    );
}

// --- Smoke: fixture YAML compiles ---

#[test]
fn fixture_yaml_compiles() {
    let _harness = start_projections().expect("fixture sb.yml must compile");
}
