//! Agent-web emission: AGENTS.md + ai.txt (WOR-809).
//!
//! Verifies the two new well-known projections are served verbatim
//! from per-origin config, and that an origin which does not configure
//! them falls through to normal proxying (the path is not shadowed).
//!
//! The `Accept: text/markdown` content-negotiation criterion and
//! `/llms-full.txt` are exercised by the existing
//! `content_negotiation_e2e`, `x_markdown_tokens_e2e`, and
//! `llms_txt_projection_e2e` suites.

use sbproxy_e2e::ProxyHarness;

const CONFIG: &str = r#"
proxy:
  http_bind_port: 0
origins:
  "site.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>home</h1>"
    agents_md: |
      # AGENTS.md

      ## Build
      cargo build --workspace

      ## Test
      cargo test --workspace
    ai_txt: |
      # ai.txt (Spawning)
      User-Agent: *
      Disallow: /private
  "bare.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<h1>bare</h1>"
"#;

#[test]
fn agents_md_served_as_markdown() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness.get("/AGENTS.md", "site.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.contains("text/markdown"),
        "unexpected content-type: {ct}"
    );
    let body = String::from_utf8(resp.body).unwrap();
    assert!(body.contains("cargo build --workspace"), "got:\n{body}");
}

#[test]
fn ai_txt_served_as_plain_text() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness.get("/ai.txt", "site.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(ct.contains("text/plain"), "unexpected content-type: {ct}");
    let body = String::from_utf8(resp.body).unwrap();
    assert!(body.contains("Disallow: /private"), "got:\n{body}");
}

#[test]
fn unconfigured_agents_md_falls_through_to_origin() {
    // bare.localhost does not set agents_md: the request must reach the
    // origin (here a static action) rather than being 404'd or
    // shadowed by an empty projection.
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness.get("/AGENTS.md", "bare.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let body = String::from_utf8(resp.body).unwrap();
    assert!(
        body.contains("bare"),
        "must fall through to the origin body, got:\n{body}"
    );
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.contains("text/html"),
        "fell through should serve the origin's html, got ct: {ct}"
    );
}

#[test]
fn unconfigured_ai_txt_falls_through_to_origin() {
    let harness = ProxyHarness::start_with_yaml(CONFIG).expect("start proxy");
    let resp = harness.get("/ai.txt", "bare.localhost").expect("send");
    assert_eq!(resp.status, 200);
    let body = String::from_utf8(resp.body).unwrap();
    assert!(body.contains("bare"), "must fall through; got:\n{body}");
}
