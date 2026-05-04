//! End-to-end coverage for HTML and Markdown response transforms.
//!
//! Covers:
//! * `html`              - remove selectors, inject snippets, rewrite attrs.
//! * `optimize_html`     - strip comments and collapse whitespace.
//! * `html_to_markdown`  - convert an HTML page into Markdown.
//! * `markdown`          - convert Markdown into HTML (with GFM extensions).
//!
//! Each test uses a self-contained `static` action so the suite
//! does not depend on any external upstream.

use sbproxy_e2e::ProxyHarness;

// --- html: inject + remove + rewrite ---

#[test]
fn html_transform_injects_removes_and_rewrites_attributes() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "html.local":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: |
        <html>
          <head><title>Original</title></head>
          <body>
            <h1>Headline to remove</h1>
            <p target="_self">paragraph one</p>
            <p target="_self">paragraph two</p>
          </body>
        </html>
    transforms:
      - type: html
        remove_selectors:
          - h1
        inject:
          - position: head_end
            content: '<link rel="stylesheet" href="/sb.css">'
          - position: body_start
            content: '<div id="sb-banner">Served via sbproxy</div>'
        rewrite_attributes:
          - selector: p
            attribute: target
            value: "_blank"
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "html.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    assert!(
        !body.contains("<h1>"),
        "h1 should be removed by the selector: {}",
        body
    );
    assert!(
        body.contains(r#"<link rel="stylesheet" href="/sb.css">"#),
        "stylesheet link should be injected at head_end: {}",
        body
    );
    assert!(
        body.contains(r#"<div id="sb-banner">Served via sbproxy</div>"#),
        "banner should be injected at body_start: {}",
        body
    );
    assert!(
        body.contains(r#"target="_blank""#),
        "target attribute should be rewritten to _blank: {}",
        body
    );
    assert!(
        !body.contains(r#"target="_self""#),
        "old target value should be replaced: {}",
        body
    );
}

// --- optimize_html: comments stripped, whitespace collapsed ---

#[test]
fn optimize_html_strips_comments_and_collapses_whitespace() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "opt.local":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: "<html><body>  <!-- inline comment -->  <p>  hello   world  </p>  </body></html>"
    transforms:
      - type: optimize_html
        remove_comments: true
        collapse_whitespace: true
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "opt.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    assert!(
        !body.contains("<!--"),
        "comments should be stripped: {}",
        body
    );
    assert!(
        !body.contains("  "),
        "double spaces should be collapsed: {}",
        body
    );
    assert!(body.contains("hello"));
    assert!(body.contains("world"));
}

// --- html_to_markdown: produces atx headings and link syntax ---

#[test]
fn html_to_markdown_converts_basic_elements_to_atx_markdown() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "tomd.local":
    action:
      type: static
      status_code: 200
      content_type: text/html
      body: |
        <h1>Title</h1>
        <p>Click <a href="https://example.com">here</a> for <strong>info</strong>.</p>
    transforms:
      - type: html_to_markdown
        heading_style: atx
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "tomd.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    assert!(
        body.contains("# Title"),
        "atx h1 should be present: {}",
        body
    );
    assert!(
        body.contains("[here](https://example.com)"),
        "link should be in markdown form: {}",
        body
    );
    assert!(
        body.contains("**info**"),
        "strong should become **info**: {}",
        body
    );
    assert!(!body.contains("<h1>"), "raw HTML should be gone: {}", body);
}

// --- markdown: GFM tables + strikethrough ---

#[test]
fn markdown_transform_renders_html_with_tables_and_strikethrough() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "md.local":
    action:
      type: static
      status_code: 200
      content_type: text/markdown
      body: |
        # Release notes

        - Faster startup
        - ~~Buggy retries~~ Retries now respect the budget

        | Type | Body shape |
        |------|------------|
        | json | object     |
        | html | text       |
    transforms:
      - type: markdown
        smart_punctuation: true
        tables: true
        strikethrough: true
    response_modifiers:
      - headers:
          set:
            Content-Type: text/html; charset=utf-8
"#;
    let proxy = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let resp = proxy.get("/", "md.local").expect("GET");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("utf8 body");

    assert!(
        body.contains("<h1>Release notes</h1>"),
        "h1 should be rendered from markdown: {}",
        body
    );
    assert!(
        body.contains("<table>") && body.contains("<td>json</td>"),
        "GFM table should render with rows: {}",
        body
    );
    assert!(
        body.contains("<del>Buggy retries</del>"),
        "strikethrough should render as <del>: {}",
        body
    );
    let ct = resp
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.contains("text/html"),
        "content-type override should land in the response: {}",
        ct
    );
}
