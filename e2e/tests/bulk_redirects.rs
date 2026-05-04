//! Bulk redirects (F1.4).
//!
//! Each origin owns its own redirect list. The harness writes a tiny
//! CSV alongside the temp config, points an origin at it via the
//! `bulk_list` source, and asserts the redirect verbs work end to
//! end including per-row status codes and the fallback url.

use sbproxy_e2e::ProxyHarness;
use std::io::Write;

#[test]
fn file_backed_csv_serves_redirects_with_per_row_status() {
    let mut csv = tempfile::Builder::new()
        .suffix(".csv")
        .tempfile()
        .expect("temp csv");
    writeln!(csv, "from,to,status").unwrap();
    writeln!(csv, "/old/about,/about,301").unwrap();
    writeln!(csv, "/old/help,/help").unwrap();
    csv.flush().unwrap();

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "marketing.local":
    action:
      type: redirect
      status_code: 302
      bulk_list:
        type: file
        path: {path}
"#,
        path = csv.path().display()
    );

    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // Mapped path with explicit status: 301 -> /about
    let resp = client
        .get(format!("{}/old/about", harness.base_url()))
        .header("host", "marketing.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 301);
    assert_eq!(resp.headers().get("location").unwrap(), "/about");

    // Mapped path falling through to the action's default status (302)
    let resp = client
        .get(format!("{}/old/help", harness.base_url()))
        .header("host", "marketing.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(resp.headers().get("location").unwrap(), "/help");

    // Unmapped path with no fallback url returns 404.
    let resp = client
        .get(format!("{}/never-defined", harness.base_url()))
        .header("host", "marketing.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

#[test]
fn inline_bulk_list_supports_per_row_overrides_and_fallback_url() {
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "shop.local":
    action:
      type: redirect
      status_code: 302
      url: https://shop.example.com/
      bulk_list:
        type: inline
        rows:
          - from: /category/legacy
            to: /category/2024
            status: 308
          - from: /docs/v1
            to: https://docs.example.com/v2
"#;

    let harness = ProxyHarness::start_with_yaml(yaml).expect("start proxy");
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // Per-row status override.
    let resp = client
        .get(format!("{}/category/legacy", harness.base_url()))
        .header("host", "shop.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 308);
    assert_eq!(resp.headers().get("location").unwrap(), "/category/2024");

    // Cross-host redirect.
    let resp = client
        .get(format!("{}/docs/v1", harness.base_url()))
        .header("host", "shop.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://docs.example.com/v2"
    );

    // Unmapped path falls through to the action's `url:`.
    let resp = client
        .get(format!("{}/random/page", harness.base_url()))
        .header("host", "shop.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 302);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://shop.example.com/"
    );
}

#[test]
fn per_origin_lists_are_isolated() {
    let mut csv_a = tempfile::Builder::new().suffix(".csv").tempfile().unwrap();
    writeln!(csv_a, "/from-a,/dest-a,301").unwrap();
    csv_a.flush().unwrap();
    let mut csv_b = tempfile::Builder::new().suffix(".csv").tempfile().unwrap();
    writeln!(csv_b, "/from-b,/dest-b,301").unwrap();
    csv_b.flush().unwrap();

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "a.local":
    action:
      type: redirect
      status_code: 301
      bulk_list:
        type: file
        path: {a}
  "b.local":
    action:
      type: redirect
      status_code: 301
      bulk_list:
        type: file
        path: {b}
"#,
        a = csv_a.path().display(),
        b = csv_b.path().display()
    );

    let harness = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // Origin A's list does not leak into origin B.
    let resp = client
        .get(format!("{}/from-a", harness.base_url()))
        .header("host", "b.local")
        .send()
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "origin B must not match origin A's list"
    );

    let resp = client
        .get(format!("{}/from-a", harness.base_url()))
        .header("host", "a.local")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 301);
}
