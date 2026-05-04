//! End-to-end test for the `storage` action.
//!
//! Builds a temporary directory of static assets, points the
//! `local` storage backend at it, and walks the documented curl
//! invocations from `examples/98-storage-action/sb.yml`.

use std::io::Write;

use sbproxy_e2e::ProxyHarness;

fn config_yaml(asset_dir: &str) -> String {
    format!(
        r#"
proxy:
  http_bind_port: 0  # overridden by the harness
origins:
  "static.localhost":
    action:
      type: storage
      backend: local
      path: {dir}
      index_file: index.html
"#,
        dir = asset_dir
    )
}

fn write_assets() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let mut idx = std::fs::File::create(dir.path().join("index.html")).unwrap();
    idx.write_all(b"<h1>hello from storage</h1>").unwrap();
    let mut css = std::fs::File::create(dir.path().join("site.css")).unwrap();
    css.write_all(b"body { background: #eee; }").unwrap();
    dir
}

#[test]
fn directory_request_serves_index_file() {
    let assets = write_assets();
    let yaml = config_yaml(assets.path().to_str().unwrap());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/", "static.localhost").expect("GET /");
    assert_eq!(resp.status, 200);
    assert!(resp.text().unwrap().contains("hello from storage"));
    assert_eq!(
        resp.headers.get("content-type").map(|s| s.as_str()),
        Some("text/html; charset=utf-8")
    );
}

#[test]
fn css_file_returns_correct_content_type() {
    let assets = write_assets();
    let yaml = config_yaml(assets.path().to_str().unwrap());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/site.css", "static.localhost").expect("GET css");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text().unwrap(), "body { background: #eee; }");
    assert_eq!(
        resp.headers.get("content-type").map(|s| s.as_str()),
        Some("text/css; charset=utf-8")
    );
}

#[test]
fn missing_object_returns_404() {
    let assets = write_assets();
    let yaml = config_yaml(assets.path().to_str().unwrap());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy.get("/nope", "static.localhost").expect("GET miss");
    assert_eq!(resp.status, 404);
}

#[test]
fn range_request_returns_206_with_content_range() {
    let assets = write_assets();
    let yaml = config_yaml(assets.path().to_str().unwrap());
    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");

    let resp = proxy
        .get_with_headers("/site.css", "static.localhost", &[("range", "bytes=0-3")])
        .expect("range get");
    assert_eq!(resp.status, 206);
    assert_eq!(resp.text().unwrap(), "body");
    let range_header = resp
        .headers
        .get("content-range")
        .map(String::as_str)
        .unwrap_or("");
    assert!(
        range_header.starts_with("bytes 0-3/"),
        "expected content-range to start with `bytes 0-3/`, got: {range_header:?}"
    );
}
