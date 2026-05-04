//! End-to-end tests for the WASM transform.
//!
//! Loads the checked-in echo module (the same fixture the unit tests
//! use), wires it to a `static` origin via a `wasm` transform, and
//! verifies the body comes back unchanged. Exercises the full
//! response-body pipeline: buffering, transform dispatch, WASI
//! stdin/stdout round-trip, content-length rewrite.

use std::io::Write;
use tempfile::NamedTempFile;

use sbproxy_e2e::ProxyHarness;

/// The echo wasm module embedded by the extension crate's unit tests.
/// We re-embed here rather than reading from disk so the e2e test
/// works regardless of cwd or build profile.
const ECHO_WASM: &[u8] =
    include_bytes!("../../crates/sbproxy-extension/src/wasm/testdata/echo.wasm");

#[test]
fn wasm_transform_round_trips_body_through_module() {
    // Materialise the module to a temp .wasm file the proxy can load.
    let mut module_file = NamedTempFile::new().expect("create temp wasm file");
    module_file
        .write_all(ECHO_WASM)
        .expect("write wasm bytes to temp file");
    module_file.flush().expect("flush temp wasm file");
    let module_path = module_file.path().to_path_buf();

    let yaml = format!(
        r#"
proxy:
  http_bind_port: 0
origins:
  "wasm.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "hello from sbproxy"
    transforms:
      - type: wasm
        module_path: "{}"
        timeout_ms: 1000
        max_memory_pages: 64
"#,
        module_path.display()
    );

    let proxy = ProxyHarness::start_with_yaml(&yaml).expect("start proxy");
    let resp = proxy.get("/", "wasm.localhost").expect("GET /");
    assert_eq!(resp.status, 200);
    let body = resp.text().expect("decode body");
    assert_eq!(
        body, "hello from sbproxy",
        "echo wasm module should not modify the body"
    );
}

#[test]
fn wasm_transform_with_missing_module_path_fails_to_start() {
    // A wasm transform pointing at a non-existent module is a
    // configuration error: the runtime should fail to compile and
    // surface it at startup rather than at first request.
    let yaml = r#"
proxy:
  http_bind_port: 0
origins:
  "wasm.localhost":
    action:
      type: static
      status_code: 200
      content_type: text/plain
      body: "ok"
    transforms:
      - type: wasm
        module_path: "/this/path/does/not/exist.wasm"
        timeout_ms: 500
"#;
    // start_with_yaml waits for the proxy to bind; if the config is
    // rejected the binary exits and the bind never happens.
    let result = ProxyHarness::start_with_yaml(yaml);
    assert!(
        result.is_err(),
        "expected proxy startup to fail with bogus module_path"
    );
}
