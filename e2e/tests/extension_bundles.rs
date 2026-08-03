//! End-to-end coverage for pipeline-local extension bundle reloads.

use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

use sbproxy_e2e::ProxyHarness;

const MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: reload-action
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: reload_action
    export: run
"#;

fn action_source(body: &str) -> String {
    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, body.as_bytes());
    format!(
        r#"export function run() {{
            return {{
                version: "sbproxy-envelope/v1",
                outcome: "response",
                status: 200,
                headers: [["content-type", "text/plain"]],
                body_base64: "{encoded}"
            }};
        }}
"#
    )
}

fn pick_admin_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral admin port")
        .local_addr()
        .expect("read admin address")
        .port()
}

fn config(admin_port: u16) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
  admin:
    enabled: true
    port: {admin_port}
    username: admin
    password: secret
extensions:
  bundles_dir: bundles
origins:
  extension.localhost:
    action:
      type: reload_action
"#
    )
}

fn post_reload(admin_port: u16) -> (u16, String) {
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build admin client")
        .post(format!("http://127.0.0.1:{admin_port}/admin/reload"))
        .header("authorization", "Basic YWRtaW46c2VjcmV0")
        .send()
        .expect("post admin reload");
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    (status, body)
}

fn write_entry(config_path: &Path, source: &str) {
    let entry = config_path
        .parent()
        .expect("workspace config has a parent")
        .join("bundles/reload-action/entry.js");
    std::fs::write(entry, source).expect("replace bundle entry");
}

#[test]
fn extension_bundle_reload_publishes_one_complete_generation() {
    let admin_port = pick_admin_port();
    let first_source = action_source("generation one");
    let files = [
        ("bundles/reload-action/bundle.yaml", MANIFEST),
        ("bundles/reload-action/entry.js", first_source.as_str()),
    ];
    let proxy =
        ProxyHarness::start_with_workspace(&config(admin_port), &files).expect("start proxy");
    ProxyHarness::wait_for_port(admin_port, Duration::from_secs(5))
        .expect("admin port should bind");

    let first = proxy
        .get("/", "extension.localhost")
        .expect("request first generation");
    assert_eq!(first.status, 200);
    assert_eq!(first.text().expect("first response text"), "generation one");

    write_entry(&proxy.config_path(), &action_source("generation two"));
    let (status, body) = post_reload(admin_port);
    assert_eq!(status, 200, "reload failed: {body}");
    let second = proxy
        .get("/", "extension.localhost")
        .expect("request second generation");
    assert_eq!(second.status, 200);
    assert_eq!(
        second.text().expect("second response text"),
        "generation two"
    );

    write_entry(
        &proxy.config_path(),
        "export function missingExpectedExport() {}",
    );
    let (status, body) = post_reload(admin_port);
    assert_eq!(status, 500, "invalid candidate response: {body}");
    assert!(body.contains("reload failed"), "{body}");
    let after_failure = proxy
        .get("/", "extension.localhost")
        .expect("request after rejected generation");
    assert_eq!(after_failure.status, 200);
    assert_eq!(
        after_failure.text().expect("last-good response text"),
        "generation two"
    );
}
