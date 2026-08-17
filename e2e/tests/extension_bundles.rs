//! End-to-end coverage for pipeline-local extension bundle reloads.

use std::net::TcpListener;
use std::path::Path;
use std::time::Duration;

use sbproxy_e2e::{MockUpstream, ProxyHarness};

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

const BUFFERED_POLICY_MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: buffered-policy
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: inspect_buffered_body
    export: inspect
    execution:
      body_mode: buffered
failure_posture: closed
sandbox:
  max_buffer_bytes: 1048576
"#;

const BUFFERED_POLICY_SOURCE: &str = r#"export function inspect(input) {
    if (input.request.body_base64.length !== 349528) {
        return {
            version: "sbproxy-envelope/v1",
            decision: "deny",
            status: 422,
            message: `expected complete body, got ${input.request.body_base64.length}`
        };
    }
    return { version: "sbproxy-envelope/v1", decision: "allow" };
}
"#;

const NONE_POLICY_MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: none-policy
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: inspect_none_body
    export: inspect
    execution:
      body_mode: none
failure_posture: closed
"#;

const NONE_POLICY_SOURCE: &str = r#"export function inspect(input) {
    if (input.request.body_base64.length !== 0) {
        return {
            version: "sbproxy-envelope/v1",
            decision: "deny",
            status: 422,
            message: "none policy received body bytes"
        };
    }
    return { version: "sbproxy-envelope/v1", decision: "allow" };
}
"#;

const LIMITED_POLICY_SOURCE: &str = r#"export function inspect() {
    return { version: "sbproxy-envelope/v1", decision: "allow" };
}
"#;

const SKIPPED_POLICY_SOURCE: &str = r#"export function inspect() {
    return {
        version: "sbproxy-envelope/v1",
        decision: "deny",
        status: 418,
        message: "oversize open policy should have been skipped"
    };
}
"#;

fn limited_policy_manifest(name: &str, policy_type: &str, posture: &str) -> String {
    format!(
        r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: {name}
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: {policy_type}
    export: inspect
    execution:
      body_mode: buffered
failure_posture: {posture}
sandbox:
  max_buffer_bytes: 1024
"#
    )
}

fn proxy_policy_config(upstream: &MockUpstream, policy_type: &str) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
extensions:
  bundles_dir: bundles
origins:
  extension.localhost:
    action:
      type: proxy
      url: {}
    policies:
      - type: {policy_type}
"#,
        upstream.base_url()
    )
}

const ACTION_BODY_MODES_MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: action-body-modes
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: echo_buffered_action
    export: echo
    execution:
      body_mode: buffered
  - kind: action
    type: none_body_action
    export: none
    execution:
      body_mode: none
failure_posture: closed
sandbox:
  max_buffer_bytes: 1048576
"#;

const ACTION_BODY_MODES_SOURCE: &str = r#"export function echo(input) {
    return {
        version: "sbproxy-envelope/v1",
        outcome: "response",
        status: 200,
        headers: [["content-type", "application/octet-stream"]],
        body_base64: input.request.body_base64
    };
}

export function none(input) {
    const empty = input.request.body_base64.length === 0;
    return {
        version: "sbproxy-envelope/v1",
        outcome: "response",
        status: empty ? 200 : 422,
        headers: [["content-type", "text/plain"]],
        body_base64: empty ? "bm9uZQ==" : "Ym9keSB3YXMgbm90IGVtcHR5"
    };
}
"#;

const LIMITED_ACTION_MANIFEST: &str = r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: limited-action
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: action
    type: limited_buffered_action
    export: run
    execution:
      body_mode: buffered
failure_posture: closed
sandbox:
  max_buffer_bytes: 1024
"#;

const LIMITED_ACTION_SOURCE: &str = r#"export function run() {
    return {
        version: "sbproxy-envelope/v1",
        outcome: "response",
        status: 200,
        headers: [],
        body_base64: "cnVu"
    };
}
"#;

fn action_config(action_type: &str) -> String {
    format!(
        r#"proxy:
  http_bind_port: 0
extensions:
  bundles_dir: bundles
origins:
  extension.localhost:
    action:
      type: {action_type}
"#
    )
}

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
    // A candidate the operator submitted that does not compile is their
    // error, not the node's, so the reload endpoint answers 400 and names the
    // key at fault. It used to answer 500, which read as "the node broke"
    // for what is a typo in the submitted config.
    assert_eq!(status, 400, "invalid candidate response: {body}");
    assert!(
        body.contains("does not compile") && body.contains("bundle.javascript"),
        "the refusal must name what failed to compile: {body}"
    );
    let after_failure = proxy
        .get("/", "extension.localhost")
        .expect("request after rejected generation");
    assert_eq!(after_failure.status, 200);
    assert_eq!(
        after_failure.text().expect("last-good response text"),
        "generation two"
    );
}

#[test]
fn dynamic_buffered_policy_receives_complete_large_body() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let yaml = proxy_policy_config(&upstream, "inspect_buffered_body");
    let files = [
        (
            "bundles/buffered-policy/bundle.yaml",
            BUFFERED_POLICY_MANIFEST,
        ),
        ("bundles/buffered-policy/entry.js", BUFFERED_POLICY_SOURCE),
    ];
    let proxy = ProxyHarness::start_with_workspace(&yaml, &files).expect("start proxy");
    let body = (0..256 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            body.clone(),
            &[],
        )
        .expect("send large request");

    assert!(
        (200..300).contains(&response.status),
        "buffered policy should receive the complete body, got {}: {}",
        response.status,
        response.text().unwrap_or_default()
    );
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "upstream should receive one request");
    assert_eq!(
        captured[0].body, body,
        "upstream body should be replayed intact"
    );
}

#[test]
fn dynamic_none_policy_keeps_large_body_streaming_and_receives_empty_body() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let yaml = proxy_policy_config(&upstream, "inspect_none_body");
    let files = [
        ("bundles/none-policy/bundle.yaml", NONE_POLICY_MANIFEST),
        ("bundles/none-policy/entry.js", NONE_POLICY_SOURCE),
    ];
    let proxy = ProxyHarness::start_with_workspace(&yaml, &files).expect("start proxy");
    let body = (0..256 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            body.clone(),
            &[],
        )
        .expect("send large request");

    assert!(
        (200..300).contains(&response.status),
        "status: {}",
        response.status
    );
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "upstream should receive one request");
    assert_eq!(
        captured[0].body, body,
        "none policy must not alter the body stream"
    );
}

#[test]
fn dynamic_closed_policy_oversize_rejects_before_hook_and_upstream() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let yaml = proxy_policy_config(&upstream, "limited_closed_policy");
    let manifest =
        limited_policy_manifest("limited-closed-policy", "limited_closed_policy", "closed");
    let files = [
        (
            "bundles/limited-closed-policy/bundle.yaml",
            manifest.as_str(),
        ),
        (
            "bundles/limited-closed-policy/entry.js",
            LIMITED_POLICY_SOURCE,
        ),
    ];
    let proxy = ProxyHarness::start_with_workspace(&yaml, &files).expect("start proxy");

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            vec![b'x'; 8 * 1024],
            &[],
        )
        .expect("send oversize request");

    assert_eq!(response.status, 413, "closed hook overflow must be a 413");
    assert!(
        upstream.captured().is_empty(),
        "closed hook overflow must not reach upstream"
    );
}

#[test]
fn dynamic_open_policy_oversize_skips_hook_and_forwards_body() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let yaml = proxy_policy_config(&upstream, "limited_open_policy");
    let manifest = limited_policy_manifest("limited-open-policy", "limited_open_policy", "open");
    let files = [
        ("bundles/limited-open-policy/bundle.yaml", manifest.as_str()),
        (
            "bundles/limited-open-policy/entry.js",
            LIMITED_POLICY_SOURCE,
        ),
    ];
    let proxy = ProxyHarness::start_with_workspace(&yaml, &files).expect("start proxy");
    let body = vec![b'x'; 8 * 1024];

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            body.clone(),
            &[],
        )
        .expect("send oversize request");

    assert!(
        (200..300).contains(&response.status),
        "open hook overflow should forward, got {}: {}",
        response.status,
        response.text().unwrap_or_default()
    );
    let captured = upstream.captured();
    assert_eq!(captured.len(), 1, "upstream should receive one request");
    assert_eq!(
        captured[0].body, body,
        "forwarded body should remain intact"
    );
}

#[test]
fn dynamic_none_action_receives_empty_body_without_draining_for_itself() {
    let files = [
        (
            "bundles/action-body-modes/bundle.yaml",
            ACTION_BODY_MODES_MANIFEST,
        ),
        (
            "bundles/action-body-modes/entry.js",
            ACTION_BODY_MODES_SOURCE,
        ),
    ];
    let proxy = ProxyHarness::start_with_workspace(&action_config("none_body_action"), &files)
        .expect("start proxy");

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            vec![b'x'; 32 * 1024],
            &[],
        )
        .expect("send request");

    assert_eq!(response.status, 200, "none action received body bytes");
    assert_eq!(response.body, b"none");
}

#[test]
fn dynamic_buffered_action_receives_complete_body() {
    let files = [
        (
            "bundles/action-body-modes/bundle.yaml",
            ACTION_BODY_MODES_MANIFEST,
        ),
        (
            "bundles/action-body-modes/entry.js",
            ACTION_BODY_MODES_SOURCE,
        ),
    ];
    let proxy = ProxyHarness::start_with_workspace(&action_config("echo_buffered_action"), &files)
        .expect("start proxy");
    let body = (0..256 * 1024)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            body.clone(),
            &[],
        )
        .expect("send large request");

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body, body,
        "buffered action should receive every byte"
    );
}

#[test]
fn dynamic_buffered_action_oversize_rejects_before_hook() {
    let files = [
        (
            "bundles/limited-action/bundle.yaml",
            LIMITED_ACTION_MANIFEST,
        ),
        ("bundles/limited-action/entry.js", LIMITED_ACTION_SOURCE),
    ];
    let proxy =
        ProxyHarness::start_with_workspace(&action_config("limited_buffered_action"), &files)
            .expect("start proxy");

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            vec![b'x'; 8 * 1024],
            &[],
        )
        .expect("send oversize request");

    assert_eq!(response.status, 413, "action overflow must be a 413");
    assert_ne!(response.body, b"run", "oversize action must not run");
}

#[test]
fn dynamic_action_keeps_buffering_after_a_smaller_open_policy_is_skipped() {
    let policy_manifest =
        limited_policy_manifest("limited-open-policy", "limited_open_policy", "open");
    let yaml = r#"proxy:
  http_bind_port: 0
extensions:
  bundles_dir: bundles
origins:
  extension.localhost:
    action:
      type: echo_buffered_action
    policies:
      - type: limited_open_policy
"#;
    let files = [
        (
            "bundles/action-body-modes/bundle.yaml",
            ACTION_BODY_MODES_MANIFEST,
        ),
        (
            "bundles/action-body-modes/entry.js",
            ACTION_BODY_MODES_SOURCE,
        ),
        (
            "bundles/limited-open-policy/bundle.yaml",
            policy_manifest.as_str(),
        ),
        (
            "bundles/limited-open-policy/entry.js",
            SKIPPED_POLICY_SOURCE,
        ),
    ];
    let proxy = ProxyHarness::start_with_workspace(yaml, &files).expect("start proxy");
    let body = vec![b'x'; 8 * 1024];

    let response = proxy
        .post_bytes(
            "/upload",
            "extension.localhost",
            "application/octet-stream",
            body.clone(),
            &[],
        )
        .expect("send request");

    assert_eq!(
        response.status, 200,
        "smaller open policy should be skipped"
    );
    assert_eq!(
        response.body, body,
        "the buffered action should still receive the complete body"
    );
}

// --- Header-phase failure posture (WOR-2423) ---
//
// A `body_mode: none` policy hook runs in the header phase. Its
// manifest `failure_posture` must decide what an engine fault does,
// exactly as the buffered path already honors it: `open` admits the
// request, `closed` refuses it.

fn header_phase_policy_manifest(name: &str, policy_type: &str, posture: &str) -> String {
    format!(
        r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: {name}
version: 1.0.0
runtime: javascript
entry: entry.js
hooks:
  - kind: policy
    type: {policy_type}
    export: inspect
    execution:
      body_mode: none
failure_posture: {posture}
"#
    )
}

const THROWING_POLICY_JS: &str =
    r#"export function inspect() { throw new Error("engine fault on purpose"); }"#;

#[test]
fn header_phase_policy_fault_admits_under_an_open_posture() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let manifest = header_phase_policy_manifest("open-fault", "open_fault_policy", "open");
    let files = [
        ("bundles/open-fault/bundle.yaml", manifest.as_str()),
        ("bundles/open-fault/entry.js", THROWING_POLICY_JS),
    ];
    let proxy = ProxyHarness::start_with_workspace(
        &proxy_policy_config(&upstream, "open_fault_policy"),
        &files,
    )
    .expect("start proxy");

    let response = proxy.get("/", "extension.localhost").expect("request");
    assert_eq!(
        response.status,
        200,
        "an open posture must admit the request when the hook faults: {:?}",
        response.text().unwrap_or_default()
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "the admitted request must reach the upstream"
    );
}

#[test]
fn header_phase_policy_fault_refuses_under_the_closed_default() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let manifest = header_phase_policy_manifest("closed-fault", "closed_fault_policy", "closed");
    let files = [
        ("bundles/closed-fault/bundle.yaml", manifest.as_str()),
        ("bundles/closed-fault/entry.js", THROWING_POLICY_JS),
    ];
    let proxy = ProxyHarness::start_with_workspace(
        &proxy_policy_config(&upstream, "closed_fault_policy"),
        &files,
    )
    .expect("start proxy");

    let response = proxy.get("/", "extension.localhost").expect("request");
    assert_eq!(
        response.status, 500,
        "a closed posture must refuse the request when the hook faults"
    );
    assert_eq!(
        upstream.captured().len(),
        0,
        "the refused request must not reach the upstream: {:?}",
        upstream.captured()
    );
}

// --- runtime: rego fault posture (WOR-2482 review finding I1) ---
//
// Mirrors the pair above with a `runtime: rego` bundle instead of a
// throwing JS export. The module returns a document rather than a
// boolean: that passes candidate load (the load-time trial only
// proves the rule evaluates, not that its value is boolean) and
// faults at request time instead, which is what proves the fault
// reaches the shared `failure_posture` handling rather than being
// swallowed into a hardcoded deny inside the adapter.

fn rego_fault_manifest(name: &str, policy_type: &str, posture: &str) -> String {
    format!(
        r#"apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: {name}
version: 1.0.0
runtime: rego
entry: policy.rego
hooks:
  - kind: policy
    type: {policy_type}
    execution:
      body_mode: none
failure_posture: {posture}
"#
    )
}

const FAULTING_POLICY_REGO: &str = r#"package sbproxy

allow := {"reason": "not a boolean"}
"#;

#[test]
fn rego_bundle_policy_fault_admits_under_an_open_posture() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let manifest = rego_fault_manifest("rego-open-fault", "rego_open_fault_policy", "open");
    let files = [
        ("bundles/rego-open-fault/bundle.yaml", manifest.as_str()),
        ("bundles/rego-open-fault/policy.rego", FAULTING_POLICY_REGO),
    ];
    let proxy = ProxyHarness::start_with_workspace(
        &proxy_policy_config(&upstream, "rego_open_fault_policy"),
        &files,
    )
    .expect("start proxy");

    let response = proxy.get("/", "extension.localhost").expect("request");
    assert_eq!(
        response.status,
        200,
        "an open posture must admit the request when the rego hook faults: {:?}",
        response.text().unwrap_or_default()
    );
    assert_eq!(
        upstream.captured().len(),
        1,
        "the admitted request must reach the upstream"
    );
}

#[test]
fn rego_bundle_policy_fault_refuses_under_the_closed_default() {
    let upstream = MockUpstream::start(serde_json::json!({"ok": true})).expect("start upstream");
    let manifest = rego_fault_manifest("rego-closed-fault", "rego_closed_fault_policy", "closed");
    let files = [
        ("bundles/rego-closed-fault/bundle.yaml", manifest.as_str()),
        ("bundles/rego-closed-fault/policy.rego", FAULTING_POLICY_REGO),
    ];
    let proxy = ProxyHarness::start_with_workspace(
        &proxy_policy_config(&upstream, "rego_closed_fault_policy"),
        &files,
    )
    .expect("start proxy");

    let response = proxy.get("/", "extension.localhost").expect("request");
    assert_eq!(
        response.status, 500,
        "a closed posture must refuse the request when the rego hook faults"
    );
    assert_eq!(
        upstream.captured().len(),
        0,
        "the refused request must not reach the upstream: {:?}",
        upstream.captured()
    );
}
