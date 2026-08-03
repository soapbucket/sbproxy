use std::collections::BTreeSet;
use std::time::Duration;

use sbproxy_config::{
    compile_config, reserved_builtin_hook_names, BundleBodyMode, BundleHookKind, BundleManifest,
    BundleRuntime, BundleSourceConfig, EnforcementMode, FailureMode, BUNDLE_API_VERSION,
    BUNDLE_KIND, MAX_BUNDLE_MANIFEST_BYTES,
};

const JAVASCRIPT_MANIFEST: &str = r#"
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: rate-limit-by-plan
version: 0.3.1
runtime: javascript
entry: src/index.ts
hooks:
  - kind: policy
    type: rate_limit_by_plan
    export: enforce
    config_schema:
      type: object
      additionalProperties: false
      properties:
        requests_per_minute: { type: integer, default: 60 }
failure_posture: closed
sandbox:
  budget_ms: 50
  memory_mb: 16
  stack_kb: 512
permissions: []
"#;

fn parse_manifest(yaml: &str) -> BundleManifest {
    BundleManifest::parse_yaml(yaml.as_bytes()).expect("manifest parses")
}

fn manifest_error(yaml: &str) -> String {
    BundleManifest::parse_yaml(yaml.as_bytes())
        .expect_err("manifest must be rejected")
        .to_string()
}

fn replace_once(source: &str, from: &str, to: &str) -> String {
    assert!(source.contains(from), "fixture must contain {from:?}");
    source.replacen(from, to, 1)
}

#[test]
fn top_level_extensions_keep_shorthand_and_ordered_sources() {
    let compiled = compile_config(
        r#"
extensions:
  bundles_dir: ./bundles
  sources:
    - type: directory
      path: ./shared-bundles
    - type: git
      repo: https://example.test/platform/extensions.git
      revision: 0123456789abcdef0123456789abcdef01234567
      path: production
      credential: env:EXTENSION_GIT_TOKEN
      verify_signature: true
      timeout_secs: 20
proxy: {}
"#,
    )
    .expect("extension config compiles");

    assert_eq!(
        compiled.extension_bundles.bundles_dir.as_deref(),
        Some("./bundles")
    );
    assert_eq!(compiled.extension_bundles.sources.len(), 2);
    assert!(matches!(
        &compiled.extension_bundles.sources[0],
        BundleSourceConfig::Directory { path } if path == "./shared-bundles"
    ));
    assert!(matches!(
        &compiled.extension_bundles.sources[1],
        BundleSourceConfig::Git {
            repo,
            revision,
            path,
            credential,
            verify_signature: true,
            timeout_secs: 20,
            ..
        } if repo == "https://example.test/platform/extensions.git"
            && revision == "0123456789abcdef0123456789abcdef01234567"
            && path == "production"
            && credential.as_deref() == Some("env:EXTENSION_GIT_TOKEN")
    ));
}

#[test]
fn extension_config_rejects_unknown_nested_fields() {
    let error = match compile_config(
        r#"
extensions:
  bundles_dir: ./bundles
  bundle_dri: ./misspelled
proxy: {}
"#,
    ) {
        Ok(_) => panic!("unknown extension field must fail"),
        Err(error) => format!("{error:#}"),
    };

    assert!(error.contains("bundle_dri"), "{error}");
}

#[test]
fn bundle_refresh_uses_the_shortest_enabled_git_interval() {
    let compiled = compile_config(
        r#"
extensions:
  sources:
    - type: git
      repo: https://example.test/frozen.git
      revision: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      path: bundles
      refresh_interval_secs: 0
    - type: directory
      path: local-bundles
    - type: git
      repo: https://example.test/release.git
      revision: signed-release
      path: bundles
      verify_signature: true
      refresh_interval_secs: 45
    - type: git
      repo: https://example.test/slower.git
      revision: signed-release
      path: bundles
      verify_signature: true
      refresh_interval_secs: 300
proxy: {}
"#,
    )
    .expect("extension config compiles");

    assert_eq!(
        compiled.extension_bundles.refresh_interval(),
        Some(Duration::from_secs(45))
    );
}

#[test]
fn bundle_refresh_interval_is_bounded() {
    let error = match compile_config(
        r#"
extensions:
  sources:
    - type: git
      repo: https://example.test/release.git
      revision: signed-release
      path: bundles
      verify_signature: true
      refresh_interval_secs: 86401
proxy: {}
"#,
    ) {
        Ok(_) => panic!("an unbounded refresh sleep must be rejected"),
        Err(error) => error,
    };

    let displayed = format!("{error:#}");
    assert!(displayed.contains("refresh_interval_secs"), "{displayed}");
    assert!(displayed.contains("86400"), "{displayed}");
}

#[test]
fn manifest_parses_the_versioned_javascript_contract_and_defaults() {
    let manifest = parse_manifest(JAVASCRIPT_MANIFEST);

    assert_eq!(manifest.api_version, BUNDLE_API_VERSION);
    assert_eq!(manifest.kind, BUNDLE_KIND);
    assert_eq!(manifest.runtime, BundleRuntime::Javascript);
    assert_eq!(manifest.failure_posture, FailureMode::Closed);
    assert_eq!(manifest.hooks[0].kind, BundleHookKind::Policy);
    assert_eq!(manifest.hooks[0].enforcement_mode, EnforcementMode::Block);
    assert_eq!(
        manifest.hooks[0].execution.body_mode,
        BundleBodyMode::Buffered
    );
    assert_eq!(manifest.sandbox.max_buffer_bytes, 1_048_576);
    assert_eq!(manifest.sandbox.max_output_bytes, 1_048_576);
    assert_eq!(manifest.sandbox.max_fuel, 100_000_000);
}

#[test]
fn proxy_wasm_accepts_streamed_ai_events_with_observe_mode() {
    let manifest = parse_manifest(
        r#"
apiVersion: sbproxy.dev/v1alpha1
kind: Bundle
name: stream-observer
version: 1.0.0
runtime: proxy_wasm
abi: 0.2.1
entry: observer.wasm
hooks:
  - kind: ai_stream_event
    type: stream_observer
    enforcement_mode: observe
    execution:
      body_mode: streamed
"#,
    );

    assert_eq!(manifest.hooks[0].kind, BundleHookKind::AiStreamEvent);
    assert_eq!(manifest.hooks[0].enforcement_mode, EnforcementMode::Observe);
    assert_eq!(
        manifest.hooks[0].execution.body_mode,
        BundleBodyMode::Streamed
    );
}

#[test]
fn javascript_runtime_accepts_direct_js_entry() {
    let yaml = replace_once(
        JAVASCRIPT_MANIFEST,
        "entry: src/index.ts",
        "entry: dist/index.js",
    );

    let manifest = parse_manifest(&yaml);
    assert_eq!(manifest.runtime, BundleRuntime::Javascript);
    assert_eq!(manifest.entry, "dist/index.js");
}

#[test]
fn payment_hook_manifest_uses_no_body_contract() {
    let yaml = JAVASCRIPT_MANIFEST
        .replace("kind: policy", "kind: payment")
        .replace(
            "    export: enforce",
            "    export: enforce\n    execution:\n      body_mode: none",
        );

    let manifest = parse_manifest(&yaml);

    assert_eq!(manifest.hooks[0].kind, BundleHookKind::Payment);
    assert_eq!(manifest.hooks[0].execution.body_mode, BundleBodyMode::None);
}

#[test]
fn payment_hook_manifest_rejects_body_access() {
    let yaml = JAVASCRIPT_MANIFEST.replace("kind: policy", "kind: payment");

    let error = manifest_error(&yaml);

    assert!(
        error.contains("payment") && error.contains("body_mode none"),
        "{error}"
    );
}

#[test]
fn manifest_is_strict_and_versioned() {
    for (from, to, needle) in [
        (
            "apiVersion: sbproxy.dev/v1alpha1",
            "apiVersion: sbproxy.dev/v2",
            "apiVersion",
        ),
        ("kind: Bundle", "kind: Plugin", "kind"),
        (
            "permissions: []",
            "permissions: []\nunexpected: true",
            "unexpected",
        ),
        (
            "    export: enforce",
            "    export: enforce\n    unexpected: true",
            "unexpected",
        ),
    ] {
        let error = manifest_error(&replace_once(JAVASCRIPT_MANIFEST, from, to));
        assert!(error.contains(needle), "{error}");
    }
}

#[test]
fn manifest_size_is_checked_before_yaml_deserialization() {
    let oversized = vec![b' '; MAX_BUNDLE_MANIFEST_BYTES + 1];
    let error = BundleManifest::parse_yaml(&oversized)
        .expect_err("oversized manifest must fail")
        .to_string();

    assert!(error.contains("256 KiB"), "{error}");
}

#[test]
fn manifest_rejects_duplicate_and_reserved_hook_types() {
    let duplicate = replace_once(
        JAVASCRIPT_MANIFEST,
        "failure_posture: closed",
        r#"  - kind: policy
    type: rate_limit_by_plan
    export: enforce_again
failure_posture: closed"#,
    );
    let error = manifest_error(&duplicate);
    assert!(
        error.contains("duplicate") && error.contains("rate_limit_by_plan"),
        "{error}"
    );

    let manifest = parse_manifest(JAVASCRIPT_MANIFEST);
    let reserved = BTreeSet::from([(BundleHookKind::Policy, "rate_limit_by_plan".to_owned())]);
    let error = manifest
        .validate(&reserved)
        .expect_err("built-in collision must fail")
        .to_string();
    assert!(
        error.contains("reserved") && error.contains("rate_limit_by_plan"),
        "{error}"
    );
}

#[test]
fn built_in_reservations_are_kind_aware_and_deterministic() {
    let reservations = reserved_builtin_hook_names();
    assert!(reservations.contains(&(BundleHookKind::Policy, "rate_limiting".to_owned())));
    assert!(reservations.contains(&(BundleHookKind::Action, "proxy".to_owned())));
    assert!(reservations.contains(&(BundleHookKind::Transform, "wasm".to_owned())));
    assert!(!reservations.contains(&(BundleHookKind::Transform, "rate_limiting".to_owned())));

    let yaml = JAVASCRIPT_MANIFEST.replace("rate_limit_by_plan", "rate_limiting");
    let manifest = parse_manifest(&yaml);
    let error = manifest
        .validate(&reservations)
        .expect_err("built-in policy collision must fail")
        .to_string();
    assert!(
        error.contains("reserved") && error.contains("rate_limiting"),
        "{error}"
    );
}

#[test]
fn runtime_entry_and_export_contracts_are_enforced() {
    let js_without_export = replace_once(JAVASCRIPT_MANIFEST, "    export: enforce\n", "");
    assert!(manifest_error(&js_without_export).contains("export"));

    let js_wrong_suffix = replace_once(JAVASCRIPT_MANIFEST, "src/index.ts", "src/index.wasm");
    assert!(manifest_error(&js_wrong_suffix).contains(".ts or .js"));

    let wasm_with_export = JAVASCRIPT_MANIFEST
        .replace(
            "runtime: javascript",
            "runtime: wasm\nabi: sbproxy-envelope/v1",
        )
        .replace("src/index.ts", "dist/bundle.wasm");
    assert!(manifest_error(&wasm_with_export).contains("export"));

    let wasm_without_export = wasm_with_export.replace("    export: enforce\n", "");
    parse_manifest(&wasm_without_export);

    let proxy_wasm = wasm_without_export
        .replace("runtime: wasm", "runtime: proxy_wasm")
        .replace("abi: sbproxy-envelope/v1", "abi: 0.2.1")
        .replace(
            "    config_schema:\n      type: object\n      additionalProperties: false\n      properties:\n        requests_per_minute: { type: integer, default: 60 }\n",
            "",
        )
        .replace(
            "  - kind: policy\n",
            "  - kind: proxy_wasm\n    execution:\n      body_mode: streamed\n",
        );
    parse_manifest(&proxy_wasm);

    let buffered_runtime_claiming_streamed = replace_once(
        JAVASCRIPT_MANIFEST,
        "  - kind: policy\n",
        "  - kind: policy\n    execution:\n      body_mode: streamed\n",
    );
    assert!(manifest_error(&buffered_runtime_claiming_streamed).contains("streamed"));
}

#[test]
fn javascript_runtime_rejects_ai_stream_event_hooks() {
    let yaml = replace_once(
        JAVASCRIPT_MANIFEST,
        "  - kind: policy\n",
        "  - kind: ai_stream_event\n",
    );

    let error = manifest_error(&yaml);
    assert!(
        error.contains("javascript") && error.contains("ai_stream_event"),
        "{error}"
    );
}

#[test]
fn envelope_wasm_runtime_rejects_ai_stream_event_hooks() {
    let yaml = JAVASCRIPT_MANIFEST
        .replace(
            "runtime: javascript",
            "runtime: wasm\nabi: sbproxy-envelope/v1",
        )
        .replace("entry: src/index.ts", "entry: dist/bundle.wasm")
        .replace("  - kind: policy\n", "  - kind: ai_stream_event\n")
        .replace("    export: enforce\n", "");

    let error = manifest_error(&yaml);
    assert!(
        error.contains("wasm") && error.contains("ai_stream_event"),
        "{error}"
    );
}

#[test]
fn manifest_rejects_inactive_permissions_and_unsafe_schemas() {
    let permissions = replace_once(
        JAVASCRIPT_MANIFEST,
        "permissions: []",
        "permissions: [network]",
    );
    assert!(manifest_error(&permissions).contains("permissions"));

    let remote_ref = replace_once(
        JAVASCRIPT_MANIFEST,
        "      type: object",
        "      type: object\n      $ref: https://example.test/schema.json",
    );
    assert!(manifest_error(&remote_ref).contains("remote $ref"));

    let mut deep = "{}".to_owned();
    for _ in 0..33 {
        deep = format!(r#"{{"nested":{deep}}}"#);
    }
    let depth = replace_once(
        JAVASCRIPT_MANIFEST,
        "      type: object\n      additionalProperties: false\n      properties:\n        requests_per_minute: { type: integer, default: 60 }",
        &format!("      {deep}"),
    );
    assert!(manifest_error(&depth).contains("depth 32"));

    let properties = (0..65)
        .map(|index| format!("        field_{index}: {{ type: string }}"))
        .collect::<Vec<_>>()
        .join("\n");
    let too_many_properties = replace_once(
        JAVASCRIPT_MANIFEST,
        "        requests_per_minute: { type: integer, default: 60 }",
        &properties,
    );
    assert!(manifest_error(&too_many_properties).contains("64 properties"));
}

#[test]
fn manifest_rejects_malformed_executable_sha256() {
    let malformed = replace_once(
        JAVASCRIPT_MANIFEST,
        "entry: src/index.ts",
        "entry: src/index.ts\nsha256: not-a-sha256",
    );

    let error = manifest_error(&malformed);
    assert!(error.contains("sha256") && error.contains("64"), "{error}");
}

#[test]
fn manifest_errors_are_bounded_and_do_not_echo_remote_ref_credentials() {
    let long_version = "x".repeat(700);
    let version_error = manifest_error(&replace_once(
        JAVASCRIPT_MANIFEST,
        "version: 0.3.1",
        &format!("version: {long_version}"),
    ));
    assert!(version_error.len() <= 512, "{}", version_error.len());

    let remote_ref = replace_once(
        JAVASCRIPT_MANIFEST,
        "      type: object",
        "      type: object\n      $ref: https://user:secret@example.test/schema.json",
    );
    let ref_error = manifest_error(&remote_ref);
    assert!(!ref_error.contains("secret"), "{ref_error}");
}

#[test]
fn malformed_manifest_yaml_errors_render_within_512_bytes() {
    let unknown_runtime = "x".repeat(700);
    let yaml = replace_once(
        JAVASCRIPT_MANIFEST,
        "runtime: javascript",
        &format!("runtime: {unknown_runtime}"),
    );

    let rendered = BundleManifest::parse_yaml(yaml.as_bytes())
        .expect_err("unknown runtime must be rejected as malformed manifest YAML")
        .to_string();
    assert!(
        rendered.len() <= 512,
        "rendered error is {} bytes: {rendered}",
        rendered.len()
    );
}

#[test]
fn manifest_enforces_hook_count_identifiers_and_failure_posture() {
    let invalid_name = replace_once(
        JAVASCRIPT_MANIFEST,
        "name: rate-limit-by-plan",
        "name: ../bundle",
    );
    assert!(manifest_error(&invalid_name).contains("name"));

    let hooks = (0..129)
        .map(|index| {
            format!("  - kind: policy\n    type: fixture_{index}\n    export: enforce_{index}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let too_many_hooks = replace_once(
        JAVASCRIPT_MANIFEST,
        "  - kind: policy\n    type: rate_limit_by_plan\n    export: enforce\n    config_schema:\n      type: object\n      additionalProperties: false\n      properties:\n        requests_per_minute: { type: integer, default: 60 }",
        &hooks,
    );
    assert!(manifest_error(&too_many_hooks).contains("128 hooks"));

    for posture in ["observe", "degraded"] {
        let yaml = JAVASCRIPT_MANIFEST
            .replace("kind: policy", "kind: transform")
            .replace(
                "failure_posture: closed",
                &format!("failure_posture: {posture}"),
            );
        let error = manifest_error(&yaml);
        assert!(
            error.contains("transform") && error.contains(posture),
            "{error}"
        );
    }
}

#[test]
fn action_hooks_require_closed_failure_posture() {
    for posture in ["open", "degraded", "observe"] {
        let yaml = JAVASCRIPT_MANIFEST
            .replace("kind: policy", "kind: action")
            .replace(
                "failure_posture: closed",
                &format!("failure_posture: {posture}"),
            );

        let error = manifest_error(&yaml);

        assert!(
            error.contains("action hooks are terminal and require failure_posture closed"),
            "unexpected {posture} posture error: {error}"
        );
    }
}

#[test]
fn manifest_enforces_every_execution_ceiling() {
    for (field, value, ceiling) in [
        ("budget_ms", "1001", "1000"),
        ("memory_mb", "65", "64"),
        ("stack_kb", "2049", "2048"),
        ("max_buffer_bytes", "16777217", "16777216"),
        ("max_output_bytes", "16777217", "16777216"),
        ("max_fuel", "1000000001", "1000000000"),
    ] {
        let current = match field {
            "budget_ms" => "50",
            "memory_mb" => "16",
            "stack_kb" => "512",
            _ => "",
        };
        let yaml = if current.is_empty() {
            replace_once(
                JAVASCRIPT_MANIFEST,
                "  stack_kb: 512",
                &format!("  stack_kb: 512\n  {field}: {value}"),
            )
        } else {
            replace_once(
                JAVASCRIPT_MANIFEST,
                &format!("  {field}: {current}"),
                &format!("  {field}: {value}"),
            )
        };
        let error = manifest_error(&yaml);
        assert!(error.contains(field) && error.contains(ceiling), "{error}");
    }
}

#[test]
fn proxy_wasm_filter_attachment_compiles_with_typed_fields() {
    let compiled = compile_config(
        r#"
origins:
  filter.example:
    action: { type: noop }
    filters:
      - type: fixture_http_filter
        config: { enabled: true }
        failure_posture: open
proxy: {}
"#,
    )
    .expect("Proxy-Wasm filter attachment compiles");

    let attachment = &compiled.origins[0].filters[0];
    assert_eq!(attachment.type_name, "fixture_http_filter");
    assert_eq!(attachment.config, serde_json::json!({"enabled": true}));
    assert_eq!(attachment.failure_posture, Some(FailureMode::Open));
}

#[test]
fn proxy_wasm_filter_attachment_rejects_failure_mode_alias() {
    let error = match compile_config(
        r#"
origins:
  filter.example:
    action: { type: noop }
    filters:
      - type: fixture_http_filter
        failure_mode: open
proxy: {}
"#,
    ) {
        Ok(_) => panic!("misspelled attachment posture must fail"),
        Err(error) => format!("{error:#}"),
    };

    assert!(error.contains("failure_mode"), "{error}");
}
