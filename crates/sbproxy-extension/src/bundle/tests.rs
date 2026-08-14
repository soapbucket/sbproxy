use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sbproxy_config::{
    BundleDigestScope, BundleHookKind, BundleSourceConfig, Cloner, ConfigSourceError,
    ExtensionBundlesConfig, FetchContext, FetchRequest, ResolvedRevision,
};
use sbproxy_plugin::{
    ExtensionBodyMode, ExtensionDispatch, ExtensionHookKind, ExtensionRegistrationSource,
    ExtensionRuntime,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{
    build_proxy_wasm_filter, BundleLoadError, BundleRegistry, DynamicBundleRegistry,
    ProxyWasmAction,
};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VALID_JAVASCRIPT: &[u8] = b"export function run() {}";

type CloneCalls = Arc<Mutex<Vec<(String, Option<String>, bool)>>>;

struct TreeCloner {
    source: std::path::PathBuf,
    calls: CloneCalls,
}

impl Cloner for TreeCloner {
    fn fetch(&self, request: &FetchRequest<'_>) -> Result<ResolvedRevision, ConfigSourceError> {
        self.calls.lock().unwrap().push((
            request.repo.to_owned(),
            request.revision.map(str::to_owned),
            request.verify_signature,
        ));
        copy_tree(&self.source, request.dest);
        Ok(ResolvedRevision {
            repo: sbproxy_config::redact_repo(request.repo),
            reference: request.revision.unwrap_or("HEAD").to_owned(),
            commit: COMMIT.to_owned(),
        })
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn write_bundle(root: &Path, directory: &str, manifest: &str, artifact: &[u8]) {
    let bundle = root.join(directory);
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(bundle.join("bundle.yaml"), manifest).unwrap();
    std::fs::write(bundle.join("entry.js"), artifact).unwrap();
}

fn manifest(name: &str, kind: &str, type_name: &str, digest: Option<&str>) -> String {
    let digest = digest
        .map(|value| format!("sha256: {value}\n"))
        .unwrap_or_default();
    format!(
        "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: {name}\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\n{digest}hooks:\n  - kind: {kind}\n    type: {type_name}\n    export: run\n"
    )
}

fn local_config(path: &Path) -> ExtensionBundlesConfig {
    ExtensionBundlesConfig {
        bundles_dir: Some(path.display().to_string()),
        sources: Vec::new(),
        grants: Default::default(),
    }
}

/// A `digest_scope: bundle_v1` manifest whose digest is still a placeholder.
///
/// The placeholder is safe to hash around: the canonical form deletes the
/// whole `sha256:` line, so the manifest bytes that feed the digest are the
/// same before and after the real value is written back.
fn bundle_v1_manifest(name: &str, kind: &str, type_name: &str) -> String {
    format!(
        "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: {name}\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nsha256: __DIGEST__\ndigest_scope: bundle_v1\npermissions: []\nhooks:\n  - kind: {kind}\n    type: {type_name}\n    export: run\n"
    )
}

/// Write a `bundle_v1` bundle and pin the digest the format produces for it.
fn write_bundle_v1(
    root: &Path,
    directory: &str,
    manifest: &str,
    files: &[(&str, &[u8])],
) -> String {
    let bundle = root.join(directory);
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(bundle.join("bundle.yaml"), manifest).unwrap();
    for (name, bytes) in files {
        let path = bundle.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    let digest = bundle_v1_digest_by_hand(&bundle);
    std::fs::write(
        bundle.join("bundle.yaml"),
        manifest.replace("__DIGEST__", &digest),
    )
    .unwrap();
    digest
}

/// Recompute the canonical index from the published rules, independently of
/// the loader, so the two implementations have to agree.
fn bundle_v1_digest_by_hand(bundle: &Path) -> String {
    let mut lines = Vec::new();
    index_lines_by_hand(bundle, "", &mut lines);
    lines.sort();
    let mut index = String::from("sbproxy-bundle-digest/v1\n");
    for (path, content_digest) in &lines {
        index.push_str(content_digest);
        index.push_str("  ");
        index.push_str(path);
        index.push('\n');
    }
    hex::encode(Sha256::digest(index.as_bytes()))
}

fn index_lines_by_hand(dir: &Path, prefix: &str, lines: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type().unwrap().is_dir() {
            index_lines_by_hand(&entry.path(), &path, lines);
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        let bytes = if path == "bundle.yaml" {
            std::str::from_utf8(&bytes)
                .unwrap()
                .split_inclusive('\n')
                .filter(|line| !line.starts_with("sha256:"))
                .collect::<String>()
                .into_bytes()
        } else {
            bytes
        };
        lines.push((path, hex::encode(Sha256::digest(&bytes))));
    }
}

fn load_error(root: &Path) -> BundleLoadError {
    DynamicBundleRegistry::load(&local_config(root), root, &BTreeSet::new()).unwrap_err()
}

fn load_ok(root: &Path) {
    DynamicBundleRegistry::load(&local_config(root), root, &BTreeSet::new()).unwrap();
}

#[test]
fn local_candidate_loads_bundles_and_sorts_public_inventory() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "z-last",
        &manifest("z-last", "transform", "z_transform", None),
        b"export function run() {}",
    );
    write_bundle(
        temp.path(),
        "a-first",
        &manifest("a-first", "policy", "a_policy", None),
        b"export function run() {}",
    );

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();

    assert!(registry.policy("a_policy").is_some());
    assert!(registry.transform("z_transform").is_some());
    assert!(registry.action("a_policy").is_none());
    assert!(registry.proxy_wasm_filter("a_policy").is_none());
    assert!(registry.ai_hooks(BundleHookKind::AiClose).is_empty());
    assert_eq!(
        registry
            .inventory()
            .bundles
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        ["a-first", "z-last"]
    );
    assert_eq!(registry.inventory().summary.bundles, 2);
    assert_eq!(registry.inventory().summary.hooks, 2);
}

#[test]
fn checked_in_fixture_tree_loads_without_environment_dependent_paths() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bundle/testdata/valid");
    let registry = DynamicBundleRegistry::load(
        &local_config(&fixture),
        Path::new(env!("CARGO_MANIFEST_DIR")),
        &BTreeSet::new(),
    )
    .unwrap();

    assert!(registry.policy("fixture_policy").is_some());
    assert!(registry.action("fixture_action").is_some());
    assert_eq!(
        registry
            .inventory()
            .bundles
            .iter()
            .map(|bundle| bundle.id.as_str())
            .collect::<Vec<_>>(),
        ["fixture-action", "fixture-policy"]
    );
}

#[test]
fn sources_process_bundles_dir_first_then_declarations_in_order() {
    let base = TempDir::new().unwrap();
    for source in ["short", "declared-one", "declared-two"] {
        std::fs::create_dir(base.path().join(source)).unwrap();
    }
    write_bundle(
        &base.path().join("short"),
        "bundle",
        &manifest("short-bundle", "policy", "collision", None),
        VALID_JAVASCRIPT,
    );
    write_bundle(
        &base.path().join("declared-one"),
        "bundle",
        &manifest("declared-one", "policy", "collision", None),
        VALID_JAVASCRIPT,
    );
    let config = ExtensionBundlesConfig {
        grants: Default::default(),
        bundles_dir: Some("short".to_owned()),
        sources: vec![
            BundleSourceConfig::Directory {
                path: "declared-one".to_owned(),
            },
            BundleSourceConfig::Directory {
                path: "declared-two".to_owned(),
            },
        ],
    };

    let error = DynamicBundleRegistry::load(&config, base.path(), &BTreeSet::new()).unwrap_err();
    assert!(error.to_string().contains("short-bundle"), "{error}");
    assert!(error.to_string().contains("declared-one"), "{error}");
}

#[test]
fn collision_rejects_whole_candidate_against_dynamic_and_reserved_names() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "a",
        &manifest("bundle-a", "policy", "claimed", None),
        VALID_JAVASCRIPT,
    );
    write_bundle(
        temp.path(),
        "b",
        &manifest("bundle-b", "policy", "claimed", None),
        VALID_JAVASCRIPT,
    );
    let error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert!(error.to_string().contains("bundle-a"), "{error}");
    assert!(error.to_string().contains("bundle-b"), "{error}");

    std::fs::remove_dir_all(temp.path().join("b")).unwrap();
    let reserved = BTreeSet::from([(BundleHookKind::Policy, "claimed".to_owned())]);
    let reserved_error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &reserved)
            .unwrap_err();
    assert!(reserved_error.to_string().contains("reserved"));

    let empty = TempDir::new().unwrap();
    let empty_registry =
        DynamicBundleRegistry::load(&local_config(empty.path()), empty.path(), &BTreeSet::new())
            .unwrap();
    assert!(empty_registry.inventory().bundles.is_empty());
}

#[test]
fn reverse_creation_order_still_reports_lexical_bundle_as_earlier_registration() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "z-created-first",
        &manifest("lexical-z", "policy", "ordered_collision", None),
        VALID_JAVASCRIPT,
    );
    write_bundle(
        temp.path(),
        "a-created-last",
        &manifest("lexical-a", "policy", "ordered_collision", None),
        VALID_JAVASCRIPT,
    );

    let error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert_eq!(
        error.to_string(),
        "bundle.collision: bundle `lexical-a` and bundle `lexical-z` both declare policy hook `ordered_collision`"
    );
}

#[test]
fn built_in_and_linked_static_reservations_use_the_same_kind_aware_rejection() {
    for (owner, reserved_type) in [
        ("built-in", "builtin_reserved_policy"),
        ("linked-static", "static_reserved_policy"),
    ] {
        let temp = TempDir::new().unwrap();
        write_bundle(
            temp.path(),
            "bundle",
            &manifest("reserved-bundle", "policy", reserved_type, None),
            b"entry",
        );
        let combined_builtin_and_static =
            BTreeSet::from([(BundleHookKind::Policy, reserved_type.to_owned())]);
        let error = DynamicBundleRegistry::load(
            &local_config(temp.path()),
            temp.path(),
            &combined_builtin_and_static,
        )
        .unwrap_err();
        assert!(error.to_string().contains("reserved"), "{owner}: {error}");
    }
}

#[test]
fn hooks_are_checked_lexically_for_deterministic_errors() {
    let temp = TempDir::new().unwrap();
    let hooks = manifest("ordered", "policy", "z_reserved", None).replace(
        "hooks:\n  - kind: policy\n    type: z_reserved\n    export: run\n",
        "hooks:\n  - kind: policy\n    type: z_reserved\n    export: run\n  - kind: policy\n    type: a_reserved\n    export: run\n",
    );
    write_bundle(temp.path(), "bundle", &hooks, b"entry");
    let reserved = BTreeSet::from([
        (BundleHookKind::Policy, "a_reserved".to_owned()),
        (BundleHookKind::Policy, "z_reserved".to_owned()),
    ]);

    let error = DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &reserved)
        .unwrap_err();
    let detail = error.to_string();
    assert!(detail.contains("a_reserved"), "{detail}");
    assert!(!detail.contains("z_reserved"), "{detail}");
}

#[test]
fn kind_is_part_of_the_collision_key() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "policy",
        &manifest("policy-bundle", "policy", "shared", None),
        VALID_JAVASCRIPT,
    );
    write_bundle(
        temp.path(),
        "action",
        &manifest("action-bundle", "action", "shared", None),
        VALID_JAVASCRIPT,
    );

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    assert!(registry.policy("shared").is_some());
    assert!(registry.action("shared").is_some());
}

#[test]
fn proxy_wasm_and_ai_lookups_map_kinds_and_sort_ai_hooks() {
    let temp = TempDir::new().unwrap();
    let proxy_dir = temp.path().join("proxy-filter");
    std::fs::create_dir(&proxy_dir).unwrap();
    std::fs::write(
        proxy_dir.join("bundle.yaml"),
        "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: proxy-filter\nversion: 1.0.0\nruntime: proxy_wasm\nabi: 0.2.1\nentry: filter.wasm\nhooks:\n  - kind: proxy_wasm\n    type: fixture_proxy_filter\n",
    )
    .unwrap();
    std::fs::write(
        proxy_dir.join("filter.wasm"),
        include_bytes!("testdata/proxy_wasm/minimal.wasm"),
    )
    .unwrap();

    write_bundle(
        temp.path(),
        "z-ai-created-first",
        &manifest("z-ai", "ai_close", "z_close", None),
        VALID_JAVASCRIPT,
    );
    write_bundle(
        temp.path(),
        "a-ai-created-last",
        &manifest("a-ai", "ai_close", "a_close", None),
        VALID_JAVASCRIPT,
    );
    write_bundle(
        temp.path(),
        "m-ai-tool",
        &manifest("m-ai", "ai_tool_call", "tool_call", None),
        VALID_JAVASCRIPT,
    );

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    let proxy = registry.proxy_wasm_filter("fixture_proxy_filter").unwrap();
    assert_eq!(proxy.hook().kind, BundleHookKind::ProxyWasm);
    let filter = build_proxy_wasm_filter(proxy, serde_json::json!({"enabled": true})).unwrap();
    assert_eq!(filter.type_name(), "fixture_proxy_filter");
    assert_eq!(
        filter
            .start_session()
            .unwrap()
            .on_request_headers(Vec::new(), true)
            .unwrap()
            .action,
        ProxyWasmAction::Continue
    );
    let close_hooks = registry.ai_hooks(BundleHookKind::AiClose);
    assert_eq!(
        close_hooks
            .iter()
            .map(|hook| hook.hook().type_name.as_str())
            .collect::<Vec<_>>(),
        ["a_close", "z_close"]
    );
    let tool_hooks = registry.ai_hooks(BundleHookKind::AiToolCall);
    assert_eq!(tool_hooks.len(), 1);
    assert_eq!(tool_hooks[0].hook().kind, BundleHookKind::AiToolCall);
    assert!(registry.inventory().hooks.iter().any(|hook| {
        hook.match_key == "fixture_proxy_filter"
            && hook.kind == ExtensionHookKind::ProxyWasmFilter
            && hook.runtime == ExtensionRuntime::ProxyWasm
            && hook.capabilities.contains(&"request_body".to_owned())
            && hook.capabilities.contains(&"local_response".to_owned())
    }));
    assert!(registry.inventory().hooks.iter().any(|hook| {
        hook.match_key == "a_close"
            && hook.kind == ExtensionHookKind::AiClose
            && hook.runtime == ExtensionRuntime::Javascript
    }));
    assert!(registry.inventory().hooks.iter().any(|hook| {
        hook.match_key == "tool_call"
            && hook.kind == ExtensionHookKind::AiToolCall
            && hook.runtime == ExtensionRuntime::Javascript
    }));
}

/// WOR-2289: `secret_vars`/`masked_vars` name a `config_schema`
/// property, and a Proxy-Wasm hook is required (elsewhere in this
/// module) to omit `config_schema` entirely, so it structurally cannot
/// declare either list. A value shaped like a secret reference in its
/// config is therefore passed straight through to `plugin_configuration`
/// bytes, unexamined and unresolved; this proves the build never fails
/// or blocks on one, the way it would if this runtime attempted
/// resolution the way JavaScript and envelope-WASM hooks do.
#[test]
fn proxy_wasm_filter_config_passes_a_reference_shaped_value_through_unresolved() {
    let temp = TempDir::new().unwrap();
    let proxy_dir = temp.path().join("proxy-filter");
    std::fs::create_dir(&proxy_dir).unwrap();
    std::fs::write(
        proxy_dir.join("bundle.yaml"),
        "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: proxy-filter\nversion: 1.0.0\nruntime: proxy_wasm\nabi: 0.2.1\nentry: filter.wasm\nhooks:\n  - kind: proxy_wasm\n    type: fixture_proxy_filter\n",
    )
    .unwrap();
    std::fs::write(
        proxy_dir.join("filter.wasm"),
        include_bytes!("testdata/proxy_wasm/minimal.wasm"),
    )
    .unwrap();

    let secret_dir = TempDir::new().unwrap();
    let secret_path = secret_dir.path().join("token");
    std::fs::write(&secret_path, "DISTINCTIVE_PROXY_WASM_SECRET_2d6f").unwrap();

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    let proxy = registry.proxy_wasm_filter("fixture_proxy_filter").unwrap();

    let filter = build_proxy_wasm_filter(
        proxy,
        serde_json::json!({ "token": format!("file:{}", secret_path.display()) }),
    )
    .unwrap();
    assert_eq!(filter.type_name(), "fixture_proxy_filter");
}

/// WOR-2289: loading a candidate registers its hooks' `secret_vars`/
/// `masked_vars` names with the process-wide log redactor
/// (`sbproxy_observe::logging::set_bundle_secret_field_names`), and the
/// public inventory never carries the attachment config a var's value
/// would appear in.
#[test]
fn loading_a_candidate_registers_its_secret_vars_with_the_log_redactor() {
    sbproxy_observe::logging::set_bundle_secret_field_names(Vec::new());
    let temp = TempDir::new().unwrap();
    let schema_manifest = manifest("redactor-bundle", "policy", "redactor_policy", None).replace(
        "    export: run\n",
        "    export: run\n    config_schema:\n      type: object\n      properties:\n        hmac_key:\n          type: string\n    secret_vars: [hmac_key]\n",
    );
    write_bundle(temp.path(), "redactor", &schema_manifest, VALID_JAVASCRIPT);

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();

    let registered = sbproxy_observe::logging::bundle_secret_field_names();
    assert!(
        registered.iter().any(|name| name == "hmac_key"),
        "{registered:?}"
    );

    let rendered = serde_json::to_string(registry.inventory()).unwrap();
    assert!(
        !rendered.contains("hmac_key"),
        "public inventory must never carry attachment config: {rendered}"
    );

    sbproxy_observe::logging::set_bundle_secret_field_names(Vec::new());
}

#[test]
fn invalid_proxy_wasm_module_rejects_the_complete_candidate() {
    let temp = TempDir::new().unwrap();
    let proxy_dir = temp.path().join("proxy-filter");
    std::fs::create_dir(&proxy_dir).unwrap();
    std::fs::write(
        proxy_dir.join("bundle.yaml"),
        "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: proxy-filter\nversion: 1.0.0\nruntime: proxy_wasm\nabi: 0.2.1\nentry: filter.wasm\nhooks:\n  - kind: proxy_wasm\n    type: fixture_proxy_filter\n",
    )
    .unwrap();
    std::fs::write(proxy_dir.join("filter.wasm"), b"not a wasm module").unwrap();

    let error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();

    assert_eq!(error.to_string(), "bundle.proxy_wasm: invalid_module");
}

#[test]
fn payment_hooks_load_in_deterministic_order_and_use_no_body_inventory() {
    let temp = TempDir::new().unwrap();
    for (directory, bundle, type_name) in [
        ("z-created-first", "z-payment", "z_payment"),
        ("a-created-last", "a-payment", "a_payment"),
    ] {
        let manifest = manifest(bundle, "payment", type_name, None).replace(
            "    export: run\n",
            "    export: run\n    execution:\n      body_mode: none\n",
        );
        write_bundle(temp.path(), directory, &manifest, VALID_JAVASCRIPT);
    }

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();

    assert_eq!(
        registry
            .payment_hooks()
            .iter()
            .map(|hook| hook.hook().type_name.as_str())
            .collect::<Vec<_>>(),
        ["a_payment", "z_payment"]
    );
    let record = registry
        .inventory()
        .hooks
        .iter()
        .find(|hook| hook.match_key == "a_payment")
        .unwrap();
    assert_eq!(record.kind, ExtensionHookKind::Payment);
    assert_eq!(record.dispatch, ExtensionDispatch::Chain);
    assert_eq!(record.execution.phase, "payment");
    assert_eq!(record.execution.body_mode, ExtensionBodyMode::None);
}

#[test]
fn intentional_in_root_nested_entry_loads() {
    let temp = TempDir::new().unwrap();
    let bundle = temp.path().join("nested");
    std::fs::create_dir_all(bundle.join("assets")).unwrap();
    std::fs::write(
        bundle.join("bundle.yaml"),
        manifest("nested", "policy", "nested_policy", None)
            .replace("entry: entry.js", "entry: assets/entry.js"),
    )
    .unwrap();
    std::fs::write(bundle.join("assets/entry.js"), VALID_JAVASCRIPT).unwrap();

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    assert_eq!(
        registry.policy("nested_policy").unwrap().artifact(),
        VALID_JAVASCRIPT
    );
}

#[test]
fn executable_bytes_digest_manifest_and_schema_are_immutable_records() {
    let temp = TempDir::new().unwrap();
    let artifact = b"export function run() { return true; }";
    let schema_manifest = manifest("schema-bundle", "policy", "schema_policy", None).replace(
        "    export: run\n",
        "    export: run\n    config_schema:\n      type: object\n      properties:\n        enabled:\n          type: boolean\n",
    );
    write_bundle(temp.path(), "schema", &schema_manifest, artifact);
    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    std::fs::write(temp.path().join("schema/entry.js"), b"changed").unwrap();

    let loaded = registry.policy("schema_policy").unwrap();
    assert_eq!(loaded.artifact(), artifact);
    assert_eq!(
        loaded.sha256(),
        "e78874093dfaf4a6056e06c8e57efa785babecf20a66b91628f27149f7b1d41c"
    );
    assert_eq!(loaded.manifest().name, "schema-bundle");
    assert!(loaded.config_validator().is_some());
    assert!(loaded
        .validate_config(&serde_json::json!({"enabled": true}))
        .is_ok());
    assert!(loaded
        .validate_config(&serde_json::json!({"enabled": "yes"}))
        .is_err());
}

#[test]
fn attachment_validation_error_never_echoes_instance_secrets() {
    let temp = TempDir::new().unwrap();
    let schema_manifest = manifest("safe-schema", "policy", "safe_policy", None).replace(
        "    export: run\n",
        "    export: run\n    config_schema:\n      type: object\n      properties:\n        enabled:\n          type: boolean\n",
    );
    write_bundle(temp.path(), "bundle", &schema_manifest, VALID_JAVASCRIPT);
    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();

    let error = registry
        .policy("safe_policy")
        .unwrap()
        .validate_config(&serde_json::json!({"enabled": "DISTINCTIVE_SECRET_91f2"}))
        .unwrap_err();
    let rendered = error.to_string();
    assert!(!rendered.contains("DISTINCTIVE_SECRET_91f2"), "{rendered}");
    assert!(rendered.contains("/enabled"), "{rendered}");
    assert!(rendered.len() <= 512, "{rendered}");
}

#[test]
fn invalid_schema_and_digest_fail_before_records_exist() {
    let temp = TempDir::new().unwrap();
    let invalid_schema = manifest("invalid-schema", "policy", "schema_policy", None).replace(
        "    export: run\n",
        "    export: run\n    config_schema:\n      type: impossible\n",
    );
    write_bundle(temp.path(), "a-schema", &invalid_schema, b"schema");
    let schema_error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert!(
        schema_error.to_string().contains("Draft 7"),
        "{schema_error}"
    );

    std::fs::remove_dir_all(temp.path().join("a-schema")).unwrap();
    write_bundle(
        temp.path(),
        "digest",
        &manifest(
            "digest-bundle",
            "policy",
            "digest_policy",
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        ),
        b"actual",
    );
    let digest_error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert!(
        digest_error.to_string().contains("digest"),
        "{digest_error}"
    );
}

#[test]
fn traversal_symlink_escape_and_size_limits_are_rejected() {
    let temp = TempDir::new().unwrap();
    let bundle = temp.path().join("traversal");
    std::fs::create_dir(&bundle).unwrap();
    std::fs::write(temp.path().join("outside.js"), b"outside").unwrap();
    std::fs::write(
        bundle.join("bundle.yaml"),
        manifest("traversal", "policy", "traversal_policy", None)
            .replace("entry: entry.js", "entry: ../outside.js"),
    )
    .unwrap();
    let traversal =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert!(traversal.to_string().contains("traversal"), "{traversal}");

    std::fs::remove_dir_all(&bundle).unwrap();
    write_bundle(
        temp.path(),
        "symlink",
        &manifest("symlink", "policy", "symlink_policy", None),
        b"inside",
    );
    #[cfg(unix)]
    {
        std::fs::remove_file(temp.path().join("symlink/entry.js")).unwrap();
        std::os::unix::fs::symlink(
            temp.path().join("outside.js"),
            temp.path().join("symlink/entry.js"),
        )
        .unwrap();
        let symlink =
            DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
                .unwrap_err();
        assert!(symlink.to_string().contains("escape"), "{symlink}");
    }

    std::fs::remove_dir_all(temp.path().join("symlink")).unwrap();
    let oversized_manifest = temp.path().join("manifest-size");
    std::fs::create_dir(&oversized_manifest).unwrap();
    std::fs::write(
        oversized_manifest.join("bundle.yaml"),
        vec![b' '; sbproxy_config::MAX_BUNDLE_MANIFEST_BYTES + 1],
    )
    .unwrap();
    let manifest_size =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert!(
        manifest_size.to_string().contains("256 KiB"),
        "{manifest_size}"
    );
}

#[cfg(unix)]
#[test]
fn manifest_symlink_escape_is_rejected() {
    let source = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(
        outside.path().join("bundle.yaml"),
        manifest("outside", "policy", "outside_policy", None),
    )
    .unwrap();
    std::fs::create_dir(source.path().join("bundle")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("bundle.yaml"),
        source.path().join("bundle/bundle.yaml"),
    )
    .unwrap();

    let error = DynamicBundleRegistry::load(
        &local_config(source.path()),
        source.path(),
        &BTreeSet::new(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("escape"), "{error}");
}

#[test]
fn artifact_larger_than_sixteen_mib_is_rejected_without_loading_it() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "large",
        &manifest("large", "policy", "large_policy", None),
        b"placeholder",
    );
    let artifact = std::fs::File::create(temp.path().join("large/entry.js")).unwrap();
    artifact.set_len(16 * 1024 * 1024 + 1).unwrap();

    let error =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap_err();
    assert!(error.to_string().contains("16 MiB"), "{error}");
}

#[test]
fn git_source_uses_verified_materializer_and_safe_provenance() {
    let repository = TempDir::new().unwrap();
    let artifact = b"export function run() {}";
    let digest = hex::encode(Sha256::digest(artifact));
    write_bundle(
        &repository.path().join("extensions"),
        "git-bundle",
        &manifest("git-bundle", "policy", "git_policy", Some(&digest)),
        artifact,
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let context = FetchContext::with_cloner(Box::new(TreeCloner {
        source: repository.path().to_owned(),
        calls: calls.clone(),
    }))
    .with_credential(
        "https://secret@example.test/repo.git",
        "resolved-private-token",
    );
    let config = ExtensionBundlesConfig {
        grants: Default::default(),
        bundles_dir: None,
        sources: vec![BundleSourceConfig::Git {
            repo: "https://secret@example.test/repo.git".to_owned(),
            revision: "release-v1".to_owned(),
            path: "extensions".to_owned(),
            credential: Some("env:EXTENSION_PRIVATE_TOKEN".to_owned()),
            verify_signature: true,
            timeout_secs: 17,
            refresh_interval_secs: 0,
        }],
    };

    let registry = DynamicBundleRegistry::load_with_context(
        &config,
        repository.path(),
        &BTreeSet::new(),
        &context,
    )
    .unwrap();
    let call = &calls.lock().unwrap()[0];
    assert_eq!(call.1.as_deref(), Some("release-v1"));
    assert!(call.2);
    let hook = registry.policy("git_policy").unwrap();
    assert_eq!(hook.provenance().source(), ExtensionRegistrationSource::Git);
    let provenance = format!("{:?}", hook.provenance());
    assert!(provenance.contains("example.test/repo.git"), "{provenance}");
    assert!(!provenance.contains("secret"), "{provenance}");
    assert!(!provenance.contains(repository.path().to_string_lossy().as_ref()));
    assert_eq!(
        registry.inventory().hooks[0].runtime,
        ExtensionRuntime::Javascript
    );
    assert_eq!(
        registry.inventory().hooks[0].kind,
        ExtensionHookKind::Policy
    );
    assert_eq!(registry.revision_fingerprint(), COMMIT);
    assert_eq!(registry.git_revisions().len(), 1);
    assert_eq!(registry.git_revisions()[0].commit, COMMIT);
    assert_eq!(
        registry.inventory().bundles[0].load.detail.as_deref(),
        Some("https://example.test/repo.git at release-v1 (aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)")
    );
    let inventory = serde_json::to_string(registry.inventory()).expect("serialize inventory");
    assert!(!inventory.contains("secret"), "{inventory}");
    assert!(
        !inventory.contains("EXTENSION_PRIVATE_TOKEN"),
        "{inventory}"
    );
    assert!(!inventory.contains("resolved-private-token"), "{inventory}");
}

#[test]
fn git_rejects_missing_digest_mutable_revision_and_unresolved_credential() {
    let repository = TempDir::new().unwrap();
    write_bundle(
        &repository.path().join("extensions"),
        "git-bundle",
        &manifest("git-bundle", "policy", "git_policy", None),
        b"entry",
    );
    let context = FetchContext::with_cloner(Box::new(TreeCloner {
        source: repository.path().to_owned(),
        calls: Arc::new(Mutex::new(Vec::new())),
    }));
    let mut config = ExtensionBundlesConfig {
        grants: Default::default(),
        bundles_dir: None,
        sources: vec![BundleSourceConfig::Git {
            repo: "https://token@example.test/repo.git".to_owned(),
            revision: COMMIT.to_owned(),
            path: "extensions".to_owned(),
            credential: None,
            verify_signature: false,
            timeout_secs: 60,
            refresh_interval_secs: 60,
        }],
    };
    let missing_digest = DynamicBundleRegistry::load_with_context(
        &config,
        repository.path(),
        &BTreeSet::new(),
        &context,
    )
    .unwrap_err();
    assert!(
        missing_digest.to_string().contains("sha256"),
        "{missing_digest}"
    );

    if let BundleSourceConfig::Git { revision, .. } = &mut config.sources[0] {
        *revision = "main".to_owned();
    }
    let mutable = DynamicBundleRegistry::load_with_context(
        &config,
        repository.path(),
        &BTreeSet::new(),
        &context,
    )
    .unwrap_err();
    assert!(mutable.to_string().contains("mutable"), "{mutable}");

    if let BundleSourceConfig::Git {
        revision,
        credential,
        ..
    } = &mut config.sources[0]
    {
        *revision = COMMIT.to_owned();
        *credential = Some("env:PRIVATE_TOKEN".to_owned());
    }
    let credential = DynamicBundleRegistry::load_with_context(
        &config,
        repository.path(),
        &BTreeSet::new(),
        &context,
    )
    .unwrap_err();
    assert!(
        credential.to_string().contains("credential"),
        "{credential}"
    );
    assert!(!credential.to_string().contains("PRIVATE_TOKEN"));
    assert!(credential.to_string().len() <= 512);
}

#[test]
fn load_error_debug_and_display_are_bounded_and_hide_paths() {
    let missing = TempDir::new()
        .unwrap()
        .path()
        .join("private/absolute/missing");
    let error =
        DynamicBundleRegistry::load(&local_config(&missing), Path::new("."), &BTreeSet::new())
            .unwrap_err();
    assert!(error.to_string().len() <= 512);
    assert!(!error
        .to_string()
        .contains(missing.to_string_lossy().as_ref()));
    assert!(!format!("{error:?}").contains(missing.to_string_lossy().as_ref()));
    let _: &BundleLoadError = &error;
}

#[test]
fn entry_scope_bundles_written_before_digest_scope_existed_still_load() {
    let temp = TempDir::new().unwrap();
    let artifact = b"export function run() {}";
    let digest = hex::encode(Sha256::digest(artifact));
    write_bundle(
        temp.path(),
        "legacy",
        &manifest("legacy", "policy", "legacy_policy", Some(&digest)),
        artifact,
    );
    std::fs::write(temp.path().join("legacy/notes.txt"), b"shipped").unwrap();

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    let loaded = registry.policy("legacy_policy").unwrap();
    assert_eq!(loaded.manifest().digest_scope, BundleDigestScope::Entry);
    assert_eq!(loaded.sha256(), digest);

    // The narrow scope is exactly why it is named in the manifest. Editing a
    // file this digest never covered still loads, and the bundle says so.
    std::fs::write(temp.path().join("legacy/notes.txt"), b"tampered").unwrap();
    load_ok(temp.path());
}

#[test]
fn bundle_v1_digest_covers_the_manifest_permissions_line() {
    let temp = TempDir::new().unwrap();
    let template = bundle_v1_manifest("perms", "policy", "perms_policy");
    write_bundle_v1(
        temp.path(),
        "perms",
        &template,
        &[("entry.js", VALID_JAVASCRIPT)],
    );
    load_ok(temp.path());

    let manifest_path = temp.path().join("perms/bundle.yaml");
    let original = std::fs::read_to_string(&manifest_path).unwrap();

    // `permissions: [ ]` parses to the same empty list as `permissions: []`,
    // so no validation rule can tell the two files apart and only the digest
    // is left to notice the manifest moved.
    std::fs::write(
        &manifest_path,
        original.replace("permissions: []", "permissions: [ ]"),
    )
    .unwrap();
    let spaced = load_error(temp.path());
    assert!(
        spaced.to_string().contains("digest does not match"),
        "{spaced}"
    );

    // And the edit that the empty list is there to prevent. Two gates refuse
    // it today, the inactive-permissions rule and this digest; when
    // permissions become active the digest is the one that remains.
    std::fs::write(
        &manifest_path,
        original.replace("permissions: []", "permissions: [\"fs:read\"]"),
    )
    .unwrap();
    assert!(
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .is_err(),
        "a capability grant edited into a digested manifest must not load"
    );
}

#[test]
fn bundle_v1_digest_detects_a_tampered_non_entry_file() {
    let temp = TempDir::new().unwrap();
    let template = bundle_v1_manifest("data", "policy", "data_policy");
    write_bundle_v1(
        temp.path(),
        "data",
        &template,
        &[
            ("entry.js", VALID_JAVASCRIPT),
            ("assets/rules.json", "{\"deny\":[]}".as_bytes()),
        ],
    );
    load_ok(temp.path());

    std::fs::write(
        temp.path().join("data/assets/rules.json"),
        b"{\"deny\":[\"*\"]}",
    )
    .unwrap();

    let error = load_error(temp.path());
    assert!(
        error.to_string().contains("digest does not match"),
        "{error}"
    );
}

#[test]
fn bundle_v1_digest_detects_swapped_and_renamed_files() {
    let temp = TempDir::new().unwrap();
    let template = bundle_v1_manifest("swap", "policy", "swap_policy");
    write_bundle_v1(
        temp.path(),
        "swap",
        &template,
        &[
            ("entry.js", VALID_JAVASCRIPT),
            ("a.txt", "first".as_bytes()),
            ("b.txt", "second".as_bytes()),
        ],
    );
    load_ok(temp.path());

    // The same set of file contents under swapped names. A digest over bytes
    // alone would see an unchanged multiset and pass.
    std::fs::write(temp.path().join("swap/a.txt"), b"second").unwrap();
    std::fs::write(temp.path().join("swap/b.txt"), b"first").unwrap();
    let swapped = load_error(temp.path());
    assert!(
        swapped.to_string().contains("digest does not match"),
        "{swapped}"
    );

    // A plain rename moves the same bytes to a path the digest does not name.
    std::fs::write(temp.path().join("swap/a.txt"), b"first").unwrap();
    std::fs::remove_file(temp.path().join("swap/b.txt")).unwrap();
    std::fs::write(temp.path().join("swap/c.txt"), b"second").unwrap();
    let renamed = load_error(temp.path());
    assert!(
        renamed.to_string().contains("digest does not match"),
        "{renamed}"
    );
}

#[cfg(unix)]
#[test]
fn bundle_v1_refuses_symlinks_instead_of_following_them() {
    let temp = TempDir::new().unwrap();
    std::fs::write(temp.path().join("outside.txt"), b"outside").unwrap();
    let template = bundle_v1_manifest("linked", "policy", "linked_policy");
    write_bundle_v1(
        temp.path(),
        "linked",
        &template,
        &[("entry.js", VALID_JAVASCRIPT)],
    );
    load_ok(temp.path());

    // A link out of the bundle directory reads bytes the operator never
    // shipped, so it is refused rather than followed and hashed.
    let escape = temp.path().join("linked/escape.txt");
    std::os::unix::fs::symlink("../outside.txt", &escape).unwrap();
    let escaping = load_error(temp.path());
    assert!(escaping.to_string().contains("symlink"), "{escaping}");

    // An internal link is refused on the same rule: its bytes are named by a
    // target, and a target is not content the digest can cover.
    std::fs::remove_file(&escape).unwrap();
    std::os::unix::fs::symlink("entry.js", temp.path().join("linked/alias.js")).unwrap();
    let internal = load_error(temp.path());
    assert!(internal.to_string().contains("symlink"), "{internal}");
}

#[test]
fn bundle_v1_refuses_a_manifest_whose_digest_line_cannot_be_excluded() {
    let temp = TempDir::new().unwrap();
    let template = bundle_v1_manifest("quoted", "policy", "quoted_policy");
    write_bundle_v1(
        temp.path(),
        "quoted",
        &template,
        &[("entry.js", VALID_JAVASCRIPT)],
    );
    load_ok(temp.path());

    let manifest_path = temp.path().join("quoted/bundle.yaml");
    let original = std::fs::read_to_string(&manifest_path).unwrap();

    // A quoted key parses to the same field but hides the line from the
    // textual exclusion rule. Hashing it anyway would fold the digest into
    // its own input, so the bundle is refused instead.
    std::fs::write(
        &manifest_path,
        original.replacen("sha256: ", "\"sha256\": ", 1),
    )
    .unwrap();
    let quoted = load_error(temp.path());
    assert!(
        quoted.to_string().contains("cannot be canonicalized"),
        "{quoted}"
    );

    // A manifest with no terminating newline cannot round-trip through the
    // published line-oriented recipe either.
    std::fs::write(&manifest_path, original.trim_end()).unwrap();
    let unterminated = load_error(temp.path());
    assert!(
        unterminated.to_string().contains("cannot be canonicalized"),
        "{unterminated}"
    );
}

#[test]
fn bundle_v1_digest_is_stable_across_two_computations() {
    let temp = TempDir::new().unwrap();
    let template = bundle_v1_manifest("stable", "policy", "stable_policy");
    let pinned = write_bundle_v1(
        temp.path(),
        "stable",
        &template,
        &[
            ("entry.js", VALID_JAVASCRIPT),
            ("nested/deep/file.txt", "deep".as_bytes()),
        ],
    );
    let bundle = temp.path().join("stable");

    assert_eq!(pinned.len(), 64);
    assert_eq!(
        bundle_v1_digest_by_hand(&bundle),
        bundle_v1_digest_by_hand(&bundle)
    );
    assert_eq!(bundle_v1_digest_by_hand(&bundle), pinned);

    // The loader's implementation has to land on the same value twice, which
    // is the whole basis for pinning it in bundle.yaml.
    load_ok(temp.path());
    load_ok(temp.path());
}

// --- net:outbound (WOR-2424) ---

fn outbound_manifest(name: &str, destination: &str) -> String {
    format!(
        "apiVersion: sbproxy.dev/v1alpha1\nkind: Bundle\nname: {name}\nversion: 1.0.0\nruntime: javascript\nentry: entry.js\nhooks:\n  - kind: policy\n    type: outbound_probe\n    export: run\n    permissions:\n      - \"net:outbound={destination}\"\n"
    )
}

#[test]
fn a_declared_destination_without_a_grant_refuses_the_candidate() {
    let base = tempfile::TempDir::new().unwrap();
    write_bundle(
        base.path(),
        "prober",
        &outbound_manifest("prober", "https://api.example.test"),
        br#"export function run() { return {version:"sbproxy-envelope/v1",decision:"allow"}; }"#,
    );
    let config = local_config(base.path());
    let error = DynamicBundleRegistry::load(&config, base.path(), &BTreeSet::new()).unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains("has not granted"),
        "the refusal must say what is missing: {text}"
    );
    assert!(
        text.contains("https://api.example.test:443"),
        "the refusal must name the ungranted destination: {text}"
    );
    assert!(
        text.contains("grants nothing"),
        "the refusal must name the granted set: {text}"
    );
}

#[test]
fn a_granted_destination_loads_and_an_extra_grant_is_harmless() {
    let base = tempfile::TempDir::new().unwrap();
    write_bundle(
        base.path(),
        "prober",
        &outbound_manifest("prober", "https://api.example.test"),
        br#"export function run() { return {version:"sbproxy-envelope/v1",decision:"allow"}; }"#,
    );
    let mut config = local_config(base.path());
    config.grants.insert(
        "prober".to_owned(),
        vec![
            "net:outbound=https://api.example.test".to_owned(),
            "net:outbound=https://unused.example.test".to_owned(),
        ],
    );
    DynamicBundleRegistry::load(&config, base.path(), &BTreeSet::new())
        .expect("a fully granted declaration must load");
}

#[test]
fn a_granted_fetch_reaches_a_listener_and_an_undeclared_one_refuses() {
    // A one-shot local HTTP listener stands in for the destination.
    // Loopback grants are literal-address grants, which is exactly the
    // operator-typed internal-service case the allowlist admits.
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0u8; 4096];
        let _ = stream.read(&mut buffer);
        let body = b"granted-destination-body";
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
    });

    let base = tempfile::TempDir::new().unwrap();
    let source = format!(
        r#"export function run() {{
  const granted = JSON.parse(sbproxy_fetch(JSON.stringify({{url: "http://127.0.0.1:{port}/probe"}})));
  const refused = JSON.parse(sbproxy_fetch(JSON.stringify({{url: "https://never-granted.example.test/"}})));
  return {{version:"sbproxy-envelope/v1",decision:"deny",status:451,message:(granted.body_base64 || "none") + "|" + (refused.error || "none")}};
}}"#
    );
    write_bundle(
        base.path(),
        "prober",
        &outbound_manifest("prober", &format!("http://127.0.0.1:{port}")),
        source.as_bytes(),
    );
    let mut config = local_config(base.path());
    config.grants.insert(
        "prober".to_owned(),
        vec![format!("net:outbound=http://127.0.0.1:{port}")],
    );
    let registry = DynamicBundleRegistry::load(&config, base.path(), &BTreeSet::new())
        .expect("granted bundle loads");

    let policy = registry
        .policy("outbound_probe")
        .expect("policy hook present");
    let adapter = crate::bundle::javascript::build_javascript_policy(policy, serde_json::json!({}))
        .expect("adapter builds");
    let request = http::Request::builder()
        .method("GET")
        .uri("http://origin.test/")
        .body(bytes::Bytes::new())
        .unwrap();
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use sbproxy_plugin::PolicyEnforcer as _;
            let mut context: Box<dyn std::any::Any> = Box::new(());
            adapter.enforce(&request, context.as_mut()).await
        })
        .expect("hook evaluates");
    served.join().unwrap();

    let message = format!("{outcome:?}");
    // base64("granted-destination-body")
    use base64::Engine as _;
    let expected = base64::engine::general_purpose::STANDARD.encode(b"granted-destination-body");
    assert!(
        message.contains(&expected),
        "the granted fetch's body must reach the guest: {message}"
    );
    assert!(
        message.contains("egress_denied"),
        "the undeclared fetch must refuse with a bounded reason: {message}"
    );
}
