use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sbproxy_config::{
    BundleHookKind, BundleSourceConfig, Cloner, ConfigSourceError, ExtensionBundlesConfig,
    FetchContext, FetchRequest, ResolvedRevision,
};
use sbproxy_plugin::{ExtensionHookKind, ExtensionRegistrationSource, ExtensionRuntime};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{BundleLoadError, BundleRegistry, DynamicBundleRegistry};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
    }
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
        b"short",
    );
    write_bundle(
        &base.path().join("declared-one"),
        "bundle",
        &manifest("declared-one", "policy", "collision", None),
        b"one",
    );
    let config = ExtensionBundlesConfig {
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
        b"a",
    );
    write_bundle(
        temp.path(),
        "b",
        &manifest("bundle-b", "policy", "claimed", None),
        b"b",
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
        b"policy",
    );
    write_bundle(
        temp.path(),
        "action",
        &manifest("action-bundle", "action", "shared", None),
        b"action",
    );

    let registry =
        DynamicBundleRegistry::load(&local_config(temp.path()), temp.path(), &BTreeSet::new())
            .unwrap();
    assert!(registry.policy("shared").is_some());
    assert!(registry.action("shared").is_some());
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
    write_bundle(temp.path(), "bundle", &schema_manifest, b"entry");
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
    }));
    let config = ExtensionBundlesConfig {
        bundles_dir: None,
        sources: vec![BundleSourceConfig::Git {
            repo: "https://secret@example.test/repo.git".to_owned(),
            revision: "release-v1".to_owned(),
            path: "extensions".to_owned(),
            credential: None,
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
