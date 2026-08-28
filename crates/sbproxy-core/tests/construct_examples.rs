//! Sweep every published example sb.yml through full module construction:
//! `compile_config` followed by
//! `CompiledPipeline::from_config_for_validation`, the same declared-
//! dependency path used by the `validate` subcommand.
//!
//! The sibling sweep in `sbproxy-config/tests/validate_examples.rs`
//! stops at `compile_config`, which cannot see constructor-level
//! errors (a provider with both `serve:` and `base_url:`, a field typo
//! inside an opaque `policies:` blob). Five published examples passed
//! that sweep and refused to boot; this test closes the gap.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

struct RedisTlsExampleFixtures {
    _directory: tempfile::TempDir,
    ca_file: String,
    cert_file: String,
    key_file: String,
}

fn redis_tls_example_fixtures() -> &'static RedisTlsExampleFixtures {
    static FIXTURES: OnceLock<RedisTlsExampleFixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let directory = tempfile::tempdir().expect("create Redis TLS example fixture directory");
        let key = rcgen::KeyPair::generate().expect("generate Redis TLS example key");
        let certificate = rcgen::CertificateParams::new(vec!["redis-client.example".to_string()])
            .expect("create Redis TLS example certificate parameters")
            .self_signed(&key)
            .expect("self-sign Redis TLS example certificate");

        let ca_file = directory.path().join("ca.pem");
        let cert_file = directory.path().join("client.pem");
        let key_file = directory.path().join("client.key");
        std::fs::write(&ca_file, certificate.pem()).expect("write Redis TLS example CA");
        std::fs::write(&cert_file, certificate.pem())
            .expect("write Redis TLS example client certificate");
        std::fs::write(&key_file, key.serialize_pem()).expect("write Redis TLS example client key");

        RedisTlsExampleFixtures {
            _directory: directory,
            ca_file: ca_file.to_string_lossy().into_owned(),
            cert_file: cert_file.to_string_lossy().into_owned(),
            key_file: key_file.to_string_lossy().into_owned(),
        }
    })
}

/// A signing key for the config-authority example.
///
/// `compile_config` refuses a publishing node whose signing key cannot be
/// loaded, so the sweep has to materialize one the way that example's README
/// tells a reader to. Owner-only, because the loader refuses a key any other
/// account on the box could read. Absolute, because this sweep chdirs to the
/// workspace root.
fn config_authority_signing_key() -> &'static (tempfile::TempDir, String) {
    static FIXTURE: OnceLock<(tempfile::TempDir, String)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        use base64::Engine as _;

        let directory =
            tempfile::tempdir().expect("create config-authority example fixture directory");
        let path = directory.path().join("authority-signing.key");
        std::fs::write(
            &path,
            base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        )
        .expect("write config-authority example signing key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("tighten config-authority example signing key permissions");
        }
        let rendered = path.to_string_lossy().into_owned();
        (directory, rendered)
    })
}

fn workspace_root() -> PathBuf {
    // sbproxy-core lives at crates/sbproxy-core/ inside the workspace.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().parent().unwrap().to_path_buf()
}

fn collect_yml_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let candidate = path.join("sb.yml");
            if candidate.is_file() {
                out.push(candidate);
            }
        }
    }
    out.extend(
        ["upstream.yml", "api.yml", "mcp.yml", "sb.yml"]
            .into_iter()
            .map(|name| root.join("enterprise-ai-gateway").join(name)),
    );
    out.sort();
    out.dedup();
    out
}

/// Dummy values for every environment variable the published examples
/// interpolate, matching what a user following each README exports.
/// Constructor checks fail loud on unresolved credential references
/// (WOR-1818), so the sweep provides placeholders.
fn export_example_env_dummies() {
    static EXPORTED: OnceLock<()> = OnceLock::new();
    EXPORTED.get_or_init(export_example_env_dummies_once);
}

/// One-shot body of [`export_example_env_dummies`].
///
/// The mutation runs exactly once per test binary, inside a `OnceLock`
/// initializer, and every test calls the wrapper before its first
/// environment read; concurrent callers block until the environment is
/// fully populated, so a `set_var` can never race a parallel test's
/// `getenv` (WOR-646). The values stay exported for the life of the
/// process: they are this binary's fixture and every test reads them,
/// so there is nothing to restore. This is the only place this binary
/// mutates the environment.
fn export_example_env_dummies_once() {
    const DUMMIES: &[(&str, &str)] = &[
        ("OPENAI_API_KEY", "sk-test-dummy-openai"),
        ("ANTHROPIC_API_KEY", "sk-ant-test-dummy"),
        ("OPENROUTER_API_KEY", "sk-or-test-dummy"),
        ("GEMINI_API_KEY", "test-dummy-gemini"),
        ("GROQ_API_KEY", "gsk-test-dummy"),
        ("MISTRAL_API_KEY", "mistral-test-dummy"),
        ("TEAM_FRONTEND_KEY", "team-frontend-dummy"),
        ("TEAM_DATA_KEY", "team-data-dummy"),
        ("VAULT_TOKEN_SHARED", "vault-shared-dummy"),
        ("VAULT_TOKEN_ACME", "vault-acme-dummy"),
        ("INTERNAL_BEARER_TOKEN", "internal-dummy"),
        ("BEDROCK_AUTH", "bedrock-dummy"),
        ("AWS_SESSION_TOKEN", "aws-session-dummy"),
        ("ADMIN_PASSWORD", "admin-dummy"),
        (
            "MERCHANT_ADDRESS",
            "0x000000000000000000000000000000000000dEaD",
        ),
        (
            "LEDGER_SIGNING_SEED_HEX",
            "abababababababababababababababababababababababababababababababab",
        ),
        ("SB_SEED", "127.0.0.1:7946"),
        ("SB_NODE_ID", "node-test"),
        ("SB_ADVERTISE", "127.0.0.1:7946"),
        (
            "DIGEST",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        ("ENV_VAR", "dummy"),
        ("VAR", "dummy"),
        ("REDIS_PASSWORD", "redis-example-dummy"),
        // The extension-bundles HMAC auth hook resolves its shared secret
        // at pipeline construction, so building that example needs a value.
        ("SBPROXY_HMAC_SECRET", "worked-example-secret"),
        // The AI toolkit resolves every agent shared secret through the
        // same bounded resolver in validation as at runtime, so the
        // agent-orchestration example needs a value here too.
        ("SB_AGENT_SECRET", "agent-example-dummy"),
    ];
    for (k, v) in DUMMIES {
        std::env::set_var(k, v);
    }

    let redis = redis_tls_example_fixtures();
    std::env::set_var("REDIS_CA_FILE", &redis.ca_file);
    std::env::set_var("REDIS_CLIENT_CERT_FILE", &redis.cert_file);
    std::env::set_var("REDIS_CLIENT_KEY_FILE", &redis.key_file);

    let (_directory, signing_key) = config_authority_signing_key();
    std::env::set_var("SB_CONFIG_AUTHORITY_SIGNING_KEY", signing_key);

    // The two classifier-sidecar examples require a real, verified local
    // ONNX fallback. Published configs take operator-supplied absolute
    // paths and pins; the construction sweep supplies the repository's
    // deliberately tiny real-ONNX fixture pair instead.
    let classifier_fixtures = workspace_root()
        .join("crates")
        .join("sbproxy-classifiers")
        .join("tests")
        .join("fixtures");
    std::env::set_var(
        "SBPROXY_PROMPT_INJECTION_FALLBACK_MODEL_PATH",
        classifier_fixtures.join("tiny_classifier.onnx"),
    );
    std::env::set_var(
        "SBPROXY_PROMPT_INJECTION_FALLBACK_TOKENIZER_PATH",
        classifier_fixtures.join("tiny_tokenizer.json"),
    );
    std::env::set_var(
        "SBPROXY_PROMPT_INJECTION_FALLBACK_MODEL_SHA256",
        "ad7fcdb89a7ae4c926e132ce8bc9c4fc27aa6c87df1ebf1aab42c5fe6bec23ba",
    );
    std::env::set_var(
        "SBPROXY_PROMPT_INJECTION_FALLBACK_TOKENIZER_SHA256",
        "cbcbc48e5d42dd6c9166cecbaebeb397a51552f91599daa6076b8a78d112769b",
    );
}

#[test]
fn every_oss_example_constructs_its_pipeline() {
    export_example_env_dummies();
    let root = workspace_root();
    let examples = root.join("examples");
    if !examples.is_dir() {
        eprintln!(
            "skipping: examples directory not present at {}",
            examples.display()
        );
        return;
    }
    // Examples that read files at construction (WASM modules, CSV
    // redirect lists) use repo-root-relative paths, matching the
    // documented `make run CONFIG=examples/<dir>/sb.yml` invocation.
    std::env::set_current_dir(&root).expect("chdir to workspace root");

    let files = collect_yml_files(&examples);
    assert!(
        !files.is_empty(),
        "no example sb.yml files found under {}",
        examples.display()
    );
    let mut failures: Vec<String> = Vec::new();
    for file in &files {
        let yaml = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{}: read failed: {}", file.display(), e));
                continue;
            }
        };
        let compiled = match sbproxy_config::compile_config(&yaml) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("{}: compile_config: {:#}", file.display(), e));
                continue;
            }
        };
        // examples/ai-rag-local configures gateway-side retrieval, which
        // only exists behind the `rag` feature family. A default-feature
        // build of this crate compiles none of it, so the sweep expects
        // the documented missing-feature rejection there instead of a
        // successful construction. Every other outcome (any other error,
        // or an unexpected success without the feature) is a failure.
        let is_rag_example = file
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "ai-rag-local");
        let expect_missing_rag_feature = is_rag_example && !cfg!(feature = "rag");
        match sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
            compiled,
            file.parent()
                .expect("an example config should have a parent directory"),
        ) {
            Ok(_) => {
                if expect_missing_rag_feature {
                    failures.push(format!(
                        "{}: constructed without the `rag` feature; expected the \
                         \"rebuild with feature 'rag'\" rejection",
                        file.display()
                    ));
                }
            }
            Err(e) => {
                let rendered = format!("{:#}", e);
                if expect_missing_rag_feature && rendered.contains("rebuild with feature 'rag'") {
                    // Expected: the config is valid, this build just
                    // ships no RAG runtime.
                } else {
                    failures.push(format!(
                        "{}: pipeline construction: {}",
                        file.display(),
                        rendered
                    ));
                }
            }
        }
    }
    if !failures.is_empty() {
        let summary = failures.join("\n  ");
        panic!(
            "{} of {} example(s) failed module construction:\n  {}",
            failures.len(),
            files.len(),
            summary
        );
    }
}

/// Compose every published project profile against the runtime half
/// beside it, then run the result through the same module construction
/// the sweep above runs, and the same one `ConfigAuthority::publish`
/// runs before it signs anything.
///
/// The two sweeps that existed could not see this. `validate_examples`
/// and `every_oss_example_constructs_its_pipeline` both start from
/// `sb.yml`, where `origin_defaults` is an opaque `Mapping` and
/// `origin.yaml` is not a file either of them opens. So a published
/// project profile could name an action field that does not exist, a
/// policy type no module answers to, or an auth field a
/// `deny_unknown_fields` shim refuses, and every gate in the repository
/// stayed green while the aggregator's first publish would have been
/// refused. It shipped that way once; this is the check that would have
/// caught it.
///
/// Composition itself is pure, so this needs no git and no network: the
/// profile is read off disk as text exactly as the aggregator will hand
/// it in.
#[test]
fn every_example_origin_profile_composes_and_constructs() {
    export_example_env_dummies();
    let root = workspace_root();
    std::env::set_current_dir(&root).expect("chdir to workspace root");
    let examples = root.join("examples");
    if !examples.is_dir() {
        eprintln!("skipping: no examples directory at {}", examples.display());
        return;
    }

    let mut pairs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&examples)
        .expect("read examples/")
        .flatten()
    {
        let directory = entry.path();
        if directory.is_dir()
            && directory.join("origin.yaml").is_file()
            && directory.join("sb.yml").is_file()
        {
            pairs.push(directory);
        }
    }
    pairs.sort();
    assert!(
        !pairs.is_empty(),
        "no example directory carries both sb.yml and origin.yaml, so this sweep would pass \
         vacuously; if the origin-profiles example moved, move this with it"
    );

    let mut failures: Vec<String> = Vec::new();
    for directory in &pairs {
        let label = directory
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let runtime_text =
            std::fs::read_to_string(directory.join("sb.yml")).expect("sb.yml is readable");
        let profile =
            std::fs::read_to_string(directory.join("origin.yaml")).expect("origin.yaml readable");
        let runtime: sbproxy_config::ConfigFile = match serde_yaml::from_str(&runtime_text) {
            Ok(parsed) => parsed,
            Err(error) => {
                failures.push(format!("{label}: sb.yml does not parse: {error}"));
                continue;
            }
        };
        let Some(sources) = runtime.origin_sources.as_ref() else {
            failures.push(format!(
                "{label}: ships an origin.yaml but no `origin_sources:` to deploy it"
            ));
            continue;
        };
        let hand_written: std::collections::BTreeSet<String> =
            runtime.origins.keys().cloned().collect();
        let bindings: Vec<sbproxy_config::origin_profile::ProfileBinding<'_>> = sources
            .entries
            .iter()
            .map(|entry| sbproxy_config::origin_profile::ProfileBinding {
                entry,
                document: &profile,
                commit: None,
            })
            .collect();
        let resolution = match sbproxy_config::origin_profile::resolve_origins(
            runtime.origin_defaults.as_ref(),
            &bindings,
            &hand_written,
        ) {
            Ok(resolution) => resolution,
            Err(error) => {
                failures.push(format!("{label}: composition: {error}"));
                continue;
            }
        };
        assert!(
            !resolution.origins.is_empty(),
            "{label}: composed no origins, so constructing them proves nothing"
        );

        // Splice the composed origins into the runtime document and put
        // the whole thing through the real load path. Going back through
        // text rather than through the typed struct is deliberate: it is
        // what the aggregator publishes and what a node parses, so an
        // origin that only survives in memory is caught here.
        let mut document: serde_yaml::Value =
            serde_yaml::from_str(&runtime_text).expect("sb.yml re-parses as a value");
        let Some(map) = document.as_mapping_mut() else {
            failures.push(format!("{label}: sb.yml root is not a mapping"));
            continue;
        };
        // The composition blocks are the aggregator's input, not a
        // node's, and the composed document is what the fleet receives.
        map.remove("origin_sources");
        map.remove("origin_defaults");
        let origins = map
            .entry(serde_yaml::Value::String("origins".to_string()))
            .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
        let Some(origins) = origins.as_mapping_mut() else {
            failures.push(format!("{label}: `origins:` is not a mapping"));
            continue;
        };
        for (host, origin) in &resolution.origins {
            let value = serde_yaml::to_value(origin).expect("a composed origin re-serializes");
            origins.insert(serde_yaml::Value::String(host.clone()), value);
        }
        let composed_text =
            serde_yaml::to_string(&document).expect("the composed document serializes");

        let compiled = match sbproxy_config::compile_config(&composed_text) {
            Ok(compiled) => compiled,
            Err(error) => {
                failures.push(format!("{label}: composed compile_config: {error:#}"));
                continue;
            }
        };
        if let Err(error) = sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation_at(
            compiled, directory,
        ) {
            failures.push(format!(
                "{label}: composed pipeline construction: {error:#}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} example project profile(s) failed to compose and construct:\n  {}",
        failures.len(),
        pairs.len(),
        failures.join("\n  ")
    );
}

/// With the RAG adapters compiled in (`--features rag-full`, which the
/// released binary ships by default), the ai-rag-local example must
/// construct its pipeline end to end, not just compile its config.
#[cfg(feature = "rag-full")]
#[test]
fn ai_rag_local_constructs_with_rag_features() {
    export_example_env_dummies();
    let root = workspace_root();
    let file = root.join("examples").join("ai-rag-local").join("sb.yml");
    let yaml =
        std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("read {}: {}", file.display(), e));
    let compiled = sbproxy_config::compile_config(&yaml)
        .unwrap_or_else(|e| panic!("{}: compile_config: {:#}", file.display(), e));
    sbproxy_core::pipeline::CompiledPipeline::from_config_for_validation(compiled)
        .unwrap_or_else(|e| panic!("{}: pipeline construction: {:#}", file.display(), e));
}
