//! Sweep every published example sb.yml and assert that
//! `compile_config` accepts it. Drift between an example file and the
//! current config schema breaks new-user onboarding silently; this
//! test catches that on every CI run.

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
/// loaded, so the sweep has to materialize one the way the example's README
/// tells a reader to. Owner-only, because the loader refuses a key any other
/// account on the box could read.
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

fn examples_root() -> PathBuf {
    // sbproxy-config lives at crates/sbproxy-config/ inside the workspace.
    // Ascend to the workspace root, then dive into examples/.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
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
            // Each example is `examples/<numbered-dir>/sb.yml`.
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
/// interpolate. compile_config leaves an unset `${VAR}` literal (and
/// hard-errors for admin credentials, WOR-1818), so the sweep exports
/// placeholders the way a user following each README would.
///
/// The mutation runs exactly once per test binary, inside a `OnceLock`
/// initializer, and every test calls this before its first environment
/// read; concurrent callers block until the environment is fully
/// populated, so a `set_var` can never race a parallel test's `getenv`
/// (WOR-646). The values stay exported for the life of the process:
/// they are this binary's fixture and every test reads them, so there
/// is nothing to restore. This is the only place this binary mutates
/// the environment.
fn export_example_env_dummies() {
    static EXPORTED: OnceLock<()> = OnceLock::new();
    EXPORTED.get_or_init(export_example_env_dummies_once);
}

fn export_example_env_dummies_once() {
    const DUMMIES: &[(&str, &str)] = &[
        ("OPENAI_API_KEY", "sk-test-dummy-openai"),
        ("ANTHROPIC_API_KEY", "sk-ant-test-dummy"),
        ("OPENROUTER_API_KEY", "sk-or-test-dummy"),
        ("GEMINI_API_KEY", "test-dummy-gemini"),
        ("GROQ_API_KEY", "gsk-test-dummy"),
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
        // The config-authority subscriber example names its credential
        // as a reference rather than an inline token, the way the
        // README tells a reader to.
        ("SB_CONFIG_AUTHORITY_TOKEN", "sbca1.example.dummy-token"),
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
}

#[test]
fn every_oss_example_compiles() {
    export_example_env_dummies();
    let root = examples_root();
    if !root.is_dir() {
        eprintln!(
            "skipping: examples directory not present at {}",
            root.display()
        );
        return;
    }
    let files = collect_yml_files(&root);
    assert!(
        !files.is_empty(),
        "no example sb.yml files found under {}",
        root.display()
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
        if let Err(e) = sbproxy_config::compile_config(&yaml) {
            failures.push(format!("{}: compile_config: {}", file.display(), e));
        }
    }
    if !failures.is_empty() {
        let summary = failures.join("\n  ");
        panic!(
            "{} of {} OSS example(s) failed to compile:\n  {}",
            failures.len(),
            files.len(),
            summary
        );
    }
}

/// The config-authority example ships three files and the sweep above only
/// picks up `sb.yml`. Both halves of the pair have to compile, and so does
/// the payload: a published bundle is validated as a configuration in its
/// own right, so an example payload that does not compile is an example of
/// something the authority would refuse.
#[test]
fn the_config_authority_example_compiles_on_both_sides_of_the_wire() {
    // The subscriber's credential (`SB_CONFIG_AUTHORITY_TOKEN`) is
    // part of the one-shot dummy export.
    export_example_env_dummies();
    let example = examples_root().join("config-authority");
    for name in ["sb.yml", "subscriber.yml", "bundle.yml"] {
        let file = example.join(name);
        let yaml = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: read failed: {error}", file.display()));
        sbproxy_config::compile_config(&yaml)
            .unwrap_or_else(|error| panic!("{}: compile_config: {error:#}", file.display()));
    }

    // And the pair really is a pair: the authority publishes, the
    // subscriber subscribes, and neither does both.
    let authority = std::fs::read_to_string(example.join("sb.yml")).expect("read sb.yml");
    let authority: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&authority).expect("parse sb.yml");
    let authority = authority
        .proxy
        .config_authority
        .expect("the example authority declares a config_authority block");
    assert!(authority.publishes_bundles());
    assert!(authority.upstream.is_none());

    let subscriber =
        std::fs::read_to_string(example.join("subscriber.yml")).expect("read subscriber.yml");
    let subscriber: sbproxy_config::ConfigFile =
        serde_yaml::from_str(&subscriber).expect("parse subscriber.yml");
    let subscriber = subscriber
        .proxy
        .config_authority
        .expect("the example subscriber declares a config_authority block");
    assert!(!subscriber.publishes_bundles());
    assert!(subscriber.upstream.is_some());
}

#[test]
fn classifier_routing_example_compiles() {
    export_example_env_dummies();
    let file = examples_root().join("ai-classifier-routing/sb.yml");
    let yaml = std::fs::read_to_string(&file)
        .unwrap_or_else(|error| panic!("{}: read failed: {error}", file.display()));
    sbproxy_config::compile_config(&yaml)
        .unwrap_or_else(|error| panic!("{}: compile_config: {error}", file.display()));
}

#[test]
fn every_split_model_cluster_role_compiles() {
    export_example_env_dummies();
    let example = examples_root().join("model-cluster-split");
    let files = ["gateway.yml", "worker-a.yml", "worker-b.yml"];

    for name in files {
        let file = example.join(name);
        let yaml = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: read failed: {error}", file.display()));
        sbproxy_config::compile_config(&yaml)
            .unwrap_or_else(|error| panic!("{}: compile_config: {error}", file.display()));
    }
}
