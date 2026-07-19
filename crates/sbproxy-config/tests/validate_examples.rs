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
    out.sort();
    out
}

/// Dummy values for every environment variable the published examples
/// interpolate. compile_config leaves an unset `${VAR}` literal (and
/// hard-errors for admin credentials, WOR-1818), so the sweep exports
/// placeholders the way a user following each README would.
fn export_example_env_dummies() {
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
    ];
    for (k, v) in DUMMIES {
        std::env::set_var(k, v);
    }

    let redis = redis_tls_example_fixtures();
    std::env::set_var("REDIS_CA_FILE", &redis.ca_file);
    std::env::set_var("REDIS_CLIENT_CERT_FILE", &redis.cert_file);
    std::env::set_var("REDIS_CLIENT_KEY_FILE", &redis.key_file);
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
