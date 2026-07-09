//! Sweep every published example sb.yml through the full boot-time
//! construction path: `compile_config` followed by
//! `CompiledPipeline::from_config`, the same pair the server, the
//! reload handler, and (since WOR-1815) the `validate` subcommand run.
//!
//! The sibling sweep in `sbproxy-config/tests/validate_examples.rs`
//! stops at `compile_config`, which cannot see constructor-level
//! errors (a provider with both `serve:` and `base_url:`, a field typo
//! inside an opaque `policies:` blob). Five published examples passed
//! that sweep and refused to boot; this test closes the gap.

use std::path::{Path, PathBuf};

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
    out.sort();
    out
}

/// Dummy values for every environment variable the published examples
/// interpolate, matching what a user following each README exports.
/// Constructor checks fail loud on unresolved credential references
/// (WOR-1818), so the sweep provides placeholders.
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
    ];
    for (k, v) in DUMMIES {
        std::env::set_var(k, v);
    }
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
        if let Err(e) = sbproxy_core::pipeline::CompiledPipeline::from_config(compiled) {
            failures.push(format!(
                "{}: pipeline construction: {:#}",
                file.display(),
                e
            ));
        }
    }
    if !failures.is_empty() {
        let summary = failures.join("\n  ");
        panic!(
            "{} of {} example(s) failed boot-time construction:\n  {}",
            failures.len(),
            files.len(),
            summary
        );
    }
}
