//! Schema-compat regression test for v1 (Go) sb.yml configs.
//!
//! MIGRATION.md and the v2 launch story both promise that an existing
//! `sb.yml` written for the Go implementation continues to load and
//! compile on the Rust v2 binary unmodified. This test pins that
//! promise: every fixture in `tests/v1-compat-fixtures/` is a real
//! v1-shape config (lifted from the Go repo's `tests/config-compat/`
//! suite) and must compile against the current schema.
//!
//! When a v1-style field is intentionally removed, this test fails
//! and the breaking change has to be called out in MIGRATION.md
//! before the test is updated.

use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("v1-compat-fixtures")
}

#[test]
fn v1_fixtures_compile_unmodified() {
    let dir = fixtures_dir();
    assert!(
        dir.is_dir(),
        "fixture directory missing at {}",
        dir.display()
    );

    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {}: {}", dir.display(), e))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yml"))
        .collect();
    files.sort();

    assert!(
        !files.is_empty(),
        "no v1-compat fixtures found in {}",
        dir.display()
    );

    let mut failures = Vec::new();
    for file in &files {
        let yaml = std::fs::read_to_string(file).unwrap_or_else(|e| {
            failures.push(format!("{}: read failed: {}", file.display(), e));
            String::new()
        });
        if yaml.is_empty() {
            continue;
        }
        if let Err(e) = sbproxy_config::compile_config(&yaml) {
            failures.push(format!("{}: compile_config: {}", file.display(), e));
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} of {} v1-compat fixtures failed to compile on the v2 schema:\n  {}\n\nIf this is intentional, update MIGRATION.md with the breaking change before adjusting the fixtures.",
            failures.len(),
            files.len(),
            failures.join("\n  ")
        );
    }
}
