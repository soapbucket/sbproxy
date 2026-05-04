//! Sweep every published example sb.yml and assert that
//! `compile_config` accepts it. Drift between an example file and the
//! current config schema breaks new-user onboarding silently; this
//! test catches that on every CI run.

use std::path::{Path, PathBuf};

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

fn enterprise_examples_root() -> Option<PathBuf> {
    // Enterprise examples are a sibling-of-sibling tree. They are
    // optional in OSS-only checkouts; skip when missing.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("sbproxy-enterprise/examples");
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
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

#[test]
fn every_oss_example_compiles() {
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
fn every_enterprise_example_compiles() {
    let root = match enterprise_examples_root() {
        Some(r) => r,
        None => {
            eprintln!("skipping: enterprise examples directory not present");
            return;
        }
    };
    let files = collect_yml_files(&root);
    if files.is_empty() {
        eprintln!("skipping: no enterprise example sb.yml files");
        return;
    }
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
            "{} of {} enterprise example(s) failed to compile:\n  {}",
            failures.len(),
            files.len(),
            summary
        );
    }
}
