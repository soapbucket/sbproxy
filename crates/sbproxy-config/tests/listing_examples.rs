//! Integration test: every published example that ships a `listings/`
//! directory parses cleanly and validates against the example's
//! sibling `sb.yml`.
//!
//! Mirrors the `validate_examples.rs` sweep but for the Listing
//! surface. Picks up `examples/<NN>-*/listings/*.yaml` automatically
//! so a future ticket that drops a new Listing example does not need
//! to wire a one-off test.

use std::path::{Path, PathBuf};

use sbproxy_config::{
    load_listings_from_repo, validate_listings, ListingRegistry, NoopRevisionResolver, PlanFinding,
    Severity,
};

fn examples_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
}

fn collect_example_dirs_with_listings(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.join("listings").is_dir() && path.join("sb.yml").is_file() {
            out.push(path);
        }
    }
    out.sort();
    out
}

#[test]
fn every_example_with_listings_validates() {
    let root = examples_root();
    if !root.is_dir() {
        eprintln!(
            "skipping: examples directory not present at {}",
            root.display()
        );
        return;
    }
    let dirs = collect_example_dirs_with_listings(&root);
    assert!(
        !dirs.is_empty(),
        "no example directories with a listings/ subdir found under {}; \
         the WOR-136 sweep needs at least one example",
        root.display()
    );

    let mut failures: Vec<String> = Vec::new();

    for dir in &dirs {
        // Load the sibling sb.yml so we have the typed origins map.
        let yaml = match std::fs::read_to_string(dir.join("sb.yml")) {
            Ok(s) => s,
            Err(e) => {
                failures.push(format!("{}: read sb.yml failed: {}", dir.display(), e));
                continue;
            }
        };
        let cfg: sbproxy_config::ConfigFile = match serde_yaml::from_str(&yaml) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("{}: parse sb.yml failed: {}", dir.display(), e));
                continue;
            }
        };

        // Load Listings from the example's own root.
        let mut load_errors = Vec::new();
        let loaded = load_listings_from_repo(dir, &mut load_errors);
        if !load_errors.is_empty() {
            failures.push(format!(
                "{}: listing load errors: {:?}",
                dir.display(),
                load_errors
            ));
            continue;
        }
        if loaded.is_empty() {
            failures.push(format!(
                "{}: listings/ directory present but no listings parsed",
                dir.display()
            ));
            continue;
        }

        let mut findings: Vec<PlanFinding> = Vec::new();
        let registry = ListingRegistry::from_loaded(loaded, &mut findings);
        validate_listings(&registry, &cfg, &NoopRevisionResolver, &mut findings);

        let errors: Vec<&PlanFinding> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        if !errors.is_empty() {
            failures.push(format!(
                "{}: validation errors: {}",
                dir.display(),
                errors
                    .iter()
                    .map(|f| format!("[{}] {}: {}", f.rule_id, f.path, f.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }

    if !failures.is_empty() {
        let summary = failures.join("\n  ");
        panic!(
            "{} of {} example(s) with listings/ failed:\n  {}",
            failures.len(),
            dirs.len(),
            summary
        );
    }
}
