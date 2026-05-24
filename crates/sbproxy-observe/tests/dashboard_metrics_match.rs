//! Drift guard: every PromQL metric name referenced in
//! `dashboards/grafana/*.json` must be declared somewhere under
//! `crates/`. Spinning up the full binary just to scrape `/metrics`
//! is overkill for a CI gate, so this test grabs every distinct
//! `sbproxy_*` token from the dashboards and grep-matches each one
//! against the workspace source tree.
//!
//! Histogram series in Grafana are referenced by their auto-derived
//! `_bucket` / `_sum` / `_count` suffix; the Prometheus client
//! library generates those at scrape time. The test strips the
//! suffix before searching so a histogram declared as
//! `sbproxy_foo_seconds` matches a dashboard expression that uses
//! `sbproxy_foo_seconds_bucket`.
//!
//! Future merges that add a new dashboard panel (or rename a metric
//! in code) will fail this test until the two sides line up again.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Walk up from the test crate manifest dir to the repo root.
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/sbproxy-observe -> crates -> repo root
    manifest
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

/// All Grafana JSON files shipped under `dashboards/grafana/`.
fn dashboard_files(root: &Path) -> Vec<PathBuf> {
    let dir = root.join("dashboards").join("grafana");
    let mut out = Vec::new();
    let entries = fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {}", dir.display(), e));
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Scan a chunk of text and pull out every distinct identifier that
/// starts with `sbproxy_`. Tokens stop at any byte that is not
/// alphanumeric or underscore.
fn extract_sbproxy_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"sbproxy_") {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.insert(String::from_utf8_lossy(&bytes[start..i]).into_owned());
        } else {
            i += 1;
        }
    }
    out
}

/// Strip Prometheus auto-derived histogram suffixes so a dashboard
/// reference to `foo_seconds_bucket` matches a code declaration of
/// `foo_seconds`.
fn canonical_name(name: &str) -> &str {
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(stripped) = name.strip_suffix(suffix) {
            return stripped;
        }
    }
    name
}

/// Concatenate every `*.rs` file under `crates/` into a single search
/// buffer. Cheaper than spawning grep and gives the test a stable,
/// in-process source of truth.
fn collect_rust_sources(root: &Path) -> String {
    let crates = root.join("crates");
    let mut buf = String::new();
    walk_rs(&crates, &mut buf);
    buf
}

fn walk_rs(dir: &Path, buf: &mut String) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Skip cargo's own build artefacts; they balloon the scan
            // by two orders of magnitude and never contain source.
            if p.file_name().and_then(|s| s.to_str()) == Some("target") {
                continue;
            }
            walk_rs(&p, buf);
        } else if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(text) = fs::read_to_string(&p) {
                buf.push_str(&text);
                buf.push('\n');
            }
        }
    }
}

#[test]
fn every_dashboard_metric_is_declared_in_source() {
    let root = repo_root();
    let dashboards = dashboard_files(&root);
    assert!(
        !dashboards.is_empty(),
        "no Grafana dashboards found under dashboards/grafana/"
    );

    // Collect every metric name referenced by any dashboard.
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for path in &dashboards {
        let text =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        for tok in extract_sbproxy_tokens(&text) {
            referenced.insert(tok);
        }
    }

    let sources = collect_rust_sources(&root);
    let mut missing: Vec<String> = Vec::new();
    for name in &referenced {
        let canonical = canonical_name(name);
        // A metric is considered declared if its canonical name shows
        // up anywhere in the source tree. The Prometheus families are
        // consistently passed as a string literal to `Opts::new` /
        // `HistogramOpts::new` / `IntCounter*::new` so a plain
        // substring match is sufficient and avoids false negatives on
        // macro expansion.
        if !sources.contains(canonical) {
            missing.push(name.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "Grafana dashboards reference metrics that are not declared in any \
         crate under `crates/`. Either add the metric in code or fix the \
         dashboard:\n  {}",
        missing.join("\n  ")
    );
}
