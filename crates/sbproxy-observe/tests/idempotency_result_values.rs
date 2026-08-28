// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The `sbproxy_idempotency_cache_results_total{result}` value set is a
//! closed set, and this is what keeps it closed (WOR-2606).
//!
//! # What went wrong without it
//!
//! The recorder's rustdoc is the declaration of record for this label:
//! it is what an operator reads before writing an alert, and
//! `docs/configuration.md` restates it as a table. Two independent
//! drifts had already happened by the time anyone looked.
//!
//! `in_flight` was declared in both places, described as "a live claim
//! was found on a path that cannot wait", and recorded by nothing at
//! all. An operator alerting on it got a series that never appeared,
//! which reads exactly like a control that is working.
//!
//! In the other direction, seven values were added to the code and the
//! rustdoc still named the original five. A value nothing declares is a
//! series nobody knows to look at.
//!
//! Neither is visible to the metric registry, which records label
//! *names* rather than values, and neither is visible to a unit test,
//! because the sites that record them are behind a Pingora session.
//! Both are visible here.
//!
//! # What this cannot see
//!
//! Whether a value is recorded on the *right* branch. This proves that
//! every declared value has at least one production recording site and
//! that every recorded literal is declared, not that the branch it sits
//! on is the condition the prose describes. Reading the arm is still
//! the reviewer's job.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-observe -> crates -> repo root")
        .to_path_buf()
}

/// The source of a file with every `#[cfg(test)]` item removed.
///
/// Skipping by brace balance rather than truncating at the first
/// `#[cfg(test)]`: several files in this workspace carry a test module
/// or a test-only helper among their production items, and truncating
/// there would hide every recording site after it. `request_phase.rs`
/// has one at line 146 and its recording sites near line 4100.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut lines = source.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test")) {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        // Skip the attributed item. An item with braces ends when the
        // balance returns to zero; one without (a `use`, a `const`)
        // ends at its semicolon.
        let mut depth: i32 = 0;
        let mut opened = false;
        for body in lines.by_ref() {
            depth += body.matches('{').count() as i32;
            depth -= body.matches('}').count() as i32;
            if body.contains('{') {
                opened = true;
            }
            if opened && depth <= 0 {
                break;
            }
            if !opened && body.trim_end().ends_with(';') {
                break;
            }
        }
    }
    out
}

/// Every string literal passed to a `record_idempotency_cache_result`
/// call, taken from the call's own parenthesised argument list so a
/// conditional such as `if took_over { "takeover" } else { "miss" }`
/// yields both.
fn recorded_values(production: &str) -> BTreeSet<String> {
    const CALL: &str = "record_idempotency_cache_result(";
    let mut found = BTreeSet::new();
    let mut search_from = 0usize;
    // Byte indices throughout. An earlier version collected a
    // `Vec<char>` and indexed it with byte offsets from `str::find`,
    // which drifts on the first non-ASCII character in the file and
    // then walks parentheses somewhere else entirely.
    while let Some(offset) = production[search_from..].find(CALL) {
        let call_start = search_from + offset;
        let open = call_start + CALL.len() - 1;
        search_from = open + 1;

        // The declaration is not a call site. Its parameter list holds
        // no literals, but the macro body below it does, and reading
        // one as the other is how this scan first reported the metric's
        // own name and help text as recorded values.
        let line_start = production[..call_start].rfind('\n').map_or(0, |i| i + 1);
        if production[line_start..call_start].contains("fn ") {
            continue;
        }

        let mut depth = 0i32;
        let mut end = None;
        for (index, ch) in production[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        let mut rest = &production[open..=end];
        while let Some(start) = rest.find('"') {
            let after = &rest[start + 1..];
            let Some(close) = after.find('"') else { break };
            found.insert(after[..close].to_string());
            rest = &after[close + 1..];
        }
        search_from = end + 1;
    }
    found
}

/// Every value the recorder's own rustdoc declares, taken from the
/// bullet list in the doc block above `record_idempotency_cache_result`.
fn declared_values(metrics_rs: &str) -> BTreeSet<String> {
    let anchor = metrics_rs
        .find("pub fn record_idempotency_cache_result")
        .expect("the recorder must exist");
    let block_start = metrics_rs[..anchor]
        .rfind("/// Record an idempotency-cache outcome")
        .expect("the recorder's doc block must exist");
    let mut declared = BTreeSet::new();
    for line in metrics_rs[block_start..anchor].lines() {
        let trimmed = line.trim_start();
        let Some(bullet) = trimmed.strip_prefix("/// * `") else {
            continue;
        };
        let Some(close) = bullet.find('`') else {
            continue;
        };
        declared.insert(bullet[..close].to_string());
    }
    assert!(
        declared.len() > 5,
        "the doc-block parse found only {declared:?}, so this test is not reading what it thinks"
    );
    declared
}

fn crate_sources(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `tests/` and `benches/` are not shipping code.
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name != "tests" && name != "benches" && name != "examples" {
                    stack.push(path);
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
                && path.components().any(|c| c.as_os_str() == "src")
            {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn every_declared_idempotency_result_value_is_recorded_somewhere() {
    let root = repo_root();
    let metrics_rs = std::fs::read_to_string(root.join("crates/sbproxy-observe/src/metrics.rs"))
        .expect("read metrics.rs");
    let declared = declared_values(&metrics_rs);

    let mut recorded = BTreeSet::new();
    for file in crate_sources(&root) {
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !source.contains("record_idempotency_cache_result(") {
            continue;
        }
        recorded.extend(recorded_values(&production_region(&source)));
    }
    assert!(
        !recorded.is_empty(),
        "the scan found no recording sites at all, so it is not reading the tree"
    );

    let declared_but_never_recorded: Vec<_> = declared.difference(&recorded).cloned().collect();
    assert!(
        declared_but_never_recorded.is_empty(),
        "these `result` values are declared in the recorder's rustdoc and recorded by nothing in \
         production, so an operator alerting on one gets a series that never appears: {:?}",
        declared_but_never_recorded
    );

    let recorded_but_never_declared: Vec<_> = recorded.difference(&declared).cloned().collect();
    assert!(
        recorded_but_never_declared.is_empty(),
        "these `result` values are recorded in production and named in no declaration, so nobody \
         knows to look at the series: {:?}",
        recorded_but_never_declared
    );
}

/// The configuration reference restates the same closed set as a table
/// an operator reads before writing an alert. It has to name the same
/// values as the rustdoc, in both directions.
#[test]
fn the_configuration_reference_names_the_same_result_values() {
    let root = repo_root();
    let metrics_rs = std::fs::read_to_string(root.join("crates/sbproxy-observe/src/metrics.rs"))
        .expect("read metrics.rs");
    let declared = declared_values(&metrics_rs);
    let reference =
        std::fs::read_to_string(root.join("docs/configuration.md")).expect("read configuration.md");

    let missing: Vec<_> = declared
        .iter()
        .filter(|value| !reference.contains(&format!("`{value}`")))
        .cloned()
        .collect();
    assert!(
        missing.is_empty(),
        "declared in the recorder's rustdoc and absent from docs/configuration.md: {missing:?}"
    );
}
