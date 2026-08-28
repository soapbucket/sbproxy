// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The request path never takes or publishes an idempotency key on a
//! proxy worker thread (WOR-2606).
//!
//! # Why a call-site guard
//!
//! `sbproxy_middleware::idempotency` ships two shapes of each
//! operation. `claim` and `record_response` are synchronous and run
//! wherever they are called; `claim_async` and
//! `record_response_detached` move the work onto the blocking pool for
//! any backend that answers `true` to `IdempotencyCache::blocks_on_io`.
//! On `KvIdempotencyCache` the synchronous pair is up to six Redis
//! round trips against a small blocking connection pool with a five
//! second acquire and a five second command timeout, and a Pingora
//! worker that blocks on one stops serving every other connection
//! assigned to it.
//!
//! Nothing in the type system separates the two. The first fix round
//! converted every call site it found and wrote the claim into
//! `blocks_on_io`'s own rustdoc ("the request path moves a backend that
//! answers `true` onto the blocking pool"), and missed one: the
//! validated-GraphQL late path kept the synchronous `claim`, so the one
//! surface the seam skipped was the one the rustdoc said it covered.
//! Converting a call site does not keep the next one converted, and a
//! reviewer reading a two thousand line filter cannot see which shape
//! each site uses. This can.
//!
//! # What this cannot see
//!
//! A synchronous call reached through a helper of this crate's own,
//! rather than named here directly, and any call site outside
//! `sbproxy-core`. The rule is only as wide as this crate's `src/`
//! tree, which is where every request-path call site lives today.

use std::path::{Path, PathBuf};

/// Production code only. A test that exercises the synchronous shape
/// on an in-process cache is exactly right, and several do.
///
/// Skipping by brace balance rather than truncating at the first
/// `#[cfg(test)]`: this crate has test modules among its production
/// items, and truncating at the first one would put most of the tree
/// outside the rule while reading as covered.
fn production_region(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut lines = source.lines().enumerate().peekable();
    while let Some((number, line)) = lines.next() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test")) {
            out.push_str(&format!("{}\t{line}\n", number + 1));
            continue;
        }
        let mut depth: i32 = 0;
        let mut opened = false;
        for (_, body) in lines.by_ref() {
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

fn crate_sources() -> Vec<PathBuf> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn the_request_path_never_claims_or_publishes_on_a_worker_thread() {
    // The synchronous shapes, and what to use instead. `::` is part of
    // each pattern so `claim_async(` and `record_response_detached(`
    // cannot match: they are different identifiers, not suffixes.
    const BLOCKING: [(&str, &str); 2] = [
        ("idempotency::claim(", "idempotency::claim_async(...).await"),
        (
            "idempotency::record_response(",
            "idempotency::record_response_detached(...)",
        ),
    ];

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();
    for file in crate_sources() {
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        if !BLOCKING.iter().any(|(pattern, _)| source.contains(pattern)) {
            continue;
        }
        let relative = file
            .strip_prefix(&manifest)
            .unwrap_or(Path::new("."))
            .display()
            .to_string();
        for line in production_region(&source).lines() {
            for (pattern, remedy) in BLOCKING {
                if line.contains(pattern) {
                    let (number, text) = line.split_once('\t').unwrap_or(("?", line));
                    violations.push(format!(
                        "  {relative}:{number} calls the blocking `{pattern}` on a request \
                         path; use `{remedy}`\n      {}",
                        text.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "A request-path call site takes or publishes an idempotency key synchronously. On the \
         redis backend that is up to six network round trips inside a Pingora worker, which \
         stops serving every other connection assigned to it while it waits.\n\n{}\n",
        violations.join("\n")
    );
}

/// The detector has to detect. Without this, deleting the pattern list
/// leaves a test that passes on every tree.
#[test]
fn the_call_site_guard_sees_a_blocking_call_among_production_items() {
    let source = "\
#[cfg(test)]
mod tests {
    fn allowed() {
        sbproxy_middleware::idempotency::claim(&cache, ws, key, lease);
    }
}

fn engage(ctx: &mut Ctx) -> bool {
    sbproxy_middleware::idempotency::claim(&cache, ws, key, lease);
    false
}
";
    let production = production_region(source);
    assert!(
        production.contains("fn engage"),
        "a leading test module ended the scan, so the rule covers nothing after it"
    );
    assert!(
        !production.contains("fn allowed"),
        "a test-module call site is not a violation"
    );
    assert_eq!(
        production
            .lines()
            .filter(|line| line.contains("idempotency::claim("))
            .count(),
        1,
        "the production call site must be the only one seen"
    );

    // And the async shape is not a false positive.
    let converted = production_region(
        "fn engage() { sbproxy_middleware::idempotency::claim_async(&c, w, k, l).await; }\n",
    );
    assert!(
        !converted.contains("idempotency::claim("),
        "`claim_async(` must not match the blocking `claim(` pattern"
    );
}
