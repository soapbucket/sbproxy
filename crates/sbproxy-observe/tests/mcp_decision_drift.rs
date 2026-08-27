// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! The MCP OAuth enforcement-decision guard.
//!
//! `sbproxy_mcp_gateway_decisions_total` exists because the decisions it
//! counts are the ones no HTTP status alone reports. A resource-server
//! 401 looks like any other 401 on the MCP origin; a scope refusal is a
//! JSON-RPC error inside a 200; a stale authorization-server metadata
//! document is a fail-open with no status at all. The registry entry
//! names the surfaces that write this family, and `docs/mcp.md` repeats
//! the promise to whoever turns the broker on.
//!
//! Nothing enforced either promise. The counter is incremented from
//! plain function calls scattered across two crates, and deleting one
//! during a refactor takes a surface off the operator's dashboard while
//! the registry description, the catalog row, and the doc paragraph all
//! keep claiming it. That is the shape of failure this file removes: an
//! enforcement decision that stops being visible without anything going
//! red.
//!
//! The first run found the drift already there: the description named
//! seven surfaces and the code wrote nine. `authorize/cimd_unresolved`
//! and `token/cimd_unresolved` were being counted and documented
//! nowhere, which matters more than most because both answer a fixed
//! string on the wire by design.
//!
//! # What is checked
//!
//! 1. Every `record_broker_decision` call in production source passes
//!    labels this scanner can read, so the two directions below cannot
//!    quietly stop covering a call site.
//! 2. Every `(surface, decision)` pair [`PROMISED`] names is written by
//!    a real call in production source, outside the recorder's own
//!    definition and outside any `#[cfg(test)]` body.
//! 3. Every such call found in production source is in [`PROMISED`], so
//!    a surface added to the code without a row here fails too. The
//!    detector is as wide as the thing it detects, in both directions.
//! 4. The registry description for the family names each promised
//!    surface, so the catalog an operator reads cannot drift from the
//!    call sites.
//! 5. The three `record_mcp_*` helpers in `action_dispatch.rs`, which
//!    publish the typed decision-audit records beside the counter, each
//!    have a call site that is not their own definition.
//!
//! # What is not checked
//!
//! The unit is the call, not the branch. This guard proves the recorder
//! is called somewhere in a production file with the labels the registry
//! promises. It cannot prove the call sits on the refusal branch rather
//! than beside it, or that the branch is reachable from a request; that
//! needs the request path, and the crates' own tests cover the branches
//! themselves. What it does remove is the silent deletion.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-observe -> crates -> repo root")
        .to_path_buf()
}

/// The metric whose writers this file guards.
const FAMILY: &str = "sbproxy_mcp_gateway_decisions_total";

/// Every `(surface, decision)` pair the registry and `docs/mcp.md`
/// promise an operator, with the file that is supposed to write it.
///
/// A row here is a claim on the dashboard. Adding one without a call
/// site fails, and adding a call site without a row fails.
const PROMISED: &[(&str, &str, &str)] = &[
    // The resource server's 401. Indistinguishable from any other 401
    // on the MCP origin, which is why it is counted separately.
    (
        "resource_server",
        "unauthenticated",
        "crates/sbproxy-core/src/server/action_dispatch.rs",
    ),
    // The per-operation scope refusal: a JSON-RPC error inside a 200,
    // invisible to a status-code panel.
    (
        "scope",
        "refused",
        "crates/sbproxy-core/src/server/action_dispatch.rs",
    ),
    // Its fail-open twin. The mapping only applies when
    // `oauth.scopes_supported` advertises the scope, so a partial
    // vocabulary admits every call this check was meant to refuse. The
    // rubric requires a fail-open to be counted as one.
    (
        "scope",
        "admitted_unadvertised",
        "crates/sbproxy-core/src/server/action_dispatch.rs",
    ),
    // The `/authorize` fixed-window limiter, which exists so 4096
    // unauthenticated requests cannot wedge the session store.
    (
        "authorize",
        "rate_limited",
        "crates/sbproxy-mcp-gateway/src/authorize.rs",
    ),
    // The same limiter on `/par`.
    (
        "par",
        "rate_limited",
        "crates/sbproxy-mcp-gateway/src/par.rs",
    ),
    // The session store's fail-closed capacity refusal.
    (
        "authorize",
        "session_capacity",
        "crates/sbproxy-mcp-gateway/src/authorize.rs",
    ),
    // Serving stale authorization-server metadata after a refresh
    // failure. A fail-open bounded by `max_staleness_secs`, and a
    // `warn` alone is not a count.
    (
        "as_metadata",
        "stale_fallback",
        "crates/sbproxy-mcp-gateway/src/as_metadata.rs",
    ),
    // The device-code consent CSRF refusal: a missing or replayed form
    // token, or a cross-origin POST.
    (
        "verify",
        "csrf_refused",
        "crates/sbproxy-mcp-gateway/src/device_code.rs",
    ),
    // A CIMD document the broker could not resolve, on each of the two
    // endpoints that resolve one. The wire answer is a fixed string
    // (the detail would name the address a client-chosen URL resolved
    // to), so the counter is the only place an operator can see the
    // rate at which client-id metadata fetches are failing.
    (
        "authorize",
        "cimd_unresolved",
        "crates/sbproxy-mcp-gateway/src/authorize.rs",
    ),
    (
        "token",
        "cimd_unresolved",
        "crates/sbproxy-mcp-gateway/src/token.rs",
    ),
];

/// Production files that may write the family. Everything else is
/// scanned only to prove it does not.
fn production_rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // `tests/` and `examples/` are not the shipped request
                // path, and `target` is not source at all.
                if matches!(name, "tests" | "examples" | "target" | "benches") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Strip `#[cfg(test)]` items that have a body, so a recorder called
/// only from a test cannot satisfy a promise about production.
///
/// The attribute appears in three shapes in the crates scanned, and the
/// difference matters: `#[cfg(test)] mod tests { .. }` and
/// `#[cfg(test)] fn helper() { .. }` have a body to strip, while
/// `#[cfg(test)] mod test_env;` and `#[cfg(test)] use ..;` do not.
/// Taking the next `{` unconditionally would, on the third shape, strip
/// from some unrelated later block to its match and silently blind the
/// scanner to whatever sat in between. So: whichever of `;` and `{`
/// comes first decides.
///
/// Brace counting is enough for these files because none of them nests
/// a string literal holding unbalanced braces inside a test body.
fn strip_test_bodies(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(idx) = rest.find("#[cfg(test)]") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx..];
        let open = after.find('{');
        let semi = after.find(';');
        match (open, semi) {
            // A declaration with no body. Keep it and move past it;
            // there is nothing here that can hold a recorder call.
            (Some(o), Some(s)) if s < o => {
                out.push_str(&after[..=s]);
                rest = &after[s + 1..];
            }
            (None, Some(s)) => {
                out.push_str(&after[..=s]);
                rest = &after[s + 1..];
            }
            (Some(open), _) => {
                let mut depth = 0usize;
                let mut end = None;
                for (offset, ch) in after[open..].char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = Some(open + offset + 1);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                match end {
                    Some(end) => rest = &after[end..],
                    // Unbalanced: drop the rest rather than guess.
                    None => return out,
                }
            }
            (None, None) => return out,
        }
    }
    out.push_str(rest);
    out
}

/// The call this guard scans for.
const RECORDER: &str = "record_broker_decision(";

/// What one production call site turned out to be.
enum Site {
    /// A call with two string literals: the pair, and the file.
    Pair(String, String, String),
    /// A call whose labels are not literals, so this scanner cannot
    /// read them. Reported rather than skipped: a silent skip here is
    /// exactly the blindness the guard exists to remove. Carries
    /// `file:line`.
    Opaque(String),
}

/// Every `record_broker_decision` call in production source.
fn recorded_sites(root: &Path) -> Vec<Site> {
    let mut found = Vec::new();
    for path in production_rust_files(root) {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let source = strip_test_bodies(&raw);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let mut cursor = 0usize;
        while let Some(idx) = source[cursor..].find(RECORDER) {
            let call_start = cursor + idx;
            let start = call_start + RECORDER.len();
            let Some(close) = source[start..].find(')') else {
                break;
            };
            cursor = start + close;
            // The definition names its parameters rather than calling
            // anything, so skip it by its `fn ` prefix rather than by
            // its argument shape.
            let prefix_start = call_start.saturating_sub(8);
            if source[prefix_start..call_start].contains("fn ") {
                continue;
            }
            let args = &source[start..start + close];
            let literals: Vec<String> = args
                .split(',')
                .filter_map(|arg| {
                    let arg = arg.trim();
                    arg.strip_prefix('"')
                        .and_then(|a| a.strip_suffix('"'))
                        .map(str::to_string)
                })
                .collect();
            if literals.len() == 2 {
                found.push(Site::Pair(
                    literals[0].clone(),
                    literals[1].clone(),
                    rel.clone(),
                ));
            } else {
                let line = source[..call_start].matches('\n').count() + 1;
                found.push(Site::Opaque(format!("{rel}:{line}")));
            }
        }
    }
    found
}

/// The literal pairs among them.
fn recorded_pairs(root: &Path) -> Vec<(String, String, String)> {
    recorded_sites(root)
        .into_iter()
        .filter_map(|site| match site {
            Site::Pair(s, d, f) => Some((s, d, f)),
            Site::Opaque(..) => None,
        })
        .collect()
}

#[test]
fn every_production_call_site_is_readable_by_this_scanner() {
    let root = repo_root();
    let opaque: Vec<String> = recorded_sites(&root)
        .into_iter()
        .filter_map(|site| match site {
            Site::Opaque(where_) => Some(where_),
            Site::Pair(..) => None,
        })
        .collect();
    assert!(
        opaque.is_empty(),
        "a {RECORDER} call passes labels this scanner cannot read, so the two \
         directions below silently stop covering it. Pass string literals, or widen \
         the scanner and say here what it now understands.\n  {}",
        opaque.join("\n  ")
    );
}

#[test]
fn every_promised_decision_surface_has_a_production_writer() {
    let root = repo_root();
    let found = recorded_pairs(&root);
    let mut missing = Vec::new();
    for (surface, decision, file) in PROMISED {
        let hit = found
            .iter()
            .any(|(s, d, f)| s == surface && d == decision && f == file);
        if !hit {
            missing.push(format!("{surface}/{decision} expected in {file}"));
        }
    }
    assert!(
        missing.is_empty(),
        "{FAMILY} promises decision surfaces nothing writes.\n\
         The registry entry and docs/mcp.md tell an operator to watch these, so a \
         missing writer is a dashboard panel that can only ever draw zero.\n  {}\n\
         Found in production source: {found:#?}",
        missing.join("\n  ")
    );
}

#[test]
fn every_production_decision_write_is_a_promised_surface() {
    let root = repo_root();
    let found = recorded_pairs(&root);
    let mut unlisted = Vec::new();
    for (surface, decision, file) in &found {
        let listed = PROMISED
            .iter()
            .any(|(s, d, _)| s == surface && d == decision);
        if !listed {
            unlisted.push(format!("{surface}/{decision} at {file}"));
        }
    }
    assert!(
        unlisted.is_empty(),
        "a decision surface writes {FAMILY} without a row in PROMISED.\n\
         Add the row here and to the registry description, or the label appears on \
         an operator's dashboard with nothing documenting what it means.\n  {}",
        unlisted.join("\n  ")
    );
}

#[test]
fn the_registry_description_names_every_promised_surface() {
    let entry = sbproxy_observe::metric_registry::METRICS
        .iter()
        .find(|m| m.name == FAMILY)
        .expect("the decisions family is in the registry");
    let description = entry.description.to_lowercase();
    // The description is prose, not a label list, so match on the
    // recognizable noun for each surface rather than the label itself.
    let expected = [
        ("resource_server", "resource server"),
        ("scope", "scope refusal"),
        ("scope/admitted_unadvertised", "fail-open"),
        ("authorize", "/authorize"),
        ("par", "/par"),
        ("authorize/session_capacity", "session-capacity"),
        ("as_metadata", "as-metadata"),
        ("verify", "csrf"),
        ("cimd_unresolved", "client-id metadata document"),
    ];
    let missing: Vec<&str> = expected
        .iter()
        .filter(|(_, needle)| !description.contains(needle))
        .map(|(surface, _)| *surface)
        .collect();
    assert!(
        missing.is_empty(),
        "the registry description for {FAMILY} does not name {missing:?}.\n\
         docs/metrics-stability.md is generated from this string, so a surface \
         missing here is a surface an operator has no way to learn about.\n\
         Description: {}",
        entry.description
    );
    assert_eq!(
        entry.labels,
        &["surface", "decision"],
        "the label vocabulary this guard scans for is not the one the family declares"
    );
}

#[test]
fn the_typed_decision_recorders_are_called_where_the_refusal_is() {
    let root = repo_root();
    let path = root.join("crates/sbproxy-core/src/server/action_dispatch.rs");
    let raw = std::fs::read_to_string(&path).expect("action_dispatch.rs is readable");
    let source = strip_test_bodies(&raw);
    // Each of these publishes the typed decision-audit record beside
    // the counter, so the SIEM feed carries the refusal and not just
    // Prometheus. A definition with no caller is the failure.
    for recorder in [
        "record_mcp_broker_refusal",
        "record_mcp_authentication_refusal",
        "record_mcp_scope_decision",
    ] {
        let definition = format!("fn {recorder}(");
        let calls = source.matches(&format!("{recorder}(")).count();
        let definitions = source.matches(&definition).count();
        assert_eq!(
            definitions, 1,
            "{recorder} should be defined exactly once in action_dispatch.rs"
        );
        assert!(
            calls > definitions,
            "{recorder} is defined and never called, so the MCP refusal it publishes \
             reaches no decision-audit sink. docs/mcp.md tells operators it does."
        );
    }
}
