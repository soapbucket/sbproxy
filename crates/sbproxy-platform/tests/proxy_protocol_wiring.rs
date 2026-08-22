//! Keeps the PROXY protocol row in `docs/comparison.md` honest.
//!
//! `parse_proxy_protocol_v1` is a complete, well-tested v1 parser that nothing
//! calls. The comparison table advertised it as shipped support, which is the
//! worst shape a docs claim can take: an operator puts SBproxy behind an NLB
//! with PROXY protocol enabled, goes looking for the config key, and finds
//! none, while the load balancer's `PROXY TCP4 ...\r\n` preamble reaches the
//! HTTP parser as a request line and every connection 400s with the real
//! client IP nowhere in the access log, the WAF, or the IP filter.
//!
//! Two facts decide whether the feature is wired, and both are checkable:
//!
//! 1. An operator can only turn it on through configuration, so
//!    `crates/sbproxy-config` must name it.
//! 2. A listener has to call the parser, so some crate other than
//!    `sbproxy-platform` must reference it.
//!
//! # What this guard cannot see
//!
//! It cannot tell a production call site from a test one. Fact 2 is scoped to
//! *outside* `crates/sbproxy-platform`, so the parser's own unit tests do not
//! trip it, but an integration test elsewhere that exercises the parser
//! without a listener behind it would. That is deliberate: a caller outside
//! this crate is what "wired" looks like from here, so the guard asks for the
//! doc row to be revisited rather than guessing.

use std::fs;
use std::path::{Path, PathBuf};

/// The row to publish while the parser has no listener behind it.
const UNWIRED_ROW: &str = "| PROXY protocol | No (v1 parser present, not wired to a listener) |";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sbproxy-platform -> crates -> repo root")
        .to_path_buf()
}

/// Collect every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // `target/` under a crate directory is build output, not source.
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn files_mentioning(root: &Path, needle: &str, skip_prefix: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    for area in ["crates", "e2e"] {
        rust_files(&root.join(area), &mut sources);
    }
    sources
        .into_iter()
        .filter(|path| !path.starts_with(skip_prefix))
        .filter(|path| fs::read_to_string(path).is_ok_and(|text| text.contains(needle)))
        .collect()
}

#[test]
fn the_comparison_table_matches_whether_the_parser_is_actually_wired() {
    let root = repo_root();

    let callers = files_mentioning(
        &root,
        "parse_proxy_protocol_v1",
        &root.join("crates").join("sbproxy-platform"),
    );
    let config_keys = files_mentioning(
        &root,
        "proxy_protocol",
        &root.join("crates").join("sbproxy-platform"),
    )
    .into_iter()
    .filter(|path| path.starts_with(root.join("crates").join("sbproxy-config")))
    .collect::<Vec<_>>();

    let wired = !callers.is_empty() || !config_keys.is_empty();

    let comparison = fs::read_to_string(root.join("docs").join("comparison.md"))
        .expect("read docs/comparison.md");
    let claims_unwired = comparison.contains(UNWIRED_ROW);

    if wired {
        assert!(
            !claims_unwired,
            "PROXY protocol looks wired now (callers: {callers:?}, config: {config_keys:?}) \
             but docs/comparison.md still says it is parser-only. Update the row and \
             document the config key."
        );
    } else {
        assert!(
            claims_unwired,
            "Nothing calls parse_proxy_protocol_v1 and sbproxy-config has no \
             proxy_protocol key, so docs/comparison.md must carry the row:\n  \
             {UNWIRED_ROW}\nAdvertising PROXY protocol support an operator cannot \
             enable sends the real client IP nowhere and 400s every connection \
             behind a load balancer that sends the preamble."
        );
    }
}
