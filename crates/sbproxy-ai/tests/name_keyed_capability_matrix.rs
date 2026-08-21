// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Provider capability is decided from the catalog type, never from the
//! provider's name.
//!
//! `multimodal.rs` carried a second capability matrix that answered
//! "can this provider do images" from a string literal: `("anthropic",
//! Modality::Image) => false`. Nothing called it, so nothing disagreed
//! with it, and the disagreement is the point. The wired matrix is
//! `api_routes::provider_supports_surface_for_modality`, which asks
//! `ProviderConfig::effective_provider_type()` and therefore follows a
//! provider an operator declared under any name. A name-keyed sibling
//! answers a different question and drifts the moment an operator names
//! their Anthropic-compatible origin `claude-eu`.
//!
//! # What this sees
//!
//! Every `.rs` file under this crate's `src/`, minus `api_routes.rs`,
//! flattened so a match arm split across lines still reads as one arm,
//! with `//` comments stripped. It flags a match arm whose pattern names
//! a provider as a string literal and whose body is a capability answer
//! (`true`, `false`, or a `matches!`). That covers both shapes the dead
//! matrix used, the bare `"openai" => true` and the crossed
//! `("openai", _) => true`.
//!
//! # What it does not see, and why that is stated rather than implied
//!
//! A ratchet that claims more than its detector covers is worse than no
//! ratchet, so plainly:
//!
//! * A capability decided by `if provider == "openai"`, by a `HashMap`
//!   keyed on the name, or by a `const` table. Only `match` arms are read.
//! * A provider name outside [`PROVIDER_NAMES`]. The list is explicit
//!   because a bare-word scan cannot tell a provider from any other
//!   string.
//! * A match arm whose body is a non-boolean stand-in for a capability,
//!   for example one returning `Option<Surface>`. `usage_parser.rs`
//!   selects a parser per provider name that way and is legitimate: it
//!   is decoding that provider's usage wire format, not deciding what
//!   the provider can do. Requiring a boolean body is what keeps that
//!   file out of an allowlist nobody would reread.
//! * Anything outside this crate. A name-keyed matrix in `sbproxy-core`
//!   is somebody else's guard.
//! * A block comment carrying an example arm. Only `//` comments are
//!   stripped.

use std::path::{Path, PathBuf};

/// Provider names a capability match could plausibly key on. The dead
/// matrix used the first six; the rest are the other names that appear
/// in this crate's provider handling today.
const PROVIDER_NAMES: &[&str] = &[
    "openai",
    "anthropic",
    "gemini",
    "cohere",
    "mistral",
    "groq",
    "bedrock",
    "vertex",
    "azure",
    "azure-openai",
    "deepseek",
    "ollama",
    "together",
    "fireworks",
    "perplexity",
    "xai",
];

/// The one file allowed to answer a capability question, and only
/// because it re-derives the name from `effective_provider_type()`
/// first. See the surface matrix in `api_routes.rs`.
const CATALOG_KEYED_MATRIX: &str = "api_routes.rs";

/// Bodies that make a match arm a capability answer rather than a
/// dispatch table.
const CAPABILITY_BODIES: &[&str] = &["true", "false", "matches!", "!matches!"];

/// How far past a provider literal an arm's `=>` may sit. Long enough
/// for `("anthropic", Modality::Embedding)`, short enough that an
/// unrelated `=>` further down the flattened file is not read as this
/// literal's body.
const ARM_WINDOW: usize = 120;

/// Characters that end whatever the provider literal was part of. A
/// second quote means the next arm alternative or an unrelated string,
/// and the braces and semicolon mean a different statement entirely.
const ARM_STOPPERS: &[char] = &['"', ';', '{', '}'];

fn source_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("crate source directory is readable") {
        let entry = entry.expect("directory entry is readable");
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Drop `//` comments and collapse the file to one line, so an arm
/// written across three lines reads the same as one written across one.
fn flatten(source: &str) -> String {
    let mut flat = String::with_capacity(source.len());
    for line in source.lines() {
        let code = match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        };
        flat.push_str(code.trim());
        flat.push(' ');
    }
    flat
}

/// Walk `end` back to a character boundary so a non-ASCII byte inside a
/// nearby string literal cannot panic the slice.
fn clamp_to_boundary(text: &str, end: usize) -> usize {
    let mut end = end.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn starts_with_capability_body(rest: &str) -> bool {
    let rest = rest.trim_start();
    CAPABILITY_BODIES.iter().any(|body| {
        rest.strip_prefix(body).is_some_and(|tail| {
            // `true` and `false` need a word boundary; `matches!` already
            // carries its own.
            !tail.starts_with(|c: char| c.is_alphanumeric() || c == '_')
        })
    })
}

/// Every capability-answering match arm keyed on a provider name.
fn name_keyed_capability_arms(flat: &str) -> Vec<String> {
    let mut found = Vec::new();
    for name in PROVIDER_NAMES {
        let literal = format!("\"{name}\"");
        let mut from = 0;
        while let Some(at) = flat[from..].find(&literal) {
            let after = from + at + literal.len();
            from = after;
            let window = &flat[after..clamp_to_boundary(flat, after + ARM_WINDOW)];
            let Some(arrow) = window.find("=>") else {
                continue;
            };
            if window[..arrow].contains(ARM_STOPPERS) {
                continue;
            }
            if starts_with_capability_body(&window[arrow + 2..]) {
                let start = after - literal.len();
                let end = clamp_to_boundary(flat, after + arrow + 32);
                found.push(flat[start..end].trim().to_string());
            }
        }
    }
    found
}

/// A provider's capabilities come from its catalog type. Any file here
/// that answers them from the provider's name is a second source of
/// truth, and the two will disagree.
#[test]
fn no_capability_match_is_keyed_on_a_provider_name() {
    let root = source_root();
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);
    assert!(!sources.is_empty(), "found no sources under {root:?}");

    let mut offenders = Vec::new();
    for path in sources {
        if path.file_name().is_some_and(|f| f == CATALOG_KEYED_MATRIX) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("source file is readable UTF-8");
        for arm in name_keyed_capability_arms(&flatten(&source)) {
            offenders.push(format!("{}: {arm}", path.display()));
        }
    }

    assert!(
        offenders.is_empty(),
        "capability answered from a provider's name rather than its catalog type.\n\
         Route the question through `api_routes::provider_supports_surface_for_modality`,\n\
         which reads `ProviderConfig::effective_provider_type()`, so an operator who names\n\
         an Anthropic-compatible origin `claude-eu` still gets the Anthropic answer:\n{}",
        offenders.join("\n")
    );
}

/// The deleted pair by name, so a revert that restores the module fails
/// here even if it renames the arms out of the scan above.
#[test]
fn the_name_keyed_modality_matrix_does_not_come_back() {
    let root = source_root();
    let mut sources = Vec::new();
    rust_sources(&root, &mut sources);

    let mut offenders = Vec::new();
    for path in sources {
        let source = std::fs::read_to_string(&path).expect("source file is readable UTF-8");
        for symbol in [
            "fn provider_supports_modality",
            "fn filter_providers_by_modality",
        ] {
            if source.contains(symbol) {
                offenders.push(format!("{}: {symbol}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "the name-keyed modality matrix is back. It has no production caller and it\n\
         contradicts the catalog-keyed matrix in api_routes.rs:\n{}",
        offenders.join("\n")
    );
}
