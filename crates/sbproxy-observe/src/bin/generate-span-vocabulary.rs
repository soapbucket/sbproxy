// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Splice the executable span registry into `docs/observability.md`.
//!
//! Unlike `generate-metrics-stability`, which owns a whole file and prints
//! it, the span vocabulary is one block inside a hand-written document. So
//! this rewrites the file between its markers rather than printing to
//! stdout, and takes the path as an optional argument for anyone running it
//! from somewhere other than the workspace root.

use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use sbproxy_observe::span_registry;

fn doc_path() -> PathBuf {
    if let Some(path) = std::env::args().nth(1) {
        return PathBuf::from(path);
    }
    // crates/sbproxy-observe -> crates -> repo root.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent().and_then(Path::parent) {
        Some(root) => root.join("docs/observability.md"),
        None => manifest.join("../../docs/observability.md"),
    }
}

fn main() -> std::io::Result<()> {
    let path = doc_path();
    let committed = std::fs::read_to_string(&path)?;

    let Some(spliced) = span_registry::splice(&committed) else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "{} carries no generated span block. Add the markers back:\n  {}\n  {}",
                path.display(),
                span_registry::BLOCK_BEGIN,
                span_registry::BLOCK_END,
            ),
        ));
    };

    if spliced == committed {
        eprintln!("{} is already current", path.display());
        return Ok(());
    }

    std::fs::write(&path, spliced)?;
    eprintln!("{} span vocabulary regenerated", path.display());
    Ok(())
}
