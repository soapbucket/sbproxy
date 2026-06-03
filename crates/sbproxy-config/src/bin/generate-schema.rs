// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Soap Bucket LLC

//! WOR-1081: generate the JSON Schema for `sb.yml` from the
//! `sbproxy_config::ConfigFile` Rust type.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p sbproxy-config --bin generate-schema > schemas/sb-config.schema.json
//! ```
//!
//! The CI gate runs the same command and `git diff --exit-code
//! schemas/` so a Rust type change that does not regenerate the
//! schema is rejected at PR time.
//!
//! The output is committed at `schemas/sb-config.schema.json` and
//! consumed by editor tooling (vscode-yaml, IntelliJ) via the
//! `# yaml-language-server: $schema=...` opt-in header on each
//! `examples/*/sb.yml`. The generator is deterministic: the
//! `preserve_order` feature on `schemars` keeps object property
//! order stable across runs so the diff is byte-for-byte.

use sbproxy_config::ConfigFile;

fn main() {
    let schema = schemars::schema_for!(ConfigFile);
    let json =
        serde_json::to_string_pretty(&schema).expect("schema serialises to JSON without panic");
    println!("{json}");
}
