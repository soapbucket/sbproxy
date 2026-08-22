// SPDX-License-Identifier: Apache-2.0
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
//! `preserve_order` feature on `schemars` keeps schema property
//! order stable across runs, and this crate's own `serde_json`
//! dependency requests `preserve_order` too (WOR-2585) so the
//! `serde_json::to_value` of each type's default instance embedded
//! in the schema stays in declaration order regardless of whether
//! this binary is built alone or as part of `--workspace` (where
//! `sbproxy-extension`'s `cedar-policy-core` dependency forces the
//! same serde_json feature on regardless of this crate's manifest).
//! Either feature missing reintroduces a byte-for-byte diff between
//! the two invocations without changing a single field.
//!
//! The generation itself lives in [`sbproxy_config::config_json_schema`],
//! which the admin API also serves. Keeping it in one place is what makes
//! the served document and the committed file the same document rather
//! than two that agree until one of them is edited.

fn main() {
    println!("{}", sbproxy_config::config_json_schema());
}
