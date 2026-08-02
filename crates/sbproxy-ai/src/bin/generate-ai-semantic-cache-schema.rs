// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Generate the committed schema for an `ai_proxy` action's `semantic_cache`
//! block.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p sbproxy-ai --bin generate-ai-semantic-cache-schema \
//!   > schemas/ai-semantic-cache.schema.json
//! ```
//!
//! The top-level action node is intentionally polymorphic and opaque in the
//! main configuration schema. This dedicated schema gives editors and example
//! validation the exact route-scoped semantic-cache surface, including the
//! closed backend and embedding-source enums and every numeric bound that
//! `EmbeddingCacheConfig::validate` enforces at config load.

use sbproxy_ai::semantic_cache::config::EmbeddingCacheConfig;

fn main() {
    let schema = schemars::schema_for!(EmbeddingCacheConfig);
    let json =
        serde_json::to_string_pretty(&schema).expect("schema serializes to JSON without panic");
    println!("{json}");
}
