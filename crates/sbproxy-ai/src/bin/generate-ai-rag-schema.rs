// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Generate the committed schema for an `ai_proxy` action's `rag` block.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p sbproxy-ai --bin generate-ai-rag-schema \
//!   > schemas/ai-rag.schema.json
//! ```
//!
//! The top-level action node is intentionally polymorphic and opaque in the
//! main configuration schema. This dedicated schema gives editors and example
//! validation the exact route-scoped retrieval surface without coupling
//! `sbproxy-config` back to `sbproxy-ai`.

use sbproxy_ai::rag_config::RagRouteConfig;

fn main() {
    let schema = schemars::schema_for!(RagRouteConfig);
    let json =
        serde_json::to_string_pretty(&schema).expect("schema serializes to JSON without panic");
    println!("{json}");
}
