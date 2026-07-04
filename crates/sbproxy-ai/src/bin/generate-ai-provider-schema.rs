// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! WOR-1686: generate the JSON Schema for an `ai_proxy` provider entry
//! (including the local-serving `serve:` block) from the
//! `sbproxy_ai::ProviderConfig` Rust type.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p sbproxy-ai --bin generate-ai-provider-schema \
//!   > schemas/ai-proxy-provider.schema.json
//! ```
//!
//! Why a separate schema. The top-level `sb-config.schema.json` keeps
//! `origins[].action` as an opaque object, on purpose: the action is
//! polymorphic across every action type (ai_proxy, mcp, grpc, ...) and
//! each carries a typed config that lives in a downstream crate
//! (sbproxy-ai, sbproxy-modules) which sbproxy-config cannot depend on
//! (that would be a dependency cycle). Typing that shared node to one
//! action would misrepresent the others. Instead this emits a
//! dedicated, committed schema for the ai_proxy provider block so an
//! editor pointed at it gets completion for the exact `serve:` surface
//! the self-hosting quickstart rides on. `ModelHostConfig` (the
//! `serve:` block) already derives `JsonSchema`; this pulls the
//! provider surface around it in.
//!
//! The CI gate runs the same command and diffs the committed file, so a
//! Rust type change that does not regenerate the schema is rejected at
//! PR time. Deterministic via schemars' `preserve_order`.

use sbproxy_ai::ProviderConfig;

fn main() {
    let schema = schemars::schema_for!(ProviderConfig);
    let json =
        serde_json::to_string_pretty(&schema).expect("schema serialises to JSON without panic");
    println!("{json}");
}
