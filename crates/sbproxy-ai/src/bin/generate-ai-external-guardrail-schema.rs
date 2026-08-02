// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Generate the JSON Schema for an external AI guardrail entry.
//!
//! Run from the workspace root:
//!
//! ```text
//! cargo run -p sbproxy-ai --bin generate-ai-external-guardrail-schema \
//!   > schemas/ai-external-guardrail.schema.json
//! ```
//!
//! The schema describes the stable wire fields and their local ranges. A
//! provider selection makes some fields conditionally required, so the config
//! compiler remains the source of truth for those cross-field checks.

use sbproxy_ai::external_guardrail::ExternalGuardrailConfig;

fn main() {
    let mut schema = schemars::schema_for!(ExternalGuardrailConfig);
    schema.schema.metadata().title = Some("SBproxy AI external guardrail configuration".into());
    let json =
        serde_json::to_string_pretty(&schema).expect("schema serialises to JSON without panic");
    println!("{json}");
}
