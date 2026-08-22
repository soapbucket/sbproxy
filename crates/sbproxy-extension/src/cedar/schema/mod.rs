//! Cedar schema loading, workspace overrides, and validate-before-apply.
//!
//! Ships the default MCP schema as a static asset at
//! `data/mcp-schema.cedar` plus the schema-evolution refusal flow: when
//! a workspace proposes a new schema, [`validate_against_schema`]
//! re-checks every pinned policy against it and reports which ones
//! would break.

pub mod evolution;
pub mod mcp;

pub use evolution::{validate_against_schema, PinnedPolicy};
pub use mcp::{
    default_schema, merged_schema, McpSchemaConfig, SchemaError, DEFAULT_MCP_SCHEMA_SRC,
};

use serde::Serialize;

/// Per-policy refusal report produced when a schema change would
/// break pinned policies.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SchemaRefusalReport {
    /// `(policy_id, list_of_broken_type_or_action_references)` for
    /// each pinned policy that fails validation against the proposed
    /// schema.
    pub failed_policies: Vec<(uuid::Uuid, Vec<String>)>,
}

impl SchemaRefusalReport {
    /// `true` when no pinned policy failed validation, i.e. the
    /// schema change is safe to apply.
    pub fn is_clean(&self) -> bool {
        self.failed_policies.is_empty()
    }
}
