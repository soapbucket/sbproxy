//! Default MCP Cedar schema and workspace-override merging.
//!
//! The default schema declares the eight MCP entity types (`Agent`,
//! `AgentClass`, `User`, `Group`, `Server`, `Tool`, `ToolInvocation`,
//! `ArgumentBinding`) and the `MCP::` action namespace (`Initialize`,
//! `ListTools`, `CallTool`, `Ping`).
//!
//! Workspaces extend the schema by appending their own Cedar source
//! at compile time. Workspace overrides are namespaced under the
//! workspace's own prefix to avoid collisions with the default shape;
//! the merge step refuses any override that re-declares an entity
//! type or action name from the default schema.
//!
//! ## Disabling MCP primitives
//!
//! A workspace can opt out entirely with [`McpSchemaConfig::disabled`].
//! A caller then falls back to a generic principal/resource schema
//! and to action-level allow/deny on URL path + method.

use cedar_policy::{Schema, SchemaWarning};
use thiserror::Error;

/// The bundled default MCP schema, as Cedar source.
///
/// Lives at `crates/sbproxy-extension/data/mcp-schema.cedar`.
pub const DEFAULT_MCP_SCHEMA_SRC: &str = include_str!("../../../data/mcp-schema.cedar");

/// Default-schema and override-merge errors.
#[derive(Debug, Error)]
pub enum SchemaError {
    /// The bundled default schema failed to parse. This is a
    /// programmer error; the file is shipped with the binary and
    /// reviewed at every change.
    #[error("default schema parse failed: {0}")]
    DefaultParse(String),
    /// A workspace override failed to parse on its own.
    #[error("workspace override parse failed: {0}")]
    OverrideParse(String),
    /// The merged schema (default + override) failed to parse. This
    /// usually means the override re-declared a name that already
    /// exists in the default schema.
    #[error("merged schema parse failed: {0}")]
    MergedParse(String),
    /// The override declares an entity type or action that already
    /// exists in the default schema. We refuse rather than silently
    /// shadow.
    #[error("workspace override conflicts with default name: {0}")]
    Conflict(String),
}

/// Workspace-level schema configuration.
#[derive(Debug, Clone, Default)]
pub struct McpSchemaConfig {
    /// `false` ships the generic principal/resource model only; MCP
    /// primitives are not registered. Defaults to `true`.
    pub mcp_primitives_enabled: bool,
    /// Optional Cedar source the workspace appends to the default
    /// schema. Names declared here must not collide with the default
    /// schema; see the merge contract on [`merged_schema`].
    pub workspace_override: Option<String>,
}

impl McpSchemaConfig {
    /// Default config: MCP primitives on, no workspace override.
    pub fn enabled() -> Self {
        Self {
            mcp_primitives_enabled: true,
            workspace_override: None,
        }
    }

    /// Workspace has opted out of MCP primitives entirely.
    pub fn disabled() -> Self {
        Self {
            mcp_primitives_enabled: false,
            workspace_override: None,
        }
    }
}

/// Parse and return the bundled default MCP schema.
///
/// Surfaces parser warnings as a `Vec<SchemaWarning>` so an admin
/// view can report them; callers that don't care discard the second
/// tuple element.
pub fn default_schema() -> Result<(Schema, Vec<SchemaWarning>), SchemaError> {
    let (schema, warnings) = Schema::from_cedarschema_str(DEFAULT_MCP_SCHEMA_SRC)
        .map_err(|e| SchemaError::DefaultParse(e.to_string()))?;
    Ok((schema, warnings.collect()))
}

/// Build the effective schema for a workspace given its config.
///
/// - When [`McpSchemaConfig::mcp_primitives_enabled`] is `false`,
///   returns `Ok(None)`. A caller uses Cedar's generic anonymous
///   principal/resource schema in that mode.
/// - When `mcp_primitives_enabled` is `true` and no override is set,
///   returns `Ok(Some(default_schema()))`.
/// - When an override is provided, merges it with the default and
///   returns `Ok(Some(merged))`. Conflict detection runs first; an
///   override that re-declares a default name is rejected.
pub fn merged_schema(
    config: &McpSchemaConfig,
) -> Result<Option<(Schema, Vec<SchemaWarning>)>, SchemaError> {
    if !config.mcp_primitives_enabled {
        return Ok(None);
    }
    let Some(override_src) = config.workspace_override.as_deref() else {
        return Ok(Some(default_schema()?));
    };

    // Parse the override on its own first so a malformed override
    // surfaces as `OverrideParse` rather than `MergedParse`. This
    // matters for the admin-view error message: the operator wants to
    // know whether their override is wrong, or whether it collided
    // with the default.
    let _ = Schema::from_cedarschema_str(override_src)
        .map_err(|e| SchemaError::OverrideParse(e.to_string()))?;

    detect_conflicts(DEFAULT_MCP_SCHEMA_SRC, override_src)?;

    let merged_src = format!("{DEFAULT_MCP_SCHEMA_SRC}\n{override_src}");
    let (schema, warnings) = Schema::from_cedarschema_str(&merged_src)
        .map_err(|e| SchemaError::MergedParse(e.to_string()))?;
    Ok(Some((schema, warnings.collect())))
}

/// Lightweight conflict check that scans Cedar source text for
/// `entity X` and `action Y` declarations and flags any that appear
/// in both the default and the override.
///
/// Cedar's parser does not surface a structured "name already
/// declared" error in a stable shape across versions, so we run a
/// pre-flight pass over the source text. The check is deliberately
/// permissive: it matches Cedar's keyword + identifier surface
/// without trying to be a full parser. False positives are possible
/// in pathological cases (e.g. `entity` appearing inside a comment
/// the regex sees as code); when that happens the operator can rename
/// the offending declaration. False negatives let the merged
/// `Schema::from_cedarschema_str` catch the conflict downstream as
/// [`SchemaError::MergedParse`].
fn detect_conflicts(default_src: &str, override_src: &str) -> Result<(), SchemaError> {
    let default_names = collect_declared_names(default_src);
    let override_names = collect_declared_names(override_src);
    for name in &override_names {
        if default_names.contains(name) {
            return Err(SchemaError::Conflict(name.clone()));
        }
    }
    Ok(())
}

fn collect_declared_names(src: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("entity ") {
            if let Some(name) = read_identifier(rest) {
                names.insert(name);
            }
        } else if let Some(rest) = line.strip_prefix("action ") {
            // Cedar accepts both bareword (`action Foo`) and
            // string-literal (`action "Foo"`) action names. The
            // schema in this crate uses the literal form because the
            // actions carry the `MCP::` prefix.
            let trimmed = rest.trim_start();
            let name = if let Some(quoted) = trimmed.strip_prefix('"') {
                quoted.split('"').next().map(str::to_string)
            } else {
                read_identifier(trimmed)
            };
            if let Some(n) = name {
                names.insert(format!("Action::{n}"));
            }
        }
    }
    names
}

fn read_identifier(s: &str) -> Option<String> {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            out.push(ch);
        } else {
            break;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_schema_parses() {
        let (_schema, _warnings) = default_schema().expect("default parse");
    }

    #[test]
    fn default_schema_declares_eight_entity_types() {
        let names = collect_declared_names(DEFAULT_MCP_SCHEMA_SRC);
        for required in [
            "Agent",
            "AgentClass",
            "User",
            "Group",
            "Server",
            "Tool",
            "ToolInvocation",
            "ArgumentBinding",
        ] {
            assert!(
                names.contains(required),
                "default schema missing entity {required}"
            );
        }
    }

    #[test]
    fn merged_schema_returns_none_when_disabled() {
        let cfg = McpSchemaConfig::disabled();
        assert!(merged_schema(&cfg).unwrap().is_none());
    }

    #[test]
    fn merged_schema_returns_default_when_no_override() {
        let cfg = McpSchemaConfig::enabled();
        let result = merged_schema(&cfg).unwrap();
        assert!(result.is_some(), "expected default schema");
    }

    #[test]
    fn merged_schema_merges_compatible_override() {
        let cfg = McpSchemaConfig {
            mcp_primitives_enabled: true,
            workspace_override: Some(
                r#"
                entity AcmeWidget = {
                    sku: String,
                };
            "#
                .into(),
            ),
        };
        let result = merged_schema(&cfg).expect("merge ok");
        assert!(result.is_some(), "expected Some(schema)");
    }

    #[test]
    fn merged_schema_rejects_conflicting_entity_name() {
        let cfg = McpSchemaConfig {
            mcp_primitives_enabled: true,
            workspace_override: Some(
                r#"
                entity Server = {
                    rogue_field: String,
                };
            "#
                .into(),
            ),
        };
        let err = merged_schema(&cfg).expect_err("conflict");
        match err {
            SchemaError::Conflict(name) => assert_eq!(name, "Server"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn merged_schema_rejects_conflicting_action_name() {
        let cfg = McpSchemaConfig {
            mcp_primitives_enabled: true,
            workspace_override: Some(
                r#"
                entity AcmeServer;
                action "MCP::CallTool" appliesTo {
                    principal: [AcmeServer],
                    resource: [AcmeServer],
                };
            "#
                .into(),
            ),
        };
        let err = merged_schema(&cfg).expect_err("conflict");
        match err {
            SchemaError::Conflict(name) => assert!(name.contains("CallTool")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn malformed_override_returns_override_parse() {
        let cfg = McpSchemaConfig {
            mcp_primitives_enabled: true,
            workspace_override: Some("entity { not valid".into()),
        };
        let err = merged_schema(&cfg).expect_err("parse fail");
        assert!(matches!(err, SchemaError::OverrideParse(_)));
    }

    #[test]
    fn collect_declared_names_skips_comment_lines() {
        let src = r#"
            // entity FakeOne;
            entity RealOne;
            // action FakeAction
            action RealAction;
            action "Quoted::Name" appliesTo { principal: [RealOne], resource: [RealOne] };
        "#;
        let names = collect_declared_names(src);
        assert!(names.contains("RealOne"));
        assert!(names.contains("Action::RealAction"));
        assert!(names.contains("Action::Quoted::Name"));
        assert!(!names.contains("FakeOne"));
        assert!(!names.contains("Action::FakeAction"));
    }
}
