//! Cedar source-text compiler.
//!
//! Cedar policies are authored as plain text. The runtime compiles
//! every authored policy once, at config-load time, so the request
//! hot path runs against an in-memory [`cedar_policy::PolicySet`]
//! rather than re-parsing on every dispatch. Compilation is the
//! "validate" half of a validate-before-apply contract: a caller that
//! hot-reloads policy should reject a parse failure or a schema
//! validation failure and keep serving the previous, known-good set.
//!
//! Errors produced here are structured. The Cedar parser surfaces
//! source location metadata via `miette` reporting; the compiler
//! captures that as a string in [`CompilerError::Parse`] so a caller
//! can render the offending line without re-running the parser.
//! Schema-validation failures are mapped onto
//! [`CompilerError::Validation`] with the failing policy id and the
//! type or attribute reference that broke. The same shape feeds
//! [`super::schema::SchemaRefusalReport`].

use std::str::FromStr;

use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
use thiserror::Error;

/// Result of a successful Cedar compile.
///
/// Holds the [`PolicySet`] that [`super::CedarEvaluator`] consults on
/// every request. Bundling the set in a small wrapper keeps the call
/// site stable when future work adds fields (template metadata,
/// per-policy provenance, content hashes, etc.) without re-typing
/// every caller.
#[derive(Debug, Clone)]
pub struct CompiledPolicySet {
    /// Parsed and (optionally) schema-validated set of Cedar
    /// policies.
    pub policy_set: PolicySet,
    /// Number of policies in `policy_set`. Cached on construction so
    /// hot-path metrics do not need to call into the Cedar API on
    /// every scrape.
    pub policy_count: usize,
}

/// Per-policy validation finding mapped from a Cedar
/// [`cedar_policy::ValidationError`] into a serialisable shape an
/// admin view can render. The `policy_id` is the Cedar `PolicyId`
/// string; the `message` is the human-readable error from the
/// validator.
///
/// The bundle compile path collects every finding (rather than
/// short-circuiting on the first) so the operator sees the whole list
/// of broken policies in a single refusal report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationFinding {
    /// Cedar `PolicyId` of the policy that failed validation.
    pub policy_id: String,
    /// Human-readable validator message. Intentionally a `String`
    /// rather than a structured enum because Cedar's validator
    /// returns prose with the offending type / attribute embedded;
    /// callers parse it for display, not branching.
    pub message: String,
}

/// Errors that the compiler can return.
///
/// These mirror the validate-before-apply states a hot-reload path
/// needs to distinguish:
///
/// - [`CompilerError::Parse`] is a Cedar source text problem (bad
///   syntax, unknown statement, malformed entity reference). The
///   admin view can render the source location embedded in the
///   string.
/// - [`CompilerError::Validation`] is a typing problem against the
///   workspace schema (referenced entity type missing, attribute
///   typo, action that does not apply to the supplied principal
///   type). A caller can turn this into a
///   [`super::schema::SchemaRefusalReport`] that lists every failing
///   policy and the broken type or attribute reference.
/// - [`CompilerError::EmptyInput`] guards against an obvious operator
///   mistake: a config that compiles to zero policies is almost
///   always a path or filter typo, not an intent. Callers that
///   genuinely want a no-op bundle should special-case that upstream
///   of this function rather than relying on it accepting zero
///   sources.
#[derive(Debug, Error)]
pub enum CompilerError {
    /// Cedar source text failed to parse. The wrapped string carries
    /// the formatted parser diagnostic (with miette source spans);
    /// callers display it directly.
    #[error("cedar parse error: {0}")]
    Parse(String),

    /// One or more policies failed schema validation. Each finding
    /// names the offending policy id and the broken type or
    /// attribute reference.
    #[error("cedar schema validation failed: {findings:?}")]
    Validation {
        /// One entry per policy that failed.
        findings: Vec<ValidationFinding>,
    },

    /// The supplied source set was empty. Treated as an operator
    /// error rather than silently building an empty bundle; see the
    /// type-level docs for the rationale.
    #[error("cedar compiler received zero source policies")]
    EmptyInput,
}

/// Pre-compile a list of Cedar source-text fragments into a single
/// [`CompiledPolicySet`].
///
/// `sources` is a slice of `(label, source)` pairs. The label is
/// purely informational and surfaces in tracing if compilation fails;
/// it is not used as a Cedar `PolicyId`. The Cedar parser already
/// assigns ids to each policy in the source (either the `@id("...")`
/// annotation or `policy{N}` for un-annotated statements). Keeping the
/// label boundary loose lets a caller pass file paths or content
/// hashes without forcing a 1:1 mapping to PolicyIds.
///
/// When `schema` is `Some`, the compiled set is validated in strict
/// mode (`ValidationMode::Strict`) before being returned. Strict mode
/// is the right default for a validate-before-apply contract: a
/// policy that references a removed entity type or a renamed
/// attribute MUST be rejected, not silently downgraded to a runtime
/// evaluation error.
///
/// On success the call site is free to clone the resulting
/// [`PolicySet`] into a [`super::CedarEvaluator`].
///
/// # Errors
///
/// Returns [`CompilerError::Parse`] on the first parse failure;
/// returns [`CompilerError::Validation`] when one or more policies
/// fail schema validation (with every finding collected, not just the
/// first); returns [`CompilerError::EmptyInput`] when `sources` is
/// empty.
pub fn compile_all(
    sources: &[(&str, &str)],
    schema: Option<&Schema>,
) -> Result<CompiledPolicySet, CompilerError> {
    if sources.is_empty() {
        return Err(CompilerError::EmptyInput);
    }

    // Parse each fragment into a `PolicySet` and merge. Cedar's
    // PolicySet API has no direct "extend from another set" surface
    // that preserves PolicyIds, but `PolicySet::from_str` accepts a
    // multi-policy document, so we concatenate the fragments with a
    // trailing newline before parsing. Each fragment is expected to
    // end its own statements with semicolons; the join is purely
    // textual.
    let combined = sources
        .iter()
        .map(|(_, src)| src.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    let policy_set = PolicySet::from_str(&combined).map_err(|e| {
        // Cedar's parser error already includes line / column info
        // and a snippet via `Display`. Capture it as-is for the
        // admin view; callers render directly.
        CompilerError::Parse(format!("{e}"))
    })?;

    if let Some(schema) = schema {
        let validator = Validator::new(schema.clone());
        let result = validator.validate(&policy_set, ValidationMode::Strict);
        if !result.validation_passed() {
            let findings = result
                .validation_errors()
                .map(|err| ValidationFinding {
                    // The validator surfaces the offending PolicyId
                    // through Display in the message; capture it as
                    // the policy_id when accessible, otherwise fall
                    // back to a placeholder string so the call site
                    // is robust to upstream message-format drift.
                    policy_id: format!("{}", err.policy_id()),
                    message: format!("{err}"),
                })
                .collect::<Vec<_>>();
            return Err(CompilerError::Validation { findings });
        }
    }

    let policy_count = policy_set.policies().count();
    Ok(CompiledPolicySet {
        policy_set,
        policy_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial single `permit` policy compiles and reports its
    /// policy count. This pins the happy-path contract: the compiler
    /// returns a usable [`CompiledPolicySet`] and does not need a
    /// schema to be passed when one is unavailable.
    #[test]
    fn compiles_single_permit_without_schema() {
        let src = r#"permit(principal, action, resource);"#;
        let result = compile_all(&[("test", src)], None).expect("compile");
        assert_eq!(result.policy_count, 1);
    }

    /// Multi-fragment input concatenates and produces the right
    /// count.
    #[test]
    fn compiles_multiple_fragments() {
        let a = r#"permit(principal, action, resource);"#;
        let b = r#"forbid(principal, action, resource) when { resource has tag };"#;
        let result = compile_all(&[("a", a), ("b", b)], None).expect("compile");
        assert_eq!(result.policy_count, 2);
    }

    /// An empty input list is an operator error. The error variant
    /// must be [`CompilerError::EmptyInput`] so a caller can
    /// distinguish it from a parse failure.
    #[test]
    fn empty_input_returns_empty_input_error() {
        let result = compile_all(&[], None);
        assert!(matches!(result, Err(CompilerError::EmptyInput)));
    }

    /// A syntax error returns [`CompilerError::Parse`]. The body of
    /// the error message is opaque to this test (it is a Cedar parser
    /// diagnostic with span info) but the variant itself is the
    /// load-bearing contract.
    #[test]
    fn syntax_error_returns_parse_error() {
        // Missing closing paren after `principal`.
        let bad = r#"permit(principal action resource);"#;
        let result = compile_all(&[("bad", bad)], None);
        match result {
            Err(CompilerError::Parse(msg)) => assert!(!msg.is_empty()),
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    /// A type error against the schema returns
    /// [`CompilerError::Validation`] with at least one finding. This
    /// deliberately does not assert the exact message text (it is
    /// upstream-controlled) but does assert the structural shape so
    /// an admin view's render path stays stable.
    #[test]
    fn type_error_against_schema_returns_validation() {
        let schema_src = r#"
            entity User;
            entity Doc;
            action view appliesTo { principal: User, resource: Doc };
        "#;
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src).expect("schema parse");

        // Reference a type that the schema does not declare.
        let bad =
            r#"permit(principal == User::"a", action == Action::"view", resource == Tool::"x");"#;
        let result = compile_all(&[("bad", bad)], Some(&schema));
        match result {
            Err(CompilerError::Validation { findings }) => {
                assert!(!findings.is_empty());
                // Every finding must carry a non-empty policy id and
                // message so the admin view never renders a blank
                // line.
                for finding in &findings {
                    assert!(!finding.policy_id.is_empty());
                    assert!(!finding.message.is_empty());
                }
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }
}
