//! Schema validation guardrail - validates structured AI output against
//! a JSON Schema document.

use anyhow::{bail, Result};

use super::GuardrailBlock;

/// Serialized-size cap for a configured schema document. Large enough
/// for any hand-written structured-output contract, small enough that
/// a pathological schema cannot make config publication or
/// per-response validation expensive.
const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// Nesting-depth cap for a configured schema document. Also bounds the
/// recursion in the load-time walks below.
const MAX_SCHEMA_DEPTH: usize = 32;

/// Validates that AI output conforms to a JSON Schema (WOR-2174).
///
/// The schema compiles once, at config publication, through the same
/// `jsonschema` machinery the `json_schema` transform, the
/// `request_validator` policy, and the OpenAPI validator already use,
/// so the full keyword set is enforced: property types, nested
/// `required`, `additionalProperties`, array constraints, `enum` and
/// `const`, numeric and string bounds, and `allOf` / `anyOf` / `oneOf`
/// / `not` composition. A schema that does not compile fails config
/// load. Remote `$ref` targets are rejected at load time, and remote
/// resolution is additionally disabled at the workspace level (no
/// `resolve-http` feature), so a malicious schema cannot become an
/// SSRF primitive.
pub struct SchemaGuardrail {
    /// The raw schema document, kept for diagnostics.
    schema: serde_json::Value,
    /// Validator compiled once at config publication.
    compiled: jsonschema::JSONSchema,
    /// True when the schema's top-level `type` is exactly `"string"`:
    /// the assistant text is then validated directly as a string
    /// instance instead of being parsed as JSON first.
    expects_plain_string: bool,
}

impl std::fmt::Debug for SchemaGuardrail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `jsonschema::JSONSchema` is not `Debug`; the raw document is
        // the useful diagnostic anyway.
        f.debug_struct("SchemaGuardrail")
            .field("schema", &self.schema)
            .finish()
    }
}

impl SchemaGuardrail {
    /// Build from a guardrail config value.
    ///
    /// The `schema` key is required: a schema guardrail without a
    /// schema can only ever be a no-op, and silently accepting one
    /// hides an operator mistake. Invalid, oversized, over-nested, or
    /// externally-referencing schemas fail here, which fails config
    /// load before the candidate configuration can be published.
    pub fn from_config(config: &serde_json::Value) -> Result<Self> {
        let Some(schema) = config.get("schema") else {
            bail!("schema guardrail requires a `schema` key holding a JSON Schema document");
        };
        Self::compile(schema.clone())
    }

    /// Compile a JSON Schema document into a guardrail.
    fn compile(schema: serde_json::Value) -> Result<Self> {
        if !(schema.is_object() || schema.is_boolean()) {
            bail!("schema guardrail: `schema` must be a JSON Schema object or boolean schema");
        }
        let serialized_len = schema.to_string().len();
        if serialized_len > MAX_SCHEMA_BYTES {
            bail!(
                "schema guardrail: schema document is {serialized_len} bytes serialized; \
                 the limit is {MAX_SCHEMA_BYTES} bytes"
            );
        }
        ensure_depth(&schema, MAX_SCHEMA_DEPTH)?;
        reject_external_refs(&schema)?;
        let compiled = jsonschema::JSONSchema::options()
            .compile(&schema)
            .map_err(|error| anyhow::anyhow!("schema guardrail: invalid JSON Schema: {error}"))?;
        let expects_plain_string =
            schema.get("type").and_then(serde_json::Value::as_str) == Some("string");
        Ok(Self {
            schema,
            compiled,
            expects_plain_string,
        })
    }

    /// Check that `content` conforms to the compiled schema.
    ///
    /// `content` is the canonical assistant payload text (see
    /// [`super::GuardrailPipeline::check_output`]), parsed as JSON
    /// unless the schema's top-level `type` is `"string"`, in which
    /// case the raw text is validated as a string instance. Block
    /// reasons carry the failing instance path and the schema keyword,
    /// never the offending value: model output must not leak back
    /// through the error surface.
    pub fn check(&self, content: &str) -> Option<GuardrailBlock> {
        let instance: serde_json::Value = if self.expects_plain_string {
            serde_json::Value::String(content.to_owned())
        } else {
            match serde_json::from_str(content) {
                Ok(value) => value,
                Err(error) => {
                    // serde_json errors carry a position, not content.
                    return Some(GuardrailBlock {
                        name: "schema".to_string(),
                        reason: format!("Output is not valid JSON: {error}"),
                    });
                }
            }
        };
        if let Err(errors) = self.compiled.validate(&instance) {
            let reason = errors
                .into_iter()
                .next()
                .map(|error| low_leak_reason(&error))
                .unwrap_or_else(|| "Schema validation failed".to_string());
            return Some(GuardrailBlock {
                name: "schema".to_string(),
                reason,
            });
        }
        None
    }
}

/// Format one validation error as instance path plus schema keyword.
///
/// The offending value never appears: it is model output that would
/// otherwise be relayed into the client-visible error body. Missing
/// `required` property names do appear, because those names come from
/// the operator's schema, not from the response.
fn low_leak_reason(error: &jsonschema::ValidationError<'_>) -> String {
    let instance_path = error.instance_path.to_string();
    let at = if instance_path.is_empty() {
        "<root>"
    } else {
        instance_path.as_str()
    };
    let schema_path = error.schema_path.to_string();
    let keyword = schema_keyword(&schema_path);
    if let jsonschema::error::ValidationErrorKind::Required { property } = &error.kind {
        return format!(
            "Schema validation failed at {at}: missing required property {property} \
             (keyword: {keyword})"
        );
    }
    format!("Schema validation failed at {at} (keyword: {keyword})")
}

/// Last non-index segment of a schema path, e.g.
/// `/properties/summary/type` yields `type` and `/anyOf/1/type` yields
/// `type`. Falls back to `schema` for a root-level failure (for
/// example a `false` boolean schema, whose path is empty).
fn schema_keyword(schema_path: &str) -> &str {
    schema_path
        .rsplit('/')
        .find(|segment| !segment.is_empty() && !segment.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or("schema")
}

/// Reject documents nested deeper than the cap so compilation, the
/// `$ref` walk, and per-response validation stay cheap and stack-safe.
fn ensure_depth(value: &serde_json::Value, remaining: usize) -> Result<()> {
    if remaining == 0 {
        bail!(
            "schema guardrail: schema document exceeds the maximum nesting depth of \
             {MAX_SCHEMA_DEPTH}"
        );
    }
    match value {
        serde_json::Value::Object(map) => {
            for child in map.values() {
                ensure_depth(child, remaining - 1)?;
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                ensure_depth(child, remaining - 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Reject any `$ref` that is not an in-document `#...` pointer.
///
/// Remote resolution is already disabled at the workspace level (the
/// `jsonschema` crate builds without `resolve-http` / `resolve-file`),
/// so an external reference could never be fetched anyway; rejecting
/// it here turns an opaque resolver failure into an actionable config
/// error naming the offending reference. The reference text comes from
/// the operator's config, not from response data, so echoing it is
/// safe.
fn reject_external_refs(value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(target) = map.get("$ref").and_then(serde_json::Value::as_str) {
                if !target.starts_with('#') {
                    bail!(
                        "schema guardrail: external $ref {target:?} is not supported; only \
                         in-document \"#/...\" references are allowed"
                    );
                }
            }
            for child in map.values() {
                reject_external_refs(child)?;
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                reject_external_refs(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(schema: serde_json::Value) -> SchemaGuardrail {
        SchemaGuardrail::from_config(&serde_json::json!({"type": "schema", "schema": schema}))
            .expect("schema compiles")
    }

    /// The schema shipped in `examples/ai-guardrails/sb.yml`, verbatim.
    fn example_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["summary", "tags"],
            "properties": {
                "summary": {"type": "string"},
                "tags": {"type": "array"}
            }
        })
    }

    #[test]
    fn example_schema_rejects_wrong_property_types() {
        // WOR-2174 regression: this body passed the old checker because
        // it only looked at the top-level `type` and `required` keys.
        let g = guard(example_schema());
        let block = g
            .check(r#"{"summary":7,"tags":"wrong"}"#)
            .expect("wrong-typed properties must block");
        assert!(
            block.reason.contains("/summary") || block.reason.contains("/tags"),
            "reason names the failing path: {}",
            block.reason
        );
        assert!(
            block.reason.contains("keyword: type"),
            "reason names the keyword: {}",
            block.reason
        );
        // Low-leak: the offending values never appear.
        assert!(
            !block.reason.contains('7') && !block.reason.contains("wrong"),
            "reason must not echo the offending value: {}",
            block.reason
        );
    }

    #[test]
    fn example_schema_accepts_valid_body() {
        let g = guard(example_schema());
        assert!(g
            .check(r#"{"summary":"a note","tags":["a","b"]}"#)
            .is_none());
    }

    #[test]
    fn nested_required_enforced() {
        let g = guard(serde_json::json!({
            "type": "object",
            "required": ["user"],
            "properties": {
                "user": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "integer"}}
                }
            }
        }));
        assert!(g.check(r#"{"user":{"id":3}}"#).is_none());
        let block = g
            .check(r#"{"user":{}}"#)
            .expect("nested required must block");
        assert!(
            block.reason.contains("/user") && block.reason.contains("required"),
            "reason: {}",
            block.reason
        );
        assert!(
            block.reason.contains("id"),
            "missing property names come from the schema and are safe to name: {}",
            block.reason
        );
    }

    #[test]
    fn additional_properties_enforced() {
        let g = guard(serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"a": {"type": "integer"}}
        }));
        assert!(g.check(r#"{"a":1}"#).is_none());
        let block = g
            .check(r#"{"a":1,"surplus_key":2}"#)
            .expect("additionalProperties: false must block");
        assert!(
            block.reason.contains("additionalProperties"),
            "reason: {}",
            block.reason
        );
        assert!(
            !block.reason.contains("surplus_key"),
            "unexpected property names are response data and must not leak: {}",
            block.reason
        );
    }

    #[test]
    fn array_constraints_enforced() {
        let g = guard(serde_json::json!({
            "type": "array",
            "items": {"type": "integer"},
            "minItems": 2
        }));
        assert!(g.check("[1,2,3]").is_none());
        let short = g.check("[1]").expect("minItems must block");
        assert!(
            short.reason.contains("minItems"),
            "reason: {}",
            short.reason
        );
        let wrong = g.check(r#"[1,"x",3]"#).expect("item type must block");
        assert!(
            wrong.reason.contains("/1") && wrong.reason.contains("keyword: type"),
            "reason: {}",
            wrong.reason
        );
    }

    #[test]
    fn enum_and_const_enforced() {
        let g = guard(serde_json::json!({"enum": ["red", "green"]}));
        assert!(g.check(r#""green""#).is_none());
        let block = g.check(r#""blue""#).expect("enum must block");
        assert!(block.reason.contains("enum"), "reason: {}", block.reason);
        assert!(
            !block.reason.contains("blue"),
            "reason must not echo the offending value: {}",
            block.reason
        );

        let g = guard(serde_json::json!({"const": 42}));
        assert!(g.check("42").is_none());
        let block = g.check("43").expect("const must block");
        assert!(block.reason.contains("const"), "reason: {}", block.reason);
        assert!(
            !block.reason.contains("43"),
            "reason must not echo the offending value: {}",
            block.reason
        );
    }

    #[test]
    fn numeric_bounds_enforced() {
        let g = guard(serde_json::json!({"type": "integer", "minimum": 10}));
        assert!(g.check("11").is_none());
        let block = g.check("5").expect("minimum must block");
        assert!(block.reason.contains("minimum"), "reason: {}", block.reason);
    }

    #[test]
    fn plain_string_schema_validates_raw_text() {
        // A top-level `type: string` schema judges the assistant text
        // directly, without requiring it to be a quoted JSON string.
        let g = guard(serde_json::json!({"type": "string", "maxLength": 3}));
        assert!(g.check("abc").is_none());
        let block = g.check("abcd").expect("maxLength must block");
        assert!(
            block.reason.contains("maxLength"),
            "reason: {}",
            block.reason
        );
        assert!(
            !block.reason.contains("abcd"),
            "reason must not echo the offending value: {}",
            block.reason
        );
    }

    #[test]
    fn composition_enforced() {
        let g = guard(serde_json::json!({
            "oneOf": [{"type": "string"}, {"type": "integer"}]
        }));
        assert!(g.check("3").is_none());
        assert!(g.check(r#""three""#).is_none());
        let block = g.check("true").expect("oneOf must block");
        assert!(block.reason.contains("oneOf"), "reason: {}", block.reason);

        let g = guard(serde_json::json!({"not": {"type": "object"}}));
        assert!(g.check("[1]").is_none());
        let block = g.check("{}").expect("not must block");
        assert!(block.reason.contains("not"), "reason: {}", block.reason);
    }

    #[test]
    fn in_document_ref_resolves() {
        let g = guard(serde_json::json!({
            "type": "object",
            "properties": {"a": {"$ref": "#/definitions/int"}},
            "definitions": {"int": {"type": "integer"}}
        }));
        assert!(g.check(r#"{"a":1}"#).is_none());
        assert!(g.check(r#"{"a":"one"}"#).is_some());
    }

    #[test]
    fn remote_ref_rejected_at_config_load() {
        let error = SchemaGuardrail::from_config(&serde_json::json!({
            "type": "schema",
            "schema": {"$ref": "https://example.com/schema.json"}
        }))
        .expect_err("remote $ref must fail config load")
        .to_string();
        assert!(error.contains("external $ref"), "error: {error}");

        // Nested references are walked too.
        let error = SchemaGuardrail::from_config(&serde_json::json!({
            "type": "schema",
            "schema": {
                "type": "object",
                "properties": {"a": {"$ref": "file:///etc/passwd"}}
            }
        }))
        .expect_err("nested external $ref must fail config load")
        .to_string();
        assert!(error.contains("external $ref"), "error: {error}");
    }

    #[test]
    fn invalid_schema_rejected_at_config_load() {
        let error = SchemaGuardrail::from_config(&serde_json::json!({
            "type": "schema",
            "schema": {"type": 123}
        }))
        .expect_err("a malformed schema must fail config load")
        .to_string();
        assert!(error.contains("invalid JSON Schema"), "error: {error}");
    }

    #[test]
    fn missing_schema_key_rejected() {
        let error = SchemaGuardrail::from_config(&serde_json::json!({"type": "schema"}))
            .expect_err("a schema guardrail without a schema must fail config load")
            .to_string();
        assert!(error.contains("requires a `schema` key"), "error: {error}");
    }

    #[test]
    fn non_object_schema_rejected() {
        let error = SchemaGuardrail::from_config(&serde_json::json!({
            "type": "schema",
            "schema": "not a schema"
        }))
        .expect_err("a non-object schema must fail config load")
        .to_string();
        assert!(error.contains("JSON Schema object"), "error: {error}");
    }

    #[test]
    fn oversized_schema_rejected() {
        let error = SchemaGuardrail::from_config(&serde_json::json!({
            "type": "schema",
            "schema": {"description": "x".repeat(MAX_SCHEMA_BYTES + 1)}
        }))
        .expect_err("an oversized schema must fail config load")
        .to_string();
        assert!(error.contains("limit is"), "error: {error}");
    }

    #[test]
    fn deeply_nested_schema_rejected() {
        let mut schema = serde_json::json!({"type": "integer"});
        for _ in 0..MAX_SCHEMA_DEPTH {
            schema = serde_json::json!({"type": "object", "properties": {"a": schema}});
        }
        let error = SchemaGuardrail::from_config(&serde_json::json!({
            "type": "schema",
            "schema": schema
        }))
        .expect_err("an over-nested schema must fail config load")
        .to_string();
        assert!(error.contains("nesting depth"), "error: {error}");
    }

    #[test]
    fn boolean_schema_supported() {
        // JSON Schema allows `true` (accept everything) and `false`
        // (reject everything) as complete schemas.
        let accept = guard(serde_json::json!(true));
        assert!(accept.check(r#"{"anything": 1}"#).is_none());
        let reject = guard(serde_json::json!(false));
        assert!(reject.check(r#"{"anything": 1}"#).is_some());
    }

    #[test]
    fn invalid_json_blocked() {
        let g = guard(serde_json::json!({}));
        let block = g.check("this is not json {").expect("must block");
        assert!(block.reason.contains("not valid JSON"), "{}", block.reason);
    }

    #[test]
    fn type_mismatch_blocked() {
        let g = guard(serde_json::json!({"type": "object"}));
        let block = g.check("[1, 2, 3]").expect("must block");
        assert!(
            block.reason.contains("keyword: type"),
            "reason: {}",
            block.reason
        );
    }

    #[test]
    fn required_fields_missing() {
        let g = guard(serde_json::json!({
            "type": "object",
            "required": ["name", "age"]
        }));
        assert!(g.check(r#"{"name": "Alice", "age": 30}"#).is_none());
        let block = g.check(r#"{"name": "Alice"}"#).expect("must block");
        assert!(block.reason.contains("age"), "reason: {}", block.reason);
    }

    #[test]
    fn array_type_passes() {
        let g = guard(serde_json::json!({"type": "array"}));
        assert!(g.check("[1, 2, 3]").is_none());
    }

    #[test]
    fn from_config() {
        let config = serde_json::json!({
            "type": "schema",
            "schema": {
                "type": "object",
                "required": ["result"]
            }
        });
        let g = SchemaGuardrail::from_config(&config).unwrap();
        assert!(g.check(r#"{"result": true}"#).is_none());
        assert!(g.check(r#"{"other": 1}"#).is_some());
    }

    #[test]
    fn empty_schema_only_checks_valid_json() {
        let g = guard(serde_json::json!({}));
        assert!(g.check(r#"{"anything": true}"#).is_none());
        assert!(g.check("not json").is_some());
    }
}
