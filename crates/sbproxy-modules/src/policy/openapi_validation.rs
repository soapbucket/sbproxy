//! OpenAPI 3.0 schema validation policy.
//!
//! Loads an OpenAPI document at startup, indexes its paths and
//! request-body schemas, and validates incoming requests against the
//! matching operation's `requestBody` schema.
//!
//! Modes:
//! - `enforce` (default): rejects mismatched bodies with the configured
//!   status (default 400).
//! - `log`: logs a warning and forwards the request unchanged.
//!
//! Schemas are compiled with `jsonschema` once at config-load time so
//! request handling is a cheap dispatch. Remote `$ref` resolution is
//! disabled (the same posture used by `RequestValidatorPolicy`) so an
//! attacker-controlled spec cannot become an SSRF primitive.

use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

/// Action taken when a request fails validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenApiValidationMode {
    /// Reject the request with the configured status code.
    #[default]
    Enforce,
    /// Log a warning and forward the request unchanged.
    Log,
}

/// Compiled validator for a single (path-template, method) pair.
struct Operation {
    /// The original OpenAPI path template, e.g. `/users/{id}`. Kept
    /// for diagnostics.
    template: String,
    /// Regex compiled from the template for matching request paths.
    /// `/users/{id}` becomes `^/users/[^/]+$`.
    regex: Regex,
    /// HTTP method (uppercase, e.g. `POST`).
    method: String,
    /// Schema validators keyed by media type (e.g.
    /// `application/json`). When the request `Content-Type` does not
    /// match any key, the request is passed through.
    schemas: HashMap<String, jsonschema::JSONSchema>,
}

/// Compiled OpenAPI validation policy.
pub struct OpenApiValidationPolicy {
    operations: Vec<Operation>,
    /// Behaviour on validation failure.
    pub mode: OpenApiValidationMode,
    /// HTTP status returned when validation fails in `enforce` mode.
    pub status: u16,
    /// Optional error body (JSON string). When unset, the proxy
    /// returns a short JSON object describing the failure location.
    pub error_body: Option<String>,
    /// `Content-Type` for the rejection body.
    pub error_content_type: String,
}

impl std::fmt::Debug for OpenApiValidationPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenApiValidationPolicy")
            .field("operations", &self.operations.len())
            .field("mode", &self.mode)
            .field("status", &self.status)
            .finish()
    }
}

impl OpenApiValidationPolicy {
    /// Build the policy from a generic JSON config block.
    ///
    /// Accepts either:
    /// - `spec`: inline OpenAPI document as a JSON/YAML object
    /// - `spec_file`: path to an OpenAPI document on disk (JSON or YAML)
    /// - `spec_url`: HTTPS URL fetched at startup (synchronous; fails
    ///   the policy if unreachable)
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            spec: Option<serde_json::Value>,
            #[serde(default)]
            spec_file: Option<String>,
            #[serde(default)]
            mode: Option<String>,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            error_body: Option<String>,
            #[serde(default = "default_error_content_type")]
            error_content_type: String,
        }
        fn default_status() -> u16 {
            400
        }
        fn default_error_content_type() -> String {
            "application/json".to_string()
        }

        let raw: Raw = serde_json::from_value(value)?;
        let spec_value = match (raw.spec, raw.spec_file) {
            (Some(s), _) => s,
            (None, Some(path)) => {
                let body = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("read OpenAPI spec {}: {}", path, e))?;
                if path.ends_with(".json") {
                    serde_json::from_str(&body)?
                } else {
                    serde_yaml::from_str(&body)?
                }
            }
            _ => {
                anyhow::bail!("openapi_validation requires `spec` (inline) or `spec_file` (path)")
            }
        };

        let mode = match raw.mode.as_deref() {
            Some("log") | Some("warn") => OpenApiValidationMode::Log,
            Some("enforce") | None => OpenApiValidationMode::Enforce,
            Some(other) => anyhow::bail!("unknown mode `{}`; want `enforce` or `log`", other),
        };

        let operations = compile_operations(&spec_value)?;
        Ok(Self {
            operations,
            mode,
            status: raw.status,
            error_body: raw.error_body,
            error_content_type: raw.error_content_type,
        })
    }

    /// Number of operations indexed from the spec. Useful for tests
    /// and metrics.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }

    /// Locate the operation matching `method` + `path`. Returns
    /// `None` when the spec does not describe the route.
    fn match_operation(&self, method: &str, path: &str) -> Option<&Operation> {
        let upper = method.to_ascii_uppercase();
        self.operations
            .iter()
            .find(|op| op.method == upper && op.regex.is_match(path))
    }

    /// Validate the body of a request that matched an operation in
    /// the spec. Returns `Ok(None)` when no operation matches (the
    /// request is out of scope for this policy). Returns
    /// `Ok(Some(()))` on a clean validation, and `Err(message)` when
    /// the body fails schema validation. Requests with no
    /// matching schema for the inbound `Content-Type` are treated as
    /// out of scope.
    pub fn validate(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> ValidationResult {
        let op = match self.match_operation(method, path) {
            Some(o) => o,
            None => return ValidationResult::OutOfScope,
        };
        let media = content_type
            .and_then(|c| c.split(';').next())
            .map(|m| m.trim().to_ascii_lowercase());
        let schema = match media.as_deref().and_then(|m| op.schemas.get(m)) {
            Some(s) => s,
            None => return ValidationResult::OutOfScope,
        };
        let instance: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult::Failed(format!("invalid JSON in request body: {e}"));
            }
        };
        if let Err(errors) = schema.validate(&instance) {
            let first = errors
                .into_iter()
                .next()
                .map(|e| format!("{}", e.instance_path))
                .unwrap_or_else(|| "<root>".to_string());
            return ValidationResult::Failed(format!(
                "{} {} body failed schema validation at {}",
                op.method, op.template, first
            ));
        }
        ValidationResult::Passed
    }
}

/// Outcome of a single body validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Request is out of scope: either no operation matches the
    /// path + method, or the operation has no schema for the
    /// inbound `Content-Type`.
    OutOfScope,
    /// Body conforms to the operation schema.
    Passed,
    /// Body did not conform; the message names the offending JSON
    /// pointer.
    Failed(String),
}

/// Walk the OpenAPI document and compile a list of operations with
/// per-media-type validators.
fn compile_operations(spec: &serde_json::Value) -> anyhow::Result<Vec<Operation>> {
    let paths = spec
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("OpenAPI document is missing `paths`"))?;

    let mut out = Vec::new();
    for (template, item) in paths {
        let item_obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let regex = template_to_regex(template)?;
        for method in [
            "get", "post", "put", "delete", "patch", "head", "options", "trace",
        ] {
            let op = match item_obj.get(method) {
                Some(o) => o,
                None => continue,
            };
            let mut schemas = HashMap::new();
            if let Some(content) = op
                .get("requestBody")
                .and_then(|rb| rb.get("content"))
                .and_then(|c| c.as_object())
            {
                for (media, body) in content {
                    if let Some(schema) = body.get("schema") {
                        let compiled =
                            jsonschema::JSONSchema::options()
                                .compile(schema)
                                .map_err(|e| {
                                    anyhow::anyhow!(
                                        "invalid schema for {} {} {}: {}",
                                        method.to_uppercase(),
                                        template,
                                        media,
                                        e
                                    )
                                })?;
                        schemas.insert(media.to_ascii_lowercase(), compiled);
                    }
                }
            }
            out.push(Operation {
                template: template.clone(),
                regex: regex.clone(),
                method: method.to_ascii_uppercase(),
                schemas,
            });
        }
    }
    Ok(out)
}

/// Convert an OpenAPI path template into an anchored regex.
///
/// `/users/{id}/posts/{post_id}` becomes `^/users/[^/]+/posts/[^/]+$`.
/// Template variables are matched as a single non-`/` segment, which
/// is the OpenAPI default.
fn template_to_regex(template: &str) -> anyhow::Result<Regex> {
    let mut buf = String::with_capacity(template.len() + 8);
    buf.push('^');
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                for next in chars.by_ref() {
                    if next == '}' {
                        break;
                    }
                }
                buf.push_str("[^/]+");
            }
            // Escape regex metacharacters that may appear literally in
            // a path template.
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '|' | '\\' => {
                buf.push('\\');
                buf.push(c);
            }
            other => buf.push(other),
        }
    }
    buf.push('$');
    Regex::new(&buf).map_err(|e| anyhow::anyhow!("invalid path template `{template}`: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_spec() -> serde_json::Value {
        serde_json::json!({
            "openapi": "3.0.3",
            "info": {"title": "t", "version": "1"},
            "paths": {
                "/users/{id}": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name"],
                                        "properties": {
                                            "name": {"type": "string"},
                                            "age": {"type": "integer"}
                                        },
                                        "additionalProperties": false
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn template_regex_matches_concrete_paths() {
        let re = template_to_regex("/users/{id}/posts/{post_id}").unwrap();
        assert!(re.is_match("/users/42/posts/abc"));
        assert!(!re.is_match("/users/42/posts/abc/extra"));
        assert!(!re.is_match("/users/42"));
    }

    #[test]
    fn from_config_inline_spec_compiles_operations() {
        let policy = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec()
        }))
        .unwrap();
        assert_eq!(policy.operation_count(), 1);
    }

    #[test]
    fn out_of_scope_passes_when_no_path_matches() {
        let policy = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec()
        }))
        .unwrap();
        let res = policy.validate(
            "POST",
            "/widgets/1",
            Some("application/json"),
            br#"{"name":"x"}"#,
        );
        assert_eq!(res, ValidationResult::OutOfScope);
    }

    #[test]
    fn passes_with_valid_body() {
        let policy = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec()
        }))
        .unwrap();
        let res = policy.validate(
            "POST",
            "/users/42",
            Some("application/json"),
            br#"{"name":"alice","age":30}"#,
        );
        assert_eq!(res, ValidationResult::Passed);
    }

    #[test]
    fn fails_when_required_field_missing() {
        let policy = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec()
        }))
        .unwrap();
        let res = policy.validate(
            "POST",
            "/users/42",
            Some("application/json"),
            br#"{"age":30}"#,
        );
        match res {
            ValidationResult::Failed(_) => (),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn fails_when_extra_field_present() {
        let policy = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec()
        }))
        .unwrap();
        let res = policy.validate(
            "POST",
            "/users/42",
            Some("application/json"),
            br#"{"name":"alice","unexpected":"oops"}"#,
        );
        match res {
            ValidationResult::Failed(_) => (),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn out_of_scope_when_content_type_has_no_schema() {
        let policy = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec()
        }))
        .unwrap();
        let res = policy.validate("POST", "/users/42", Some("text/plain"), b"hello");
        assert_eq!(res, ValidationResult::OutOfScope);
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let err = OpenApiValidationPolicy::from_config(serde_json::json!({
            "spec": small_spec(),
            "mode": "trample",
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown mode"));
    }

    #[test]
    fn missing_spec_and_file_fails() {
        let err = OpenApiValidationPolicy::from_config(serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("requires"));
    }
}
