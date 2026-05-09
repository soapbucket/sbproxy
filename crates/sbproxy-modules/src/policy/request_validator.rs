//! Request body JSON Schema validator policy.
//!
//! Modelled on Kong's request-validator and Envoy's JSON-schema
//! filter: the schema is compiled at config-load time so each request
//! is a cheap dispatch. Remote `$ref` resolution is disabled at the
//! workspace level so a malicious schema cannot become an SSRF
//! primitive.

use serde::Deserialize;

/// Validates request bodies against a JSON Schema at the edge.
///
/// Modelled on Kong's request-validator and Envoy's JSON-schema
/// filter: the schema is compiled at config-load time so each request
/// is a cheap dispatch. Remote `$ref` resolution is disabled at the
/// workspace level so a malicious schema cannot become an SSRF
/// primitive.
///
/// The policy applies to requests whose `Content-Type` matches one
/// of the configured `content_types` (default: `application/json`).
/// Requests of any other type are passed through untouched.
pub struct RequestValidatorPolicy {
    /// The raw schema document, kept for diagnostics.
    pub schema: serde_json::Value,
    /// Pre-compiled validator.
    compiled: jsonschema::JSONSchema,
    /// Content-types that trigger validation. Matched
    /// case-insensitively against the leading media type of the
    /// inbound `Content-Type` (parameters like `; charset=utf-8` are
    /// ignored).
    pub content_types: Vec<String>,
    /// HTTP status returned when the body fails validation.
    /// Default 400.
    pub status: u16,
    /// Optional response body to send on rejection. When unset, the
    /// proxy returns a short JSON object describing the failure
    /// location (without echoing the offending payload back to the
    /// caller).
    pub error_body: Option<String>,
    /// `Content-Type` for the rejection body. Default
    /// `application/json`.
    pub error_content_type: String,
}

impl std::fmt::Debug for RequestValidatorPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestValidatorPolicy")
            .field("content_types", &self.content_types)
            .field("status", &self.status)
            .finish()
    }
}

impl RequestValidatorPolicy {
    /// Build from a generic JSON config value.
    pub fn from_config(value: serde_json::Value) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            schema: serde_json::Value,
            #[serde(default = "default_content_types")]
            content_types: Vec<String>,
            #[serde(default = "default_status")]
            status: u16,
            #[serde(default)]
            error_body: Option<String>,
            #[serde(default = "default_error_content_type")]
            error_content_type: String,
        }
        fn default_content_types() -> Vec<String> {
            vec!["application/json".to_string()]
        }
        fn default_status() -> u16 {
            400
        }
        fn default_error_content_type() -> String {
            "application/json".to_string()
        }

        let raw: Raw = serde_json::from_value(value)?;
        let compiled = jsonschema::JSONSchema::options()
            .compile(&raw.schema)
            .map_err(|e| anyhow::anyhow!("invalid request_validator schema: {e}"))?;
        Ok(Self {
            schema: raw.schema,
            compiled,
            content_types: raw.content_types,
            status: raw.status,
            error_body: raw.error_body,
            error_content_type: raw.error_content_type,
        })
    }

    /// True when this policy should validate a request with the given
    /// `Content-Type` header value (`None` = absent header).
    pub fn applies_to(&self, content_type: Option<&str>) -> bool {
        let ct = match content_type {
            Some(c) => c,
            None => return false,
        };
        let media = ct.split(';').next().unwrap_or("").trim();
        self.content_types
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(media))
    }

    /// Validate a request body. Returns `Ok(())` when the body
    /// conforms; otherwise an `Err(message)` describing where
    /// validation failed (the location only, since the offending value is
    /// omitted because it is attacker-controlled).
    pub fn validate(&self, body: &[u8]) -> Result<(), String> {
        let instance: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| format!("invalid JSON in request body: {e}"))?;
        if let Err(errors) = self.compiled.validate(&instance) {
            let first = errors
                .into_iter()
                .next()
                .map(|e| format!("{}", e.instance_path))
                .unwrap_or_else(|| "<root>".to_string());
            return Err(format!("request body failed schema validation at {first}"));
        }
        Ok(())
    }
}
