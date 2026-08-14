//! Lossless MCP tool contracts and bounded JSON Schema compilation.

use super::{decode_header_value, encode_header_value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// The root JSON value has depth one; nested values add one and object keys do not count.
const ROOT_VALUE_DEPTH: usize = 1;

/// Error vocabulary for MCP contract parsing, schema compilation, and headers.
#[derive(Debug, thiserror::Error)]
pub enum McpContractError {
    /// The tool contract was not a JSON object.
    #[error("tool contract must be an object")]
    ToolMustBeObject,
    /// The tool result was not a JSON object.
    #[error("tool result must be an object")]
    ToolResultMustBeObject,
    /// A required string field was absent or not a string.
    #[error("missing required string field {0}")]
    MissingStringField(&'static str),
    /// A required object field was absent or not an object.
    #[error("missing required object field {0}")]
    MissingObjectField(&'static str),
    /// A required array field was absent or not an array.
    #[error("missing required array field {0}")]
    MissingArrayField(&'static str),
    /// The schema dialect was not in the supported allowlist.
    #[error("unsupported JSON Schema dialect {0}")]
    UnsupportedSchemaDialect(String),
    /// The schema did not validate against its dialect meta-schema.
    #[error("invalid JSON Schema: {0}")]
    InvalidSchema(String),
    /// A schema reference could retrieve an external resource.
    #[error("external {keyword} reference is forbidden: {reference}")]
    ExternalReference {
        /// Reference keyword.
        keyword: &'static str,
        /// External reference value.
        reference: String,
    },
    /// A fixed schema budget was exceeded.
    #[error("schema limit {limit} exceeded: {actual} > {maximum}")]
    LimitExceeded {
        /// Budget name.
        limit: &'static str,
        /// Observed amount.
        actual: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// A header annotation was not reached solely through properties.
    #[error("x-mcp-header {0} is not statically reachable through properties")]
    UnreachableHeaderProjection(String),
    /// Header annotation names are case-insensitively unique.
    #[error("duplicate case-insensitive x-mcp-header name {0}")]
    DuplicateHeaderProjection(String),
    /// An annotation did not name an HTTP token.
    #[error("invalid x-mcp-header token {0}")]
    InvalidHeaderName(String),
    /// An annotation was attached to an unsupported property type.
    #[error("x-mcp-header {header} has unsupported schema type {schema_type}")]
    UnsupportedHeaderValueKind {
        /// Complete normalized header name.
        header: String,
        /// Schema type that cannot be projected.
        schema_type: String,
    },
    /// A required body-derived header was absent.
    #[error("required mirrored header is missing: {0}")]
    MissingMirroredHeader(String),
    /// A header was supplied for a missing or null body value.
    #[error("mirrored header has no non-null body value: {0}")]
    UnexpectedMirroredHeader(String),
    /// A header did not agree with its body value.
    #[error("mirrored header does not match its body value: {0}")]
    MirroredHeaderMismatch(String),
    /// An integer cannot safely cross the JavaScript header boundary.
    #[error("integer projected to {0} is outside the JavaScript safe range")]
    UnsafeProjectedInteger(String),
}

/// Lossless MCP tool document wrapper.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolContract {
    document: serde_json::Map<String, serde_json::Value>,
}

impl TryFrom<serde_json::Value> for McpToolContract {
    type Error = McpContractError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let document = value
            .as_object()
            .cloned()
            .ok_or(McpContractError::ToolMustBeObject)?;
        if document
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return Err(McpContractError::MissingStringField("name"));
        }
        if !document
            .get("inputSchema")
            .is_some_and(serde_json::Value::is_object)
        {
            return Err(McpContractError::MissingObjectField("inputSchema"));
        }
        Ok(Self { document })
    }
}

impl McpToolContract {
    /// Return the validated contract name.
    pub fn name(&self) -> &str {
        self.document["name"]
            .as_str()
            .expect("constructor validates name")
    }

    /// Return the validated input schema document.
    pub fn input_schema(&self) -> &serde_json::Value {
        &self.document["inputSchema"]
    }

    /// Return an optional tool description.
    pub fn description(&self) -> Option<&str> {
        self.document
            .get("description")
            .and_then(serde_json::Value::as_str)
    }

    /// Return an optional output schema.
    pub fn output_schema(&self) -> Option<&serde_json::Value> {
        self.document.get("outputSchema")
    }

    /// Return a lossless clone with a different advertised name.
    pub fn with_advertised_name(&self, name: &str) -> Self {
        let mut document = self.document.clone();
        document.insert("name".into(), serde_json::Value::String(name.into()));
        Self { document }
    }

    /// Return the complete tool document.
    pub fn as_value(&self) -> serde_json::Value {
        serde_json::Value::Object(self.document.clone())
    }
}

impl Serialize for McpToolContract {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.document.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpToolContract {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// Lossless MCP tool-result document wrapper.
#[derive(Debug, Clone, PartialEq)]
pub struct McpToolResultDocument {
    document: serde_json::Map<String, serde_json::Value>,
}

impl TryFrom<serde_json::Value> for McpToolResultDocument {
    type Error = McpContractError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let document = value
            .as_object()
            .cloned()
            .ok_or(McpContractError::ToolResultMustBeObject)?;
        if !document
            .get("content")
            .is_some_and(serde_json::Value::is_array)
        {
            return Err(McpContractError::MissingArrayField("content"));
        }
        Ok(Self { document })
    }
}

impl McpToolResultDocument {
    /// Return the complete result document.
    pub fn as_value(&self) -> serde_json::Value {
        serde_json::Value::Object(self.document.clone())
    }

    /// Consume the wrapper and return the complete result document.
    pub fn into_value(self) -> serde_json::Value {
        serde_json::Value::Object(self.document)
    }
}

impl Serialize for McpToolResultDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.document.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for McpToolResultDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

/// Fixed resource limits for an MCP JSON Schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpSchemaLimits {
    /// Maximum serialized schema bytes.
    pub max_bytes: usize,
    /// Maximum JSON value depth, with the root value at depth one and object keys excluded.
    pub max_depth: usize,
    /// Maximum JSON values visited.
    pub max_nodes: usize,
    /// Maximum nested schema-bearing branches.
    pub max_subschemas: usize,
    /// Maximum static `x-mcp-header` annotations.
    pub max_header_projections: usize,
    /// Maximum bytes in one pattern or patternProperties key.
    pub max_pattern_bytes: usize,
    /// Maximum bytes across all patterns.
    pub max_total_pattern_bytes: usize,
}

impl Default for McpSchemaLimits {
    fn default() -> Self {
        Self {
            max_bytes: 262_144,
            max_depth: 32,
            max_nodes: 4_096,
            max_subschemas: 512,
            max_header_projections: 64,
            max_pattern_bytes: 2_048,
            max_total_pattern_bytes: 8_192,
        }
    }
}

/// JSON Schema dialect accepted for modern MCP tool contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpSchemaDialect {
    /// JSON Schema draft 4.
    Draft4,
    /// JSON Schema draft 6.
    Draft6,
    /// JSON Schema draft 7.
    Draft7,
    /// JSON Schema draft 2019-09.
    Draft201909,
    /// JSON Schema draft 2020-12.
    Draft202012,
}

impl McpSchemaDialect {
    fn into_jsonschema_draft(self) -> jsonschema_modern::Draft {
        match self {
            Self::Draft4 => jsonschema_modern::Draft::Draft4,
            Self::Draft6 => jsonschema_modern::Draft::Draft6,
            Self::Draft7 => jsonschema_modern::Draft::Draft7,
            Self::Draft201909 => jsonschema_modern::Draft::Draft201909,
            Self::Draft202012 => jsonschema_modern::Draft::Draft202012,
        }
    }
}

/// Primitive body type compared to a projected header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpHeaderValueKind {
    /// String values use the Base64 sentinel transport when needed.
    String,
    /// Integer values use decimal and must be JavaScript-safe.
    Integer,
    /// Boolean values use lowercase `true` or `false`.
    Boolean,
}

/// A static body-property to MCP header projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpHeaderProjection {
    /// Complete normalized `mcp-param-*` header name.
    pub header_name: http::HeaderName,
    /// Exact path through object properties.
    pub property_path: Vec<String>,
    /// Primitive representation expected at the property path.
    pub kind: McpHeaderValueKind,
}

/// Reusable validators and projections compiled from a modern tool contract.
#[derive(Debug, Clone)]
pub struct CompiledMcpToolContract {
    /// Input JSON Schema validator.
    pub input: jsonschema_modern::Validator,
    /// Optional output JSON Schema validator.
    pub output: Option<jsonschema_modern::Validator>,
    /// Statically reachable body-to-header projections.
    pub header_projections: Vec<McpHeaderProjection>,
}

/// Compile a modern tool contract with fixed schema and projection bounds.
pub fn compile_modern_tool_contract(
    contract: &McpToolContract,
    limits: McpSchemaLimits,
) -> Result<CompiledMcpToolContract, McpContractError> {
    let header_projections = analyze_input_schema(contract.input_schema(), limits)?;
    let input = compile_schema(contract.input_schema(), limits, true)?;
    let output = contract
        .output_schema()
        .map(|schema| compile_schema(schema, limits, false))
        .transpose()?;
    Ok(CompiledMcpToolContract {
        input,
        output,
        header_projections,
    })
}

/// Build the headers mirrored from a validated tool-argument document.
pub fn build_mirrored_headers(
    projections: &[McpHeaderProjection],
    body: &serde_json::Value,
) -> Result<http::HeaderMap, McpContractError> {
    let mut headers = http::HeaderMap::new();
    for projection in projections {
        let Some(value) = value_at_path(body, &projection.property_path) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let value = header_value_for_body(projection, value)?;
        let header_value = http::HeaderValue::from_str(&value).map_err(|_| {
            McpContractError::MirroredHeaderMismatch(projection.header_name.as_str().to_string())
        })?;
        headers.insert(projection.header_name.clone(), header_value);
    }
    Ok(headers)
}

/// Validate headers mirrored from a tool-argument document.
pub fn validate_mirrored_headers(
    headers: &http::HeaderMap,
    projections: &[McpHeaderProjection],
    body: &serde_json::Value,
) -> Result<(), McpContractError> {
    for projection in projections {
        let label = projection.header_name.as_str().to_string();
        let value = value_at_path(body, &projection.property_path);
        let Some(value) = value.filter(|value| !value.is_null()) else {
            if headers.contains_key(&projection.header_name) {
                return Err(McpContractError::UnexpectedMirroredHeader(label));
            }
            continue;
        };
        let header = headers
            .get(&projection.header_name)
            .ok_or_else(|| McpContractError::MissingMirroredHeader(label.clone()))?
            .to_str()
            .map_err(|_| McpContractError::MirroredHeaderMismatch(label.clone()))?;
        let matches = match projection.kind {
            McpHeaderValueKind::String => value
                .as_str()
                .and_then(|body| {
                    decode_header_value(header)
                        .ok()
                        .map(|decoded| decoded == body)
                })
                .unwrap_or(false),
            McpHeaderValueKind::Integer => {
                let body = integer_at_header_boundary(value, &label)?;
                parse_safe_integer(header)
                    .map(|header| header == body)
                    .unwrap_or(false)
            }
            McpHeaderValueKind::Boolean => value
                .as_bool()
                .map(|body| header == if body { "true" } else { "false" })
                .unwrap_or(false),
        };
        if !matches {
            return Err(McpContractError::MirroredHeaderMismatch(label));
        }
    }
    Ok(())
}

fn select_schema_dialect(schema: &serde_json::Value) -> Result<McpSchemaDialect, McpContractError> {
    match schema.get("$schema") {
        None => Ok(McpSchemaDialect::Draft202012),
        Some(serde_json::Value::String(uri)) => match uri.as_str() {
            "http://json-schema.org/draft-04/schema#" => Ok(McpSchemaDialect::Draft4),
            "http://json-schema.org/draft-06/schema#" => Ok(McpSchemaDialect::Draft6),
            "http://json-schema.org/draft-07/schema#" => Ok(McpSchemaDialect::Draft7),
            "https://json-schema.org/draft/2019-09/schema" => Ok(McpSchemaDialect::Draft201909),
            "https://json-schema.org/draft/2020-12/schema" => Ok(McpSchemaDialect::Draft202012),
            _ => Err(McpContractError::UnsupportedSchemaDialect(uri.clone())),
        },
        Some(value) => Err(McpContractError::UnsupportedSchemaDialect(
            value.to_string(),
        )),
    }
}

fn compile_schema(
    schema: &serde_json::Value,
    limits: McpSchemaLimits,
    require_object: bool,
) -> Result<jsonschema_modern::Validator, McpContractError> {
    analyze_schema(schema, limits, false)?;
    if require_object && schema.get("type").and_then(serde_json::Value::as_str) != Some("object") {
        return Err(McpContractError::InvalidSchema(
            "inputSchema.type must be object".into(),
        ));
    }
    let dialect = select_schema_dialect(schema)?;
    validate_meta_schema(schema, dialect)?;
    jsonschema_modern::options()
        .with_draft(dialect.into_jsonschema_draft())
        .build(schema)
        .map_err(|error| McpContractError::InvalidSchema(error.to_string()))
}

fn validate_meta_schema(
    schema: &serde_json::Value,
    dialect: McpSchemaDialect,
) -> Result<(), McpContractError> {
    let result = match dialect {
        McpSchemaDialect::Draft4 => jsonschema_modern::draft4::meta::validate(schema),
        McpSchemaDialect::Draft6 => jsonschema_modern::draft6::meta::validate(schema),
        McpSchemaDialect::Draft7 => jsonschema_modern::draft7::meta::validate(schema),
        McpSchemaDialect::Draft201909 => jsonschema_modern::draft201909::meta::validate(schema),
        McpSchemaDialect::Draft202012 => jsonschema_modern::draft202012::meta::validate(schema),
    };
    result.map_err(|error| McpContractError::InvalidSchema(error.to_string()))
}

fn analyze_input_schema(
    schema: &serde_json::Value,
    limits: McpSchemaLimits,
) -> Result<Vec<McpHeaderProjection>, McpContractError> {
    let mut projections = Vec::new();
    analyze_schema_inner(schema, limits, true, &mut projections)?;
    Ok(projections)
}

fn analyze_schema(
    schema: &serde_json::Value,
    limits: McpSchemaLimits,
    collect_headers: bool,
) -> Result<(), McpContractError> {
    let mut projections = Vec::new();
    analyze_schema_inner(schema, limits, collect_headers, &mut projections).map(|_| ())
}

#[derive(Clone, Copy)]
enum SchemaTraversalPosition {
    Schema,
    PropertiesContainer,
}

fn analyze_schema_inner(
    schema: &serde_json::Value,
    limits: McpSchemaLimits,
    collect_headers: bool,
    projections: &mut Vec<McpHeaderProjection>,
) -> Result<(), McpContractError> {
    let bytes = serde_json::to_vec(schema)
        .map_err(|error| McpContractError::InvalidSchema(error.to_string()))?
        .len();
    check_limit("bytes", bytes, limits.max_bytes)?;

    let mut nodes = 0usize;
    let mut subschemas = 0usize;
    let mut total_pattern_bytes = 0usize;
    let mut seen_headers = HashSet::new();
    let mut stack = vec![(
        schema,
        ROOT_VALUE_DEPTH,
        true,
        Vec::<String>::new(),
        SchemaTraversalPosition::Schema,
    )];

    while let Some((value, depth, reachable, path, position)) = stack.pop() {
        nodes += 1;
        check_limit("nodes", nodes, limits.max_nodes)?;
        check_limit("depth", depth, limits.max_depth)?;

        if matches!(position, SchemaTraversalPosition::PropertiesContainer) {
            if let serde_json::Value::Object(properties) = value {
                for (property, property_schema) in properties {
                    let mut property_path = path.clone();
                    property_path.push(property.clone());
                    stack.push((
                        property_schema,
                        depth + 1,
                        reachable,
                        property_path,
                        SchemaTraversalPosition::Schema,
                    ));
                }
                continue;
            }
        }

        match value {
            serde_json::Value::Object(object) => {
                for keyword in ["$ref", "$dynamicRef"] {
                    if let Some(serde_json::Value::String(reference)) = object.get(keyword) {
                        if !reference.starts_with('#') {
                            return Err(McpContractError::ExternalReference {
                                keyword,
                                reference: reference.clone(),
                            });
                        }
                    }
                }
                if let Some(serde_json::Value::String(pattern)) = object.get("pattern") {
                    add_pattern_bytes(pattern.len(), &mut total_pattern_bytes, limits)?;
                }
                if let Some(serde_json::Value::Object(pattern_properties)) =
                    object.get("patternProperties")
                {
                    for pattern in pattern_properties.keys() {
                        add_pattern_bytes(pattern.len(), &mut total_pattern_bytes, limits)?;
                    }
                }
                if collect_headers {
                    if let Some(annotation) = object.get("x-mcp-header") {
                        let annotation = annotation.as_str().ok_or_else(|| {
                            McpContractError::InvalidHeaderName(annotation.to_string())
                        })?;
                        if !reachable || path.is_empty() {
                            return Err(McpContractError::UnreachableHeaderProjection(
                                annotation.to_string(),
                            ));
                        }
                        let normalized_annotation = annotation.to_ascii_lowercase();
                        if !seen_headers.insert(normalized_annotation.clone()) {
                            return Err(McpContractError::DuplicateHeaderProjection(
                                annotation.to_string(),
                            ));
                        }
                        if !is_http_token(annotation) {
                            return Err(McpContractError::InvalidHeaderName(
                                annotation.to_string(),
                            ));
                        }
                        let complete_name = format!("mcp-param-{normalized_annotation}");
                        let header_name = http::HeaderName::from_bytes(complete_name.as_bytes())
                            .map_err(|_| {
                                McpContractError::InvalidHeaderName(annotation.to_string())
                            })?;
                        let schema_type = object
                            .get("type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("missing")
                            .to_string();
                        let kind = match schema_type.as_str() {
                            "string" => McpHeaderValueKind::String,
                            "integer" => McpHeaderValueKind::Integer,
                            "boolean" => McpHeaderValueKind::Boolean,
                            _ => {
                                return Err(McpContractError::UnsupportedHeaderValueKind {
                                    header: complete_name,
                                    schema_type,
                                });
                            }
                        };
                        let actual = projections.len() + 1;
                        check_limit("header_projections", actual, limits.max_header_projections)?;
                        projections.push(McpHeaderProjection {
                            header_name,
                            property_path: path.clone(),
                            kind,
                        });
                    }
                }

                for keyword in ["$defs", "definitions"] {
                    if let Some(serde_json::Value::Object(entries)) = object.get(keyword) {
                        subschemas += entries.len();
                        check_limit("subschemas", subschemas, limits.max_subschemas)?;
                    }
                }
                for keyword in ["anyOf", "oneOf", "allOf"] {
                    if let Some(serde_json::Value::Array(entries)) = object.get(keyword) {
                        subschemas += entries.len();
                        check_limit("subschemas", subschemas, limits.max_subschemas)?;
                    }
                }
                for keyword in ["if", "then", "else"] {
                    if object
                        .get(keyword)
                        .is_some_and(serde_json::Value::is_object)
                    {
                        subschemas += 1;
                        check_limit("subschemas", subschemas, limits.max_subschemas)?;
                    }
                }

                for (keyword, child) in object {
                    if keyword == "properties" {
                        if child.is_object() {
                            stack.push((
                                child,
                                depth + 1,
                                reachable,
                                path.clone(),
                                SchemaTraversalPosition::PropertiesContainer,
                            ));
                            continue;
                        }
                    }
                    stack.push((
                        child,
                        depth + 1,
                        false,
                        path.clone(),
                        SchemaTraversalPosition::Schema,
                    ));
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    stack.push((
                        item,
                        depth + 1,
                        false,
                        path.clone(),
                        SchemaTraversalPosition::Schema,
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn check_limit(limit: &'static str, actual: usize, maximum: usize) -> Result<(), McpContractError> {
    if actual > maximum {
        Err(McpContractError::LimitExceeded {
            limit,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn add_pattern_bytes(
    bytes: usize,
    total: &mut usize,
    limits: McpSchemaLimits,
) -> Result<(), McpContractError> {
    check_limit("pattern_bytes", bytes, limits.max_pattern_bytes)?;
    *total += bytes;
    check_limit(
        "total_pattern_bytes",
        *total,
        limits.max_total_pattern_bytes,
    )
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().iter().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            )
        })
}

fn value_at_path<'a>(
    body: &'a serde_json::Value,
    path: &[String],
) -> Option<&'a serde_json::Value> {
    let mut current = body;
    for property in path {
        current = current.as_object()?.get(property)?;
    }
    Some(current)
}

fn header_value_for_body(
    projection: &McpHeaderProjection,
    value: &serde_json::Value,
) -> Result<String, McpContractError> {
    let label = projection.header_name.as_str().to_string();
    match projection.kind {
        McpHeaderValueKind::String => value
            .as_str()
            .map(encode_header_value)
            .ok_or(McpContractError::MirroredHeaderMismatch(label)),
        McpHeaderValueKind::Integer => {
            integer_at_header_boundary(value, &label).map(|value| value.to_string())
        }
        McpHeaderValueKind::Boolean => value
            .as_bool()
            .map(|value| if value { "true" } else { "false" }.to_string())
            .ok_or(McpContractError::MirroredHeaderMismatch(label)),
    }
}

fn integer_at_header_boundary(
    value: &serde_json::Value,
    header: &str,
) -> Result<i128, McpContractError> {
    let number = value
        .as_number()
        .ok_or_else(|| McpContractError::MirroredHeaderMismatch(header.to_string()))?;
    if let Some(value) = number.as_i64() {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(McpContractError::UnsafeProjectedInteger(header.to_string()));
        }
        return Ok(i128::from(value));
    }
    if let Some(value) = number.as_u64() {
        if value > MAX_SAFE_INTEGER {
            return Err(McpContractError::UnsafeProjectedInteger(header.to_string()));
        }
        return Ok(i128::from(value));
    }
    if let Some(value) = number.as_f64() {
        if !value.is_finite() || value.fract() != 0.0 {
            return Err(McpContractError::MirroredHeaderMismatch(header.to_string()));
        }
        if value.abs() > MAX_SAFE_INTEGER as f64 {
            return Err(McpContractError::UnsafeProjectedInteger(header.to_string()));
        }
        return Ok(value as i128);
    }
    Err(McpContractError::MirroredHeaderMismatch(header.to_string()))
}

fn parse_safe_integer(value: &str) -> Option<i128> {
    if let Ok(value) = value.parse::<i64>() {
        if value.unsigned_abs() <= MAX_SAFE_INTEGER {
            return Some(i128::from(value));
        }
    }
    if let Ok(value) = value.parse::<u64>() {
        if value <= MAX_SAFE_INTEGER {
            return Some(i128::from(value));
        }
    }
    None
}
