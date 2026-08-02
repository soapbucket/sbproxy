use base64::Engine as _;
use bytes::Bytes;
use sbproxy_plugin::{ActionOutcome, PolicyDecision};
use serde::Deserialize;
use serde_json::{json, Value};

use sbproxy_config::BundleHookKind;

pub(crate) const ENVELOPE_VERSION: &str = sbproxy_config::BUNDLE_ENVELOPE_ABI;

const MAX_POLICY_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_ACTION_HEADERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnvelopeError(&'static str);

impl EnvelopeError {
    pub(crate) const fn new(code: &'static str) -> Self {
        Self(code)
    }

    pub(crate) const fn code(self) -> &'static str {
        self.0
    }
}

pub(crate) const fn hook_kind_label(kind: BundleHookKind) -> &'static str {
    match kind {
        BundleHookKind::Policy => "policy",
        BundleHookKind::Transform => "transform",
        BundleHookKind::Action => "action",
        BundleHookKind::AiToolCall => "ai_tool_call",
        BundleHookKind::AiGuardrailInput => "ai_guardrail_input",
        BundleHookKind::AiGuardrailOutput => "ai_guardrail_output",
        BundleHookKind::AiStreamEvent => "ai_stream_event",
        BundleHookKind::AiClose => "ai_close",
        BundleHookKind::ProxyWasm => "proxy_wasm",
    }
}

pub(crate) fn apply_schema_defaults(value: &mut Value, schema: &Value) {
    if value.is_null() {
        if let Some(default) = schema.get("default") {
            *value = default.clone();
        }
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            apply_schema_defaults(value, branch);
        }
    }
    if let (Some(object), Some(properties)) = (
        value.as_object_mut(),
        schema.get("properties").and_then(Value::as_object),
    ) {
        for (name, property_schema) in properties {
            if !object.contains_key(name) {
                if let Some(default) = property_schema.get("default") {
                    object.insert(name.clone(), default.clone());
                }
            }
            if let Some(property_value) = object.get_mut(name) {
                apply_schema_defaults(property_value, property_schema);
            }
        }
    }
    if let (Some(items), Some(item_schema)) = (value.as_array_mut(), schema.get("items")) {
        for item in items {
            apply_schema_defaults(item, item_schema);
        }
    }
}

pub(crate) fn request_value(
    request: &http::Request<Bytes>,
    maximum: usize,
) -> Result<Value, EnvelopeError> {
    if request.body().len() > maximum {
        return Err(EnvelopeError::new("input_limit"));
    }
    let headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| json!([name.as_str(), value]))
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "method": request.method().as_str(),
        "uri": request.uri().to_string(),
        "headers": headers,
        "body_base64": base64::engine::general_purpose::STANDARD.encode(request.body()),
    }))
}

pub(crate) fn serialize_envelope(
    envelope: &Value,
    maximum: usize,
) -> Result<Vec<u8>, EnvelopeError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| EnvelopeError::new("input_invalid"))?;
    if bytes.len() > maximum {
        return Err(EnvelopeError::new("input_limit"));
    }
    Ok(bytes)
}

pub(crate) fn hook_envelope(
    payload_name: &str,
    hook_kind: &str,
    type_name: &str,
    config: &Value,
    payload: Value,
) -> Value {
    let mut envelope = json!({
        "version": ENVELOPE_VERSION,
        "hook": {
            "kind": hook_kind,
            "type": type_name,
        },
        "config": config,
    });
    envelope
        .as_object_mut()
        .expect("literal bundle envelope should be an object")
        .insert(payload_name.to_owned(), payload);
    envelope
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyWire {
    version: String,
    decision: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
}

pub(crate) fn decode_policy(bytes: &[u8]) -> Result<PolicyDecision, EnvelopeError> {
    let response: PolicyWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    match response.decision.as_str() {
        "allow"
            if response.status.is_none()
                && response.message.is_none()
                && response.headers.is_empty() =>
        {
            Ok(PolicyDecision::Allow)
        }
        "deny" => {
            if !response.headers.is_empty() {
                return Err(EnvelopeError::new("invalid_envelope"));
            }
            let status = response
                .status
                .filter(|status| (400..=599).contains(status))
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            let message = response
                .message
                .filter(|message| message.len() <= MAX_POLICY_MESSAGE_BYTES)
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            Ok(PolicyDecision::Deny { status, message })
        }
        "allow_with_headers" if response.status.is_none() && response.message.is_none() => {
            validate_headers(&response.headers)?;
            Ok(PolicyDecision::AllowWithHeaders {
                headers: response.headers,
            })
        }
        _ => Err(EnvelopeError::new("invalid_envelope")),
    }
}

fn validate_headers(headers: &[(String, String)]) -> Result<(), EnvelopeError> {
    if headers.len() > MAX_ACTION_HEADERS {
        return Err(EnvelopeError::new("invalid_envelope"));
    }
    for (name, value) in headers {
        http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| EnvelopeError::new("invalid_envelope"))?;
        http::header::HeaderValue::from_str(value)
            .map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformWire {
    version: String,
    body_base64: String,
}

pub(crate) fn decode_body(bytes: &[u8], maximum: usize) -> Result<Vec<u8>, EnvelopeError> {
    let response: TransformWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    let body = base64::engine::general_purpose::STANDARD
        .decode(response.body_base64)
        .map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if body.len() > maximum {
        return Err(EnvelopeError::new("output_limit"));
    }
    Ok(body)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionWire {
    version: String,
    outcome: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body_base64: Option<String>,
}

pub(crate) fn decode_action(bytes: &[u8], maximum: usize) -> Result<ActionOutcome, EnvelopeError> {
    let response: ActionWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    match response.outcome.as_str() {
        "proxy"
            if response.status.is_none()
                && response.headers.is_empty()
                && response.body_base64.is_none() =>
        {
            Ok(ActionOutcome::Proxy)
        }
        "response" => {
            let status = response
                .status
                .filter(|status| (100..=599).contains(status))
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            validate_headers(&response.headers)?;
            let body = response
                .body_base64
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))
                .and_then(|body| {
                    base64::engine::general_purpose::STANDARD
                        .decode(body)
                        .map_err(|_| EnvelopeError::new("invalid_envelope"))
                })?;
            if body.len() > maximum {
                return Err(EnvelopeError::new("output_limit"));
            }
            Ok(ActionOutcome::Response {
                status,
                headers: response.headers,
                body: Bytes::from(body),
            })
        }
        _ => Err(EnvelopeError::new("invalid_envelope")),
    }
}
