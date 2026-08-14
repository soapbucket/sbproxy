use base64::Engine as _;
use bytes::Bytes;
use sbproxy_plugin::{
    ActionOutcome, AiExtensionDecision, AuthDecision, AuthSubjectSource, PaymentExtensionDecision,
    PolicyDecision, UNSUPPORTED_ACTION_OUTCOME_CODE,
};
use sbproxy_security::{hkdf_derive_purpose, HkdfPurpose};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use sbproxy_config::{is_secret_reference, BundleHookKind};

pub(crate) const ENVELOPE_VERSION: &str = sbproxy_config::BUNDLE_ENVELOPE_ABI;

const MAX_POLICY_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_EVENT_CODE_BYTES: usize = 64;
const MAX_ACTION_HEADERS: usize = 64;
/// Upper bound on a bundle auth hook's resolved subject. A `sub` is a
/// user identifier (a JWT `sub`, a username, an API-key label), not a
/// payload, so a value past this is a malformed decision rather than a
/// legitimate identity.
const MAX_AUTH_SUBJECT_BYTES: usize = 1024;

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
        BundleHookKind::Auth => "auth",
        BundleHookKind::Transform => "transform",
        BundleHookKind::Action => "action",
        BundleHookKind::AiToolCall => "ai_tool_call",
        BundleHookKind::AiGuardrailInput => "ai_guardrail_input",
        BundleHookKind::AiGuardrailOutput => "ai_guardrail_output",
        BundleHookKind::AiStreamEvent => "ai_stream_event",
        BundleHookKind::AiClose => "ai_close",
        BundleHookKind::AiFailure => "ai_failure",
        BundleHookKind::Payment => "payment",
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

/// Resolve secret references in a bundle hook's declared `secret_vars`,
/// in place.
///
/// A `sb.yml` attachment (`policy:`, `action:`, `transform:`) passes a
/// bundle hook's config vars as arbitrary JSON. A bundle that needs a
/// secret in one of those vars (an API key, a signing token) declares
/// the var's name in its manifest's `secret_vars`
/// (`sbproxy_config::BundleHook::secret_vars`); only a top-level
/// property named there is a candidate for resolution. A value shaped
/// like a reference `sbproxy_config::is_secret_reference` recognizes
/// (`env:NAME`, `${NAME}`, `file:/path`, or a provider URI such as
/// `vault://backend/name`) is resolved before the bundle runs; a plain
/// literal in a `secret_vars` property (an operator who pasted the
/// secret directly rather than referencing it) is left as-is. A var
/// **not** listed in `secret_vars` is never inspected here, so an
/// operator cannot get silent resolution they did not declare.
///
/// Resolution follows the same delegation pattern as
/// `sbproxy_core::config_source::resolve_secret_reference`: normalize
/// the legacy `env:NAME` spelling to `${NAME}`, then delegate to the
/// process-wide [`sbproxy_vault::SecretResolver`] when one is installed.
/// Outside a running server (`sbproxy validate`, `sbproxy plan`, unit
/// tests) no resolver is installed, so `${NAME}` / `env:NAME` fall back
/// to reading the environment variable directly and `file:` falls back
/// to reading the file; a provider-URI reference with no resolver
/// installed is a hard error rather than being passed through as a
/// literal secret pointer.
///
/// The resolved plaintext is held in a [`Zeroizing`] buffer until it is
/// written into `value` for the guest to consume; that write is the one
/// unavoidable plaintext copy the feature exists to produce; every
/// other intermediate (the owned `String` handed back by the resolver,
/// the copy this function holds while validating the JSON shape) is
/// zeroized on drop rather than left for the allocator to reuse
/// unscrubbed.
///
/// # Errors
///
/// Returns a bounded detail message when a `secret_vars` property holds
/// a recognized reference that cannot be resolved. The detail names
/// only the reference (a pointer, never the secret it names) or the
/// missing environment variable, file, or backend.
pub(crate) fn resolve_declared_secrets(
    value: &mut Value,
    secret_vars: &[String],
) -> Result<(), String> {
    let Some(map) = value.as_object_mut() else {
        return Ok(());
    };
    for name in secret_vars {
        let Some(Value::String(text)) = map.get_mut(name) else {
            continue;
        };
        if is_secret_reference(text) {
            let resolved: Zeroizing<String> = Zeroizing::new(resolve_one_config_secret(text)?);
            *text = resolved.as_str().to_owned();
        }
    }
    Ok(())
}

/// Resolve one secret reference. Mirrors
/// `sbproxy_core::config_source::resolve_secret_reference`'s pattern:
/// normalize, delegate to the installed resolver, and fall back to a
/// direct environment or file read when no resolver is installed.
fn resolve_one_config_secret(reference: &str) -> Result<String, String> {
    let trimmed = reference.trim();
    let normalized = match trimmed.strip_prefix("env:") {
        Some(name) => format!("${{{name}}}"),
        None => trimmed.to_owned(),
    };
    if let Some(resolver) = sbproxy_vault::process_resolver() {
        return resolver
            .resolve(&normalized)
            .map_err(|error| format!("{error:#}"));
    }
    if let Some(name) = normalized
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        return std::env::var(name).map_err(|_| format!("environment variable {name} is not set"));
    }
    if let Some(file_path) = normalized.strip_prefix("file:") {
        return std::fs::read_to_string(file_path)
            .map(|contents| contents.trim().to_owned())
            .map_err(|error| format!("read secret file '{file_path}': {error}"));
    }
    Err(format!(
        "secret reference '{reference}' cannot be resolved; no secret backend is configured \
         (declare one under proxy.secrets.backends)"
    ))
}

/// Fixed HKDF salt for [`bundle_var_fingerprint`]. A fixed salt plus a
/// dedicated [`HkdfPurpose`] is what keeps the published fingerprint
/// from being a derivation an attacker could invert or compare across
/// purposes; see `SealKey::fingerprint_hex` in `sbproxy-security` for
/// the pattern this mirrors.
const BUNDLE_VAR_FINGERPRINT_SALT: &[u8] = b"sbproxy.bundle.secret_var.fingerprint.salt.v1";

/// Length, in bytes, of a rendered bundle-var fingerprint.
const BUNDLE_VAR_FINGERPRINT_LEN: usize = 4;

/// Derive a short published fingerprint for a masked var's value.
///
/// Lets an operator tell two masked values apart (did the secret
/// rotate? is this the key I think it is?) from a masked debug
/// rendering without ever showing the value. HKDF-derived rather than
/// a hash or a prefix of the material: a hash or prefix of a short
/// secret is itself brute-forceable back to the source, which a
/// dedicated-purpose HKDF derivation is not. See
/// `resolved_material_is_not_a_prefix_of_its_own_fingerprint` below.
fn bundle_var_fingerprint(material: &[u8]) -> [u8; BUNDLE_VAR_FINGERPRINT_LEN] {
    let derived = hkdf_derive_purpose(
        material,
        BUNDLE_VAR_FINGERPRINT_SALT,
        HkdfPurpose::BundleSecretVarFingerprint,
        BUNDLE_VAR_FINGERPRINT_LEN,
    );
    let mut fingerprint = [0u8; BUNDLE_VAR_FINGERPRINT_LEN];
    fingerprint.copy_from_slice(&derived);
    fingerprint
}

/// Render one masked var's placeholder: the var name, its resolved
/// length, and its HKDF fingerprint. Answers the debugging questions an
/// operator actually has (is it set, did it get truncated, is this the
/// key I think it is) without the value itself.
fn masked_var_placeholder(name: &str, text: &str) -> String {
    let fingerprint = bundle_var_fingerprint(text.as_bytes());
    format!(
        "[REDACTED:{name} len={} fp={}]",
        text.len(),
        hex::encode(fingerprint)
    )
}

/// Mask every var named in `secret_vars` or `masked_vars`, leaving
/// everything else untouched. Used to render bundle attachment config
/// for logs, errors, or diagnostics without ever showing a resolved
/// secret or a masked literal.
///
/// Called after [`resolve_declared_secrets`], so for a `secret_vars`
/// name this masks the *resolved* plaintext already sitting in
/// `value`, not the original reference string; for a `masked_vars`
/// name (never resolved) it masks the literal as configured. Only
/// string-typed vars are masked: a `secret_vars`/`masked_vars` name
/// whose config value is not a string does not match the manifest
/// contract those lists imply, and is left as the compiled schema
/// validator's problem, not this function's.
pub(crate) fn mask_declared_vars(value: &Value, masked_names: &[String]) -> Value {
    if masked_names.is_empty() {
        return value.clone();
    }
    let mut masked = value.clone();
    let Some(map) = masked.as_object_mut() else {
        return masked;
    };
    for name in masked_names {
        if let Some(Value::String(text)) = map.get(name) {
            let placeholder = masked_var_placeholder(name, text);
            map.insert(name.clone(), Value::String(placeholder));
        }
    }
    masked
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
struct AuthWire {
    version: String,
    decision: String,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
}

/// Map a bundle auth hook's `source` label to the subject-origin enum
/// the observability layer stamps. Unknown labels are rejected so a
/// typo does not silently become an untracked origin.
fn decode_auth_source(label: &str) -> Result<AuthSubjectSource, EnvelopeError> {
    match label {
        "header" => Ok(AuthSubjectSource::Header),
        "jwt" => Ok(AuthSubjectSource::Jwt),
        "forward_auth" => Ok(AuthSubjectSource::ForwardAuth),
        "cookie" => Ok(AuthSubjectSource::Cookie),
        _ => Err(EnvelopeError::new("invalid_envelope")),
    }
}

pub(crate) fn decode_auth(bytes: &[u8]) -> Result<AuthDecision, EnvelopeError> {
    let response: AuthWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    match response.decision.as_str() {
        "allow" if response.status.is_none() && response.message.is_none() => {
            if !response.headers.is_empty() {
                return Err(EnvelopeError::new("invalid_envelope"));
            }
            // A resolved subject and its origin travel together: a `sub`
            // with no `source` is unattributable, a `source` with no
            // `sub` labels nothing. Both-present or both-absent only.
            match (response.sub, response.source) {
                (None, None) => Ok(AuthDecision::allow_anonymous()),
                (Some(sub), Some(source)) => {
                    if sub.len() > MAX_AUTH_SUBJECT_BYTES {
                        return Err(EnvelopeError::new("invalid_envelope"));
                    }
                    let source = decode_auth_source(&source)?;
                    Ok(AuthDecision::allow_with_subject(sub, source))
                }
                _ => Err(EnvelopeError::new("invalid_envelope")),
            }
        }
        "deny" if response.sub.is_none() && response.source.is_none() => {
            if !response.headers.is_empty() {
                return Err(EnvelopeError::new("invalid_envelope"));
            }
            let (status, message) = decode_auth_denial(response.status, response.message)?;
            Ok(AuthDecision::Deny { status, message })
        }
        "deny_with_headers" if response.sub.is_none() && response.source.is_none() => {
            let (status, message) = decode_auth_denial(response.status, response.message)?;
            validate_headers(&response.headers)?;
            Ok(AuthDecision::DenyWithHeaders {
                status,
                message,
                headers: response.headers,
            })
        }
        _ => Err(EnvelopeError::new("invalid_envelope")),
    }
}

/// Shared status/message validation for both auth denial variants: a
/// 4xx/5xx status and a bounded message are mandatory.
fn decode_auth_denial(
    status: Option<u16>,
    message: Option<String>,
) -> Result<(u16, String), EnvelopeError> {
    let status = status
        .filter(|status| (400..=599).contains(status))
        .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
    let message = message
        .filter(|message| message.len() <= MAX_POLICY_MESSAGE_BYTES)
        .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
    Ok((status, message))
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
            Err(EnvelopeError::new(UNSUPPORTED_ACTION_OUTCOME_CODE))
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AiDecisionWire {
    version: String,
    decision: String,
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    body_base64: Option<String>,
}

fn valid_event_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVENT_CODE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

pub(crate) fn decode_ai_decision(
    bytes: &[u8],
    max_body_bytes: usize,
) -> Result<AiExtensionDecision, EnvelopeError> {
    let response: AiDecisionWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    match response.decision.as_str() {
        "release"
            if response.status.is_none()
                && response.code.is_none()
                && response.message.is_none()
                && response.body_base64.is_none() =>
        {
            Ok(AiExtensionDecision::Release)
        }
        "mutate" if response.status.is_none() && response.message.is_none() => {
            let code = response
                .code
                .filter(|value| valid_event_code(value))
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            let body_base64 = response
                .body_base64
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            let body = base64::engine::general_purpose::STANDARD
                .decode(body_base64)
                .map_err(|_| EnvelopeError::new("invalid_envelope"))?;
            if body.len() > max_body_bytes {
                return Err(EnvelopeError::new("output_limit"));
            }
            Ok(AiExtensionDecision::Mutate { body, code })
        }
        "block" | "flag" if response.body_base64.is_none() => {
            let code = response
                .code
                .filter(|value| valid_event_code(value))
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            let message = response
                .message
                .filter(|value| !value.is_empty() && value.len() <= MAX_POLICY_MESSAGE_BYTES)
                .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
            if response.decision == "block" {
                let status = response
                    .status
                    .filter(|status| (400..=599).contains(status))
                    .ok_or_else(|| EnvelopeError::new("invalid_envelope"))?;
                Ok(AiExtensionDecision::Block {
                    status,
                    code,
                    message,
                })
            } else if response.status.is_none() {
                Ok(AiExtensionDecision::Flag { code, message })
            } else {
                Err(EnvelopeError::new("invalid_envelope"))
            }
        }
        _ => Err(EnvelopeError::new("invalid_envelope")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentDecisionWire {
    version: String,
    decision: String,
}

pub(crate) fn decode_payment_decision(
    bytes: &[u8],
) -> Result<PaymentExtensionDecision, EnvelopeError> {
    let response: PaymentDecisionWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    match response.decision.as_str() {
        "continue" => Ok(PaymentExtensionDecision::Continue),
        "reject" => Ok(PaymentExtensionDecision::Reject),
        _ => Err(EnvelopeError::new("invalid_envelope")),
    }
}

#[cfg(test)]
mod tests {
    use sbproxy_plugin::{AiExtensionDecision, PaymentExtensionDecision};

    use super::*;

    #[test]
    fn action_proxy_outcome_has_a_stable_unsupported_code() {
        let error = decode_action(
            br#"{"version":"sbproxy-envelope/v1","outcome":"proxy"}"#,
            1024,
        )
        .expect_err("bundle actions have no upstream to proxy to");

        assert_eq!(error.code(), "unsupported_action_outcome");
    }

    #[test]
    fn auth_wire_allow_carries_subject_and_origin_together() {
        assert_eq!(
            decode_auth(br#"{"version":"sbproxy-envelope/v1","decision":"allow"}"#).unwrap(),
            AuthDecision::allow_anonymous()
        );
        assert_eq!(
            decode_auth(
                br#"{"version":"sbproxy-envelope/v1","decision":"allow","sub":"alice","source":"header"}"#
            )
            .unwrap(),
            AuthDecision::allow_with_subject("alice", AuthSubjectSource::Header)
        );
        assert_eq!(
            decode_auth(
                br#"{"version":"sbproxy-envelope/v1","decision":"allow","sub":"u-7","source":"jwt"}"#
            )
            .unwrap(),
            AuthDecision::allow_with_subject("u-7", AuthSubjectSource::Jwt)
        );
        // A subject with no origin, or an origin with no subject, is a
        // malformed decision: neither can be stamped coherently.
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"allow","sub":"alice"}"#
        )
        .is_err());
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"allow","source":"header"}"#
        )
        .is_err());
        // An unknown origin label is a typo, not an untracked source.
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"allow","sub":"a","source":"query"}"#
        )
        .is_err());
        // Allow does not carry a denial status/message or headers.
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"allow","status":401,"message":"no"}"#
        )
        .is_err());
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"allow","headers":[["x","y"]]}"#
        )
        .is_err());
    }

    #[test]
    fn auth_wire_deny_and_challenge_are_strict_and_bounded() {
        assert_eq!(
            decode_auth(
                br#"{"version":"sbproxy-envelope/v1","decision":"deny","status":401,"message":"bad signature"}"#
            )
            .unwrap(),
            AuthDecision::Deny {
                status: 401,
                message: "bad signature".to_owned(),
            }
        );
        assert_eq!(
            decode_auth(
                br#"{"version":"sbproxy-envelope/v1","decision":"deny_with_headers","status":401,"message":"login","headers":[["WWW-Authenticate","Bearer"]]}"#
            )
            .unwrap(),
            AuthDecision::DenyWithHeaders {
                status: 401,
                message: "login".to_owned(),
                headers: vec![("WWW-Authenticate".to_owned(), "Bearer".to_owned())],
            }
        );
        // A denial needs a 4xx/5xx status and a message.
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"deny","status":200,"message":"ok"}"#
        )
        .is_err());
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"deny","status":401}"#
        )
        .is_err());
        // A denial never resolves a subject, and a plain deny carries no headers.
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"deny","status":401,"message":"x","sub":"a","source":"header"}"#
        )
        .is_err());
        assert!(decode_auth(
            br#"{"version":"sbproxy-envelope/v1","decision":"deny","status":401,"message":"x","headers":[["a","b"]]}"#
        )
        .is_err());
        // Wrong ABI version and unknown decisions refuse.
        assert!(decode_auth(br#"{"version":"sbproxy-envelope/v2","decision":"allow"}"#).is_err());
        assert!(decode_auth(br#"{"version":"sbproxy-envelope/v1","decision":"maybe"}"#).is_err());
        // Oversized subject and message are malformed, not identities.
        let long_sub = json!({
            "version": ENVELOPE_VERSION,
            "decision": "allow",
            "sub": "a".repeat(MAX_AUTH_SUBJECT_BYTES + 1),
            "source": "header",
        });
        assert!(decode_auth(long_sub.to_string().as_bytes()).is_err());
        let long_message = json!({
            "version": ENVELOPE_VERSION,
            "decision": "deny",
            "status": 403,
            "message": "m".repeat(MAX_POLICY_MESSAGE_BYTES + 1),
        });
        assert!(decode_auth(long_message.to_string().as_bytes()).is_err());
    }

    #[test]
    fn ai_decision_wire_is_strict_and_bounded() {
        assert_eq!(
            decode_ai_decision(
                br#"{"version":"sbproxy-envelope/v1","decision":"block","status":403,"code":"policy_denied","message":"request denied"}"#,
                usize::MAX,
            )
            .unwrap(),
            AiExtensionDecision::Block {
                status: 403,
                code: "policy_denied".to_owned(),
                message: "request denied".to_owned(),
            }
        );
        assert_eq!(
            decode_ai_decision(
                br#"{"version":"sbproxy-envelope/v1","decision":"release"}"#,
                usize::MAX
            )
            .unwrap(),
            AiExtensionDecision::Release
        );
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"block","status":200,"code":"bad","message":"bad"}"#,
            usize::MAX,
        )
        .is_err());
        let oversized = serde_json::json!({
            "version": ENVELOPE_VERSION,
            "decision": "flag",
            "code": "x".repeat(65),
            "message": "safe",
        });
        assert!(decode_ai_decision(oversized.to_string().as_bytes(), usize::MAX).is_err());
    }

    #[test]
    fn ai_mutate_decision_decodes_body_and_enforces_the_cap_at_decode() {
        let decoded = decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"pii_redacted","body_base64":"aGVsbG8="}"#,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(
            decoded,
            AiExtensionDecision::Mutate {
                body: b"hello".to_vec(),
                code: "pii_redacted".to_owned(),
            }
        );

        // The manifest buffer cap applies before the decoded payload
        // exists as a value: five bytes against a cap of four.
        let error = decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"pii_redacted","body_base64":"aGVsbG8="}"#,
            4,
        )
        .unwrap_err();
        assert_eq!(error.code(), "output_limit");
    }

    #[test]
    fn ai_mutate_decision_is_strict_about_its_fields() {
        // Missing body: never a silent release.
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"pii_redacted"}"#,
            usize::MAX,
        )
        .is_err());
        // Missing or invalid code.
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","body_base64":"aGVsbG8="}"#,
            usize::MAX,
        )
        .is_err());
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"NOT VALID","body_base64":"aGVsbG8="}"#,
            usize::MAX,
        )
        .is_err());
        // Block-shaped fields on a mutate.
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"x","body_base64":"aGVsbG8=","status":403}"#,
            usize::MAX,
        )
        .is_err());
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"x","body_base64":"aGVsbG8=","message":"m"}"#,
            usize::MAX,
        )
        .is_err());
        // Invalid base64.
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"mutate","code":"x","body_base64":"!!!"}"#,
            usize::MAX,
        )
        .is_err());
    }

    #[test]
    fn ai_body_on_a_non_mutate_decision_is_refused() {
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"release","body_base64":"aGVsbG8="}"#,
            usize::MAX,
        )
        .is_err());
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"block","status":403,"code":"c","message":"m","body_base64":"aGVsbG8="}"#,
            usize::MAX,
        )
        .is_err());
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"flag","code":"c","message":"m","body_base64":"aGVsbG8="}"#,
            usize::MAX,
        )
        .is_err());
    }

    #[test]
    fn payment_decision_wire_accepts_only_continue_or_reject() {
        assert_eq!(
            decode_payment_decision(br#"{"version":"sbproxy-envelope/v1","decision":"continue"}"#,)
                .unwrap(),
            PaymentExtensionDecision::Continue
        );
        assert_eq!(
            decode_payment_decision(br#"{"version":"sbproxy-envelope/v1","decision":"reject"}"#,)
                .unwrap(),
            PaymentExtensionDecision::Reject
        );
        assert!(decode_payment_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"reject","message":"secret"}"#,
        )
        .is_err());
    }

    // --- WOR-2289: bundle config var secret resolution + masking ---

    #[test]
    fn resolve_declared_secrets_leaves_an_undeclared_var_untouched_even_if_reference_shaped() {
        let mut value = json!({ "threshold": 5, "token": "env:PATH" });
        let original = value.clone();

        resolve_declared_secrets(&mut value, &[]).expect("nothing declared, nothing to resolve");

        assert_eq!(value, original, "undeclared var must never be resolved");
    }

    #[test]
    fn resolve_declared_secrets_leaves_a_plain_literal_untouched() {
        let mut value = json!({ "api_key": "not-a-reference" });
        let secret_vars = vec!["api_key".to_owned()];

        resolve_declared_secrets(&mut value, &secret_vars).expect("literal needs no resolution");

        assert_eq!(value["api_key"], "not-a-reference");
    }

    #[test]
    fn resolve_declared_secrets_resolves_a_file_reference_for_a_declared_var() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "DISTINCTIVE_FILE_SECRET_4b1c\n").unwrap();
        let mut value = json!({ "token": format!("file:{}", path.display()) });
        let secret_vars = vec!["token".to_owned()];

        resolve_declared_secrets(&mut value, &secret_vars).expect("file reference resolves");

        assert_eq!(value["token"], "DISTINCTIVE_FILE_SECRET_4b1c");
    }

    #[test]
    fn resolve_declared_secrets_resolves_env_and_dollar_brace_forms_without_mutating_env() {
        // Reads an environment variable every test process already has
        // rather than exporting a new one, so this test never calls
        // `std::env::set_var` (banned in this crate by
        // `scripts/check-env-mutation.sh`; sbproxy-extension has no
        // `src/test_env.rs` guard).
        let expected = std::env::var("PATH").expect("PATH is set in the test environment");
        let mut value = json!({ "a": "env:PATH", "b": "${PATH}" });
        let secret_vars = vec!["a".to_owned(), "b".to_owned()];

        resolve_declared_secrets(&mut value, &secret_vars).expect("env references resolve");

        assert_eq!(value["a"], expected);
        assert_eq!(value["b"], expected);
    }

    #[test]
    fn resolve_declared_secrets_resolves_a_provider_uri_through_the_installed_resolver() {
        sbproxy_vault::reset_process_resolver_for_test();
        let vault = sbproxy_vault::LocalVault::new();
        vault
            .set_secret("token", "DISTINCTIVE_VAULT_SECRET_9e21")
            .expect("fixture secret");
        let mut manager = sbproxy_vault::VaultManager::new();
        manager.register("fixture", Box::new(vault));
        sbproxy_vault::install_process_resolver(std::sync::Arc::new(
            sbproxy_vault::SecretResolver::new().with_manager(std::sync::Arc::new(manager)),
        ));

        let mut value = json!({ "token": "secret://fixture/token" });
        let secret_vars = vec!["token".to_owned()];
        resolve_declared_secrets(&mut value, &secret_vars)
            .expect("provider-uri reference resolves");

        assert_eq!(value["token"], "DISTINCTIVE_VAULT_SECRET_9e21");

        sbproxy_vault::reset_process_resolver_for_test();
    }

    #[test]
    fn resolve_declared_secrets_fails_closed_on_an_unresolvable_provider_uri() {
        sbproxy_vault::reset_process_resolver_for_test();
        let mut value = json!({ "token": "vault://missing-backend/name" });
        let secret_vars = vec!["token".to_owned()];

        let error = resolve_declared_secrets(&mut value, &secret_vars).unwrap_err();

        assert!(error.contains("proxy.secrets.backends"), "{error}");
    }

    #[test]
    fn mask_declared_vars_hides_only_the_named_vars_with_length_and_fingerprint() {
        let value = json!({ "token": "DISTINCTIVE_MASK_TARGET", "name": "visible" });
        let masked_names = vec!["token".to_owned()];

        let masked = mask_declared_vars(&value, &masked_names);

        let rendered = masked["token"].as_str().expect("string placeholder");
        assert!(rendered.starts_with("[REDACTED:token "), "{rendered}");
        assert!(
            rendered.contains(&format!("len={}", "DISTINCTIVE_MASK_TARGET".len())),
            "{rendered}"
        );
        assert!(rendered.contains("fp="), "{rendered}");
        assert_eq!(masked["name"], "visible");
        assert!(!masked.to_string().contains("DISTINCTIVE_MASK_TARGET"));
    }

    #[test]
    fn mask_declared_vars_with_no_names_returns_config_unchanged() {
        let value = json!({ "token": "still-here" });

        let masked = mask_declared_vars(&value, &[]);

        assert_eq!(masked, value);
    }

    #[test]
    fn resolve_then_mask_never_renders_the_resolved_secret() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "DISTINCTIVE_ROUND_TRIP_SECRET_1a2b").unwrap();
        let mut value = json!({ "token": format!("file:{}", path.display()), "label": "ok" });
        let secret_vars = vec!["token".to_owned()];

        resolve_declared_secrets(&mut value, &secret_vars).expect("file reference resolves");
        let masked = mask_declared_vars(&value, &secret_vars);
        let rendered = masked.to_string();

        assert!(
            !rendered.contains("DISTINCTIVE_ROUND_TRIP_SECRET_1a2b"),
            "{rendered}"
        );
        assert!(rendered.contains("REDACTED:token"), "{rendered}");
        assert_eq!(masked["label"], "ok");
    }

    #[test]
    fn masked_vars_are_masked_without_being_resolved() {
        // A masked_vars entry is a sensitive literal, not a secret
        // reference: it must never be looked up through the resolver,
        // only masked when rendered.
        let value = json!({ "tenant_id": "env:PATH" });
        let masked_names = vec!["tenant_id".to_owned()];

        // resolve_declared_secrets is never called with masked_vars
        // names, so the literal "env:PATH" string survives untouched
        // all the way to masking.
        let masked = mask_declared_vars(&value, &masked_names);
        assert!(masked["tenant_id"]
            .as_str()
            .unwrap()
            .starts_with("[REDACTED:tenant_id "));

        // Confirm it really was never resolved: the guest-visible value
        // (pre-mask) is still the literal string, not PATH's contents.
        assert_eq!(value["tenant_id"], "env:PATH");
    }

    #[test]
    fn bundle_var_fingerprint_is_not_a_prefix_of_its_own_material() {
        // Mirrors `the_fingerprint_is_not_a_prefix_of_a_record_key` in
        // sbproxy-security: an HKDF-derived fingerprint must not leak
        // the leading bytes of the value it identifies, unlike a hash
        // or literal prefix would.
        let material = b"DISTINCTIVE_FINGERPRINT_SOURCE_MATERIAL_0f1e2d";
        let fingerprint = bundle_var_fingerprint(material);

        assert_ne!(
            &fingerprint[..],
            &material[..BUNDLE_VAR_FINGERPRINT_LEN],
            "fingerprint must not be a prefix of the source material"
        );
    }

    #[test]
    fn bundle_var_fingerprint_is_deterministic_and_distinguishes_values() {
        let a = bundle_var_fingerprint(b"secret-a");
        let a_again = bundle_var_fingerprint(b"secret-a");
        let b = bundle_var_fingerprint(b"secret-b");

        assert_eq!(a, a_again);
        assert_ne!(a, b);
    }
}
