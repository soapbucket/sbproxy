use std::collections::BTreeSet;

use base64::Engine as _;
use bytes::Bytes;
use sbproxy_plugin::{
    ActionOutcome, AiExtensionDecision, PaymentExtensionDecision, PolicyDecision,
    UNSUPPORTED_ACTION_OUTCOME_CODE,
};
use serde::Deserialize;
use serde_json::{json, Value};

use sbproxy_config::{is_secret_reference, BundleHookKind};

pub(crate) const ENVELOPE_VERSION: &str = sbproxy_config::BUNDLE_ENVELOPE_ABI;

const MAX_POLICY_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_EVENT_CODE_BYTES: usize = 64;
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

/// Resolve secret references embedded in a bundle attachment's config
/// values, in place.
///
/// A `sb.yml` attachment (`policy:`, `action:`, `transform:`, or a
/// Proxy-Wasm filter) passes a bundle hook's config vars as arbitrary
/// JSON. A bundle that needs a secret in one of those vars (an API key,
/// a signing token) should not need the operator to write it as a
/// literal: any value shaped like a reference `sbproxy_config::is_secret_reference`
/// recognizes (`env:NAME`, `${NAME}`, `file:/path`, or a provider URI
/// such as `vault://backend/name`) is resolved before the bundle runs.
/// Every other string is a plain literal and is returned unchanged.
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
/// Returns the slash-joined paths (for example `/api_key` or
/// `/upstream/token`) whose value was replaced, so a caller that later
/// shows this config in a log or diagnostic can mask exactly those
/// values with [`mask_config_secrets`] instead of guessing from key
/// names.
///
/// # Errors
///
/// Returns a bounded detail message when a recognized reference cannot
/// be resolved. The detail names only the reference (a pointer, never
/// the secret it names) or the missing environment variable, file, or
/// backend.
pub(crate) fn resolve_config_secrets(value: &mut Value) -> Result<BTreeSet<String>, String> {
    let mut secret_paths = BTreeSet::new();
    let mut path = String::new();
    resolve_config_secrets_at(value, &mut path, &mut secret_paths)?;
    Ok(secret_paths)
}

fn resolve_config_secrets_at(
    value: &mut Value,
    path: &mut String,
    secret_paths: &mut BTreeSet<String>,
) -> Result<(), String> {
    match value {
        Value::String(text) if is_secret_reference(text) => {
            *text = resolve_one_config_secret(text)?;
            secret_paths.insert(config_secret_path(path));
        }
        Value::String(_) => {}
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                let mark = path.len();
                path.push('/');
                path.push_str(&index.to_string());
                resolve_config_secrets_at(item, path, secret_paths)?;
                path.truncate(mark);
            }
        }
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                let mark = path.len();
                path.push('/');
                path.push_str(key);
                resolve_config_secrets_at(nested, path, secret_paths)?;
                path.truncate(mark);
            }
        }
        _ => {}
    }
    Ok(())
}

fn config_secret_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
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

/// Mask every value at a resolved-secret path, leaving everything else
/// untouched. Used to render bundle attachment config for logs, errors,
/// or diagnostics without ever showing a resolved secret value; the
/// paths come from [`resolve_config_secrets`].
pub(crate) fn mask_config_secrets(value: &Value, secret_paths: &BTreeSet<String>) -> Value {
    if secret_paths.is_empty() {
        return value.clone();
    }
    let mut masked = value.clone();
    let mut path = String::new();
    mask_config_secrets_at(&mut masked, &mut path, secret_paths);
    masked
}

fn mask_config_secrets_at(value: &mut Value, path: &mut String, secret_paths: &BTreeSet<String>) {
    if secret_paths.contains(&config_secret_path(path)) {
        *value = Value::String("***MASKED***".to_owned());
        return;
    }
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                let mark = path.len();
                path.push('/');
                path.push_str(&index.to_string());
                mask_config_secrets_at(item, path, secret_paths);
                path.truncate(mark);
            }
        }
        Value::Object(map) => {
            for (key, nested) in map.iter_mut() {
                let mark = path.len();
                path.push('/');
                path.push_str(key);
                mask_config_secrets_at(nested, path, secret_paths);
                path.truncate(mark);
            }
        }
        _ => {}
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
}

fn valid_event_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EVENT_CODE_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

pub(crate) fn decode_ai_decision(bytes: &[u8]) -> Result<AiExtensionDecision, EnvelopeError> {
    let response: AiDecisionWire =
        serde_json::from_slice(bytes).map_err(|_| EnvelopeError::new("invalid_envelope"))?;
    if response.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::new("invalid_version"));
    }
    match response.decision.as_str() {
        "release"
            if response.status.is_none()
                && response.code.is_none()
                && response.message.is_none() =>
        {
            Ok(AiExtensionDecision::Release)
        }
        "block" | "flag" => {
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
    fn ai_decision_wire_is_strict_and_bounded() {
        assert_eq!(
            decode_ai_decision(
                br#"{"version":"sbproxy-envelope/v1","decision":"block","status":403,"code":"policy_denied","message":"request denied"}"#,
            )
            .unwrap(),
            AiExtensionDecision::Block {
                status: 403,
                code: "policy_denied".to_owned(),
                message: "request denied".to_owned(),
            }
        );
        assert_eq!(
            decode_ai_decision(br#"{"version":"sbproxy-envelope/v1","decision":"release"}"#,)
                .unwrap(),
            AiExtensionDecision::Release
        );
        assert!(decode_ai_decision(
            br#"{"version":"sbproxy-envelope/v1","decision":"block","status":200,"code":"bad","message":"bad"}"#,
        )
        .is_err());
        let oversized = serde_json::json!({
            "version": ENVELOPE_VERSION,
            "decision": "flag",
            "code": "x".repeat(65),
            "message": "safe",
        });
        assert!(decode_ai_decision(oversized.to_string().as_bytes()).is_err());
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
    fn resolve_config_secrets_leaves_a_plain_literal_untouched() {
        let mut value = json!({ "threshold": 5, "name": "not-a-reference" });
        let original = value.clone();

        let secret_paths = resolve_config_secrets(&mut value).expect("no reference to resolve");

        assert!(secret_paths.is_empty(), "{secret_paths:?}");
        assert_eq!(value, original);
    }

    #[test]
    fn resolve_config_secrets_resolves_a_file_reference() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "DISTINCTIVE_FILE_SECRET_4b1c\n").unwrap();
        let mut value = json!({ "token": format!("file:{}", path.display()) });

        let secret_paths = resolve_config_secrets(&mut value).expect("file reference resolves");

        assert_eq!(value["token"], "DISTINCTIVE_FILE_SECRET_4b1c");
        assert_eq!(secret_paths, BTreeSet::from(["/token".to_owned()]));
    }

    #[test]
    fn resolve_config_secrets_resolves_env_and_dollar_brace_forms_without_mutating_env() {
        // Reads an environment variable every test process already has
        // rather than exporting a new one, so this test never calls
        // `std::env::set_var` (banned in this crate by
        // `scripts/check-env-mutation.sh`; sbproxy-extension has no
        // `src/test_env.rs` guard).
        let expected = std::env::var("PATH").expect("PATH is set in the test environment");
        let mut value = json!({ "a": "env:PATH", "b": "${PATH}" });

        let secret_paths = resolve_config_secrets(&mut value).expect("env references resolve");

        assert_eq!(value["a"], expected);
        assert_eq!(value["b"], expected);
        assert_eq!(
            secret_paths,
            BTreeSet::from(["/a".to_owned(), "/b".to_owned()])
        );
    }

    #[test]
    fn resolve_config_secrets_resolves_a_provider_uri_through_the_installed_resolver() {
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
        let secret_paths =
            resolve_config_secrets(&mut value).expect("provider-uri reference resolves");

        assert_eq!(value["token"], "DISTINCTIVE_VAULT_SECRET_9e21");
        assert_eq!(secret_paths, BTreeSet::from(["/token".to_owned()]));

        sbproxy_vault::reset_process_resolver_for_test();
    }

    #[test]
    fn resolve_config_secrets_fails_closed_on_an_unresolvable_provider_uri() {
        sbproxy_vault::reset_process_resolver_for_test();
        let mut value = json!({ "token": "vault://missing-backend/name" });

        let error = resolve_config_secrets(&mut value).unwrap_err();

        assert!(error.contains("proxy.secrets.backends"), "{error}");
    }

    #[test]
    fn mask_config_secrets_hides_only_the_resolved_paths() {
        let value = json!({ "token": "DISTINCTIVE_MASK_TARGET", "name": "visible" });
        let secret_paths = BTreeSet::from(["/token".to_owned()]);

        let masked = mask_config_secrets(&value, &secret_paths);

        assert_eq!(masked["token"], "***MASKED***");
        assert_eq!(masked["name"], "visible");
        assert!(!masked.to_string().contains("DISTINCTIVE_MASK_TARGET"));
    }

    #[test]
    fn resolve_then_mask_never_renders_the_resolved_secret() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "DISTINCTIVE_ROUND_TRIP_SECRET_1a2b").unwrap();
        let mut value = json!({ "token": format!("file:{}", path.display()), "label": "ok" });

        let secret_paths = resolve_config_secrets(&mut value).expect("file reference resolves");
        let masked = mask_config_secrets(&value, &secret_paths);
        let rendered = masked.to_string();

        assert!(
            !rendered.contains("DISTINCTIVE_ROUND_TRIP_SECRET_1a2b"),
            "{rendered}"
        );
        assert!(rendered.contains("MASKED"), "{rendered}");
        assert_eq!(masked["label"], "ok");
    }
}
