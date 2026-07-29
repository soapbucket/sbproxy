//! Generic and Presidio provider contracts.

use serde_json::{json, Value};

use super::{
    ExternalGuardrailRequest, GenericConfig, GuardrailCallError, GuardrailVerdict, PresidioConfig,
};

pub(super) fn generic_request(
    _config: &GenericConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    json!({
        "input": request.content,
        "model": request.model,
        "phase": request.phase.as_str()
    })
}

pub(super) fn presidio_request(
    config: &PresidioConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    json!({ "text": request.content, "language": config.language })
}

pub(super) fn parse_generic(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    let allowed = body
        .get("allowed")
        .and_then(Value::as_bool)
        .or_else(|| {
            body.get("flagged")
                .and_then(Value::as_bool)
                .map(|value| !value)
        })
        .or_else(|| {
            body.get("blocked")
                .and_then(Value::as_bool)
                .map(|value| !value)
        })
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let categories = body
        .get("categories")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(normalize_category)
                .take(32)
                .collect()
        })
        .unwrap_or_default();
    let scores = body
        .get("scores")
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .filter_map(|(key, value)| {
                    let key = normalize_category(key)?;
                    let score = value.as_f64().filter(|score| score.is_finite())?;
                    Some((key, score))
                })
                .take(32)
                .collect()
        })
        .unwrap_or_default();
    Ok(GuardrailVerdict {
        allowed,
        reason: (!allowed).then(|| "external guardrail blocked content".to_string()),
        categories,
        scores,
    })
}

pub(super) fn parse_presidio(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    let findings = body.as_array().ok_or(GuardrailCallError::InvalidVerdict)?;
    let categories = findings
        .iter()
        .filter_map(|item| item.get("entity_type").and_then(Value::as_str))
        .filter_map(normalize_category)
        .take(32)
        .collect::<Vec<_>>();
    Ok(GuardrailVerdict {
        allowed: findings.is_empty(),
        reason: (!findings.is_empty())
            .then(|| "presidio identified protected entities".to_string()),
        categories,
        ..GuardrailVerdict::default()
    })
}

fn normalize_category(value: &str) -> Option<String> {
    let normalized = value
        .chars()
        .take(64)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    (!normalized.is_empty()).then_some(normalized)
}
