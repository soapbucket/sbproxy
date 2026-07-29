//! Generic and Presidio provider contracts.

use serde_json::{json, Value};

use super::{
    ExternalGuardrailConfig, ExternalGuardrailRequest, GuardrailCallError, GuardrailProvider,
    GuardrailVerdict,
};

pub(super) fn request_body(
    config: &ExternalGuardrailConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    match config.provider {
        GuardrailProvider::Presidio => {
            json!({ "text": request.content, "language": config.language.as_deref().unwrap_or("en") })
        }
        GuardrailProvider::Generic => {
            json!({ "input": request.content, "model": request.model, "phase": request.phase.as_str() })
        }
        _ => unreachable!("only generic and Presidio use this request builder"),
    }
}

pub(super) fn parse(
    provider: GuardrailProvider,
    body: &Value,
) -> Result<GuardrailVerdict, GuardrailCallError> {
    if provider == GuardrailProvider::Presidio {
        let findings = body.as_array().ok_or(GuardrailCallError::InvalidVerdict)?;
        let categories = findings
            .iter()
            .filter_map(|item| {
                item.get("entity_type")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        return Ok(GuardrailVerdict {
            allowed: findings.is_empty(),
            reason: (!findings.is_empty())
                .then(|| "presidio identified protected entities".to_string()),
            categories,
            ..GuardrailVerdict::default()
        });
    }
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
    let reason = body
        .get("reason")
        .or_else(|| body.get("message"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let categories = body
        .get("categories")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let scores = body
        .get("scores")
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .filter_map(|(key, value)| value.as_f64().map(|score| (key.clone(), score)))
                .collect()
        })
        .unwrap_or_default();
    Ok(GuardrailVerdict {
        allowed,
        reason,
        categories,
        scores,
    })
}
