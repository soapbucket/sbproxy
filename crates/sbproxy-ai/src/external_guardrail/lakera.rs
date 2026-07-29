//! Lakera Guard provider contract.

use serde_json::{json, Value};

use super::{
    generic::normalize_category, ExternalGuardrailRequest, GuardrailCallError, GuardrailVerdict,
    LakeraConfig,
};

pub(super) fn lakera_request(
    config: &LakeraConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    let mut body = json!({
        "messages": [{"role": "user", "content": request.content}],
        "breakdown": true,
    });
    if let Some(project_id) = &config.project_id {
        body["project_id"] = Value::String(project_id.clone());
    }
    body
}

pub(super) fn parse_lakera(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    let flagged = body
        .get("flagged")
        .and_then(Value::as_bool)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let breakdown: &[Value] = match body.get("breakdown") {
        Some(value) => value.as_array().ok_or(GuardrailCallError::InvalidVerdict)?,
        None => &[],
    };
    let categories = breakdown
        .into_iter()
        .filter(|item| item.get("detected").and_then(Value::as_bool) == Some(true))
        .filter_map(|item| item.get("detector_type").and_then(Value::as_str))
        .filter_map(normalize_category)
        .take(32)
        .collect();
    Ok(GuardrailVerdict {
        allowed: !flagged,
        reason: flagged.then(|| "lakera blocked content".to_string()),
        categories,
        ..GuardrailVerdict::default()
    })
}
