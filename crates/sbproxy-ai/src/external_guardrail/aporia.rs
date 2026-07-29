//! Aporia Guardrails provider contract.

use serde_json::{json, Value};

use super::{
    AporiaConfig, ExternalGuardrailRequest, GuardrailCallError, GuardrailPhase, GuardrailVerdict,
};

pub(super) fn aporia_request(
    _config: &AporiaConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    let mut body = json!({
        "messages": [{"role": "user", "content": request.content}],
        "validation_target": match request.phase {
            GuardrailPhase::Input => "prompt",
            GuardrailPhase::Output => "response",
        },
        "explain": true,
    });
    if matches!(request.phase, GuardrailPhase::Output) {
        body["response"] = Value::String(request.content.to_string());
    }
    body
}

pub(super) fn parse_aporia(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    let result = body
        .get("result")
        .and_then(Value::as_str)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let allowed = match result {
        "allow" => true,
        "block" => false,
        _ => return Err(GuardrailCallError::InvalidVerdict),
    };
    Ok(GuardrailVerdict {
        allowed,
        reason: (!allowed).then(|| "aporia blocked content".to_string()),
        ..GuardrailVerdict::default()
    })
}
