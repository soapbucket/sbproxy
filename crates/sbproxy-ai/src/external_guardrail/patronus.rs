//! Patronus evaluation provider contract.

use serde_json::{json, Value};

use super::{
    ExternalGuardrailRequest, GuardrailCallError, GuardrailPhase, GuardrailVerdict, PatronusConfig,
};

pub(super) fn patronus_request(
    config: &PatronusConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    let mut evaluator = json!({"evaluator": config.evaluator});
    if let Some(criteria) = &config.criteria {
        evaluator["criteria"] = Value::String(criteria.clone());
    }
    let mut body = json!({"evaluators": [evaluator]});
    match request.phase {
        GuardrailPhase::Input => {
            body["task_input"] = Value::String(request.content.to_string());
        }
        GuardrailPhase::Output => {
            body["task_output"] = Value::String(request.content.to_string());
        }
    }
    body
}

pub(super) fn parse_patronus(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .filter(|results| results.len() == 1)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let result = results[0]
        .as_object()
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    if result.get("status").and_then(Value::as_str) != Some("success") {
        return Err(GuardrailCallError::InvalidVerdict);
    }
    let passed = result
        .get("evaluation_result")
        .and_then(Value::as_object)
        .and_then(|evaluation| evaluation.get("pass"))
        .and_then(Value::as_bool)
        .ok_or(GuardrailCallError::InvalidVerdict)?;

    Ok(GuardrailVerdict {
        allowed: passed,
        reason: (!passed).then(|| "patronus blocked content".to_string()),
        ..GuardrailVerdict::default()
    })
}
