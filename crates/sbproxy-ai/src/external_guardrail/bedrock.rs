//! Amazon Bedrock ApplyGuardrail provider contract.

use serde_json::{json, Value};

use super::{
    BedrockConfig, ExternalGuardrailRequest, GuardrailCallError, GuardrailPhase, GuardrailVerdict,
};

pub(super) fn bedrock_request(
    _config: &BedrockConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    json!({
        "source": match request.phase {
            GuardrailPhase::Input => "INPUT",
            GuardrailPhase::Output => "OUTPUT",
        },
        "content": [{"text": {"text": request.content}}],
    })
}

pub(super) fn parse_bedrock(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .ok_or(GuardrailCallError::InvalidVerdict)?;
    let allowed = match action {
        "NONE" => true,
        "GUARDRAIL_INTERVENED" => false,
        _ => return Err(GuardrailCallError::InvalidVerdict),
    };
    Ok(GuardrailVerdict {
        allowed,
        reason: (!allowed).then(|| "bedrock guardrail intervened".to_string()),
        ..GuardrailVerdict::default()
    })
}
