//! CrowdStrike AIDR guard provider contract.

use serde_json::{json, Value};

use super::{
    parse_blocked_detector_result, CrowdStrikeConfig, ExternalGuardrailRequest, GuardrailCallError,
    GuardrailPhase, GuardrailVerdict,
};

pub(super) fn crowdstrike_request(
    config: &CrowdStrikeConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    let mut body = json!({
        "guard_input": {
            "messages": [{"role": "user", "content": request.content}],
        },
    });
    if let Some(application_id) = &config.application_id {
        body["app_id"] = Value::String(application_id.clone());
    }
    if matches!(request.phase, GuardrailPhase::Output) {
        body["event_type"] = Value::String("output".to_string());
    }
    body
}

pub(super) fn parse_crowdstrike(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    parse_blocked_detector_result(body, "crowdstrike blocked content")
}
