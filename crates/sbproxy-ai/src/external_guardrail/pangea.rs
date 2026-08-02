//! Pangea AI Guard provider contract.

use serde_json::{json, Value};

use super::{
    parse_blocked_detector_result, ExternalGuardrailRequest, GuardrailCallError, GuardrailPhase,
    GuardrailVerdict, PangeaConfig,
};

pub(super) fn pangea_request(
    config: &PangeaConfig,
    request: ExternalGuardrailRequest<'_>,
) -> Value {
    let recipe = match request.phase {
        GuardrailPhase::Input => &config.input_recipe,
        GuardrailPhase::Output => &config.output_recipe,
    };
    json!({
        "text": request.content,
        "recipe": recipe,
        "debug": true,
    })
}

pub(super) fn parse_pangea(body: &Value) -> Result<GuardrailVerdict, GuardrailCallError> {
    parse_blocked_detector_result(body, "pangea blocked content")
}
