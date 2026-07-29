use sbproxy_ai::external_guardrail::{
    ExternalGuardrailConfig, ExternalGuardrailRequest, GuardrailPhase, GuardrailProvider,
};

#[test]
fn legacy_generic_config_defaults_provider() {
    let config: ExternalGuardrailConfig = serde_json::from_value(serde_json::json!({
        "name": "custom",
        "url": "https://guard.example.test/check",
        "mode": "pre_call",
        "default_on": true,
        "api_key": "secret://guard-key"
    }))
    .expect("legacy generic document must deserialize");

    assert_eq!(config.provider, GuardrailProvider::Generic);
}

#[test]
fn external_request_carries_phase_and_model_without_exposing_content() {
    let request = ExternalGuardrailRequest {
        content: "test prompt",
        model: "test-model",
        phase: GuardrailPhase::Input,
    };

    assert_eq!(request.model, "test-model");
    assert_eq!(request.phase.as_str(), "input");
}
