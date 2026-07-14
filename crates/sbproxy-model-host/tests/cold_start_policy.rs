use sbproxy_config::{ManagedColdStartPolicy, ManagedDeploymentConfig, ModelHostControlConfig};
use sbproxy_model_host::{compile_desired_state, Catalog, ColdStartPolicy, RuntimeDesiredInput};

fn control(cold_start: Option<&str>) -> ModelHostControlConfig {
    let cold_start = cold_start
        .map(|value| format!(r#", "cold_start": "{value}""#))
        .unwrap_or_default();
    serde_json::from_str(&format!(
        r#"{{
            "deployments": {{
                "coder": {{
                    "model": "qwen2.5-0.5b-instruct",
                    "variant": "q4_k_m"{cold_start}
                }}
            }}
        }}"#
    ))
    .expect("model host control")
}

#[test]
fn operator_policy_is_optional_but_compiled_policy_is_concrete() {
    let unset: ManagedDeploymentConfig =
        serde_json::from_str(r#"{"model":"qwen2.5-0.5b-instruct","variant":"q4_k_m"}"#)
            .expect("deployment config");
    assert_eq!(unset.cold_start, None);

    let desired = compile_desired_state(
        RuntimeDesiredInput {
            source_revision: "cold-start-default".to_string(),
            canonical: Some(control(None)),
            managed_providers: Vec::new(),
            legacy_providers: Vec::new(),
        },
        &Catalog::builtin(),
    )
    .expect("compile default policy");
    assert_eq!(
        desired.deployments["coder"].desired.cold_start,
        ColdStartPolicy::Wait
    );
}

#[test]
fn every_explicit_policy_round_trips() {
    for (wire, configured, compiled) in [
        ("wait", ManagedColdStartPolicy::Wait, ColdStartPolicy::Wait),
        (
            "reject",
            ManagedColdStartPolicy::Reject,
            ColdStartPolicy::Reject,
        ),
        (
            "fallback",
            ManagedColdStartPolicy::Fallback,
            ColdStartPolicy::Fallback,
        ),
    ] {
        let control = control(Some(wire));
        assert_eq!(control.deployments["coder"].cold_start, Some(configured));
        let desired = compile_desired_state(
            RuntimeDesiredInput {
                source_revision: format!("cold-start-{wire}"),
                canonical: Some(control),
                managed_providers: Vec::new(),
                legacy_providers: Vec::new(),
            },
            &Catalog::builtin(),
        )
        .expect("compile explicit policy");
        assert_eq!(desired.deployments["coder"].desired.cold_start, compiled);
        let encoded = serde_json::to_vec(&desired.revision.deployments["coder"])
            .expect("serialize concrete deployment");
        assert!(String::from_utf8(encoded)
            .expect("deployment JSON")
            .contains(&format!(r#""cold_start":"{wire}""#)));
    }
}
