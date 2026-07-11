use sbproxy_ai::ProviderConfig;

fn provider(yaml: &str) -> ProviderConfig {
    serde_yaml::from_str(yaml).expect("provider should deserialize")
}

#[test]
fn managed_model_provider_references_a_deployment() {
    let provider = provider(
        r#"
name: local-coder
provider_type: managed_model
deployment: coder
models: [coder, coder-fast]
"#,
    );

    assert!(provider.is_managed_model());
    assert_eq!(provider.deployment.as_deref(), Some("coder"));
    provider
        .validate_managed_model()
        .expect("complete managed provider");
}

#[test]
fn managed_model_provider_schema_exposes_deployment_reference() {
    let schema = schemars::schema_for!(ProviderConfig);
    let json = serde_json::to_string(&schema).expect("serialize schema");

    assert!(json.contains("\"deployment\""));
    assert!(json.contains("managed_model"));
}

#[test]
fn managed_model_provider_rejects_ambiguous_upstream_configuration() {
    let cases = [
        (
            "missing deployment",
            r#"
name: local-coder
provider_type: managed_model
"#,
            "requires deployment",
        ),
        (
            "upstream URL",
            r#"
name: local-coder
provider_type: managed_model
deployment: coder
base_url: http://127.0.0.1:9999/v1
allow_private_base_url: true
"#,
            "must not set base_url",
        ),
        (
            "deployment on cloud provider",
            r#"
name: openai
provider_type: openai
deployment: coder
api_key: test
"#,
            "only valid when provider_type is managed_model",
        ),
    ];

    for (name, yaml, expected) in cases {
        let error = provider(yaml).validate_managed_model().expect_err(name);
        assert!(
            error.contains(expected),
            "{name}: expected {expected:?}, got {error}"
        );
    }
}
