use sbproxy_config::{ModelHostAuthority, ProxyServerConfig};

fn parse(yaml: &str) -> ProxyServerConfig {
    serde_yaml::from_str(yaml).expect("model-host config should deserialize")
}

#[test]
fn canonical_model_host_config_round_trips() {
    let proxy = parse(
        r#"
model_host:
  authority: file_managed
  max_parallel_prepares: 2
  safety_margin: 0.10
  cache:
    directory: /var/lib/sbproxy/models
    budget_gib: 200
  engines:
    vllm:
      launch: container
      image: ghcr.io/vllm-project/vllm-openai@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  deployments:
    coder:
      model: qwen2.5-0.5b-instruct
      variant: q4_k_m
      spread_by: [zone, rack]
      warm: true
      max_concurrency: 4
      queue_timeout_ms: 30000
"#,
    );

    let host = proxy.model_host.expect("typed model host");
    assert_eq!(host.authority, ModelHostAuthority::FileManaged);
    assert_eq!(host.max_parallel_prepares, 2);
    assert_eq!(host.deployments["coder"].max_concurrency, Some(4));
    assert_eq!(host.deployments["coder"].spread_by, ["zone", "rack"]);
    host.validate().expect("complete canonical config");

    let encoded = serde_yaml::to_string(&host).expect("serialize model-host config");
    let decoded = serde_yaml::from_str(&encoded).expect("round-trip model-host config");
    assert_eq!(host, decoded);
}

#[test]
fn generated_proxy_schema_exposes_model_host_deployments() {
    let schema = schemars::schema_for!(ProxyServerConfig);
    let json = serde_json::to_string(&schema).expect("serialize schema");

    assert!(json.contains("\"model_host\""));
    assert!(json.contains("\"deployments\""));
    assert!(json.contains("\"spread_by\""));
    assert!(json.contains("\"max_parallel_prepares\""));
}

#[test]
fn model_host_validation_rejects_invalid_deployments_and_authority() {
    let cases = [
        (
            "empty model",
            r#"
model_host:
  deployments:
    broken:
      model: ""
"#,
            "model must not be empty",
        ),
        (
            "zero concurrency",
            r#"
model_host:
  deployments:
    broken:
      model: qwen2.5-0.5b-instruct
      max_concurrency: 0
"#,
            "max_concurrency must be positive",
        ),
        (
            "duplicate spread label",
            r#"
model_host:
  deployments:
    broken:
      model: qwen2.5-0.5b-instruct
      spread_by: [zone, zone]
"#,
            "spread_by contains an invalid or duplicate label key",
        ),
        (
            "tagged container",
            r#"
model_host:
  engines:
    vllm:
      launch: container
      image: ghcr.io/vllm-project/vllm-openai:v0.10.0
"#,
            "must use an immutable sha256 digest",
        ),
        (
            "admin authority without store",
            r#"
model_host:
  authority: admin_managed
"#,
            "store_path is required",
        ),
    ];

    for (name, yaml, expected) in cases {
        let host = parse(yaml).model_host.expect("typed model host");
        let error = host.validate().expect_err(name);
        assert!(
            error.to_string().contains(expected),
            "{name}: expected {expected:?}, got {error}"
        );
    }
}
