use sbproxy_config::{
    GovernanceBackendConfig, GovernanceConsistency, KeyGovernanceConfig, ProxyServerConfig,
};

fn parse(yaml: &str) -> ProxyServerConfig {
    serde_yaml::from_str(yaml).expect("governance config should deserialize")
}

#[test]
fn governance_defaults_to_approximate_fail_closed() {
    let proxy = parse(
        r#"
key_management:
  enabled: true
  governance: {}
"#,
    );

    let governance = &proxy.key_management.expect("key management").governance;
    assert_eq!(governance.consistency, GovernanceConsistency::Approximate);
    assert!(governance.backend.is_none());
    assert_eq!(governance.lease_ttl_secs, 120);
    assert_eq!(governance.terminal_retention_secs, 300);
    assert_eq!(
        governance.lease_ttl_millis().expect("lease millis"),
        120_000
    );
    assert_eq!(
        governance
            .terminal_retention_millis()
            .expect("retention millis"),
        300_000
    );
    assert!(!governance.failure_mode_allow);
    assert!(!governance.key_introspection);
    assert!(!governance.require_governed_key);
    governance.validate().expect("default governance config");
}

#[test]
fn strict_governance_requires_an_explicit_redis_backend() {
    let proxy = parse(
        r#"
key_management:
  enabled: true
  governance:
    consistency: strict
"#,
    );

    let error = proxy
        .key_management
        .expect("key management")
        .governance
        .validate()
        .expect_err("strict mode without Redis must fail");
    assert!(
        error
            .to_string()
            .contains("strict governance requires an explicit redis backend"),
        "unexpected error: {error}"
    );
}

#[test]
fn canonical_strict_governance_round_trips() {
    let proxy = parse(
        r#"
key_management:
  enabled: true
  governance:
    consistency: strict
    backend:
      type: redis
      url: rediss://governance.internal:6379/2
    lease_ttl_secs: 180
    terminal_retention_secs: 360
    failure_mode_allow: false
    key_introspection: true
    require_governed_key: true
"#,
    );

    let governance = proxy.key_management.expect("key management").governance;
    assert_eq!(governance.consistency, GovernanceConsistency::Strict);
    assert_eq!(governance.lease_ttl_secs, 180);
    assert_eq!(governance.terminal_retention_secs, 360);
    assert!(governance.key_introspection);
    assert!(governance.require_governed_key);
    assert_eq!(
        governance.backend,
        Some(GovernanceBackendConfig::Redis {
            url: "rediss://governance.internal:6379/2".into(),
        })
    );
    governance.validate().expect("valid strict config");

    let encoded = serde_yaml::to_string(&governance).expect("serialize governance config");
    let decoded: KeyGovernanceConfig =
        serde_yaml::from_str(&encoded).expect("round-trip governance config");
    assert_eq!(governance, decoded);
}

#[test]
fn governance_rejects_invalid_lease_and_redis_url() {
    for (yaml, expected) in [
        (
            r#"
consistency: approximate
lease_ttl_secs: 0
"#,
            "lease_ttl_secs must be positive",
        ),
        (
            r#"
consistency: strict
backend:
  type: redis
  url: http://not-redis.example
"#,
            "redis backend URL must start with redis:// or rediss://",
        ),
        (
            r#"
consistency: strict
backend:
  type: redis
  url: redis://
"#,
            "redis backend URL must include a host",
        ),
        (
            r#"
consistency: approximate
backend:
  type: redis
  url: redis://governance.internal:6379/2
"#,
            "redis governance backend requires strict consistency",
        ),
        (
            r#"
consistency: approximate
lease_ttl_secs: 121
terminal_retention_secs: 120
"#,
            "terminal_retention_secs must be at least lease_ttl_secs",
        ),
    ] {
        let governance: KeyGovernanceConfig =
            serde_yaml::from_str(yaml).expect("typed governance config");
        let error = governance.validate().expect_err("invalid config");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn governance_rejects_duration_conversion_overflow() {
    let governance = KeyGovernanceConfig {
        lease_ttl_secs: u64::MAX,
        terminal_retention_secs: u64::MAX,
        ..KeyGovernanceConfig::default()
    };

    let error = governance
        .validate()
        .expect_err("milliseconds must fit u64");
    assert!(
        error
            .to_string()
            .contains("lease_ttl_secs overflows milliseconds"),
        "unexpected error: {error}"
    );
}

#[test]
fn governance_debug_redacts_dedicated_redis_credentials() {
    let governance = KeyGovernanceConfig {
        consistency: GovernanceConsistency::Strict,
        backend: Some(GovernanceBackendConfig::Redis {
            url: "rediss://operator:super-secret@governance.internal:6379/2".to_string(),
        }),
        ..KeyGovernanceConfig::default()
    };

    let backend_debug = format!("{:?}", governance.backend.as_ref().expect("backend"));
    let config_debug = format!("{governance:?}");
    for rendered in [&backend_debug, &config_debug] {
        assert!(
            rendered.contains("[redacted]"),
            "missing redaction: {rendered}"
        );
        assert!(
            !rendered.contains("operator"),
            "username leaked: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret"),
            "password leaked: {rendered}"
        );
    }
}

#[test]
fn governance_rejects_unknown_fields_and_is_present_in_schema() {
    let typo = serde_yaml::from_str::<KeyGovernanceConfig>(
        r#"
consistency: approximate
failure_mode_open: true
"#,
    );
    assert!(typo.is_err(), "unknown governance fields must be rejected");

    let schema = schemars::schema_for!(ProxyServerConfig);
    let json = serde_json::to_string(&schema).expect("serialize schema");
    for field in [
        "governance",
        "consistency",
        "lease_ttl_secs",
        "terminal_retention_secs",
        "failure_mode_allow",
        "key_introspection",
        "require_governed_key",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing {field}");
    }
}
