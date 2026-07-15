use sbproxy_config::{
    compile_config, GovernanceBackendConfig, GovernanceConsistency, GovernanceFailureMode,
    KeyManagementConfig, MissingRatePolicy, ProxyServerConfig,
};

fn parse_key_management(yaml: &str) -> KeyManagementConfig {
    serde_yaml::from_str(yaml).expect("key-management config should deserialize")
}

fn compile_with_governance(governance: &str) -> anyhow::Result<sbproxy_config::CompiledConfig> {
    compile_config(&format!(
        r#"
proxy:
  key_management:
    enabled: false
{governance}
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers: []
"#
    ))
}

#[test]
fn config_compiler_rejects_invalid_governance_before_startup() {
    let cases = [
        (
            "strict without backend",
            "    governance:\n      consistency: strict",
            "strict consistency requires a Redis backend",
        ),
        (
            "zero lease",
            "    governance:\n      lease_ttl_secs: 0",
            "lease_ttl_secs must be positive",
        ),
        (
            "invalid backend URL",
            "    governance:\n      consistency: strict\n      backend:\n        type: redis\n        url: https://redis.example.com",
            "governance Redis backend url",
        ),
    ];

    for (name, governance, expected) in cases {
        let error = match compile_with_governance(governance) {
            Ok(_) => panic!("{name} must fail during config compilation"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains(expected),
            "{name} returned unexpected error: {message}"
        );
    }
}

#[test]
fn config_compiler_accepts_valid_strict_governance() {
    compile_with_governance(
        "    governance:\n      consistency: strict\n      backend:\n        type: redis\n        url: redis://redis.example.com:6379/4",
    )
    .expect("valid strict governance compiles");
}

#[test]
fn governance_defaults_are_backward_compatible_and_valid() {
    let keys = parse_key_management("{}");
    let governance = &keys.governance;

    assert_eq!(governance.consistency, GovernanceConsistency::Approximate);
    assert_eq!(governance.backend, None);
    assert_eq!(governance.lease_ttl_secs, 120);
    assert_eq!(governance.terminal_retention_secs, 300);
    assert_eq!(governance.failure_mode, GovernanceFailureMode::Closed);
    assert_eq!(governance.missing_rate, MissingRatePolicy::ZeroCost);
    assert_eq!(governance.default_max_output_tokens, 4096);
    keys.validate().expect("default governance config is valid");
}

#[test]
fn strict_redis_governance_round_trips_and_validates() {
    let keys = parse_key_management(
        r#"
governance:
  consistency: strict
  backend:
    type: redis
    url: rediss://governor:secret@redis.example:6380/4
  lease_ttl_secs: 45
  terminal_retention_secs: 180
  failure_mode: allow_unreserved
  missing_rate: require_rate
  default_max_output_tokens: 8192
"#,
    );

    assert_eq!(keys.governance.consistency, GovernanceConsistency::Strict);
    assert_eq!(
        keys.governance.backend,
        Some(GovernanceBackendConfig::Redis {
            url: "rediss://governor:secret@redis.example:6380/4".to_string(),
        })
    );
    assert_eq!(
        keys.governance.failure_mode,
        GovernanceFailureMode::AllowUnreserved
    );
    assert_eq!(keys.governance.missing_rate, MissingRatePolicy::RequireRate);
    keys.validate().expect("strict Redis governance is valid");

    let encoded = serde_yaml::to_string(&keys).expect("serialize key management");
    let decoded: KeyManagementConfig =
        serde_yaml::from_str(&encoded).expect("round-trip key management");
    assert_eq!(decoded.governance, keys.governance);
}

#[test]
fn consistency_and_backend_must_form_a_supported_pair() {
    let approximate_with_backend = parse_key_management(
        r#"
governance:
  consistency: approximate
  backend:
    type: redis
    url: redis://redis:6379/4
"#,
    );
    let error = approximate_with_backend
        .validate()
        .expect_err("approximate mode must stay process-local");
    assert!(
        error
            .to_string()
            .contains("approximate consistency does not accept a backend"),
        "unexpected error: {error}"
    );

    let strict_without_backend = parse_key_management(
        r#"
governance:
  consistency: strict
"#,
    );
    let error = strict_without_backend
        .validate()
        .expect_err("strict mode needs shared atomic state");
    assert!(
        error
            .to_string()
            .contains("strict consistency requires a Redis backend"),
        "unexpected error: {error}"
    );
}

#[test]
fn governance_numeric_bounds_are_validated_before_runtime_conversion() {
    let cases = [
        (
            "zero lease",
            r#"
governance:
  lease_ttl_secs: 0
"#,
            "lease_ttl_secs must be positive",
        ),
        (
            "short terminal retention",
            r#"
governance:
  lease_ttl_secs: 120
  terminal_retention_secs: 119
"#,
            "terminal_retention_secs must be at least the lease TTL and 60-second accounting window",
        ),
        (
            "retention shorter than accounting window",
            r#"
governance:
  lease_ttl_secs: 1
  terminal_retention_secs: 59
"#,
            "terminal_retention_secs must be at least the lease TTL and 60-second accounting window",
        ),
        (
            "zero output ceiling",
            r#"
governance:
  default_max_output_tokens: 0
"#,
            "default_max_output_tokens must be positive",
        ),
        (
            "output ceiling overflow",
            r#"
governance:
  default_max_output_tokens: 4294967296
"#,
            "default_max_output_tokens must fit in a 32-bit token count",
        ),
        (
            "lease millisecond overflow",
            r#"
governance:
  lease_ttl_secs: 18446744073709551615
  terminal_retention_secs: 18446744073709551615
"#,
            "lease_ttl_secs overflows Redis millisecond time",
        ),
        (
            "retention millisecond overflow",
            r#"
governance:
  lease_ttl_secs: 1
  terminal_retention_secs: 18446744073709551615
"#,
            "terminal_retention_secs overflows Redis millisecond time",
        ),
    ];

    for (name, yaml, expected) in cases {
        let keys = parse_key_management(yaml);
        let error = keys.validate().expect_err(name);
        assert!(
            error.to_string().contains(expected),
            "{name}: expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn governed_seed_integer_limits_are_positive_and_lua_exact() {
    const FIRST_INEXACT_LUA_INTEGER: u64 = 9_007_199_254_740_992;
    let cases = [
        ("max_requests_per_minute", 0),
        ("max_requests_per_minute", FIRST_INEXACT_LUA_INTEGER),
        ("max_tokens_per_minute", 0),
        ("max_tokens_per_minute", FIRST_INEXACT_LUA_INTEGER),
        ("max_budget_tokens", 0),
        ("max_budget_tokens", FIRST_INEXACT_LUA_INTEGER),
    ];

    for (field, value) in cases {
        let yaml = format!(
            r#"
seed:
  keys:
    - key_id: governed-seed
      secret: secret
      {field}: {value}
"#,
        );
        let keys = parse_key_management(&yaml);
        let error = match keys.validate() {
            Ok(()) => panic!("{field}={value} must be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains(field),
            "{field}={value}: field missing from error: {message}"
        );
        assert!(
            message.contains(if value == 0 {
                "must be positive"
            } else {
                "exact Redis Lua integer range"
            }),
            "{field}={value}: unexpected error: {message}"
        );
    }
}

#[test]
fn governed_seed_usd_limit_is_positive_finite_and_lua_exact() {
    let cases = [
        ("0", "must be positive"),
        ("-1", "must be positive"),
        (".nan", "must be finite"),
        ("0.0000001", "at least one micro-USD"),
        ("10000000000", "exact Redis Lua integer range"),
    ];

    for (value, expected) in cases {
        let keys = parse_key_management(&format!(
            r#"
seed:
  keys:
    - key_id: governed-seed
      secret: secret
      max_budget_usd: {value}
"#,
        ));
        let error = match keys.validate() {
            Ok(()) => panic!("max_budget_usd={value} must be rejected"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("max_budget_usd"),
            "unexpected error: {message}"
        );
        assert!(message.contains(expected), "unexpected error: {message}");
    }
}

#[test]
fn governed_seed_limits_accept_strict_backend_boundaries() {
    let keys = parse_key_management(
        r#"
seed:
  keys:
    - key_id: governed-seed
      secret: secret
      max_requests_per_minute: 9007199254740991
      max_tokens_per_minute: 9007199254740991
      max_budget_tokens: 9007199254740991
      max_budget_usd: 0.000001
governance:
  lease_ttl_secs: 1
  terminal_retention_secs: 60
"#,
    );

    keys.validate()
        .expect("positive Lua-exact limits and 60-second retention are valid");
}

#[test]
fn config_credentials_reject_unsafe_governance_limits() {
    let cases = [
        (
            "rate-limit zero",
            "      policies:\n        - type: rate_limit\n          rpm: 0",
            "policies[0].rpm",
        ),
        (
            "rate-limit inexact",
            "      policies:\n        - type: rate_limit\n          rpm: 9007199254740992",
            "policies[0].rpm",
        ),
        (
            "token budget zero",
            "      attrs:\n        budget:\n          max_tokens: 0",
            "attrs.budget.max_tokens",
        ),
        (
            "token budget inexact",
            "      attrs:\n        budget:\n          max_tokens: 9007199254740992",
            "attrs.budget.max_tokens",
        ),
        (
            "USD budget zero",
            "      attrs:\n        budget:\n          max_cost_usd: 0",
            "attrs.budget.max_cost_usd",
        ),
        (
            "USD budget nonfinite",
            "      attrs:\n        budget:\n          max_cost_usd: .nan",
            "attrs.budget.max_cost_usd",
        ),
        (
            "USD budget below accounting unit",
            "      attrs:\n        budget:\n          max_cost_usd: 0.0000001",
            "attrs.budget.max_cost_usd",
        ),
        (
            "USD budget inexact",
            "      attrs:\n        budget:\n          max_cost_usd: 10000000000",
            "attrs.budget.max_cost_usd",
        ),
    ];

    for (name, fields, expected_path) in cases {
        let yaml = format!(
            r#"
proxy:
  credentials:
    - name: governed-credential
      type: ai_provider
      provider: openai
{fields}
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers: []
"#,
        );
        let error = match compile_config(&yaml) {
            Ok(_) => panic!("{name} must fail during config compilation"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("governed-credential"),
            "{name}: credential missing from error: {message}"
        );
        assert!(
            message.contains(expected_path),
            "{name}: path missing from error: {message}"
        );
    }
}

#[test]
fn config_credential_governance_validation_covers_tenant_and_origin_scopes() {
    let cases = [
        (
            "tenant",
            r#"
proxy:
  tenants:
    - id: acme
      credentials:
        - name: tenant-governed
          type: ai_provider
          attrs:
            budget:
              max_tokens: 0
origins:
  "ai.example.com":
    tenant_id: acme
    action:
      type: ai_proxy
      providers: []
"#,
            "tenant `acme`",
        ),
        (
            "origin",
            r#"
origins:
  "ai.example.com":
    credentials:
      - name: origin-governed
        type: ai_provider
        policies:
          - type: rate_limit
            rpm: 0
    action:
      type: ai_proxy
      providers: []
"#,
            "origin `ai.example.com`",
        ),
    ];

    for (name, yaml, expected_scope) in cases {
        let error = match compile_config(yaml) {
            Ok(_) => panic!("{name} must fail during config compilation"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains(expected_scope),
            "{name}: scope missing from error: {message}"
        );
    }
}

#[test]
fn config_credentials_accept_governance_numeric_boundaries() {
    compile_config(
        r#"
proxy:
  credentials:
    - name: governed-credential
      type: ai_provider
      policies:
        - type: rate_limit
          rpm: 9007199254740991
      attrs:
        budget:
          max_tokens: 9007199254740991
          max_cost_usd: 0.000001
origins:
  "ai.example.com":
    action:
      type: ai_proxy
      providers: []
"#,
    )
    .expect("Lua-exact credential limits compile");
}

#[test]
fn strict_backend_requires_a_redis_url_with_a_host() {
    for valid in [
        "redis://redis:6379/4",
        "rediss://redis.internal/0",
        "redis://[2001:db8::1]:6379/4",
    ] {
        let yaml = format!(
            "governance:\n  consistency: strict\n  backend:\n    type: redis\n    url: {valid}\n"
        );
        parse_key_management(&yaml)
            .validate()
            .unwrap_or_else(|error| panic!("{valid} should be valid: {error}"));
    }

    for invalid in [
        "http://redis:6379/4",
        "redis://",
        "redis:///4",
        "redis://:6379/4",
        "redis://redis:bad/4",
        "redis://redis:70000/4",
        "redis://2001:db8::1/4",
    ] {
        let yaml = format!(
            "governance:\n  consistency: strict\n  backend:\n    type: redis\n    url: '{invalid}'\n"
        );
        let error = parse_key_management(&yaml)
            .validate()
            .expect_err("malformed Redis URL must fail validation");
        assert!(
            error.to_string().contains("governance Redis backend url"),
            "{invalid}: unexpected error: {error}"
        );
    }
}

#[test]
fn debug_output_redacts_the_governance_backend_url() {
    let keys = parse_key_management(
        r#"
governance:
  consistency: strict
  backend:
    type: redis
    url: redis://governor:super-secret@redis.internal:6379/4
"#,
    );

    let debug = format!("{keys:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("super-secret"));
    assert!(!debug.contains("redis.internal"));
}

#[test]
fn generated_proxy_schema_exposes_the_governance_contract() {
    let schema = schemars::schema_for!(ProxyServerConfig);
    let json = serde_json::to_string(&schema).expect("serialize schema");

    for field in [
        "governance",
        "consistency",
        "backend",
        "lease_ttl_secs",
        "terminal_retention_secs",
        "failure_mode",
        "missing_rate",
        "default_max_output_tokens",
        "allow_unreserved",
        "require_rate",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing {field}");
    }
}
