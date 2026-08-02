use sbproxy_config::{
    FailureMode, GovernanceBackendConfig, GovernanceConsistency, GovernanceFailureMode,
    GovernanceMissingRatePolicy, KeyGovernanceConfig, KeyManagementConfig, ProxyServerConfig,
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
    assert_eq!(governance.failure_mode, GovernanceFailureMode::Closed);
    assert_eq!(
        governance.missing_rate,
        GovernanceMissingRatePolicy::ZeroCost
    );
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
    failure_mode: closed
    missing_rate: zero_cost
    key_introspection: true
    require_governed_key: true
"#,
    );

    let governance = proxy.key_management.expect("key management").governance;
    assert_eq!(governance.consistency, GovernanceConsistency::Strict);
    assert_eq!(governance.lease_ttl_secs, 180);
    assert_eq!(governance.terminal_retention_secs, 360);
    assert_eq!(governance.failure_mode, GovernanceFailureMode::Closed);
    assert_eq!(
        governance.missing_rate,
        GovernanceMissingRatePolicy::ZeroCost
    );
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
        "failure_mode",
        "failure_posture",
        "missing_rate",
        "key_introspection",
        "require_governed_key",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing {field}");
    }
}

/// WOR-1835: `failure_mode` gates a governance backend outage at reserve
/// time; `missing_rate` gates a governed key's monetary limit when the
/// resolved model has no rate. Both default to the strict setting
/// (`closed` / `zero_cost` respectively already covered by
/// `governance_defaults_to_approximate_fail_closed`); this test pins the
/// non-default parse of each and confirms they are independent knobs.
#[test]
fn failure_mode_and_missing_rate_parse_non_default_values() {
    let governance: KeyGovernanceConfig = serde_yaml::from_str(
        r#"
failure_mode: allow_unreserved
missing_rate: require_rate
"#,
    )
    .expect("typed governance config");
    assert_eq!(
        governance.failure_mode,
        GovernanceFailureMode::AllowUnreserved
    );
    assert_eq!(
        governance.missing_rate,
        GovernanceMissingRatePolicy::RequireRate
    );
    governance
        .validate()
        .expect("non-default enums are still valid");

    // Setting one does not implicitly change the other's default.
    let governance_partial: KeyGovernanceConfig = serde_yaml::from_str(
        r#"
failure_mode: allow_unreserved
"#,
    )
    .expect("typed governance config");
    assert_eq!(
        governance_partial.failure_mode,
        GovernanceFailureMode::AllowUnreserved
    );
    assert_eq!(
        governance_partial.missing_rate,
        GovernanceMissingRatePolicy::ZeroCost
    );
}

/// An unrecognized `failure_mode` / `missing_rate` value must fail to
/// parse rather than silently falling back to the default; the whole
/// point of `deny_unknown_fields` plus a closed enum is that a typo in
/// operator config surfaces at load time, not as quietly-wrong runtime
/// behavior.
#[test]
fn failure_mode_and_missing_rate_reject_unknown_variants() {
    assert!(
        serde_yaml::from_str::<KeyGovernanceConfig>("failure_mode: open\n").is_err(),
        "unknown failure_mode variant must be rejected"
    );
    assert!(
        serde_yaml::from_str::<KeyGovernanceConfig>("missing_rate: ignore\n").is_err(),
        "unknown missing_rate variant must be rejected"
    );
}

// --- WOR-2121: the shared `failure_posture` key ---

/// The new key is `failure_posture`, and it has to be a new word.
///
/// `failure_mode` is taken here by a narrower enum, and the test directly
/// above pins that `failure_mode: open` must fail to parse. Reusing the
/// name would mean either breaking that promise or accepting a key whose
/// accepted values differ per block. One new word that works at every
/// site beats one that collides at two, so both spellings coexist and
/// `failure_mode: open` stays an error while `failure_posture: open`
/// parses.
#[test]
fn failure_posture_parses_where_failure_mode_open_still_cannot() {
    assert!(
        serde_yaml::from_str::<KeyGovernanceConfig>("failure_mode: open\n").is_err(),
        "the legacy field keeps its narrow enum"
    );

    for (wire, expected) in [
        ("closed", FailureMode::Closed),
        ("open", FailureMode::Open),
        ("degraded", FailureMode::Degraded),
    ] {
        let governance: KeyGovernanceConfig =
            serde_yaml::from_str(&format!("failure_posture: {wire}\n"))
                .expect("the new key accepts the full posture vocabulary");
        assert_eq!(governance.failure_posture, Some(expected));
        assert_eq!(governance.failure_posture(), expected);
        governance
            .validate()
            .expect("a meaningful posture validates");
    }
}

/// A config written before `failure_posture` existed resolves to exactly
/// the posture its legacy field always meant, at both sites. This is the
/// whole promise of the migration.
#[test]
fn a_legacy_config_resolves_to_an_identical_posture_at_both_sites() {
    let proxy = parse(
        r#"
key_management:
  enabled: true
  failure_mode_allow: true
  governance:
    failure_mode: allow_unreserved
"#,
    );
    let key_management = proxy.key_management.expect("key management");

    assert_eq!(key_management.failure_posture, None, "absent stays absent");
    assert_eq!(
        key_management.governance.failure_posture, None,
        "absent stays absent"
    );

    // `failure_mode_allow: true` has always meant "fall through to the
    // origin's configured auth with no per-key policy, budget, or
    // attribution". That is a waived guarantee, not a plain open.
    assert_eq!(key_management.failure_posture(), FailureMode::Degraded);
    assert_eq!(
        key_management.governance.failure_posture(),
        FailureMode::Degraded
    );

    let closed = parse(
        r#"
key_management:
  enabled: true
"#,
    )
    .key_management
    .expect("key management");
    assert!(!closed.failure_mode_allow, "the legacy default is deny");
    assert_eq!(closed.failure_posture(), FailureMode::Closed);
    assert_eq!(closed.governance.failure_posture(), FailureMode::Closed);
    closed
        .validate_failure_posture()
        .expect("the legacy default validates");
}

/// With both keys present the explicit one wins, at both sites and in
/// both directions.
#[test]
fn an_explicit_failure_posture_wins_over_the_legacy_field() {
    let proxy = parse(
        r#"
key_management:
  enabled: true
  failure_mode_allow: true
  failure_posture: closed
  governance:
    failure_mode: allow_unreserved
    failure_posture: closed
"#,
    );
    let key_management = proxy.key_management.expect("key management");
    assert!(
        key_management.failure_mode_allow,
        "the legacy field is kept"
    );
    assert_eq!(key_management.failure_posture(), FailureMode::Closed);
    assert_eq!(
        key_management.governance.failure_mode,
        GovernanceFailureMode::AllowUnreserved,
        "the legacy field is kept"
    );
    assert_eq!(
        key_management.governance.failure_posture(),
        FailureMode::Closed
    );

    let proxy = parse(
        r#"
key_management:
  enabled: true
  failure_mode_allow: false
  failure_posture: open
  governance:
    failure_mode: closed
    failure_posture: degraded
"#,
    );
    let key_management = proxy.key_management.expect("key management");
    assert_eq!(key_management.failure_posture(), FailureMode::Open);
    assert_eq!(
        key_management.governance.failure_posture(),
        FailureMode::Degraded
    );
}

/// `degraded` and `open` both admit, and are still not the same answer.
///
/// `degraded` says a guarantee that was advertised was not delivered, and
/// every site keys its audit event and its fail-open counter off exactly
/// this bit. `open` admits and claims nothing.
#[test]
fn degraded_is_distinguishable_from_open() {
    assert!(FailureMode::Degraded.admits());
    assert!(FailureMode::Open.admits());
    assert!(FailureMode::Degraded.guarantee_waived());
    assert!(!FailureMode::Open.guarantee_waived());
    assert_eq!(FailureMode::Degraded.as_label(), "degraded");
    assert_eq!(FailureMode::Open.as_label(), "open");
}

/// `observe` parses (it is a real posture elsewhere) and is then refused
/// at config-compile time, with a message naming the exact key. Accepting
/// it would mean silently choosing some other behaviour: a control that
/// never ran produced no counterfactual verdict to record.
#[test]
fn observe_is_rejected_at_both_key_management_sites() {
    let governance: KeyGovernanceConfig = serde_yaml::from_str("failure_posture: observe\n")
        .expect("observe is a real posture and parses");
    let error = governance
        .validate()
        .expect_err("observe must not validate for governance");
    assert!(
        error
            .to_string()
            .contains("key_management.governance.failure_posture"),
        "the error must name the site: {error}"
    );
    assert!(
        error.to_string().contains("no counterfactual verdict"),
        "the error must say why: {error}"
    );

    let key_management = KeyManagementConfig {
        failure_posture: Some(FailureMode::Observe),
        ..KeyManagementConfig::default()
    };
    let error = key_management
        .validate_failure_posture()
        .expect_err("observe must not validate for the key store");
    assert!(
        error.contains("key_management.failure_posture"),
        "the error must name the site: {error}"
    );

    // The outer check also covers the nested block, so one call at boot
    // catches either spelling of the mistake.
    let nested = KeyManagementConfig {
        governance: KeyGovernanceConfig {
            failure_posture: Some(FailureMode::Observe),
            ..KeyGovernanceConfig::default()
        },
        ..KeyManagementConfig::default()
    };
    let error = nested
        .validate_failure_posture()
        .expect_err("the nested site is checked too");
    assert!(
        error.contains("key_management.governance.failure_posture"),
        "the nested site names itself: {error}"
    );
}

/// The new key stays out of the serialized form when it was never set, so
/// a round trip of a legacy config does not silently acquire it.
#[test]
fn an_unset_failure_posture_is_not_serialized() {
    let governance = KeyGovernanceConfig {
        failure_mode: GovernanceFailureMode::AllowUnreserved,
        ..KeyGovernanceConfig::default()
    };
    let encoded = serde_yaml::to_string(&governance).expect("serialize governance config");
    assert!(
        !encoded.contains("failure_posture"),
        "an absent posture must not be written back: {encoded}"
    );

    let decoded: KeyGovernanceConfig =
        serde_yaml::from_str(&encoded).expect("round-trip governance config");
    assert_eq!(governance, decoded);
    assert_eq!(decoded.failure_posture(), FailureMode::Degraded);
}
