//! WOR-1140: schema-wide `deny_unknown_fields` contract.
//!
//! The compile gate from PR #495 (`serde_ignored`) already rejects a
//! misspelled key in a plain nested block. These tests pin the cases
//! that gate could NOT see, which is what the struct-level
//! `#[serde(deny_unknown_fields)]` layer adds:
//!
//! - keys inside internally tagged enums (`credentials[].policies[]`),
//!   whose buffered content `serde_ignored` never visits;
//! - keys inside `serde_json::Value` blocks that a later compile step
//!   parses into a typed struct (`origins.<host>.response_cache`);
//! - the quality of the error itself (serde names the field and lists
//!   the accepted ones);
//! - and the schema-v1 escape hatch: unknown TOP-level keys still only
//!   warn, so archived flat v0.1.x configs keep compiling.

use sbproxy_config::compile_config;

/// A misspelled key inside a credential policy entry must fail the
/// compile. `credentials[].policies[]` is an internally tagged enum, so
/// serde buffers its content and the `serde_ignored` gate never sees
/// inside it; before WOR-1140 closed this hole, the published
/// ai-virtual-keys example shipped a `tpm:` cap here that the runtime
/// silently dropped.
#[test]
fn unknown_key_inside_a_credential_policy_fails_compile() {
    let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "ai.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    credentials:
      - name: team-a
        type: ai_provider
        provider: anthropic
        key: literal-test-key
        policies:
          - type: rate_limit
            rpm: 30
            tpm: 60000
"#;
    let err = compile_config(yaml)
        .err()
        .expect("a dead key inside a credential policy must fail compile");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("tpm"),
        "error must name the offending key: {msg}"
    );
}

/// A misspelled key inside `response_cache:` must fail the compile.
/// The block is an opaque `serde_json::Value` on `RawOriginConfig` and
/// only becomes typed inside `compile_origin`; that deferred parse used
/// to downgrade failures to a warning plus a silently disabled cache.
#[test]
fn unknown_key_inside_response_cache_fails_compile() {
    let yaml = r#"
proxy:
  http_bind_port: 8080
origins:
  "cached.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
    response_cache:
      enabled: true
      ttl_secds: 60
"#;
    let err = compile_config(yaml)
        .err()
        .expect("a typo inside response_cache must fail compile");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("response_cache") && msg.contains("ttl_secds"),
        "error must name the block and the offending key: {msg}"
    );
}

/// The rejection an operator sees stays actionable: serde's
/// unknown-field error names the bad key and lists the accepted ones,
/// so a `trusted_proxys` typo points straight at `trusted_proxies`.
#[test]
fn rejection_names_the_field_and_lists_alternatives() {
    let err = serde_yaml::from_str::<sbproxy_config::ProxyServerConfig>(
        "trusted_proxys: [\"10.0.0.1\"]\n",
    )
    .expect_err("a misspelled security key must not parse");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("trusted_proxys"),
        "error must identify the unknown field: {msg}"
    );
    assert!(
        msg.contains("trusted_proxies"),
        "error must list the accepted fields so the fix is visible: {msg}"
    );
}

/// A misspelled key in a security-relevant nested block fails through
/// `compile_config` itself, which is the path boot and reload take.
#[test]
fn unknown_key_in_a_security_block_fails_compile() {
    let yaml = r#"
proxy:
  http_bind_port: 8080
  key_management:
    inbound:
      native_polices: {}
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
"#;
    let err = compile_config(yaml)
        .err()
        .expect("a typo in a key-management block must fail compile");
    assert!(format!("{err:#}").contains("native_polices"));
}

/// The schema-v1 promise survives the deny layer: a flat v0.1.x-style
/// file, including a key no schema version ever had, still compiles
/// because the root `ConfigFile` stays permissive and top-level
/// unknowns only warn.
#[test]
fn v1_flat_file_with_unknown_top_level_keys_still_compiles() {
    let yaml = r#"
config_version: 2
id: "legacy-1"
hostname: "api.example.com"
workspace_id: "ws-legacy"
version: "1.0"
some_key_no_schema_ever_had: true
action:
  type: proxy
  url: https://test.sbproxy.dev
"#;
    compile_config(yaml).expect("v1 flat files must keep compiling under deny_unknown_fields");
}

/// The deliberate pass-through blocks stay open: `extensions` maps and
/// the module-layer `action` / `policies` values accept arbitrary keys
/// under the deny layer exactly as before.
#[test]
fn extension_and_module_blocks_still_accept_arbitrary_keys() {
    let yaml = r#"
proxy:
  http_bind_port: 8080
  extensions:
    out_of_tree_block:
      anything: 1
origins:
  "api.example.com":
    action:
      type: proxy
      url: https://test.sbproxy.dev
      module_specific_knob: true
    extensions:
      per_origin_block:
        also: fine
"#;
    compile_config(yaml).expect("extension maps and module Values must stay permissive");
}
