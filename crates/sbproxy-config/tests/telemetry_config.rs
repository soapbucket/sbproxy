//! `proxy.observability.telemetry.headers` parses, preserves secret
//! reference values verbatim (resolution happens at boot in the
//! binary), and defaults to empty when absent (WOR-1869).

use sbproxy_config::ProxyServerConfig;

#[test]
fn telemetry_headers_parse_with_reference_values() {
    let proxy: ProxyServerConfig = serde_yaml::from_str(
        r#"
observability:
  telemetry:
    enabled: true
    endpoint: "https://api.honeycomb.io"
    headers:
      x-honeycomb-team: "${HONEYCOMB_KEY}"
      authorization: "vault://kv/otlp#token"
"#,
    )
    .expect("telemetry config parses");
    let telemetry = proxy
        .observability
        .as_ref()
        .and_then(|o| o.telemetry.as_ref())
        .expect("telemetry block");
    assert_eq!(
        telemetry
            .headers
            .get("x-honeycomb-team")
            .map(String::as_str),
        Some("${HONEYCOMB_KEY}"),
        "reference values must parse verbatim; boot resolves them"
    );
    assert_eq!(
        telemetry.headers.get("authorization").map(String::as_str),
        Some("vault://kv/otlp#token")
    );
}

#[test]
fn telemetry_headers_default_empty() {
    let proxy: ProxyServerConfig = serde_yaml::from_str(
        r#"
observability:
  telemetry:
    enabled: true
"#,
    )
    .expect("telemetry config parses");
    let telemetry = proxy
        .observability
        .as_ref()
        .and_then(|o| o.telemetry.as_ref())
        .expect("telemetry block");
    assert!(telemetry.headers.is_empty());
}
