use std::path::Path;

use anyhow::Error;
use sbproxy_config::{build_l2_redis_connection, L2CacheConfig, L2CacheParams, ProxyServerConfig};

const MAX_REDIS_TLS_FILE_BYTES: usize = 1_048_576;

fn certificate_and_key(name: &str) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate().expect("generate test key");
    let params = rcgen::CertificateParams::new(vec![name.to_string()])
        .expect("create test certificate parameters");
    let certificate = params
        .self_signed(&key)
        .expect("self-sign test certificate");
    (
        certificate.pem().into_bytes(),
        key.serialize_pem().into_bytes(),
    )
}

fn write_file(path: &Path, bytes: &[u8]) -> String {
    std::fs::write(path, bytes).expect("write test fixture");
    path.to_string_lossy().into_owned()
}

fn params(dsn: &str) -> L2CacheParams {
    L2CacheParams {
        dsn: dsn.to_string(),
        ..L2CacheParams::default()
    }
}

fn assert_safe_error(error: &Error, expected: &str, forbidden: &[&str]) {
    assert_eq!(error.to_string(), expected);
    let chain = format!("{error:#}");
    for value in forbidden {
        assert!(
            !chain.contains(value),
            "error chain exposed forbidden Redis configuration material: {chain}"
        );
    }
}

#[test]
fn l2_redis_params_debug_exposes_only_configuration_presence() {
    let params = L2CacheParams {
        dsn: "rediss://sentinel-user:sentinel-password@sentinel-host.invalid:6380/7".to_string(),
        ca_file: Some("/sentinel/tls/ca.pem".to_string()),
        cert_file: Some("/sentinel/tls/client.pem".to_string()),
        key_file: Some("/sentinel/tls/client-key.pem".to_string()),
    };

    assert_eq!(
        format!("{params:?}"),
        "L2CacheParams { dsn_configured: true, ca_file_configured: true, cert_file_configured: true, key_file_configured: true }"
    );
}

#[test]
fn l2_redis_enclosing_config_debug_uses_redacted_params() {
    let config = L2CacheConfig {
        driver: "redis".to_string(),
        params: L2CacheParams {
            dsn: "rediss://sentinel-user:sentinel-password@sentinel-host.invalid:6380/7"
                .to_string(),
            ca_file: Some("/sentinel/tls/ca.pem".to_string()),
            cert_file: Some("/sentinel/tls/client.pem".to_string()),
            key_file: Some("/sentinel/tls/client-key.pem".to_string()),
        },
    };

    let debug = format!("{config:?}");
    assert_eq!(
        debug,
        "L2CacheConfig { driver: \"redis\", params: L2CacheParams { dsn_configured: true, ca_file_configured: true, cert_file_configured: true, key_file_configured: true } }"
    );
    for forbidden in [
        "sentinel-user",
        "sentinel-password",
        "sentinel-host",
        "/7",
        "/sentinel/tls",
    ] {
        assert!(
            !debug.contains(forbidden),
            "enclosing config Debug exposed Redis material: {debug}"
        );
    }
}

#[test]
fn l2_redis_deserializes_tls_file_fields() {
    let yaml = r#"
proxy:
  l2_cache_settings:
    driver: redis
    params:
      dsn: rediss://default:p%40ss@[::1]:6380/7
      ca_file: /tmp/redis-ca.pem
      cert_file: /tmp/redis-client.pem
      key_file: /tmp/redis-client-key.pem
"#;

    let config: sbproxy_config::ConfigFile = serde_yaml::from_str(yaml).expect("parse config");
    let l2 = config.proxy.l2_cache.expect("L2 cache settings");
    assert_eq!(l2.params.dsn, "rediss://default:p%40ss@[::1]:6380/7");
    assert_eq!(l2.params.ca_file.as_deref(), Some("/tmp/redis-ca.pem"));
    assert_eq!(
        l2.params.cert_file.as_deref(),
        Some("/tmp/redis-client.pem")
    );
    assert_eq!(
        l2.params.key_file.as_deref(),
        Some("/tmp/redis-client-key.pem")
    );
}

#[test]
fn l2_redis_schema_exposes_tls_file_fields() {
    let schema = schemars::schema_for!(ProxyServerConfig);
    let json = serde_json::to_string(&schema).expect("serialize schema");

    for field in ["ca_file", "cert_file", "key_file"] {
        assert!(json.contains(&format!("\"{field}\"")), "missing {field}");
    }
}

#[test]
fn l2_redis_compiles_private_ca_and_mtls_without_network_io() {
    let directory = tempfile::tempdir().expect("create test directory");
    let (certificate, key) = certificate_and_key("redis-client.example");
    let mut config = params("rediss://default:p%40ss@[::1]:6380/7");
    config.ca_file = Some(write_file(&directory.path().join("ca.pem"), &certificate));
    config.cert_file = Some(write_file(
        &directory.path().join("client.pem"),
        &certificate,
    ));
    config.key_file = Some(write_file(&directory.path().join("client-key.pem"), &key));

    let connection = build_l2_redis_connection(&config)
        .expect("valid private CA and client identity must compile");

    assert!(connection.uses_tls());
}

#[test]
fn l2_redis_rejects_tls_files_for_plaintext_connections_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let (certificate, _) = certificate_and_key("sentinel-plaintext-certificate.example");
    let path = directory.path().join("sentinel-plaintext-ca.pem");
    let dsn = "redis://default:sentinel-plaintext-password@sentinel-plaintext-host.invalid:6379/7";
    let mut config = params(dsn);
    config.ca_file = Some(write_file(&path, &certificate));

    let error = build_l2_redis_connection(&config).expect_err("plaintext TLS files must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-plaintext", "/7"],
    );
}

#[test]
fn l2_redis_rejects_certificate_without_key_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let (certificate, _) = certificate_and_key("sentinel-cert-only.example");
    let path = directory.path().join("sentinel-cert-only.pem");
    let dsn = "rediss://default:sentinel-cert-only-password@sentinel-cert-only-host.invalid:6380/7";
    let mut config = params(dsn);
    config.cert_file = Some(write_file(&path, &certificate));

    let error = build_l2_redis_connection(&config).expect_err("one-sided identity must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-cert-only", "/7"],
    );
}

#[test]
fn l2_redis_rejects_key_without_certificate_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let (_, key) = certificate_and_key("sentinel-key-only.example");
    let path = directory.path().join("sentinel-key-only.pem");
    let dsn = "rediss://default:sentinel-key-only-password@sentinel-key-only-host.invalid:6380/7";
    let mut config = params(dsn);
    config.key_file = Some(write_file(&path, &key));

    let error = build_l2_redis_connection(&config).expect_err("one-sided identity must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-key-only", "/7"],
    );
}

#[test]
fn l2_redis_rejects_missing_file_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let path = directory.path().join("sentinel-missing-ca.pem");
    let dsn = "rediss://default:sentinel-missing-password@sentinel-missing-host.invalid:6380/7";
    let mut config = params(dsn);
    config.ca_file = Some(path.to_string_lossy().into_owned());

    let error = build_l2_redis_connection(&config).expect_err("missing TLS file must fail");

    assert_safe_error(
        &error,
        "invalid Redis ca_file configuration",
        &[dsn, "sentinel-missing", "/7"],
    );
}

#[test]
fn l2_redis_rejects_empty_file_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let path = directory.path().join("sentinel-empty-ca.pem");
    let dsn = "rediss://default:sentinel-empty-password@sentinel-empty-host.invalid:6380/7";
    let mut config = params(dsn);
    config.ca_file = Some(write_file(&path, b""));

    let error = build_l2_redis_connection(&config).expect_err("empty TLS file must fail");

    assert_safe_error(
        &error,
        "invalid Redis ca_file configuration",
        &[dsn, "sentinel-empty", "/7"],
    );
}

#[test]
fn l2_redis_rejects_oversized_file_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let path = directory.path().join("sentinel-oversized-ca.pem");
    let dsn = "rediss://default:sentinel-oversized-password@sentinel-oversized-host.invalid:6380/7";
    let mut config = params(dsn);
    let oversized = vec![b'x'; MAX_REDIS_TLS_FILE_BYTES + 1];
    config.ca_file = Some(write_file(&path, &oversized));

    let error = build_l2_redis_connection(&config).expect_err("oversized TLS file must fail");

    assert_safe_error(
        &error,
        "invalid Redis ca_file configuration",
        &[dsn, "sentinel-oversized", "/7"],
    );
}

#[test]
fn l2_redis_rejects_malformed_file_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let path = directory.path().join("sentinel-malformed-ca.pem");
    let dsn = "rediss://default:sentinel-malformed-password@sentinel-malformed-host.invalid:6380/7";
    let mut config = params(dsn);
    config.ca_file = Some(write_file(
        &path,
        b"-----BEGIN CERTIFICATE-----\nsentinel-malformed-content\n",
    ));

    let error = build_l2_redis_connection(&config).expect_err("malformed TLS file must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-malformed", "/7"],
    );
}

#[test]
fn l2_redis_rejects_mismatched_identity_without_disclosure() {
    let directory = tempfile::tempdir().expect("create test directory");
    let (certificate, _) = certificate_and_key("sentinel-mismatched-client.example");
    let (_, other_key) = certificate_and_key("sentinel-mismatched-other.example");
    let cert_path = directory.path().join("sentinel-mismatched-cert.pem");
    let key_path = directory.path().join("sentinel-mismatched-key.pem");
    let dsn =
        "rediss://default:sentinel-mismatched-password@sentinel-mismatched-host.invalid:6380/7";
    let mut config = params(dsn);
    config.cert_file = Some(write_file(&cert_path, &certificate));
    config.key_file = Some(write_file(&key_path, &other_key));

    let error = build_l2_redis_connection(&config).expect_err("mismatched identity must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-mismatched", "/7"],
    );
}

#[test]
fn l2_redis_rejects_query_without_disclosure() {
    let dsn = "redis://default:sentinel-query-password@sentinel-query-host.invalid:6379/7?sentinel-query=true";
    let error = build_l2_redis_connection(&params(dsn)).expect_err("query must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-query", "/7"],
    );
}

#[test]
fn l2_redis_rejects_fragment_without_disclosure() {
    let dsn = "rediss://default:sentinel-fragment-password@sentinel-fragment-host.invalid:6380/7#sentinel-fragment";
    let error = build_l2_redis_connection(&params(dsn)).expect_err("fragment must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-fragment", "/7"],
    );
}

#[test]
fn l2_redis_rejects_negative_database_without_disclosure() {
    let dsn = "redis://default:sentinel-negative-password@sentinel-negative-host.invalid:6379/-1";
    let error = build_l2_redis_connection(&params(dsn)).expect_err("negative database must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-negative", "/-1"],
    );
}

#[test]
fn l2_redis_rejects_username_without_password_without_disclosure() {
    let dsn = "redis://sentinel-username@sentinel-username-host.invalid:6379/7";
    let error =
        build_l2_redis_connection(&params(dsn)).expect_err("username without password must fail");

    assert_safe_error(
        &error,
        "invalid Redis connection configuration",
        &[dsn, "sentinel-username", "/7"],
    );
}
