mod support;

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use sbproxy_platform::storage::{
    KVStore, RedisConfig, RedisKVStore, RedisTlsConfig, ValidatedRedisConnection,
};
use support::redis_server::{RedisServer, RedisTlsServerConfig};
use tempfile::TempDir;

const PASSWORD: &str = "p@ss:/?#[]";
const ENCODED_PASSWORD: &str = "p%40ss%3A%2F%3F%23%5B%5D";

fn authenticated_dsn(port: u16, password: &str, database: u8) -> String {
    format!("redis://default:{password}@127.0.0.1:{port}/{database}")
}

fn store_for(dsn: &str, tls: RedisTlsConfig) -> RedisKVStore {
    let connection = ValidatedRedisConnection::new(dsn, tls)
        .unwrap_or_else(|_| panic!("secure Redis test connection configuration was rejected"));
    let mut config = RedisConfig::new(connection);
    config.pool_size = 1;
    config.acquire_timeout = Duration::from_millis(500);
    config.connect_timeout = Duration::from_millis(500);
    config.command_timeout = Duration::from_millis(500);
    RedisKVStore::new(config)
}

struct TestPki {
    _directory: TempDir,
    server_cert_file: PathBuf,
    server_key_file: PathBuf,
    ca_cert_file: PathBuf,
    ca_pem: Vec<u8>,
    wrong_ca_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

impl TestPki {
    fn generate() -> Self {
        let directory = tempfile::tempdir()
            .unwrap_or_else(|_| panic!("failed to create the temporary Redis PKI directory"));
        let (ca, ca_key) = generate_ca("WOR-1946 Redis test CA");
        let (wrong_ca, _wrong_ca_key) = generate_ca("WOR-1946 wrong Redis test CA");

        let server_key = KeyPair::generate()
            .unwrap_or_else(|_| panic!("failed to generate the Redis server test key"));
        let mut server_params = CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|_| panic!("failed to configure the Redis server test certificate"));
        server_params.distinguished_name = DistinguishedName::new();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "WOR-1946 Redis test server");
        server_params.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .unwrap_or_else(|_| panic!("failed to sign the Redis server test certificate"));

        let client_key = KeyPair::generate()
            .unwrap_or_else(|_| panic!("failed to generate the Redis client test key"));
        let mut client_params = CertificateParams::new(Vec::<String>::new())
            .unwrap_or_else(|_| panic!("failed to configure the Redis client test certificate"));
        client_params.distinguished_name = DistinguishedName::new();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "WOR-1946 Redis test client");
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params
            .signed_by(&client_key, &ca, &ca_key)
            .unwrap_or_else(|_| panic!("failed to sign the Redis client test certificate"));

        let server_cert_file = directory.path().join("redis-server.pem");
        let server_key_file = directory.path().join("redis-server-key.pem");
        let ca_cert_file = directory.path().join("redis-ca.pem");
        write_private_fixture(&server_cert_file, server_cert.pem().as_bytes());
        write_private_fixture(&server_key_file, server_key.serialize_pem().as_bytes());
        write_private_fixture(&ca_cert_file, ca.pem().as_bytes());

        Self {
            _directory: directory,
            server_cert_file,
            server_key_file,
            ca_cert_file,
            ca_pem: ca.pem().into_bytes(),
            wrong_ca_pem: wrong_ca.pem().into_bytes(),
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
        }
    }

    fn server_config(&self) -> RedisTlsServerConfig {
        RedisTlsServerConfig {
            server_cert_file: self.server_cert_file.clone(),
            server_key_file: self.server_key_file.clone(),
            ca_cert_file: self.ca_cert_file.clone(),
            readiness_root_cert: self.ca_pem.clone(),
            readiness_client_cert: self.client_cert_pem.clone(),
            readiness_client_key: self.client_key_pem.clone(),
        }
    }

    fn client_tls(&self) -> RedisTlsConfig {
        RedisTlsConfig {
            root_cert: Some(self.ca_pem.clone()),
            client_cert: Some(self.client_cert_pem.clone()),
            client_key: Some(self.client_key_pem.clone()),
        }
    }
}

fn generate_ca(common_name: &str) -> (Certificate, KeyPair) {
    let key =
        KeyPair::generate().unwrap_or_else(|_| panic!("failed to generate a Redis test CA key"));
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .unwrap_or_else(|_| panic!("failed to configure a Redis test CA"));
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let certificate = params
        .self_signed(&key)
        .unwrap_or_else(|_| panic!("failed to create a Redis test CA"));
    (certificate, key)
}

fn write_private_fixture(path: &std::path::Path, contents: &[u8]) {
    fs::write(path, contents)
        .unwrap_or_else(|_| panic!("failed to write an ephemeral Redis TLS fixture"));
}

fn tls_dsn(port: u16) -> String {
    format!("rediss://127.0.0.1:{port}/0")
}

fn assert_safe_failure(error: anyhow::Error, expected: &str) {
    assert_eq!(error.to_string(), expected);
    assert_eq!(error.chain().count(), 1);
    for forbidden in [PASSWORD, ENCODED_PASSWORD, "PRIVATE KEY", "CERTIFICATE"] {
        assert!(!error.to_string().contains(forbidden));
    }
}

fn raw_get(dsn: &str, key: &str, database: u8) -> Option<Vec<u8>> {
    let client = redis::Client::open(dsn)
        .unwrap_or_else(|_| panic!("failed to build the independent Redis verification client"));
    let mut connection = client
        .get_connection_with_timeout(Duration::from_millis(500))
        .unwrap_or_else(|_| panic!("independent Redis verification client failed to connect"));
    redis::cmd("SELECT")
        .arg(database)
        .query::<()>(&mut connection)
        .unwrap_or_else(|_| panic!("independent Redis verification client failed to select DB"));
    redis::cmd("GET")
        .arg(key)
        .query(&mut connection)
        .unwrap_or_else(|_| panic!("independent Redis verification client failed to read"))
}

#[test]
#[ignore = "requires redis-server executable on PATH"]
fn auth_and_db7_preserve_percent_encoded_credentials_and_isolate_data() {
    let server = RedisServer::spawn_authenticated(PASSWORD);
    let dsn = authenticated_dsn(server.port(), ENCODED_PASSWORD, 7);
    let store = store_for(&dsn, RedisTlsConfig::default());
    let key = b"wor-1946-db7-isolation";
    let value = b"stored-only-in-db7";

    store
        .put(key, value)
        .unwrap_or_else(|_| panic!("authenticated DB 7 write failed"));

    let encoded_key = hex::encode(key);
    assert_eq!(raw_get(&dsn, &encoded_key, 7), Some(value.to_vec()));
    assert_eq!(raw_get(&dsn, &encoded_key, 0), None);
}

#[test]
#[ignore = "requires redis-server executable on PATH"]
fn wrong_password_is_safe_auth_failure_without_anonymous_retry() {
    let server = RedisServer::spawn_authenticated(PASSWORD);
    let wrong_dsn = authenticated_dsn(server.port(), "definitely-wrong", 7);
    let store = store_for(&wrong_dsn, RedisTlsConfig::default());

    let error = store
        .get(b"must-not-run-anonymously")
        .expect_err("wrong Redis password must fail");

    assert_eq!(error.to_string(), "redis get failed: auth");
    assert_eq!(error.chain().count(), 1);
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn private_ca_and_required_client_identity_succeed() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(&tls_dsn(server.port()), pki.client_tls());

    store
        .put(b"mtls-key", b"mtls-value")
        .unwrap_or_else(|_| panic!("private-CA Redis mTLS write failed"));
    assert_eq!(
        store
            .get(b"mtls-key")
            .unwrap_or_else(|_| panic!("private-CA Redis mTLS read failed"))
            .as_deref(),
        Some(&b"mtls-value"[..])
    );
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn missing_client_identity_is_rejected_by_mtls_server() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(
        &tls_dsn(server.port()),
        RedisTlsConfig {
            root_cert: Some(pki.ca_pem.clone()),
            ..RedisTlsConfig::default()
        },
    );

    assert_safe_failure(
        store
            .get(b"missing-client-identity")
            .expect_err("Redis mTLS must require a client identity"),
        "redis get failed: tls",
    );
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn wrong_private_ca_is_rejected() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(
        &tls_dsn(server.port()),
        RedisTlsConfig {
            root_cert: Some(pki.wrong_ca_pem.clone()),
            client_cert: Some(pki.client_cert_pem.clone()),
            client_key: Some(pki.client_key_pem.clone()),
        },
    );

    assert_safe_failure(
        store
            .get(b"wrong-private-ca")
            .expect_err("an untrusted Redis server certificate must fail"),
        "redis get failed: tls",
    );
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn omitted_private_ca_is_rejected() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(
        &tls_dsn(server.port()),
        RedisTlsConfig {
            client_cert: Some(pki.client_cert_pem.clone()),
            client_key: Some(pki.client_key_pem.clone()),
            ..RedisTlsConfig::default()
        },
    );

    assert_safe_failure(
        store
            .get(b"omitted-private-ca")
            .expect_err("the private Redis CA must not be optional"),
        "redis get failed: tls",
    );
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn plaintext_never_succeeds_on_tls_only_port() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let plaintext = store_for(
        &format!("redis://127.0.0.1:{}/0", server.port()),
        RedisTlsConfig::default(),
    );

    for _ in 0..2 {
        assert_safe_failure(
            plaintext
                .get(b"plaintext-must-fail")
                .expect_err("a TLS-only Redis port must reject plaintext"),
            "redis get failed: transport",
        );
    }

    let tls = store_for(&tls_dsn(server.port()), pki.client_tls());
    tls.put(b"still-tls-only", b"ok")
        .unwrap_or_else(|_| panic!("valid mTLS stopped working after plaintext probes"));
}

#[test]
#[ignore = "requires redis-server executable on PATH"]
fn pooled_connection_recovers_after_redis_kill_and_restart() {
    let mut server = RedisServer::spawn_authenticated(PASSWORD);
    let dsn = authenticated_dsn(server.port(), ENCODED_PASSWORD, 0);
    let store = store_for(&dsn, RedisTlsConfig::default());
    store
        .put(b"before-restart", b"present")
        .unwrap_or_else(|_| panic!("initial Redis write failed"));

    server.stop();
    server.restart();

    assert_safe_failure(
        store
            .get(b"before-restart")
            .expect_err("the pooled connection must observe Redis process replacement"),
        "redis get failed: transport",
    );
    store
        .put(b"after-restart", b"reconnected")
        .unwrap_or_else(|_| panic!("Redis store did not reconnect after invalidation"));
    assert_eq!(
        store
            .get(b"after-restart")
            .unwrap_or_else(|_| panic!("Redis store could not use the replacement connection"))
            .as_deref(),
        Some(&b"reconnected"[..])
    );
}
