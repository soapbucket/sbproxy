mod support;

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use sbproxy_platform::storage::{
    KVStore, RedisConfig, RedisKVStore, RedisTlsConfig, ValidatedRedisConnection,
};
use support::redis_server::{RedisProtocolAuditProxy, RedisServer, RedisTlsServerConfig};
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

fn pooled_store_for(dsn: &str, tls: RedisTlsConfig, pool_size: usize) -> RedisKVStore {
    let connection = ValidatedRedisConnection::new(dsn, tls)
        .unwrap_or_else(|_| panic!("secure Redis test connection configuration was rejected"));
    let mut config = RedisConfig::new(connection);
    config.pool_size = pool_size;
    config.acquire_timeout = Duration::from_secs(2);
    config.connect_timeout = Duration::from_secs(2);
    config.command_timeout = Duration::from_secs(2);
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

fn raw_put(dsn: &str, key: &str, value: &[u8], database: u8) {
    let client = redis::Client::open(dsn)
        .unwrap_or_else(|_| panic!("failed to build the independent Redis verification client"));
    let mut connection = client
        .get_connection_with_timeout(Duration::from_millis(500))
        .unwrap_or_else(|_| panic!("independent Redis verification client failed to connect"));
    redis::cmd("SELECT")
        .arg(database)
        .query::<()>(&mut connection)
        .unwrap_or_else(|_| panic!("independent Redis verification client failed to select DB"));
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .query::<()>(&mut connection)
        .unwrap_or_else(|_| panic!("independent Redis verification client failed to write"));
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
    let server = RedisServer::spawn_acl_fallback_trap("wor1946-test-user", PASSWORD);
    let anonymous_dsn = format!("redis://127.0.0.1:{}/7", server.port());
    let key = b"must-not-run-anonymously";
    let encoded_key = hex::encode(key);
    raw_put(
        &anonymous_dsn,
        &encoded_key,
        b"anonymous-fallback-would-read-this",
        7,
    );
    assert_eq!(
        raw_get(&anonymous_dsn, &encoded_key, 7),
        Some(b"anonymous-fallback-would-read-this".to_vec())
    );

    let wrong_dsn = format!(
        "redis://wor1946-test-user:definitely-wrong@127.0.0.1:{}/7",
        server.port()
    );
    let store = store_for(&wrong_dsn, RedisTlsConfig::default());

    let error = store.get(key).expect_err("wrong Redis password must fail");

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
fn private_ca_mtls_ttl_value_expires_within_a_bounded_window() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(&tls_dsn(server.port()), pki.client_tls());
    let key = b"wor-1946-live-ttl";

    store
        .put_with_ttl(key, b"expires", 1)
        .unwrap_or_else(|_| panic!("private-CA Redis TTL write failed"));
    assert_eq!(
        store
            .get(key)
            .unwrap_or_else(|_| panic!("private-CA Redis TTL read failed"))
            .as_deref(),
        Some(&b"expires"[..])
    );

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match store
            .get(key)
            .unwrap_or_else(|_| panic!("private-CA Redis TTL polling read failed"))
        {
            None => break,
            Some(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Some(_) => panic!("private-CA Redis TTL did not expire within the bounded window"),
        }
    }
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn private_ca_mtls_increment_is_atomic_across_concurrent_connections() {
    const WORKERS: usize = 4;

    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = Arc::new(pooled_store_for(
        &tls_dsn(server.port()),
        pki.client_tls(),
        WORKERS,
    ));
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut workers = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let worker_store = Arc::clone(&store);
        let worker_barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            worker_barrier.wait();
            worker_store
                .incr_with_ttl(b"wor-1946-live-counter", 30)
                .unwrap_or_else(|_| panic!("private-CA Redis concurrent increment failed"))
        }));
    }

    let mut observed = workers
        .into_iter()
        .map(|worker| {
            worker
                .join()
                .unwrap_or_else(|_| panic!("private-CA Redis increment worker panicked"))
        })
        .collect::<Vec<_>>();
    observed.sort_unstable();
    assert_eq!(observed, (1..=WORKERS as i64).collect::<Vec<_>>());
    assert_eq!(
        store
            .get(b"wor-1946-live-counter")
            .unwrap_or_else(|_| panic!("private-CA Redis counter read failed"))
            .map(|value| value.to_vec()),
        Some(WORKERS.to_string().into_bytes())
    );
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn private_ca_mtls_unlock_is_scoped_to_the_lock_owner() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(&tls_dsn(server.port()), pki.client_tls());
    let key = b"wor-1946-live-lock";

    assert!(store
        .try_lock(key, b"owner-a", 30)
        .unwrap_or_else(|_| panic!("private-CA Redis lock acquisition failed")));
    assert!(!store
        .try_lock(key, b"owner-b", 30)
        .unwrap_or_else(|_| panic!("private-CA Redis lock contention failed")));

    store
        .unlock(key, b"owner-b")
        .unwrap_or_else(|_| panic!("private-CA Redis non-owner unlock failed"));
    assert!(!store
        .try_lock(key, b"owner-c", 30)
        .unwrap_or_else(|_| panic!("private-CA Redis lock fencing check failed")));

    store
        .unlock(key, b"owner-a")
        .unwrap_or_else(|_| panic!("private-CA Redis owner unlock failed"));
    assert!(store
        .try_lock(key, b"owner-b", 30)
        .unwrap_or_else(|_| panic!("private-CA Redis lock handoff failed")));

    store
        .unlock(key, b"owner-a")
        .unwrap_or_else(|_| panic!("private-CA Redis stale-owner unlock failed"));
    assert!(!store
        .try_lock(key, b"owner-c", 30)
        .unwrap_or_else(|_| panic!("private-CA Redis stale-owner fencing check failed")));

    store
        .unlock(key, b"owner-b")
        .unwrap_or_else(|_| panic!("private-CA Redis final owner unlock failed"));
    assert!(store
        .try_lock(key, b"owner-c", 30)
        .unwrap_or_else(|_| panic!("private-CA Redis final lock handoff failed")));
}

#[test]
#[ignore = "requires redis-server executable on PATH with TLS support"]
fn private_ca_mtls_scan_returns_only_the_requested_prefix() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let store = store_for(&tls_dsn(server.port()), pki.client_tls());

    for (key, value) in [
        (&b"wor-1946-live-scan:a"[..], &b"value-a"[..]),
        (&b"wor-1946-live-scan:b"[..], &b"value-b"[..]),
        (&b"wor-1946-live-other"[..], &b"not-returned"[..]),
    ] {
        store
            .put(key, value)
            .unwrap_or_else(|_| panic!("private-CA Redis scan fixture write failed"));
    }

    let mut actual = store
        .scan_prefix(b"wor-1946-live-scan:")
        .unwrap_or_else(|_| panic!("private-CA Redis prefix scan failed"))
        .into_iter()
        .map(|(key, value)| (key.to_vec(), value.to_vec()))
        .collect::<Vec<_>>();
    actual.sort();
    assert_eq!(
        actual,
        vec![
            (b"wor-1946-live-scan:a".to_vec(), b"value-a".to_vec()),
            (b"wor-1946-live-scan:b".to_vec(), b"value-b".to_vec()),
        ]
    );
    assert!(store
        .scan_prefix(b"wor-1946-live-missing:")
        .unwrap_or_else(|_| panic!("private-CA Redis empty prefix scan failed"))
        .is_empty());
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
fn wrong_private_ca_is_rejected_without_plaintext_fallback() {
    let pki = TestPki::generate();
    let server = RedisServer::spawn_tls(pki.server_config());
    let audit_proxy = RedisProtocolAuditProxy::spawn(server.port());
    let store = store_for(
        &tls_dsn(audit_proxy.port()),
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

    let counts = audit_proxy.protocol_counts();
    assert!(
        counts.tls > 0,
        "failed rediss must make an observable TLS attempt"
    );
    assert_eq!(
        counts.plaintext, 0,
        "failed rediss must never retry with RESP plaintext"
    );
    assert_eq!(
        counts.other, 0,
        "failed rediss emitted an unexpected protocol prefix"
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
