//! ACME integration tests against Pebble (Let's Encrypt's test CA).
//!
//! These tests require a running Pebble instance:
//!   cd e2e/pebble && ./run-pebble.sh up
//!
//! Run with:
//!   cargo test -p sbproxy-tls --test acme_integration -- --ignored
//!
//! Tests are #[ignore] by default so they don't run in CI without Pebble.

use std::sync::Arc;

use ring::signature::KeyPair;
use sbproxy_platform::MemoryKVStore;
use sbproxy_tls::acme::AcmeClient;
use sbproxy_tls::cert_resolver::CertResolver;
use sbproxy_tls::cert_store::{CertMeta, CertStore};
use sbproxy_tls::challenges::Http01ChallengeStore;

/// Pebble's ACME directory URL (matches docker-compose config).
const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";
/// Build a reqwest client that trusts Pebble's self-signed CA.
fn pebble_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Pebble uses test certs
        .build()
        .unwrap()
}

/// Check if Pebble is reachable.
async fn pebble_available() -> bool {
    let client = pebble_http_client();
    client
        .get(PEBBLE_DIRECTORY)
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

// --- Tests ---

#[tokio::test]
#[ignore = "requires Pebble: cd e2e/pebble && ./run-pebble.sh up"]
async fn test_fetch_pebble_directory() {
    if !pebble_available().await {
        eprintln!("SKIP: Pebble not running at {}", PEBBLE_DIRECTORY);
        return;
    }

    let mut client = AcmeClient::new(PEBBLE_DIRECTORY, "test@example.com", vec![]);

    // Fetch directory should succeed and populate endpoints.
    let dir = client.fetch_directory().await.unwrap();
    assert!(
        dir.new_account.contains("localhost:14000"),
        "new_account URL should point to Pebble: {}",
        dir.new_account
    );
    assert!(
        dir.new_order.contains("localhost:14000"),
        "new_order URL should point to Pebble: {}",
        dir.new_order
    );
    assert!(!dir.new_nonce.is_empty(), "new_nonce URL should be set");
}

#[tokio::test]
#[ignore = "requires Pebble: cd e2e/pebble && ./run-pebble.sh up"]
async fn test_fetch_nonce() {
    if !pebble_available().await {
        eprintln!("SKIP: Pebble not running at {}", PEBBLE_DIRECTORY);
        return;
    }

    let mut client = AcmeClient::new(PEBBLE_DIRECTORY, "test@example.com", vec![]);
    client.fetch_directory().await.unwrap();

    let nonce = client.new_nonce().await.unwrap();
    assert!(!nonce.is_empty(), "nonce should not be empty");

    // Each nonce should be unique.
    let nonce2 = client.new_nonce().await.unwrap();
    assert_ne!(nonce, nonce2, "nonces should be unique");
}

#[tokio::test]
#[ignore = "requires Pebble: cd e2e/pebble && ./run-pebble.sh up"]
async fn test_account_key_persists_across_clients() {
    let store = CertStore::new(std::sync::Arc::new(MemoryKVStore::new(0)));

    // Generate key with first client.
    let key1 = AcmeClient::load_or_create_account_key(&store).unwrap();
    let pub1 = key1.public_key().as_ref().to_vec();

    // Second load should return the same key.
    let key2 = AcmeClient::load_or_create_account_key(&store).unwrap();
    let pub2 = key2.public_key().as_ref().to_vec();

    assert_eq!(
        pub1, pub2,
        "account key should persist and reload identically"
    );
}

#[tokio::test]
#[ignore = "requires Pebble: cd e2e/pebble && ./run-pebble.sh up"]
async fn test_cert_store_roundtrip_with_resolver() {
    let store = CertStore::new(std::sync::Arc::new(MemoryKVStore::new(0)));
    let resolver = Arc::new(CertResolver::new());

    // Generate a self-signed cert to simulate an ACME-issued cert.
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key.serialize_pem().into_bytes();

    // Store it the way production does: under the fenced issuance lease
    // (WOR-2633); there is no unfenced publication path outside the crate.
    let meta = CertMeta {
        issued_at: "2026-04-15T00:00:00Z".to_string(),
        expires_at: "2026-07-14T00:00:00Z".to_string(),
        serial: "test-serial".to_string(),
    };
    let lease = store
        .acquire_issue_lease("test.example.com", 60)
        .unwrap()
        .expect("lease acquired");
    assert!(matches!(
        store
            .put_cert_bundle_fenced(&lease, &cert_pem, &key_pem, &meta)
            .unwrap(),
        sbproxy_tls::cert_store::PublishOutcome::Published { .. }
    ));
    store
        .release_issue_lock("test.example.com", lease.token())
        .unwrap();

    // Load it back through the validated bundle (the production reader
    // path) and register in the resolver.
    let bundle = store
        .get_cert_bundle("test.example.com")
        .unwrap()
        .expect("the published bundle validates")
        .expect("cert should exist");
    resolver
        .set_cert("test.example.com", &bundle.cert_pem, &bundle.key_pem)
        .unwrap();

    // Resolver should now serve the cert for this hostname.
    assert!(
        resolver.resolve("test.example.com").is_some(),
        "resolver should have cert for test.example.com"
    );
    assert!(
        resolver.resolve("other.example.com").is_none(),
        "resolver should not have cert for other hostname"
    );

    // Metadata should also be retrievable.
    let loaded_meta = store.get_meta("test.example.com").unwrap().unwrap();
    assert_eq!(loaded_meta.serial, "test-serial");
}

#[tokio::test]
#[ignore = "requires Pebble: cd e2e/pebble && ./run-pebble.sh up"]
async fn test_challenge_store_with_pebble_flow() {
    if !pebble_available().await {
        eprintln!("SKIP: Pebble not running at {}", PEBBLE_DIRECTORY);
        return;
    }

    let challenge_store = Http01ChallengeStore::new();

    // Simulate what the ACME flow does: register a pending challenge.
    let store = CertStore::new(std::sync::Arc::new(MemoryKVStore::new(0)));
    let key_pair = AcmeClient::load_or_create_account_key(&store).unwrap();
    let token = "test-challenge-token-12345";
    let key_auth = AcmeClient::key_authorization(token, &key_pair);

    // Store the challenge response. Pebble's authorization is not fetched
    // here, so there is no server `expires` to honor and the store falls back
    // to its own default TTL.
    challenge_store.set(token, &key_auth, None).unwrap();

    // Verify we can look it up (this is what the request filter would do).
    let response = challenge_store.get(token).unwrap();
    assert_eq!(response, key_auth);
    assert!(response.starts_with("test-challenge-token-12345."));

    // Clean up.
    challenge_store.remove(token);
    assert!(challenge_store.get(token).is_none());
}

#[tokio::test]
#[ignore = "requires Pebble: cd e2e/pebble && ./run-pebble.sh up"]
async fn test_account_registration() {
    if !pebble_available().await {
        eprintln!("SKIP: Pebble not running at {}", PEBBLE_DIRECTORY);
        return;
    }

    let store = CertStore::new(std::sync::Arc::new(MemoryKVStore::new(0)));
    let key_pair = AcmeClient::load_or_create_account_key(&store).unwrap();

    let mut client = AcmeClient::new(PEBBLE_DIRECTORY, "test@example.com", vec!["http-01".into()]);
    client.fetch_directory().await.unwrap();

    let kid = client.register_account(&key_pair).await.unwrap();
    assert!(!kid.is_empty(), "account URL (kid) should not be empty");
    assert!(
        kid.contains("localhost:14000"),
        "kid should point to Pebble: {kid}"
    );

    // Re-registration with same key should succeed and return same or compatible URL.
    let kid2 = client.register_account(&key_pair).await.unwrap();
    assert!(
        !kid2.is_empty(),
        "re-registration should return an account URL"
    );
}

#[tokio::test]
#[ignore = "requires Pebble with PEBBLE_VA_ALWAYS_VALID=1"]
async fn test_full_cert_issuance() {
    // This test requires:
    //   1. Pebble running: cd e2e/pebble && ./run-pebble.sh up
    //   2. PEBBLE_VA_ALWAYS_VALID=1 to skip HTTP-01 validation (no real HTTP server needed)
    //
    // The challenge_store is populated but Pebble won't actually verify it
    // because PEBBLE_VA_ALWAYS_VALID skips the validation step.

    if !pebble_available().await {
        eprintln!("SKIP: Pebble not running at {}", PEBBLE_DIRECTORY);
        return;
    }

    let store = CertStore::new(std::sync::Arc::new(MemoryKVStore::new(0)));
    let key_pair = AcmeClient::load_or_create_account_key(&store).unwrap();
    let challenge_store = Http01ChallengeStore::new();

    let mut client = AcmeClient::new(PEBBLE_DIRECTORY, "test@example.com", vec!["http-01".into()]);
    client.fetch_directory().await.unwrap();

    let hostname = "test.example.com";
    let result = client
        .issue_cert(&key_pair, hostname, &challenge_store)
        .await;

    match result {
        Ok((cert_pem, key_pem)) => {
            // cert_pem should be a valid PEM chain.
            assert!(!cert_pem.is_empty(), "cert PEM should not be empty");
            let cert_str = std::str::from_utf8(&cert_pem).expect("cert PEM should be UTF-8");
            assert!(
                cert_str.contains("BEGIN CERTIFICATE"),
                "cert PEM missing header"
            );

            // key_pem should be a valid private key.
            assert!(!key_pem.is_empty(), "key PEM should not be empty");
            let key_str = std::str::from_utf8(&key_pem).expect("key PEM should be UTF-8");
            assert!(key_str.contains("PRIVATE KEY"), "key PEM missing header");

            // Challenge should have been cleaned up.
            // (We don't know the token, but the store should be empty after success.)

            // Verify cert loads into rustls.
            let resolver = Arc::new(CertResolver::new());
            resolver
                .set_cert(hostname, &cert_pem, &key_pem)
                .expect("issued cert should load into resolver");
            assert!(
                resolver.resolve(hostname).is_some(),
                "resolver should serve the issued cert"
            );

            eprintln!("Full ACME issuance test PASSED for {hostname}");
        }
        Err(e) => {
            panic!("ACME issuance failed: {e:#}");
        }
    }
}

// --- Fleet safety regressions (WOR-2633, WOR-2634, WOR-2635) --------------
//
// None of the cases below need Pebble, so none of them are `#[ignore]`d:
// they are the regressions the gate has to run on every change. Each one
// builds its own store, its own generation namespace, and its own resolver.

mod fleet {
    use super::*;
    use sbproxy_platform::storage::FileKVStore;
    use sbproxy_platform::KVStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    /// A `KVStore` that fails the Nth and every later write.
    ///
    /// This is the failure injector for WOR-2635: it stands in for a crash,
    /// a killed pod, or a backend that rejects a write part-way through a
    /// multi-key publication. `allow` is the number of writes that land
    /// before the store starts refusing, so a test can put the cut at
    /// exactly the seam it cares about.
    struct FailAfterWrites {
        inner: Arc<dyn KVStore>,
        allow: AtomicUsize,
    }

    impl FailAfterWrites {
        fn new(inner: Arc<dyn KVStore>, allow: usize) -> Self {
            Self {
                inner,
                allow: AtomicUsize::new(allow),
            }
        }
    }

    impl KVStore for FailAfterWrites {
        fn get(&self, key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
            if self.allow.load(Ordering::SeqCst) == 0 {
                anyhow::bail!("injected write failure");
            }
            self.allow.fetch_sub(1, Ordering::SeqCst);
            self.inner.put(key, value)
        }
        fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
            self.inner.delete(key)
        }
        fn scan_prefix(&self, prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            self.inner.scan_prefix(prefix)
        }
    }

    fn pair(host: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn meta(serial: &str) -> CertMeta {
        CertMeta {
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            serial: serial.to_string(),
        }
    }

    /// Publish the way production does: acquire the fenced lease, publish
    /// under it, release. There is no unfenced publication path outside the
    /// crate, on purpose.
    fn publish(cs: &CertStore, host: &str, cert_pem: &[u8], key_pem: &[u8], m: &CertMeta) {
        let lease = cs
            .acquire_issue_lease(host, 60)
            .unwrap()
            .expect("issuance lease acquired");
        match cs
            .put_cert_bundle_fenced(&lease, cert_pem, key_pem, m)
            .unwrap()
        {
            sbproxy_tls::cert_store::PublishOutcome::Published { .. } => {}
            other => panic!("expected a publication, got {other:?}"),
        }
        cs.release_issue_lock(host, lease.token()).unwrap();
    }

    /// WOR-2635: a publication interrupted at any write must leave a reader
    /// with a complete generation, never a new certificate paired with the
    /// old key or metadata describing material the store cannot produce.
    ///
    /// The pre-fix layout wrote certificate, key, and metadata as three
    /// puts, so failing the store after one write left exactly the mixed
    /// state this asserts against. The fixed layout is one write, so the
    /// injection sweep below degenerates to "all or nothing": every allowed
    /// write count must yield whole-old or whole-new, and the failure has
    /// to surface to the caller whenever the new generation did not land.
    #[test]
    fn interrupted_publication_never_exposes_a_mixed_generation() {
        for allow in 0..=1usize {
            let backing: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
            let host = "torn.example.com";
            let unfailing = CertStore::new(Arc::clone(&backing));

            // Generation 1: a complete, matching bundle.
            let (cert1, key1) = pair(host);
            publish(&unfailing, host, &cert1, &key1, &meta("gen-1"));

            // Generation 2 goes through a store that fails every write past
            // `allow`. Under the pre-WOR-2635 three-write layout, allow=1
            // cut between the certificate and its private key. The lease is
            // acquired against the unfailing handle so the injection budget
            // is spent entirely on the publication itself.
            let (cert2, key2) = pair(host);
            let lease = unfailing
                .acquire_issue_lease(host, 60)
                .unwrap()
                .expect("lease acquired");
            let injected =
                CertStore::new(Arc::new(FailAfterWrites::new(Arc::clone(&backing), allow)));
            let outcome = injected.put_cert_bundle_fenced(&lease, &cert2, &key2, &meta("gen-2"));

            // A reader (a peer, or this node after a restart) must see one
            // complete generation, and the caller's result must agree with
            // what the reader can see.
            let reader = CertStore::new(Arc::clone(&backing));
            let bundle = reader
                .get_cert_bundle(host)
                .unwrap()
                .expect("the store must never hold a torn record")
                .expect("a complete generation survives the injected failure");
            let (cert, key) = (bundle.cert_pem, bundle.key_pem);
            assert!(
                sbproxy_tls::cert_resolver::load_certified_key(&cert, &key).is_ok(),
                "allow={allow}: the observed certificate and key must be one \
                 matching generation"
            );
            let serial = reader.get_meta(host).unwrap().unwrap().serial;
            match outcome {
                Ok(sbproxy_tls::cert_store::PublishOutcome::Published { .. }) => {
                    assert_eq!(
                        cert, cert2,
                        "allow={allow}: a reported success is whole-new"
                    );
                    assert_eq!(serial, "gen-2");
                }
                Ok(other) => panic!("allow={allow}: unexpected refusal {other:?}"),
                Err(_) => {
                    assert_eq!(
                        cert, cert1,
                        "allow={allow}: a reported failure is whole-old"
                    );
                    assert_eq!(
                        serial, "gen-1",
                        "metadata must describe the certificate a reader can actually serve"
                    );
                }
            }
        }
    }

    /// WOR-2635: a reader running concurrently with a publication must never
    /// observe a partially written record.
    ///
    /// 400 iterations, not one: a non-atomic `write(2)` over an existing file
    /// leaves a torn window measured in microseconds, so a single-shot read
    /// passes by luck. The two generations are deliberately different lengths
    /// so a truncated write is detectable as a short read rather than as
    /// identical bytes.
    #[test]
    fn a_concurrent_reader_never_observes_a_partial_record() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn KVStore> = Arc::new(FileKVStore::new(dir.path()).unwrap());
        let key = b"acme:bundle:concurrent.example.com".to_vec();
        let small = vec![b'a'; 4096];
        let large = vec![b'b'; 262_144];
        store.put(&key, &large).unwrap();

        let iterations = 400usize;
        let barrier = Arc::new(Barrier::new(2));
        let writer_store = Arc::clone(&store);
        let writer_key = key.clone();
        let writer_small = small.clone();
        let writer_large = large.clone();
        let writer_barrier = Arc::clone(&barrier);
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            for i in 0..iterations {
                let value = if i % 2 == 0 {
                    &writer_small
                } else {
                    &writer_large
                };
                writer_store.put(&writer_key, value).unwrap();
            }
        });

        barrier.wait();
        let mut torn = 0usize;
        for _ in 0..(iterations * 8) {
            if let Some(observed) = store.get(&key).unwrap() {
                let complete =
                    observed.as_ref() == small.as_slice() || observed.as_ref() == large.as_slice();
                if !complete {
                    torn += 1;
                }
            }
        }
        writer.join().unwrap();
        assert_eq!(
            torn, 0,
            "a reader observed {torn} partially written records; a bundle write must be atomic"
        );
    }

    /// Back-date a file lock's mtime so its lease reads as expired without a
    /// wall-clock sleep. The file backend leases on mtime age, so this is the
    /// same staleness a crashed holder leaves behind.
    fn expire_file_lock(dir: &std::path::Path, key: &[u8]) {
        let path = dir.join(hex::encode(key));
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
            .unwrap();
    }

    /// WOR-2633: two contenders racing the same expired file lease must not
    /// both come away believing they hold it.
    ///
    /// Two separate `FileKVStore` handles over one directory, because that is
    /// the deployment this lock exists for: two replicas on a shared mount.
    /// One handle would serialize both contenders behind its own process
    /// mutex and prove nothing. 300 barriered rounds, because the takeover is
    /// a read followed by a write and a single round can interleave safely by
    /// accident.
    #[test]
    fn two_barriered_stealers_of_a_stale_file_lease_do_not_both_win() {
        let mut double_acquires = 0usize;
        let rounds = 300usize;
        for round in 0..rounds {
            let dir = tempfile::tempdir().unwrap();
            let key = format!("acme:lock:stale-{round}.example.com").into_bytes();
            let owner = FileKVStore::new(dir.path()).unwrap();
            assert!(owner.try_lock(&key, b"crashed-owner", 60).unwrap());
            expire_file_lock(dir.path(), &key);

            let barrier = Arc::new(Barrier::new(2));
            let mut handles = Vec::new();
            for token in [b"contender-b".as_slice(), b"contender-c".as_slice()] {
                // A fresh handle per contender: a separate node, separate
                // process mutex, same shared directory.
                let node = FileKVStore::new(dir.path()).unwrap();
                let key = key.clone();
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    node.try_lock(&key, token, 60).unwrap()
                }));
            }
            let won = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|acquired| *acquired)
                .count();
            if won > 1 {
                double_acquires += 1;
            }
        }
        assert_eq!(
            double_acquires, 0,
            "{double_acquires}/{rounds} rounds handed the same expired file lease to two holders"
        );
    }

    /// WOR-2633 for the object-store backend: a store that cannot do a
    /// conditional write must refuse the takeover outright, because an
    /// unconditional overwrite is the double acquisition. `object_store`'s
    /// local filesystem is exactly such a store, so both contenders must
    /// lose here. The exactly-one-wins property on a conditional store is
    /// pinned by the barriered in-memory test inside `cert_object_store`.
    #[test]
    fn a_stale_object_lease_on_an_unconditional_store_is_never_taken_over() {
        for round in 0..3usize {
            let dir = tempfile::tempdir().unwrap();
            let url = format!("file://{}", dir.path().display());
            let store = Arc::new(
                sbproxy_tls::cert_object_store::ObjectStoreCertKv::from_url(&url).unwrap(),
            );
            let key = format!("acme:lock:obj-{round}.example.com").into_bytes();
            // A zero TTL is a lease that is expired the moment it lands.
            assert!(store.try_lock(&key, b"crashed-owner", 0).unwrap());

            let barrier = Arc::new(Barrier::new(2));
            let mut handles = Vec::new();
            for token in [b"contender-b".as_slice(), b"contender-c".as_slice()] {
                let store = Arc::clone(&store);
                let key = key.clone();
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    barrier.wait();
                    store.try_lock(&key, token, 60).unwrap()
                }));
            }
            let won = handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|acquired| *acquired)
                .count();
            assert_eq!(
                won, 0,
                "round {round}: a backend with no conditional write handed out a takeover"
            );
        }
    }

    /// WOR-2634, the seam itself: a follower whose resolver was loaded at
    /// startup must install the leader's renewal on its next renewal tick,
    /// without a restart. Before the fix, a tick that saw valid metadata
    /// `continue`d without touching the resolver, so this test times out
    /// polling for the new certificate.
    ///
    /// The store carries a far-future expiry, so the follower's tick never
    /// tries to issue and no CA is contacted; the tick's whole job here is
    /// the read-back-and-install the fleet documentation promises.
    #[tokio::test]
    async fn a_follower_installs_the_leaders_renewal_without_a_restart() {
        use sbproxy_config::ProxyServerConfig;

        let dir = tempfile::tempdir().unwrap();
        let storage_path = dir.path().to_str().unwrap().to_string();
        let host = "fleet.example.com";

        // The leader is represented by its own store handle over the same
        // shared directory, publishing generation 1 before the follower
        // boots and generation 2 after.
        let leader = CertStore::new(Arc::new(FileKVStore::new(dir.path()).unwrap()));
        let (cert1, key1) = pair(host);
        publish(&leader, host, &cert1, &key1, &meta("gen-1"));

        let config = ProxyServerConfig {
            https_bind_port: Some(8443),
            acme: Some(sbproxy_config::AcmeConfig {
                enabled: true,
                email: "operator@example.com".to_string(),
                directory_url: "https://acme.invalid/directory".to_string(),
                challenge_types: vec!["http-01".to_string()],
                storage_backend: "file".to_string(),
                storage_path,
                renew_before_days: 30,
                ca_root: None,
            }),
            ..Default::default()
        };
        let follower = sbproxy_tls::TlsState::init(&config, vec![host.to_string()])
            .expect("follower TLS state initializes against the shared store");
        assert_eq!(
            served_der(&follower.resolver, host),
            first_der(&cert1),
            "initialization installs the generation published before boot"
        );

        // The leader renews while the follower is running.
        let (cert2, key2) = pair(host);
        publish(&leader, host, &cert2, &key2, &meta("gen-2"));

        // A renewal tick fires immediately on task start. It must install
        // generation 2 even though the metadata says nothing needs issuing.
        follower.start_acme_renewal_task();
        let want = first_der(&cert2);
        let mut installed = false;
        for _ in 0..200 {
            if served_der(&follower.resolver, host) == want {
                installed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            installed,
            "the follower must hot-install the leader's renewal on its tick, \
             not serve the old certificate until a restart"
        );
    }

    fn served_der(resolver: &sbproxy_tls::cert_resolver::CertResolver, hostname: &str) -> Vec<u8> {
        resolver
            .resolve(hostname)
            .expect("a certificate is served for the hostname")
            .cert
            .first()
            .expect("served chain is non-empty")
            .as_ref()
            .to_vec()
    }

    fn first_der(cert_pem: &[u8]) -> Vec<u8> {
        use rustls::pki_types::{pem::PemObject as _, CertificateDer};
        CertificateDer::pem_slice_iter(cert_pem)
            .filter_map(|r| r.ok())
            .next()
            .expect("PEM contains a certificate")
            .as_ref()
            .to_vec()
    }
}
