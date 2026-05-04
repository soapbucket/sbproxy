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
    let store = CertStore::new(MemoryKVStore::new(0));

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
    let store = CertStore::new(MemoryKVStore::new(0));
    let resolver = Arc::new(CertResolver::new());

    // Generate a self-signed cert to simulate an ACME-issued cert.
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key.serialize_pem().into_bytes();

    // Store it.
    let meta = CertMeta {
        issued_at: "2026-04-15T00:00:00Z".to_string(),
        expires_at: "2026-07-14T00:00:00Z".to_string(),
        serial: "test-serial".to_string(),
    };
    store
        .put_cert_bundle("test.example.com", &cert_pem, &key_pem, &meta)
        .unwrap();

    // Load it back and register in resolver.
    let (loaded_cert, loaded_key) = store
        .get_cert_and_key("test.example.com")
        .unwrap()
        .expect("cert should exist");
    resolver
        .set_cert("test.example.com", &loaded_cert, &loaded_key)
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
    let store = CertStore::new(MemoryKVStore::new(0));
    let key_pair = AcmeClient::load_or_create_account_key(&store).unwrap();
    let token = "test-challenge-token-12345";
    let key_auth = AcmeClient::key_authorization(token, &key_pair);

    // Store the challenge response.
    challenge_store.set(token, &key_auth);

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

    let store = CertStore::new(MemoryKVStore::new(0));
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

    let store = CertStore::new(MemoryKVStore::new(0));
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
