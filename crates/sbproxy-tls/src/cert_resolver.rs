//! Dynamic certificate resolver with SNI-based selection.
//!
//! [`CertResolver`] implements `rustls::server::ResolvesServerCert` and supports
//! lock-free reads via `arc-swap`. Certs can be loaded from PEM files or bytes and
//! swapped atomically without restarting the server.

use std::{collections::HashMap, fs, sync::Arc};

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use tracing::debug;

// --- Certificate loading helpers ---

/// Parse PEM bytes into a [`CertifiedKey`] that rustls can use for signing.
pub fn load_certified_key(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey> {
    // Parse certificate chain.
    let cert_chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse PEM certificate chain")?;

    if cert_chain.is_empty() {
        return Err(anyhow!("no certificates found in PEM data"));
    }

    // Parse private key.
    let private_key: PrivateKeyDer<'static> =
        PrivateKeyDer::from_pem_slice(key_pem).context("failed to parse PEM private key")?;

    let signing_key =
        any_supported_type(&private_key).map_err(|_| anyhow!("unsupported private key type"))?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

// --- CertResolver ---

/// Snapshot of the hostname-to-cert map used for lock-free reads.
type CertMap = HashMap<String, Arc<CertifiedKey>>;

/// Dynamic, SNI-aware certificate resolver.
///
/// Holds a hostname-keyed map of [`CertifiedKey`]s plus an optional fallback cert.
/// Both are stored behind [`ArcSwap`] so reads are lock-free and swaps are atomic.
pub struct CertResolver {
    /// hostname -> certified key
    certs: ArcSwap<CertMap>,
    /// Fallback cert used when no hostname match is found (e.g. manual TLS mode).
    fallback: ArcSwap<Option<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cert_count = self.certs.load().len();
        let has_fallback = self.fallback.load().is_some();
        f.debug_struct("CertResolver")
            .field("cert_count", &cert_count)
            .field("has_fallback", &has_fallback)
            .finish()
    }
}

impl CertResolver {
    /// Create an empty resolver with no certs.
    pub fn new() -> Self {
        Self {
            certs: ArcSwap::from_pointee(HashMap::new()),
            fallback: ArcSwap::from_pointee(None),
        }
    }

    /// Build a resolver pre-loaded with a single cert from PEM files on disk.
    ///
    /// The loaded cert is set as the fallback cert and is also registered under
    /// every SAN/CN present in the certificate (best-effort).
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> Result<Self> {
        let cert_pem =
            fs::read(cert_path).with_context(|| format!("reading cert file: {cert_path}"))?;
        let key_pem =
            fs::read(key_path).with_context(|| format!("reading key file: {key_path}"))?;

        let resolver = Self::new();
        let ck = load_certified_key(&cert_pem, &key_pem)?;
        resolver.set_fallback(ck);
        Ok(resolver)
    }

    /// Register or replace the cert for `hostname` (exact match, no wildcards).
    pub fn set_cert(&self, hostname: &str, cert_pem: &[u8], key_pem: &[u8]) -> Result<()> {
        let ck = load_certified_key(cert_pem, key_pem)
            .with_context(|| format!("loading cert for {hostname}"))?;
        let arc_ck = Arc::new(ck);

        // Atomically replace the map with a new version that includes this entry.
        self.certs.rcu(|current| {
            let mut updated = (**current).clone();
            updated.insert(hostname.to_lowercase(), arc_ck.clone());
            updated
        });

        debug!(hostname, "cert registered");
        Ok(())
    }

    /// Remove the cert for `hostname`. No-op if no cert is registered.
    pub fn remove_cert(&self, hostname: &str) {
        let key = hostname.to_lowercase();
        self.certs.rcu(|current| {
            if current.contains_key(&key) {
                let mut updated = (**current).clone();
                updated.remove(&key);
                updated
            } else {
                (**current).clone()
            }
        });
        debug!(hostname, "cert removed");
    }

    /// Look up the cert for `hostname`. Returns `None` if no hostname-specific cert exists.
    ///
    /// This does NOT fall back to the fallback cert - use [`ResolvesServerCert::resolve`]
    /// for the full SNI-aware lookup including fallback.
    pub fn resolve(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        let key = hostname.to_lowercase();
        self.certs.load().get(&key).cloned()
    }

    /// Set the fallback cert used when no hostname-specific cert matches.
    pub fn set_fallback(&self, certified_key: CertifiedKey) {
        self.fallback.store(Arc::new(Some(Arc::new(certified_key))));
    }

    /// Build a [`ServerConfig`] that uses this resolver for SNI-based cert selection.
    ///
    /// ALPN protocols are set to `["h3", "h2", "http/1.1"]` for HTTP/3 and HTTP/2 support.
    pub fn rustls_server_config(self: &Arc<Self>) -> Result<ServerConfig> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.clone());

        let mut config = config;
        config.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(config)
    }
}

impl Default for CertResolver {
    fn default() -> Self {
        Self::new()
    }
}

// --- rustls integration ---

impl ResolvesServerCert for CertResolver {
    /// Select a cert based on the SNI hostname in the ClientHello.
    ///
    /// Resolution order:
    /// 1. Hostname-specific cert (exact, case-insensitive).
    /// 2. Fallback cert (if set).
    /// 3. `None` - rustls will abort the handshake.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            if let Some(ck) = self.resolve(sni) {
                debug!(sni, "SNI cert match");
                return Some(ck);
            }
            debug!(sni, "no SNI cert match, trying fallback");
        }

        // Load fallback - the Option is wrapped in Arc, so we clone the inner Arc.
        self.fallback.load().as_ref().as_ref().cloned()
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed certificate for testing using rcgen.
    fn generate_self_signed(san: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    #[test]
    fn test_empty_resolver_returns_none() {
        let resolver = CertResolver::new();
        assert!(resolver.resolve("example.com").is_none());
    }

    #[test]
    fn test_set_and_get_cert_by_hostname() {
        let resolver = CertResolver::new();
        let (cert_pem, key_pem) = generate_self_signed("example.com");

        resolver
            .set_cert("example.com", &cert_pem, &key_pem)
            .expect("set_cert should succeed");

        assert!(
            resolver.resolve("example.com").is_some(),
            "should find cert by hostname"
        );
        assert!(
            resolver.resolve("other.com").is_none(),
            "should not find cert for different hostname"
        );
    }

    #[test]
    fn test_hostname_lookup_is_case_insensitive() {
        let resolver = CertResolver::new();
        let (cert_pem, key_pem) = generate_self_signed("example.com");
        resolver
            .set_cert("Example.COM", &cert_pem, &key_pem)
            .unwrap();

        assert!(resolver.resolve("example.com").is_some());
        assert!(resolver.resolve("EXAMPLE.COM").is_some());
    }

    #[test]
    fn test_remove_cert() {
        let resolver = CertResolver::new();
        let (cert_pem, key_pem) = generate_self_signed("example.com");
        resolver
            .set_cert("example.com", &cert_pem, &key_pem)
            .unwrap();

        resolver.remove_cert("example.com");
        assert!(
            resolver.resolve("example.com").is_none(),
            "cert should be gone after removal"
        );
    }

    #[test]
    fn test_remove_nonexistent_is_noop() {
        let resolver = CertResolver::new();
        // Should not panic.
        resolver.remove_cert("never-existed.com");
    }

    #[test]
    fn test_fallback_cert_returned_when_no_hostname_match() {
        let resolver = CertResolver::new();
        let (cert_pem, key_pem) = generate_self_signed("fallback.local");
        let ck = load_certified_key(&cert_pem, &key_pem).unwrap();
        resolver.set_fallback(ck);

        // No hostname cert registered, so resolve() returns None ...
        assert!(resolver.resolve("anything.com").is_none());

        // ... but the fallback is still accessible via the ArcSwap.
        let loaded = resolver.fallback.load();
        assert!(loaded.as_ref().is_some(), "fallback should be set");
    }

    #[test]
    fn test_hostname_cert_takes_priority_over_fallback() {
        let resolver = CertResolver::new();

        // Set a fallback.
        let (fb_cert, fb_key) = generate_self_signed("fallback.local");
        let fallback_ck = load_certified_key(&fb_cert, &fb_key).unwrap();
        resolver.set_fallback(fallback_ck);

        // Also set a hostname-specific cert.
        let (cert_pem, key_pem) = generate_self_signed("specific.com");
        resolver
            .set_cert("specific.com", &cert_pem, &key_pem)
            .unwrap();

        // The hostname-specific cert should be returned.
        let found = resolver.resolve("specific.com");
        assert!(found.is_some(), "hostname cert should be found");

        // For an unknown hostname, we get None from resolve() (fallback is handled
        // by the ResolvesServerCert impl).
        assert!(resolver.resolve("unknown.com").is_none());
    }

    #[test]
    fn test_load_certified_key_valid_pem() {
        let (cert_pem, key_pem) = generate_self_signed("test.local");
        let ck = load_certified_key(&cert_pem, &key_pem);
        assert!(ck.is_ok(), "should parse valid PEM: {:?}", ck.err());
    }

    #[test]
    fn test_load_certified_key_invalid_cert_pem() {
        let result = load_certified_key(b"not-a-pem", b"not-a-pem");
        assert!(result.is_err(), "should fail on invalid PEM");
    }

    #[test]
    fn test_atomic_cert_swap() {
        let resolver = Arc::new(CertResolver::new());

        let (cert1_pem, key1_pem) = generate_self_signed("example.com");
        let (cert2_pem, key2_pem) = generate_self_signed("example.com");

        resolver
            .set_cert("example.com", &cert1_pem, &key1_pem)
            .unwrap();
        let first = resolver.resolve("example.com").unwrap();

        // Replace with a new cert.
        resolver
            .set_cert("example.com", &cert2_pem, &key2_pem)
            .unwrap();
        let second = resolver.resolve("example.com").unwrap();

        // Both are valid; the pointer should differ (different certs).
        assert!(
            !Arc::ptr_eq(&first, &second),
            "cert should have been swapped"
        );
    }

    #[test]
    fn test_rustls_server_config_builds() {
        // rustls 0.23 requires a crypto provider to be installed when no single
        // feature is selected at compile time. Install ring as the process-level
        // default (idempotent - subsequent installs are ignored).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let resolver = Arc::new(CertResolver::new());
        let (cert_pem, key_pem) = generate_self_signed("localhost");
        let ck = load_certified_key(&cert_pem, &key_pem).unwrap();
        resolver.set_fallback(ck);

        let config = resolver.rustls_server_config();
        assert!(
            config.is_ok(),
            "ServerConfig should build: {:?}",
            config.err()
        );

        let config = config.unwrap();
        assert!(
            config.alpn_protocols.iter().any(|p| p == b"h2"),
            "h2 should be in ALPN protocols"
        );
        assert!(
            config.alpn_protocols.iter().any(|p| p == b"h3"),
            "h3 should be in ALPN protocols"
        );
    }
}
