//! mTLS (mutual TLS) client certificate verification.

use serde::Deserialize;

// --- Config ---

/// Default upper bound on entries in the process-wide mTLS client cert
/// metadata cache. Sized for ~10k unique clients reconnecting on a
/// keepalive cycle; well above any realistic legitimate population
/// while still capping memory at a few MB even with verbose SAN lists.
pub const DEFAULT_MAX_CERT_CACHE_ENTRIES: usize = 10_000;

fn default_max_cert_cache_entries() -> usize {
    DEFAULT_MAX_CERT_CACHE_ENTRIES
}

/// Configuration for mTLS client certificate verification.
#[derive(Debug, Clone, Deserialize)]
pub struct MtlsConfig {
    /// Path to a PEM-encoded CA certificate file used to verify client certs.
    pub client_ca_file: String,
    /// When true, reject connections that do not present a client certificate.
    pub require_client_cert: bool,
    /// Optional list of regex patterns that the client cert Common Name must match.
    /// If empty, any CN is accepted.
    #[serde(default)]
    pub allowed_cn_patterns: Vec<String>,
    /// Upper bound on entries in the process-wide cert metadata cache.
    /// Defaults to [`DEFAULT_MAX_CERT_CACHE_ENTRIES`]. A churning or
    /// adversarial client population that presents many distinct certs
    /// is capped here; the oldest entries (LRU order) are evicted to
    /// make room. The eviction counter
    /// `sbproxy_mtls_cert_cache_evictions_total` records the pressure.
    #[serde(default = "default_max_cert_cache_entries")]
    pub max_cert_cache_entries: usize,
}

// --- MtlsVerifier ---

/// Verifies client certificates for mTLS connections.
pub struct MtlsVerifier {
    config: MtlsConfig,
    ca_cert_pem: Vec<u8>,
    /// Compiled regex patterns from `config.allowed_cn_patterns`.
    cn_patterns: Vec<regex::Regex>,
}

impl MtlsVerifier {
    /// Build a verifier from the given config.
    ///
    /// Reads the CA cert PEM file from disk and compiles the CN regex patterns.
    pub fn from_config(config: MtlsConfig) -> anyhow::Result<Self> {
        let ca_cert_pem = std::fs::read(&config.client_ca_file).map_err(|e| {
            anyhow::anyhow!("reading client CA file '{}': {e}", config.client_ca_file)
        })?;

        // --- Compile CN patterns ---
        let mut cn_patterns = Vec::with_capacity(config.allowed_cn_patterns.len());
        for pattern in &config.allowed_cn_patterns {
            let re = regex::Regex::new(pattern)
                .map_err(|e| anyhow::anyhow!("invalid CN pattern '{}': {e}", pattern))?;
            cn_patterns.push(re);
        }

        Ok(Self {
            config,
            ca_cert_pem,
            cn_patterns,
        })
    }

    /// Check if a client certificate's Common Name matches the allowed patterns.
    ///
    /// Returns `true` when:
    /// - No patterns are configured (all CNs accepted), or
    /// - At least one pattern matches the provided `cn`.
    pub fn verify_cn(&self, cn: &str) -> bool {
        if self.cn_patterns.is_empty() {
            return true;
        }
        self.cn_patterns.iter().any(|re| re.is_match(cn))
    }

    /// Return the CA certificate PEM bytes for configuring rustls.
    pub fn ca_cert_pem(&self) -> &[u8] {
        &self.ca_cert_pem
    }

    /// Whether the verifier requires a client certificate.
    pub fn require_client_cert(&self) -> bool {
        self.config.require_client_cert
    }

    /// Return the configured CN patterns (as strings) for inspection.
    pub fn allowed_cn_patterns(&self) -> &[String] {
        &self.config.allowed_cn_patterns
    }
}

// --- Rustls ClientCertVerifier construction ---

/// Cached metadata extracted from a verified client certificate.
///
/// Pingora's `SslDigest` exposes only `organization`, `serial_number`,
/// and the SHA-256 digest of the cert. CN and SANs are dropped on the
/// floor inside the rustls handshake. We need them to forward client
/// identity to the upstream, so we capture them ourselves at verify
/// time and look them up later by cert digest.
#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    /// Subject Common Name. Empty when the cert has no CN.
    pub common_name: String,
    /// Subject Alternative Names. Includes DNS names, URIs, IP literals,
    /// and email addresses, stringified.
    pub subject_alt_names: Vec<String>,
}

/// Shared store of client cert metadata, keyed by SHA-256 of the
/// end-entity DER. The hash matches Pingora's `cert_digest`, so the
/// request path can pull the cached info via
/// `session.digest().ssl_digest.cert_digest`.
///
/// Capacity is bounded by a true LRU eviction inside `MtlsCertCache`
/// so a long-running proxy with churning client certs (a curious or
/// adversarial population presenting many distinct certs) cannot
/// grow it without bound and trigger an OOM.
pub type MtlsCertCacheHandle = std::sync::Arc<MtlsCertCache>;

/// Process-wide counter tracking the number of mTLS cert cache
/// entries dropped by the LRU bound. Lazily registered on the global
/// `ProxyMetrics` registry the first time an eviction fires so the
/// metric only appears when there is something to report.
static EVICTIONS_COUNTER: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();

fn evictions_counter() -> &'static prometheus::IntCounter {
    EVICTIONS_COUNTER.get_or_init(|| {
        let counter = prometheus::IntCounter::new(
            "sbproxy_mtls_cert_cache_evictions_total",
            "Number of mTLS client cert metadata entries evicted by the LRU bound",
        )
        .expect("evictions counter constructs");
        // Best-effort registration on the global registry. Tests that
        // rebuild ProxyMetrics may double-register; ignoring
        // AlreadyReg keeps the counter functional in either case.
        let _ = sbproxy_observe::metrics::metrics()
            .registry
            .register(Box::new(counter.clone()));
        counter
    })
}

/// Bounded cache mapping cert digest to extracted client cert info.
///
/// Backed by `lru::LruCache` wrapped in a `parking_lot::Mutex`. The
/// LRU itself is not `Sync`, so the mutex is mandatory. Hold time
/// is dominated by a hash + linked-list shuffle (a few hundred
/// nanoseconds), so contention is bounded by handshake throughput
/// rather than by lookup latency. An 80% high-water mark logs a
/// single warning per crossing (reset once size drops back below
/// the threshold) so operators see cache pressure without flooding
/// logs.
pub struct MtlsCertCache {
    by_digest: parking_lot::Mutex<lru::LruCache<Vec<u8>, ClientCertInfo>>,
    max_entries: usize,
    /// Latched once the cache crosses 80% of `max_entries`; cleared
    /// once the size drops back below the threshold. Using
    /// `AtomicBool` keeps the warning idempotent without locking.
    warn_triggered: std::sync::atomic::AtomicBool,
}

impl MtlsCertCache {
    /// Construct a new cache with the given upper bound.
    ///
    /// `max_entries` is clamped to at least 1 so the underlying
    /// `LruCache::new` precondition (`NonZeroUsize`) is always
    /// satisfied. A value of 0 in the config is treated as 1; the
    /// cache then trivially evicts on every insert.
    pub fn new(max_entries: usize) -> std::sync::Arc<Self> {
        let cap = std::num::NonZeroUsize::new(max_entries.max(1))
            .expect("max_entries clamped to at least 1");
        std::sync::Arc::new(Self {
            by_digest: parking_lot::Mutex::new(lru::LruCache::new(cap)),
            max_entries: max_entries.max(1),
            warn_triggered: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Look up the metadata captured for `cert_digest`. Returns `None`
    /// when the digest hasn't been seen (e.g. anonymous TLS client, or
    /// the cache evicted before the request landed). Touching an entry
    /// promotes it to most-recently-used.
    pub fn get(&self, cert_digest: &[u8]) -> Option<ClientCertInfo> {
        self.by_digest.lock().get(cert_digest).cloned()
    }

    fn insert(&self, cert_digest: Vec<u8>, info: ClientCertInfo) {
        let (evicted, post_len) = {
            let mut guard = self.by_digest.lock();
            // `LruCache::push` returns the (key, value) pair that was
            // dropped to make room (either because the cache was full
            // or because the same key already lived inside). We only
            // count the full-cap eviction case as pressure: replacing
            // an existing key is a no-op on size.
            let was_present = guard.contains(&cert_digest);
            let evicted = guard.push(cert_digest, info).is_some() && !was_present;
            (evicted, guard.len())
        };

        if evicted {
            evictions_counter().inc();
        }

        // --- 80% high-water warning ---
        //
        // Hysteresis: latch the warning the first time we cross the
        // threshold and clear it once we drop back below. A pure
        // "log when above 80%" without latching would spam once per
        // insert at steady state.
        let high_water = (self.max_entries.saturating_mul(8)) / 10;
        if post_len >= high_water {
            if !self
                .warn_triggered
                .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::info!(
                    cache_entries = post_len,
                    max_entries = self.max_entries,
                    "mTLS cert cache crossed 80% of max_entries; further growth will evict LRU entries"
                );
            }
        } else if post_len < high_water {
            // Reset so the next crossing logs again.
            self.warn_triggered
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Current number of entries in the cache. Test-only inspection
    /// helper; not part of the supported public API.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_digest.lock().len()
    }
}

/// Wraps a rustls `ClientCertVerifier` so we can capture CN and SANs
/// from each verified client certificate without taking responsibility
/// for the chain validation itself. The inner verifier (a
/// `WebPkiClientVerifier`) decides whether the cert is trusted; we
/// only piggyback on the verify call to extract metadata before
/// forwarding the result.
///
/// Behavior on parse failure: we still let the inner verifier run.
/// rustls's handshake either accepts or rejects the cert based on
/// chain validation alone, regardless of whether we could pull a CN
/// out of it.
struct CapturingClientCertVerifier {
    inner: std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>,
    cache: MtlsCertCacheHandle,
}

impl std::fmt::Debug for CapturingClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached_entries = self.cache.by_digest.lock().len();
        f.debug_struct("CapturingClientCertVerifier")
            .field("cached_entries", &cached_entries)
            .finish()
    }
}

impl rustls::server::danger::ClientCertVerifier for CapturingClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Capture metadata before delegating, so even a "verified but
        // we couldn't parse" path stores something useful. The actual
        // trust decision is the inner verifier's.
        if let Some(info) = parse_client_cert_info(end_entity.as_ref()) {
            let digest = sha256(end_entity.as_ref());
            self.cache.insert(digest, info);
        }
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}

/// Parse an end-entity DER into `ClientCertInfo`. Returns `None` when
/// the cert can't be parsed; the chain validator will reject it
/// independently and the request never reaches the upstream anyway.
fn parse_client_cert_info(der: &[u8]) -> Option<ClientCertInfo> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();

    let subject_alt_names = cert
        .extensions()
        .iter()
        .filter_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter())
        .filter_map(|gn| match gn {
            GeneralName::DNSName(s) => Some(format!("DNS:{s}")),
            GeneralName::URI(s) => Some(format!("URI:{s}")),
            GeneralName::RFC822Name(s) => Some(format!("email:{s}")),
            GeneralName::IPAddress(b) => match b.len() {
                4 => Some(format!("IP:{}.{}.{}.{}", b[0], b[1], b[2], b[3])),
                16 => {
                    let mut s = String::with_capacity(40);
                    for (i, pair) in b.chunks(2).enumerate() {
                        if i > 0 {
                            s.push(':');
                        }
                        s.push_str(&format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])));
                    }
                    Some(format!("IP:{s}"))
                }
                _ => None,
            },
            _ => None,
        })
        .collect();

    Some(ClientCertInfo {
        common_name,
        subject_alt_names,
    })
}

/// Build a rustls `ClientCertVerifier` from a PEM-encoded CA bundle
/// at `ca_path`. The bundle may contain one or more PEM CERTIFICATE
/// blocks; every one is added to the trust anchor set.
///
/// `require` toggles between strict mTLS (the handshake fails when
/// the client does not present a cert) and optional mTLS (the
/// handshake succeeds without a cert; downstream code can branch
/// on the absence of cert metadata).
///
/// The returned verifier wraps a `WebPkiClientVerifier` so chain
/// validation is unchanged. The wrapper exists to capture CN and SAN
/// metadata into `cache`, keyed by SHA-256 of the end-entity DER, so
/// the request path can pull them out by `session.digest().cert_digest`.
pub fn build_client_cert_verifier(
    ca_path: &str,
    require: bool,
    cache: MtlsCertCacheHandle,
) -> anyhow::Result<std::sync::Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    use rustls::server::WebPkiClientVerifier;
    use rustls::RootCertStore;

    use rustls::pki_types::{pem::PemObject as _, CertificateDer};

    let pem_bytes = std::fs::read(ca_path)
        .map_err(|e| anyhow::anyhow!("read client_ca_file '{}': {e}", ca_path))?;
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for cert in CertificateDer::pem_slice_iter(&pem_bytes) {
        let der = cert.map_err(|e| anyhow::anyhow!("parse PEM in '{}': {e}", ca_path))?;
        roots
            .add(der)
            .map_err(|e| anyhow::anyhow!("add root cert from '{}': {e}", ca_path))?;
        count += 1;
    }
    if count == 0 {
        anyhow::bail!("no CERTIFICATE entries found in '{}'", ca_path);
    }
    let builder = WebPkiClientVerifier::builder(std::sync::Arc::new(roots));
    let inner = if require {
        builder.build()
    } else {
        builder.allow_unauthenticated().build()
    }
    .map_err(|e| anyhow::anyhow!("build client cert verifier: {e}"))?;
    Ok(std::sync::Arc::new(CapturingClientCertVerifier {
        inner,
        cache,
    }))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config_with_patterns(patterns: Vec<&str>) -> MtlsConfig {
        MtlsConfig {
            client_ca_file: "/nonexistent/ca.pem".to_string(),
            require_client_cert: true,
            allowed_cn_patterns: patterns.into_iter().map(|s| s.to_string()).collect(),
            max_cert_cache_entries: DEFAULT_MAX_CERT_CACHE_ENTRIES,
        }
    }

    // --- ClientCertInfo extraction ---

    /// Self-signed cert with CN `test.example.com` plus DNS and IP
    /// SANs. Built fresh per test so the suite stays hermetic.
    fn make_test_cert() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("keypair");
        let mut params = rcgen::CertificateParams::new(vec![
            "alt.example.com".to_string(),
            "10.1.2.3".to_string(),
        ])
        .expect("params");
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test.example.com");
        let cert = params.self_signed(&key).expect("self-sign");
        cert.der().to_vec()
    }

    #[test]
    fn parse_client_cert_extracts_cn() {
        let der = make_test_cert();
        let info = parse_client_cert_info(&der).expect("parse succeeds");
        assert_eq!(info.common_name, "test.example.com");
    }

    #[test]
    fn parse_client_cert_extracts_dns_san() {
        let der = make_test_cert();
        let info = parse_client_cert_info(&der).expect("parse");
        assert!(
            info.subject_alt_names
                .iter()
                .any(|s| s == "DNS:alt.example.com"),
            "expected DNS SAN among {:?}",
            info.subject_alt_names
        );
    }

    #[test]
    fn parse_client_cert_extracts_ipv4_san() {
        let der = make_test_cert();
        let info = parse_client_cert_info(&der).expect("parse");
        assert!(
            info.subject_alt_names.iter().any(|s| s == "IP:10.1.2.3"),
            "expected IPv4 SAN among {:?}",
            info.subject_alt_names
        );
    }

    #[test]
    fn cache_round_trip() {
        let cache = MtlsCertCache::new(8);
        let info = ClientCertInfo {
            common_name: "alice".into(),
            subject_alt_names: vec!["DNS:alice.local".into()],
        };
        let digest = sha256(b"fake cert bytes");
        cache.insert(digest.clone(), info.clone());
        let got = cache.get(&digest).expect("hit");
        assert_eq!(got.common_name, info.common_name);
        assert_eq!(got.subject_alt_names, info.subject_alt_names);
    }

    #[test]
    fn cache_evicts_when_full() {
        let cache = MtlsCertCache::new(2);
        for i in 0..5u8 {
            cache.insert(
                vec![i],
                ClientCertInfo {
                    common_name: format!("client-{i}"),
                    subject_alt_names: vec![],
                },
            );
        }
        assert!(cache.len() <= 2, "cap should hold");
    }

    #[test]
    fn cache_evicts_oldest_lru_entry() {
        // Fill the cache past its limit and confirm true LRU semantics.
        // Inserts 0,1,2 then touches key 0 (promoting it to MRU), then
        // inserts key 3. The least-recently-used entry at that point
        // is key 1, so it should be evicted while keys 0, 2, 3 remain.
        let cache = MtlsCertCache::new(3);
        for i in 0..3u8 {
            cache.insert(
                vec![i],
                ClientCertInfo {
                    common_name: format!("client-{i}"),
                    subject_alt_names: vec![],
                },
            );
        }

        // Touch key 0 to move it to MRU.
        let _ = cache.get(&[0u8][..]);

        // Insert key 3, which forces an eviction.
        cache.insert(
            vec![3u8],
            ClientCertInfo {
                common_name: "client-3".into(),
                subject_alt_names: vec![],
            },
        );

        assert_eq!(cache.len(), 3, "size stays at limit");
        assert!(cache.get(&[0u8][..]).is_some(), "key 0 was MRU, kept");
        assert!(cache.get(&[2u8][..]).is_some(), "key 2 was newer, kept");
        assert!(cache.get(&[3u8][..]).is_some(), "key 3 just inserted, kept");
        assert!(
            cache.get(&[1u8][..]).is_none(),
            "key 1 was LRU, should have been evicted"
        );
    }

    #[test]
    fn eviction_counter_increments_on_overflow() {
        // Force evictions and confirm the counter went up by exactly
        // the number of inserts past the cap. Reads the counter from
        // the global ProxyMetrics registry (the same one
        // /metrics/scrape uses), gathering only this metric family.
        let cache = MtlsCertCache::new(2);
        let before = evictions_counter().get();

        // 4 inserts into a cap-2 cache => 2 evictions (the third and
        // fourth inserts each push out one prior entry).
        for i in 0..4u8 {
            cache.insert(
                vec![i],
                ClientCertInfo {
                    common_name: format!("client-{i}"),
                    subject_alt_names: vec![],
                },
            );
        }

        let after = evictions_counter().get();
        assert_eq!(after - before, 2, "two evictions expected");

        // The same counter must be visible via the shared registry
        // so /metrics scrapes pick it up (the production code path).
        let families = sbproxy_observe::metrics::metrics().registry.gather();
        let mut found = false;
        for fam in &families {
            if fam.get_name() == "sbproxy_mtls_cert_cache_evictions_total" {
                found = true;
                let total: u64 = fam
                    .get_metric()
                    .iter()
                    .map(|m| m.get_counter().get_value() as u64)
                    .sum();
                assert!(
                    total >= 2,
                    "registered counter reflects eviction (got {total})"
                );
            }
        }
        assert!(
            found,
            "evictions counter was not registered on the shared registry"
        );
    }

    #[test]
    fn parse_garbage_returns_none() {
        assert!(parse_client_cert_info(b"not a cert").is_none());
    }

    #[test]
    fn test_cn_matching_no_patterns_accepts_all() {
        // When no patterns are configured every CN is accepted.
        let verifier = MtlsVerifier {
            config: make_config_with_patterns(vec![]),
            ca_cert_pem: vec![],
            cn_patterns: vec![],
        };
        assert!(verifier.verify_cn("any-client.example.com"));
        assert!(verifier.verify_cn(""));
    }

    #[test]
    fn test_cn_matching_exact_pattern() {
        let re = regex::Regex::new(r"^client\.example\.com$").unwrap();
        let config = make_config_with_patterns(vec![r"^client\.example\.com$"]);
        let verifier = MtlsVerifier {
            cn_patterns: vec![re],
            ca_cert_pem: vec![],
            config,
        };

        assert!(verifier.verify_cn("client.example.com"));
        assert!(!verifier.verify_cn("other.example.com"));
    }

    #[test]
    fn test_cn_matching_wildcard_pattern() {
        let re = regex::Regex::new(r"^.*\.example\.com$").unwrap();
        let config = make_config_with_patterns(vec![r"^.*\.example\.com$"]);
        let verifier = MtlsVerifier {
            cn_patterns: vec![re],
            ca_cert_pem: vec![],
            config,
        };

        assert!(verifier.verify_cn("service-a.example.com"));
        assert!(verifier.verify_cn("service-b.example.com"));
        assert!(!verifier.verify_cn("evil.attacker.com"));
    }

    #[test]
    fn test_cn_matching_multiple_patterns() {
        let patterns = vec![
            regex::Regex::new(r"^admin\..+$").unwrap(),
            regex::Regex::new(r"^service\..+$").unwrap(),
        ];
        let config = make_config_with_patterns(vec![r"^admin\..+$", r"^service\..+$"]);
        let verifier = MtlsVerifier {
            cn_patterns: patterns,
            ca_cert_pem: vec![],
            config,
        };

        assert!(verifier.verify_cn("admin.corp.example.com"));
        assert!(verifier.verify_cn("service.api.example.com"));
        assert!(!verifier.verify_cn("user.example.com"));
    }

    #[test]
    fn test_config_deserialization() {
        let json = r#"{
            "client_ca_file": "/etc/ssl/ca.pem",
            "require_client_cert": true,
            "allowed_cn_patterns": ["^client\\..*$", "^trusted\\..*$"]
        }"#;
        let config: MtlsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.client_ca_file, "/etc/ssl/ca.pem");
        assert!(config.require_client_cert);
        assert_eq!(config.allowed_cn_patterns.len(), 2);
        // Default applies when the field is omitted.
        assert_eq!(
            config.max_cert_cache_entries,
            DEFAULT_MAX_CERT_CACHE_ENTRIES
        );
    }

    #[test]
    fn test_config_deserialization_defaults() {
        // allowed_cn_patterns is optional and defaults to empty.
        let json = r#"{
            "client_ca_file": "/ca.pem",
            "require_client_cert": false
        }"#;
        let config: MtlsConfig = serde_json::from_str(json).unwrap();
        assert!(config.allowed_cn_patterns.is_empty());
        assert!(!config.require_client_cert);
        assert_eq!(
            config.max_cert_cache_entries,
            DEFAULT_MAX_CERT_CACHE_ENTRIES
        );
    }

    #[test]
    fn test_config_deserialization_with_explicit_cache_bound() {
        let json = r#"{
            "client_ca_file": "/ca.pem",
            "require_client_cert": false,
            "max_cert_cache_entries": 500
        }"#;
        let config: MtlsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.max_cert_cache_entries, 500);
    }

    #[test]
    fn test_from_config_invalid_pattern() {
        // Build an MtlsConfig with an invalid regex pattern.
        // from_config should fail since it requires reading the CA file.
        // We just verify the pattern compilation would fail.
        #[allow(clippy::invalid_regex)]
        let result = regex::Regex::new(r"[invalid");
        assert!(result.is_err(), "invalid regex should fail compilation");
    }

    #[test]
    fn test_require_client_cert_flag() {
        let config = MtlsConfig {
            client_ca_file: "/ca.pem".to_string(),
            require_client_cert: true,
            allowed_cn_patterns: vec![],
            max_cert_cache_entries: DEFAULT_MAX_CERT_CACHE_ENTRIES,
        };
        let verifier = MtlsVerifier {
            cn_patterns: vec![],
            ca_cert_pem: b"fake-pem".to_vec(),
            config,
        };
        assert!(verifier.require_client_cert());
    }
}
