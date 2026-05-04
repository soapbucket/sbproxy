//! TLS, ACME auto-cert, and HTTP/3 support for sbproxy.

#![warn(missing_docs)]

pub mod acme;
pub mod alt_svc;
pub mod cert_resolver;
pub mod cert_store;
pub mod challenges;
pub mod fingerprint;
pub mod h3_listener;
pub mod mtls;
pub mod ocsp;

pub use fingerprint::{
    classify_trustworthy, compute_ja4h, parse_client_hello, TlsFingerprint, TrustworthyConfig,
};

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use acme::AcmeClient;
use cert_resolver::{load_certified_key, CertResolver};
use cert_store::{CertMeta, CertStore};
use challenges::Http01ChallengeStore;
use sbproxy_config::ProxyServerConfig;
use sbproxy_platform::MemoryKVStore;

// --- TlsState ---

/// Central TLS state: certificate resolver, ACME challenge store, and lifecycle tasks.
pub struct TlsState {
    /// SNI-aware certificate resolver shared with the TLS acceptor.
    pub resolver: Arc<CertResolver>,
    /// Store for in-flight ACME HTTP-01 challenge tokens.
    pub challenge_store: Arc<Http01ChallengeStore>,
    /// ACME configuration (None means ACME is disabled).
    acme_config: Option<sbproxy_config::AcmeConfig>,
    /// Persistent certificate storage backend.
    cert_store: Arc<CertStore<MemoryKVStore>>,
    /// Hostnames this proxy is responsible for.
    hostnames: Vec<String>,
}

impl TlsState {
    /// Initialize TLS state from a [`ProxyServerConfig`].
    ///
    /// - Validates that `https_bind_port` is configured.
    /// - Loads manual TLS cert/key files as a fallback cert when provided.
    /// - Pre-loads any cached ACME certificates from the cert store.
    pub fn init(config: &ProxyServerConfig, hostnames: Vec<String>) -> Result<Self> {
        // --- Validate HTTPS port ---
        if config.https_bind_port.is_none() {
            return Err(anyhow::anyhow!("https_bind_port must be set to use TLS"));
        }

        let resolver = Arc::new(CertResolver::new());
        let challenge_store = Arc::new(Http01ChallengeStore::new());
        let cert_store = Arc::new(CertStore::new(MemoryKVStore::new(0)));

        // --- Manual cert files ---
        if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_file, &config.tls_key_file) {
            match cert_resolver::load_certified_key(
                &std::fs::read(cert_path)
                    .with_context(|| format!("reading TLS cert: {cert_path}"))?,
                &std::fs::read(key_path).with_context(|| format!("reading TLS key: {key_path}"))?,
            ) {
                Ok(ck) => {
                    resolver.set_fallback(ck);
                    info!(cert = %cert_path, "loaded manual TLS certificate as fallback");
                }
                Err(e) => {
                    warn!(
                        "failed to load manual TLS cert/key ({e:#}), continuing without fallback"
                    );
                }
            }
        }

        // --- Pre-load cached ACME certs ---
        if let Some(acme_cfg) = &config.acme {
            if acme_cfg.enabled {
                for hostname in &hostnames {
                    match cert_store.get_cert_and_key(hostname) {
                        Ok(Some((cert_pem, key_pem))) => {
                            match cert_resolver::load_certified_key(&cert_pem, &key_pem) {
                                Ok(_ck) => {
                                    // Register under the exact hostname only.
                                    // ACME certs are hostname-specific, not fallback.
                                    if let Err(e) = resolver.set_cert(hostname, &cert_pem, &key_pem)
                                    {
                                        warn!(hostname, "failed to register cached cert: {e:#}");
                                    } else {
                                        info!(hostname, "loaded cached ACME certificate");
                                    }
                                }
                                Err(e) => {
                                    warn!(hostname, "cached cert is invalid: {e:#}");
                                }
                            }
                        }
                        Ok(None) => {
                            // No cached cert yet - will be obtained via ACME.
                        }
                        Err(e) => {
                            warn!(hostname, "error reading cert store: {e:#}");
                        }
                    }
                }
            }
        }

        Ok(Self {
            resolver,
            challenge_store,
            acme_config: config.acme.clone(),
            cert_store,
            hostnames,
        })
    }

    /// Spawn a background task that checks certificate expiry every 12 hours
    /// and issues or renews certificates via ACME when needed.
    ///
    /// Does nothing if ACME is not configured or is disabled.
    pub fn start_acme_renewal_task(&self) {
        let acme_config = match &self.acme_config {
            Some(cfg) if cfg.enabled => cfg.clone(),
            _ => return,
        };

        let cert_store = self.cert_store.clone();
        let resolver = self.resolver.clone();
        let challenge_store = self.challenge_store.clone();
        let hostnames = self.hostnames.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));
            // The first tick fires immediately; skip it so we don't flood logs at startup.
            interval.tick().await;

            loop {
                interval.tick().await;

                for hostname in &hostnames {
                    let needs_issuance = match cert_store.get_meta(hostname) {
                        Ok(Some(ref meta)) => {
                            if cert_needs_renewal(meta, acme_config.renew_before_days) {
                                info!(hostname, "certificate needs renewal");
                                true
                            } else {
                                false
                            }
                        }
                        Ok(None) => {
                            info!(hostname, "no certificate found, issuing via ACME");
                            true
                        }
                        Err(e) => {
                            error!(hostname, "error checking cert meta: {e:#}");
                            false
                        }
                    };

                    if !needs_issuance {
                        continue;
                    }

                    // --- Issue or renew certificate via ACME ---
                    let mut acme_client = AcmeClient::new(
                        &acme_config.directory_url,
                        &acme_config.email,
                        acme_config.challenge_types.clone(),
                    );

                    // Load the account key.
                    let key_pair = match AcmeClient::load_or_create_account_key(&cert_store) {
                        Ok(kp) => kp,
                        Err(e) => {
                            error!(hostname, "failed to load ACME account key: {e:#}");
                            continue;
                        }
                    };

                    // Fetch directory.
                    if let Err(e) = acme_client.fetch_directory().await {
                        error!(hostname, "failed to fetch ACME directory: {e:#}");
                        continue;
                    }

                    // Run full issuance flow.
                    match acme_client
                        .issue_cert(&key_pair, hostname, &challenge_store)
                        .await
                    {
                        Ok((cert_pem, key_pem)) => {
                            // Extract expiry from the cert to build metadata.
                            let expires_at = parse_cert_expiry(&cert_pem).unwrap_or_else(|| {
                                // Fallback: 90 days from now (typical ACME cert validity).
                                (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339()
                            });

                            let meta = CertMeta {
                                issued_at: chrono::Utc::now().to_rfc3339(),
                                expires_at,
                                serial: String::from("acme-issued"),
                            };

                            // Persist to cert store.
                            if let Err(e) =
                                cert_store.put_cert_bundle(hostname, &cert_pem, &key_pem, &meta)
                            {
                                error!(hostname, "failed to persist issued cert: {e:#}");
                                continue;
                            }

                            // Validate the issued cert parses before installing in resolver.
                            match load_certified_key(&cert_pem, &key_pem) {
                                Ok(_) => {
                                    // Register under the hostname for SNI-based selection.
                                    if let Err(e) = resolver.set_cert(hostname, &cert_pem, &key_pem)
                                    {
                                        error!(
                                            hostname,
                                            "failed to install cert in resolver: {e:#}"
                                        );
                                    } else {
                                        info!(hostname, "ACME certificate installed in resolver");
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        hostname,
                                        "failed to parse issued cert for resolver: {e:#}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            error!(hostname, "ACME issuance failed: {e:#}");
                        }
                    }
                }
            }
        });
    }

    /// Start an HTTP/3 listener if HTTP/3 is enabled in `config`.
    /// Generate temporary self-signed cert files for bootstrapping HTTPS when
    /// ACME is enabled but no manual certs are provided.
    ///
    /// Returns `(cert_path, key_path)` pointing to temp files. The files live
    /// for the process lifetime. Once ACME issues a real cert, the proxy should
    /// be restarted or the cert hot-swapped via the CertResolver.
    pub fn generate_self_signed_bootstrap_cert(&self) -> Result<(String, String)> {
        let hostname = self
            .hostnames
            .first()
            .map(|s| s.as_str())
            .unwrap_or("localhost");
        let key_pair = rcgen::KeyPair::generate().context("generating bootstrap key pair")?;
        let params = rcgen::CertificateParams::new(vec![hostname.to_string()])
            .context("creating bootstrap cert params")?;
        let cert = params
            .self_signed(&key_pair)
            .context("self-signing bootstrap cert")?;

        let cert_dir = std::env::temp_dir().join("sbproxy-tls");
        std::fs::create_dir_all(&cert_dir).context("creating temp cert directory")?;

        let cert_path = cert_dir.join("bootstrap-cert.pem");
        let key_path = cert_dir.join("bootstrap-key.pem");

        std::fs::write(&cert_path, cert.pem()).context("writing bootstrap cert")?;
        std::fs::write(&key_path, key_pair.serialize_pem()).context("writing bootstrap key")?;

        let cert_str = cert_path.to_string_lossy().to_string();
        let key_str = key_path.to_string_lossy().to_string();

        info!(cert = %cert_str, "generated self-signed bootstrap cert for ACME-only mode");
        Ok((cert_str, key_str))
    }

    ///
    /// Returns `Some(handle)` when the listener was started, or `None` if HTTP/3
    /// is disabled or not configured.
    pub fn start_h3_listener(
        &self,
        config: &ProxyServerConfig,
        dispatch_fn: h3_listener::DispatchFn,
    ) -> Result<Option<JoinHandle<()>>> {
        let h3_config = match &config.http3 {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Ok(None),
        };

        // Bind on the same port as HTTPS (QUIC is UDP).
        let https_port = config
            .https_bind_port
            .expect("https_bind_port is validated in init()");

        let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{https_port}")
            .parse()
            .context("parsing H3 bind addr")?;

        let handle = h3_listener::start_h3_listener(
            bind_addr,
            self.resolver.clone(),
            dispatch_fn,
            h3_config,
        )
        .context("starting H3 listener")?;

        Ok(Some(handle))
    }
}

// --- Certificate helpers ---

/// Attempt to parse the "not after" (expiry) date from a PEM certificate.
///
/// Returns the expiry as an RFC 3339 string, or `None` if parsing fails.
fn parse_cert_expiry(cert_pem: &[u8]) -> Option<String> {
    use rustls::pki_types::{pem::PemObject as _, CertificateDer};
    use x509_parser::prelude::*;

    let der_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem)
        .filter_map(|r| r.ok())
        .collect();
    let der = der_certs.first()?;

    let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
    let not_after = cert.validity().not_after;

    // x509-parser uses a custom ASN.1 time type; convert via timestamp.
    let ts = not_after.timestamp();
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)?;
    Some(dt.to_rfc3339())
}

// --- Renewal helper ---

/// Returns `true` if the certificate described by `meta` should be renewed.
///
/// Renewal is needed when the certificate is already expired, will expire within
/// `renew_before_days` days, or when the expiry date cannot be parsed (re-issue
/// to be safe).
fn cert_needs_renewal(meta: &CertMeta, renew_before_days: u32) -> bool {
    match chrono::DateTime::parse_from_rfc3339(&meta.expires_at) {
        Err(_) => {
            // Cannot parse expiry - treat as needing renewal.
            true
        }
        Ok(expires_at) => {
            let now = chrono::Utc::now();
            let window = chrono::Duration::days(i64::from(renew_before_days));
            // Renew if expiry is within the renewal window.
            expires_at.signed_duration_since(now) <= window
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use cert_store::CertMeta;

    fn meta(expires_at: &str) -> CertMeta {
        CertMeta {
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: expires_at.into(),
            serial: "01".into(),
        }
    }

    #[test]
    fn test_needs_renewal_expired_cert() {
        // An already-expired certificate must trigger renewal.
        let m = meta("2020-01-01T00:00:00Z");
        assert!(
            cert_needs_renewal(&m, 30),
            "expired cert should need renewal"
        );
    }

    #[test]
    fn test_needs_renewal_within_window() {
        // 15 days left, threshold is 30 days -> renewal required.
        let expires = chrono::Utc::now() + chrono::Duration::days(15);
        let m = meta(&expires.to_rfc3339());
        assert!(
            cert_needs_renewal(&m, 30),
            "cert expiring in 15 days with 30-day window should need renewal"
        );
    }

    #[test]
    fn test_no_renewal_outside_window() {
        // 60 days left, threshold is 30 days -> no renewal needed.
        let expires = chrono::Utc::now() + chrono::Duration::days(60);
        let m = meta(&expires.to_rfc3339());
        assert!(
            !cert_needs_renewal(&m, 30),
            "cert expiring in 60 days with 30-day window should NOT need renewal"
        );
    }

    #[test]
    fn test_needs_renewal_bad_date() {
        // Unparseable date -> safe to re-issue.
        let m = meta("not-a-date");
        assert!(
            cert_needs_renewal(&m, 30),
            "bad date should trigger renewal"
        );
    }
}
