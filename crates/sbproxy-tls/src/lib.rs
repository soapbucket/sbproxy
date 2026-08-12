//! TLS, ACME auto-cert, and HTTP/3 support for sbproxy.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod acme;
pub mod alt_svc;
pub mod cert_object_store;
pub mod cert_resolver;
pub mod cert_store;
pub mod challenges;
pub mod fingerprint;
pub mod h3_listener;
pub mod mtls;
pub mod ocsp;

pub use fingerprint::{compute_ja4h, parse_client_hello, TlsFingerprint};

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use acme::AcmeClient;
use cert_resolver::{load_certified_key, CertResolver};
use cert_store::{CertMeta, CertStore};
use challenges::Http01ChallengeStore;
use ocsp::OcspStapler;
use sbproxy_config::ProxyServerConfig;
use sbproxy_platform::{KVStore, MemoryKVStore};

/// A tokio runtime handle for the TLS maintenance tasks (OCSP refresh, ACME
/// renewal). These are started from the synchronous proxy-setup path, before
/// Pingora installs its own runtime, so there is usually no current runtime to
/// `tokio::spawn` on, which would panic. Reuse the caller's runtime when one is
/// present; otherwise fall back to a small process-lifetime runtime so the
/// long-running refresh loops keep being driven for the life of the process.
pub(crate) fn maintenance_handle() -> tokio::runtime::Handle {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle;
    }
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("sbproxy-tls-maint")
            .build()
            .expect("build sbproxy-tls maintenance runtime")
    })
    .handle()
    .clone()
}

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
    cert_store: Arc<CertStore>,
    /// Hostnames this proxy is responsible for.
    hostnames: Vec<String>,
    /// OCSP stapler for the manual fallback cert. `None` when no
    /// manual cert is configured or the cert lacks an AIA extension
    /// pointing at an OCSP responder; in either case the proxy
    /// serves TLS without stapling. Populated by [`Self::init`] and
    /// kicked off by [`Self::start_ocsp_refresh_task`] once a tokio
    /// runtime is available.
    ocsp_stapler: Option<Arc<OcspStapler>>,
    /// Manual cert PEM bytes, retained alongside the stapler so the
    /// refresh task can re-fetch the OCSP response for the same
    /// cert. Stored only when a manual cert was loaded; `None`
    /// otherwise.
    manual_cert_pem: Option<Vec<u8>>,
}

/// Earliest active ACME certificate expiry for alert evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeCertExpiry {
    /// Certificate hostname.
    pub hostname: String,
    /// Whole days remaining, rounded up so `30d 1s` does not report 30 days.
    pub days_remaining: u32,
}

/// Cloneable, read-only ACME certificate-expiry input seam.
///
/// The alert loop owns this lightweight reader instead of reaching through a
/// process global. Reads use the same persistent metadata store as renewal.
#[derive(Clone)]
pub struct AcmeExpiryReader {
    cert_store: Arc<CertStore>,
    hostnames: Arc<[String]>,
}

impl AcmeExpiryReader {
    /// Return the certificate with the earliest parseable expiry.
    pub fn earliest(&self) -> Option<AcmeCertExpiry> {
        self.earliest_at(chrono::Utc::now())
    }

    fn earliest_at(&self, now: chrono::DateTime<chrono::Utc>) -> Option<AcmeCertExpiry> {
        let mut expiries = Vec::with_capacity(self.hostnames.len());
        for hostname in self.hostnames.iter() {
            let meta = match self.cert_store.get_meta(hostname) {
                Ok(Some(meta)) => meta,
                Ok(None) => {
                    tracing::debug!(
                        %hostname,
                        "ACME expiry snapshot unavailable because certificate metadata is missing"
                    );
                    return None;
                }
                Err(error) => {
                    tracing::debug!(
                        %hostname,
                        %error,
                        "ACME expiry snapshot unavailable because certificate metadata could not be read"
                    );
                    return None;
                }
            };
            let expires_at = match chrono::DateTime::parse_from_rfc3339(&meta.expires_at) {
                Ok(expires_at) => expires_at.with_timezone(&chrono::Utc),
                Err(error) => {
                    tracing::debug!(
                        %hostname,
                        expires_at = %meta.expires_at,
                        %error,
                        "ACME expiry snapshot unavailable because certificate metadata is invalid"
                    );
                    return None;
                }
            };
            expiries.push((hostname.clone(), expires_at));
        }

        expiries
            .into_iter()
            .min_by_key(|(_, expires_at)| *expires_at)
            .map(|(hostname, expires_at)| {
                let seconds = expires_at.signed_duration_since(now).num_seconds();
                let days_remaining = if seconds <= 0 {
                    0
                } else {
                    seconds.saturating_add(86_399) / 86_400
                };
                AcmeCertExpiry {
                    hostname,
                    days_remaining: u32::try_from(days_remaining).unwrap_or(u32::MAX),
                }
            })
    }
}

/// Open the KVStore backing the ACME cert store and the HTTP-01 challenge
/// store, chosen by `acme.storage_backend` at `acme.storage_path` (WOR-1773).
///
/// `redb` (the default) and `sqlite` persist locally so a single node
/// survives a restart without re-issuing. The shared backends (`file` on
/// shared storage, `redis`, `s3`/`gcs`/`azure`) are what a fleet needs: they
/// carry the per-hostname issuance lease and, since WOR-2310, the published
/// HTTP-01 key authorization, so the replica the load balancer happens to
/// hand the CA's validation request to can answer it.
///
/// An unrecognized backend is an error rather than a silent downgrade to
/// in-memory. A downgrade looks like a working proxy that quietly re-issues
/// every certificate on every restart, which surfaces as a CA rate limit
/// days later instead of as a config mistake at boot.
/// `check_acme` in `sbproxy-config` rejects the same value at plan time so
/// the error normally arrives before the config is ever applied.
fn open_cert_backend(acme: Option<&sbproxy_config::AcmeConfig>) -> Result<Arc<dyn KVStore>> {
    use sbproxy_platform::storage::{RedbKVStore, SqliteKVStore};
    let Some(acme) = acme else {
        return Ok(Arc::new(MemoryKVStore::new(0)));
    };
    let store: Arc<dyn KVStore> = match acme.storage_backend.as_str() {
        "memory" => Arc::new(MemoryKVStore::new(0)),
        "redb" => {
            let dir = acme.storage_path.trim_end_matches('/');
            if let Err(e) = std::fs::create_dir_all(dir) {
                warn!(path = %dir, error = %e,
                    "cert store: cannot create storage dir; certs will NOT persist (in-memory fallback)");
                return Ok(Arc::new(MemoryKVStore::new(0)));
            }
            let file = format!("{dir}/certstore.redb");
            match RedbKVStore::new(&file) {
                Ok(s) => {
                    info!(path = %file, "cert store backend: redb (persistent)");
                    Arc::new(s)
                }
                Err(e) => {
                    warn!(path = %file, error = %e,
                        "cert store: redb open failed; certs will NOT persist (in-memory fallback)");
                    Arc::new(MemoryKVStore::new(0))
                }
            }
        }
        "sqlite" => {
            // storage_path is a directory, matching `redb`, so an operator can
            // switch the two without also moving the path.
            let dir = acme.storage_path.trim_end_matches('/');
            if let Err(e) = std::fs::create_dir_all(dir) {
                warn!(path = %dir, error = %e,
                    "cert store: cannot create storage dir; certs will NOT persist (in-memory fallback)");
                return Ok(Arc::new(MemoryKVStore::new(0)));
            }
            let file = format!("{dir}/certstore.sqlite");
            match SqliteKVStore::new(&file) {
                Ok(s) => {
                    info!(path = %file, "cert store backend: sqlite (persistent)");
                    Arc::new(s)
                }
                Err(e) => {
                    warn!(path = %file, error = %e,
                        "cert store: sqlite open failed; certs will NOT persist (in-memory fallback)");
                    Arc::new(MemoryKVStore::new(0))
                }
            }
        }
        "redis" => {
            // Connections open lazily. The distributed issuance lock
            // (SET NX PX) makes a fleet issue a cert once instead of
            // stampeding the CA (WOR-1774).
            let cfg = match sbproxy_platform::storage::RedisConfig::from_dsn(&acme.storage_path) {
                Ok(cfg) => cfg,
                Err(_) => {
                    warn!(
                        "cert store: invalid Redis connection configuration; certs will NOT persist (in-memory fallback)"
                    );
                    return Ok(Arc::new(MemoryKVStore::new(0)));
                }
            };
            info!("cert store backend: redis (shared, cluster-safe)");
            Arc::new(sbproxy_platform::storage::RedisKVStore::new(cfg))
        }
        "file" => {
            // storage_path is a directory; on a shared filesystem (NFS/EFS)
            // this gives a fleet a shared cert store, with a cross-node
            // issuance lock via atomic lock files (WOR-1776).
            match sbproxy_platform::storage::FileKVStore::new(&acme.storage_path) {
                Ok(s) => {
                    info!(path = %acme.storage_path, "cert store backend: file (shared filesystem)");
                    Arc::new(s)
                }
                Err(e) => {
                    warn!(path = %acme.storage_path, error = %e,
                        "cert store: file backend open failed; certs will NOT persist (in-memory fallback)");
                    Arc::new(MemoryKVStore::new(0))
                }
            }
        }
        "s3" | "gcs" | "azure" => {
            // storage_path is an object-store URL (s3://bucket/prefix,
            // gs://bucket/prefix, az://...); credentials come from the
            // environment. The issuance lock uses the atomic conditional
            // create the object store provides (WOR-1775).
            match crate::cert_object_store::ObjectStoreCertKv::from_url(&acme.storage_path) {
                Ok(s) => {
                    info!(url = %acme.storage_path, backend = %acme.storage_backend,
                        "cert store backend: object storage (shared, cluster-safe)");
                    Arc::new(s)
                }
                Err(e) => {
                    warn!(url = %acme.storage_path, error = %e,
                        "cert store: object-store backend open failed; certs will NOT persist (in-memory fallback)");
                    Arc::new(MemoryKVStore::new(0))
                }
            }
        }
        other => {
            return Err(anyhow::anyhow!(
                "acme.storage_backend '{other}' is not a certificate store backend sbproxy \
                 knows how to open (use redb, sqlite, file, redis, s3, gcs, azure, or memory)"
            ));
        }
    };
    Ok(store)
}

/// RAII release of the ACME per-host issuance lock (WOR-1774). Dropping
/// the guard releases the lease, so every exit from the issuance block (an
/// early `continue` on error, or normal completion) unlocks - a peer in a
/// fleet is never left waiting on a lock this node abandoned.
struct IssueLockGuard<'a> {
    store: &'a CertStore,
    hostname: &'a str,
    token: Vec<u8>,
}

impl Drop for IssueLockGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.store.release_issue_lock(self.hostname, &self.token) {
            warn!(
                hostname = self.hostname,
                "failed to release ACME issuance lock: {e:#}"
            );
        }
    }
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
        // One backend, two stores. The HTTP-01 challenge has to be readable
        // by whichever replica the load balancer hands the CA's validation
        // request to, and that is the same reachability requirement the cert
        // itself has, so it gets the same backing store rather than a second
        // one an operator would have to configure separately (WOR-2310).
        let backend = open_cert_backend(config.acme.as_ref())?;
        let challenge_store = Arc::new(Http01ChallengeStore::with_store(Arc::clone(&backend)));
        let cert_store = Arc::new(CertStore::new(backend));

        // --- Manual cert files ---
        let mut ocsp_stapler: Option<Arc<OcspStapler>> = None;
        let mut manual_cert_pem: Option<Vec<u8>> = None;
        if let (Some(cert_path), Some(key_path)) = (&config.tls_cert_file, &config.tls_key_file) {
            let cert_bytes = std::fs::read(cert_path)
                .with_context(|| format!("reading TLS cert: {cert_path}"))?;
            let key_bytes =
                std::fs::read(key_path).with_context(|| format!("reading TLS key: {key_path}"))?;
            match cert_resolver::load_certified_key(&cert_bytes, &key_bytes) {
                Ok(ck) => {
                    resolver.set_fallback(ck);
                    info!(cert = %cert_path, "loaded manual TLS certificate as fallback");
                    // Stash the cert PEM and a stapler instance so
                    // start_ocsp_refresh_task can wire them up once a
                    // tokio runtime is available. We do not fetch the
                    // OCSP response here because TlsState::init runs
                    // before any runtime is spun up.
                    ocsp_stapler = Some(Arc::new(OcspStapler::new()));
                    manual_cert_pem = Some(cert_bytes);
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
            ocsp_stapler,
            manual_cert_pem,
        })
    }

    /// Build a read-only expiry source when ACME is enabled.
    pub fn acme_expiry_reader(&self) -> Option<AcmeExpiryReader> {
        self.acme_config
            .as_ref()
            .is_some_and(|config| config.enabled)
            .then(|| AcmeExpiryReader {
                cert_store: Arc::clone(&self.cert_store),
                hostnames: Arc::from(self.hostnames.clone()),
            })
    }

    /// Spawn the OCSP refresh task for the manual fallback cert.
    ///
    /// No-op when no manual cert was loaded. The task does an
    /// initial OCSP fetch immediately, then refreshes every 12
    /// hours; on every successful fetch it calls
    /// [`CertResolver::update_fallback_ocsp`] so subsequent
    /// handshakes staple the fresh response.
    ///
    /// Must be called from a tokio runtime. The Pingora server
    /// installs its own runtime before any service starts, so this
    /// is invoked from the proxy's startup hook.
    ///
    /// # What stapling covers, said out loud (WOR-2310)
    ///
    /// Stapling covers exactly one certificate: the manual fallback.
    /// `update_fallback_ocsp` writes one slot, and no SNI entry, which
    /// is where every ACME-issued certificate lives, is ever written.
    /// Both paths below log how many certificates the resolver serves
    /// and how many of those stapling can reach, because the failure
    /// mode this closes is silence: nothing errors, nothing warns, and
    /// an operator who turned on HTTPS and read a clean log has no way
    /// to tell a stapled deployment from an unstapled one until a TLS
    /// scanner tells them.
    pub fn start_ocsp_refresh_task(&self) {
        let served = self.resolver.served_cert_count();
        let stapled = self.resolver.stapled_cert_count();

        let (Some(stapler), Some(cert_pem)) =
            (self.ocsp_stapler.as_ref(), self.manual_cert_pem.as_ref())
        else {
            info!(
                served,
                stapled,
                covered = 0,
                "OCSP stapling is inactive: it reaches the manual fallback certificate \
                 only, and no proxy.tls_cert_file is configured. Every certificate this \
                 proxy serves, including every ACME-issued one, is served without a \
                 stapled response."
            );
            return;
        };

        let resolver = self.resolver.clone();
        stapler.start_refresh_task("_fallback".to_string(), cert_pem.clone(), move |bytes| {
            resolver.update_fallback_ocsp(bytes);
        });
        info!(
            served,
            stapled,
            covered = 1,
            "OCSP refresh task started for the manual fallback certificate. Stapling \
             reaches that certificate only; SNI-selected and ACME-issued certificates \
             are served without a stapled response."
        );
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

        maintenance_handle().spawn(async move {
            // 12h renewal cadence. tokio's interval fires its first tick
            // immediately, and we deliberately DO NOT skip it: a
            // freshly-deployed domain with no cached cert must be issued at
            // startup, not after the first 12h period (otherwise the
            // listener serves the self-signed bootstrap cert for 12h). The
            // per-hostname pass only logs when a cert is actually missing or
            // due for renewal, so the immediate first tick is not noisy.
            let mut interval = tokio::time::interval(Duration::from_secs(12 * 3600));

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

                    // WOR-1774: serialize issuance across a fleet. Acquire a
                    // per-host lock - an atomic lease on a shared backend
                    // (redis), a no-op on a local one. Wait briefly for a peer
                    // that is mid-issue, long enough to cover a typical ACME
                    // order, so the loser reads the peer's cert rather than
                    // racing the CA.
                    let mut token = [0u8; 16];
                    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token)
                        .is_err()
                    {
                        error!(hostname, "failed to generate issuance lock token; skipping");
                        continue;
                    }
                    let mut acquired = false;
                    for attempt in 0..15 {
                        match cert_store.try_issue_lock(hostname, &token, 120) {
                            Ok(true) => {
                                acquired = true;
                                break;
                            }
                            Ok(false) => {
                                if attempt == 0 {
                                    info!(hostname, "ACME issuance lock held by a peer; waiting");
                                }
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                            Err(e) => {
                                warn!(hostname, "ACME issuance lock error: {e:#}; skipping tick");
                                break;
                            }
                        }
                    }
                    if !acquired {
                        info!(hostname, "did not acquire ACME issuance lock; retrying next tick");
                        continue;
                    }
                    // Releases on every exit path below (Drop).
                    let _issue_lock = IssueLockGuard {
                        store: &cert_store,
                        hostname: hostname.as_str(),
                        token: token.to_vec(),
                    };

                    // Re-check under the lock: a peer may have issued while we
                    // waited, so we do not double-issue and burn CA quota.
                    if let Ok(Some(ref meta)) = cert_store.get_meta(hostname) {
                        if !cert_needs_renewal(meta, acme_config.renew_before_days) {
                            info!(
                                hostname,
                                "certificate already present after acquiring lock; skipping issuance"
                            );
                            continue;
                        }
                    }

                    // --- Issue or renew certificate via ACME ---
                    // `ca_root` trusts a private or test CA for the
                    // directory endpoint (Caddy's `acme_ca_root`). Read
                    // here rather than cached, because issuance is rare
                    // and a rotated test CA should not need a restart.
                    let ca_root = match acme_config.ca_root.as_deref() {
                        Some(path) => match std::fs::read(path) {
                            Ok(bytes) => Some(bytes),
                            Err(e) => {
                                error!(
                                    hostname,
                                    path,
                                    "acme.ca_root could not be read: {e}. Refusing to fall back \
                                     to system roots, which would silently restore the \
                                     verification failure this setting exists to fix."
                                );
                                continue;
                            }
                        },
                        None => None,
                    };
                    let mut acme_client = match AcmeClient::with_ca_root(
                        &acme_config.directory_url,
                        &acme_config.email,
                        acme_config.challenge_types.clone(),
                        ca_root.as_deref(),
                    ) {
                        Ok(client) => client,
                        Err(e) => {
                            error!(hostname, "failed to build the ACME client: {e:#}");
                            continue;
                        }
                    };

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

    /// Install a self-signed fallback cert on the resolver (WOR-1772).
    ///
    /// With the forked Pingora listener reading the dynamic `CertResolver`,
    /// the ACME cert installed by the renewal task is served live via SNI. But
    /// before the first issue (and for SNI misses), the resolver needs a
    /// fallback so `:443` still completes a handshake. This installs a
    /// self-signed cert for the primary hostname as that fallback. ACME-only
    /// mode has no manual cert, so there is nothing to clobber; calling this on
    /// every (re)start is idempotent.
    pub fn install_self_signed_fallback(&self) -> Result<()> {
        let hostname = self
            .hostnames
            .first()
            .map(|s| s.as_str())
            .unwrap_or("localhost");
        let key_pair = rcgen::KeyPair::generate().context("generating fallback key pair")?;
        let params = rcgen::CertificateParams::new(vec![hostname.to_string()])
            .context("creating fallback cert params")?;
        let cert = params
            .self_signed(&key_pair)
            .context("self-signing fallback cert")?;
        let ck = cert_resolver::load_certified_key(
            cert.pem().as_bytes(),
            key_pair.serialize_pem().as_bytes(),
        )
        .context("loading self-signed fallback cert")?;
        self.resolver.set_fallback(ck);
        info!(
            hostname,
            "installed self-signed fallback cert for the ACME bootstrap window"
        );
        Ok(())
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

        // WOR-2199: same interface as the TCP listeners. Enabling HTTP/3
        // is rejected at config load today, so this path does not run,
        // which is exactly why it is worth fixing now: a listener that
        // ignored proxy.bind_address would reopen the restriction the
        // operator asked for on the day someone turns the feature on.
        let bind_addr: std::net::SocketAddr =
            format!("{}:{https_port}", config.effective_bind_address())
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

    fn acme_with_storage(backend: &str, path: &str) -> sbproxy_config::AcmeConfig {
        sbproxy_config::AcmeConfig {
            enabled: true,
            email: "operator@example.com".to_string(),
            directory_url: "https://acme.invalid/directory".to_string(),
            challenge_types: vec!["http-01".to_string()],
            storage_backend: backend.to_string(),
            storage_path: path.to_string(),
            renew_before_days: 30,
            ca_root: None,
        }
    }

    #[test]
    fn redis_cert_backend_rejects_invalid_full_dsn_without_network_io() {
        let sentinel = "rediss://default:sentinel-acme-password@sentinel-acme-host.invalid:6380/-1";
        let acme = acme_with_storage("redis", sentinel);

        let backend = open_cert_backend(Some(&acme)).expect("a known backend opens");

        backend
            .put(b"certificate-key", b"certificate-value")
            .expect("invalid Redis config must retain the in-memory fallback posture");
        assert_eq!(
            backend
                .get(b"certificate-key")
                .expect("read fallback certificate state")
                .as_deref(),
            Some(b"certificate-value".as_slice())
        );
    }

    #[test]
    fn sqlite_cert_backend_persists_across_reopen() {
        // `sqlite` was advertised in the config rustdoc with no arm here, so
        // it fell through to the in-memory fallback: the proxy looked healthy
        // and silently re-issued every certificate on every restart until the
        // CA rate-limited the domain. Pin that it now actually persists.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_str().expect("utf-8 temp path").to_string();
        let acme = acme_with_storage("sqlite", &path);

        {
            let backend = open_cert_backend(Some(&acme)).expect("sqlite is a known backend");
            backend
                .put(b"acme:cert:example.com", b"CERTPEM")
                .expect("write a cert through the sqlite backend");
        } // dropped: simulates a process restart

        let reopened = open_cert_backend(Some(&acme)).expect("sqlite reopens the same database");
        assert_eq!(
            reopened
                .get(b"acme:cert:example.com")
                .expect("read the cert back")
                .as_deref(),
            Some(b"CERTPEM".as_slice()),
            "a sqlite cert store must survive a restart instead of re-issuing"
        );
    }

    #[test]
    fn an_unrecognized_storage_backend_is_an_error_not_an_in_memory_downgrade() {
        let acme = acme_with_storage("postgres", "/var/lib/sbproxy/certs");

        // `Arc<dyn KVStore>` withholds `Debug`, so `expect_err` cannot
        // name the Ok value and this has to discard it first.
        let err = open_cert_backend(Some(&acme))
            .err()
            .expect("an unknown backend must not degrade to in-memory");

        let message = format!("{err:#}");
        assert!(message.contains("postgres"), "{message}");
        assert!(message.contains("acme.storage_backend"), "{message}");
    }

    #[test]
    fn tls_init_gives_the_challenge_store_the_cert_store_backend() {
        // The wiring this whole fix rests on: the challenge published by the
        // replica that won the issuance lease has to be readable by a replica
        // that never called `set`. `file` on a shared directory stands in for
        // the fleet here because two handles can hold it open at once.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_str().expect("utf-8 temp path").to_string();
        let acme = acme_with_storage("file", &path);
        let config = ProxyServerConfig {
            https_bind_port: Some(8443),
            acme: Some(acme.clone()),
            ..Default::default()
        };

        let issuer = TlsState::init(&config, vec!["example.com".to_string()])
            .expect("TLS state initializes with a file-backed cert store");
        issuer
            .challenge_store
            .set("tok-fleet", "tok-fleet.thumbprint", None)
            .expect("publish the challenge to the shared backend");

        let peer = Http01ChallengeStore::with_store(
            open_cert_backend(Some(&acme)).expect("file is a known backend"),
        );
        assert_eq!(
            peer.get("tok-fleet").as_deref(),
            Some("tok-fleet.thumbprint"),
            "a peer replica reading the same cert store must answer the challenge"
        );
    }

    // Regression: the OCSP refresh task and the maintenance handle are started
    // from the synchronous proxy-setup path, before Pingora installs a runtime.
    // A bare `tokio::spawn` there panics with "there is no reactor running",
    // which made every TLS config with a manual cert crash on startup. These
    // tests run as plain `#[test]` (no `#[tokio::test]`), so there is no current
    // runtime, reproducing that context.

    #[test]
    fn maintenance_handle_runs_a_task_without_a_current_runtime() {
        let (tx, rx) = std::sync::mpsc::channel();
        maintenance_handle().spawn(async move {
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("task spawned on the maintenance handle ran to completion");
    }

    // --- OCSP coverage boundary (WOR-2310) ---

    fn self_signed_pem(san: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("generate a test key pair");
        let params =
            rcgen::CertificateParams::new(vec![san.to_string()]).expect("test cert params");
        let cert = params.self_signed(&key).expect("self-sign the test cert");
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    #[test]
    fn acme_only_tls_serves_certificates_that_stapling_never_reaches() {
        // The WOR-2310 claim at the TlsState level. With no
        // `proxy.tls_cert_file` there is no stapler at all, so
        // `start_ocsp_refresh_task` has nothing to start however many
        // certificates the resolver is serving. The point is not that
        // the call is a no-op; it is that a no-op here means every
        // served certificate goes out unstapled, and the startup line
        // this test guards is the only place that says so.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_str().expect("utf-8 temp path").to_string();
        let config = ProxyServerConfig {
            https_bind_port: Some(8443),
            acme: Some(acme_with_storage("file", &path)),
            ..Default::default()
        };
        let tls = TlsState::init(&config, vec!["example.com".to_string()])
            .expect("TLS state initializes without a manual certificate");

        tls.install_self_signed_fallback()
            .expect("the ACME bootstrap fallback installs");
        for host in ["one.example", "two.example"] {
            let (cert_pem, key_pem) = self_signed_pem(host);
            tls.resolver
                .set_cert(host, &cert_pem, &key_pem)
                .expect("an issued certificate registers under its hostname");
        }

        assert_eq!(
            tls.resolver.served_cert_count(),
            3,
            "two SNI entries plus the bootstrap fallback"
        );

        tls.start_ocsp_refresh_task();

        assert_eq!(
            tls.resolver.stapled_cert_count(),
            0,
            "with no manual certificate nothing is stapled, not even the fallback"
        );
    }

    #[test]
    fn ocsp_refresh_task_does_not_panic_outside_a_runtime() {
        // Before the fix this panicked at the `tokio::spawn` inside
        // `start_refresh_task`. The bogus cert makes the initial fetch fail,
        // which the task handles gracefully; the point is that it spawns and
        // runs without a current runtime instead of bringing the process down.
        let stapler = ocsp::OcspStapler::new();
        stapler.start_refresh_task("_test".to_string(), b"not-a-real-cert".to_vec(), |_| {});
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

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

    #[test]
    fn acme_expiry_reader_returns_the_nearest_fixture_certificate() {
        let store = Arc::new(CertStore::new(Arc::new(MemoryKVStore::new(0))));
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .put_meta(
                "later.example",
                &meta(&(now + chrono::Duration::days(20)).to_rfc3339()),
            )
            .unwrap();
        store
            .put_meta(
                "near.example",
                &meta(
                    &(now + chrono::Duration::days(6) + chrono::Duration::seconds(1)).to_rfc3339(),
                ),
            )
            .unwrap();

        let reader = AcmeExpiryReader {
            cert_store: store,
            hostnames: Arc::from(["later.example".to_string(), "near.example".to_string()]),
        };
        let expiry = reader.earliest_at(now).unwrap();
        assert_eq!(expiry.hostname, "near.example");
        assert_eq!(expiry.days_remaining, 7);
    }

    #[test]
    fn acme_expiry_reader_rejects_a_partial_snapshot_with_invalid_metadata() {
        let store = Arc::new(CertStore::new(Arc::new(MemoryKVStore::new(0))));
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .put_meta(
                "healthy.example",
                &meta(&(now + chrono::Duration::days(90)).to_rfc3339()),
            )
            .unwrap();
        store
            .put_meta("unreadable.example", &meta("not-an-rfc3339-timestamp"))
            .unwrap();

        let reader = AcmeExpiryReader {
            cert_store: store,
            hostnames: Arc::from([
                "healthy.example".to_string(),
                "unreadable.example".to_string(),
            ]),
        };

        assert_eq!(reader.earliest_at(now), None);
    }

    #[test]
    fn acme_expiry_reader_rejects_a_partial_snapshot_with_missing_metadata() {
        let store = Arc::new(CertStore::new(Arc::new(MemoryKVStore::new(0))));
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        store
            .put_meta(
                "healthy.example",
                &meta(&(now + chrono::Duration::days(90)).to_rfc3339()),
            )
            .unwrap();
        let reader = AcmeExpiryReader {
            cert_store: store,
            hostnames: Arc::from(["healthy.example".to_string(), "missing.example".to_string()]),
        };

        assert_eq!(reader.earliest_at(now), None);
    }
}
