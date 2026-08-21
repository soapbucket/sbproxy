//! TLS, ACME auto-cert, and HTTP/3 support for sbproxy.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod acme;
pub mod alt_svc;
pub mod cert_bundle;
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
use cert_resolver::CertResolver;
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
    /// The single install path for shared certificate bundles (WOR-2634).
    installer: Arc<BundleInstaller>,
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
///
/// A *shared* backend that cannot be opened is an error for the same reason
/// and a larger one. See [`SHARED_CERT_BACKENDS`].
fn open_cert_backend(acme: Option<&sbproxy_config::AcmeConfig>) -> Result<Arc<dyn KVStore>> {
    use sbproxy_platform::storage::{RedbKVStore, SqliteKVStore};
    let Some(acme) = acme else {
        return Ok(Arc::new(MemoryKVStore::new(0)));
    };
    let backend_name = acme.storage_backend.as_str();
    let store: Arc<dyn KVStore> = match backend_name {
        "memory" => Arc::new(MemoryKVStore::new(0)),
        "redb" => {
            let dir = acme.storage_path.trim_end_matches('/');
            if let Err(e) = std::fs::create_dir_all(dir) {
                return cert_backend_open_failed(
                    backend_name,
                    &format!("cannot create storage dir {dir}: {e}"),
                );
            }
            let file = format!("{dir}/certstore.redb");
            match RedbKVStore::new(&file) {
                Ok(s) => {
                    info!(path = %file, "cert store backend: redb (persistent)");
                    Arc::new(s)
                }
                Err(e) => {
                    return cert_backend_open_failed(
                        backend_name,
                        &format!("opening {file} failed: {e}"),
                    )
                }
            }
        }
        "sqlite" => {
            // storage_path is a directory, matching `redb`, so an operator can
            // switch the two without also moving the path.
            let dir = acme.storage_path.trim_end_matches('/');
            if let Err(e) = std::fs::create_dir_all(dir) {
                return cert_backend_open_failed(
                    backend_name,
                    &format!("cannot create storage dir {dir}: {e}"),
                );
            }
            let file = format!("{dir}/certstore.sqlite");
            match SqliteKVStore::new(&file) {
                Ok(s) => {
                    info!(path = %file, "cert store backend: sqlite (persistent)");
                    Arc::new(s)
                }
                Err(e) => {
                    return cert_backend_open_failed(
                        backend_name,
                        &format!("opening {file} failed: {e}"),
                    )
                }
            }
        }
        "redis" => {
            // Connections open lazily. The distributed issuance lock
            // (SET NX PX) makes a fleet issue a cert once instead of
            // stampeding the CA (WOR-1774).
            let cfg = match sbproxy_platform::storage::RedisConfig::from_dsn(&acme.storage_path) {
                Ok(cfg) => cfg,
                // No `{e}`: the DSN is operator config and an operator can
                // write credentials into it, so the parser's message, which
                // quotes the input, does not reach the log (WOR-2640).
                Err(_) => {
                    return cert_backend_open_failed(
                        backend_name,
                        "the connection DSN in acme.storage_path is not valid Redis \
                         connection configuration",
                    )
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
                    return cert_backend_open_failed(
                        backend_name,
                        &format!("opening {} failed: {e}", acme.storage_path),
                    )
                }
            }
        }
        "s3" | "gcs" | "azure" => {
            // storage_path is an object-store URL (s3://bucket/prefix,
            // gs://bucket/prefix, az://...); credentials come from the
            // environment. The issuance lock uses the atomic conditional
            // create the object store provides (WOR-1775).
            // Origin only at both log sites: `storage_path` is operator
            // config and an operator can write credentials into it
            // (WOR-2640). The bucket is what identifies the backend.
            let store_origin = sbproxy_security::url_redact::redacted_url(&acme.storage_path);
            match crate::cert_object_store::ObjectStoreCertKv::from_url(&acme.storage_path) {
                Ok(s) => {
                    info!(url = %store_origin, backend = %acme.storage_backend,
                        "cert store backend: object storage (shared, cluster-safe)");
                    Arc::new(s)
                }
                Err(e) => {
                    return cert_backend_open_failed(
                        backend_name,
                        &format!("opening {store_origin} failed: {e}"),
                    )
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
    sbproxy_observe::metrics::set_cert_store_degraded(backend_name, false);
    Ok(store)
}

/// Certificate-store backends whose entire purpose is that every replica
/// reads and writes the same store.
///
/// Falling back to `MemoryKVStore` on one of these is not the persistence
/// downgrade the log line used to describe. `MemoryKVStore` overrides neither
/// `KVStore::try_lock` nor `KVStore::renew_lock`, so it inherits the
/// single-node trait defaults, both of which are an unconditional `Ok(true)`.
/// Every replica therefore wins its own issuance lease and its own fencing
/// generation: three pods open three ACME orders for the same hostname and
/// publish three HTTP-01 tokens to three stores no peer can read, so roughly
/// two thirds of the CA's validation fetches land on a pod that has never
/// seen the token, and the account burns through Let's Encrypt's limit of
/// five duplicate certificates per hostname set per week. Nothing in
/// `/metrics` told that apart from a CA outage.
///
/// The operator's `check_acme_storage_for_replicas` guard does not cover it
/// either: that guard reads the *configured* backend, and the configured
/// backend here is a shared one. What failed is opening it.
///
/// So a shared backend that cannot be opened refuses to start. The operator
/// asked for mutual exclusion across the fleet and cannot be given it, and a
/// pod that will not start is a far cheaper failure than a rate-limited
/// domain days later.
///
/// This is an allowlist of shared backends rather than a denylist of local
/// ones on purpose: a backend added to `open_cert_backend` later and
/// classified in neither list is caught by
/// `every_backend_is_classified_shared_or_pod_local`.
const SHARED_CERT_BACKENDS: [&str; 5] = ["file", "redis", "s3", "gcs", "azure"];

/// Certificate-store backends that live and die with a single process.
///
/// A failure to open one of these still degrades to in-memory, because a
/// single node has no peer to be mutually excluded from and refusing to serve
/// traffic over a cert store is a worse trade there. It is no longer silent:
/// the log is at `error!` and names the backend, and
/// `sbproxy_cert_store_degraded{backend}` goes to 1 so it can be alerted on.
/// The cost of the degradation is still real, which is that certificates are
/// re-issued on every restart.
const POD_LOCAL_CERT_BACKENDS: [&str; 3] = ["memory", "redb", "sqlite"];

/// Decide what a failure to open the configured certificate store means.
///
/// Shared backend: an `Err`, which `TlsState::init` propagates, so the
/// process refuses to start. Pod-local backend: an in-memory store, at
/// `error!` and with the degraded gauge set.
///
/// `detail` must not carry anything an operator could have written a secret
/// into. `acme.storage_path` is exactly that (a Redis DSN carries a password,
/// an object-store URL can carry a query credential), so callers pass either
/// a filesystem path, a redacted origin, or no path at all.
fn cert_backend_open_failed(backend: &str, detail: &str) -> Result<Arc<dyn KVStore>> {
    if SHARED_CERT_BACKENDS.contains(&backend) {
        return Err(anyhow::anyhow!(
            "acme.storage_backend '{backend}' is a shared certificate store and could \
             not be opened ({detail}). Refusing to start: an in-memory fallback would \
             give every replica its own issuance lease, so each one would open its own \
             ACME order for the same hostname and publish an HTTP-01 token no other \
             replica can read. Fix the backend, or set acme.storage_backend to a \
             pod-local one (redb, sqlite, memory) and run a single replica."
        ));
    }
    sbproxy_observe::metrics::set_cert_store_degraded(backend, true);
    error!(
        backend = %backend,
        detail = %detail,
        "cert store: the configured backend could not be opened; running on an \
         in-memory store, so certificates will NOT persist and will be re-issued on \
         every restart"
    );
    Ok(Arc::new(MemoryKVStore::new(0)))
}

// --- Fleet issuance lease timing (WOR-2633) ---
//
// The lease does not try to outlast a worst-case ACME order; the heartbeat
// does that. The TTL only has to cover the gap between two heartbeats plus
// scheduling noise, and be short enough that a crashed holder frees the
// fleet quickly.

/// Issuance lease TTL. A holder that stops renewing frees the host for a
/// peer after this long.
const ISSUE_LEASE_TTL_SECS: u64 = 120;
/// Heartbeat cadence while an order is in flight. One sixth of the TTL, so
/// several renewals can fail transiently before the lease is at risk.
const ISSUE_LEASE_RENEW_SECS: u64 = 20;
/// How long a renewal is allowed to keep failing before the holder fences
/// itself. Strictly inside the TTL: a peer can only take the lease over
/// once the TTL has fully elapsed since our last successful renewal, so a
/// holder that stops publishing at TTL minus one renewal period has stopped
/// before any successor can have started.
const ISSUE_LEASE_SAFETY_SECS: u64 = ISSUE_LEASE_TTL_SECS - ISSUE_LEASE_RENEW_SECS;
/// How many two-second waits a contender spends watching a peer's issuance
/// before giving up until the next renewal tick. Long enough to cover a
/// normal order, so a fresh follower installs the winner's certificate
/// within seconds of publication instead of at the next 12h tick.
const ISSUE_WAIT_ATTEMPTS: u32 = 90;
/// Pause between lease attempts while a peer holds it.
const ISSUE_WAIT_INTERVAL: Duration = Duration::from_secs(2);
/// Total time one renewal tick may spend waiting on peers, summed across
/// every hostname it visits.
///
/// [`ISSUE_WAIT_ATTEMPTS`] bounds one hostname's wait at 180 seconds, and
/// the tick walks hostnames serially, so without a shared budget a proxy
/// with forty hostnames could spend two hours inside a single tick: no
/// installs, no renewal decisions, nothing but sleeping on a lock a peer
/// holds. The budget is the tick's, not the hostname's. A hostname that
/// finds it exhausted gives up immediately and says so, and the tick moves
/// on; the next tick starts with a full budget and a different hostname
/// order of business.
const ISSUE_WAIT_TICK_BUDGET: Duration = Duration::from_secs(180);

/// How long this hostname may sleep before its next issuance-lease attempt,
/// given what is left of the tick's shared budget.
///
/// `None` means the tick has spent its budget: give up on this hostname
/// now rather than adding to a wait that is already too long.
fn issue_wait_pause(remaining: Duration) -> Option<Duration> {
    if remaining.is_zero() {
        return None;
    }
    Some(std::cmp::min(ISSUE_WAIT_INTERVAL, remaining))
}

/// How the bounded wait for one hostname's issuance lease ended.
enum LeaseWait {
    /// The lease is ours; issue under it.
    Acquired(cert_store::IssueLease),
    /// A peer published a certificate we could install while we waited.
    /// Nothing to issue, and nothing to complain about.
    PeerPublished,
    /// The backend could not be asked. Already logged at warn.
    Backend,
    /// Attempts or the tick's shared budget ran out with a peer still
    /// holding the lock.
    Exhausted {
        /// How long this hostname waited before giving up.
        waited: Duration,
    },
}

/// RAII release of the ACME per-host issuance lease (WOR-1774). Dropping
/// the guard releases the lease, so every exit from the issuance block (an
/// early `continue` on error, or normal completion) unlocks - a peer in a
/// fleet is never left waiting on a lock this node abandoned. Release keeps
/// the backend's fencing generation, so a released lease still fences.
struct IssueLeaseGuard<'a> {
    store: &'a CertStore,
    lease: cert_store::IssueLease,
}

impl Drop for IssueLeaseGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self
            .store
            .release_issue_lock(self.lease.hostname(), self.lease.token())
        {
            warn!(
                hostname = self.lease.hostname(),
                "failed to release ACME issuance lease: {e:#}"
            );
        }
    }
}

/// Heartbeat that keeps an issuance lease alive for the whole order
/// (WOR-2633).
///
/// A normal ACME flow can legitimately spend longer than any sensible TTL
/// in authorization and finalization polling, so the holder renews on a
/// cadence instead of gambling on a TTL that covers the worst case. Two
/// exits matter:
///
/// * the backend says the lease is no longer ours: the lease is marked
///   lost (renewal does that), so [`CertStore::put_cert_bundle_fenced`]
///   will refuse the order's result;
/// * renewals keep erroring past [`ISSUE_LEASE_SAFETY_SECS`]: the holder
///   cannot prove it still owns the lease, so it fences itself before any
///   peer could have taken over, rather than publishing on hope.
///
/// Dropping the guard aborts the task, so a finished or abandoned order
/// stops renewing on every exit path.
struct HeartbeatGuard {
    task: JoinHandle<()>,
}

impl HeartbeatGuard {
    fn spawn(store: Arc<CertStore>, lease: cert_store::IssueLease) -> Self {
        let task = maintenance_handle().spawn(async move {
            let mut last_ok = std::time::Instant::now();
            let mut ticker = tokio::time::interval(Duration::from_secs(ISSUE_LEASE_RENEW_SECS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // An interval's first tick is immediate; the lease was acquired
            // moments ago, so skip it.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                match store.renew_issue_lease(&lease, ISSUE_LEASE_TTL_SECS) {
                    Ok(true) => {
                        last_ok = std::time::Instant::now();
                    }
                    Ok(false) => {
                        // renew_issue_lease has already marked the lease
                        // lost; the publication path refuses it from here.
                        warn!(
                            hostname = lease.hostname(),
                            generation = lease.generation(),
                            "the ACME issuance lease was taken by a peer; this node's \
                             in-flight order will be discarded instead of published"
                        );
                        return;
                    }
                    Err(e) => {
                        warn!(
                            hostname = lease.hostname(),
                            "ACME issuance lease renewal error: {e:#}"
                        );
                        if last_ok.elapsed().as_secs() >= ISSUE_LEASE_SAFETY_SECS {
                            lease.mark_lost();
                            warn!(
                                hostname = lease.hostname(),
                                generation = lease.generation(),
                                "could not prove lease ownership within the safety deadline; \
                                 fencing this node's in-flight order"
                            );
                            return;
                        }
                    }
                }
            }
        });
        Self { task }
    }
}

impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The one place a shared certificate bundle enters the resolver (WOR-2634).
///
/// Initialization, ordinary renewal ticks, the lease-wait path, and the
/// post-publication path all install through here, so a valid bundle
/// observed anywhere is a bundle that gets served. The installed generation
/// per hostname makes an unchanged bundle a no-op and a regressed one (an
/// older generation appearing after a newer one) a refusal rather than a
/// downgrade.
struct BundleInstaller {
    resolver: Arc<CertResolver>,
    installed: std::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl BundleInstaller {
    fn new(resolver: Arc<CertResolver>) -> Self {
        Self {
            resolver,
            installed: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Read the published bundle for `hostname`, install it if it is new,
    /// and return the metadata renewal decisions should be made from.
    ///
    /// `None` means nothing trustworthy is published: either nothing is
    /// there, or what is there was refused (torn, corrupted, mismatched).
    /// Refusal keeps the last installed certificate serving; the caller's
    /// renewal path is what repairs the store.
    fn sync_from_store(&self, cert_store: &CertStore, hostname: &str) -> Option<CertMeta> {
        let bundle = match cert_store.get_cert_bundle(hostname) {
            Ok(Ok(Some(bundle))) => bundle,
            Ok(Ok(None)) => return None,
            Ok(Err(reason)) => {
                warn!(
                    hostname,
                    reason = reason.as_str(),
                    "published certificate bundle refused; keeping the last installed \
                     certificate and treating this host as needing issuance"
                );
                return None;
            }
            Err(e) => {
                warn!(
                    hostname,
                    "error reading the shared certificate store: {e:#}"
                );
                return None;
            }
        };

        // Poison recovery rather than a panic: the map only tracks which
        // generation is installed, and a poisoned map must not stop a valid
        // certificate from installing.
        let mut installed = match self.installed.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(have) = installed.get(hostname) {
            if *have == bundle.generation {
                return Some(bundle.meta);
            }
            if *have > bundle.generation {
                warn!(
                    hostname,
                    installed = *have,
                    published = bundle.generation,
                    "the published bundle generation went backwards; keeping the newer \
                     installed certificate"
                );
                return Some(bundle.meta);
            }
        }

        // A published bundle that is already expired is worth no more than
        // the bootstrap certificate it would replace; leave the resolver
        // alone and let the metadata drive re-issuance.
        if let Some(expires_at) = parse_cert_expiry(&bundle.cert_pem) {
            let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
                .map(|exp| exp.with_timezone(&chrono::Utc) <= chrono::Utc::now())
                .unwrap_or(false);
            if expired {
                warn!(
                    hostname,
                    generation = bundle.generation,
                    "published certificate bundle is already expired; not installing it"
                );
                return Some(bundle.meta);
            }
        }

        match self
            .resolver
            .set_cert(hostname, &bundle.cert_pem, &bundle.key_pem)
        {
            Ok(()) => {
                info!(
                    hostname,
                    generation = bundle.generation,
                    "installed the shared certificate bundle in the resolver"
                );
                installed.insert(hostname.to_string(), bundle.generation);
                Some(bundle.meta)
            }
            Err(e) => {
                error!(
                    hostname,
                    generation = bundle.generation,
                    "failed to install the shared certificate bundle: {e:#}"
                );
                None
            }
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
        //
        // WOR-2634: this goes through the same installer the renewal task
        // uses, so initialization is just the first of many syncs rather
        // than the only one. Certs register under the exact hostname only;
        // ACME certs are hostname-specific, not fallback.
        let installer = Arc::new(BundleInstaller::new(Arc::clone(&resolver)));
        if let Some(acme_cfg) = &config.acme {
            if acme_cfg.enabled {
                for hostname in &hostnames {
                    // A missing bundle is normal before first issuance; a
                    // refused one already warned inside the installer.
                    let _ = installer.sync_from_store(&cert_store, hostname);
                }
            }
        }

        Ok(Self {
            resolver,
            challenge_store,
            acme_config: config.acme.clone(),
            cert_store,
            installer,
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
        let installer = self.installer.clone();
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

                // One budget for the whole tick. Spent by whichever
                // hostnames find a peer holding their lock, in the order
                // they are visited, and refilled only by the next tick.
                let mut tick_budget = ISSUE_WAIT_TICK_BUDGET;

                for hostname in &hostnames {
                    // WOR-2634: install whatever the fleet's store publishes
                    // before deciding anything else. A tick that only reads
                    // metadata and continues is how two of three replicas
                    // serve the bootstrap certificate forever while the
                    // third serves the real one. The metadata driving the
                    // renewal decision comes from the same synced bundle, so
                    // it can never describe material this node is not
                    // actually able to serve.
                    let synced = installer.sync_from_store(&cert_store, hostname);
                    let needs_issuance = match &synced {
                        Some(meta) => {
                            if cert_needs_renewal(meta, acme_config.renew_before_days) {
                                info!(hostname, "certificate needs renewal");
                                true
                            } else {
                                false
                            }
                        }
                        None => {
                            info!(hostname, "no valid shared certificate, issuing via ACME");
                            true
                        }
                    };

                    if !needs_issuance {
                        continue;
                    }

                    // WOR-1774 serialized issuance across a fleet; WOR-2633
                    // made the hold a renewable, fenced lease. While a peer
                    // holds it, keep watching the shared store: the moment
                    // the peer publishes, install its bundle and stand down
                    // (WOR-2634) instead of waiting for a restart.
                    let mut waited = Duration::ZERO;
                    let mut outcome = LeaseWait::Exhausted { waited };
                    for attempt in 0..ISSUE_WAIT_ATTEMPTS {
                        match cert_store.acquire_issue_lease(hostname, ISSUE_LEASE_TTL_SECS) {
                            Ok(Some(acquired)) => {
                                outcome = LeaseWait::Acquired(acquired);
                                break;
                            }
                            Ok(None) => {
                                if attempt == 0 {
                                    info!(
                                        hostname,
                                        "ACME issuance lease held by a peer; waiting and \
                                         watching the shared store"
                                    );
                                }
                                // The budget belongs to the whole tick, so
                                // one contended hostname cannot spend the
                                // hours that forty of them would add up to.
                                let Some(pause) = issue_wait_pause(tick_budget) else {
                                    outcome = LeaseWait::Exhausted { waited };
                                    break;
                                };
                                tokio::time::sleep(pause).await;
                                tick_budget -= pause;
                                waited += pause;
                                outcome = LeaseWait::Exhausted { waited };
                                if let Some(meta) = installer.sync_from_store(&cert_store, hostname)
                                {
                                    if !cert_needs_renewal(&meta, acme_config.renew_before_days) {
                                        info!(
                                            hostname,
                                            "a peer published the certificate; installed it \
                                             without issuing"
                                        );
                                        outcome = LeaseWait::PeerPublished;
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(hostname, "ACME issuance lease error: {e:#}; skipping tick");
                                outcome = LeaseWait::Backend;
                                break;
                            }
                        }
                    }
                    let lease = match outcome {
                        LeaseWait::Acquired(lease) => lease,
                        LeaseWait::PeerPublished | LeaseWait::Backend => continue,
                        LeaseWait::Exhausted { waited } => {
                            // Restored from the pre-WOR-2634 loop, which
                            // said this and was dropped. A node that never
                            // wins the lock is otherwise completely silent:
                            // it serves the bootstrap certificate and
                            // nothing in the log says why.
                            info!(
                                hostname,
                                waited_secs = waited.as_secs(),
                                tick_budget_left_secs = tick_budget.as_secs(),
                                "did not acquire the ACME issuance lock; a peer is holding it \
                                 and published nothing we could install. Retrying next tick"
                            );
                            continue;
                        }
                    };
                    // Releases on every exit path below (Drop).
                    let _issue_lease = IssueLeaseGuard {
                        store: &cert_store,
                        lease: lease.clone(),
                    };

                    // Re-check under the lease: a peer may have issued while
                    // we waited, so we do not double-issue and burn CA
                    // quota. The sync also installs that peer's bundle.
                    if let Some(meta) = installer.sync_from_store(&cert_store, hostname) {
                        if !cert_needs_renewal(&meta, acme_config.renew_before_days) {
                            info!(
                                hostname,
                                "certificate already present after acquiring the lease; \
                                 skipping issuance"
                            );
                            continue;
                        }
                    }

                    // Keep the lease alive for however long the CA takes.
                    // Aborts when this scope ends, whatever the exit path.
                    let _heartbeat = HeartbeatGuard::spawn(Arc::clone(&cert_store), lease.clone());

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

                            // WOR-2633 and WOR-2635: publish the order's
                            // result as one fenced record. The store refuses
                            // it if the lease was lost or a newer holder
                            // already published, however convinced this node
                            // is that it won.
                            match cert_store
                                .put_cert_bundle_fenced(&lease, &cert_pem, &key_pem, &meta)
                            {
                                Ok(cert_store::PublishOutcome::Published { generation }) => {
                                    info!(
                                        hostname,
                                        generation, "ACME certificate published for the fleet"
                                    );
                                }
                                Ok(refused) => {
                                    warn!(
                                        hostname,
                                        outcome = refused.as_str(),
                                        generation = lease.generation(),
                                        "issued a certificate but the lease no longer \
                                         authorizes publication; discarding this order's \
                                         result in favor of the fleet's bundle"
                                    );
                                }
                                Err(e) => {
                                    error!(hostname, "failed to persist issued cert: {e:#}");
                                    continue;
                                }
                            }

                            // WOR-2634: install through the same path a
                            // follower uses, reading back what the store
                            // actually holds. On a refused publication this
                            // installs the winning peer's bundle rather than
                            // this node's discarded one.
                            let _ = installer.sync_from_store(&cert_store, hostname);
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
    fn one_renewal_tick_cannot_wait_for_hours_across_hostnames() {
        // ISSUE_WAIT_ATTEMPTS grew from 15 to 90, which is 180 seconds per
        // hostname, and the tick walks hostnames one at a time. Forty
        // hostnames all waiting on a peer's lock is two hours inside a
        // single tick: no installs, no renewal decisions, no log line
        // saying why. The budget belongs to the tick, so replay the tick's
        // arithmetic here and hold it to that.
        let mut budget = ISSUE_WAIT_TICK_BUDGET;
        let mut total = Duration::ZERO;
        let mut hostnames_that_gave_up_immediately = 0;
        for _hostname in 0..40 {
            let mut waited = Duration::ZERO;
            for _attempt in 0..ISSUE_WAIT_ATTEMPTS {
                let Some(pause) = issue_wait_pause(budget) else {
                    break;
                };
                budget -= pause;
                total += pause;
                waited += pause;
            }
            if waited.is_zero() {
                hostnames_that_gave_up_immediately += 1;
            }
        }
        assert_eq!(
            total, ISSUE_WAIT_TICK_BUDGET,
            "the whole tick must be bounded by one shared budget"
        );
        assert!(
            total <= Duration::from_secs(300),
            "a renewal tick that spends {total:?} waiting is a tick that does \
             nothing else for {total:?}"
        );
        assert!(
            hostnames_that_gave_up_immediately > 0,
            "a hostname reached once the budget is gone has to give up at once, \
             which is what the give-up log line reports"
        );
        // Per-hostname bound unchanged, so a single-hostname deployment
        // still waits out a normal order.
        assert!(
            ISSUE_WAIT_INTERVAL * ISSUE_WAIT_ATTEMPTS >= ISSUE_WAIT_TICK_BUDGET,
            "the tick budget is the binding constraint, not a second per-host cap"
        );
        assert_eq!(issue_wait_pause(Duration::ZERO), None);
        assert_eq!(
            issue_wait_pause(Duration::from_secs(1)),
            Some(Duration::from_secs(1)),
            "the last of the budget is spent, not overshot"
        );
        assert_eq!(
            issue_wait_pause(Duration::from_secs(30)),
            Some(ISSUE_WAIT_INTERVAL)
        );
    }

    #[test]
    fn an_unopenable_shared_cert_backend_refuses_to_start() {
        // The DSN is rejected by `RedisConfig::from_dsn` before any socket is
        // opened, so this stays offline. It used to log one warn and hand
        // back a MemoryKVStore, which overrides neither `try_lock` nor
        // `renew_lock` and so inherits the unconditional `Ok(true)` trait
        // defaults: every replica would win its own issuance lease, open its
        // own order for the same hostname, and publish an HTTP-01 token to a
        // store no peer can read. The operator's replica guard cannot catch
        // it either, because the *configured* backend is shared and it is the
        // open that failed.
        let sentinel = "rediss://default:sentinel-acme-password@sentinel-acme-host.invalid:6380/-1";
        let acme = acme_with_storage("redis", sentinel);

        // `Arc<dyn KVStore>` withholds `Debug`, so `expect_err` cannot name
        // the Ok value and this has to discard it first.
        let err = open_cert_backend(Some(&acme))
            .err()
            .expect("a shared backend that cannot be opened must refuse to start");

        let message = format!("{err:#}");
        assert!(message.contains("redis"), "{message}");
        assert!(message.contains("shared certificate store"), "{message}");
        assert!(
            !message.contains("sentinel-acme-password"),
            "the DSN carries a password and must never reach the message: {message}"
        );
    }

    #[test]
    fn an_unopenable_object_store_cert_backend_refuses_to_start() {
        // The other shared family, so the refusal is pinned as a property of
        // the classification rather than of one match arm.
        let acme = acme_with_storage("s3", "not-a-url");
        let err = open_cert_backend(Some(&acme))
            .err()
            .expect("an object-store backend that cannot be opened must refuse to start");
        assert!(format!("{err:#}").contains("shared certificate store"));
    }

    #[test]
    fn an_unopenable_pod_local_cert_backend_degrades_loudly_instead() {
        // A single node has no peer to be mutually excluded from, so this one
        // still falls back. What changed is that it is now visible: the gauge
        // says the process is not running the store it was configured with.
        //
        // A path that cannot be a directory forces the open to fail without
        // depending on filesystem permissions.
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let path = file.path().to_str().expect("utf-8 temp path").to_string();
        let acme = acme_with_storage("redb", &format!("{path}/certstore"));

        let backend = open_cert_backend(Some(&acme))
            .expect("a pod-local backend degrades rather than refusing to start");
        backend
            .put(b"certificate-key", b"certificate-value")
            .expect("the in-memory fallback is usable");

        let rendered = sbproxy_observe::metrics::metrics().render();
        assert!(
            rendered.contains("sbproxy_cert_store_degraded"),
            "the fallback has to be alertable, not one warn line at boot: {rendered}"
        );
        assert!(
            rendered.contains("sbproxy_cert_store_degraded{backend=\"redb\"} 1"),
            "{rendered}"
        );
    }

    #[test]
    fn every_backend_is_classified_shared_or_pod_local() {
        // `cert_backend_open_failed` decides refuse-versus-degrade by asking
        // whether the backend is in SHARED_CERT_BACKENDS. A backend added to
        // `open_cert_backend` later and left out of both lists would silently
        // take the degrade branch, which is the exact fail-open this change
        // removed. Keep the two lists exhaustive against the match arms.
        //
        // What this cannot see: an arm added to `open_cert_backend` whose
        // name is not also added here. It is a consistency check between two
        // lists in this file, not a parse of the match.
        let known = [
            "memory", "redb", "sqlite", "redis", "file", "s3", "gcs", "azure",
        ];
        for backend in known {
            let shared = SHARED_CERT_BACKENDS.contains(&backend);
            let pod_local = POD_LOCAL_CERT_BACKENDS.contains(&backend);
            assert!(
                shared ^ pod_local,
                "{backend} must be classified in exactly one of the two lists"
            );
        }
        assert_eq!(
            SHARED_CERT_BACKENDS.len() + POD_LOCAL_CERT_BACKENDS.len(),
            known.len(),
            "a backend in a list but not in `known` means this test stopped covering an arm"
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

    /// Publish a real bundle carrying the fixture metadata. `get_meta` reads
    /// through the published bundle since WOR-2635, so a standalone metadata
    /// row no longer counts as a certificate; these fixtures have to be
    /// certificates.
    fn publish_fixture(store: &CertStore, hostname: &str, meta: &CertMeta) {
        let (cert_pem, key_pem) = self_signed_pem(hostname);
        store
            .put_cert_bundle(hostname, &cert_pem, &key_pem, meta)
            .expect("publish fixture bundle");
    }

    #[test]
    fn acme_expiry_reader_returns_the_nearest_fixture_certificate() {
        let store = Arc::new(CertStore::new(Arc::new(MemoryKVStore::new(0))));
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        publish_fixture(
            &store,
            "later.example",
            &meta(&(now + chrono::Duration::days(20)).to_rfc3339()),
        );
        publish_fixture(
            &store,
            "near.example",
            &meta(&(now + chrono::Duration::days(6) + chrono::Duration::seconds(1)).to_rfc3339()),
        );

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
        publish_fixture(
            &store,
            "healthy.example",
            &meta(&(now + chrono::Duration::days(90)).to_rfc3339()),
        );
        publish_fixture(
            &store,
            "unreadable.example",
            &meta("not-an-rfc3339-timestamp"),
        );

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
        publish_fixture(
            &store,
            "healthy.example",
            &meta(&(now + chrono::Duration::days(90)).to_rfc3339()),
        );
        let reader = AcmeExpiryReader {
            cert_store: store,
            hostnames: Arc::from(["healthy.example".to_string(), "missing.example".to_string()]),
        };

        assert_eq!(reader.earliest_at(now), None);
    }

    // --- Shared bundle install path (WOR-2634, WOR-2635) ---

    fn served_der(resolver: &CertResolver, hostname: &str) -> Vec<u8> {
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

    #[test]
    fn a_refused_bundle_keeps_the_last_installed_certificate() {
        // WOR-2635 fail posture: published-but-untrustworthy is not the
        // same as absent. The resolver keeps serving the last good
        // generation, and the sync reports "needs issuance" so the renewal
        // path repairs the store.
        let backend: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let cs = CertStore::new(Arc::clone(&backend));
        let resolver = Arc::new(CertResolver::new());
        let installer = BundleInstaller::new(Arc::clone(&resolver));
        let host = "keeplast.example";

        let (cert_pem, key_pem) = self_signed_pem(host);
        cs.put_cert_bundle(host, &cert_pem, &key_pem, &meta("2027-01-01T00:00:00Z"))
            .expect("publish");
        let synced = installer.sync_from_store(&cs, host);
        assert!(synced.is_some(), "a valid bundle syncs");
        assert_eq!(served_der(&resolver, host), first_der(&cert_pem));

        // Tear the record where a crashed writer would have.
        backend
            .put(
                format!("acme:bundle:{host}").as_bytes(),
                b"{\"version\":1,\"gen",
            )
            .expect("write torn record");
        assert!(
            installer.sync_from_store(&cs, host).is_none(),
            "a torn record is a refusal, not a certificate"
        );
        assert_eq!(
            served_der(&resolver, host),
            first_der(&cert_pem),
            "the last good certificate must keep serving through a torn store"
        );
    }

    #[test]
    fn an_older_generation_never_replaces_a_newer_installed_one() {
        // WOR-2634: the installer moves forward only. A write that lands
        // out of order in the store must not downgrade a resolver that has
        // already installed a newer generation.
        let backend: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let cs = CertStore::new(Arc::clone(&backend));
        let resolver = Arc::new(CertResolver::new());
        let installer = BundleInstaller::new(Arc::clone(&resolver));
        let host = "monotonic.example";

        let (old_cert, old_key) = self_signed_pem(host);
        let (new_cert, new_key) = self_signed_pem(host);
        cs.put_cert_bundle(host, &old_cert, &old_key, &meta("2027-01-01T00:00:00Z"))
            .expect("publish generation 1");
        cs.put_cert_bundle(host, &new_cert, &new_key, &meta("2027-06-01T00:00:00Z"))
            .expect("publish generation 2");
        assert!(installer.sync_from_store(&cs, host).is_some());
        assert_eq!(served_der(&resolver, host), first_der(&new_cert));

        // Regress the store to generation 1 by hand.
        let regressed = crate::cert_bundle::CertBundle::new(
            host,
            1,
            &old_cert,
            &old_key,
            meta("2027-01-01T00:00:00Z"),
        )
        .expect("build older record")
        .encode()
        .expect("encode older record");
        backend
            .put(format!("acme:bundle:{host}").as_bytes(), &regressed)
            .expect("write older record");

        assert!(installer.sync_from_store(&cs, host).is_some());
        assert_eq!(
            served_der(&resolver, host),
            first_der(&new_cert),
            "an older published generation must not replace a newer installed one"
        );
    }
}
