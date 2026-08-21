//! Certificate persistence via KVStore trait.

use anyhow::Result;
use sbproxy_platform::KVStore;
use serde::{Deserialize, Serialize};

use crate::cert_bundle::{BundleReject, CertBundle};

// --- Key helpers ---

const ACCOUNT_KEY: &[u8] = b"acme:account_key";
const CERT_PREFIX: &str = "acme:cert:";
const KEY_PREFIX: &str = "acme:key:";
const META_PREFIX: &str = "acme:meta:";

fn cert_key(hostname: &str) -> String {
    format!("{}{}", CERT_PREFIX, hostname)
}

fn key_key(hostname: &str) -> String {
    format!("{}{}", KEY_PREFIX, hostname)
}

fn meta_key(hostname: &str) -> String {
    format!("{}{}", META_PREFIX, hostname)
}

const BUNDLE_PREFIX: &str = "acme:bundle:";

fn bundle_key(hostname: &str) -> String {
    format!("{}{}", BUNDLE_PREFIX, hostname)
}

const LOCK_PREFIX: &str = "acme:lock:";

fn lock_key(hostname: &str) -> String {
    format!("{}{}", LOCK_PREFIX, hostname)
}

// --- CertMeta ---

/// Metadata associated with a stored certificate.
///
/// Every field here is covered by the certificate bundle's integrity
/// digest, and `cert_bundle::digest_of` destructures this struct so that
/// adding a field is a compile error there until the digest covers it too.
/// Do not make this `#[non_exhaustive]` without replacing that binding with
/// something equally load bearing: a field outside the digest is a field
/// the record verifies while it says anything at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertMeta {
    /// RFC 3339 timestamp when the certificate was issued.
    pub issued_at: String,
    /// RFC 3339 timestamp when the certificate expires.
    pub expires_at: String,
    /// Certificate serial number string.
    pub serial: String,
}

// --- CertStore ---

/// KVStore adapter for ACME certificate persistence.
pub struct CertStore {
    store: std::sync::Arc<dyn KVStore>,
}

impl CertStore {
    /// Create a new CertStore over any [`KVStore`] backend (WOR-1773).
    ///
    /// The backend is a trait object so an operator can persist certs to
    /// redb (local, default), sqlite, or a shared store (redis) for a
    /// fleet, chosen by `acme.storage_backend`, without changing this type.
    pub fn new(store: std::sync::Arc<dyn KVStore>) -> Self {
        Self { store }
    }

    // --- Account key ---

    /// Persist the ACME account private key PEM bytes.
    pub fn put_account_key(&self, key_pem: &[u8]) -> Result<()> {
        self.store.put(ACCOUNT_KEY, key_pem)
    }

    /// Retrieve the ACME account private key PEM bytes, if present.
    pub fn get_account_key(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.store.get(ACCOUNT_KEY)?.map(|b| b.to_vec()))
    }

    // --- Certificate ---

    /// Persist the certificate PEM for a hostname.
    pub fn put_cert(&self, hostname: &str, cert_pem: &[u8]) -> Result<()> {
        self.store.put(cert_key(hostname).as_bytes(), cert_pem)
    }

    /// Retrieve the certificate PEM for a hostname, if present.
    pub fn get_cert(&self, hostname: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .get(cert_key(hostname).as_bytes())?
            .map(|b| b.to_vec()))
    }

    // --- Private key ---

    /// Persist the private key PEM for a hostname.
    pub fn put_key(&self, hostname: &str, key_pem: &[u8]) -> Result<()> {
        self.store.put(key_key(hostname).as_bytes(), key_pem)
    }

    /// Retrieve the private key PEM for a hostname, if present.
    pub fn get_key(&self, hostname: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .store
            .get(key_key(hostname).as_bytes())?
            .map(|b| b.to_vec()))
    }

    // --- Metadata ---

    /// Persist JSON-encoded [`CertMeta`] for a hostname under the legacy
    /// standalone key.
    ///
    /// Kept for tests and for reading tools that predate WOR-2635. The
    /// publication path does not use it: metadata now travels inside the
    /// bundle record so it cannot describe a generation the store does not
    /// have.
    // WOR-2635: no production caller remains. The fenced single-record
    // publish replaced this; the only callers left are the tests that
    // stage a legacy record to prove migration still reads one. Gating it
    // to test builds is what stops an unfenced write path from being
    // reachable again, which is the whole point of the fencing work.
    #[cfg(test)]
    pub(crate) fn put_meta(&self, hostname: &str, meta: &CertMeta) -> Result<()> {
        let json = serde_json::to_vec(meta)?;
        self.store.put(meta_key(hostname).as_bytes(), &json)?;
        stamp_expiry_metric(hostname, meta);
        Ok(())
    }

    /// Retrieve the metadata for the certificate a reader could actually
    /// serve, if any.
    ///
    /// This reads through the published bundle rather than a standalone
    /// metadata key (WOR-2635). Renewal decisions are made from this value,
    /// and metadata that describes material the store cannot produce is how
    /// a node concludes "a peer has this covered" about a certificate that
    /// does not exist.
    pub fn get_meta(&self, hostname: &str) -> Result<Option<CertMeta>> {
        match self.get_cert_bundle(hostname)? {
            Ok(Some(bundle)) => Ok(Some(bundle.meta)),
            Ok(None) => Ok(None),
            Err(reason) => {
                tracing::warn!(
                    hostname = %hostname,
                    reason = %reason,
                    "stored certificate bundle refused; treating this host as having no certificate"
                );
                Ok(None)
            }
        }
    }

    // --- Composite helpers ---

    /// Return all hostnames that have a stored certificate.
    ///
    /// Scans both the bundle records and the pre-WOR-2635 certificate keys,
    /// so an operator upgrading in place does not lose sight of a host whose
    /// bundle has not been republished yet.
    pub fn list_hostnames(&self) -> Result<Vec<String>> {
        let mut hostnames = Vec::new();
        for (prefix, pairs) in [
            (
                BUNDLE_PREFIX,
                self.store.scan_prefix(BUNDLE_PREFIX.as_bytes())?,
            ),
            (CERT_PREFIX, self.store.scan_prefix(CERT_PREFIX.as_bytes())?),
        ] {
            for (key, _) in pairs {
                let hostname = std::str::from_utf8(&key[prefix.len()..])?.to_owned();
                if !hostnames.contains(&hostname) {
                    hostnames.push(hostname);
                }
            }
        }
        Ok(hostnames)
    }

    /// Read the published bundle for `hostname`, fully validated.
    ///
    /// `Ok(None)` means nothing is published. `Err(BundleReject)` means
    /// something is published and cannot be trusted, which is a different
    /// answer and deserves a different response: a caller keeps serving its
    /// last good certificate and says so, rather than treating unreadable
    /// material as an absent certificate and issuing over the top of it.
    pub fn get_cert_bundle(
        &self,
        hostname: &str,
    ) -> Result<std::result::Result<Option<CertBundle>, BundleReject>> {
        if let Some(bytes) = self.store.get(bundle_key(hostname).as_bytes())? {
            return Ok(CertBundle::decode(&bytes, hostname).map(Some));
        }
        // Pre-WOR-2635 three-key state. It is adopted as generation zero
        // only once the certificate and key prove to be a pair; a torn row
        // is quarantined as a rejection rather than migrated forward.
        let (Some(cert_pem), Some(key_pem), Some(meta)) = (
            self.get_cert(hostname)?,
            self.get_key(hostname)?,
            self.get_meta_raw(hostname)?,
        ) else {
            return Ok(Ok(None));
        };
        // Both halves have to parse AND belong to each other. Parsing
        // alone proves nothing here: `load_certified_key` reads the chain
        // and the key independently and never compares them, so a row
        // whose key was replaced by a later generation's parses perfectly
        // and then fails every TLS handshake it is served for.
        // `keys_match` compares the key's SubjectPublicKeyInfo against the
        // certificate's, which is the thing "these are a pair" means.
        match crate::cert_resolver::load_certified_key(&cert_pem, &key_pem) {
            Err(_) => return Ok(Err(BundleReject::TornLegacy)),
            Ok(certified) => match certified.keys_match() {
                Ok(()) => {}
                Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
                    // The key type cannot produce its public key, so the
                    // pairing is unprovable rather than disproved. Adopting
                    // matches the behavior before single-record publishing
                    // and keeps a working deployment working; the warning is
                    // what makes the one case we cannot check visible.
                    tracing::warn!(
                        target: "sbproxy::tls",
                        hostname = %hostname,
                        "legacy certificate row adopted without a key-pair check:                          the signing key cannot produce its public key"
                    );
                }
                Err(_) => return Ok(Err(BundleReject::TornLegacy)),
            },
        }
        match CertBundle::new(hostname, 0, &cert_pem, &key_pem, meta) {
            Ok(bundle) => Ok(Ok(Some(bundle))),
            Err(_) => Ok(Err(BundleReject::TornLegacy)),
        }
    }

    /// Retrieve both the certificate and private key PEM for a hostname.
    ///
    /// Returns `None` when nothing complete and self-consistent is
    /// published. The pair always comes from one generation.
    ///
    /// Crate-internal convenience over [`Self::get_cert_bundle`], which is
    /// what production readers consume so a refusal stays distinguishable
    /// from an absence.
    // WOR-2635: no production caller remains. The fenced single-record
    // publish replaced this; the only callers left are the tests that
    // stage a legacy record to prove migration still reads one. Gating it
    // to test builds is what stops an unfenced write path from being
    // reachable again, which is the whole point of the fencing work.
    #[cfg(test)]
    pub(crate) fn get_cert_and_key(&self, hostname: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match self.get_cert_bundle(hostname)? {
            Ok(Some(bundle)) => Ok(Some((bundle.cert_pem, bundle.key_pem))),
            Ok(None) => Ok(None),
            Err(reason) => {
                tracing::warn!(
                    hostname = %hostname,
                    reason = %reason,
                    "stored certificate bundle refused; not serving it"
                );
                Ok(None)
            }
        }
    }

    /// Publish a certificate, private key, and metadata as one record.
    ///
    /// One backend write, so a reader observes the whole previous generation
    /// or the whole new one. `generation` is one past whatever is currently
    /// published, and the record carries a digest a reader checks.
    ///
    /// Crate-internal: the production path publishes through
    /// [`Self::put_cert_bundle_fenced`] so every publication is checked
    /// against the issuance lease. This unfenced form exists for tests and
    /// single-node tooling inside the crate.
    // WOR-2635: no production caller remains. The fenced single-record
    // publish replaced this; the only callers left are the tests that
    // stage a legacy record to prove migration still reads one. Gating it
    // to test builds is what stops an unfenced write path from being
    // reachable again, which is the whole point of the fencing work.
    #[cfg(test)]
    pub(crate) fn put_cert_bundle(
        &self,
        hostname: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        meta: &CertMeta,
    ) -> Result<u64> {
        let generation = self.published_generation(hostname)?.saturating_add(1);
        self.publish_bundle(hostname, cert_pem, key_pem, meta, generation)
    }

    /// The generation currently published, or zero when nothing is.
    ///
    /// A record that fails validation still contributes its generation: a
    /// torn record is a publication that happened, and the next one has to
    /// sort after it.
    pub fn published_generation(&self, hostname: &str) -> Result<u64> {
        let Some(bytes) = self.store.get(bundle_key(hostname).as_bytes())? else {
            return Ok(0);
        };
        Ok(CertBundle::decode(&bytes, hostname)
            .map(|bundle| bundle.generation)
            .unwrap_or_else(|_| {
                serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .and_then(|value| value.get("generation").and_then(|g| g.as_u64()))
                    .unwrap_or(0)
            }))
    }

    fn publish_bundle(
        &self,
        hostname: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        meta: &CertMeta,
        generation: u64,
    ) -> Result<u64> {
        let bundle = CertBundle::new(hostname, generation, cert_pem, key_pem, meta.clone())?;
        let encoded = bundle.encode()?;
        self.store.put(bundle_key(hostname).as_bytes(), &encoded)?;
        stamp_expiry_metric(hostname, meta);
        Ok(generation)
    }

    /// Publish under a fenced issuance lease (WOR-2633).
    ///
    /// Two things have to hold before a certificate becomes the fleet's
    /// serving material, and neither is "we acquired a lock a while ago".
    /// The lease has to still be ours right now, and our fencing generation
    /// has to be at least as new as whatever last published. A holder that
    /// paused past its deadline and was taken over fails the second test
    /// even if it never noticed the first.
    ///
    /// "Right now" is asked of the store, not of a local flag. The lease's
    /// `held` bit only turns false when the heartbeat task runs, and the
    /// heartbeat runs on the TLS maintenance runtime, which is a single
    /// worker that every blocking `CertStore` call occupies for its whole
    /// duration. A backend call that hangs therefore starves the very task
    /// whose job is to notice the lease was lost, and the flag stays true
    /// for exactly as long as the answer matters most. A conditional
    /// renewal against the backend is the check that cannot be starved: it
    /// asks the thing that actually knows, and it marks the lease lost on
    /// the way through so nothing later in this order slips past either.
    /// The carried fence generation below stays as the second line of
    /// defense, for backends whose renewal cannot be conditional.
    pub fn put_cert_bundle_fenced(
        &self,
        lease: &IssueLease,
        cert_pem: &[u8],
        key_pem: &[u8],
        meta: &CertMeta,
    ) -> Result<PublishOutcome> {
        if !lease.is_held() {
            return Ok(PublishOutcome::LeaseLost);
        }
        if !self.renew_issue_lease(lease, lease.ttl_secs)? {
            tracing::warn!(
                hostname = %lease.hostname,
                generation = lease.generation,
                "the issuance lease could not be re-proven against the store at \
                 publication time; refusing to publish"
            );
            return Ok(PublishOutcome::LeaseLost);
        }
        let published = self.published_generation(&lease.hostname)?;
        if published >= lease.generation {
            return Ok(PublishOutcome::Superseded {
                published,
                ours: lease.generation,
            });
        }
        // Stamp at least our own fencing generation, never merely
        // published-plus-one. Lease generations are minted per acquisition
        // and most acquisitions publish nothing, so the two counters drift:
        // with a dense bundle counter, a holder taken over at generation 5
        // would see its successor's publication land as generation 1 and
        // sail right past the `published >= ours` refusal above. Carrying
        // the fence into the record makes every later publication sort
        // after every earlier holder by construction.
        let generation = published.saturating_add(1).max(lease.generation);
        self.publish_bundle(&lease.hostname, cert_pem, key_pem, meta, generation)?;
        Ok(PublishOutcome::Published { generation })
    }

    /// Acquire a renewable, fenced issuance lease (WOR-2633).
    ///
    /// `Ok(None)` means a peer holds it. The returned lease carries the
    /// fencing generation the backend minted, and is the only thing
    /// [`Self::put_cert_bundle_fenced`] will publish under.
    pub fn acquire_issue_lease(&self, hostname: &str, ttl_secs: u64) -> Result<Option<IssueLease>> {
        let mut token = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token)
            .map_err(|_| anyhow::anyhow!("generate an issuance lease token"))?;
        let acquired =
            self.store
                .try_lock_fenced(lock_key(hostname).as_bytes(), &token, ttl_secs)?;
        Ok(acquired.map(|generation| IssueLease {
            hostname: hostname.to_string(),
            token: token.to_vec(),
            generation,
            ttl_secs,
            held: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }))
    }

    /// Extend a lease this node holds. `false` means it is no longer ours,
    /// and the lease is marked lost so no later publication can slip through.
    pub fn renew_issue_lease(&self, lease: &IssueLease, ttl_secs: u64) -> Result<bool> {
        let renewed =
            self.store
                .renew_lock(lock_key(&lease.hostname).as_bytes(), &lease.token, ttl_secs)?;
        if !renewed {
            lease.mark_lost();
        }
        Ok(renewed)
    }

    /// Release the issuance lock for `hostname` held with `token`. Safe to
    /// call after the lease has already expired (a mismatched token is a
    /// no-op on the backend).
    pub fn release_issue_lock(&self, hostname: &str, token: &[u8]) -> Result<()> {
        self.store.unlock(lock_key(hostname).as_bytes(), token)
    }

    fn get_meta_raw(&self, hostname: &str) -> Result<Option<CertMeta>> {
        match self.store.get(meta_key(hostname).as_bytes())? {
            None => Ok(None),
            Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        }
    }
}

/// A renewable, fenced hold on issuance for one hostname (WOR-2633).
///
/// The generation is the fencing token: it strictly increases across every
/// acquisition of the same lease on a shared backend, so a publication can
/// refuse a holder that has already been superseded. `held` is cleared the
/// moment a renewal comes back negative, which is what lets the issuance
/// flow stop at its next checkpoint instead of finishing an order nobody
/// will accept.
#[derive(Clone)]
pub struct IssueLease {
    hostname: String,
    token: Vec<u8>,
    generation: u64,
    /// The TTL this lease was acquired with, so the publication-time
    /// re-proof extends it by the same amount the heartbeat does rather
    /// than inventing a second number.
    ttl_secs: u64,
    held: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl IssueLease {
    /// The hostname this lease covers.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The fencing generation minted at acquisition.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The opaque owner token, for release.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Whether this node still believes it holds the lease.
    pub fn is_held(&self) -> bool {
        self.held.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Record that the lease has been lost. Irreversible for this lease.
    pub fn mark_lost(&self) {
        self.held.store(false, std::sync::atomic::Ordering::Release);
    }
}

impl std::fmt::Debug for IssueLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssueLease")
            .field("hostname", &self.hostname)
            .field("generation", &self.generation)
            .field("held", &self.is_held())
            .finish()
    }
}

/// What happened to a fenced publication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The bundle is now the published generation.
    Published {
        /// The generation written.
        generation: u64,
    },
    /// The lease was lost before the write; nothing was published.
    LeaseLost,
    /// A newer holder already published; nothing was written.
    Superseded {
        /// The generation already in the store.
        published: u64,
        /// The fencing generation this caller was holding.
        ours: u64,
    },
}

impl PublishOutcome {
    /// A short, bounded label for structured logs.
    ///
    /// Deliberately not a metric label yet, though the shape is ready to be
    /// one. `lease_lost` and `superseded` are exactly what an operator
    /// would alert on, and no counter carries them today: the metric
    /// registry lives in `sbproxy-observe`, which this change does not
    /// touch, so these outcomes are visible in the log line and in nothing
    /// else. Anyone wiring the counter should keep this closed set as the
    /// label values, which is why it is bounded rather than a formatted
    /// message.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Published { .. } => "published",
            Self::LeaseLost => "lease_lost",
            Self::Superseded { .. } => "superseded",
        }
    }
}

/// WOR-1024: stamp `sbproxy_cert_expiry_seconds{host}` from a bundle's
/// metadata. A parse failure is logged at warn and the metric skipped; the
/// publication still stands, because losing a gauge sample is not a reason
/// to lose a certificate.
fn stamp_expiry_metric(hostname: &str, meta: &CertMeta) {
    match chrono::DateTime::parse_from_rfc3339(&meta.expires_at) {
        Ok(exp) => {
            let now = chrono::Utc::now();
            let seconds = (exp.with_timezone(&chrono::Utc) - now).num_seconds() as f64;
            sbproxy_observe::metrics::record_cert_expiry(hostname, seconds);
        }
        Err(e) => {
            tracing::warn!(
                hostname = %hostname,
                expires_at = %meta.expires_at,
                error = %e,
                "cert meta expires_at is not RFC 3339; skipping sbproxy_cert_expiry_seconds stamp"
            );
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_platform::MemoryKVStore;

    fn store() -> CertStore {
        CertStore::new(std::sync::Arc::new(MemoryKVStore::new(0)))
    }

    /// Real material, because the bundle contract now proves the
    /// certificate and the key are a pair before it publishes them. A
    /// placeholder string would have been accepted by the three-key layout
    /// and is exactly the state WOR-2635 exists to refuse.
    fn pair(hostname: &str) -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("key pair");
        let params = rcgen::CertificateParams::new(vec![hostname.to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("self-signed cert");
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn sample_meta() -> CertMeta {
        CertMeta {
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            serial: "01ABCDEF".into(),
        }
    }

    #[test]
    fn redb_backend_persists_across_reopen() {
        // WOR-1773: the whole point of a non-memory backend is that a
        // restart does not lose the cert (and so does not re-issue). Write
        // a bundle through a redb-backed store, drop it (a "restart"), then
        // reopen the same file and confirm the cert is still there.
        use sbproxy_platform::storage::RedbKVStore;
        let path = std::env::temp_dir().join(format!(
            "sbproxy-certstore-test-{}.redb",
            std::process::id()
        ));
        let path_str = path.to_str().expect("utf-8 path");
        let _ = std::fs::remove_file(&path);
        let (cert_pem, key_pem) = pair("example.com");

        {
            let cs = CertStore::new(std::sync::Arc::new(
                RedbKVStore::new(path_str).expect("open redb"),
            ));
            cs.put_cert_bundle("example.com", &cert_pem, &key_pem, &sample_meta())
                .expect("publish");
        } // store dropped: simulates a process restart

        let reopened = CertStore::new(std::sync::Arc::new(
            RedbKVStore::new(path_str).expect("reopen redb"),
        ));
        let (cert, key) = reopened
            .get_cert_and_key("example.com")
            .expect("read")
            .expect("cert survives a reopen");
        assert_eq!(cert, cert_pem);
        assert_eq!(key, key_pem);
        assert!(reopened.get_meta("example.com").expect("meta").is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn local_backend_issue_lease_is_a_noop_that_acquires() {
        // WOR-1774: on a local (single-node) backend the issuance lease has
        // no cross-node contention, so it always acquires and release is a
        // no-op. The fencing generation still strictly increases, so the
        // publish-time check stays meaningful. The real distributed lease
        // lives in the redis, file, and object-store backends.
        let cs = store();
        let first = cs
            .acquire_issue_lease("example.com", 30)
            .expect("acquire")
            .expect("held");
        // A second acquire also succeeds; nothing to serialize on one node.
        let second = cs
            .acquire_issue_lease("example.com", 30)
            .expect("acquire again")
            .expect("held");
        assert!(second.generation() > first.generation());
        // Release is a no-op and does not error.
        cs.release_issue_lock("example.com", first.token())
            .expect("release");
    }

    #[test]
    fn test_account_key_roundtrip() {
        let cs = store();
        assert!(cs.get_account_key().expect("read").is_none());
        cs.put_account_key(b"-----BEGIN EC KEY-----\nFAKE\n-----END EC KEY-----\n")
            .expect("write");
        let got = cs.get_account_key().expect("read").expect("present");
        assert_eq!(got, b"-----BEGIN EC KEY-----\nFAKE\n-----END EC KEY-----\n");
    }

    #[test]
    fn test_cert_roundtrip() {
        let cs = store();
        assert!(cs.get_cert("example.com").expect("read").is_none());
        cs.put_cert("example.com", b"CERT_PEM").expect("write");
        let got = cs.get_cert("example.com").expect("read").expect("present");
        assert_eq!(got, b"CERT_PEM");
    }

    #[test]
    fn test_key_roundtrip() {
        let cs = store();
        assert!(cs.get_key("example.com").expect("read").is_none());
        cs.put_key("example.com", b"KEY_PEM").expect("write");
        let got = cs.get_key("example.com").expect("read").expect("present");
        assert_eq!(got, b"KEY_PEM");
    }

    #[test]
    fn metadata_comes_from_the_published_bundle() {
        // WOR-2635: renewal reads this, and metadata that outlives the
        // material it describes is how a node decides a peer has a
        // certificate covered when no certificate exists.
        let cs = store();
        assert!(cs.get_meta("example.com").expect("read").is_none());
        cs.put_meta("example.com", &sample_meta()).expect("write");
        assert!(
            cs.get_meta("example.com").expect("read").is_none(),
            "a standalone metadata key with no certificate behind it is not a certificate"
        );

        let (cert_pem, key_pem) = pair("example.com");
        cs.put_cert_bundle("example.com", &cert_pem, &key_pem, &sample_meta())
            .expect("publish");
        let got = cs.get_meta("example.com").expect("read").expect("present");
        assert_eq!(got.serial, "01ABCDEF");
    }

    #[test]
    fn a_certificate_without_its_key_is_not_a_bundle() {
        let cs = store();
        cs.put_cert("example.com", b"CERT_PEM").expect("write");
        assert!(cs.get_cert_and_key("example.com").expect("read").is_none());
    }

    #[test]
    fn legacy_three_key_state_migrates_only_when_the_pair_matches() {
        // WOR-2635: an in-place upgrade must keep serving a coherent legacy
        // row, and must quarantine a torn one rather than adopt it.
        let cs = store();
        let (cert_pem, key_pem) = pair("legacy.example.com");
        cs.put_cert("legacy.example.com", &cert_pem).expect("cert");
        cs.put_key("legacy.example.com", &key_pem).expect("key");
        cs.put_meta("legacy.example.com", &sample_meta())
            .expect("meta");
        let bundle = cs
            .get_cert_bundle("legacy.example.com")
            .expect("read")
            .expect("a coherent legacy row is adopted")
            .expect("present");
        assert_eq!(
            bundle.generation, 0,
            "legacy state sorts before any publication"
        );
        assert_eq!(bundle.cert_pem, cert_pem);

        // Now tear it: a key from a different generation.
        let (_, other_key) = pair("legacy.example.com");
        cs.put_key("legacy.example.com", &other_key).expect("key");
        assert_eq!(
            cs.get_cert_bundle("legacy.example.com")
                .expect("read")
                .err(),
            Some(BundleReject::TornLegacy)
        );
        assert!(
            cs.get_cert_and_key("legacy.example.com")
                .expect("read")
                .is_none(),
            "torn legacy state is quarantined, not served"
        );
    }

    #[test]
    fn test_list_hostnames() {
        let cs = store();
        assert!(cs.list_hostnames().expect("scan").is_empty());
        for host in ["alpha.com", "beta.com"] {
            let (cert_pem, key_pem) = pair(host);
            cs.put_cert_bundle(host, &cert_pem, &key_pem, &sample_meta())
                .expect("publish");
        }
        // A legacy certificate key still shows up, so an in-place upgrade
        // does not lose sight of a host.
        cs.put_cert("gamma.com", b"C1").expect("write");
        // A private key on its own does not.
        cs.put_key("delta.com", b"K1").expect("write");
        let mut names = cs.list_hostnames().expect("scan");
        names.sort();
        assert_eq!(names, vec!["alpha.com", "beta.com", "gamma.com"]);
    }

    #[test]
    fn generations_increase_and_a_torn_record_is_refused() {
        let cs = store();
        let host = "gen.example.com";
        let (cert_pem, key_pem) = pair(host);
        assert_eq!(
            cs.put_cert_bundle(host, &cert_pem, &key_pem, &sample_meta())
                .expect("publish"),
            1
        );
        let (cert2, key2) = pair(host);
        assert_eq!(
            cs.put_cert_bundle(host, &cert2, &key2, &sample_meta())
                .expect("republish"),
            2
        );
        assert_eq!(cs.published_generation(host).expect("read"), 2);

        // Truncate the record at a spread of offsets. Every one of them has
        // to be refused: a short read of a JSON document is the shape a
        // crashed write leaves behind, and "parses as far as it goes" is
        // not the same as "is a certificate".
        let encoded = cs
            .store
            .get(bundle_key(host).as_bytes())
            .expect("read")
            .expect("present");
        for cut in [
            1usize,
            16,
            64,
            encoded.len() / 3,
            encoded.len() / 2,
            encoded.len() - 1,
        ] {
            cs.store
                .put(bundle_key(host).as_bytes(), &encoded[..cut])
                .expect("write torn record");
            assert!(
                cs.get_cert_bundle(host).expect("read").is_err(),
                "a record truncated at {cut} of {} bytes was accepted",
                encoded.len()
            );
            assert!(cs.get_cert_and_key(host).expect("read").is_none());
            assert!(cs.get_meta(host).expect("read").is_none());
        }
    }

    #[test]
    fn a_record_changed_without_its_digest_is_refused() {
        // Not named "tampered", because that is not what this proves. The
        // digest is an unkeyed SHA-256 stored inside the record it covers,
        // so a writer who edits the record can recompute it and this check
        // passes. What it catches is a change the digest did not follow: a
        // half-finished write, a corrupted block, a hand-edited field.
        let cs = store();
        let host = "digest.example.com";
        let (cert_pem, key_pem) = pair(host);
        cs.put_cert_bundle(host, &cert_pem, &key_pem, &sample_meta())
            .expect("publish");
        let encoded = cs
            .store
            .get(bundle_key(host).as_bytes())
            .expect("read")
            .expect("present");
        let mut record: serde_json::Value =
            serde_json::from_slice(&encoded).expect("bundle is JSON");
        record["meta"]["expires_at"] = serde_json::json!("2099-01-01T00:00:00Z");
        cs.store
            .put(
                bundle_key(host).as_bytes(),
                &serde_json::to_vec(&record).expect("re-encode"),
            )
            .expect("write");
        assert_eq!(
            cs.get_cert_bundle(host).expect("read").err(),
            Some(BundleReject::DigestMismatch),
            "an expiry edited underneath the digest must not be believed"
        );
    }

    #[test]
    fn a_record_filed_under_the_wrong_hostname_is_refused() {
        let cs = store();
        let (cert_pem, key_pem) = pair("right.example.com");
        let bundle = CertBundle::new("right.example.com", 1, &cert_pem, &key_pem, sample_meta())
            .expect("build");
        cs.store
            .put(
                bundle_key("wrong.example.com").as_bytes(),
                &bundle.encode().expect("encode"),
            )
            .expect("write");
        assert_eq!(
            cs.get_cert_bundle("wrong.example.com").expect("read").err(),
            Some(BundleReject::HostnameMismatch)
        );
    }

    #[test]
    fn a_superseded_lease_cannot_publish() {
        // WOR-2633: the fence is the point. A holder that paused past its
        // deadline and was taken over must be refused at the write, whether
        // or not it ever noticed it lost the lease.
        let cs = store();
        let host = "fenced.example.com";
        let old = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");
        let new = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");
        assert!(new.generation() > old.generation());

        let (cert_pem, key_pem) = pair(host);
        assert!(matches!(
            cs.put_cert_bundle_fenced(&new, &cert_pem, &key_pem, &sample_meta())
                .expect("publish"),
            PublishOutcome::Published { .. }
        ));
        let (stale_cert, stale_key) = pair(host);
        assert!(matches!(
            cs.put_cert_bundle_fenced(&old, &stale_cert, &stale_key, &sample_meta())
                .expect("refuse"),
            PublishOutcome::Superseded { .. }
        ));
        assert_eq!(
            cs.get_cert_and_key(host).expect("read").expect("present").0,
            cert_pem,
            "the superseded holder must not have replaced the serving material"
        );
    }

    #[test]
    fn the_fence_survives_acquisitions_that_never_published() {
        // WOR-2633, the counter-gap case. Lease generations are minted per
        // acquisition and most acquisitions publish nothing (the metadata
        // was still fresh), so a stale holder's generation is usually far
        // ahead of a dense per-publication counter. If the record carried
        // published-plus-one instead of the fence, the sequence below would
        // let the stale holder through: burner takes generation 1 and
        // publishes nothing, stale takes 2, successor takes 3 and publishes;
        // a dense counter would stamp that publication as generation 1, and
        // the stale holder's check "1 >= 2" would wave it in.
        let cs = store();
        let host = "gap.example.com";
        let burner = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");
        drop(burner); // never publishes, never releases: a crashed holder
        let stale = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");
        let successor = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");
        assert!(successor.generation() > stale.generation());

        let (new_cert, new_key) = pair(host);
        let outcome = cs
            .put_cert_bundle_fenced(&successor, &new_cert, &new_key, &sample_meta())
            .expect("publish");
        match outcome {
            PublishOutcome::Published { generation } => assert!(
                generation >= successor.generation(),
                "the record must carry the fence: got {generation}, fence {}",
                successor.generation()
            ),
            other => panic!("the successor must publish, got {other:?}"),
        }

        let (stale_cert, stale_key) = pair(host);
        assert!(
            matches!(
                cs.put_cert_bundle_fenced(&stale, &stale_cert, &stale_key, &sample_meta())
                    .expect("refuse"),
                PublishOutcome::Superseded { .. }
            ),
            "a holder superseded before the successor published must stay fenced out"
        );
        assert_eq!(
            cs.get_cert_and_key(host).expect("read").expect("present").0,
            new_cert,
            "the successor's material must still be the published generation"
        );
    }

    /// A store that can hand the lease to a peer without the holder's
    /// local flag ever being told.
    struct DeposingStore {
        inner: MemoryKVStore,
        lease_ours: std::sync::atomic::AtomicBool,
    }

    impl DeposingStore {
        fn new() -> Self {
            Self {
                inner: MemoryKVStore::new(0),
                lease_ours: std::sync::atomic::AtomicBool::new(true),
            }
        }
        fn depose(&self) {
            self.lease_ours
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl sbproxy_platform::KVStore for DeposingStore {
        fn get(&self, key: &[u8]) -> Result<Option<bytes::Bytes>> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.inner.put(key, value)
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.inner.delete(key)
        }
        fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            self.inner.scan_prefix(prefix)
        }
        fn renew_lock(&self, _key: &[u8], _token: &[u8], _ttl_secs: u64) -> Result<bool> {
            Ok(self.lease_ours.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    #[test]
    fn a_publication_reproves_the_lease_against_the_store_not_a_cached_flag() {
        // `is_held()` reads a local `AtomicBool` that only turns false when
        // the heartbeat task runs, and the heartbeat shares a one-worker
        // maintenance runtime with every blocking `CertStore` call. A
        // backend call that hangs starves the task whose whole job is to
        // notice the lease was lost, so at the exact moment the answer
        // matters the flag still says "held" and a deposed holder publishes
        // over its successor's certificate. The doc comment promised "the
        // lease has to still be ours right now"; only asking the store can
        // make that true.
        let store = std::sync::Arc::new(DeposingStore::new());
        let cs = CertStore::new(std::sync::Arc::clone(&store) as std::sync::Arc<dyn KVStore>);
        let host = "starved.example.com";
        let lease = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");

        // The backend has handed the lease to a peer. The heartbeat that
        // would have observed it never got scheduled.
        store.depose();
        assert!(
            lease.is_held(),
            "the stale cached flag is exactly the thing under test"
        );

        let (cert_pem, key_pem) = pair(host);
        assert_eq!(
            cs.put_cert_bundle_fenced(&lease, &cert_pem, &key_pem, &sample_meta())
                .expect("refuse"),
            PublishOutcome::LeaseLost,
            "a lease the store will not re-prove must not publish"
        );
        assert!(
            cs.get_cert_and_key(host).expect("read").is_none(),
            "nothing may have reached the store"
        );
        assert!(
            !lease.is_held(),
            "the re-proof marks the lease lost, so nothing later in the order slips through"
        );
    }

    #[test]
    fn a_lost_lease_cannot_publish() {
        let cs = store();
        let host = "lost.example.com";
        let lease = cs
            .acquire_issue_lease(host, 60)
            .expect("acquire")
            .expect("held");
        lease.mark_lost();
        let (cert_pem, key_pem) = pair(host);
        assert_eq!(
            cs.put_cert_bundle_fenced(&lease, &cert_pem, &key_pem, &sample_meta())
                .expect("refuse"),
            PublishOutcome::LeaseLost
        );
        assert!(cs.get_cert_and_key(host).expect("read").is_none());
    }
}
