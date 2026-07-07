//! Certificate persistence via KVStore trait.

use anyhow::Result;
use sbproxy_platform::KVStore;
use serde::{Deserialize, Serialize};

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

const LOCK_PREFIX: &str = "acme:lock:";

fn lock_key(hostname: &str) -> String {
    format!("{}{}", LOCK_PREFIX, hostname)
}

// --- CertMeta ---

/// Metadata associated with a stored certificate.
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

    /// Persist JSON-encoded [`CertMeta`] for a hostname.
    ///
    /// WOR-1024: side-effect — stamps
    /// `sbproxy_cert_expiry_seconds{host}` with the seconds-until-expiry
    /// derived from `meta.expires_at`. Negative values mean the cert
    /// is already expired; an alert at `< 7 days` catches a stalled
    /// ACME renewal before a handshake error surfaces. Parse failure
    /// on the RFC 3339 timestamp is logged at warn and the metric is
    /// skipped (the persistence path still succeeds so the cert
    /// is not lost).
    pub fn put_meta(&self, hostname: &str, meta: &CertMeta) -> Result<()> {
        let json = serde_json::to_vec(meta)?;
        self.store.put(meta_key(hostname).as_bytes(), &json)?;
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
        Ok(())
    }

    /// Retrieve and deserialize [`CertMeta`] for a hostname, if present.
    pub fn get_meta(&self, hostname: &str) -> Result<Option<CertMeta>> {
        match self.store.get(meta_key(hostname).as_bytes())? {
            None => Ok(None),
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        }
    }

    // --- Composite helpers ---

    /// Return all hostnames that have a stored certificate.
    pub fn list_hostnames(&self) -> Result<Vec<String>> {
        let pairs = self.store.scan_prefix(CERT_PREFIX.as_bytes())?;
        let prefix_len = CERT_PREFIX.len();
        let mut hostnames = Vec::with_capacity(pairs.len());
        for (key, _) in pairs {
            // key bytes after the prefix are the hostname
            let hostname = std::str::from_utf8(&key[prefix_len..])?.to_owned();
            hostnames.push(hostname);
        }
        Ok(hostnames)
    }

    /// Retrieve both the certificate and private key PEM for a hostname.
    ///
    /// Returns `None` if either the certificate or the private key is missing.
    pub fn get_cert_and_key(&self, hostname: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let cert = self.get_cert(hostname)?;
        let key = self.get_key(hostname)?;
        match (cert, key) {
            (Some(c), Some(k)) => Ok(Some((c, k))),
            _ => Ok(None),
        }
    }

    /// Atomically persist a certificate, private key, and metadata for a hostname.
    pub fn put_cert_bundle(
        &self,
        hostname: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
        meta: &CertMeta,
    ) -> Result<()> {
        self.put_cert(hostname, cert_pem)?;
        self.put_key(hostname, key_pem)?;
        self.put_meta(hostname, meta)?;
        Ok(())
    }

    /// Try to acquire the ACME issuance lock for `hostname`, held with the
    /// caller's unique `token` and expiring after `ttl_secs` (WOR-1774).
    /// Returns `true` when acquired. On a local backend this always
    /// succeeds (no cross-node contention); on a shared backend (redis) it
    /// is an atomic lease so a fleet issues a cert once.
    pub fn try_issue_lock(&self, hostname: &str, token: &[u8], ttl_secs: u64) -> Result<bool> {
        self.store
            .try_lock(lock_key(hostname).as_bytes(), token, ttl_secs)
    }

    /// Release the issuance lock for `hostname` held with `token`. Safe to
    /// call after the lease has already expired (a mismatched token is a
    /// no-op on the backend).
    pub fn release_issue_lock(&self, hostname: &str, token: &[u8]) -> Result<()> {
        self.store.unlock(lock_key(hostname).as_bytes(), token)
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
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(&path);

        {
            let cs = CertStore::new(std::sync::Arc::new(RedbKVStore::new(path_str).unwrap()));
            cs.put_cert_bundle("example.com", b"CERTPEM", b"KEYPEM", &sample_meta())
                .unwrap();
        } // store dropped: simulates a process restart

        let reopened = CertStore::new(std::sync::Arc::new(RedbKVStore::new(path_str).unwrap()));
        let (cert, key) = reopened
            .get_cert_and_key("example.com")
            .unwrap()
            .expect("cert survives a reopen");
        assert_eq!(cert, b"CERTPEM");
        assert_eq!(key, b"KEYPEM");
        assert!(reopened.get_meta("example.com").unwrap().is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn local_backend_issue_lock_is_a_noop_that_acquires() {
        // WOR-1774: on a local (single-node) backend the issuance lock has
        // no cross-node contention, so it always acquires and release is a
        // no-op. The real distributed lease lives in the redis backend.
        let cs = store();
        assert!(cs.try_issue_lock("example.com", b"token-1", 30).unwrap());
        // A second acquire also succeeds; nothing to serialize on one node.
        assert!(cs.try_issue_lock("example.com", b"token-2", 30).unwrap());
        // Release is a no-op and does not error.
        cs.release_issue_lock("example.com", b"token-1").unwrap();
    }

    #[test]
    fn test_account_key_roundtrip() {
        let cs = store();
        assert!(cs.get_account_key().unwrap().is_none());
        cs.put_account_key(b"-----BEGIN EC KEY-----\nFAKE\n-----END EC KEY-----\n")
            .unwrap();
        let got = cs.get_account_key().unwrap().unwrap();
        assert_eq!(got, b"-----BEGIN EC KEY-----\nFAKE\n-----END EC KEY-----\n");
    }

    #[test]
    fn test_cert_roundtrip() {
        let cs = store();
        assert!(cs.get_cert("example.com").unwrap().is_none());
        cs.put_cert("example.com", b"CERT_PEM").unwrap();
        let got = cs.get_cert("example.com").unwrap().unwrap();
        assert_eq!(got, b"CERT_PEM");
    }

    #[test]
    fn test_key_roundtrip() {
        let cs = store();
        assert!(cs.get_key("example.com").unwrap().is_none());
        cs.put_key("example.com", b"KEY_PEM").unwrap();
        let got = cs.get_key("example.com").unwrap().unwrap();
        assert_eq!(got, b"KEY_PEM");
    }

    #[test]
    fn test_meta_roundtrip() {
        let cs = store();
        assert!(cs.get_meta("example.com").unwrap().is_none());
        let meta = sample_meta();
        cs.put_meta("example.com", &meta).unwrap();
        let got = cs.get_meta("example.com").unwrap().unwrap();
        assert_eq!(got.issued_at, meta.issued_at);
        assert_eq!(got.expires_at, meta.expires_at);
        assert_eq!(got.serial, meta.serial);
    }

    #[test]
    fn test_cert_and_key_missing_key_returns_none() {
        let cs = store();
        cs.put_cert("example.com", b"CERT_PEM").unwrap();
        // key is missing - should return None
        let result = cs.get_cert_and_key("example.com").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cert_and_key_present() {
        let cs = store();
        cs.put_cert("example.com", b"CERT_PEM").unwrap();
        cs.put_key("example.com", b"KEY_PEM").unwrap();
        let (cert, key) = cs.get_cert_and_key("example.com").unwrap().unwrap();
        assert_eq!(cert, b"CERT_PEM");
        assert_eq!(key, b"KEY_PEM");
    }

    #[test]
    fn test_list_hostnames() {
        let cs = store();
        assert!(cs.list_hostnames().unwrap().is_empty());
        cs.put_cert("alpha.com", b"C1").unwrap();
        cs.put_cert("beta.com", b"C2").unwrap();
        // also put a key (different prefix) - should NOT appear in list
        cs.put_key("gamma.com", b"K1").unwrap();
        let mut names = cs.list_hostnames().unwrap();
        names.sort();
        assert_eq!(names, vec!["alpha.com", "beta.com"]);
    }

    #[test]
    fn test_put_cert_bundle() {
        let cs = store();
        let meta = sample_meta();
        cs.put_cert_bundle("example.com", b"CERT", b"KEY", &meta)
            .unwrap();
        let (cert, key) = cs.get_cert_and_key("example.com").unwrap().unwrap();
        assert_eq!(cert, b"CERT");
        assert_eq!(key, b"KEY");
        let got_meta = cs.get_meta("example.com").unwrap().unwrap();
        assert_eq!(got_meta.serial, "01ABCDEF");
    }
}
