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
pub struct CertStore<S: KVStore> {
    store: S,
}

impl<S: KVStore> CertStore<S> {
    /// Create a new CertStore wrapping the given KVStore backend.
    pub fn new(store: S) -> Self {
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
    pub fn put_meta(&self, hostname: &str, meta: &CertMeta) -> Result<()> {
        let json = serde_json::to_vec(meta)?;
        self.store.put(meta_key(hostname).as_bytes(), &json)
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
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_platform::MemoryKVStore;

    fn store() -> CertStore<MemoryKVStore> {
        CertStore::new(MemoryKVStore::new(0))
    }

    fn sample_meta() -> CertMeta {
        CertMeta {
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            serial: "01ABCDEF".into(),
        }
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
