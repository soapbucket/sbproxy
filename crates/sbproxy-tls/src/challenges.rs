//! ACME challenge handlers: HTTP-01 and TLS-ALPN-01.

use anyhow::{Context, Result};
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, KeyPair};
use ring::digest::{digest, SHA256};
use std::collections::HashMap;
use std::sync::Mutex;

// --- Constants ---

/// URL prefix for ACME HTTP-01 challenge responses.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

// --- Http01ChallengeStore ---

/// Thread-safe store of pending HTTP-01 challenge tokens.
pub struct Http01ChallengeStore {
    pending: Mutex<HashMap<String, String>>,
}

impl Http01ChallengeStore {
    /// Create a new, empty challenge store.
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Register a token and its corresponding key authorization.
    pub fn set(&self, token: &str, key_authorization: &str) {
        self.pending
            .lock()
            .unwrap()
            .insert(token.to_owned(), key_authorization.to_owned());
    }

    /// Look up the key authorization for a token.
    pub fn get(&self, token: &str) -> Option<String> {
        self.pending.lock().unwrap().get(token).cloned()
    }

    /// Remove a token once the challenge is complete.
    pub fn remove(&self, token: &str) {
        self.pending.lock().unwrap().remove(token);
    }
}

impl Default for Http01ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

// --- Path helper ---

/// Extract the challenge token from an ACME HTTP-01 challenge path.
///
/// Returns `Some(token)` when `path` starts with `ACME_CHALLENGE_PREFIX`,
/// otherwise `None`.
pub fn extract_challenge_token(path: &str) -> Option<&str> {
    path.strip_prefix(ACME_CHALLENGE_PREFIX)
}

// --- TLS-ALPN-01 cert builder ---

/// Build a self-signed TLS-ALPN-01 validation certificate for `domain`.
///
/// The certificate includes the `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31)
/// whose value is a DER OCTET STRING containing the SHA-256 hash of
/// `key_authorization`.
///
/// Returns `(cert_pem, key_pem)`.
pub fn build_tls_alpn01_cert(domain: &str, key_authorization: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    // SHA-256 hash of the key authorization
    let hash = digest(&SHA256, key_authorization.as_bytes());
    let hash_bytes = hash.as_ref();

    // DER OCTET STRING: tag 0x04, length 0x20 (32), then 32 bytes
    let mut ext_value = Vec::with_capacity(34);
    ext_value.push(0x04); // OCTET STRING tag
    ext_value.push(0x20); // length = 32
    ext_value.extend_from_slice(hash_bytes);

    // OID 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)
    let acme_ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 31], ext_value);

    // Build certificate params
    let mut params = CertificateParams::new(vec![domain.to_owned()])
        .context("failed to create certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    params.custom_extensions.push(acme_ext);

    // Generate ephemeral key
    let key_pair = KeyPair::generate().context("failed to generate key pair")?;

    // Self-sign
    let cert = params
        .self_signed(&key_pair)
        .context("failed to self-sign certificate")?;

    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();

    Ok((cert_pem, key_pem))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{pem::PemObject as _, CertificateDer};

    // --- Http01ChallengeStore ---

    #[test]
    fn test_store_set_get() {
        let store = Http01ChallengeStore::new();
        store.set("mytoken", "mytoken.thumbprint");
        assert_eq!(store.get("mytoken").as_deref(), Some("mytoken.thumbprint"));
    }

    #[test]
    fn test_store_get_missing() {
        let store = Http01ChallengeStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn test_store_remove() {
        let store = Http01ChallengeStore::new();
        store.set("tok", "tok.abc");
        store.remove("tok");
        assert!(store.get("tok").is_none());
    }

    #[test]
    fn test_store_overwrite() {
        let store = Http01ChallengeStore::new();
        store.set("tok", "first");
        store.set("tok", "second");
        assert_eq!(store.get("tok").as_deref(), Some("second"));
    }

    // --- extract_challenge_token ---

    #[test]
    fn test_extract_valid_path() {
        let token = extract_challenge_token("/.well-known/acme-challenge/abc123");
        assert_eq!(token, Some("abc123"));
    }

    #[test]
    fn test_extract_prefix_only() {
        let token = extract_challenge_token("/.well-known/acme-challenge/");
        assert_eq!(token, Some(""));
    }

    #[test]
    fn test_extract_invalid_path() {
        assert!(extract_challenge_token("/other/path").is_none());
    }

    #[test]
    fn test_extract_empty_path() {
        assert!(extract_challenge_token("").is_none());
    }

    // --- build_tls_alpn01_cert ---

    #[test]
    fn test_alpn01_cert_valid_pem() {
        let (cert_pem, key_pem) = build_tls_alpn01_cert("example.com", "token.thumbprint")
            .expect("cert generation failed");

        // cert_pem must be parseable as PEM via rustls-pki-types.
        let certs_parsed: Vec<_> = CertificateDer::pem_slice_iter(&cert_pem).collect();
        assert!(!certs_parsed.is_empty(), "no certs parsed from PEM");
        assert!(certs_parsed[0].is_ok(), "cert parse error");

        // key_pem must be non-empty and contain PEM header
        let key_str = std::str::from_utf8(&key_pem).expect("key not UTF-8");
        assert!(key_str.contains("PRIVATE KEY"), "key PEM header missing");
    }

    #[test]
    fn test_alpn01_cert_different_domains() {
        let (c1, _) = build_tls_alpn01_cert("a.com", "tok.x").unwrap();
        let (c2, _) = build_tls_alpn01_cert("b.com", "tok.x").unwrap();
        // Different domains produce different cert PEM bytes
        assert_ne!(c1, c2);
    }
}
