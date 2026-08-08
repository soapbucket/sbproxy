//! ACME challenge handlers: HTTP-01 and TLS-ALPN-01.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use rcgen::{CertificateParams, CustomExtension, DistinguishedName, KeyPair};
use ring::digest::{digest, SHA256};
use sbproxy_platform::KVStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::warn;

// --- Constants ---

/// URL prefix for ACME HTTP-01 challenge responses.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Key prefix for a published HTTP-01 key authorization in the shared cert
/// store. Matches the `acme:` namespace [`crate::cert_store::CertStore`]
/// already uses for `acme:cert:`, `acme:key:`, `acme:meta:` and `acme:lock:`,
/// so one backend holds the whole ACME working set under one prefix.
const CHALLENGE_PREFIX: &str = "acme:challenge:";

fn challenge_key(token: &str) -> String {
    format!("{}{}", CHALLENGE_PREFIX, token)
}

/// How long a published key authorization stays answerable, in seconds.
///
/// Ten minutes. The floor is set by our own issuance flow: after the token is
/// published, [`crate::acme::AcmeClient`] waits up to 120s for the
/// authorization to go valid, up to 120s for the order to go ready, and up to
/// another 120s for it to go valid after finalization, so a slow but healthy
/// order can keep the token live for six minutes plus CSR and download time.
/// The ceiling is set by cleanup: the issuing node deletes the key on the
/// happy path, but a node that is killed between publishing the token and
/// finishing the order cannot, and on a shared backend that orphan would
/// otherwise be served forever. Ten minutes covers the slowest healthy order
/// with slack for a CA that retries validation, and ages out an orphan fast
/// enough that it never outlives the order it belonged to.
const CHALLENGE_TTL_SECS: u64 = 600;

// --- Http01ChallengeStore ---

/// A published HTTP-01 key authorization plus the instant it stops counting.
///
/// The deadline travels inside the value rather than relying on the backend,
/// because only Redis implements [`KVStore::put_with_ttl`]. Stamping it here
/// gives every backend (redb, sqlite, file, object storage) the same expiry
/// semantics, and a reader enforces it without trusting the writer's clock to
/// have been the one that wrote the key.
#[derive(Serialize, Deserialize)]
struct ChallengeRecord {
    /// Unix seconds after which this key authorization must not be served.
    expires_at: i64,
    /// The `token.thumbprint` value the CA fetches (RFC 8555 §8.1).
    key_authorization: String,
}

/// Store of pending HTTP-01 challenge tokens, answerable fleet-wide.
///
/// A token is written to two places: a process-local map, and (when one is
/// configured) the same [`KVStore`] that backs
/// [`crate::cert_store::CertStore`]. Both halves matter.
///
/// The shared write is the correctness requirement. Only one node in a fleet
/// wins the per-hostname issuance lease and drives the order, but the CA's
/// `GET /.well-known/acme-challenge/<token>` lands on whichever node the load
/// balancer picks. Without the shared write, every node but the issuer
/// answers 404 and the authorization fails. Reads fall through to the shared
/// store precisely so a node that did not issue can still answer.
///
/// The local map is a fast path, not the source of truth: it saves the
/// issuing node a backend round-trip on the request it is most likely to
/// receive. It cannot mask a missing shared write, because a node with an
/// empty map still consults the backend.
///
/// Uses `parking_lot::Mutex`, which is unpoisoned by design, so a panic
/// while a challenge insert/lookup is in flight cannot cascade to subsequent
/// ACME validations.
pub struct Http01ChallengeStore {
    pending: Mutex<HashMap<String, ChallengeRecord>>,
    shared: Option<Arc<dyn KVStore>>,
}

impl Http01ChallengeStore {
    /// Create a process-local challenge store with no shared backing.
    ///
    /// Only a single-process deployment can serve challenges from this.
    /// Anything running more than one replica wants [`Self::with_store`].
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            shared: None,
        }
    }

    /// Create a challenge store backed by `store`, which should be the same
    /// [`KVStore`] that backs the [`crate::cert_store::CertStore`] so a whole
    /// fleet answers from one place.
    pub fn with_store(store: Arc<dyn KVStore>) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            shared: Some(store),
        }
    }

    /// Register a token and its corresponding key authorization.
    ///
    /// Fails when the shared backing store rejects the write. That is
    /// deliberate: silently keeping a token this node alone can answer is the
    /// exact failure that makes issuance behind a load balancer look like a
    /// CA problem. Failing here aborts the order instead, with a real error.
    pub fn set(&self, token: &str, key_authorization: &str) -> Result<()> {
        self.set_at(token, key_authorization, now_unix())
    }

    /// Look up the key authorization for a token, local map first, then the
    /// shared store. Expired records never match.
    pub fn get(&self, token: &str) -> Option<String> {
        self.get_at(token, now_unix())
    }

    /// [`Self::get`] for an async caller.
    ///
    /// A local hit resolves without awaiting anything. A miss falls through
    /// to the shared store on the blocking pool, because a [`KVStore`] read
    /// can be network I/O (Redis uses a blocking socket) and the two serving
    /// sites are both on a request path driven by a tokio worker.
    pub async fn get_async(&self, token: &str) -> Option<String> {
        let now = now_unix();
        if let Some(hit) = self.local_get(token, now) {
            return Some(hit);
        }
        let store = Arc::clone(self.shared.as_ref()?);
        let key = challenge_key(token).into_bytes();
        match tokio::task::spawn_blocking(move || store.get(&key)).await {
            Ok(Ok(Some(bytes))) => decode_unexpired(&bytes, now),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                warn!(token = %token, "reading the shared ACME challenge store failed: {e:#}");
                None
            }
            Err(e) => {
                warn!(token = %token, "shared ACME challenge store read did not join: {e}");
                None
            }
        }
    }

    /// Remove a token once the challenge is complete.
    ///
    /// Best effort on the shared store: a failed delete is logged, not
    /// returned, because the record carries its own expiry and the caller is
    /// on the success path of an order that has already been issued.
    pub fn remove(&self, token: &str) {
        self.pending.lock().remove(token);
        let Some(store) = &self.shared else {
            return;
        };
        if let Err(e) = store.delete(challenge_key(token).as_bytes()) {
            warn!(
                token = %token,
                "removing the ACME challenge from the shared cert store failed: {e:#}"
            );
        }
    }

    // --- Internals (clock injected so expiry is testable without sleeping) ---

    fn set_at(&self, token: &str, key_authorization: &str, now: i64) -> Result<()> {
        let record = ChallengeRecord {
            expires_at: now.saturating_add(CHALLENGE_TTL_SECS as i64),
            key_authorization: key_authorization.to_owned(),
        };
        if let Some(store) = &self.shared {
            let value =
                serde_json::to_vec(&record).context("encode the HTTP-01 challenge record")?;
            let key = challenge_key(token);
            // Redis expires the key itself; every other backend has no TTL
            // primitive and returns "not supported", in which case the
            // `expires_at` inside the record is what bounds the lifetime.
            if store
                .put_with_ttl(key.as_bytes(), &value, CHALLENGE_TTL_SECS)
                .is_err()
            {
                store
                    .put(key.as_bytes(), &value)
                    .context("publish the HTTP-01 challenge to the shared cert store")?;
            }
        }
        self.pending.lock().insert(token.to_owned(), record);
        Ok(())
    }

    fn get_at(&self, token: &str, now: i64) -> Option<String> {
        if let Some(hit) = self.local_get(token, now) {
            return Some(hit);
        }
        let store = self.shared.as_ref()?;
        match store.get(challenge_key(token).as_bytes()) {
            Ok(Some(bytes)) => decode_unexpired(&bytes, now),
            Ok(None) => None,
            Err(e) => {
                warn!(token = %token, "reading the shared ACME challenge store failed: {e:#}");
                None
            }
        }
    }

    fn local_get(&self, token: &str, now: i64) -> Option<String> {
        self.pending
            .lock()
            .get(token)
            .filter(|record| record.expires_at > now)
            .map(|record| record.key_authorization.clone())
    }
}

impl Default for Http01ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Decode a stored record and return its key authorization only while it is
/// still inside its window. A record we cannot parse is treated as absent:
/// serving a half-understood value would answer the CA with the wrong bytes.
fn decode_unexpired(bytes: &[u8], now: i64) -> Option<String> {
    let record: ChallengeRecord = serde_json::from_slice(bytes).ok()?;
    (record.expires_at > now).then_some(record.key_authorization)
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
    use sbproxy_platform::MemoryKVStore;

    // --- Http01ChallengeStore ---

    #[test]
    fn test_store_set_get() {
        let store = Http01ChallengeStore::new();
        store.set("mytoken", "mytoken.thumbprint").unwrap();
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
        store.set("tok", "tok.abc").unwrap();
        store.remove("tok");
        assert!(store.get("tok").is_none());
    }

    #[test]
    fn test_store_overwrite() {
        let store = Http01ChallengeStore::new();
        store.set("tok", "first").unwrap();
        store.set("tok", "second").unwrap();
        assert_eq!(store.get("tok").as_deref(), Some("second"));
    }

    // --- Http01ChallengeStore: fleet-wide answerability ---

    #[test]
    fn a_challenge_published_by_one_node_is_answerable_by_another() {
        // The load balancer sends the CA's validation GET to an arbitrary
        // replica, which is almost never the replica that won the issuance
        // lease. Node B never called `set` and has an empty local map; it
        // must still answer, or the authorization fails and no cert is ever
        // issued behind a load balancer.
        let shared: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let node_a = Http01ChallengeStore::with_store(Arc::clone(&shared));
        let node_b = Http01ChallengeStore::with_store(Arc::clone(&shared));

        node_a.set("tok-abc", "tok-abc.thumbprint").unwrap();

        assert_eq!(
            node_b.get("tok-abc").as_deref(),
            Some("tok-abc.thumbprint"),
            "a replica that did not issue must still answer the challenge"
        );
    }

    #[tokio::test]
    async fn a_challenge_published_by_one_node_is_answerable_by_another_async() {
        // Same guarantee through the accessor both serving sites call.
        let shared: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let node_a = Http01ChallengeStore::with_store(Arc::clone(&shared));
        let node_b = Http01ChallengeStore::with_store(Arc::clone(&shared));

        node_a.set("tok-async", "tok-async.thumbprint").unwrap();

        assert_eq!(
            node_b.get_async("tok-async").await.as_deref(),
            Some("tok-async.thumbprint")
        );
        assert!(node_b.get_async("tok-missing").await.is_none());
    }

    #[test]
    fn a_node_on_a_different_store_cannot_answer_the_challenge() {
        // The read-through is scoped to the configured backend, not global.
        // Two proxies that do not share a cert store must stay isolated.
        let node_a = Http01ChallengeStore::with_store(Arc::new(MemoryKVStore::new(0)));
        let node_c = Http01ChallengeStore::with_store(Arc::new(MemoryKVStore::new(0)));

        node_a.set("tok-abc", "tok-abc.thumbprint").unwrap();

        assert!(
            node_c.get("tok-abc").is_none(),
            "a proxy on an unrelated cert store must not answer another fleet's challenge"
        );
    }

    #[test]
    fn a_shared_challenge_is_namespaced_under_the_acme_prefix() {
        // Pins the wire key. Operators point several proxies at one Redis or
        // one bucket, and the ACME working set has to stay inside the same
        // `acme:` namespace the cert, key, meta and lock records use.
        let shared: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let node = Http01ChallengeStore::with_store(Arc::clone(&shared));

        node.set("tok-abc", "tok-abc.thumbprint").unwrap();

        let raw = shared
            .get(b"acme:challenge:tok-abc")
            .unwrap()
            .expect("the challenge is stored under acme:challenge:<token>");
        let decoded: ChallengeRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(decoded.key_authorization, "tok-abc.thumbprint");
    }

    #[test]
    fn an_expired_challenge_is_no_longer_answerable() {
        // Only Redis expires keys on its own, so the deadline stamped into
        // the record has to be what stops the read on every other backend.
        let shared: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let node_a = Http01ChallengeStore::with_store(Arc::clone(&shared));
        let node_b = Http01ChallengeStore::with_store(Arc::clone(&shared));
        let issued_at = 1_800_000_000_i64;

        node_a
            .set_at("tok-abc", "tok-abc.thumbprint", issued_at)
            .unwrap();

        let ttl = CHALLENGE_TTL_SECS as i64;
        assert_eq!(
            node_a.get_at("tok-abc", issued_at + ttl - 1).as_deref(),
            Some("tok-abc.thumbprint"),
            "the issuing node answers from its local map inside the window"
        );
        assert_eq!(
            node_b.get_at("tok-abc", issued_at + ttl - 1).as_deref(),
            Some("tok-abc.thumbprint"),
            "a peer answers through the shared store inside the window"
        );
        assert!(
            node_a.get_at("tok-abc", issued_at + ttl).is_none(),
            "the local fast path must honor the same deadline"
        );
        assert!(
            node_b.get_at("tok-abc", issued_at + ttl).is_none(),
            "an orphaned record must stop being served once it expires"
        );
    }

    #[test]
    fn removing_a_challenge_clears_it_for_the_whole_fleet() {
        let shared: Arc<dyn KVStore> = Arc::new(MemoryKVStore::new(0));
        let node_a = Http01ChallengeStore::with_store(Arc::clone(&shared));
        let node_b = Http01ChallengeStore::with_store(Arc::clone(&shared));

        node_a.set("tok-abc", "tok-abc.thumbprint").unwrap();
        assert!(node_b.get("tok-abc").is_some());

        node_a.remove("tok-abc");

        assert!(node_a.get("tok-abc").is_none());
        assert!(node_b.get("tok-abc").is_none());
        assert!(shared.get(b"acme:challenge:tok-abc").unwrap().is_none());
    }

    #[test]
    fn a_single_node_answers_from_the_local_map_with_no_shared_store() {
        // The single-process path is unchanged: no backing store, no backend
        // read, and the challenge is still answered.
        let node = Http01ChallengeStore::new();
        node.set("tok-abc", "tok-abc.thumbprint").unwrap();
        assert_eq!(node.get("tok-abc").as_deref(), Some("tok-abc.thumbprint"));
        node.remove("tok-abc");
        assert!(node.get("tok-abc").is_none());
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
