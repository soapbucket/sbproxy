// CIMD → RFC 7591 Dynamic Client Registration translation.
//
// CIMD is the parecki draft mechanism whereby a `client_id` is itself
// an https URL pointing at a JSON metadata document. Most production
// upstreams (Auth0, Okta, Keycloak) do not natively understand a
// URL-shaped client_id; they only speak RFC 7591 DCR. When
// `dcr_translate_cimd_clients` is enabled the broker bridges the gap:
//
//   1. Resolve the CIMD document via the CIMD cache.
//   2. POST it to the upstream registration endpoint as RFC 7591
//      metadata, receiving back an opaque server-side `client_id`.
//   3. Cache the mapping (CIMD URL → registered client_id) keyed by a
//      hash of the URL so subsequent /authorize requests skip the
//      double round trip.
//   4. When the CIMD document's ETag changes the cache entry is
//      invalidated and a fresh DCR is performed.
//
// The cache is intentionally in-process for Wave 4C. A storage-trait
// extension that lets us share the mapping across replicas is on the
// Wave 6 backlog.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::cimd::ClientIdMetadataDocument;

// --- Translated registration ---

/// The result of a successful CIMD → DCR translation.
///
/// `registered_client_id` is the opaque identifier the upstream
/// returned and is what the broker substitutes into outbound
/// /authorize and /token requests in place of the original CIMD URL.
/// `client_secret` is preserved when the upstream issues one (some
/// flows still require a secret even for "public" clients).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DcrRegisteredClient {
    /// Opaque identifier the upstream assigned to this client.
    pub registered_client_id: String,
    /// Optional client_secret returned by the upstream.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Echo of the registration response so callers can inspect any
    /// upstream-specific extensions.
    #[serde(default)]
    pub raw: Option<serde_json::Value>,
}

// --- Translator ---

/// Translate a CIMD document into an RFC 7591 registration request,
/// post it to `dcr_endpoint`, and return the upstream-assigned
/// `client_id`.
///
/// The translation strips fields that have no RFC 7591 equivalent and
/// rewrites `grant_types` / `response_types` defaults so an upstream
/// that requires them sees a valid request.
pub async fn translate_cimd_to_dcr(
    doc: &ClientIdMetadataDocument,
    dcr_endpoint: &str,
    http: &Client,
) -> Result<DcrRegisteredClient> {
    if doc.redirect_uris.is_empty() {
        bail!("CIMD document has no redirect_uris; refusing to register");
    }
    let payload = build_dcr_payload(doc);
    let resp = http
        .post(dcr_endpoint)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload.to_string())
        .send()
        .await
        .map_err(|e| anyhow!("upstream DCR call failed: {e}"))?;

    let status = resp.status();
    let body_bytes = resp
        .bytes()
        .await
        .map_err(|e| anyhow!("upstream DCR body read failed: {e}"))?;
    if !status.is_success() {
        bail!(
            "upstream DCR returned status {} body {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        );
    }
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| anyhow!("upstream DCR returned non-JSON: {e}"))?;
    let registered_client_id = parsed
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("upstream DCR response missing client_id"))?
        .to_string();
    let client_secret = parsed
        .get("client_secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(DcrRegisteredClient {
        registered_client_id,
        client_secret,
        raw: Some(parsed),
    })
}

/// Build the RFC 7591 JSON payload from a CIMD document. Field
/// rewrites:
///
///   * `client_id` (CIMD's self-id) is dropped because RFC 7591 says
///     the AS assigns it.
///   * `grant_types` defaults to `["authorization_code"]` when the
///     CIMD document does not list any (RFC 7591 §2 default).
///   * `response_types` defaults to `["code"]` similarly.
///   * `token_endpoint_auth_method` defaults to `none` because CIMD
///     clients are public.
fn build_dcr_payload(doc: &ClientIdMetadataDocument) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert(
        "redirect_uris".to_string(),
        serde_json::Value::Array(
            doc.redirect_uris
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    let grant_types = if doc.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        doc.grant_types.clone()
    };
    obj.insert(
        "grant_types".to_string(),
        serde_json::Value::Array(
            grant_types
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    let response_types = if doc.response_types.is_empty() {
        vec!["code".to_string()]
    } else {
        doc.response_types.clone()
    };
    obj.insert(
        "response_types".to_string(),
        serde_json::Value::Array(
            response_types
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    obj.insert(
        "token_endpoint_auth_method".to_string(),
        serde_json::Value::String(
            doc.token_endpoint_auth_method
                .clone()
                .unwrap_or_else(|| "none".to_string()),
        ),
    );
    if let Some(name) = &doc.client_name {
        obj.insert(
            "client_name".to_string(),
            serde_json::Value::String(name.clone()),
        );
    }
    if let Some(scope) = &doc.scope {
        obj.insert(
            "scope".to_string(),
            serde_json::Value::String(scope.clone()),
        );
    }
    if let Some(uri) = &doc.client_uri {
        obj.insert(
            "client_uri".to_string(),
            serde_json::Value::String(uri.clone()),
        );
    }
    if let Some(uri) = &doc.logo_uri {
        obj.insert(
            "logo_uri".to_string(),
            serde_json::Value::String(uri.clone()),
        );
    }
    if let Some(uri) = &doc.tos_uri {
        obj.insert(
            "tos_uri".to_string(),
            serde_json::Value::String(uri.clone()),
        );
    }
    if let Some(uri) = &doc.policy_uri {
        obj.insert(
            "policy_uri".to_string(),
            serde_json::Value::String(uri.clone()),
        );
    }
    if let Some(uri) = &doc.jwks_uri {
        obj.insert(
            "jwks_uri".to_string(),
            serde_json::Value::String(uri.clone()),
        );
    }
    if let Some(jwks) = &doc.jwks {
        obj.insert("jwks".to_string(), jwks.clone());
    }
    if let Some(s) = &doc.software_id {
        obj.insert(
            "software_id".to_string(),
            serde_json::Value::String(s.clone()),
        );
    }
    if let Some(s) = &doc.software_version {
        obj.insert(
            "software_version".to_string(),
            serde_json::Value::String(s.clone()),
        );
    }
    serde_json::Value::Object(obj)
}

// --- Cache ---

/// In-memory cache of CIMD URL → upstream-registered DCR client. Keyed
/// by a SHA-256 of the CIMD URL (so we never log the URL itself in a
/// cache key) plus a fingerprint of the document content (an etag if
/// known, otherwise a hash of the doc).
///
/// This is intentionally in-process for Wave 4C; a future storage-trait
/// extension that supports content-addressed entries will replace it.
pub struct CimdToDcrCache {
    entries: Mutex<HashMap<CacheKey, CachedRegistration>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    url_hash: [u8; 32],
    fingerprint: [u8; 32],
}

#[derive(Clone, Debug)]
struct CachedRegistration {
    registration: DcrRegisteredClient,
    /// When the entry was written. Held for log context and for a
    /// future TTL extension; the cache currently relies on fingerprint
    /// invalidation rather than wall-clock TTL.
    #[allow(dead_code)]
    cached_at: Instant,
}

impl Default for CimdToDcrCache {
    fn default() -> Self {
        Self::new()
    }
}

impl CimdToDcrCache {
    /// Build a fresh, empty cache.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Wrap in an `Arc` for handler injection.
    pub fn arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Look up a cached registration for `cimd_url` whose fingerprint
    /// matches `fingerprint`. A mismatched fingerprint (the document
    /// changed) returns `None` so the caller re-registers.
    pub async fn get(&self, cimd_url: &str, fingerprint: &[u8; 32]) -> Option<DcrRegisteredClient> {
        let key = CacheKey {
            url_hash: hash_url(cimd_url),
            fingerprint: *fingerprint,
        };
        let guard = self.entries.lock().await;
        guard.get(&key).map(|c| c.registration.clone())
    }

    /// Store a registration result.
    pub async fn put(
        &self,
        cimd_url: &str,
        fingerprint: &[u8; 32],
        registration: DcrRegisteredClient,
    ) {
        let key = CacheKey {
            url_hash: hash_url(cimd_url),
            fingerprint: *fingerprint,
        };
        let mut guard = self.entries.lock().await;
        guard.insert(
            key,
            CachedRegistration {
                registration,
                cached_at: Instant::now(),
            },
        );
    }

    /// Invalidate every entry for `cimd_url` regardless of fingerprint.
    /// Useful when an upstream tells us the registered client was
    /// revoked.
    pub async fn invalidate(&self, cimd_url: &str) {
        let url_hash = hash_url(cimd_url);
        let mut guard = self.entries.lock().await;
        guard.retain(|k, _| k.url_hash != url_hash);
    }
}

// --- PersistentKv-backed cache ---

/// `CimdToDcrCache`-shaped cache backed by
/// [`sbproxy_storage::PersistentKv`]. DCR registration
/// results are durable across process restarts and shared across
/// replicas, so the persistent (not ephemeral) trait is the right
/// fit: a fresh replica should not have to re-register every CIMD
/// client just because it cold-booted.
///
/// ## Key layout
///
/// `dcr:{url_hash_hex}:{fingerprint_hex}`. The URL is hashed (we
/// never store it) and the fingerprint encodes the doc content, so
/// a doc change naturally rotates the key without needing explicit
/// invalidation. URL-level invalidation uses `PersistentKv::list_prefix`
/// to enumerate every fingerprint under a given URL hash and delete
/// each in turn.
pub struct PersistentKvDcrCache {
    store: std::sync::Arc<dyn sbproxy_storage::PersistentKv>,
}

impl PersistentKvDcrCache {
    /// Build a cache backed by `store`. The store is held by `Arc`
    /// so the cache is cheap to clone for handler injection.
    pub fn new(store: std::sync::Arc<dyn sbproxy_storage::PersistentKv>) -> Self {
        Self { store }
    }

    /// Construct and return as `Arc<Self>`.
    pub fn arc(store: std::sync::Arc<dyn sbproxy_storage::PersistentKv>) -> Arc<Self> {
        Arc::new(Self::new(store))
    }

    fn cache_key(cimd_url: &str, fingerprint: &[u8; 32]) -> String {
        let url_hex = hex_lower(&hash_url(cimd_url));
        let fp_hex = hex_lower(fingerprint);
        format!("dcr:{url_hex}:{fp_hex}")
    }

    fn url_prefix(cimd_url: &str) -> String {
        let url_hex = hex_lower(&hash_url(cimd_url));
        format!("dcr:{url_hex}:")
    }

    /// Lookup a cached registration for `cimd_url` whose fingerprint
    /// matches `fingerprint`. Returns `None` when missing OR when the
    /// stored bytes fail to deserialize (treat schema drift as miss).
    pub async fn get(&self, cimd_url: &str, fingerprint: &[u8; 32]) -> Option<DcrRegisteredClient> {
        let key = Self::cache_key(cimd_url, fingerprint);
        match self.store.get(&key).await {
            Ok(Some(bytes)) => serde_json::from_slice::<DcrRegisteredClient>(&bytes).ok(),
            _ => None,
        }
    }

    /// Store `registration` under `(cimd_url, fingerprint)`. A
    /// serialization failure is logged but not propagated; the next
    /// request will re-register and try again.
    pub async fn put(
        &self,
        cimd_url: &str,
        fingerprint: &[u8; 32],
        registration: DcrRegisteredClient,
    ) {
        let key = Self::cache_key(cimd_url, fingerprint);
        match serde_json::to_vec(&registration) {
            Ok(bytes) => {
                if let Err(e) = self.store.put(&key, bytes::Bytes::from(bytes)).await {
                    tracing::warn!(
                        target: "mcp_gateway::cimd_to_dcr",
                        error = %e,
                        "PersistentKv put failed; DCR registration not cached"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "mcp_gateway::cimd_to_dcr",
                    error = %e,
                    "DCR registration serialize failed; not cached"
                );
            }
        }
    }

    /// Invalidate every cached registration for `cimd_url` regardless
    /// of fingerprint. Walks the URL's prefix in storage and deletes
    /// each key. Useful when an upstream signals the client was
    /// revoked.
    pub async fn invalidate(&self, cimd_url: &str) {
        let prefix = Self::url_prefix(cimd_url);
        let keys = match self.store.list_prefix(&prefix).await {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    target: "mcp_gateway::cimd_to_dcr",
                    error = %e,
                    "PersistentKv list_prefix failed during DCR invalidate"
                );
                return;
            }
        };
        for key in keys {
            if let Err(e) = self.store.delete(&key).await {
                tracing::warn!(
                    target: "mcp_gateway::cimd_to_dcr",
                    error = %e,
                    key = %key,
                    "PersistentKv delete failed during DCR invalidate"
                );
            }
        }
    }
}

/// Lowercase hex encoding of a 32-byte hash. Used to render cache
/// keys as printable strings without dragging in a hex crate.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// SHA-256 of `cimd_url`. Used as an opaque cache key so we never
/// store the URL itself.
fn hash_url(cimd_url: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(cimd_url.as_bytes());
    h.finalize().into()
}

/// Compute a content fingerprint for a CIMD document. When an ETag is
/// known we use it; otherwise we hash a stable JSON serialisation of
/// the document.
pub fn fingerprint(etag: Option<&str>, doc: &ClientIdMetadataDocument) -> [u8; 32] {
    let mut h = Sha256::new();
    if let Some(e) = etag {
        h.update(b"etag:");
        h.update(e.as_bytes());
    } else {
        // Deterministic by virtue of serde_json sorting object keys
        // alphabetically when we route through a BTreeMap. We do that
        // by re-serialising via a Value first, then via to_string on
        // a sorted map. Practically this is `to_string` which is
        // stable for the same input within a serde_json version.
        let body = serde_json::to_vec(doc).unwrap_or_default();
        h.update(b"doc:");
        h.update(&body);
    }
    h.finalize().into()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn fixture_doc() -> ClientIdMetadataDocument {
        ClientIdMetadataDocument {
            client_id: "https://client.example/.well-known/cimd".to_string(),
            client_name: Some("Demo Client".to_string()),
            redirect_uris: vec!["https://client.example/cb".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scope: Some("read write".to_string()),
            token_endpoint_auth_method: Some("none".to_string()),
            ..Default::default()
        }
    }

    // --- Fingerprint + cache unit tests ---

    #[test]
    fn fingerprint_changes_with_etag() {
        let doc = fixture_doc();
        let a = fingerprint(Some("\"v1\""), &doc);
        let b = fingerprint(Some("\"v2\""), &doc);
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_changes_with_doc_when_no_etag() {
        let mut doc = fixture_doc();
        let a = fingerprint(None, &doc);
        doc.client_name = Some("Other Name".to_string());
        let b = fingerprint(None, &doc);
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn cache_hit_after_put() {
        let cache = CimdToDcrCache::new();
        let doc = fixture_doc();
        let fp = fingerprint(Some("\"v1\""), &doc);
        let reg = DcrRegisteredClient {
            registered_client_id: "abc-123".to_string(),
            client_secret: None,
            raw: None,
        };
        cache.put(&doc.client_id, &fp, reg.clone()).await;
        let got = cache.get(&doc.client_id, &fp).await.expect("hit");
        assert_eq!(got.registered_client_id, "abc-123");
    }

    #[tokio::test]
    async fn cache_miss_when_fingerprint_changes() {
        let cache = CimdToDcrCache::new();
        let doc = fixture_doc();
        let fp1 = fingerprint(Some("\"v1\""), &doc);
        let fp2 = fingerprint(Some("\"v2\""), &doc);
        cache
            .put(
                &doc.client_id,
                &fp1,
                DcrRegisteredClient {
                    registered_client_id: "abc-123".to_string(),
                    client_secret: None,
                    raw: None,
                },
            )
            .await;
        assert!(cache.get(&doc.client_id, &fp1).await.is_some());
        assert!(cache.get(&doc.client_id, &fp2).await.is_none());
    }

    #[test]
    fn dcr_payload_defaults_grant_types_and_auth_method() {
        let mut doc = fixture_doc();
        doc.grant_types.clear();
        doc.response_types.clear();
        doc.token_endpoint_auth_method = None;
        let payload = build_dcr_payload(&doc);
        let obj = payload.as_object().unwrap();
        assert_eq!(
            obj.get("grant_types").unwrap(),
            &serde_json::json!(["authorization_code"])
        );
        assert_eq!(
            obj.get("response_types").unwrap(),
            &serde_json::json!(["code"])
        );
        assert_eq!(
            obj.get("token_endpoint_auth_method").unwrap(),
            &serde_json::json!("none")
        );
    }

    #[test]
    fn dcr_payload_drops_client_id() {
        let doc = fixture_doc();
        let payload = build_dcr_payload(&doc);
        // The CIMD client_id is the URL of the doc; RFC 7591 has the
        // AS assign it, so we must not propagate ours.
        assert!(payload.as_object().unwrap().get("client_id").is_none());
    }

    // --- Mock-backed translate tests ---

    struct MockDcrServer {
        addr: SocketAddr,
        hits: Arc<AtomicUsize>,
    }

    impl MockDcrServer {
        async fn spawn(response_body: String, status: u16) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let hits = Arc::new(AtomicUsize::new(0));
            let hits_clone = hits.clone();
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            tokio::spawn(async move {
                loop {
                    let (mut sock, _) = match listener.accept().await {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    let mut buf = vec![0u8; 8192];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                    hits_clone.fetch_add(1, Ordering::SeqCst);
                }
            });
            Self { addr, hits }
        }

        fn url(&self) -> String {
            format!("http://{}/register", self.addr)
        }
    }

    #[tokio::test]
    async fn translate_returns_registered_client_id() {
        let server = MockDcrServer::spawn(
            r#"{"client_id":"upstream-abc","client_secret":"shh"}"#.to_string(),
            200,
        )
        .await;
        let http = Client::new();
        let doc = fixture_doc();
        let reg = translate_cimd_to_dcr(&doc, &server.url(), &http)
            .await
            .expect("translate ok");
        assert_eq!(reg.registered_client_id, "upstream-abc");
        assert_eq!(reg.client_secret.as_deref(), Some("shh"));
        assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn translate_propagates_upstream_failure() {
        let server =
            MockDcrServer::spawn(r#"{"error":"invalid_redirect_uri"}"#.to_string(), 400).await;
        // Our toy HTTP responder always sets the literal " OK" reason
        // text; reqwest cares about the numeric status only.
        let http = Client::new();
        let doc = fixture_doc();
        let err = translate_cimd_to_dcr(&doc, &server.url(), &http)
            .await
            .expect_err("must fail on 400");
        assert!(err.to_string().contains("400"), "got: {err}");
    }

    #[tokio::test]
    async fn translate_rejects_response_without_client_id() {
        let server = MockDcrServer::spawn(r#"{"unrelated":true}"#.to_string(), 200).await;
        let http = Client::new();
        let doc = fixture_doc();
        let err = translate_cimd_to_dcr(&doc, &server.url(), &http)
            .await
            .expect_err("must fail without client_id");
        assert!(err.to_string().contains("client_id"), "got: {err}");
    }

    #[tokio::test]
    async fn translate_refuses_doc_without_redirect_uris() {
        let server = MockDcrServer::spawn(r#"{"client_id":"x"}"#.to_string(), 200).await;
        let http = Client::new();
        let mut doc = fixture_doc();
        doc.redirect_uris.clear();
        let err = translate_cimd_to_dcr(&doc, &server.url(), &http)
            .await
            .expect_err("empty redirect_uris must fail before any HTTP call");
        assert!(err.to_string().contains("redirect_uris"), "got: {err}");
        assert_eq!(
            server.hits.load(Ordering::SeqCst),
            0,
            "translate must short-circuit before hitting the upstream"
        );
    }

    // --- PersistentKv-backed cache tests ---

    fn persistent_kv() -> std::sync::Arc<dyn sbproxy_storage::PersistentKv> {
        std::sync::Arc::new(crate::local_store::LocalStore::new())
    }

    fn fixture_registration(client_id: &str) -> DcrRegisteredClient {
        DcrRegisteredClient {
            registered_client_id: client_id.to_string(),
            client_secret: Some("secret".to_string()),
            raw: Some(serde_json::json!({"client_id_issued_at": 1_700_000_000})),
        }
    }

    #[tokio::test]
    async fn persistent_kv_cache_round_trip() {
        let cache = PersistentKvDcrCache::new(persistent_kv());
        let url = "https://client.example/.well-known/cimd";
        let fp = [0xaau8; 32];
        let reg = fixture_registration("client-abc");

        cache.put(url, &fp, reg.clone()).await;
        let got = cache.get(url, &fp).await.expect("entry should be present");
        assert_eq!(got.registered_client_id, reg.registered_client_id);
        assert_eq!(got.client_secret, reg.client_secret);
        assert_eq!(got.raw, reg.raw);
    }

    #[tokio::test]
    async fn persistent_kv_cache_fingerprint_mismatch_returns_none() {
        let cache = PersistentKvDcrCache::new(persistent_kv());
        let url = "https://client.example/.well-known/cimd";
        cache
            .put(url, &[0x01u8; 32], fixture_registration("c1"))
            .await;

        // Different fingerprint -> miss (key is content-addressed).
        assert!(cache.get(url, &[0x02u8; 32]).await.is_none());
    }

    #[tokio::test]
    async fn persistent_kv_cache_invalidate_removes_all_fingerprints_for_url() {
        let cache = PersistentKvDcrCache::new(persistent_kv());
        let url = "https://client.example/.well-known/cimd";
        // Two entries for the same URL under different fingerprints
        // (the document changed once and re-registered).
        cache
            .put(url, &[0x01u8; 32], fixture_registration("c1"))
            .await;
        cache
            .put(url, &[0x02u8; 32], fixture_registration("c2"))
            .await;
        // And one for an unrelated URL that must survive.
        let other_url = "https://other.example/.well-known/cimd";
        cache
            .put(other_url, &[0x01u8; 32], fixture_registration("c3"))
            .await;

        cache.invalidate(url).await;

        assert!(cache.get(url, &[0x01u8; 32]).await.is_none());
        assert!(cache.get(url, &[0x02u8; 32]).await.is_none());
        assert!(
            cache.get(other_url, &[0x01u8; 32]).await.is_some(),
            "invalidation must not bleed across URLs"
        );
    }

    #[tokio::test]
    async fn persistent_kv_cache_corrupt_stored_bytes_returns_none() {
        let kv = persistent_kv();
        let url = "https://client.example/.well-known/cimd";
        let fp = [0x42u8; 32];
        // Pre-seed garbage at the cache key. Defends against schema
        // drift across deploys: a struct field rename should not
        // wedge the broker into a hard error.
        kv.put(
            &PersistentKvDcrCache::cache_key(url, &fp),
            bytes::Bytes::from_static(b"not valid json"),
        )
        .await
        .unwrap();
        let cache = PersistentKvDcrCache::new(kv);

        assert!(
            cache.get(url, &fp).await.is_none(),
            "garbage stored bytes must read as miss, not error or panic"
        );
    }
}
