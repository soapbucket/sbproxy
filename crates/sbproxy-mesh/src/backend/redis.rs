//! Redis backend for mesh persistence and cross-cluster federation.
//!
//! Originally a thin wrapper around `redis::aio::MultiplexedConnection`;
//! Wave 6G migrated this onto the workspace storage trait surface
//! (`PersistentKv` + `EphemeralKv` + `SetKv`) so deployments can swap
//! backends without touching mesh code. Two consumers are unchanged:
//!
//! 1. **Persistence** (§4 of the hybrid design doc): the mesh leader
//!    periodically snapshots local CRDTs here. Other nodes read on
//!    cold start to warm up faster than pure gossip convergence.
//! 2. **Federation**: peer clusters publish summary keys; every node
//!    pulls sibling-cluster summaries on a fixed cadence and merges
//!    them into the local CRDT.
//!
//! The TTL split (snapshot writes vs. plain writes) maps onto the two
//! KV traits: `EphemeralKv` for TTL-bearing writes, `PersistentKv`
//! for non-TTL writes. Set membership goes through `SetKv`.

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use sbproxy_storage::{EphemeralKv, PersistentKv, RedisStore, SetKv};
use url::Url;

// --- WOR-48: credential-safe redaction for Redis DSNs ---

/// Redact the password component of a Redis URL so the result is safe
/// to log or surface in an error message.
///
/// Redis DSNs commonly embed credentials inline, e.g.
/// `redis://user:password@host:6379/0`. Startup crashes and connection
/// errors get shipped to shared observability systems, so leaking the
/// raw DSN is a credential disclosure. This helper parses the URL with
/// the `url` crate, replaces the password with `***`, and returns the
/// rebuilt string. Username (when present without a password) is left
/// alone because usernames are typically public ACL identifiers.
///
/// Falls back to `"<unparseable redis url>"` for inputs that cannot be
/// parsed at all. Never returns the original string in that path. That
/// is deliberate: an unparseable input might be a typo that pasted a
/// password into the wrong field, and echoing it back through a log
/// would leak it.
pub(crate) fn redact_redis_url(url: &str) -> String {
    let Ok(parsed) = Url::parse(url) else {
        return "<unparseable redis url>".to_string();
    };
    if parsed.password().is_none() {
        // No password component, nothing to redact. Hand back the
        // input verbatim (parsed and serialized are equivalent here
        // for valid URLs, but using the original avoids cosmetic
        // re-encoding differences).
        return url.to_string();
    }
    let mut redacted = parsed.clone();
    // `set_password(Some("***"))` only fails on cannot-be-a-base URLs
    // (data:, mailto:), which redis:// is not. Guard anyway so a future
    // schema accident does not panic.
    if redacted.set_password(Some("***")).is_err() {
        return "<unparseable redis url>".to_string();
    }
    redacted.to_string()
}

/// Configuration for connecting to a Redis instance via the storage
/// trait surface.
///
/// Kept for backwards compatibility with `with_redis_url` / call sites
/// that still want to construct the backend from a DSN + prefix pair.
#[derive(Debug, Clone)]
pub struct RedisBackendConfig {
    /// Redis connection URL (e.g. redis://localhost:6379/0).
    pub url: String,
    /// Key prefix applied to every read/write. Lets two mesh federations
    /// share a Redis without colliding. Default: `sbproxy:mesh:`.
    pub key_prefix: String,
}

impl RedisBackendConfig {
    /// Create a new config with the given Redis URL. Uses the default
    /// `sbproxy:mesh:` key prefix.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            key_prefix: "sbproxy:mesh:".to_string(),
        }
    }

    /// Builder-style setter for the key prefix.
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.key_prefix = prefix.to_string();
        self
    }
}

/// Trait-driven facade over a workspace storage backend, exposing the
/// surface mesh persistence + federation expect (`get`, `set` with TTL,
/// `sadd` / `srem` / `smembers`, prefix scan).
///
/// Holds three trait objects so a single `RedisStore` can satisfy all
/// roles in production while tests inject `MockPersistentKv` /
/// `MockEphemeralKv` / `MockSetKv` from the storage crate's `mock`
/// feature.
pub struct RedisBackend {
    persistent: Arc<dyn PersistentKv>,
    ephemeral: Arc<dyn EphemeralKv>,
    set: Arc<dyn SetKv>,
    /// Recorded for `Self::url` / `Self::key_prefix` accessors. Empty
    /// when the backend was assembled via `from_traits`.
    url: String,
    /// Recorded prefix string. Reflects the *mesh* convention, i.e.
    /// retains a trailing colon if the caller supplied one. The wrapped
    /// `RedisStore` strips that colon at construction time so on-wire
    /// keys stay byte-for-byte compatible with the pre-6G layout.
    key_prefix: String,
}

impl std::fmt::Debug for RedisBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisBackend")
            .field("url", &self.url)
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl RedisBackend {
    /// Backwards-compatible constructor. Builds a single `RedisStore`
    /// and uses it for all three trait roles.
    ///
    /// `key_prefix` follows the mesh convention (typically ending in
    /// `:`, e.g. `"sbproxy:mesh:"`); the trailing colon is stripped
    /// before being handed to `RedisStore::new` because `RedisStore`
    /// re-inserts the separator. The on-wire keys are unchanged.
    ///
    /// Returns `Err` when the supplied DSN is unparseable. WOR-48: the
    /// previous implementation panicked here with the raw `config.url`
    /// in the panic message, leaking any inline credentials into crash
    /// logs. The error returned now redacts the password component via
    /// `redact_redis_url`.
    pub fn new(config: RedisBackendConfig) -> Result<Self> {
        let store_prefix = trim_trailing_colon(&config.key_prefix);
        let store = RedisStore::new(&config.url, store_prefix.to_string()).map_err(|e| {
            // Two-stage redaction: strip credentials out of the DSN
            // before it ever lands in the error message, *and* wipe
            // any echo of the URL that `RedisStore::new`'s error string
            // may have included by reporting a kind tag rather than
            // the inner Display.
            anyhow::anyhow!(
                "invalid redis url '{}': {}",
                redact_redis_url(&config.url),
                e.kind()
            )
        })?;
        let store = Arc::new(store);
        Ok(Self {
            persistent: store.clone() as Arc<dyn PersistentKv>,
            ephemeral: store.clone() as Arc<dyn EphemeralKv>,
            set: store as Arc<dyn SetKv>,
            url: config.url,
            key_prefix: config.key_prefix,
        })
    }

    /// Backwards-compat shim used by the bootstrap path. Equivalent to
    /// `RedisBackend::new(RedisBackendConfig::new(url).with_prefix(prefix))`.
    ///
    /// Returns `Err` on an unparseable DSN, with the redacted form in
    /// the error (see [`Self::new`]).
    pub fn with_redis_url(url: &str, key_prefix: &str) -> Result<Self> {
        Self::new(RedisBackendConfig::new(url).with_prefix(key_prefix))
    }

    /// Dependency-injection constructor. Tests pass `MockPersistentKv`
    /// / `MockEphemeralKv` / `MockSetKv`; production assemblies pass a
    /// shared `Arc<RedisStore>`.
    ///
    /// `key_prefix` is metadata only here. Backends are responsible for
    /// their own prefixing.
    pub fn from_traits(
        persistent: Arc<dyn PersistentKv>,
        ephemeral: Arc<dyn EphemeralKv>,
        set: Arc<dyn SetKv>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
            set,
            url: String::new(),
            key_prefix: String::new(),
        }
    }

    /// Configured Redis URL. Empty when assembled via `from_traits`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Configured key prefix. Empty when assembled via `from_traits`.
    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    /// Get a byte-array value. Returns `None` on missing key.
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let v = self
            .persistent
            .get(key)
            .await
            .with_context(|| format!("storage GET failed for key '{key}'"))?;
        Ok(v.map(|b| b.to_vec()))
    }

    /// Set a byte-array value with optional TTL (`0` = no expiry, durable
    /// `PersistentKv::put`; non-zero = `EphemeralKv::put` with the TTL).
    pub async fn set(&self, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        let payload = Bytes::copy_from_slice(value);
        if ttl_secs == 0 {
            self.persistent
                .put(key, payload)
                .await
                .with_context(|| format!("storage PUT (durable) failed for key '{key}'"))?;
        } else {
            self.ephemeral
                .put(key, payload, std::time::Duration::from_secs(ttl_secs))
                .await
                .with_context(|| format!("storage PUT (ttl={ttl_secs}s) failed for key '{key}'"))?;
        }
        Ok(())
    }

    /// Delete a key. Returns `true` unconditionally because the trait
    /// surface does not expose pre-delete existence and the mesh call
    /// sites do not depend on the boolean (cleanup paths only).
    pub async fn delete(&self, key: &str) -> Result<bool> {
        self.persistent
            .delete(key)
            .await
            .with_context(|| format!("storage DELETE failed for key '{key}'"))?;
        Ok(true)
    }

    /// Add a member to a set.
    pub async fn sadd(&self, key: &str, member: &str) -> Result<()> {
        let members = [Bytes::copy_from_slice(member.as_bytes())];
        self.set
            .sadd(key, &members)
            .await
            .with_context(|| format!("storage SADD failed for key '{key}'"))?;
        Ok(())
    }

    /// Remove a member from a set.
    pub async fn srem(&self, key: &str, member: &str) -> Result<()> {
        let members = [Bytes::copy_from_slice(member.as_bytes())];
        self.set
            .srem(key, &members)
            .await
            .with_context(|| format!("storage SREM failed for key '{key}'"))?;
        Ok(())
    }

    /// Return all members of a set as UTF-8 strings. Empty set returned
    /// as empty `Vec`. Non-UTF-8 members are lossily converted, matching
    /// the pre-6G `Vec<String>` shape.
    pub async fn smembers(&self, key: &str) -> Result<Vec<String>> {
        let members = self
            .set
            .smembers(key)
            .await
            .with_context(|| format!("storage SMEMBERS failed for key '{key}'"))?;
        Ok(members
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect())
    }

    /// Enumerate keys under a prefix. The supplied pattern is a *glob*
    /// in the legacy API (`"foo:*"`); we strip a trailing `*` so the
    /// trait's prefix-only `list_prefix` behaves identically. Returned
    /// keys are relative to the backend's prefix because that is the
    /// shape `PersistentKv::list_prefix` already produces.
    pub async fn scan_prefix(&self, pattern_without_prefix: &str) -> Result<Vec<String>> {
        let prefix = pattern_without_prefix
            .strip_suffix('*')
            .unwrap_or(pattern_without_prefix);
        let keys = self
            .persistent
            .list_prefix(prefix)
            .await
            .with_context(|| format!("storage LIST_PREFIX failed for prefix '{prefix}'"))?;
        Ok(keys)
    }

    /// EXPIRE-equivalent. The trait surface lacks a standalone TTL
    /// reset, so this re-puts the current value through `EphemeralKv`
    /// to attach the new TTL. No-op when the key is absent.
    pub async fn expire(&self, key: &str, ttl_secs: u64) -> Result<()> {
        let Some(value) =
            self.persistent.get(key).await.with_context(|| {
                format!("storage GET (for EXPIRE refresh) failed for key '{key}'")
            })?
        else {
            return Ok(());
        };
        self.ephemeral
            .put(key, value, std::time::Duration::from_secs(ttl_secs))
            .await
            .with_context(|| format!("storage PUT (EXPIRE refresh) failed for key '{key}'"))?;
        Ok(())
    }
}

/// Drop one trailing `:` so a mesh-style prefix like `"sbproxy:mesh:"`
/// produces the same on-wire keys when reused as a `RedisStore` prefix
/// (`RedisStore::key_for` re-inserts the separator).
fn trim_trailing_colon(prefix: &str) -> &str {
    prefix.strip_suffix(':').unwrap_or(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbproxy_storage::mock::{MockEphemeralKv, MockPersistentKv, MockSetKv};

    fn mock_backend() -> RedisBackend {
        RedisBackend::from_traits(
            Arc::new(MockPersistentKv::new()),
            Arc::new(MockEphemeralKv::new()),
            Arc::new(MockSetKv::new()),
        )
    }

    #[test]
    fn config_stores_url_and_prefix() {
        let cfg = RedisBackendConfig::new("redis://myhost:6380");
        assert_eq!(cfg.url, "redis://myhost:6380");
        assert_eq!(cfg.key_prefix, "sbproxy:mesh:");
        let cfg2 = cfg.clone().with_prefix("test:");
        assert_eq!(cfg2.key_prefix, "test:");
    }

    #[test]
    fn backend_new_defers_connection() {
        let backend = RedisBackend::new(RedisBackendConfig::new("redis://127.0.0.1:6379"))
            .expect("valid url constructs ok");
        assert_eq!(backend.url(), "redis://127.0.0.1:6379");
        assert_eq!(backend.key_prefix(), "sbproxy:mesh:");
    }

    #[test]
    fn with_redis_url_shim_round_trips() {
        let backend = RedisBackend::with_redis_url("redis://127.0.0.1:6379", "p:")
            .expect("valid url constructs ok");
        assert_eq!(backend.url(), "redis://127.0.0.1:6379");
        assert_eq!(backend.key_prefix(), "p:");
    }

    // --- WOR-48: redactor + fallible constructor tests ---

    #[test]
    fn redact_redis_url_strips_password() {
        assert_eq!(
            redact_redis_url("redis://user:secret@host:6379/0"),
            "redis://user:***@host:6379/0"
        );
    }

    #[test]
    fn redact_redis_url_passthrough_when_no_password() {
        // No userinfo at all: nothing to redact, value is returned verbatim.
        assert_eq!(redact_redis_url("redis://host:6379"), "redis://host:6379");
        // Username present, password absent: ACL usernames are public,
        // so the username is preserved.
        let with_user = redact_redis_url("redis://aclname@host:6379");
        assert!(
            with_user.contains("aclname"),
            "expected username preserved, got {with_user}"
        );
        assert!(!with_user.contains("***"));
    }

    #[test]
    fn redact_redis_url_unparseable_returns_sentinel() {
        // A bare string is not a URL at all. Must NOT echo the input
        // back, because operators sometimes paste secrets into the
        // wrong field and we don't want logs to capture them.
        assert_eq!(redact_redis_url("not a url"), "<unparseable redis url>");
    }

    #[test]
    fn redact_redis_url_handles_rediss_and_path() {
        // TLS scheme + database index must round-trip cleanly.
        assert_eq!(
            redact_redis_url("rediss://admin:hunter2@redis.prod.example.com:6380/3"),
            "rediss://admin:***@redis.prod.example.com:6380/3"
        );
    }

    #[test]
    fn backend_new_invalid_url_returns_err_without_panic() {
        // Garbage input: must be `Err`, not a panic.
        let result = RedisBackend::new(RedisBackendConfig::new("not a url at all"));
        let err = result.expect_err("invalid url should error, not panic");
        let msg = format!("{err}");
        // The error string must not echo the original input verbatim
        // (WOR-48 leak vector); the redactor returns the sentinel
        // for unparseable input.
        assert!(
            msg.contains("<unparseable redis url>"),
            "expected redacted sentinel in error, got: {msg}"
        );
    }

    #[test]
    fn backend_new_with_password_in_url_does_not_leak_secret() {
        // Even if the URL is well-formed but `RedisStore::new` rejects
        // it for some other reason, the password must never reach the
        // error message. We use an obviously-malformed scheme to force
        // the redis client to reject the DSN.
        let dsn = "http://user:topsecret@host:6379";
        let result = RedisBackend::new(RedisBackendConfig::new(dsn));
        let err = result.expect_err("non-redis scheme should error");
        let msg = format!("{err}");
        assert!(
            !msg.contains("topsecret"),
            "password leaked into error message: {msg}"
        );
        // The redacted form *should* show up so operators can identify
        // which DSN was at fault.
        assert!(
            msg.contains("***"),
            "expected redacted password marker in error, got: {msg}"
        );
    }

    #[test]
    fn trim_trailing_colon_strips_one_only() {
        assert_eq!(trim_trailing_colon("sbproxy:mesh:"), "sbproxy:mesh");
        assert_eq!(trim_trailing_colon("plain"), "plain");
        // Only one trailing colon is removed, matching `RedisStore::key_for`'s
        // "{prefix}:{key}" join.
        assert_eq!(trim_trailing_colon("a::"), "a:");
    }

    #[tokio::test]
    async fn set_get_delete_roundtrip_durable() {
        let b = mock_backend();
        b.set("k1", b"hello", 0).await.expect("set");
        assert_eq!(b.get("k1").await.expect("get"), Some(b"hello".to_vec()));
        assert!(b.delete("k1").await.expect("delete"));
        assert_eq!(b.get("k1").await.expect("get-after-delete"), None);
    }

    #[tokio::test]
    async fn set_with_ttl_routes_to_ephemeral() {
        let persistent = Arc::new(MockPersistentKv::new());
        let ephemeral = Arc::new(MockEphemeralKv::new());
        let set = Arc::new(MockSetKv::new());
        let b = RedisBackend::from_traits(persistent.clone(), ephemeral.clone(), set);
        b.set("session", b"payload", 60).await.expect("set ttl");
        // The TTL write should land in the ephemeral store, not the
        // durable one.
        assert_eq!(persistent.get("session").await.expect("p"), None);
        assert_eq!(
            ephemeral.get("session").await.expect("e"),
            Some(Bytes::from_static(b"payload"))
        );
    }

    #[tokio::test]
    async fn set_membership_round_trip() {
        let b = mock_backend();
        b.sadd("members", "alpha").await.expect("sadd alpha");
        b.sadd("members", "beta").await.expect("sadd beta");
        let mut members = b.smembers("members").await.expect("smembers");
        members.sort();
        assert_eq!(members, vec!["alpha".to_string(), "beta".to_string()]);
        b.srem("members", "alpha").await.expect("srem");
        let after = b.smembers("members").await.expect("smembers after");
        assert_eq!(after, vec!["beta".to_string()]);
    }

    #[tokio::test]
    async fn scan_prefix_strips_trailing_glob() {
        let b = mock_backend();
        b.set("cluster:state:n0", b"v0", 0).await.expect("set n0");
        b.set("cluster:state:n1", b"v1", 0).await.expect("set n1");
        b.set("other:state:n9", b"v9", 0).await.expect("set other");
        let mut keys = b.scan_prefix("cluster:state:*").await.expect("scan");
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "cluster:state:n0".to_string(),
                "cluster:state:n1".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn expire_refreshes_ttl_via_ephemeral() {
        let persistent = Arc::new(MockPersistentKv::new());
        let ephemeral = Arc::new(MockEphemeralKv::new());
        let set = Arc::new(MockSetKv::new());
        let b = RedisBackend::from_traits(persistent.clone(), ephemeral.clone(), set);
        // Seed the durable store first.
        b.set("k", b"v", 0).await.expect("durable seed");
        // Refresh: should read from durable, write to ephemeral.
        b.expire("k", 30).await.expect("expire");
        assert_eq!(
            ephemeral.get("k").await.expect("e"),
            Some(Bytes::from_static(b"v"))
        );
    }

    #[tokio::test]
    async fn expire_missing_key_is_noop() {
        let b = mock_backend();
        b.expire("nope", 30).await.expect("noop ok");
        assert_eq!(b.get("nope").await.expect("still missing"), None);
    }

    // Integration test (requires live Redis at REDIS_URL). Exercises the
    // full RedisStore-backed assembly through the legacy facade so the
    // on-wire keys still land where mesh persistence expects them.
    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn e2e_set_get_delete_roundtrip() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let b = RedisBackend::new(RedisBackendConfig::new(&url).with_prefix("sbproxy:mesh:test:"))
            .expect("valid REDIS_URL");
        let key = format!("rt-{}", std::process::id());
        b.set(&key, b"hello", 10).await.unwrap();
        let got = b.get(&key).await.unwrap();
        assert_eq!(got, Some(b"hello".to_vec()));
        assert!(b.delete(&key).await.unwrap());
        assert_eq!(b.get(&key).await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL env"]
    async fn e2e_set_membership() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let b = RedisBackend::new(RedisBackendConfig::new(&url).with_prefix("sbproxy:mesh:test:"))
            .expect("valid REDIS_URL");
        let setk = format!("set-{}", std::process::id());
        b.sadd(&setk, "alpha").await.unwrap();
        b.sadd(&setk, "beta").await.unwrap();
        let mut members = b.smembers(&setk).await.unwrap();
        members.sort();
        assert_eq!(members, vec!["alpha".to_string(), "beta".to_string()]);
        b.srem(&setk, "alpha").await.unwrap();
        b.delete(&setk).await.unwrap();
    }
}
