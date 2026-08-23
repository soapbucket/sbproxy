// Session storage for the MCP OAuth 2.1 broker.
//
// Each `state` value the broker mints for an upstream `/authorize`
// hop is bound to a `Session` row containing the original client
// state, redirect URI, resource URI (RFC 8707), and the client's
// PKCE challenge. The row is single-use: `take` removes it from the
// store, which guarantees that a leaked or replayed `state` cannot
// be exchanged for a code more than once.
//
// 4B.1 shipped `InMemorySessionStore`. 4B.3 added a Redis-backed
// `RedisSessionStore` that talked to `redis::Client` directly. Wave
// 6D rewrote `RedisSessionStore` as a thin wrapper around
// `Arc<dyn EphemeralKv>`: the SETEX / GETDEL flow maps cleanly onto
// the trait's `put` / `take` shape, and tests now drive the broker
// with `MockEphemeralKv` instead of standing up a Redis instance.
// The legacy `RedisSessionStore::new(url, prefix, ttl)` constructor
// is preserved as a backwards-compatible shim that builds a
// `RedisStore` internally so existing call sites and sb.yml configs
// keep working without change.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_storage::{EphemeralKv, RedisStore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const DEFAULT_SESSION_CAPACITY: usize = 4_096;

// --- Session row ---

/// One pending authorization request, keyed by the broker's outbound
/// `state` value.
///
/// Serializable so the Redis-backed store can round-trip rows as JSON
/// values with `SETEX` / `GETDEL`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    /// The original client-supplied `state`. The broker mints a
    /// separate state for the upstream hop so that the upstream AS
    /// cannot observe (or correlate against) the client's state.
    pub client_state: String,
    /// The client's original `redirect_uri`. Validated against the
    /// `allowed_redirect_uris` list at /authorize time.
    pub redirect_uri: String,
    /// RFC 8707 resource indicator. Required by the broker even
    /// though the wider OAuth 2.1 spec leaves it optional, because
    /// MCP servers always identify themselves.
    pub resource_uri: String,
    /// The client's PKCE code challenge. The broker stores this and
    /// forwards it to the upstream AS verbatim. The PKCE verifier
    /// never leaves the client.
    pub code_challenge: String,
    /// PKCE method. Only `S256` is supported by the request layer,
    /// but the field is stored verbatim for forward compatibility.
    pub code_challenge_method: String,
}

// --- Trait ---

/// Storage backend for in-flight authorization sessions.
///
/// Implementations must be `Send + Sync` so the axum router can hold
/// them inside an `Arc`. `take` MUST remove the row before returning
/// it; the broker relies on this to make `state` single-use.
#[async_trait]
pub trait SessionStore: Send + Sync + 'static {
    /// Insert a session under `state` with the configured TTL. The
    /// implementation is free to evict expired rows on insert.
    async fn put(&self, state: &str, session: Session) -> Result<()>;

    /// Atomically remove and return the session for `state` if it
    /// exists and has not expired.
    async fn take(&self, state: &str) -> Option<Session>;
}

// --- In-memory implementation ---

struct Entry {
    session: Session,
    expires_at: Instant,
}

/// In-process `HashMap` backed session store. Single-process only;
/// multi-replica deployments should use the Redis store landing in
/// 4B.3.
pub struct InMemorySessionStore {
    inner: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    capacity: usize,
}

impl InMemorySessionStore {
    /// Builds a new store with the given TTL applied to every entry.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_SESSION_CAPACITY)
            .expect("non-zero default authorization-session capacity")
    }

    /// Build a store with a strict live-session capacity. A new state
    /// fails closed at capacity; live sessions are never evicted to make
    /// room for an attacker-controlled request.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Result<Self> {
        if ttl.is_zero() || capacity == 0 {
            return Err(anyhow!(
                "session TTL and capacity must be greater than zero"
            ));
        }
        Ok(Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            capacity,
        })
    }

    /// Convenience constructor for callers that hold the store inside
    /// an `Arc` (the only shape `Router` accepts).
    pub fn arc(ttl: Duration) -> Arc<Self> {
        Arc::new(Self::new(ttl))
    }

    /// Drops every entry whose `expires_at` is in the past. Called
    /// from `put`, but exposed for tests.
    pub async fn purge_expired(&self) {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        guard.retain(|_, entry| entry.expires_at > now);
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn put(&self, state: &str, session: Session) -> Result<()> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        // Inline purge keeps the map bounded without spawning a
        // background sweeper task.
        guard.retain(|_, entry| entry.expires_at > now);
        if !guard.contains_key(state) && guard.len() >= self.capacity {
            return Err(anyhow!(
                "authorization session capacity {} reached",
                self.capacity
            ));
        }
        guard.insert(
            state.to_string(),
            Entry {
                session,
                expires_at: now + self.ttl,
            },
        );
        Ok(())
    }

    async fn take(&self, state: &str) -> Option<Session> {
        let now = Instant::now();
        let mut guard = self.inner.lock().await;
        let entry = guard.remove(state)?;
        if entry.expires_at <= now {
            // Expired row: drop on the floor.
            return None;
        }
        Some(entry.session)
    }
}

// --- Storage-backed implementation (Wave 6D) ---

/// Backend-agnostic implementation of `SessionStore` that persists
/// session rows in any [`EphemeralKv`] backend.
///
/// Sessions are JSON-encoded and stored at `<key_prefix>:<state>` with
/// the configured TTL. `take` calls the trait's atomic `take`
/// (Redis GETDEL semantics on the Redis backend, `HashMap::remove`
/// on the in-memory mock) so the single-use contract is preserved
/// regardless of which backend is in use.
///
/// The struct is named `RedisSessionStore` for backwards compatibility
/// with the 4B.3 binary layout, but as of Wave 6D it accepts any
/// `Arc<dyn EphemeralKv>`. The legacy `RedisSessionStore::new(url, ...)`
/// constructor is preserved as a shim that builds a `RedisStore`
/// internally so existing call sites and sb.yml configs keep working.
///
/// Cloning the store is cheap: the inner `Arc<dyn EphemeralKv>` is
/// shared by reference and the storage trait is `Send + Sync`.
pub struct RedisSessionStore {
    kv: Arc<dyn EphemeralKv>,
    key_prefix: String,
    ttl: Duration,
}

impl RedisSessionStore {
    /// Build a new store on top of any `EphemeralKv` backend. This is
    /// the preferred constructor for new call sites: tests inject
    /// `MockEphemeralKv`, production injects `RedisStore` (or any
    /// future backend).
    pub fn with_storage(
        kv: Arc<dyn EphemeralKv>,
        key_prefix: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            kv,
            key_prefix: key_prefix.into(),
            ttl,
        }
    }

    /// `Arc`-wrapped convenience for the storage-backed constructor.
    pub fn with_storage_arc(
        kv: Arc<dyn EphemeralKv>,
        key_prefix: impl Into<String>,
        ttl: Duration,
    ) -> Arc<Self> {
        Arc::new(Self::with_storage(kv, key_prefix, ttl))
    }

    /// Backwards-compatible Redis URL constructor. Validates the URL
    /// eagerly so misconfigured callers fail at boot rather than on
    /// the first session write. Connection establishment is lazy
    /// inside `RedisStore`, so a temporarily unavailable Redis at
    /// construction time is not fatal.
    ///
    /// Internally this builds a [`RedisStore`] with the given prefix
    /// and forwards to [`Self::with_storage`]. New call sites should
    /// prefer the trait-based constructor; this shim exists only so
    /// the 4B.3 public API and existing sb.yml `redis_url:` fields
    /// keep working unchanged.
    pub fn new(redis_url: &str, key_prefix: impl Into<String>, ttl: Duration) -> Result<Self> {
        let prefix = key_prefix.into();
        let store = RedisStore::new(redis_url, prefix.clone())
            .map_err(|e| anyhow!("invalid redis url {redis_url:?}: {e}"))?;
        Ok(Self::with_storage(Arc::new(store), prefix, ttl))
    }

    /// `Arc`-wrapped convenience for callers building `AppState`.
    /// Delegates to [`Self::new`].
    pub fn arc(redis_url: &str, key_prefix: impl Into<String>, ttl: Duration) -> Result<Arc<Self>> {
        Ok(Arc::new(Self::new(redis_url, key_prefix, ttl)?))
    }

    /// Returns the fully-qualified key for `state`. Public so
    /// operators can grep their backing store for in-flight rows
    /// matching the broker's prefix. The prefix is applied here
    /// rather than inside the trait so backends with their own
    /// namespacing (e.g. `RedisStore::key_for`) still see the full
    /// `<key_prefix>:<state>` key on the wire.
    pub fn key_for(&self, state: &str) -> String {
        format!("{}:{}", self.key_prefix, state)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn put(&self, state: &str, session: Session) -> Result<()> {
        let key = self.key_for(state);
        let payload = Bytes::from(
            serde_json::to_vec(&session)
                .map_err(|error| anyhow!("failed to serialize authorization session: {error}"))?,
        );
        // Trait `put` enforces TTL itself. `EphemeralKv` implementations
        // pin a 1s minimum (Redis SETEX rejects 0); duplicating that
        // floor here would just hide the trait's behavior from logs.
        self.kv
            .put(&key, payload, self.ttl)
            .await
            .map_err(|error| anyhow!("authorization session persistence failed: {error}"))
    }

    async fn take(&self, state: &str) -> Option<Session> {
        let key = self.key_for(state);
        // Atomic read-and-delete. `EphemeralKv::take` is contractually
        // GETDEL semantics: the row vanishes from the backend before
        // the bytes return to us, which guarantees single-use even
        // under concurrent takes for the same `state`.
        let raw = match self.kv.take(&key).await {
            Ok(Some(b)) => b,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(error = %e, key = %key, "session take failed");
                return None;
            }
        };
        match serde_json::from_slice::<Session>(&raw) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(error = %e, key = %key, "session JSON parse failed");
                None
            }
        }
    }
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(state: &str) -> Session {
        Session {
            client_state: format!("client-{state}"),
            redirect_uri: "https://client.example/cb".to_string(),
            resource_uri: "https://mcp.example/api".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
        }
    }

    #[tokio::test]
    async fn put_then_take_returns_row() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        store.put("st-1", fixture("st-1")).await.unwrap();
        let got = store.take("st-1").await.expect("row missing");
        assert_eq!(got.client_state, "client-st-1");
    }

    #[tokio::test]
    async fn take_is_single_use() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        store.put("st-2", fixture("st-2")).await.unwrap();
        assert!(store.take("st-2").await.is_some());
        assert!(
            store.take("st-2").await.is_none(),
            "second take must return None"
        );
    }

    #[tokio::test]
    async fn take_unknown_state_is_none() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        assert!(store.take("ghost").await.is_none());
    }

    #[tokio::test]
    async fn expired_session_is_not_returned() {
        // Zero TTL means every entry is expired the instant after insert.
        let store = InMemorySessionStore::new(Duration::from_nanos(1));
        store.put("st-3", fixture("st-3")).await.unwrap();
        // Tiny sleep to make sure the clock has moved past the TTL.
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(store.take("st-3").await.is_none());
    }

    #[tokio::test]
    async fn put_purges_expired_entries() {
        let store = InMemorySessionStore::new(Duration::from_millis(10));
        store.put("old-1", fixture("old-1")).await.unwrap();
        store.put("old-2", fixture("old-2")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        // Now insert a fresh row, which should sweep the two stale rows.
        store.put("fresh", fixture("fresh")).await.unwrap();
        assert_eq!(store.len().await, 1);
    }

    #[tokio::test]
    async fn in_memory_session_capacity_fails_closed_without_evicting_live_state() {
        let store = InMemorySessionStore::with_capacity(Duration::from_secs(60), 1).unwrap();
        store.put("first", fixture("first")).await.unwrap();
        let error = store.put("second", fixture("second")).await.unwrap_err();
        assert!(error.to_string().contains("capacity"));
        assert!(store.take("first").await.is_some());
        assert!(store.take("second").await.is_none());
    }

    // --- Redis store tests ---
    //
    // The constructor and key derivation are exercised without a live
    // Redis. The put/take round trip needs a real server, so it is
    // gated behind `#[ignore]` and the `MCP_GATEWAY_REDIS_URL` env var.
    // CI does not run these by default; local contributors enable them
    // with:
    //
    //     MCP_GATEWAY_REDIS_URL=redis://127.0.0.1:6379/15 \
    //       cargo test -p sbproxy-mcp-gateway --lib redis -- --ignored

    #[test]
    fn redis_store_rejects_invalid_url() {
        let err = RedisSessionStore::new("not a url", "mcp:session", Duration::from_secs(60));
        assert!(err.is_err(), "obviously bad URL must fail");
    }

    #[test]
    fn redis_store_accepts_well_formed_url_lazily() {
        // No connection attempt happens at construction time, so a
        // syntactically valid URL pointing at a closed port still
        // succeeds. The first put/take is the operation that may fail.
        let store = RedisSessionStore::new(
            "redis://127.0.0.1:1/0",
            "mcp:session",
            Duration::from_secs(60),
        )
        .expect("syntactically valid URL must construct");
        assert_eq!(store.key_for("abc"), "mcp:session:abc");
    }

    #[test]
    fn redis_store_key_prefix_is_applied() {
        let store =
            RedisSessionStore::new("redis://127.0.0.1:1/0", "wave-4b3", Duration::from_secs(60))
                .unwrap();
        assert_eq!(store.key_for("xyz"), "wave-4b3:xyz");
    }

    // --- Wave 6D: trait-driven tests using the in-memory mock ---
    //
    // These tests exercise the storage-trait integration without
    // requiring a real Redis. They verify that:
    //   1. The new `with_storage` constructor works with any
    //      `Arc<dyn EphemeralKv>` backend.
    //   2. The single-use `take` contract is preserved by the
    //      trait's GETDEL-equivalent semantics.
    //   3. Bad JSON in the backend (a malformed row left over from
    //      an older broker version, say) is handled by logging and
    //      returning `None` rather than panicking.

    #[tokio::test]
    async fn storage_backed_round_trip_with_mock() {
        use sbproxy_storage::mock::MockEphemeralKv;
        let kv: Arc<dyn EphemeralKv> = Arc::new(MockEphemeralKv::new());
        let store = RedisSessionStore::with_storage(kv, "mcp:session", Duration::from_secs(60));

        store.put("st-mock", fixture("st-mock")).await.unwrap();
        let got = store.take("st-mock").await.expect("row present after put");
        assert_eq!(got.client_state, "client-st-mock");
        // Single-use: the second take must miss because the trait
        // contract removes the row atomically on read.
        assert!(store.take("st-mock").await.is_none());
    }

    #[tokio::test]
    async fn storage_backed_take_unknown_is_none() {
        use sbproxy_storage::mock::MockEphemeralKv;
        let kv: Arc<dyn EphemeralKv> = Arc::new(MockEphemeralKv::new());
        let store = RedisSessionStore::with_storage(kv, "mcp:session", Duration::from_secs(60));
        assert!(store.take("ghost").await.is_none());
    }

    #[tokio::test]
    async fn storage_backed_corrupt_payload_returns_none() {
        // If a sibling process wrote a malformed payload under the
        // session key (downgrade scenario, manual SET in redis-cli,
        // etc.) the broker must log and return `None` rather than
        // panicking. We simulate that by writing raw bytes through
        // the trait directly.
        use sbproxy_storage::mock::MockEphemeralKv;
        let mock = Arc::new(MockEphemeralKv::new());
        let kv: Arc<dyn EphemeralKv> = mock.clone();
        let store =
            RedisSessionStore::with_storage(kv.clone(), "mcp:session", Duration::from_secs(60));
        kv.put(
            &store.key_for("bad"),
            Bytes::from_static(b"not json"),
            Duration::from_secs(60),
        )
        .await
        .expect("put");
        assert!(store.take("bad").await.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live Redis at MCP_GATEWAY_REDIS_URL"]
    async fn redis_store_round_trip_against_live_redis() {
        let url = match std::env::var("MCP_GATEWAY_REDIS_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("SKIP: MCP_GATEWAY_REDIS_URL not set");
                return;
            }
        };
        let prefix = format!("mcp-test-{}", uuid_like());
        let store = RedisSessionStore::new(&url, &prefix, Duration::from_secs(60))
            .expect("redis client open");
        store.put("st-redis", fixture("st-redis")).await.unwrap();
        let got = store.take("st-redis").await.expect("row present after put");
        assert_eq!(got.client_state, "client-st-redis");
        // Single-use: a second take must miss.
        assert!(store.take("st-redis").await.is_none());
    }

    /// Tiny ID helper so the live-Redis test does not need uuid as a
    /// dev-dep just to namespace its keys.
    #[cfg(test)]
    fn uuid_like() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
