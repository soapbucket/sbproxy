//! In-process storage backend for the broker's OAuth flow state.
//!
//! [`sbproxy_storage::EphemeralKv`] and [`sbproxy_storage::PersistentKv`]
//! are the trait surfaces every stateful piece of this crate (sessions,
//! PKCE-adjacent state, DPoP replay, device codes, PAR entries, the CIMD
//! → DCR cache) is written against. `sbproxy-storage` ships a
//! production Redis backend (`RedisStore`, on by default) for
//! multi-replica deployments, but a single-process deployment should
//! not have to stand up Redis just to run an OAuth broker: every value
//! held here is short-lived flow state, never a system of record.
//!
//! [`LocalStore`] is that in-process default. It is a plain
//! `Mutex`-guarded `HashMap` with lazy TTL eviction, scoped to this
//! crate rather than added to `sbproxy-storage` itself: the shared
//! storage crate's own `mock` feature ships equivalent doubles
//! (`MockEphemeralKv`, `MockPersistentKv`), but those are documented as
//! test-only fixtures, gated behind a feature named for that purpose.
//! A broker that runs with no configured Redis URL should default to a
//! real, permanently-supported in-process backend, not a type whose
//! name and feature flag both say "for tests" — so this crate carries
//! its own, and every constructor in this crate that takes an
//! `Arc<dyn EphemeralKv>` / `Arc<dyn PersistentKv>` accepts a
//! `LocalStore::arc()` exactly as it would a `RedisStore`.
//!
//! Every router constructor in [`crate`] takes the storage traits as
//! `Arc<dyn ...>`, so callers pick per-backend at wiring time:
//!
//! ```
//! use std::sync::Arc;
//! use sbproxy_mcp_gateway::LocalStore;
//! use sbproxy_storage::EphemeralKv;
//!
//! # async fn example() {
//! let par_store: Arc<dyn EphemeralKv> = LocalStore::arc();
//! # let _ = par_store;
//! # }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_storage::{EphemeralKv, PersistentKv, StorageError};
use tokio::sync::Mutex;

struct EphemeralEntry {
    value: Bytes,
    expires_at: Instant,
}

/// In-process, `Mutex`-guarded backend implementing both
/// [`EphemeralKv`] and [`PersistentKv`].
///
/// Ephemeral and persistent values are held in separate maps so a TTL
/// write can never accidentally outlive (or be evicted alongside) a
/// durable one; "durable" here means "survives for the life of this
/// process", which is the only persistence a single-process broker can
/// promise without an external store. Both maps are swept lazily
/// (checked on the next `get`/`put`/`exists` for the touched key)
/// rather than by a background task, so an idle broker pays no
/// scanning cost.
pub struct LocalStore {
    ephemeral: Mutex<HashMap<String, EphemeralEntry>>,
    persistent: Mutex<HashMap<String, Bytes>>,
}

impl Default for LocalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self {
            ephemeral: Mutex::new(HashMap::new()),
            persistent: Mutex::new(HashMap::new()),
        }
    }

    /// `Arc`-wrapped convenience constructor for the common case of
    /// injecting this store as a trait object.
    pub fn arc() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl EphemeralKv for LocalStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        let now = Instant::now();
        let mut guard = self.ephemeral.lock().await;
        match guard.get(key) {
            Some(entry) if entry.expires_at > now => Ok(Some(entry.value.clone())),
            Some(_) => {
                guard.remove(key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: Bytes, ttl: Duration) -> Result<(), StorageError> {
        if ttl.is_zero() {
            return Err(StorageError::InvalidConfig(
                "LocalStore: ttl must be greater than zero".to_string(),
            ));
        }
        let mut guard = self.ephemeral.lock().await;
        guard.insert(
            key.to_string(),
            EphemeralEntry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(())
    }

    async fn take(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        let now = Instant::now();
        let mut guard = self.ephemeral.lock().await;
        match guard.remove(key) {
            Some(entry) if entry.expires_at > now => Ok(Some(entry.value)),
            _ => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.ephemeral.lock().await.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let now = Instant::now();
        let guard = self.ephemeral.lock().await;
        Ok(matches!(guard.get(key), Some(entry) if entry.expires_at > now))
    }
}

#[async_trait]
impl PersistentKv for LocalStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        Ok(self.persistent.lock().await.get(key).cloned())
    }

    async fn put(&self, key: &str, value: Bytes) -> Result<(), StorageError> {
        self.persistent.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.persistent.lock().await.remove(key);
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        Ok(self
            .persistent
            .lock()
            .await
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ephemeral_put_then_get_round_trips() {
        let store = LocalStore::new();
        EphemeralKv::put(
            &store,
            "k",
            Bytes::from_static(b"v"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let got = EphemeralKv::get(&store, "k").await.unwrap();
        assert_eq!(got, Some(Bytes::from_static(b"v")));
    }

    #[tokio::test]
    async fn ephemeral_zero_ttl_is_rejected() {
        let store = LocalStore::new();
        let err = EphemeralKv::put(&store, "k", Bytes::from_static(b"v"), Duration::ZERO)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn ephemeral_expired_entry_reads_as_absent() {
        let store = LocalStore::new();
        EphemeralKv::put(
            &store,
            "k",
            Bytes::from_static(b"v"),
            Duration::from_millis(5),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(EphemeralKv::get(&store, "k").await.unwrap(), None);
        assert!(!EphemeralKv::exists(&store, "k").await.unwrap());
    }

    #[tokio::test]
    async fn ephemeral_take_is_single_use() {
        let store = LocalStore::new();
        EphemeralKv::put(
            &store,
            "k",
            Bytes::from_static(b"v"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(
            EphemeralKv::take(&store, "k").await.unwrap(),
            Some(Bytes::from_static(b"v"))
        );
        assert_eq!(EphemeralKv::take(&store, "k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn ephemeral_delete_is_idempotent() {
        let store = LocalStore::new();
        EphemeralKv::delete(&store, "ghost").await.unwrap();
        EphemeralKv::put(
            &store,
            "k",
            Bytes::from_static(b"v"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        EphemeralKv::delete(&store, "k").await.unwrap();
        assert_eq!(EphemeralKv::get(&store, "k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn persistent_survives_regardless_of_ephemeral_ttl() {
        let store = LocalStore::new();
        PersistentKv::put(&store, "p", Bytes::from_static(b"durable"))
            .await
            .unwrap();
        // Ephemeral map is untouched by a persistent write.
        assert_eq!(EphemeralKv::get(&store, "p").await.unwrap(), None);
        assert_eq!(
            PersistentKv::get(&store, "p").await.unwrap(),
            Some(Bytes::from_static(b"durable"))
        );
    }

    #[tokio::test]
    async fn persistent_list_prefix_and_delete() {
        let store = LocalStore::new();
        PersistentKv::put(&store, "dcr:aa:1", Bytes::from_static(b"x"))
            .await
            .unwrap();
        PersistentKv::put(&store, "dcr:aa:2", Bytes::from_static(b"y"))
            .await
            .unwrap();
        PersistentKv::put(&store, "dcr:bb:1", Bytes::from_static(b"z"))
            .await
            .unwrap();
        let mut keys = PersistentKv::list_prefix(&store, "dcr:aa:").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["dcr:aa:1".to_string(), "dcr:aa:2".to_string()]);
        for k in keys {
            PersistentKv::delete(&store, &k).await.unwrap();
        }
        assert!(PersistentKv::get(&store, "dcr:aa:1")
            .await
            .unwrap()
            .is_none());
        assert!(PersistentKv::get(&store, "dcr:bb:1")
            .await
            .unwrap()
            .is_some());
    }
}
