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

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use sbproxy_storage::{EphemeralKv, PersistentKv, StorageError};
use tokio::sync::Mutex;

const DEFAULT_EPHEMERAL_CAPACITY: usize = 16_384;
const DEFAULT_PERSISTENT_CAPACITY: usize = 4_096;
const DEFAULT_MAX_KEY_BYTES: usize = 1_024;
const DEFAULT_MAX_VALUE_BYTES: usize = sbproxy_storage::MAX_VALUE_BYTES;
const DEFAULT_EPHEMERAL_BYTES_PER_NAMESPACE: usize = 8 * 1_024 * 1_024;
const DEFAULT_PERSISTENT_BYTES: usize = 32 * 1_024 * 1_024;

/// Strict memory limits for the in-process OAuth state backend.
#[derive(Clone, Copy, Debug)]
pub struct LocalStoreLimits {
    /// Maximum live entries in each independent security namespace.
    pub ephemeral_entries_per_namespace: usize,
    /// Maximum process-lifetime entries.
    pub persistent_entries: usize,
    /// Maximum UTF-8 key length.
    pub max_key_bytes: usize,
    /// Maximum value length.
    pub max_value_bytes: usize,
    /// Maximum key plus value bytes in one ephemeral namespace.
    pub max_ephemeral_bytes_per_namespace: usize,
    /// Maximum key plus value bytes in the persistent map.
    pub max_persistent_bytes: usize,
}

impl Default for LocalStoreLimits {
    fn default() -> Self {
        Self {
            ephemeral_entries_per_namespace: DEFAULT_EPHEMERAL_CAPACITY,
            persistent_entries: DEFAULT_PERSISTENT_CAPACITY,
            max_key_bytes: DEFAULT_MAX_KEY_BYTES,
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
            max_ephemeral_bytes_per_namespace: DEFAULT_EPHEMERAL_BYTES_PER_NAMESPACE,
            max_persistent_bytes: DEFAULT_PERSISTENT_BYTES,
        }
    }
}

struct EphemeralEntry {
    value: Bytes,
    expires_at: Instant,
    generation: u64,
    namespace: String,
    accounted_bytes: usize,
}

#[derive(Default)]
struct NamespaceUsage {
    entries: usize,
    bytes: usize,
}

#[derive(Default)]
struct EphemeralState {
    entries: HashMap<String, EphemeralEntry>,
    expirations: BinaryHeap<Reverse<(Instant, u64, String)>>,
    usage: HashMap<String, NamespaceUsage>,
    next_generation: u64,
}

#[derive(Default)]
struct PersistentState {
    entries: HashMap<String, Bytes>,
    bytes: usize,
}

/// In-process, `Mutex`-guarded backend implementing both
/// [`EphemeralKv`] and [`PersistentKv`].
///
/// Ephemeral and persistent values are held in separate maps so a TTL
/// write can never accidentally outlive (or be evicted alongside) a
/// durable one; "durable" here means "survives for the life of this
/// process", which is the only persistence a single-process broker can
/// promise without an external store. Ephemeral operations sweep every
/// expired entry before access/capacity checks rather than waiting for
/// the exact key to be touched; no background task is required.
pub struct LocalStore {
    ephemeral: Mutex<EphemeralState>,
    persistent: Mutex<PersistentState>,
    limits: LocalStoreLimits,
}

impl Default for LocalStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_EPHEMERAL_CAPACITY, DEFAULT_PERSISTENT_CAPACITY)
            .expect("non-zero default LocalStore capacities")
    }

    /// Build an empty store with explicit upper bounds for ephemeral
    /// and process-lifetime entries. New unique keys fail closed once
    /// the corresponding capacity is full; replacing an existing key
    /// remains possible. Expired ephemeral entries are swept before
    /// the capacity check.
    pub fn with_capacity(
        ephemeral_capacity: usize,
        persistent_capacity: usize,
    ) -> Result<Self, StorageError> {
        Self::with_limits(LocalStoreLimits {
            ephemeral_entries_per_namespace: ephemeral_capacity,
            persistent_entries: persistent_capacity,
            ..LocalStoreLimits::default()
        })
    }

    /// Build an empty store with entry, key, value, and byte limits.
    pub fn with_limits(limits: LocalStoreLimits) -> Result<Self, StorageError> {
        if limits.ephemeral_entries_per_namespace == 0
            || limits.persistent_entries == 0
            || limits.max_key_bytes == 0
            || limits.max_value_bytes == 0
            || limits.max_ephemeral_bytes_per_namespace == 0
            || limits.max_persistent_bytes == 0
        {
            return Err(StorageError::InvalidConfig(
                "LocalStore limits must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            ephemeral: Mutex::new(EphemeralState::default()),
            persistent: Mutex::new(PersistentState::default()),
            limits,
        })
    }

    /// `Arc`-wrapped convenience constructor for the common case of
    /// injecting this store as a trait object.
    pub fn arc() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn validate_key(&self, key: &str) -> Result<(), StorageError> {
        if key.len() > self.limits.max_key_bytes {
            return Err(StorageError::KeyTooLarge {
                len: key.len(),
                max: self.limits.max_key_bytes,
            });
        }
        Ok(())
    }

    fn validate_value(&self, value: &Bytes) -> Result<(), StorageError> {
        if value.len() > self.limits.max_value_bytes {
            return Err(StorageError::ValueTooLarge {
                len: value.len(),
                max: self.limits.max_value_bytes,
            });
        }
        Ok(())
    }
}

fn security_namespace(key: &str) -> String {
    let parts = key.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        ["dpop", "nonce", ..] => "dpop:nonce".to_string(),
        ["dpop", "jti", ..] => "dpop:jti".to_string(),
        ["resource", "dpop", "jti", ..] => "resource:dpop:jti".to_string(),
        ["device", ..] => "device".to_string(),
        ["par", ..] => "par".to_string(),
        ["revoked", runtime, ..] if parts.len() >= 3 => format!("revoked:{runtime}"),
        ["revoked", ..] => "revoked".to_string(),
        ["refresh-binding", runtime, ..] if parts.len() >= 3 => {
            format!("refresh-binding:{runtime}")
        }
        ["refresh-binding", ..] => "refresh-binding".to_string(),
        [prefix, ..] if parts.len() >= 2 => (*prefix).to_string(),
        _ => "__default__".to_string(),
    }
}

fn remove_ephemeral_entry(state: &mut EphemeralState, key: &str) -> Option<EphemeralEntry> {
    let entry = state.entries.remove(key)?;
    if let Some(usage) = state.usage.get_mut(&entry.namespace) {
        usage.entries = usage.entries.saturating_sub(1);
        usage.bytes = usage.bytes.saturating_sub(entry.accounted_bytes);
        if usage.entries == 0 {
            state.usage.remove(&entry.namespace);
        }
    }
    Some(entry)
}

fn sweep_expired(state: &mut EphemeralState, now: Instant) {
    while state
        .expirations
        .peek()
        .is_some_and(|Reverse((expires_at, _, _))| *expires_at <= now)
    {
        let Some(Reverse((expires_at, generation, key))) = state.expirations.pop() else {
            break;
        };
        let expired = state.entries.get(&key).is_some_and(|entry| {
            entry.generation == generation && entry.expires_at == expires_at
        });
        if expired {
            remove_ephemeral_entry(state, &key);
        }
    }
}

fn insert_ephemeral(
    state: &mut EphemeralState,
    limits: LocalStoreLimits,
    key: &str,
    value: Bytes,
    expires_at: Instant,
) -> Result<(), StorageError> {
    let namespace = security_namespace(key);
    let old = state.entries.get(key);
    let old_bytes = old.map_or(0, |entry| entry.accounted_bytes);
    let old_entries = usize::from(old.is_some());
    let accounted_bytes = key.len().saturating_add(value.len());
    let usage = state.usage.get(&namespace);
    let next_entries = usage
        .map_or(0, |usage| usage.entries)
        .saturating_sub(old_entries)
        .saturating_add(1);
    let next_bytes = usage
        .map_or(0, |usage| usage.bytes)
        .saturating_sub(old_bytes)
        .saturating_add(accounted_bytes);
    if next_entries > limits.ephemeral_entries_per_namespace {
        return Err(StorageError::InvalidConfig(format!(
            "LocalStore ephemeral namespace {namespace:?} entry capacity {} reached",
            limits.ephemeral_entries_per_namespace
        )));
    }
    if next_bytes > limits.max_ephemeral_bytes_per_namespace {
        return Err(StorageError::InvalidConfig(format!(
            "LocalStore ephemeral namespace {namespace:?} byte capacity {} reached",
            limits.max_ephemeral_bytes_per_namespace
        )));
    }
    if old.is_some() {
        remove_ephemeral_entry(state, key);
    }
    state.next_generation = state.next_generation.wrapping_add(1);
    let generation = state.next_generation;
    state.entries.insert(
        key.to_string(),
        EphemeralEntry {
            value,
            expires_at,
            generation,
            namespace: namespace.clone(),
            accounted_bytes,
        },
    );
    let usage = state.usage.entry(namespace).or_default();
    usage.entries += 1;
    usage.bytes += accounted_bytes;
    state
        .expirations
        .push(Reverse((expires_at, generation, key.to_string())));
    compact_expiration_index(state);
    Ok(())
}

/// Replacement writes leave stale generation records in the heap. Rebuild
/// once those records materially outnumber live entries so repeatedly
/// replacing one security key cannot grow auxiliary memory without bound.
fn compact_expiration_index(state: &mut EphemeralState) {
    let maximum_index_len = state.entries.len().saturating_mul(2).saturating_add(64);
    if state.expirations.len() <= maximum_index_len {
        return;
    }
    state.expirations = state
        .entries
        .iter()
        .map(|(key, entry)| Reverse((entry.expires_at, entry.generation, key.clone())))
        .collect();
}

#[async_trait]
impl EphemeralKv for LocalStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        self.validate_key(key)?;
        let now = Instant::now();
        let mut guard = self.ephemeral.lock().await;
        sweep_expired(&mut guard, now);
        match guard.entries.get(key) {
            Some(entry) if entry.expires_at > now => Ok(Some(entry.value.clone())),
            Some(_) => {
                remove_ephemeral_entry(&mut guard, key);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    async fn put(&self, key: &str, value: Bytes, ttl: Duration) -> Result<(), StorageError> {
        self.validate_key(key)?;
        self.validate_value(&value)?;
        if ttl.is_zero() {
            return Err(StorageError::InvalidConfig(
                "LocalStore: ttl must be greater than zero".to_string(),
            ));
        }
        let mut guard = self.ephemeral.lock().await;
        let now = Instant::now();
        let expires_at = now.checked_add(ttl).ok_or_else(|| {
            StorageError::InvalidConfig("LocalStore ephemeral TTL overflow".to_string())
        })?;
        sweep_expired(&mut guard, now);
        insert_ephemeral(&mut guard, self.limits, key, value, expires_at)
    }

    async fn take(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        self.validate_key(key)?;
        let now = Instant::now();
        let mut guard = self.ephemeral.lock().await;
        sweep_expired(&mut guard, now);
        match remove_ephemeral_entry(&mut guard, key) {
            Some(entry) if entry.expires_at > now => Ok(Some(entry.value)),
            _ => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.validate_key(key)?;
        let mut guard = self.ephemeral.lock().await;
        remove_ephemeral_entry(&mut guard, key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        self.validate_key(key)?;
        let now = Instant::now();
        let mut guard = self.ephemeral.lock().await;
        sweep_expired(&mut guard, now);
        Ok(matches!(guard.entries.get(key), Some(entry) if entry.expires_at > now))
    }

    async fn compare_exchange(
        &self,
        key: &str,
        expected: Option<Bytes>,
        replacement: Option<(Bytes, Duration)>,
    ) -> Result<bool, StorageError> {
        self.validate_key(key)?;
        if let Some(value) = expected.as_ref() {
            self.validate_value(value)?;
        }
        let replacement = match replacement {
            Some((value, ttl)) => {
                self.validate_value(&value)?;
                if ttl.is_zero() {
                    return Err(StorageError::InvalidConfig(
                        "LocalStore: ttl must be greater than zero".to_string(),
                    ));
                }
                let expires_at = Instant::now().checked_add(ttl).ok_or_else(|| {
                    StorageError::InvalidConfig("LocalStore ephemeral TTL overflow".to_string())
                })?;
                Some((value, expires_at))
            }
            None => None,
        };
        let now = Instant::now();
        let mut guard = self.ephemeral.lock().await;
        sweep_expired(&mut guard, now);
        let current = guard.entries.get(key).map(|entry| entry.value.clone());
        if current != expected {
            return Ok(false);
        }
        match replacement {
            Some((value, expires_at)) => {
                insert_ephemeral(&mut guard, self.limits, key, value, expires_at)?;
            }
            None => {
                remove_ephemeral_entry(&mut guard, key);
            }
        }
        Ok(true)
    }
}

#[async_trait]
impl PersistentKv for LocalStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        self.validate_key(key)?;
        Ok(self.persistent.lock().await.entries.get(key).cloned())
    }

    async fn put(&self, key: &str, value: Bytes) -> Result<(), StorageError> {
        self.validate_key(key)?;
        self.validate_value(&value)?;
        let mut guard = self.persistent.lock().await;
        let old_bytes = guard
            .entries
            .get(key)
            .map_or(0, |old| key.len().saturating_add(old.len()));
        let new_bytes = key.len().saturating_add(value.len());
        let next_bytes = guard.bytes.saturating_sub(old_bytes).saturating_add(new_bytes);
        if !guard.entries.contains_key(key)
            && guard.entries.len() >= self.limits.persistent_entries
        {
            return Err(StorageError::InvalidConfig(format!(
                "LocalStore persistent capacity {} reached",
                self.limits.persistent_entries
            )));
        }
        if next_bytes > self.limits.max_persistent_bytes {
            return Err(StorageError::InvalidConfig(format!(
                "LocalStore persistent byte capacity {} reached",
                self.limits.max_persistent_bytes
            )));
        }
        guard.entries.insert(key.to_string(), value);
        guard.bytes = next_bytes;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.validate_key(key)?;
        let mut guard = self.persistent.lock().await;
        if let Some(value) = guard.entries.remove(key) {
            guard.bytes = guard.bytes.saturating_sub(key.len().saturating_add(value.len()));
        }
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        self.validate_key(prefix)?;
        Ok(self
            .persistent
            .lock()
            .await
            .entries
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    async fn compare_exchange(
        &self,
        key: &str,
        expected: Option<Bytes>,
        replacement: Option<Bytes>,
    ) -> Result<bool, StorageError> {
        self.validate_key(key)?;
        if let Some(value) = expected.as_ref() {
            self.validate_value(value)?;
        }
        if let Some(value) = replacement.as_ref() {
            self.validate_value(value)?;
        }
        let mut guard = self.persistent.lock().await;
        if guard.entries.get(key).cloned() != expected {
            return Ok(false);
        }
        let old_bytes = guard
            .entries
            .get(key)
            .map_or(0, |value| key.len().saturating_add(value.len()));
        match replacement {
            Some(value) => {
                if !guard.entries.contains_key(key)
                    && guard.entries.len() >= self.limits.persistent_entries
                {
                    return Err(StorageError::InvalidConfig(format!(
                        "LocalStore persistent capacity {} reached",
                        self.limits.persistent_entries
                    )));
                }
                let new_bytes = key.len().saturating_add(value.len());
                let next_bytes = guard
                    .bytes
                    .saturating_sub(old_bytes)
                    .saturating_add(new_bytes);
                if next_bytes > self.limits.max_persistent_bytes {
                    return Err(StorageError::InvalidConfig(format!(
                        "LocalStore persistent byte capacity {} reached",
                        self.limits.max_persistent_bytes
                    )));
                }
                guard.entries.insert(key.to_string(), value);
                guard.bytes = next_bytes;
            }
            None => {
                guard.entries.remove(key);
                guard.bytes = guard.bytes.saturating_sub(old_bytes);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn expired_ephemeral_keys_are_reclaimed_before_an_unrelated_put() {
        let store = LocalStore::with_capacity(1, 1).unwrap();
        EphemeralKv::put(
            &store,
            "expired",
            Bytes::from_static(b"v"),
            Duration::from_millis(5),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;

        EphemeralKv::put(
            &store,
            "replacement",
            Bytes::from_static(b"v2"),
            Duration::from_secs(60),
        )
        .await
        .expect("unrelated put must sweep expired unique keys");
        assert_eq!(
            EphemeralKv::get(&store, "replacement").await.unwrap(),
            Some(Bytes::from_static(b"v2"))
        );
    }

    #[tokio::test]
    async fn full_stores_reject_new_unique_keys_but_allow_replacement() {
        let store = LocalStore::with_capacity(1, 1).unwrap();
        EphemeralKv::put(
            &store,
            "one",
            Bytes::from_static(b"v1"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let err = EphemeralKv::put(
            &store,
            "two",
            Bytes::from_static(b"v2"),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, StorageError::InvalidConfig(_)));
        EphemeralKv::put(
            &store,
            "one",
            Bytes::from_static(b"new"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        PersistentKv::put(&store, "one", Bytes::from_static(b"v1"))
            .await
            .unwrap();
        let err = PersistentKv::put(&store, "two", Bytes::from_static(b"v2"))
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidConfig(_)));
        PersistentKv::put(&store, "one", Bytes::from_static(b"new"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ephemeral_put_rejects_a_ttl_that_overflows_instant() {
        let store = LocalStore::new();
        let error = EphemeralKv::put(&store, "overflow", Bytes::from_static(b"v"), Duration::MAX)
            .await
            .unwrap_err();
        assert!(matches!(error, StorageError::InvalidConfig(_)));
    }

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

    #[tokio::test]
    async fn ephemeral_compare_exchange_has_one_winner() {
        let store = Arc::new(LocalStore::new());
        EphemeralKv::put(
            store.as_ref(),
            "device:one",
            Bytes::from_static(b"pending"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let gate = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for replacement in [b"approved".as_slice(), b"denied".as_slice()] {
            let store = store.clone();
            let gate = gate.clone();
            let replacement = Bytes::copy_from_slice(replacement);
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                EphemeralKv::compare_exchange(
                    store.as_ref(),
                    "device:one",
                    Some(Bytes::from_static(b"pending")),
                    Some((replacement, Duration::from_secs(60))),
                )
                .await
                .unwrap()
            }));
        }
        gate.wait().await;
        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one state transition may win");
    }

    #[tokio::test]
    async fn repeated_replacement_keeps_expiry_index_bounded() {
        let store = LocalStore::with_capacity(1, 1).unwrap();
        for generation in 0..1_000_u32 {
            EphemeralKv::put(
                &store,
                "dpop:jti:same-key",
                Bytes::copy_from_slice(&generation.to_be_bytes()),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        }
        let state = store.ephemeral.lock().await;
        assert_eq!(state.entries.len(), 1);
        assert!(
            state.expirations.len() <= 66,
            "stale expiry nodes must remain bounded: {}",
            state.expirations.len()
        );
    }

    #[tokio::test]
    async fn persistent_compare_exchange_rejects_a_stale_sweep() {
        let store = LocalStore::new();
        PersistentKv::put(&store, "dcr:index", Bytes::from_static(b"fresh"))
            .await
            .unwrap();
        let deleted = PersistentKv::compare_exchange(
            &store,
            "dcr:index",
            Some(Bytes::from_static(b"expired")),
            None,
        )
        .await
        .unwrap();
        assert!(!deleted);
        assert_eq!(
            PersistentKv::get(&store, "dcr:index").await.unwrap(),
            Some(Bytes::from_static(b"fresh"))
        );
    }

    #[tokio::test]
    async fn byte_pressure_is_partitioned_by_security_namespace() {
        let store = LocalStore::with_limits(LocalStoreLimits {
            ephemeral_entries_per_namespace: 8,
            persistent_entries: 8,
            max_key_bytes: 128,
            max_value_bytes: 8,
            max_ephemeral_bytes_per_namespace: 24,
            max_persistent_bytes: 64,
        })
        .unwrap();
        EphemeralKv::put(
            &store,
            "device:a",
            Bytes::from_static(b"12345678"),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let error = EphemeralKv::put(
            &store,
            "device:b",
            Bytes::from_static(b"12345678"),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, StorageError::InvalidConfig(_)));

        EphemeralKv::put(
            &store,
            "dpop:nonce:a",
            Bytes::from_static(b"12345678"),
            Duration::from_secs(60),
        )
        .await
        .expect("device pressure must not consume the nonce partition");
    }

    #[tokio::test]
    async fn local_limits_reject_oversized_keys_and_values_before_allocation() {
        let store = LocalStore::with_limits(LocalStoreLimits {
            ephemeral_entries_per_namespace: 8,
            persistent_entries: 8,
            max_key_bytes: 4,
            max_value_bytes: 4,
            max_ephemeral_bytes_per_namespace: 64,
            max_persistent_bytes: 64,
        })
        .unwrap();
        let key_error = EphemeralKv::put(
            &store,
            "device:key",
            Bytes::from_static(b"v"),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();
        assert!(matches!(key_error, StorageError::KeyTooLarge { .. }));
        let value_error = PersistentKv::put(&store, "key", Bytes::from_static(b"12345"))
            .await
            .unwrap_err();
        assert!(matches!(value_error, StorageError::ValueTooLarge { .. }));
    }
}
