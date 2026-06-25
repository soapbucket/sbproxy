// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! In-memory test doubles for the storage traits.
//!
//! Compiled when the `mock` cargo feature is on (always-on under
//! `cfg(test)`). Downstream crates can opt in by adding
//! `sbproxy-storage = { workspace = true, features = ["mock"] }`
//! in their `[dev-dependencies]` and writing trait-driven tests
//! without standing up a real Redis / Postgres instance.
//!
//! These doubles are deliberately simple: the goal is correctness of
//! the trait surface, not benchmark fidelity. TTL eviction is lazy
//! (checked on access) and pub/sub fan-out uses unbounded channels,
//! so they are unsuitable for production traffic.

#![cfg(any(test, feature = "mock"))]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::{mpsc, Mutex};

use crate::error::{check_key, check_value, StorageError};
use crate::traits::{
    EphemeralKv, HashKv, PersistentKv, PubSub, SetKv, StreamEntry, StreamKv, Subscription,
};

// --- Ephemeral KV mock ---

/// In-memory [`EphemeralKv`] with lazy TTL eviction. Each entry stores
/// the value plus its expiry instant; reads after `expires_at` return
/// `None` and silently remove the entry.
///
/// `exists` is tracked through a separate counter so tests can assert
/// the migrated revocation path takes the cheap probe and does not
/// fall back through the default `get`-based shim.
#[derive(Debug, Default, Clone)]
pub struct MockEphemeralKv {
    storage: Arc<Mutex<HashMap<String, (Bytes, Instant)>>>,
    exists_calls: Arc<AtomicU64>,
}

impl MockEphemeralKv {
    /// Create a fresh empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of [`EphemeralKv::exists`] calls observed by this mock.
    /// Lets tests assert the trait override is taken instead of the
    /// default `get`-based fallback.
    pub fn exists_call_count(&self) -> u64 {
        self.exists_calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl EphemeralKv for MockEphemeralKv {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        check_key(key)?;
        let mut guard = self.storage.lock().await;
        if let Some((value, expires_at)) = guard.get(key).cloned() {
            if Instant::now() >= expires_at {
                guard.remove(key);
                return Ok(None);
            }
            return Ok(Some(value));
        }
        Ok(None)
    }

    async fn put(&self, key: &str, value: Bytes, ttl: Duration) -> Result<(), StorageError> {
        check_key(key)?;
        check_value(&value)?;
        let expires_at = Instant::now()
            .checked_add(ttl)
            .ok_or_else(|| StorageError::InvalidConfig("ttl overflow".into()))?;
        self.storage
            .lock()
            .await
            .insert(key.to_string(), (value, expires_at));
        Ok(())
    }

    async fn take(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        check_key(key)?;
        let mut guard = self.storage.lock().await;
        if let Some((value, expires_at)) = guard.remove(key) {
            if Instant::now() >= expires_at {
                return Ok(None);
            }
            return Ok(Some(value));
        }
        Ok(None)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        check_key(key)?;
        self.storage.lock().await.remove(key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        check_key(key)?;
        // Count the call distinctly from `get` so tests can assert the
        // migrated revocation path went through the `exists` override.
        self.exists_calls.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.storage.lock().await;
        if let Some((_, expires_at)) = guard.get(key).cloned() {
            if Instant::now() >= expires_at {
                guard.remove(key);
                return Ok(false);
            }
            return Ok(true);
        }
        Ok(false)
    }
}

// --- Persistent KV mock ---

/// In-memory [`PersistentKv`] backed by a `HashMap`. Survives only as
/// long as the struct itself, but that is enough for unit tests that
/// just want to verify CRUD + prefix iteration semantics.
#[derive(Debug, Default, Clone)]
pub struct MockPersistentKv {
    storage: Arc<Mutex<HashMap<String, Bytes>>>,
}

impl MockPersistentKv {
    /// Create a fresh empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PersistentKv for MockPersistentKv {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        check_key(key)?;
        Ok(self.storage.lock().await.get(key).cloned())
    }

    async fn put(&self, key: &str, value: Bytes) -> Result<(), StorageError> {
        check_key(key)?;
        check_value(&value)?;
        self.storage.lock().await.insert(key.to_string(), value);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        check_key(key)?;
        self.storage.lock().await.remove(key);
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let guard = self.storage.lock().await;
        Ok(guard
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

// --- Pub/Sub mock ---

/// In-memory [`PubSub`] using unbounded `mpsc` channels per
/// subscriber. Publishing fan-outs by cloning the message into every
/// active sender; closed senders are pruned lazily on the next
/// publish.
#[derive(Debug, Default, Clone)]
pub struct MockPubSub {
    channels: Arc<Mutex<HashMap<String, Vec<mpsc::UnboundedSender<Bytes>>>>>,
}

impl MockPubSub {
    /// Create a fresh empty broker.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PubSub for MockPubSub {
    async fn publish(&self, channel: &str, message: Bytes) -> Result<(), StorageError> {
        check_key(channel)?;
        check_value(&message)?;
        let mut guard = self.channels.lock().await;
        if let Some(senders) = guard.get_mut(channel) {
            // Drop dead senders so we do not retain Arc-cycles or grow
            // the vec on every publish.
            senders.retain(|tx| !tx.is_closed());
            for tx in senders.iter() {
                // Send is best-effort: if the receiver was dropped
                // mid-call, ignore and let the next publish prune it.
                let _ = tx.send(message.clone());
            }
        }
        Ok(())
    }

    async fn subscribe(&self, channel: &str) -> Result<Box<dyn Subscription + Send>, StorageError> {
        check_key(channel)?;
        let (tx, rx) = mpsc::unbounded_channel();
        self.channels
            .lock()
            .await
            .entry(channel.to_string())
            .or_default()
            .push(tx);
        Ok(Box::new(MockSubscription { rx }))
    }
}

/// Subscription returned by [`MockPubSub::subscribe`]. Wraps the
/// receiver half of an unbounded `mpsc` channel; `next` resolves once
/// a publisher sends or the channel is closed.
pub struct MockSubscription {
    rx: mpsc::UnboundedReceiver<Bytes>,
}

#[async_trait]
impl Subscription for MockSubscription {
    async fn next(&mut self) -> Result<Option<Bytes>, StorageError> {
        Ok(self.rx.recv().await)
    }
}

// --- HashKv mock ---

/// In-memory [`HashKv`]: a `HashMap<parent, HashMap<field, value>>`
/// behind a single `Mutex`. Mirrors the simple structure of the other
/// mocks; suitable for unit tests, not production traffic.
#[derive(Debug, Default, Clone)]
pub struct MockHashKv {
    storage: Arc<Mutex<HashMap<String, HashMap<String, Bytes>>>>,
}

impl MockHashKv {
    /// Create a fresh empty hash store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl HashKv for MockHashKv {
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Bytes>, StorageError> {
        check_key(key)?;
        check_key(field)?;
        Ok(self
            .storage
            .lock()
            .await
            .get(key)
            .and_then(|h| h.get(field).cloned()))
    }

    async fn hset(&self, key: &str, field: &str, value: Bytes) -> Result<(), StorageError> {
        check_key(key)?;
        check_key(field)?;
        check_value(&value)?;
        self.storage
            .lock()
            .await
            .entry(key.to_string())
            .or_default()
            .insert(field.to_string(), value);
        Ok(())
    }

    async fn hset_multi(&self, key: &str, fields: &[(&str, Bytes)]) -> Result<(), StorageError> {
        check_key(key)?;
        for (f, v) in fields {
            check_key(f)?;
            check_value(v)?;
        }
        let mut guard = self.storage.lock().await;
        let entry = guard.entry(key.to_string()).or_default();
        for (f, v) in fields {
            entry.insert((*f).to_string(), v.clone());
        }
        Ok(())
    }

    async fn hgetall(&self, key: &str) -> Result<Vec<(String, Bytes)>, StorageError> {
        check_key(key)?;
        Ok(self
            .storage
            .lock()
            .await
            .get(key)
            .map(|h| h.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default())
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<(), StorageError> {
        check_key(key)?;
        check_key(field)?;
        let mut guard = self.storage.lock().await;
        if let Some(h) = guard.get_mut(key) {
            h.remove(field);
            if h.is_empty() {
                guard.remove(key);
            }
        }
        Ok(())
    }

    async fn hexists(&self, key: &str, field: &str) -> Result<bool, StorageError> {
        check_key(key)?;
        check_key(field)?;
        Ok(self
            .storage
            .lock()
            .await
            .get(key)
            .is_some_and(|h| h.contains_key(field)))
    }
}

// --- SetKv mock ---

/// In-memory [`SetKv`]: a `HashMap<parent, HashSet<member>>` behind a
/// single `Mutex`. Members are deduped by `HashSet` semantics.
#[derive(Debug, Default, Clone)]
pub struct MockSetKv {
    storage: Arc<Mutex<HashMap<String, HashSet<Bytes>>>>,
}

impl MockSetKv {
    /// Create a fresh empty set store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SetKv for MockSetKv {
    async fn sadd(&self, key: &str, members: &[Bytes]) -> Result<u64, StorageError> {
        check_key(key)?;
        for m in members {
            check_value(m)?;
        }
        let mut guard = self.storage.lock().await;
        let entry = guard.entry(key.to_string()).or_default();
        let mut added = 0u64;
        for m in members {
            if entry.insert(m.clone()) {
                added += 1;
            }
        }
        Ok(added)
    }

    async fn srem(&self, key: &str, members: &[Bytes]) -> Result<u64, StorageError> {
        check_key(key)?;
        for m in members {
            check_value(m)?;
        }
        let mut guard = self.storage.lock().await;
        let mut removed = 0u64;
        if let Some(entry) = guard.get_mut(key) {
            for m in members {
                if entry.remove(m) {
                    removed += 1;
                }
            }
            if entry.is_empty() {
                guard.remove(key);
            }
        }
        Ok(removed)
    }

    async fn smembers(&self, key: &str) -> Result<Vec<Bytes>, StorageError> {
        check_key(key)?;
        Ok(self
            .storage
            .lock()
            .await
            .get(key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn scard(&self, key: &str) -> Result<u64, StorageError> {
        check_key(key)?;
        Ok(self
            .storage
            .lock()
            .await
            .get(key)
            .map(|s| s.len() as u64)
            .unwrap_or(0))
    }

    async fn sismember(&self, key: &str, member: &Bytes) -> Result<bool, StorageError> {
        check_key(key)?;
        check_value(member)?;
        Ok(self
            .storage
            .lock()
            .await
            .get(key)
            .is_some_and(|s| s.contains(member)))
    }
}

// --- StreamKv mock ---

/// In-memory [`StreamKv`]: a `HashMap<stream, VecDeque<entry>>` behind
/// a single `Mutex`. IDs are `{ms-since-epoch}-{seq}` formatted, with a
/// global monotonic counter so two `xadd` calls in the same millisecond
/// still produce strictly increasing IDs.
#[derive(Debug, Default, Clone)]
pub struct MockStreamKv {
    storage: Arc<Mutex<HashMap<String, VecDeque<StreamEntry>>>>,
    seq: Arc<AtomicU64>,
}

impl MockStreamKv {
    /// Create a fresh empty stream store.
    pub fn new() -> Self {
        Self::default()
    }

    fn next_id(&self) -> String {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        format!("{ms}-{seq}")
    }
}

#[async_trait]
impl StreamKv for MockStreamKv {
    async fn xadd(&self, stream: &str, entry: &[(&str, Bytes)]) -> Result<String, StorageError> {
        check_key(stream)?;
        for (f, v) in entry {
            check_key(f)?;
            check_value(v)?;
        }
        let id = self.next_id();
        let row = StreamEntry {
            id: id.clone(),
            fields: entry
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        };
        self.storage
            .lock()
            .await
            .entry(stream.to_string())
            .or_default()
            .push_back(row);
        Ok(id)
    }

    async fn xread(
        &self,
        stream: &str,
        since_id: &str,
        count: usize,
    ) -> Result<Vec<StreamEntry>, StorageError> {
        check_key(stream)?;
        if since_id == "$" {
            // Non-blocking backend: no entries appended after this call.
            return Ok(Vec::new());
        }
        let parsed_since = since_id
            .split_once('-')
            .and_then(|(ms, seq)| Some((ms.parse::<u64>().ok()?, seq.parse::<u64>().ok()?)));
        let guard = self.storage.lock().await;
        let q = match guard.get(stream) {
            Some(q) => q,
            None => return Ok(Vec::new()),
        };
        let mut out = Vec::with_capacity(count.min(q.len()));
        for entry in q.iter() {
            if let Some(parsed) = parsed_since {
                let eid = entry
                    .id
                    .split_once('-')
                    .and_then(|(m, s)| Some((m.parse::<u64>().ok()?, s.parse::<u64>().ok()?)));
                if let Some(eid) = eid {
                    if eid <= parsed {
                        continue;
                    }
                }
            }
            out.push(entry.clone());
            if out.len() >= count {
                break;
            }
        }
        Ok(out)
    }

    async fn xtrim(&self, stream: &str, max_len: usize) -> Result<u64, StorageError> {
        check_key(stream)?;
        let mut guard = self.storage.lock().await;
        let q = match guard.get_mut(stream) {
            Some(q) => q,
            None => return Ok(0),
        };
        let mut removed = 0u64;
        while q.len() > max_len {
            q.pop_front();
            removed += 1;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    // --- EphemeralKv coverage ---

    #[tokio::test]
    async fn ephemeral_get_put_delete_round_trip() {
        let store = MockEphemeralKv::new();
        store
            .put("k1", Bytes::from_static(b"v1"), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(store.get("k1").await.unwrap().as_deref(), Some(&b"v1"[..]));
        store.delete("k1").await.unwrap();
        assert!(store.get("k1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ephemeral_take_returns_and_removes() {
        let store = MockEphemeralKv::new();
        store
            .put("nonce", Bytes::from_static(b"abc"), Duration::from_secs(10))
            .await
            .unwrap();
        let first = store.take("nonce").await.unwrap();
        assert_eq!(first.as_deref(), Some(&b"abc"[..]));
        // GETDEL semantics: a second take returns None.
        let second = store.take("nonce").await.unwrap();
        assert!(second.is_none());
    }

    #[tokio::test]
    async fn ephemeral_ttl_expires_entry() {
        let store = MockEphemeralKv::new();
        store
            .put("temp", Bytes::from_static(b"x"), Duration::from_millis(20))
            .await
            .unwrap();
        sleep(Duration::from_millis(40)).await;
        assert!(store.get("temp").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn ephemeral_exists_distinguishes_from_get() {
        let store = MockEphemeralKv::new();
        store
            .put("present", Bytes::from_static(b"v"), Duration::from_secs(10))
            .await
            .unwrap();
        // Exists is tracked separately from get; production backends
        // override the default `get`-based shim with a key-only probe
        // (Redis EXISTS, HashMap::contains_key, SELECT 1 LIMIT 1).
        assert!(store.exists("present").await.unwrap());
        assert!(!store.exists("absent").await.unwrap());
        assert_eq!(store.exists_call_count(), 2);
    }

    #[tokio::test]
    async fn ephemeral_exists_returns_false_for_expired() {
        let store = MockEphemeralKv::new();
        store
            .put("temp", Bytes::from_static(b"x"), Duration::from_millis(20))
            .await
            .unwrap();
        sleep(Duration::from_millis(40)).await;
        assert!(!store.exists("temp").await.unwrap());
    }

    #[tokio::test]
    async fn ephemeral_oversize_key_rejected() {
        let store = MockEphemeralKv::new();
        let big = "k".repeat(crate::error::MAX_KEY_BYTES + 1);
        let err = store
            .put(&big, Bytes::from_static(b"v"), Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::KeyTooLarge { .. }));
    }

    // --- PersistentKv coverage ---

    #[tokio::test]
    async fn persistent_crud_round_trip() {
        let store = MockPersistentKv::new();
        store
            .put("config:a", Bytes::from_static(b"alpha"))
            .await
            .unwrap();
        assert_eq!(
            store.get("config:a").await.unwrap().as_deref(),
            Some(&b"alpha"[..])
        );
        store.delete("config:a").await.unwrap();
        assert!(store.get("config:a").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn persistent_list_prefix_matches_only_prefix() {
        let store = MockPersistentKv::new();
        store
            .put("ws/1/policy", Bytes::from_static(b"p1"))
            .await
            .unwrap();
        store
            .put("ws/1/route", Bytes::from_static(b"r1"))
            .await
            .unwrap();
        store
            .put("ws/2/policy", Bytes::from_static(b"p2"))
            .await
            .unwrap();
        let mut keys = store.list_prefix("ws/1/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["ws/1/policy".to_string(), "ws/1/route".into()]);
    }

    // --- PubSub coverage ---

    #[tokio::test]
    async fn pubsub_publish_then_subscribe_misses_message() {
        // Late subscribers do not receive historical messages, per
        // the trait contract.
        let bus = MockPubSub::new();
        bus.publish("waf:rules", Bytes::from_static(b"r1"))
            .await
            .unwrap();
        let mut sub = bus.subscribe("waf:rules").await.unwrap();
        // Nothing buffered, so a follow-up publish is the only way
        // to wake the subscriber.
        bus.publish("waf:rules", Bytes::from_static(b"r2"))
            .await
            .unwrap();
        let msg = sub.next().await.unwrap();
        assert_eq!(msg.as_deref(), Some(&b"r2"[..]));
    }

    #[tokio::test]
    async fn pubsub_fan_out_to_multiple_subscribers() {
        let bus = MockPubSub::new();
        let mut sub_a = bus.subscribe("entitlements").await.unwrap();
        let mut sub_b = bus.subscribe("entitlements").await.unwrap();
        bus.publish("entitlements", Bytes::from_static(b"invalidate"))
            .await
            .unwrap();
        let a = sub_a.next().await.unwrap();
        let b = sub_b.next().await.unwrap();
        assert_eq!(a.as_deref(), Some(&b"invalidate"[..]));
        assert_eq!(b.as_deref(), Some(&b"invalidate"[..]));
    }

    #[tokio::test]
    async fn pubsub_dropping_subscription_unsubscribes() {
        let bus = MockPubSub::new();
        let sub = bus.subscribe("ch").await.unwrap();
        drop(sub);
        // Publish should succeed even with the only subscriber gone.
        bus.publish("ch", Bytes::from_static(b"orphan"))
            .await
            .unwrap();
    }

    // --- HashKv coverage ---

    fn b(s: &'static str) -> Bytes {
        Bytes::from_static(s.as_bytes())
    }

    #[tokio::test]
    async fn mock_hash_round_trip_per_field() {
        let s = MockHashKv::new();
        s.hset("ent", "plan", b("pro")).await.unwrap();
        s.hset("ent", "seats", b("10")).await.unwrap();
        assert_eq!(
            s.hget("ent", "plan").await.unwrap().as_deref(),
            Some(&b"pro"[..])
        );
        assert!(s.hexists("ent", "seats").await.unwrap());
    }

    #[tokio::test]
    async fn mock_hash_multi_set_and_getall() {
        let s = MockHashKv::new();
        s.hset_multi("ent", &[("a", b("1")), ("b", b("2"))])
            .await
            .unwrap();
        let mut all = s.hgetall("ent").await.unwrap();
        all.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(all, vec![("a".into(), b("1")), ("b".into(), b("2"))]);
    }

    #[tokio::test]
    async fn mock_hash_del_collapses_empty_parent() {
        let s = MockHashKv::new();
        s.hset("ent", "only", b("x")).await.unwrap();
        s.hdel("ent", "only").await.unwrap();
        assert!(s.hgetall("ent").await.unwrap().is_empty());
    }

    // --- SetKv coverage ---

    #[tokio::test]
    async fn mock_set_dedups_on_add() {
        let s = MockSetKv::new();
        let added = s.sadd("p", &[b("a"), b("b"), b("a")]).await.unwrap();
        assert_eq!(added, 2);
        assert_eq!(s.scard("p").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn mock_set_rem_only_counts_present() {
        let s = MockSetKv::new();
        s.sadd("p", &[b("a"), b("b")]).await.unwrap();
        let removed = s.srem("p", &[b("a"), b("zzz")]).await.unwrap();
        assert_eq!(removed, 1);
        assert!(!s.sismember("p", &b("a")).await.unwrap());
    }

    #[tokio::test]
    async fn mock_set_members_returns_full_set() {
        let s = MockSetKv::new();
        s.sadd("p", &[b("a"), b("b")]).await.unwrap();
        let mut got = s.smembers("p").await.unwrap();
        got.sort();
        assert_eq!(got, vec![b("a"), b("b")]);
    }

    // --- StreamKv coverage ---

    #[tokio::test]
    async fn mock_stream_xadd_assigns_monotonic_ids() {
        let s = MockStreamKv::new();
        let id1 = s.xadd("f", &[("v", b("1"))]).await.unwrap();
        let id2 = s.xadd("f", &[("v", b("2"))]).await.unwrap();
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn mock_stream_xread_resumes_after_id() {
        let s = MockStreamKv::new();
        let id1 = s.xadd("f", &[("v", b("a"))]).await.unwrap();
        s.xadd("f", &[("v", b("b"))]).await.unwrap();
        let after = s.xread("f", &id1, 10).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].fields[0].1, b("b"));
        assert!(s.xread("f", "$", 10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn mock_stream_xtrim_drops_oldest() {
        let s = MockStreamKv::new();
        for i in 0..5 {
            s.xadd("f", &[("i", Bytes::from(i.to_string()))])
                .await
                .unwrap();
        }
        let removed = s.xtrim("f", 2).await.unwrap();
        assert_eq!(removed, 3);
        let rem = s.xread("f", "0-0", 100).await.unwrap();
        assert_eq!(rem.len(), 2);
    }
}
