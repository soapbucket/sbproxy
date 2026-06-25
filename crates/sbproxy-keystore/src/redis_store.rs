//! Redis [`KeyStore`] backend and cache tier.
//!
//! Two roles, both over the same async multiplexed connection:
//!
//! * [`RedisKeyStore`] is a `KeyStore` over Redis hashes (`keys` and
//!   `credentials`), usable as the source of truth for a replica fleet or as a
//!   coherence tier behind the embedded store. Every mutation bumps a revision
//!   counter and publishes the changed id on a pub/sub channel.
//! * [`RedisCacheTier`] is a best-effort [`CacheTier`] (the L2 behind the
//!   in-memory L1), storing serialized records with a TTL.
//!
//! [`subscribe_invalidations`] runs a background task that listens on the
//! channel and invalidates a local [`TtlCache`] when a peer mutates a record,
//! giving cross-replica instant revoke without a shared in-memory cache.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use redis::{aio::MultiplexedConnection, AsyncCommands, Client};
use tokio::sync::Mutex;

use crate::cache::{CacheTier, TtlCache};
use crate::record::{CredentialRecord, KeyRecord};
use crate::KeyStore;

const KEYS_HASH: &str = "sbproxy:keystore:keys";
const CREDS_HASH: &str = "sbproxy:keystore:credentials";
const REVISION_KEY: &str = "sbproxy:keystore:revision";
const INVALIDATE_CHANNEL: &str = "sbproxy:keystore:invalidate";
const CACHE_KEY_PREFIX: &str = "sbproxy:keystore:cache:key:";
const CACHE_CRED_PREFIX: &str = "sbproxy:keystore:cache:cred:";
/// Sentinel payload meaning "drop everything".
const INVALIDATE_ALL: &str = "*";

/// A lazily-connected, shareable multiplexed Redis link.
struct RedisLink {
    url: String,
    conn: Mutex<Option<MultiplexedConnection>>,
}

impl RedisLink {
    fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            conn: Mutex::new(None),
        }
    }

    /// Return the cached connection, establishing it on first use. The guard is
    /// never held across the connect await so concurrent callers do not
    /// serialize behind whichever one is connecting.
    async fn conn(&self) -> Result<MultiplexedConnection> {
        {
            let guard = self.conn.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(c.clone());
            }
        }
        let client = Client::open(self.url.as_str())
            .with_context(|| format!("invalid redis url '{}'", self.url))?;
        let c = client
            .get_multiplexed_async_connection()
            .await
            .with_context(|| format!("connecting to redis at '{}'", self.url))?;
        let mut guard = self.conn.lock().await;
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.clone());
        }
        *guard = Some(c.clone());
        Ok(c)
    }
}

/// A `KeyStore` backed by Redis hashes.
pub struct RedisKeyStore {
    link: RedisLink,
}

impl RedisKeyStore {
    /// Build a store against the given Redis URL (connection is deferred).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            link: RedisLink::new(url),
        }
    }

    /// Bump the revision counter and announce a changed id to peers.
    async fn announce(&self, c: &mut MultiplexedConnection, id: &str) -> Result<()> {
        let _: i64 = c
            .incr(REVISION_KEY, 1)
            .await
            .context("redis INCR revision")?;
        let _: i64 = c
            .publish(INVALIDATE_CHANNEL, id)
            .await
            .context("redis PUBLISH invalidate")?;
        Ok(())
    }
}

#[async_trait]
impl KeyStore for RedisKeyStore {
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        let mut c = self.link.conn().await?;
        let raw: Option<String> = c.hget(KEYS_HASH, key_id).await.context("redis HGET key")?;
        raw.map(|s| serde_json::from_str(&s).context("decode key record"))
            .transpose()
    }

    async fn list_keys(&self) -> Result<Vec<KeyRecord>> {
        let mut c = self.link.conn().await?;
        let raw: HashMap<String, String> =
            c.hgetall(KEYS_HASH).await.context("redis HGETALL keys")?;
        raw.values()
            .map(|s| serde_json::from_str(s).context("decode key record"))
            .collect()
    }

    async fn put_key(&self, record: KeyRecord) -> Result<()> {
        let bytes = serde_json::to_string(&record).context("encode key record")?;
        let mut c = self.link.conn().await?;
        let _: i64 = c
            .hset(KEYS_HASH, &record.key_id, bytes)
            .await
            .context("redis HSET key")?;
        self.announce(&mut c, &record.key_id).await
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        let mut c = self.link.conn().await?;
        let _: i64 = c.hdel(KEYS_HASH, key_id).await.context("redis HDEL key")?;
        self.announce(&mut c, key_id).await
    }

    async fn get_credential(&self, id: &str) -> Result<Option<CredentialRecord>> {
        let mut c = self.link.conn().await?;
        let raw: Option<String> = c
            .hget(CREDS_HASH, id)
            .await
            .context("redis HGET credential")?;
        raw.map(|s| serde_json::from_str(&s).context("decode credential record"))
            .transpose()
    }

    async fn list_credentials(&self) -> Result<Vec<CredentialRecord>> {
        let mut c = self.link.conn().await?;
        let raw: HashMap<String, String> = c
            .hgetall(CREDS_HASH)
            .await
            .context("redis HGETALL credentials")?;
        raw.values()
            .map(|s| serde_json::from_str(s).context("decode credential record"))
            .collect()
    }

    async fn put_credential(&self, record: CredentialRecord) -> Result<()> {
        let bytes = serde_json::to_string(&record).context("encode credential record")?;
        let mut c = self.link.conn().await?;
        let _: i64 = c
            .hset(CREDS_HASH, &record.id, bytes)
            .await
            .context("redis HSET credential")?;
        self.announce(&mut c, &record.id).await
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        let mut c = self.link.conn().await?;
        let _: i64 = c
            .hdel(CREDS_HASH, id)
            .await
            .context("redis HDEL credential")?;
        self.announce(&mut c, id).await
    }

    async fn revision(&self) -> Result<u64> {
        let mut c = self.link.conn().await?;
        let n: Option<i64> = c.get(REVISION_KEY).await.context("redis GET revision")?;
        Ok(n.unwrap_or(0).max(0) as u64)
    }
}

/// A best-effort Redis L2 cache tier for the [`TtlCache`].
pub struct RedisCacheTier {
    link: RedisLink,
}

impl RedisCacheTier {
    /// Build a cache tier against the given Redis URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            link: RedisLink::new(url),
        }
    }

    async fn set_ex(&self, key: &str, value: String, ttl: Duration) {
        if let Ok(mut c) = self.link.conn().await {
            let secs = ttl.as_secs().max(1);
            let _: Result<(), _> = c.set_ex(key, value, secs).await;
        }
    }

    async fn get_str(&self, key: &str) -> Option<String> {
        let mut c = self.link.conn().await.ok()?;
        c.get(key).await.ok().flatten()
    }
}

#[async_trait]
impl CacheTier for RedisCacheTier {
    async fn get_key(&self, key_id: &str) -> Option<KeyRecord> {
        let raw = self.get_str(&format!("{CACHE_KEY_PREFIX}{key_id}")).await?;
        serde_json::from_str(&raw).ok()
    }

    async fn put_key(&self, record: &KeyRecord, ttl: Duration) {
        if let Ok(json) = serde_json::to_string(record) {
            self.set_ex(&format!("{CACHE_KEY_PREFIX}{}", record.key_id), json, ttl)
                .await;
        }
    }

    async fn get_credential(&self, id: &str) -> Option<CredentialRecord> {
        let raw = self.get_str(&format!("{CACHE_CRED_PREFIX}{id}")).await?;
        serde_json::from_str(&raw).ok()
    }

    async fn put_credential(&self, record: &CredentialRecord, ttl: Duration) {
        if let Ok(json) = serde_json::to_string(record) {
            self.set_ex(&format!("{CACHE_CRED_PREFIX}{}", record.id), json, ttl)
                .await;
        }
    }

    async fn invalidate(&self, id: &str) {
        if let Ok(mut c) = self.link.conn().await {
            let _: Result<i64, _> = c.del(format!("{CACHE_KEY_PREFIX}{id}")).await;
            let _: Result<i64, _> = c.del(format!("{CACHE_CRED_PREFIX}{id}")).await;
            let _: Result<i64, _> = c.publish(INVALIDATE_CHANNEL, id).await;
        }
    }

    async fn invalidate_all(&self) {
        if let Ok(mut c) = self.link.conn().await {
            let _: Result<i64, _> = c.publish(INVALIDATE_CHANNEL, INVALIDATE_ALL).await;
        }
    }
}

/// Spawn nothing; run a blocking loop that subscribes to the invalidation
/// channel and drops matching entries from the local cache when a peer mutates
/// a record. Intended to be `tokio::spawn`ed by the caller.
///
/// Returns only on a fatal connection error; the caller decides whether to
/// retry. Each received id is invalidated in `cache`; the `*` sentinel clears
/// everything.
pub async fn subscribe_invalidations(url: String, cache: Arc<TtlCache>) -> Result<()> {
    use futures::StreamExt;

    let client =
        Client::open(url.as_str()).with_context(|| format!("invalid redis url '{url}'"))?;
    let mut pubsub = client
        .get_async_pubsub()
        .await
        .context("open redis pubsub connection")?;
    pubsub
        .subscribe(INVALIDATE_CHANNEL)
        .await
        .context("subscribe invalidate channel")?;

    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = msg.get_payload().unwrap_or_default();
        if payload == INVALIDATE_ALL {
            cache.invalidate_all().await;
        } else if !payload.is_empty() {
            cache.invalidate(&payload).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::TtlCacheConfig;
    use chrono::{DateTime, Utc};

    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn record_json_roundtrips_for_redis_values() {
        // The Redis store persists records as JSON strings; lock the shape.
        let rec = KeyRecord::new("k1", "h1", ts());
        let s = serde_json::to_string(&rec).unwrap();
        let back: KeyRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn channel_and_hash_names_are_stable() {
        // Cross-replica coherence depends on every node agreeing on these names.
        assert_eq!(KEYS_HASH, "sbproxy:keystore:keys");
        assert_eq!(CREDS_HASH, "sbproxy:keystore:credentials");
        assert_eq!(INVALIDATE_CHANNEL, "sbproxy:keystore:invalidate");
    }

    #[test]
    fn new_defers_connection() {
        // A bad URL is fine until we actually try to connect.
        let store = RedisKeyStore::new("redis://127.0.0.1:1");
        let tier = RedisCacheTier::new("redis://127.0.0.1:1");
        let _ = (&store, &tier);
    }

    #[tokio::test]
    #[ignore = "requires live redis; set REDIS_URL"]
    async fn live_roundtrip_and_invalidate() {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let store = RedisKeyStore::new(&url);
        let mut rec = KeyRecord::new("live-test", "h", ts());
        rec.name = Some("live".into());
        store.put_key(rec).await.unwrap();
        let got = store.get_key("live-test").await.unwrap().unwrap();
        assert_eq!(got.name.as_deref(), Some("live"));
        assert!(store.revision().await.unwrap() >= 1);
        store.delete_key("live-test").await.unwrap();
        assert!(store.get_key("live-test").await.unwrap().is_none());

        // The cache tier round-trips a record under a TTL.
        let tier = RedisCacheTier::new(&url);
        let cached = KeyRecord::new("tier-test", "h", ts());
        tier.put_key(&cached, Duration::from_secs(30)).await;
        assert!(tier.get_key("tier-test").await.is_some());
        tier.invalidate("tier-test").await;
        assert!(tier.get_key("tier-test").await.is_none());

        // Touch the unused config import so the test file exercises it.
        let _ = TtlCacheConfig::default();
    }
}
