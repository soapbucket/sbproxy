// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Soap Bucket LLC

//! Redis backend for the storage traits.
//!
//! [`RedisStore`] implements [`EphemeralKv`] and [`PersistentKv`]
//! against a single Redis logical database, plus [`PubSub`] over native
//! `PUBLISH` / `SUBSCRIBE`. Multi-replica deployments share one store
//! across every process.
//!
//! ## Connection lifecycle
//!
//! The struct holds a `redis::Client` (cheap, just parses the URL) and
//! lazily opens a `MultiplexedConnection` on first use. Multiplexed
//! connections pool requests over a single TCP socket, which fits the
//! KV / list-prefix workload. Pub/sub is the exception: Redis requires
//! a dedicated connection per subscriber, so [`RedisStore::subscribe`]
//! opens a fresh `aio::PubSub` every call.
//!
//! ## Key prefix
//!
//! Every operation prepends `"{prefix}:"` to the supplied key. Run
//! distinct workspaces (or distinct deployments sharing a Redis
//! instance) under distinct prefixes so a `list_prefix` cannot leak
//! across them.
//!
//! ## Error mapping
//!
//! `redis::RedisError::is_timeout` becomes [`StorageError::Timeout`].
//! `is_io_error` or `is_connection_dropped` becomes
//! [`StorageError::Disconnected`]. Everything else
//! ([`redis::ErrorKind::ResponseError`], `MOVED`, type errors) maps to
//! [`StorageError::Backend`] with the original message preserved so
//! operators can grep logs.
//!
//! ## SCAN cap
//!
//! [`RedisStore::list_prefix`] uses `SCAN MATCH {prefix}*` with `COUNT 500`
//! and stops after collecting [`MAX_LIST_PREFIX_KEYS`] keys. Callers
//! that need every key must paginate at the application layer; the
//! abstraction does not surface a cursor because the in-memory and
//! mesh backends do not have one.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use redis::{aio::MultiplexedConnection, AsyncCommands};
use tokio::sync::Mutex;

use crate::error::{check_key, check_value, StorageError};
use crate::metrics::observe_op;
use crate::traits::{
    EphemeralKv, HashKv, PersistentKv, PubSub, SetKv, StreamEntry, StreamKv, Subscription,
};

/// Backend label for metrics.
const BACKEND: &str = "redis";

/// Hard cap on keys returned by a single `list_prefix` call. Matches
/// the `SCAN COUNT` budget the existing entitlement and WAF crates
/// use; documented in the module-level docs so callers don't expect
/// unbounded enumeration.
pub const MAX_LIST_PREFIX_KEYS: usize = 1000;

/// Page size hint passed to `SCAN COUNT`. Larger means fewer round
/// trips at the cost of more wasted work when the prefix is sparse.
const SCAN_COUNT: usize = 500;

// --- Store ---

/// Redis-backed implementation of [`EphemeralKv`], [`PersistentKv`],
/// and [`PubSub`].
///
/// Cloneable: the underlying `redis::Client` and the cached
/// `MultiplexedConnection` are both shared via `Arc` internally, so
/// multiple call sites can hold their own clone without re-parsing
/// the URL or re-opening the socket.
#[derive(Clone)]
pub struct RedisStore {
    client: redis::Client,
    key_prefix: String,
    /// Lazily-initialised multiplexed connection. The `Mutex` only
    /// guards the *initialisation* race: once filled, the connection
    /// itself is internally synchronised by the redis crate, so
    /// repeated callers `clone()` the inner `MultiplexedConnection`
    /// without contending on the mutex.
    conn: Arc<Mutex<Option<MultiplexedConnection>>>,
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip the client (its Debug pretty-prints the URL, which may
        // include a password) and the connection (which is huge).
        f.debug_struct("RedisStore")
            .field("key_prefix", &self.key_prefix)
            .field(
                "connection_initialised",
                &self.conn.try_lock().map(|g| g.is_some()).unwrap_or(false),
            )
            .finish()
    }
}

impl RedisStore {
    /// Build a new store. Validates the URL eagerly so misconfigured
    /// callers fail at boot rather than on the first `get` / `put`.
    /// Connection establishment is lazy: the first I/O method opens
    /// the multiplexed connection and caches it, so a temporarily
    /// unavailable Redis at construction time is not fatal.
    pub fn new(redis_url: &str, key_prefix: impl Into<String>) -> Result<Self, StorageError> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            StorageError::InvalidConfig(format!("invalid redis url {redis_url:?}: {e}"))
        })?;
        Ok(Self {
            client,
            key_prefix: key_prefix.into(),
            conn: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns the fully-qualified key (prefix + supplied key). Public
    /// so operators can grep their Redis instance for keys belonging
    /// to a particular store.
    pub fn key_for(&self, key: &str) -> String {
        if self.key_prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}:{}", self.key_prefix, key)
        }
    }

    /// Strip the configured prefix off a Redis key returned by SCAN.
    /// Used to undo [`Self::key_for`] for the `list_prefix` result.
    fn strip_prefix(&self, full: &str) -> String {
        if self.key_prefix.is_empty() {
            return full.to_string();
        }
        let with_sep = format!("{}:", self.key_prefix);
        full.strip_prefix(&with_sep).unwrap_or(full).to_string()
    }

    /// Lazily resolve the cached multiplexed connection. The first
    /// caller pays the connection cost; subsequent callers clone the
    /// already-open connection (cheap; the redis crate documents
    /// `MultiplexedConnection::clone` as cheap).
    async fn connection(&self) -> Result<MultiplexedConnection, StorageError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(map_redis_error)?;
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

// --- Error mapping ---

/// Translate a `redis::RedisError` onto our taxonomy. Inspects the
/// error kind first (so `ResponseError`, `MOVED`, etc. surface as
/// retryable backend errors) and then the IO / timeout flags.
fn map_redis_error(err: redis::RedisError) -> StorageError {
    if err.is_timeout() {
        // Redis crate does not expose the actual elapsed duration on
        // timeout errors, so we record a sentinel zero. The metrics
        // layer still records the real wallclock latency separately.
        return StorageError::Timeout(Duration::from_secs(0));
    }
    if err.is_io_error() || err.is_connection_dropped() || err.is_connection_refusal() {
        return StorageError::Disconnected;
    }
    StorageError::Backend(err.to_string())
}

// --- EphemeralKv ---

#[async_trait]
impl EphemeralKv for RedisStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        observe_op("get", BACKEND, "ephemeral", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let raw: Option<Vec<u8>> = conn.get(&full).await.map_err(map_redis_error)?;
            Ok(raw.map(Bytes::from))
        })
        .await
    }

    async fn put(&self, key: &str, value: Bytes, ttl: Duration) -> Result<(), StorageError> {
        observe_op("put", BACKEND, "ephemeral", async {
            check_key(key)?;
            check_value(&value)?;
            // SET key value EX ttl. We pin a minimum of 1s since
            // Redis SETEX rejects 0; Duration::ZERO is treated as
            // "evict immediately on next access" via a 1s lower bound,
            // which matches the practical semantics callers want and
            // avoids a hard error.
            let ttl_secs = ttl.as_secs().max(1);
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            // `set_ex` is the typed wrapper for SET ... EX.
            let _: () = conn
                .set_ex(&full, value.as_ref(), ttl_secs)
                .await
                .map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn take(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        observe_op("take", BACKEND, "ephemeral", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            // GETDEL is atomic on Redis 6.2+. Issue as a raw command
            // so we stay independent of the typed helper signatures
            // across redis crate minor versions.
            let raw: Option<Vec<u8>> = redis::cmd("GETDEL")
                .arg(&full)
                .query_async(&mut conn)
                .await
                .map_err(map_redis_error)?;
            Ok(raw.map(Bytes::from))
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        observe_op("delete", BACKEND, "ephemeral", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let _: i64 = conn.del(&full).await.map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        observe_op("exists", BACKEND, "ephemeral", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            // Single-round-trip key probe; avoids fetching the value
            // buffer that `GET` would. Redis EXISTS returns the count
            // of supplied keys that exist, capped at 1 here.
            let count: i64 = conn.exists(&full).await.map_err(map_redis_error)?;
            Ok(count > 0)
        })
        .await
    }
}

// --- PersistentKv ---

#[async_trait]
impl PersistentKv for RedisStore {
    async fn get(&self, key: &str) -> Result<Option<Bytes>, StorageError> {
        observe_op("get", BACKEND, "persistent", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let raw: Option<Vec<u8>> = conn.get(&full).await.map_err(map_redis_error)?;
            Ok(raw.map(Bytes::from))
        })
        .await
    }

    async fn put(&self, key: &str, value: Bytes) -> Result<(), StorageError> {
        observe_op("put", BACKEND, "persistent", async {
            check_key(key)?;
            check_value(&value)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let _: () = conn
                .set(&full, value.as_ref())
                .await
                .map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        observe_op("delete", BACKEND, "persistent", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let _: i64 = conn.del(&full).await.map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        observe_op("list_prefix", BACKEND, "persistent", async {
            // The pattern is the prefix + everything-glob. We do NOT
            // escape `*`, `?`, or `[` in the supplied prefix because
            // entitlement / WAF callers depend on glob behaviour. If
            // a future caller needs literal-glob matching we will add
            // a separate helper.
            let pattern = format!("{}*", self.key_for(prefix));
            let mut conn = self.connection().await?;
            let mut iter = conn
                .scan_match::<_, String>(&pattern)
                .await
                .map_err(map_redis_error)?;

            let mut out = Vec::new();
            while let Some(full) = iter.next().await {
                out.push(self.strip_prefix(&full));
                if out.len() >= MAX_LIST_PREFIX_KEYS {
                    tracing::warn!(
                        prefix = %prefix,
                        cap = MAX_LIST_PREFIX_KEYS,
                        "list_prefix hit cap; results truncated"
                    );
                    break;
                }
            }
            Ok(out)
        })
        .await
    }
}

impl RedisStore {
    /// Default SCAN page hint, exposed for tests / docs.
    #[doc(hidden)]
    pub const fn scan_count() -> usize {
        SCAN_COUNT
    }
}

// --- PubSub ---

#[async_trait]
impl PubSub for RedisStore {
    async fn publish(&self, channel: &str, message: Bytes) -> Result<(), StorageError> {
        observe_op("publish", BACKEND, "pubsub", async {
            check_key(channel)?;
            check_value(&message)?;
            let full = self.key_for(channel);
            let mut conn = self.connection().await?;
            // `publish` returns the number of receivers Redis knew
            // about; we discard it (callers that care should query
            // `PUBSUB NUMSUB` separately).
            let _: i64 = conn
                .publish(&full, message.as_ref())
                .await
                .map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn subscribe(&self, channel: &str) -> Result<Box<dyn Subscription + Send>, StorageError> {
        observe_op("subscribe", BACKEND, "pubsub", async {
            check_key(channel)?;
            let full = self.key_for(channel);
            // Pub/sub needs a dedicated connection. `get_async_pubsub`
            // opens a fresh one every call, which matches Redis's
            // protocol requirement (a connection in subscribe mode
            // cannot serve other commands).
            let mut pubsub = self
                .client
                .get_async_pubsub()
                .await
                .map_err(map_redis_error)?;
            pubsub.subscribe(&full).await.map_err(map_redis_error)?;
            Ok(Box::new(RedisSubscription {
                inner: pubsub,
                _channel: full,
            }) as Box<dyn Subscription + Send>)
        })
        .await
    }
}

/// Subscription returned by [`RedisStore::subscribe`].
///
/// Holds the dedicated `redis::aio::PubSub` connection alive. Dropping
/// the struct closes the connection, which Redis interprets as an
/// unsubscribe.
pub struct RedisSubscription {
    inner: redis::aio::PubSub,
    /// Kept for diagnostics. Not used at runtime, but tools that dump
    /// active subscriptions can read it via Debug if we ever add one.
    _channel: String,
}

#[async_trait]
impl Subscription for RedisSubscription {
    async fn next(&mut self) -> Result<Option<Bytes>, StorageError> {
        // `on_message` is a stream of `Msg`. Returning `Ok(None)`
        // (channel closed) when the stream ends matches the trait
        // contract; pubsub IO errors propagate via the StreamExt path
        // as `None` because the redis crate filters them silently. We
        // therefore cannot distinguish "clean close" from "IO error"
        // here; callers treating `Ok(None)` as "re-subscribe" are
        // doing the right thing.
        let mut stream = self.inner.on_message();
        match stream.next().await {
            Some(msg) => {
                let payload: Vec<u8> = msg
                    .get_payload()
                    .map_err(|e| StorageError::Backend(format!("pubsub payload decode: {e}")))?;
                Ok(Some(Bytes::from(payload)))
            }
            None => Ok(None),
        }
    }
}

// --- HashKv ---

#[async_trait]
impl HashKv for RedisStore {
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Bytes>, StorageError> {
        observe_op("hget", BACKEND, "hash", async {
            check_key(key)?;
            check_key(field)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let raw: Option<Vec<u8>> = conn.hget(&full, field).await.map_err(map_redis_error)?;
            Ok(raw.map(Bytes::from))
        })
        .await
    }

    async fn hset(&self, key: &str, field: &str, value: Bytes) -> Result<(), StorageError> {
        observe_op("hset", BACKEND, "hash", async {
            check_key(key)?;
            check_key(field)?;
            check_value(&value)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let _: i64 = conn
                .hset(&full, field, value.as_ref())
                .await
                .map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn hset_multi(&self, key: &str, fields: &[(&str, Bytes)]) -> Result<(), StorageError> {
        observe_op("hset_multi", BACKEND, "hash", async {
            check_key(key)?;
            for (f, v) in fields {
                check_key(f)?;
                check_value(v)?;
            }
            if fields.is_empty() {
                return Ok(());
            }
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            // Build the variadic HSET argument list. Redis 4.0+ accepts
            // multiple field/value pairs in a single HSET, which avoids
            // the deprecated HMSET path.
            let pairs: Vec<(&str, &[u8])> = fields.iter().map(|(f, v)| (*f, v.as_ref())).collect();
            let _: i64 = conn
                .hset_multiple(&full, &pairs)
                .await
                .map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn hgetall(&self, key: &str) -> Result<Vec<(String, Bytes)>, StorageError> {
        observe_op("hgetall", BACKEND, "hash", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            // HGETALL returns flat field/value pairs. We collect into a
            // Vec<(String, Vec<u8>)> first so the redis crate's typed
            // FromRedisValue does the heavy lifting, then reshape into
            // the trait's `Bytes` value type.
            let pairs: Vec<(String, Vec<u8>)> =
                conn.hgetall(&full).await.map_err(map_redis_error)?;
            Ok(pairs
                .into_iter()
                .map(|(k, v)| (k, Bytes::from(v)))
                .collect())
        })
        .await
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<(), StorageError> {
        observe_op("hdel", BACKEND, "hash", async {
            check_key(key)?;
            check_key(field)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let _: i64 = conn.hdel(&full, field).await.map_err(map_redis_error)?;
            Ok(())
        })
        .await
    }

    async fn hexists(&self, key: &str, field: &str) -> Result<bool, StorageError> {
        observe_op("hexists", BACKEND, "hash", async {
            check_key(key)?;
            check_key(field)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let exists: bool = conn.hexists(&full, field).await.map_err(map_redis_error)?;
            Ok(exists)
        })
        .await
    }
}

// --- SetKv ---

#[async_trait]
impl SetKv for RedisStore {
    async fn sadd(&self, key: &str, members: &[Bytes]) -> Result<u64, StorageError> {
        observe_op("sadd", BACKEND, "set", async {
            check_key(key)?;
            for m in members {
                check_value(m)?;
            }
            if members.is_empty() {
                return Ok(0);
            }
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let raw: Vec<&[u8]> = members.iter().map(|m| m.as_ref()).collect();
            let added: i64 = conn.sadd(&full, raw).await.map_err(map_redis_error)?;
            Ok(added.max(0) as u64)
        })
        .await
    }

    async fn srem(&self, key: &str, members: &[Bytes]) -> Result<u64, StorageError> {
        observe_op("srem", BACKEND, "set", async {
            check_key(key)?;
            for m in members {
                check_value(m)?;
            }
            if members.is_empty() {
                return Ok(0);
            }
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let raw: Vec<&[u8]> = members.iter().map(|m| m.as_ref()).collect();
            let removed: i64 = conn.srem(&full, raw).await.map_err(map_redis_error)?;
            Ok(removed.max(0) as u64)
        })
        .await
    }

    async fn smembers(&self, key: &str) -> Result<Vec<Bytes>, StorageError> {
        observe_op("smembers", BACKEND, "set", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let members: Vec<Vec<u8>> = conn.smembers(&full).await.map_err(map_redis_error)?;
            Ok(members.into_iter().map(Bytes::from).collect())
        })
        .await
    }

    async fn scard(&self, key: &str) -> Result<u64, StorageError> {
        observe_op("scard", BACKEND, "set", async {
            check_key(key)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let card: i64 = conn.scard(&full).await.map_err(map_redis_error)?;
            Ok(card.max(0) as u64)
        })
        .await
    }

    async fn sismember(&self, key: &str, member: &Bytes) -> Result<bool, StorageError> {
        observe_op("sismember", BACKEND, "set", async {
            check_key(key)?;
            check_value(member)?;
            let full = self.key_for(key);
            let mut conn = self.connection().await?;
            let m: bool = conn
                .sismember(&full, member.as_ref())
                .await
                .map_err(map_redis_error)?;
            Ok(m)
        })
        .await
    }
}

// --- StreamKv ---

#[async_trait]
impl StreamKv for RedisStore {
    async fn xadd(&self, stream: &str, entry: &[(&str, Bytes)]) -> Result<String, StorageError> {
        observe_op("xadd", BACKEND, "stream", async {
            check_key(stream)?;
            for (f, v) in entry {
                check_key(f)?;
                check_value(v)?;
            }
            if entry.is_empty() {
                return Err(StorageError::InvalidConfig(
                    "xadd requires at least one field".into(),
                ));
            }
            let full = self.key_for(stream);
            let mut conn = self.connection().await?;
            // Build XADD <key> * <f1> <v1> <f2> <v2> ... as a raw
            // command so we control the binding precisely; the typed
            // helper's signature evolves between minor versions.
            let mut cmd = redis::cmd("XADD");
            cmd.arg(&full).arg("*");
            for (f, v) in entry {
                cmd.arg(*f).arg(v.as_ref());
            }
            let id: String = cmd.query_async(&mut conn).await.map_err(map_redis_error)?;
            Ok(id)
        })
        .await
    }

    async fn xread(
        &self,
        stream: &str,
        since_id: &str,
        count: usize,
    ) -> Result<Vec<StreamEntry>, StorageError> {
        observe_op("xread", BACKEND, "stream", async {
            check_key(stream)?;
            let full = self.key_for(stream);
            let mut conn = self.connection().await?;
            // XREAD COUNT <n> STREAMS <key> <since_id>. We do NOT use
            // BLOCK; the trait contract is non-blocking, and a `$`
            // cursor on a non-blocking XREAD just returns nothing,
            // which matches the documented in-memory / Postgres
            // behaviour.
            let mut cmd = redis::cmd("XREAD");
            cmd.arg("COUNT")
                .arg(count)
                .arg("STREAMS")
                .arg(&full)
                .arg(since_id);
            // The Redis reply shape is:
            //   [[stream_name, [[id, [f1, v1, f2, v2, ...]], ...]], ...]
            // or `nil` if nothing matched. We decode into the loosely-
            // typed `redis::Value` to handle both shapes uniformly.
            let raw: redis::Value = cmd.query_async(&mut conn).await.map_err(map_redis_error)?;
            Ok(parse_xread_reply(&raw))
        })
        .await
    }

    async fn xtrim(&self, stream: &str, max_len: usize) -> Result<u64, StorageError> {
        observe_op("xtrim", BACKEND, "stream", async {
            check_key(stream)?;
            let full = self.key_for(stream);
            let mut conn = self.connection().await?;
            // MAXLEN ~ <n> uses the approximate trim path which is much
            // cheaper than the exact form on large streams. The trait
            // contract does not promise an exact bound, only "at most
            // approximately max_len", which matches the WAF feed and
            // entitlements use-cases.
            let removed: i64 = redis::cmd("XTRIM")
                .arg(&full)
                .arg("MAXLEN")
                .arg("~")
                .arg(max_len)
                .query_async(&mut conn)
                .await
                .map_err(map_redis_error)?;
            Ok(removed.max(0) as u64)
        })
        .await
    }
}

/// Decode the nested `XREAD` reply into a flat `Vec<StreamEntry>`.
/// Anything we cannot interpret is treated as "no entries" rather than
/// an error: a malformed reply is always a backend bug and the caller
/// just polls again.
fn parse_xread_reply(raw: &redis::Value) -> Vec<StreamEntry> {
    use redis::Value as V;
    let streams = match raw {
        V::Array(s) => s,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for stream in streams {
        let parts = match stream {
            V::Array(p) if p.len() == 2 => p,
            _ => continue,
        };
        let entries = match &parts[1] {
            V::Array(e) => e,
            _ => continue,
        };
        for entry in entries {
            let pair = match entry {
                V::Array(p) if p.len() == 2 => p,
                _ => continue,
            };
            let id = match &pair[0] {
                V::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                V::SimpleString(s) => s.clone(),
                _ => continue,
            };
            let fields = match &pair[1] {
                V::Array(fv) => fv,
                _ => continue,
            };
            let mut field_vec = Vec::with_capacity(fields.len() / 2);
            let mut iter = fields.iter();
            while let (Some(fv), Some(vv)) = (iter.next(), iter.next()) {
                let field = match fv {
                    V::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                    V::SimpleString(s) => s.clone(),
                    _ => continue,
                };
                let value = match vv {
                    V::BulkString(b) => Bytes::from(b.clone()),
                    V::SimpleString(s) => Bytes::from(s.clone().into_bytes()),
                    _ => continue,
                };
                field_vec.push((field, value));
            }
            out.push(StreamEntry {
                id,
                fields: field_vec,
            });
        }
    }
    out
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;

    // --- Construction (no live Redis) ---

    #[test]
    fn new_rejects_malformed_url() {
        let err = RedisStore::new("not a url at all", "ws").unwrap_err();
        assert!(matches!(err, StorageError::InvalidConfig(_)));
    }

    #[test]
    fn new_accepts_well_formed_url_lazily() {
        // Pointing at a closed port is fine: connection is lazy.
        let store = RedisStore::new("redis://127.0.0.1:1/0", "ws").expect("URL parses");
        assert_eq!(store.key_for("abc"), "ws:abc");
    }

    #[test]
    fn key_for_with_empty_prefix_passes_through() {
        let store = RedisStore::new("redis://127.0.0.1:6379/0", "").unwrap();
        assert_eq!(store.key_for("plain"), "plain");
        assert_eq!(store.strip_prefix("plain"), "plain");
    }

    #[test]
    fn strip_prefix_round_trips_with_key_for() {
        let store = RedisStore::new("redis://127.0.0.1:6379/0", "ws/1").unwrap();
        let full = store.key_for("session:abc");
        assert_eq!(full, "ws/1:session:abc");
        assert_eq!(store.strip_prefix(&full), "session:abc");
    }

    #[test]
    fn debug_does_not_leak_password() {
        let store = RedisStore::new("redis://user:supersecret@127.0.0.1:6379/0", "ws").unwrap();
        let dbg = format!("{store:?}");
        assert!(!dbg.contains("supersecret"), "Debug must not leak password");
    }

    // --- Live tests, opt-in via env var ---
    //
    // CI does not run these by default. Local contributors enable
    // them with:
    //
    //     STORAGE_TEST_REDIS_URL=redis://127.0.0.1:6379/15 \
    //       cargo test -p sbproxy-storage --lib \
    //       --features mock -- --ignored

    fn live_url() -> Option<String> {
        std::env::var("STORAGE_TEST_REDIS_URL").ok()
    }

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_REDIS_URL"]
    async fn live_ephemeral_round_trip() {
        let url = match live_url() {
            Some(u) => u,
            None => return,
        };
        let store = RedisStore::new(&url, "test:ephem").unwrap();
        let key = format!("k-{}", std::process::id());
        EphemeralKv::put(
            &store,
            &key,
            Bytes::from_static(b"hello"),
            Duration::from_secs(10),
        )
        .await
        .expect("put succeeds");
        let got = EphemeralKv::get(&store, &key).await.expect("get succeeds");
        assert_eq!(got.as_deref(), Some(&b"hello"[..]));
        let taken = store.take(&key).await.expect("take succeeds");
        assert_eq!(taken.as_deref(), Some(&b"hello"[..]));
        // Take is single-use.
        let again = store.take(&key).await.expect("take after empty");
        assert!(again.is_none());
    }

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_REDIS_URL"]
    async fn live_persistent_round_trip_and_list_prefix() {
        let url = match live_url() {
            Some(u) => u,
            None => return,
        };
        // Distinct prefix per test run so parallel runs don't trample.
        let prefix = format!("test:persist:{}", std::process::id());
        let store = RedisStore::new(&url, &prefix).unwrap();

        for i in 0..3 {
            PersistentKv::put(&store, &format!("k{i}"), Bytes::from(format!("v{i}")))
                .await
                .unwrap();
        }
        let got = PersistentKv::get(&store, "k1").await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"v1"[..]));

        let mut keys = PersistentKv::list_prefix(&store, "k").await.unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec!["k0".to_string(), "k1".to_string(), "k2".to_string()]
        );

        // Cleanup so subsequent runs do not see stale data.
        for i in 0..3 {
            PersistentKv::delete(&store, &format!("k{i}"))
                .await
                .unwrap();
        }
    }

    // --- parse_xread_reply (offline) ---

    #[test]
    fn parse_xread_reply_handles_well_formed_reply() {
        use redis::Value as V;
        // [["mystream", [["1-0", ["field1", "v1"]], ["2-0", ["field2", "v2"]]]]]
        let reply = V::Array(vec![V::Array(vec![
            V::BulkString(b"mystream".to_vec()),
            V::Array(vec![
                V::Array(vec![
                    V::BulkString(b"1-0".to_vec()),
                    V::Array(vec![
                        V::BulkString(b"field1".to_vec()),
                        V::BulkString(b"v1".to_vec()),
                    ]),
                ]),
                V::Array(vec![
                    V::BulkString(b"2-0".to_vec()),
                    V::Array(vec![
                        V::BulkString(b"field2".to_vec()),
                        V::BulkString(b"v2".to_vec()),
                    ]),
                ]),
            ]),
        ])]);
        let parsed = parse_xread_reply(&reply);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "1-0");
        assert_eq!(
            parsed[0].fields,
            vec![("field1".into(), Bytes::from_static(b"v1"))]
        );
        assert_eq!(parsed[1].id, "2-0");
    }

    #[test]
    fn parse_xread_reply_is_empty_on_nil() {
        let parsed = parse_xread_reply(&redis::Value::Nil);
        assert!(parsed.is_empty());
    }

    // --- Live HashKv / SetKv / StreamKv ---

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_REDIS_URL"]
    async fn live_hash_round_trip() {
        let url = match live_url() {
            Some(u) => u,
            None => return,
        };
        let store = RedisStore::new(&url, "test:hash").unwrap();
        let key = format!("h-{}", std::process::id());
        store
            .hset_multi(
                &key,
                &[
                    ("plan", Bytes::from_static(b"pro")),
                    ("seats", Bytes::from_static(b"10")),
                ],
            )
            .await
            .unwrap();
        assert_eq!(
            store.hget(&key, "plan").await.unwrap().as_deref(),
            Some(&b"pro"[..])
        );
        assert!(store.hexists(&key, "seats").await.unwrap());
        let mut all = store.hgetall(&key).await.unwrap();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(all.len(), 2);
        store.hdel(&key, "seats").await.unwrap();
        assert!(!store.hexists(&key, "seats").await.unwrap());
        // Cleanup the parent hash.
        store.hdel(&key, "plan").await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_REDIS_URL"]
    async fn live_set_round_trip() {
        let url = match live_url() {
            Some(u) => u,
            None => return,
        };
        let store = RedisStore::new(&url, "test:set").unwrap();
        let key = format!("s-{}", std::process::id());
        let added = store
            .sadd(
                &key,
                &[
                    Bytes::from_static(b"a"),
                    Bytes::from_static(b"b"),
                    Bytes::from_static(b"a"),
                ],
            )
            .await
            .unwrap();
        assert_eq!(added, 2);
        assert_eq!(store.scard(&key).await.unwrap(), 2);
        assert!(store
            .sismember(&key, &Bytes::from_static(b"a"))
            .await
            .unwrap());
        let removed = store.srem(&key, &[Bytes::from_static(b"a")]).await.unwrap();
        assert_eq!(removed, 1);
        // Cleanup.
        store.srem(&key, &[Bytes::from_static(b"b")]).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_REDIS_URL"]
    async fn live_stream_round_trip() {
        let url = match live_url() {
            Some(u) => u,
            None => return,
        };
        let store = RedisStore::new(&url, "test:stream").unwrap();
        let key = format!("st-{}", std::process::id());
        let id1 = store
            .xadd(&key, &[("v", Bytes::from_static(b"1"))])
            .await
            .unwrap();
        let _id2 = store
            .xadd(&key, &[("v", Bytes::from_static(b"2"))])
            .await
            .unwrap();
        let all = store.xread(&key, "0", 10).await.unwrap();
        assert_eq!(all.len(), 2);
        let after = store.xread(&key, &id1, 10).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].fields[0].1, Bytes::from_static(b"2"));
        // Trim to a single entry.
        let _trimmed = store.xtrim(&key, 1).await.unwrap();
        // Cleanup: best-effort delete via DEL through the persistent
        // surface (the trait does not own a DELETE on the stream key).
        // Use raw command since `del` typed helper is on the store too.
        let _ = PersistentKv::delete(&store, &key).await;
    }

    #[tokio::test]
    #[ignore = "requires STORAGE_TEST_REDIS_URL"]
    async fn live_pubsub_round_trip() {
        let url = match live_url() {
            Some(u) => u,
            None => return,
        };
        let store = RedisStore::new(&url, "test:pubsub").unwrap();
        let channel = format!("c-{}", std::process::id());

        let mut sub = store.subscribe(&channel).await.expect("subscribe");
        // Give the subscription time to register before publishing.
        tokio::time::sleep(Duration::from_millis(50)).await;

        store
            .publish(&channel, Bytes::from_static(b"payload"))
            .await
            .expect("publish");

        let msg = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await
            .expect("did not time out")
            .expect("Ok result")
            .expect("got a message");
        assert_eq!(msg.as_ref(), b"payload");
    }
}
