//! Redis [`KeyStore`] backend and cache tier.
//!
//! Two roles, both over the same reconnecting multiplexed connection.
//! The link type below is where that reconnect contract is written down:
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
use redis::{
    aio::{ConnectionManager, ConnectionManagerConfig},
    AsyncCommands, Client,
};
use sbproxy_security::url_redact::redacted_url_with_path;
use tokio::sync::Mutex;

use crate::cache::{CacheTier, TtlCache};
use crate::record::{CredentialRecord, KeyRecord};
use crate::{KeyPolicyCasResult, KeyStore};

const KEYS_HASH: &str = "sbproxy:keystore:keys";
const CREDS_HASH: &str = "sbproxy:keystore:credentials";
const REVISION_KEY: &str = "sbproxy:keystore:revision";
const INVALIDATE_CHANNEL: &str = "sbproxy:keystore:invalidate";
/// Everything the L2 cache tier owns lives under this prefix, which is what
/// makes "drop everything" a bounded `SCAN` rather than a `FLUSHDB` on a
/// Redis an operator is probably sharing with something else.
const CACHE_PREFIX: &str = "sbproxy:keystore:cache:";
const CACHE_KEY_PREFIX: &str = "sbproxy:keystore:cache:key:";
const CACHE_CRED_PREFIX: &str = "sbproxy:keystore:cache:cred:";
/// Sentinel payload meaning "drop everything".
const INVALIDATE_ALL: &str = "*";
/// How many keys one `SCAN` iteration asks for while clearing the tier.
const CACHE_SCAN_COUNT: usize = 512;

/// Dial budget for one connection attempt, first connect or reconnect.
///
/// The handle this replaced had no dial deadline at all, so a black-holed
/// Redis address parked a key resolution on the request path for the OS
/// connect timeout. Two seconds is generous for a same-region or
/// cross-AZ dial and short enough that the caller's own deadline wins.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Redials inside one connection attempt, on top of the first dial.
///
/// Zero, on purpose, and the number is load bearing. A key resolution is
/// on the request path, and when Redis is genuinely down the useful
/// answer is the error, now, so `key_management.failure_posture` decides
/// what the request gets. Sleeping first only converts an outage into a
/// slow outage.
///
/// The redis crate's own default is six redials whose delay starts at one
/// second and then multiplies by its `factor` up to a one-minute ceiling,
/// so a dial against a dead Redis can sit for minutes before it answers.
/// That is why this is set rather than left alone.
///
/// Nothing is lost by refusing to retry here: the connection manager
/// starts a fresh attempt on the next command that needs one, so a Redis
/// that comes back is picked up by the next request rather than by a
/// sleep this one paid for.
const RECONNECT_RETRIES: usize = 0;

/// Write a record, bump the global revision, and publish invalidation as
/// one Redis server-side operation (WOR-2639).
///
/// These used to be three separate commands, which left two torn states a
/// fleet cannot see past: a mutation that committed while the process died
/// before the publish (peers keep serving their positive cache for the
/// whole L1 TTL), and a revision that never moved for a record that did
/// (nothing that compares revisions can detect the change). One Lua script
/// makes commit, revision, and notification indivisible: if the mutation
/// happened, the publish happened, whatever the client saw.
const MUTATE_PUT_LUA: &str = r#"
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
local rev = redis.call('INCR', KEYS[2])
redis.call('PUBLISH', KEYS[3], ARGV[1])
return rev
"#;

/// Delete a record, bump the global revision, and publish invalidation as
/// one Redis server-side operation (WOR-2639). Deletion is the security
/// path: a revoke whose invalidation can be skipped is a credential that
/// stays accepted somewhere.
const MUTATE_DEL_LUA: &str = r#"
redis.call('HDEL', KEYS[1], ARGV[1])
local rev = redis.call('INCR', KEYS[2])
redis.call('PUBLISH', KEYS[3], ARGV[1])
return rev
"#;

/// Compare, write, bump the global revision, and publish invalidation as one
/// Redis server-side operation. Legacy records without `policy_revision`
/// compare as revision one.
const KEY_POLICY_CAS_LUA: &str = r#"
local current = redis.call('HGET', KEYS[1], ARGV[1])
if not current then
  return {'not_found', '0'}
end

local actual = string.match(current, '"policy_revision"%s*:%s*(%d+)')
if not actual then
  actual = '1'
end
if actual ~= ARGV[2] then
  return {'conflict', actual}
end

redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
redis.call('INCR', KEYS[2])
redis.call('PUBLISH', KEYS[3], ARGV[1])
return {'applied', ARGV[4]}
"#;

/// A lazily-connected, shareable multiplexed Redis link that survives the
/// loss of its socket.
///
/// # Why a connection manager and not a bare multiplexed connection
///
/// This used to cache a `redis::aio::MultiplexedConnection`, and nothing
/// in this file ever wrote `None` back into the cache. That type does not
/// reconnect: once its socket dies, the pipeline task behind it is gone
/// and every later `send_recv` fails at the channel send with a
/// `BrokenPipe`, forever. One Redis restart, one failover, one
/// `CLIENT KILL`, or one idle `timeout` therefore broke every key
/// resolution for the life of the process, and the pub/sub invalidation
/// subscriber made it worse rather than better: it does reconnect, and on
/// reconnect it drops L1, so every subsequent resolution missed into the
/// dead handle. Under `key_management.failure_posture: allow` or
/// `degraded` that is a key plane failing open permanently rather than
/// transiently.
///
/// [`ConnectionManager`] is the type the redis crate provides for exactly
/// this, and it is already how `sbproxy-cache`'s reserve and
/// `sbproxy-platform`'s async KV store hold their connections, so this is
/// the third user of one pattern rather than a second pattern. The
/// alternative considered was tagging the cached handle with a generation
/// and clearing it on an I/O error, which is what `sbproxy-platform` adds
/// on top of its manager. It is not needed here: that generation tag
/// exists to evict a connection whose in-flight command was abandoned by
/// a whole-operation deadline, and nothing in this file imposes one.
/// The manager's own reconnect is generation-safe by the same reasoning,
/// through a compare-and-swap rather than a counter: a caller that sees a
/// dropped connection swaps a new shared connect future in only if the
/// future it just failed against is still the current one, so two callers
/// failing concurrently produce one dial, and neither can discard the
/// other's fresh replacement.
///
/// # What a caller sees across a reconnect
///
/// The command in flight when the socket dies fails, once, with the I/O
/// error. Commands issued after that await the single shared reconnect
/// and then run on the new socket, so the error is bounded to the
/// requests that were actually in flight. Callers do not need to retry;
/// the next call already lands on the replacement.
struct RedisLink {
    url: String,
    /// Origin and database index of `url`, rendered once at construction.
    ///
    /// Every error this link can raise is about the connection, and the
    /// DSN is the natural thing to name in one. Computing the safe form
    /// up front is what makes that safe by construction rather than by
    /// each error path remembering to redact: the connect failure at
    /// least fires on every transient outage, so a missed one is a
    /// high-volume password leak, not a rare one (WOR-2640).
    label: String,
    conn: Mutex<Option<ConnectionManager>>,
}

/// The dial budget every link in this file connects and reconnects under.
///
/// The backoff knobs beside these two are deliberately left alone: they
/// only shape the delay *between* redials, and this config takes none.
///
/// No response timeout is set on purpose either. A command deadline is a
/// separate behavior change with its own blast radius here: `list_keys`
/// and `list_credentials` are `HGETALL` over a whole fleet's key set, and
/// a deadline short enough to be useful on the request path would refuse
/// them. The dial is bounded; the command is not.
fn reconnect_config() -> ConnectionManagerConfig {
    ConnectionManagerConfig::new()
        .set_number_of_retries(RECONNECT_RETRIES)
        .set_connection_timeout(CONNECT_TIMEOUT)
}

impl RedisLink {
    fn new(url: impl Into<String>) -> Self {
        let url = url.into();
        Self {
            label: redacted_url_with_path(&url),
            url,
            conn: Mutex::new(None),
        }
    }

    /// Return the cached connection manager, establishing it on first use.
    ///
    /// The guard is never held across the connect await so concurrent
    /// callers do not serialize behind whichever one is connecting. Once
    /// the manager is cached it is never cleared, and does not need to
    /// be: a manager whose socket died reconnects itself, which is the
    /// whole reason it is a manager. Only the *first* connection is
    /// established here, so a Redis that is unreachable at boot still
    /// costs one dial per call rather than a permanently poisoned entry.
    async fn conn(&self) -> Result<ConnectionManager> {
        {
            let guard = self.conn.lock().await;
            if let Some(c) = guard.as_ref() {
                return Ok(c.clone());
            }
        }
        let client = Client::open(self.url.as_str())
            .with_context(|| format!("invalid redis url '{}'", self.label))?;
        let c = ConnectionManager::new_with_config(client, reconnect_config())
            .await
            .with_context(|| format!("connecting to redis at '{}'", self.label))?;
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

    /// Run one of the atomic mutate scripts: record write or delete,
    /// revision bump, and invalidation publish as a single server-side
    /// operation (WOR-2639).
    async fn mutate(
        &self,
        script: &str,
        hash: &str,
        id: &str,
        payload: Option<&str>,
        what: &'static str,
    ) -> Result<()> {
        let mut c = self.link.conn().await?;
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(script)
            .arg(3)
            .arg(hash)
            .arg(REVISION_KEY)
            .arg(INVALIDATE_CHANNEL)
            .arg(id);
        if let Some(payload) = payload {
            cmd.arg(payload);
        }
        let _revision: i64 = cmd.query_async(&mut c).await.context(what)?;
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
        self.mutate(
            MUTATE_PUT_LUA,
            KEYS_HASH,
            &record.key_id,
            Some(&bytes),
            "redis atomic key put",
        )
        .await
    }

    async fn put_key_if_revision(
        &self,
        mut record: KeyRecord,
        expected_revision: u64,
    ) -> Result<KeyPolicyCasResult> {
        let policy_revision = crate::next_policy_revision(expected_revision)?;
        record.policy_revision = policy_revision;
        let encoded = serde_json::to_string(&record).context("encode key record for CAS")?;
        let mut c = self.link.conn().await?;
        let (status, revision): (String, String) = redis::cmd("EVAL")
            .arg(KEY_POLICY_CAS_LUA)
            .arg(3)
            .arg(KEYS_HASH)
            .arg(REVISION_KEY)
            .arg(INVALIDATE_CHANNEL)
            .arg(&record.key_id)
            .arg(expected_revision.to_string())
            .arg(encoded)
            .arg(policy_revision.to_string())
            .query_async(&mut c)
            .await
            .context("redis key policy CAS")?;

        match status.as_str() {
            "applied" => Ok(KeyPolicyCasResult::Applied { policy_revision }),
            "conflict" => Ok(KeyPolicyCasResult::Conflict {
                actual_revision: revision
                    .parse()
                    .context("decode Redis key policy revision")?,
            }),
            "not_found" => Ok(KeyPolicyCasResult::NotFound),
            other => anyhow::bail!("unexpected Redis key policy CAS result '{other}'"),
        }
    }

    async fn delete_key(&self, key_id: &str) -> Result<()> {
        self.mutate(
            MUTATE_DEL_LUA,
            KEYS_HASH,
            key_id,
            None,
            "redis atomic key delete",
        )
        .await
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
        self.mutate(
            MUTATE_PUT_LUA,
            CREDS_HASH,
            &record.id,
            Some(&bytes),
            "redis atomic credential put",
        )
        .await
    }

    async fn delete_credential(&self, id: &str) -> Result<()> {
        self.mutate(
            MUTATE_DEL_LUA,
            CREDS_HASH,
            id,
            None,
            "redis atomic credential delete",
        )
        .await
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

    /// Delete both of this id's shared entries and announce the drop.
    ///
    /// Every step is checked and the first failure is returned. This is the
    /// revocation path: a `del` that did not run leaves the shared L2 still
    /// answering with the revoked record, and a `publish` that did not go
    /// out leaves every peer's L1 holding it. Neither is a cache miss the
    /// store can cover for, which is why this is the one part of the tier
    /// that does not swallow its errors.
    ///
    /// What `Ok` does not prove: Redis `PUBLISH` reports how many
    /// subscribers received the message and succeeds at zero, so `Ok` means
    /// the announcement went out, not that any peer was listening. A
    /// replica whose subscription was down is covered by the subscriber
    /// clearing its whole local cache on every resubscription, not by this
    /// return value.
    async fn invalidate(&self, id: &str) -> Result<()> {
        // `conn()` already names the redacted DSN in its own error.
        let mut c = self
            .link
            .conn()
            .await
            .context("reach the shared cache tier to invalidate an id")?;
        let _: i64 = c
            .del(format!("{CACHE_KEY_PREFIX}{id}"))
            .await
            .context("delete the shared key-cache entry")?;
        let _: i64 = c
            .del(format!("{CACHE_CRED_PREFIX}{id}"))
            .await
            .context("delete the shared credential-cache entry")?;
        let _: i64 = c
            .publish(INVALIDATE_CHANNEL, id)
            .await
            .context("announce the invalidation to peer replicas")?;
        Ok(())
    }

    /// Delete every entry this tier owns, then announce the drop to peers.
    ///
    /// The delete is the part that used to be missing. This method only
    /// published the `*` sentinel, so the shared entries it claimed to have
    /// cleared were still there answering L2 lookups for the rest of their
    /// TTL, and a caller that read the name reasonably assumed otherwise.
    ///
    /// `SCAN` rather than `KEYS`, because `KEYS` blocks the server for the
    /// length of the keyspace, and scoped to the cache prefix rather than
    /// `FLUSHDB`, because this Redis is not necessarily ours alone. `SCAN`
    /// gives no snapshot guarantee: an entry written after the cursor passed
    /// its slot survives, which is correct, since it was written after the
    /// invalidation and describes a later state.
    async fn invalidate_all(&self) -> Result<()> {
        let mut c = self
            .link
            .conn()
            .await
            .context("reach the shared cache tier to purge it")?;
        let pattern = format!("{CACHE_PREFIX}*");
        let mut cursor: u64 = 0;
        // A partial purge is still worth announcing, so a failure mid-scan
        // is carried past the publish rather than returned from inside the
        // loop: peers drop their L1 copies either way, and the caller still
        // learns the shared tier was not fully cleared.
        let mut scan_failure: Option<anyhow::Error> = None;
        loop {
            let scanned: std::result::Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(CACHE_SCAN_COUNT)
                .query_async(&mut c)
                .await;
            let (next, keys) = match scanned {
                Ok(page) => page,
                Err(error) => {
                    scan_failure =
                        Some(anyhow::Error::new(error).context("scan the shared cache prefix"));
                    break;
                }
            };
            if !keys.is_empty() {
                let deleted: std::result::Result<i64, _> = c.del(keys).await;
                if let Err(error) = deleted {
                    scan_failure = Some(
                        anyhow::Error::new(error).context("delete a page of shared cache entries"),
                    );
                    break;
                }
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        let published: std::result::Result<i64, _> =
            c.publish(INVALIDATE_CHANNEL, INVALIDATE_ALL).await;
        match (scan_failure, published) {
            (Some(error), _) => Err(error),
            (None, Err(error)) => {
                Err(anyhow::Error::new(error).context("announce the cache purge to peer replicas"))
            }
            (None, Ok(_)) => Ok(()),
        }
    }
}

/// Spawn nothing; run a blocking loop that subscribes to the invalidation
/// channel and drops matching entries from the local cache when a peer mutates
/// a record. Intended to be `tokio::spawn`ed by the caller.
///
/// Returns only on error; the caller decides whether to retry. Each received
/// id is invalidated in `cache`; the `*` sentinel clears everything.
///
/// # Gap recovery (WOR-2639)
///
/// Redis pub/sub has no replay: a message published while this replica was
/// disconnected is gone, and before this fix a revocation missed that way
/// stayed missed until the positive L1 TTL expired, which is a revoked
/// credential being accepted for up to a minute. Every (re)subscription
/// therefore begins by dropping the entire local cache, after the
/// subscription is live, so any mutation that happened during a gap is
/// covered either by the resync (published before we subscribed) or by the
/// stream (published after). The stream ending is reported as an error
/// rather than a clean return, so a supervising loop resubscribes and
/// resynchronizes instead of treating silence as health.
pub async fn subscribe_invalidations(url: String, cache: Arc<TtlCache>) -> Result<()> {
    use futures::StreamExt;

    let client = Client::open(url.as_str())
        .with_context(|| format!("invalid redis url '{}'", redacted_url_with_path(&url)))?;
    let mut pubsub = client
        .get_async_pubsub()
        .await
        .context("open redis pubsub connection")?;
    pubsub
        .subscribe(INVALIDATE_CHANNEL)
        .await
        .context("subscribe invalidate channel")?;

    // Best-effort revision checkpoint for the log line, so operators can
    // correlate "which revision was this replica current with when it
    // resynced". Ids and revisions only; never record contents.
    let revision: Option<i64> = match client.get_multiplexed_async_connection().await {
        Ok(mut conn) => redis::cmd("GET")
            .arg(REVISION_KEY)
            .query_async(&mut conn)
            .await
            .ok()
            .flatten(),
        Err(_) => None,
    };

    let stream = pubsub
        .on_message()
        .map(|msg| msg.get_payload::<String>().unwrap_or_default());
    resync_then_pump(&cache, stream, revision).await
}

/// The subscriber's body, split from the connection plumbing so the gap
/// contract is testable without a Redis: clear the local cache first, then
/// apply the stream, and treat the stream ending as a failure.
///
/// # Why the resync is local-only
///
/// This is a receiver, and every write path on [`RedisCacheTier`] publishes
/// on the very channel this task is subscribed to. Clearing through
/// [`TtlCache::invalidate_all`] here would publish `*`, the subscription
/// would deliver that `*` straight back, applying it would publish another
/// one, and the loop would never close: an unbounded pub/sub storm at every
/// boot and every reconnect on any deployment running
/// `key_management.cache.tier: redis`. The local clear is the whole job
/// anyway. The shared L2 entry for a record that changed during the gap was
/// already deleted by the replica that changed it, in the same
/// [`CacheTier::invalidate`] call that announced it.
async fn resync_then_pump<S>(cache: &TtlCache, mut stream: S, revision: Option<i64>) -> Result<()>
where
    S: futures::Stream<Item = String> + Unpin,
{
    use futures::StreamExt;

    // The subscription is already live, so this order leaves no window: a
    // revocation is either older than this clear (covered by it) or newer
    // (delivered by the stream).
    cache.invalidate_all_local();
    tracing::info!(
        revision = revision.unwrap_or(-1),
        "keystore invalidation subscriber connected; cleared the local cache to cover any missed window"
    );

    while let Some(payload) = stream.next().await {
        apply_invalidation(cache, &payload).await;
    }
    anyhow::bail!("keystore invalidation stream ended; a resubscribe must resynchronize")
}

/// One invalidation message: an id drops that entry, `*` drops everything,
/// an empty payload is ignored.
///
/// Every drop here is local-only, for the reason [`resync_then_pump`]
/// spells out: answering a broadcast with a broadcast is what turns one
/// revocation into an endless one.
async fn apply_invalidation(cache: &TtlCache, payload: &str) {
    if payload == INVALIDATE_ALL {
        cache.invalidate_all_local();
    } else if !payload.is_empty() {
        cache.invalidate_local(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::TtlCacheConfig;
    use crate::KeyPolicyCasResult;
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

    #[test]
    fn key_policy_cas_script_updates_record_revision_and_invalidation_atomically() {
        for command in ["HGET", "HSET", "INCR", "PUBLISH"] {
            assert!(KEY_POLICY_CAS_LUA.contains(command), "missing {command}");
        }
        assert!(KEY_POLICY_CAS_LUA.contains("policy_revision"));
    }

    #[test]
    fn mutate_scripts_commit_revision_and_publish_as_one_operation() {
        // WOR-2639: the write, the revision bump, and the invalidation
        // publish must be one server-side script, so a mutation can never
        // commit while its notification is skipped. A Lua script is the
        // atomicity boundary Redis gives us; these pins keep all three
        // commands inside it.
        for command in ["HSET", "INCR", "PUBLISH"] {
            assert!(
                MUTATE_PUT_LUA.contains(command),
                "put script missing {command}"
            );
        }
        for command in ["HDEL", "INCR", "PUBLISH"] {
            assert!(
                MUTATE_DEL_LUA.contains(command),
                "delete script missing {command}"
            );
        }
    }

    async fn warmed_cache() -> (Arc<crate::MemoryKeyStore>, Arc<TtlCache>) {
        use crate::KeyStore as _;
        let store = Arc::new(crate::MemoryKeyStore::new());
        store
            .put_key(KeyRecord::new("k1", "h1", ts()))
            .await
            .unwrap();
        store
            .put_key(KeyRecord::new("k2", "h2", ts()))
            .await
            .unwrap();
        let cache = Arc::new(TtlCache::new(
            Arc::clone(&store) as Arc<dyn crate::KeyStore>,
            TtlCacheConfig::default(),
        ));
        assert!(cache.resolve_key("k1").await.unwrap().is_some());
        assert!(cache.resolve_key("k2").await.unwrap().is_some());
        // Revoke both behind the cache's back: this is the state a replica
        // is in when a peer revoked during a pub/sub gap.
        store.delete_key("k1").await.unwrap();
        store.delete_key("k2").await.unwrap();
        assert!(
            cache.resolve_key("k1").await.unwrap().is_some(),
            "the stale positive cache is exactly the hazard under test"
        );
        (store, cache)
    }

    /// Stands in for [`RedisCacheTier`] without a Redis. The only thing
    /// under test is whether the subscriber path reaches a tier at all:
    /// every write method on the real tier ends in a `PUBLISH` on the
    /// channel the subscriber is listening to, so one call here is one
    /// message the fleet would have to process, and answer, and process
    /// again.
    #[derive(Default)]
    struct PublishCountingTier {
        published: std::sync::atomic::AtomicU64,
    }

    impl PublishCountingTier {
        fn publishes(&self) -> u64 {
            self.published.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn record(&self) {
            self.published
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl CacheTier for PublishCountingTier {
        async fn get_key(&self, _: &str) -> Option<KeyRecord> {
            None
        }
        async fn put_key(&self, _: &KeyRecord, _: Duration) {}
        async fn get_credential(&self, _: &str) -> Option<CredentialRecord> {
            None
        }
        async fn put_credential(&self, _: &CredentialRecord, _: Duration) {}
        async fn invalidate(&self, _: &str) -> Result<()> {
            self.record();
            Ok(())
        }
        async fn invalidate_all(&self) -> Result<()> {
            self.record();
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_subscriber_never_publishes_what_it_received() {
        // The self-sustaining storm this pins out: `invalidate_all` on the
        // Redis tier publishes `*` on INVALIDATE_CHANNEL, and this
        // subscriber is subscribed to INVALIDATE_CHANNEL. A resync that
        // published, or a received `*` that published, would be delivered
        // straight back to every replica including this one, each of which
        // would publish again. It never converges, and it starts at every
        // boot and every reconnect. Neither the resync nor any received
        // message may reach the tier.
        use crate::KeyStore as _;
        let store = Arc::new(crate::MemoryKeyStore::new());
        store
            .put_key(KeyRecord::new("k1", "h1", ts()))
            .await
            .unwrap();
        let tier = Arc::new(PublishCountingTier::default());
        let cache = Arc::new(
            TtlCache::new(
                Arc::clone(&store) as Arc<dyn crate::KeyStore>,
                TtlCacheConfig::default(),
            )
            .with_tier(Arc::clone(&tier) as Arc<dyn CacheTier>),
        );
        assert!(cache.resolve_key("k1").await.unwrap().is_some());
        store.delete_key("k1").await.unwrap();

        let outcome = resync_then_pump(
            &cache,
            futures::stream::iter(vec![
                INVALIDATE_ALL.to_string(),
                "k1".to_string(),
                String::new(),
            ]),
            Some(11),
        )
        .await;
        assert!(
            outcome.is_err(),
            "a stream that ends asks for a resubscribe"
        );
        assert!(
            cache.resolve_key("k1").await.unwrap().is_none(),
            "the local cache is still cleared; only the echo is gone"
        );
        assert_eq!(
            tier.publishes(),
            0,
            "the subscriber published {} message(s) in response to messages it \
             received; every one of them comes straight back",
            tier.publishes()
        );

        // Directly, so the property is pinned per message kind and not only
        // in aggregate.
        apply_invalidation(&cache, INVALIDATE_ALL).await;
        apply_invalidation(&cache, "k1").await;
        assert_eq!(tier.publishes(), 0);
    }

    #[test]
    fn the_cache_prefix_covers_both_entry_kinds() {
        // `invalidate_all` clears by scanning CACHE_PREFIX. A per-kind
        // prefix that drifted out from under it would leave entries the
        // scan cannot see and the method claims to have deleted.
        assert!(CACHE_KEY_PREFIX.starts_with(CACHE_PREFIX));
        assert!(CACHE_CRED_PREFIX.starts_with(CACHE_PREFIX));
        assert_ne!(CACHE_PREFIX, CACHE_KEY_PREFIX);
    }

    #[tokio::test]
    async fn a_subscription_start_clears_entries_cached_before_it() {
        // WOR-2639: a revocation published while this replica was
        // disconnected is gone forever (pub/sub has no replay), so the
        // subscriber's first act after subscribing must be a full local
        // clear. An empty stream then ending must be an error, so the
        // supervising loop resubscribes instead of idling forever.
        let (_store, cache) = warmed_cache().await;
        let outcome =
            resync_then_pump(&cache, futures::stream::iter(Vec::<String>::new()), Some(7)).await;
        assert!(
            outcome.is_err(),
            "a stream that ends must tell the caller to resubscribe"
        );
        assert!(
            cache.resolve_key("k1").await.unwrap().is_none(),
            "an entry cached before the subscription began must not survive it"
        );
        assert!(cache.resolve_key("k2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_invalidation_message_drops_that_id_and_star_drops_everything() {
        let (_store, cache) = warmed_cache().await;
        // Re-warm is impossible post-delete, so drive the per-message
        // handler directly against the still-cached entries.
        apply_invalidation(&cache, "k1").await;
        assert!(
            cache.resolve_key("k1").await.unwrap().is_none(),
            "a published id must invalidate that entry"
        );
        assert!(
            cache.resolve_key("k2").await.unwrap().is_some(),
            "an unrelated entry keeps its cache"
        );
        apply_invalidation(&cache, "").await;
        assert!(
            cache.resolve_key("k2").await.unwrap().is_some(),
            "an empty payload is ignored"
        );
        apply_invalidation(&cache, INVALIDATE_ALL).await;
        assert!(
            cache.resolve_key("k2").await.unwrap().is_none(),
            "the sentinel clears everything"
        );
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

        let mut updated = store.get_key("live-test").await.unwrap().unwrap();
        updated.name = Some("updated".into());
        assert_eq!(
            store.put_key_if_revision(updated, 1).await.unwrap(),
            KeyPolicyCasResult::Applied { policy_revision: 2 }
        );
        let stale = KeyRecord::new("live-test", "replacement", ts());
        assert_eq!(
            store.put_key_if_revision(stale, 1).await.unwrap(),
            KeyPolicyCasResult::Conflict { actual_revision: 2 }
        );
        store.delete_key("live-test").await.unwrap();
        assert!(store.get_key("live-test").await.unwrap().is_none());

        // The cache tier round-trips a record under a TTL.
        let tier = RedisCacheTier::new(&url);
        let cached = KeyRecord::new("tier-test", "h", ts());
        tier.put_key(&cached, Duration::from_secs(30)).await;
        assert!(tier.get_key("tier-test").await.is_some());
        tier.invalidate("tier-test")
            .await
            .expect("live redis invalidate");
        assert!(tier.get_key("tier-test").await.is_none());

        // Touch the unused config import so the test file exercises it.
        let _ = TtlCacheConfig::default();
    }

    // --- WOR-2640: a Redis DSN never reaches an error string ---

    #[test]
    fn redis_link_renders_a_credential_free_label_at_construction() {
        let link = RedisLink::new("redis://aclname:topsecret@cache.internal:6379/3");
        assert_eq!(link.label, "redis://cache.internal:6379/3");
        // The dial still needs the real DSN; only the label is rendered.
        assert!(link.url.contains("topsecret"), "the DSN was not retained");
    }

    /// The connect failure is the highest-volume site in this file: it
    /// fires on every transient outage, not only on a misconfiguration.
    #[tokio::test]
    async fn redis_link_error_names_the_origin_not_the_password() {
        let link = RedisLink::new("http://aclname:topsecret@cache.internal:6379/3");
        // `let Err(..) else` rather than `expect_err`: the Ok half is a
        // `ConnectionManager`, which is not `Debug`, so `expect_err` will
        // not compile against it.
        let Err(err) = link.conn().await else {
            panic!("a non-redis scheme cannot open");
        };
        let msg = format!("{err:#}");
        assert!(!msg.contains("topsecret"), "password leaked: {msg}");
        assert!(!msg.contains("aclname"), "username leaked: {msg}");
        assert!(
            msg.contains("http://cache.internal:6379/3"),
            "expected the redacted origin in the error, got: {msg}"
        );
    }

    #[tokio::test]
    async fn subscribe_invalidations_refuses_a_bad_dsn_without_echoing_it() {
        let store = Arc::new(crate::MemoryKeyStore::new()) as Arc<dyn crate::KeyStore>;
        let cache = Arc::new(TtlCache::new(store, TtlCacheConfig::default()));
        let dsn = "http://aclname:topsecret@cache.internal:6379/3".to_string();
        let err = subscribe_invalidations(dsn, cache)
            .await
            .expect_err("a non-redis scheme cannot open");
        let msg = format!("{err:#}");
        assert!(!msg.contains("topsecret"), "password leaked: {msg}");
        assert!(
            msg.contains("http://cache.internal:6379/3"),
            "expected the redacted origin in the error, got: {msg}"
        );
    }

    // --- A dropped socket must not outlive itself ---

    /// A stand-in Redis that speaks just enough RESP2 to answer the
    /// commands this file issues, and hangs up on its first client the
    /// way a restart, a failover, or `CLIENT KILL` does.
    ///
    /// `sbproxy-storage`'s Redis backend carries a copy of this, because
    /// the same defect lived in both files and a shared test double
    /// would mean a crate edge between them that production does not
    /// have.
    mod fake_redis {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        /// Handle on a running stand-in server.
        pub(super) struct FakeRedis {
            /// A `redis://` URL a client can dial.
            pub(super) url: String,
            accepted: Arc<AtomicUsize>,
        }

        impl FakeRedis {
            /// Bind on loopback and serve until the test ends. The first
            /// client connection is closed as soon as it has been
            /// answered once; later connections are served for as long
            /// as they live.
            pub(super) async fn start() -> Self {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind a loopback port");
                let addr = listener.local_addr().expect("read the bound port");
                let accepted = Arc::new(AtomicUsize::new(0));
                let counter = Arc::clone(&accepted);
                tokio::spawn(async move {
                    loop {
                        let Ok((socket, _)) = listener.accept().await else {
                            return;
                        };
                        let nth = counter.fetch_add(1, Ordering::SeqCst) + 1;
                        tokio::spawn(serve(socket, nth == 1));
                    }
                });
                Self {
                    url: format!("redis://{addr}"),
                    accepted,
                }
            }

            /// How many client connections the server has accepted. Two
            /// or more means the client really did redial.
            pub(super) fn accepted(&self) -> usize {
                self.accepted.load(Ordering::SeqCst)
            }
        }

        async fn serve(socket: TcpStream, hang_up_after_one_command: bool) {
            let (read, mut write) = socket.into_split();
            let mut reader = BufReader::new(read);
            let mut answered = 0usize;
            while let Ok(Some(args)) = read_command(&mut reader).await {
                let name = args
                    .first()
                    .map(|arg| arg.to_ascii_uppercase())
                    .unwrap_or_default();
                if write.write_all(reply_for(&name)).await.is_err() {
                    return;
                }
                // `CLIENT SETINFO` is the redis crate's own handshake,
                // not a caller's command. Hanging up on it would fail
                // the connect rather than break an established one,
                // which is a different scenario from the one under test.
                if name == "CLIENT" {
                    continue;
                }
                answered += 1;
                if hang_up_after_one_command && answered == 1 {
                    let _ = write.shutdown().await;
                    return;
                }
            }
        }

        fn reply_for(command: &str) -> &'static [u8] {
            match command {
                // Nil bulk string: a lookup that succeeded and found
                // nothing, which is all these tests need it to mean.
                "GET" | "HGET" => b"$-1\r\n",
                "DEL" | "EXISTS" | "PUBLISH" => b":0\r\n",
                _ => b"+OK\r\n",
            }
        }

        /// Read one RESP array-of-bulk-strings command. `Ok(None)` is a
        /// clean end of stream.
        async fn read_command<R>(reader: &mut R) -> std::io::Result<Option<Vec<String>>>
        where
            R: AsyncBufRead + Unpin,
        {
            let Some(header) = read_line(reader).await? else {
                return Ok(None);
            };
            let Some(count) = header
                .strip_prefix('*')
                .and_then(|n| n.parse::<usize>().ok())
            else {
                // Inline command: whitespace separated, no length prefixes.
                return Ok(Some(
                    header.split_whitespace().map(str::to_string).collect(),
                ));
            };
            let mut args = Vec::with_capacity(count);
            for _ in 0..count {
                let Some(len_line) = read_line(reader).await? else {
                    return Ok(None);
                };
                let Some(len) = len_line
                    .strip_prefix('$')
                    .and_then(|n| n.parse::<usize>().ok())
                else {
                    return Ok(None);
                };
                // Length plus the trailing CRLF.
                let mut buf = vec![0u8; len + 2];
                reader.read_exact(&mut buf).await?;
                buf.truncate(len);
                args.push(String::from_utf8_lossy(&buf).into_owned());
            }
            Ok(Some(args))
        }

        async fn read_line<R>(reader: &mut R) -> std::io::Result<Option<String>>
        where
            R: AsyncBufRead + Unpin,
        {
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(None);
            }
            Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
        }

        /// Bind a listener that accepts and then says nothing, holding
        /// every socket open. A client dialling this completes its TCP
        /// connect and then waits forever on the handshake reply, which
        /// is what an address black-holed by a firewall or a wedged
        /// Redis looks like from here.
        pub(super) async fn start_black_hole() -> String {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind a loopback port");
            let addr = listener.local_addr().expect("read the bound port");
            tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    // Held open rather than dropped: closing it would
                    // let the client fail fast for the wrong reason.
                    tokio::spawn(async move {
                        let _held = socket;
                        std::future::pending::<()>().await;
                    });
                }
            });
            format!("redis://{addr}")
        }
    }

    /// How long the recovery loops below are willing to wait, and how
    /// often they retry. A redial against a listener on loopback is
    /// immediate, so this is a wide margin for a loaded CI box rather
    /// than an expected wait.
    const RECOVERY_ATTEMPTS: usize = 80;
    const RECOVERY_PAUSE: Duration = Duration::from_millis(25);

    /// The regression this file exists to prevent (H5).
    ///
    /// A `MultiplexedConnection` does not reconnect, and nothing here
    /// ever cleared the cached one, so a single Redis restart, failover,
    /// or `CLIENT KILL` turned every later key resolution into the same
    /// `BrokenPipe` for the life of the process. Under
    /// `key_management.failure_posture: allow` or `degraded` that is a
    /// key plane failing open permanently rather than transiently, which
    /// is why this is not merely an availability test.
    ///
    /// Against the pre-fix code the loop below never sees an `Ok`: the
    /// dead handle is still cached and answers every attempt with the
    /// same error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lookup_after_the_socket_dies_reaches_a_new_socket() {
        let server = fake_redis::FakeRedis::start().await;
        let store = RedisKeyStore::new(&server.url);

        // Lands on the socket the server is about to close.
        assert!(
            store
                .get_key("before")
                .await
                .expect("the first lookup is answered")
                .is_none(),
            "the stand-in answers a nil record"
        );

        // The caller in flight when the socket dies sees one error; the
        // callers after it must land on a replacement socket.
        let mut recovered = false;
        for _ in 0..RECOVERY_ATTEMPTS {
            if store.get_key("after").await.is_ok() {
                recovered = true;
                break;
            }
            tokio::time::sleep(RECOVERY_PAUSE).await;
        }
        assert!(
            recovered,
            "the store never recovered from a dropped socket; a cached \
             connection that cannot reconnect is a permanent outage, not \
             a transient one"
        );
        assert!(
            server.accepted() >= 2,
            "the store answered without redialling, so the recovery above \
             did not come from a new connection"
        );
    }

    /// The cache tier shares the link, so it shares the recovery.
    ///
    /// Worth its own case because the tier swallows its own errors: a
    /// tier that silently answers "miss" forever after a Redis blip is
    /// indistinguishable from a cold cache, and the L1 clear the
    /// invalidation subscriber performs on every reconnect is what makes
    /// that miss stream expensive rather than merely wasteful.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cache_tier_serves_again_after_the_socket_dies() {
        let server = fake_redis::FakeRedis::start().await;
        let tier = RedisCacheTier::new(&server.url);

        assert!(
            tier.get_key("before").await.is_none(),
            "a nil reply is a miss"
        );

        let record = KeyRecord::new("after", "h", ts());
        for _ in 0..RECOVERY_ATTEMPTS {
            tier.put_key(&record, Duration::from_secs(30)).await;
            if server.accepted() >= 2 {
                break;
            }
            tokio::time::sleep(RECOVERY_PAUSE).await;
        }
        assert!(
            server.accepted() >= 2,
            "the tier never redialled after its socket was closed, so \
             every later write went nowhere"
        );
    }

    /// The dial this fix put a deadline on.
    ///
    /// The handle this replaced dialled with no timeout at all, so an
    /// address that accepts and then stalls parked a key resolution on a
    /// worker for as long as the peer felt like holding it. The posture
    /// in `key_management.failure_posture` cannot decide anything for a
    /// request that never gets an answer.
    ///
    /// Against the pre-fix code the inner call never returns and the
    /// outer deadline below is what fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_that_never_answers_gives_up_on_its_own() {
        let url = fake_redis::start_black_hole().await;
        let store = RedisKeyStore::new(url);
        let outcome = tokio::time::timeout(CONNECT_TIMEOUT * 3, store.get_key("k1")).await;
        let inner = outcome.expect(
            "the dial has to give up on its own; a resolution that never returns is a \
             pinned worker, not a slow lookup",
        );
        assert!(
            inner.is_err(),
            "a stalled handshake cannot report a successful lookup"
        );
    }
}
