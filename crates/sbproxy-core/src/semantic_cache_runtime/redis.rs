//! Async Redis semantic cache store.
//!
//! This adapter stores one encoded semantic payload per prompt digest and a
//! bounded manifest list per LSH bucket. It reuses the already validated
//! `proxy.l2_cache_settings` connection through
//! [`sbproxy_platform::storage::AsyncRedisKVStore`], so a semantic cache never
//! introduces a second Redis DSN, password, TLS, or pool block.
//!
//! Four properties drive the design:
//!
//! 1. Every operation is async native. The synchronous Redis store is never
//!    wrapped in `spawn_blocking`.
//! 2. A logical write touches several keys and can complete partially. Payload
//!    bytes are written before any index member, so a crash can leave an
//!    unreachable payload but never an index member pointing at a response
//!    that was not validated and stored. A payload without an index and an
//!    index without a payload are both safe misses.
//! 3. Index updates are atomic. One fixed Lua script performs the duplicate
//!    removal, insert, bound, and expiry for a bucket manifest in a single
//!    round trip, so two concurrent writers cannot leave an unbounded or
//!    duplicated manifest.
//! 4. Every backend failure is a closed [`SemanticStoreError`]. Redis
//!    addresses, credentials, keys, prompts, responses, and embeddings never
//!    reach an error, a log line, or an admin response.
//!
//! `max_entries` is accepted for configuration compatibility but Redis does
//! not pretend to enforce a process-wide distributed entry count. Retention
//! comes from the per-key TTL plus the bounded per-bucket manifests.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures::stream::StreamExt;
use sbproxy_ai::semantic_cache::{
    decode_entry, encode_entry, semantic_entry_key, semantic_purge_prefix, SemanticCacheBackend,
    SemanticCacheStore, SemanticExactSelector, SemanticHealthState, SemanticLookupError,
    SemanticPurgeReport, SemanticPurgeScope, SemanticStoreCounters, SemanticStoreError,
    SemanticStoreHealth, SemanticStoreLookup, SemanticStoreLookupQuery, SemanticStoreStats,
    SemanticStoreWrite, MAX_CANDIDATES_PER_BUCKET, MAX_LSH_TABLES, MAX_SEMANTIC_ENTRY_BYTES,
};
use sbproxy_platform::storage::{AsyncKVStore, AsyncRedisConfig, AsyncRedisKVStore, KVStore};

/// Atomic bounded bucket-manifest update.
///
/// `KEYS[1]` is one bucket manifest key. `ARGV[1]` is a safe 64 character
/// lowercase hex entry digest, `ARGV[2]` the maximum retained members, and
/// `ARGV[3]` the manifest TTL in seconds. The script removes a duplicate,
/// pushes the member at the head, trims to the bound, and re-arms the expiry
/// in one round trip. It returns a flat string-compatible array.
const SEMANTIC_INDEX_PUT: &str = r#"
-- sbproxy-semcache:index-put:v2
local member = ARGV[1]
local maximum = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
if not maximum or maximum < 1 then
  return {'invalid'}
end
if not ttl or ttl < 1 then
  return {'invalid'}
end
if type(member) ~= 'string' or #member ~= 64 or not string.match(member, '^[0-9a-f]+$') then
  return {'invalid'}
end
redis.call('LREM', KEYS[1], 0, member)
redis.call('LPUSH', KEYS[1], member)
redis.call('LTRIM', KEYS[1], 0, maximum - 1)
redis.call('EXPIRE', KEYS[1], ttl)
return {'ok', tostring(redis.call('LLEN', KEYS[1]))}
"#;

/// Bounded bucket-manifest read.
///
/// `KEYS[1]` is one bucket manifest key and `ARGV[1]` the maximum members to
/// return. The script reads at most that many members and returns only values
/// that are already 64 character lowercase hex entry digests, so a manifest
/// corrupted outside this adapter cannot inject an arbitrary key fragment into
/// a payload fetch.
const SEMANTIC_INDEX_READ: &str = r#"
-- sbproxy-semcache:index-read:v2
local maximum = tonumber(ARGV[1])
if not maximum or maximum < 1 then
  return {}
end
local members = redis.call('LRANGE', KEYS[1], 0, maximum - 1)
local safe = {}
for i = 1, #members do
  local member = members[i]
  if type(member) == 'string' and #member == 64 and string.match(member, '^[0-9a-f]+$') then
    safe[#safe + 1] = member
  end
end
return safe
"#;

/// Fixed literal prefix shared by every generated semantic cache key.
const SEMANTIC_KEY_PREFIX: &str = "sbproxy:semcache:v2:";

/// Fixed key probed by [`SemanticCacheStore::health`]. It is never written.
const SEMANTIC_HEALTH_PROBE_KEY: &str = "sbproxy:semcache:v2:health";

/// Fixed reason reported when a health probe fails. Contains no address.
const SEMANTIC_HEALTH_PROBE_FAILED: &str = "redis semantic cache probe failed";

/// Length of a hex-encoded 32 byte entry digest.
const ENTRY_DIGEST_HEX_LEN: usize = 64;

/// Maximum payload `GET` operations in flight for one lookup.
///
/// Independent of the table count so a worst-case 4,096 candidate
/// configuration cannot enqueue unbounded Redis work or retain every
/// maximum-size response at once.
const MAX_PAYLOAD_FETCHES_IN_FLIGHT: usize = 8;

/// Maximum `DEL` operations in flight for one purge page.
const MAX_PURGE_DELETES_IN_FLIGHT: usize = 32;

/// Redis `SCAN COUNT` work hint used by a generated-prefix purge.
const PURGE_SCAN_COUNT: u16 = 250;

/// Maximum `SCAN` steps one purge performs before reporting an incomplete
/// result. A server that never returns a zero cursor cannot spin this loop.
const MAX_PURGE_SCAN_ROUNDS: u32 = 100_000;

/// Redis-backed semantic cache store.
///
/// Construct through [`RedisSemanticCacheStore::from_l2_store`] so the adapter
/// always shares the operator's one validated Redis connection.
// The compiled semantic-cache registry becomes the first non-test caller in a
// later task; until then the constructor is only reachable from tests.
#[allow(dead_code)]
pub(crate) struct RedisSemanticCacheStore {
    redis: Arc<AsyncRedisKVStore>,
    stats: SemanticStoreCounters,
}

// Same rationale as the struct: the registry becomes the first non-test caller.
#[allow(dead_code)]
impl RedisSemanticCacheStore {
    /// Build the store from the already validated `proxy.l2_cache_settings`
    /// Redis connection.
    ///
    /// Returns an error when the operator selected the Redis semantic backend
    /// without a Redis L2 cache. Selecting Redis explicitly never silently
    /// falls back to the memory backend, and this adapter never accepts a
    /// semantic-cache specific DSN.
    pub(crate) fn from_l2_store(l2_store: Option<&dyn KVStore>) -> anyhow::Result<Arc<Self>> {
        let connection = l2_store
            .and_then(KVStore::validated_redis_connection)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "semantic_cache.backend redis requires proxy.l2_cache_settings.driver redis"
                )
            })?;
        let redis = AsyncRedisKVStore::new(AsyncRedisConfig::from_connection(connection));
        Ok(Arc::new(Self {
            redis,
            stats: SemanticStoreCounters::default(),
        }))
    }

    /// Build the store directly over an async Redis handle, for tests that
    /// drive a local RESP fixture or a disposable Redis process.
    #[cfg(test)]
    fn from_async_store(redis: Arc<AsyncRedisKVStore>) -> Arc<Self> {
        Arc::new(Self {
            redis,
            stats: SemanticStoreCounters::default(),
        })
    }
}

impl RedisSemanticCacheStore {
    /// Read one bucket manifest through the fixed bounded Lua script.
    async fn read_manifest(
        &self,
        manifest_key: &str,
        maximum: usize,
    ) -> Result<Vec<String>, SemanticStoreError> {
        self.redis
            .evalsha_with_reload(
                SEMANTIC_INDEX_READ,
                &[manifest_key.to_string()],
                &[maximum.to_string()],
            )
            .await
            .map_err(|_| SemanticStoreError::Unavailable)
    }

    /// Insert one member into one bucket manifest through the fixed atomic Lua
    /// script.
    async fn write_manifest(
        &self,
        manifest_key: &str,
        member: &str,
        maximum: usize,
        ttl_secs: u64,
    ) -> Result<(), SemanticStoreError> {
        let reply = self
            .redis
            .evalsha_with_reload(
                SEMANTIC_INDEX_PUT,
                &[manifest_key.to_string()],
                &[
                    member.to_string(),
                    maximum.to_string(),
                    ttl_secs.to_string(),
                ],
            )
            .await
            .map_err(|_| SemanticStoreError::Unavailable)?;
        match reply.first().map(String::as_str) {
            Some("ok") => Ok(()),
            _ => Err(SemanticStoreError::OperationFailed),
        }
    }

    /// Resolve candidate digests for one query from every bucket manifest.
    ///
    /// Returns the deterministically ordered, deduplicated, capped digest set
    /// plus the count of manifest members that were not safe entry digests and
    /// whether a manifest filled its requested bound.
    async fn candidate_digests(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<CandidateSet, SemanticStoreError> {
        let bound = query.maximum_per_bucket;
        let tables = query.keys.bucket_indexes.len();
        if bound == 0 || tables == 0 {
            return Ok(CandidateSet::default());
        }
        // Manifest reads run with at most one operation per configured table.
        // Validation already caps the table count at MAX_LSH_TABLES; clamp
        // defensively so a malformed query cannot widen concurrency.
        let in_flight = tables.min(usize::from(MAX_LSH_TABLES));
        let manifest_reads = query
            .keys
            .bucket_indexes
            .iter()
            .map(|index| self.read_manifest(index.manifest_key.as_str(), bound))
            .collect::<Vec<_>>();
        let mut manifests = futures::stream::iter(manifest_reads).buffer_unordered(in_flight);

        let mut set = CandidateSet::default();
        let mut ordered: BTreeSet<String> = BTreeSet::new();
        while let Some(result) = manifests.next().await {
            let members = result?;
            if members.len() >= bound {
                // The manifest filled the requested limit, so more candidates
                // may exist behind the bound.
                set.truncated = true;
            }
            for member in members {
                if parse_entry_digest(&member).is_some() {
                    ordered.insert(member);
                } else {
                    set.unsafe_members = set.unsafe_members.saturating_add(1);
                }
            }
        }

        let cap = tables.saturating_mul(bound);
        if ordered.len() > cap {
            set.truncated = true;
        }
        set.digests = ordered
            .iter()
            .take(cap)
            .filter_map(|member| parse_entry_digest(member))
            .collect();
        Ok(set)
    }

    /// Fetch, decode, and rerank every retained candidate for one lookup.
    async fn resolve_candidates(
        &self,
        query: &SemanticStoreLookupQuery,
        selector: &mut SemanticExactSelector,
        now_unix_ms: u64,
    ) -> Result<LookupState, SemanticStoreError> {
        let candidates = self.candidate_digests(query).await?;
        let mut state = LookupState {
            expired: 0,
            // A manifest member that is not a safe digest is a malformed
            // distributed record, not an expired one.
            incompatible: candidates.unsafe_members,
            truncated: candidates.truncated,
        };

        let fetches = candidates
            .digests
            .iter()
            .map(|digest| {
                // Payload keys are only ever rebuilt through the shared
                // generator, never assembled from a manifest string.
                let key = semantic_entry_key(&query.namespace, digest);
                async move { AsyncKVStore::get(self.redis.as_ref(), key.as_bytes()).await }
            })
            .collect::<Vec<_>>();
        let mut payloads =
            futures::stream::iter(fetches).buffer_unordered(MAX_PAYLOAD_FETCHES_IN_FLIGHT);
        while let Some(result) = payloads.next().await {
            match result {
                // Discard any partial exact winner. Returning here drops the
                // bounded stream and cancels the remaining fetches; the
                // orchestrator turns the closed error into one observable miss.
                Err(_) => return Err(SemanticStoreError::Unavailable),
                // A manifest member whose payload is gone is the ordinary
                // effect of TTL expiry and is always a safe miss.
                Ok(None) => state.expired = state.expired.saturating_add(1),
                Ok(Some(bytes)) => match decode_entry(&bytes, &query.namespace, now_unix_ms) {
                    Ok(entry) => selector.consider(Arc::new(entry)),
                    // Corrupt, wrong-version, wrong-namespace, and expired wire
                    // values are rejected independently so one bad record
                    // cannot fail the whole lookup.
                    Err(_) => state.incompatible = state.incompatible.saturating_add(1),
                },
            }
        }
        Ok(state)
    }

    /// Run one complete lookup, from bucket manifests through exact reranking.
    async fn lookup_inner(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError> {
        // One snapshot feeds wire decoding and exact selection, so candidates
        // cannot change classification halfway through the operation.
        let now_unix_ms = now_unix_ms();
        let mut selector = SemanticExactSelector::new(
            Arc::clone(&query.embedding),
            query.threshold,
            query.namespace.clone(),
            now_unix_ms,
        )
        .map_err(selector_error)?;
        let state = self
            .resolve_candidates(query, &mut selector, now_unix_ms)
            .await?;
        let mut lookup = selector.finish();
        lookup.truncated = state.truncated;
        lookup.expired = lookup.expired.saturating_add(state.expired);
        lookup.incompatible = lookup.incompatible.saturating_add(state.incompatible);
        lookup.rejected = lookup
            .rejected
            .saturating_add(state.expired)
            .saturating_add(state.incompatible);
        Ok(lookup)
    }

    /// Validate one logical write, then store the payload before any index.
    async fn put_inner(&self, write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
        // Redis retention is TTL based, so a zero TTL would store an entry
        // that no bound ever removes.
        if write.ttl_secs == 0 {
            return Err(SemanticStoreError::InvalidWrite);
        }
        if write.maximum_per_bucket == 0 || write.maximum_per_bucket > MAX_CANDIDATES_PER_BUCKET {
            return Err(SemanticStoreError::InvalidWrite);
        }
        let tables = write.keys.bucket_indexes.len();
        if tables == 0 || tables > usize::from(MAX_LSH_TABLES) {
            return Err(SemanticStoreError::InvalidWrite);
        }
        // The entry key must be the generated key for this entry, so a caller
        // can never route one namespace's response under another's key.
        let expected_key = semantic_entry_key(&write.entry.namespace, &write.entry.prompt_digest);
        if write.keys.entry_key != expected_key {
            return Err(SemanticStoreError::InvalidWrite);
        }

        let encoded = encode_entry(&write.entry).map_err(|_| SemanticStoreError::InvalidWrite)?;
        if encoded.len() > MAX_SEMANTIC_ENTRY_BYTES {
            return Err(SemanticStoreError::InvalidWrite);
        }

        // Payload first. A crash after this point can leave an unreachable
        // payload; the reverse order could leave an index member pointing at a
        // response that was never validated and stored.
        AsyncKVStore::put_with_ttl(
            self.redis.as_ref(),
            expected_key.as_bytes(),
            &encoded,
            write.ttl_secs,
        )
        .await
        .map_err(|_| SemanticStoreError::Unavailable)?;

        let member = hex::encode(write.entry.prompt_digest);
        let index_writes = write
            .keys
            .bucket_indexes
            .iter()
            .map(|index| {
                self.write_manifest(
                    index.manifest_key.as_str(),
                    member.as_str(),
                    write.maximum_per_bucket,
                    write.ttl_secs,
                )
            })
            .collect::<Vec<_>>();
        let mut indexes = futures::stream::iter(index_writes).buffer_unordered(tables);
        // A write is never reported successful before every selected index
        // acknowledges. No task is ever spawned detached.
        while let Some(result) = indexes.next().await {
            result?;
        }
        Ok(())
    }

    /// Delete every key matched by one generated pattern.
    ///
    /// Redis `SCAN` is not an atomic barrier against concurrent writers, so a
    /// complete report means every observed page and delete succeeded, not
    /// that a write racing the purge was invalidated.
    async fn purge_pattern(&self, pattern: &str) -> SemanticPurgeReport {
        let mut report = SemanticPurgeReport {
            removed: 0,
            nodes_attempted: 1,
            nodes_failed: 0,
            complete: true,
        };
        let mut cursor = 0_u64;
        let mut rounds = 0_u32;
        loop {
            rounds = rounds.saturating_add(1);
            if rounds > MAX_PURGE_SCAN_ROUNDS {
                report.nodes_failed = 1;
                report.complete = false;
                return report;
            }
            let page = match self
                .redis
                .scan_page(cursor, pattern, PURGE_SCAN_COUNT)
                .await
            {
                Ok(page) => page,
                Err(_) => {
                    report.nodes_failed = 1;
                    report.complete = false;
                    return report;
                }
            };
            let deletes = page
                .keys
                .iter()
                .map(|key| async move {
                    AsyncKVStore::delete(self.redis.as_ref(), key.as_bytes()).await
                })
                .collect::<Vec<_>>();
            let mut stream =
                futures::stream::iter(deletes).buffer_unordered(MAX_PURGE_DELETES_IN_FLIGHT);
            let mut page_failed = false;
            // Finish every already-started delete before deciding the page
            // outcome, so an early failure never abandons in-flight work.
            while let Some(result) = stream.next().await {
                match result {
                    Ok(()) => report.removed = report.removed.saturating_add(1),
                    Err(_) => page_failed = true,
                }
            }
            if page_failed {
                report.nodes_failed = 1;
                report.complete = false;
                return report;
            }
            if page.next_cursor == 0 {
                return report;
            }
            cursor = page.next_cursor;
        }
    }
}

/// Candidate identifiers resolved from every bucket manifest for one lookup.
#[derive(Default)]
struct CandidateSet {
    /// Deduplicated candidate prompt digests in deterministic order.
    digests: Vec<[u8; 32]>,
    /// Manifest members that were not safe 64 character hex digests.
    unsafe_members: u64,
    /// A manifest filled its requested bound, so more candidates may exist.
    truncated: bool,
}

/// Store-side counts accumulated while resolving one lookup.
struct LookupState {
    /// Candidates whose payload was already gone.
    expired: u64,
    /// Candidates that failed manifest or wire validation.
    incompatible: u64,
    /// A manifest filled its requested bound.
    truncated: bool,
}

#[async_trait::async_trait]
impl SemanticCacheStore for RedisSemanticCacheStore {
    fn backend(&self) -> SemanticCacheBackend {
        SemanticCacheBackend::Redis
    }

    async fn lookup(
        &self,
        query: &SemanticStoreLookupQuery,
    ) -> Result<SemanticStoreLookup, SemanticStoreError> {
        let result = self.lookup_inner(query).await;
        self.stats.record_candidate_read(result.is_ok());
        if let Ok(lookup) = result.as_ref() {
            self.stats.record_rejected(lookup.rejected);
        }
        result
    }

    async fn put(&self, write: &SemanticStoreWrite) -> Result<(), SemanticStoreError> {
        let result = self.put_inner(write).await;
        self.stats.record_write(result.is_ok());
        result
    }

    async fn purge(
        &self,
        scope: &SemanticPurgeScope,
    ) -> Result<SemanticPurgeReport, SemanticStoreError> {
        let prefix = semantic_purge_prefix(scope);
        if !is_safe_generated_prefix(&prefix) {
            // An unusable typed scope is an internal invariant failure, not a
            // partial purge, so it never reports a plausible removal count.
            self.stats.record_purge(&SemanticPurgeReport {
                removed: 0,
                nodes_attempted: 1,
                nodes_failed: 1,
                complete: false,
            });
            return Err(SemanticStoreError::InvalidState);
        }
        // Only the Redis adapter turns a literal generated prefix into a SCAN
        // glob. An entry scope is already one exact key.
        let pattern = match scope {
            SemanticPurgeScope::Entry { .. } => prefix,
            SemanticPurgeScope::All
            | SemanticPurgeScope::Origin { .. }
            | SemanticPurgeScope::Namespace { .. } => format!("{prefix}*"),
        };
        let report = self.purge_pattern(&pattern).await;
        self.stats.record_purge(&report);
        Ok(report)
    }

    async fn health(&self) -> SemanticStoreHealth {
        match AsyncKVStore::get(self.redis.as_ref(), SEMANTIC_HEALTH_PROBE_KEY.as_bytes()).await {
            // Any successful reply is healthy, whether the probe key is absent
            // or an operator happened to create it.
            Ok(_) => SemanticStoreHealth {
                backend: SemanticCacheBackend::Redis,
                state: SemanticHealthState::Healthy,
                reason: None,
            },
            Err(_) => SemanticStoreHealth {
                backend: SemanticCacheBackend::Redis,
                state: SemanticHealthState::Unavailable,
                reason: Some(SEMANTIC_HEALTH_PROBE_FAILED),
            },
        }
    }

    fn stats(&self) -> SemanticStoreStats {
        // A process cannot claim a cheap global count of a shared keyspace.
        self.stats.snapshot(None)
    }
}

/// Map an impossible store-side selector failure onto a closed store error.
///
/// The orchestrator validates the query before calling a store, so an invalid
/// embedding here is an internal invariant failure. The vector and any backend
/// detail are never attached.
fn selector_error(error: SemanticLookupError) -> SemanticStoreError {
    match error {
        SemanticLookupError::InvalidEmbedding => SemanticStoreError::InvalidState,
        SemanticLookupError::Store(error) => error,
    }
}

/// The only bytes a generated entry digest may contain.
const LOWERCASE_HEX_BYTES: &[u8] = b"0123456789abcdef";

/// Accept only a 64 character lowercase hex entry digest.
fn parse_entry_digest(candidate: &str) -> Option<[u8; 32]> {
    if candidate.len() != ENTRY_DIGEST_HEX_LEN {
        return None;
    }
    if !candidate
        .bytes()
        .all(|byte| LOWERCASE_HEX_BYTES.contains(&byte))
    {
        return None;
    }
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(candidate, &mut digest).ok()?;
    Some(digest)
}

/// Accept only a generated semantic key prefix built from fixed ASCII labels
/// and lowercase hex.
///
/// This rejects every Redis glob metacharacter, so an operator-supplied value
/// can never reach `SCAN MATCH` even if a future caller passes one in.
fn is_safe_generated_prefix(prefix: &str) -> bool {
    prefix.starts_with(SEMANTIC_KEY_PREFIX)
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b':')
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    /// How a fixture waits for an entry to age out, injected so a test can
    /// drive expiry without sleeping in real time.
    type AwaitExpiry = Box<
        dyn Fn(Arc<dyn SemanticCacheStore>, SemanticStoreLookupQuery) -> BoxFuture<'static, ()>
            + Send
            + Sync,
    >;

    /// `unwrap_err` needs `Debug` on the success value, and a bound store
    /// would print cached prompts and model output. Unwrap the error side
    /// explicitly rather than deriving `Debug` for a test assertion.
    #[track_caller]
    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
    use super::{
        RedisSemanticCacheStore, SEMANTIC_HEALTH_PROBE_FAILED, SEMANTIC_HEALTH_PROBE_KEY,
        SEMANTIC_INDEX_PUT, SEMANTIC_INDEX_READ,
    };
    use futures::future::BoxFuture;
    use sbproxy_ai::semantic_cache::{
        encode_entry, semantic_entry_key, semantic_entry_keys, CachedHttpResponse, SemanticBucket,
        SemanticCacheBackend, SemanticCacheStore, SemanticEntryKeys, SemanticHealthState,
        SemanticNamespace, SemanticNamespaceInput, SemanticPurgeScope, SemanticStoreError,
        SemanticStoreLookupQuery, SemanticStoreWrite, StoredSemanticEntry,
        SEMANTIC_CACHE_SCHEMA_VERSION,
    };
    use sbproxy_platform::storage::{
        AsyncKVStore, AsyncRedisConfig, AsyncRedisKVStore, KVStore, MemoryKVStore, RedisTlsConfig,
        ValidatedRedisConnection,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::SocketAddr;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    // --- fixtures -------------------------------------------------------

    const SENTINEL_USER: &str = "sentinel-redis-user";
    const SENTINEL_PASSWORD: &str = "sentinel-redis-password";
    const SENTINEL_TENANT: &str = "tenant-secret-a";
    const SENTINEL_OTHER_TENANT: &str = "tenant-secret-b";
    const SENTINEL_PROMPT: &str = "refund policy";

    fn namespace_for(origin: &str, tenant: &str) -> SemanticNamespace {
        let request_context = [7_u8; 32];
        let semantic_config = [9_u8; 32];
        let response_policy = [11_u8; 32];
        SemanticNamespace::derive(SemanticNamespaceInput {
            origin_route: origin,
            request_host: origin,
            tenant_id: tenant,
            credential_identity: "credential-sentinel",
            requested_model: "test-model",
            api_surface: "openai_chat",
            request_context_digest: &request_context,
            embedding_identity: "test-embedding",
            embedding_dimensions: 3,
            semantic_config_digest: &semantic_config,
            response_policy_digest: &response_policy,
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
        })
    }

    fn namespace() -> SemanticNamespace {
        namespace_for("api.test.sbproxy.dev", SENTINEL_TENANT)
    }

    fn buckets(tables: u8) -> Vec<SemanticBucket> {
        (0..tables)
            .map(|table| SemanticBucket {
                table,
                value: u64::from(table) + 1,
            })
            .collect()
    }

    fn entry_keys(
        namespace: &SemanticNamespace,
        prompt_digest: &[u8; 32],
        tables: u8,
    ) -> SemanticEntryKeys {
        semantic_entry_keys(namespace, prompt_digest, &buckets(tables))
    }

    /// One of three orthogonal unit vectors, so two different prompts never
    /// clear the same similarity threshold.
    fn embedding_for(digest: [u8; 32]) -> Vec<f32> {
        match digest[0] % 3 {
            0 => vec![1.0, 0.0, 0.0],
            1 => vec![0.0, 1.0, 0.0],
            _ => vec![0.0, 0.0, 1.0],
        }
    }

    fn stored_entry(
        namespace: &SemanticNamespace,
        prompt_digest: [u8; 32],
        ttl_secs: u64,
    ) -> Arc<StoredSemanticEntry> {
        let now = super::now_unix_ms();
        Arc::new(StoredSemanticEntry {
            schema_version: SEMANTIC_CACHE_SCHEMA_VERSION,
            namespace: namespace.clone(),
            prompt_digest,
            embedding: embedding_for(prompt_digest),
            response: Arc::new(CachedHttpResponse {
                status: 200,
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: format!(r#"{{"answer":"{SENTINEL_PROMPT}"}}"#)
                    .into_bytes()
                    .into(),
            }),
            stored_at_unix_ms: now,
            expires_at_unix_ms: now + ttl_secs.saturating_mul(1_000),
        })
    }

    fn write_for(
        namespace: &SemanticNamespace,
        prompt_digest: [u8; 32],
        tables: u8,
        ttl_secs: u64,
        maximum_per_bucket: usize,
    ) -> SemanticStoreWrite {
        SemanticStoreWrite {
            entry: stored_entry(namespace, prompt_digest, ttl_secs),
            keys: entry_keys(namespace, &prompt_digest, tables),
            ttl_secs,
            maximum_per_bucket,
        }
    }

    fn query_for(
        namespace: &SemanticNamespace,
        prompt_digest: [u8; 32],
        tables: u8,
        maximum_per_bucket: usize,
    ) -> SemanticStoreLookupQuery {
        SemanticStoreLookupQuery {
            namespace: namespace.clone(),
            keys: entry_keys(namespace, &prompt_digest, tables),
            embedding: Arc::from(embedding_for(prompt_digest).into_boxed_slice()),
            threshold: 0.9,
            maximum_per_bucket,
        }
    }

    // --- local RESP fixture ---------------------------------------------

    /// One recorded Redis command. Stored values are replaced with a fixed
    /// marker so a failing assertion never prints a cached response, a header,
    /// or an embedding.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedCommand {
        name: String,
        args: Vec<String>,
    }

    /// One recorded script invocation, labelled by which fixed script ran.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct EvalCall {
        script: String,
        keys: Vec<String>,
        args: Vec<String>,
    }

    struct FixtureInner {
        values: BTreeMap<String, Vec<u8>>,
        lists: BTreeMap<String, Vec<String>>,
        scripts: BTreeMap<String, String>,
        commands: Vec<RecordedCommand>,
        eval_calls: Vec<EvalCall>,
        get_calls: BTreeMap<String, usize>,
        scan_calls: Vec<(u64, String, u16)>,
        fail_get: BTreeSet<String>,
        fail_eval: BTreeSet<String>,
        fail_delete: BTreeSet<String>,
        fail_scan_cursor: BTreeSet<u64>,
        scan_page_size: usize,
        get_delay: Duration,
        in_flight_gets: usize,
        max_in_flight_gets: usize,
        next_script: usize,
    }

    impl Default for FixtureInner {
        fn default() -> Self {
            Self {
                values: BTreeMap::new(),
                lists: BTreeMap::new(),
                scripts: BTreeMap::new(),
                commands: Vec::new(),
                eval_calls: Vec::new(),
                get_calls: BTreeMap::new(),
                scan_calls: Vec::new(),
                fail_get: BTreeSet::new(),
                fail_eval: BTreeSet::new(),
                fail_delete: BTreeSet::new(),
                fail_scan_cursor: BTreeSet::new(),
                scan_page_size: usize::MAX,
                get_delay: Duration::ZERO,
                in_flight_gets: 0,
                max_in_flight_gets: 0,
                next_script: 0,
            }
        }
    }

    #[derive(Default)]
    struct FixtureState {
        inner: Mutex<FixtureInner>,
    }

    impl FixtureState {
        fn with<R>(&self, apply: impl FnOnce(&mut FixtureInner) -> R) -> R {
            let mut guard = self.inner.lock().expect("fixture state poisoned");
            apply(&mut guard)
        }

        fn enter_get(&self) {
            self.with(|inner| {
                inner.in_flight_gets += 1;
                inner.max_in_flight_gets = inner.max_in_flight_gets.max(inner.in_flight_gets);
            });
        }

        fn leave_get(&self) {
            self.with(|inner| {
                inner.in_flight_gets = inner.in_flight_gets.saturating_sub(1);
            });
        }

        fn command_names(&self) -> Vec<String> {
            self.with(|inner| {
                inner
                    .commands
                    .iter()
                    .map(|command| command.name.clone())
                    .collect()
            })
        }

        fn eval_calls(&self, script: &str) -> Vec<EvalCall> {
            self.with(|inner| {
                inner
                    .eval_calls
                    .iter()
                    .filter(|call| call.script == script)
                    .cloned()
                    .collect()
            })
        }
    }

    fn simple(text: &str) -> Vec<u8> {
        format!("+{text}\r\n").into_bytes()
    }

    fn error_reply(text: &str) -> Vec<u8> {
        format!("-{text}\r\n").into_bytes()
    }

    fn integer(value: i64) -> Vec<u8> {
        format!(":{value}\r\n").into_bytes()
    }

    fn bulk(value: &[u8]) -> Vec<u8> {
        let mut reply = format!("${}\r\n", value.len()).into_bytes();
        reply.extend_from_slice(value);
        reply.extend_from_slice(b"\r\n");
        reply
    }

    fn nil_bulk() -> Vec<u8> {
        b"$-1\r\n".to_vec()
    }

    fn string_array(values: &[String]) -> Vec<u8> {
        let mut reply = format!("*{}\r\n", values.len()).into_bytes();
        for value in values {
            reply.extend_from_slice(&bulk(value.as_bytes()));
        }
        reply
    }

    fn matches_pattern(key: &str, pattern: &str) -> bool {
        match pattern.strip_suffix('*') {
            Some(prefix) => key.starts_with(prefix),
            None => key == pattern,
        }
    }

    fn text(part: &[u8]) -> String {
        String::from_utf8_lossy(part).to_string()
    }

    async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Option<String> {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await.ok()?;
        if read == 0 {
            return None;
        }
        Some(line.trim_end_matches(['\r', '\n']).to_string())
    }

    async fn read_command(
        reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> Option<Vec<Vec<u8>>> {
        let header = read_line(reader).await?;
        let count: usize = header.strip_prefix('*')?.parse().ok()?;
        let mut parts = Vec::new();
        for _ in 0..count {
            let length_line = read_line(reader).await?;
            let length: usize = length_line.strip_prefix('$')?.parse().ok()?;
            let mut payload = vec![0_u8; length + 2];
            reader.read_exact(&mut payload).await.ok()?;
            payload.truncate(length);
            parts.push(payload);
        }
        Some(parts)
    }

    /// Emulate one Redis command. Returns the reply and whether it was a GET.
    fn respond(state: &FixtureState, command: &[Vec<u8>]) -> (Vec<u8>, bool) {
        let Some(head) = command.first() else {
            return (error_reply("ERR empty command"), false);
        };
        let name = text(head).to_ascii_uppercase();
        let arguments = &command[1..];
        match name.as_str() {
            "CLIENT" | "SELECT" | "AUTH" => (simple("OK"), false),
            "PING" => (simple("PONG"), false),
            "HELLO" => (error_reply("ERR unknown command 'HELLO'"), false),
            "SCRIPT" => {
                let sub = arguments
                    .first()
                    .map(|part| text(part).to_ascii_uppercase());
                if sub.as_deref() != Some("LOAD") {
                    return (simple("OK"), false);
                }
                let source = arguments
                    .get(1)
                    .map(|part| text(part.as_slice()))
                    .unwrap_or_default();
                let token = state.with(|inner| {
                    inner.next_script += 1;
                    let token = format!("script-sha-{}", inner.next_script);
                    inner.scripts.insert(token.clone(), source);
                    inner.commands.push(RecordedCommand {
                        name: "SCRIPT LOAD".to_string(),
                        args: vec![token.clone()],
                    });
                    token
                });
                (bulk(token.as_bytes()), false)
            }
            "EVALSHA" => {
                let token = arguments
                    .first()
                    .map(|part| text(part.as_slice()))
                    .unwrap_or_default();
                let numkeys: usize = arguments
                    .get(1)
                    .map(|part| text(part.as_slice()))
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let keys: Vec<String> = arguments
                    .iter()
                    .skip(2)
                    .take(numkeys)
                    .map(|part| text(part.as_slice()))
                    .collect();
                let args: Vec<String> = arguments
                    .iter()
                    .skip(2 + numkeys)
                    .map(|part| text(part.as_slice()))
                    .collect();
                (evaluate(state, &token, &keys, &args), false)
            }
            "GET" => {
                let key = arguments
                    .first()
                    .map(|part| text(part.as_slice()))
                    .unwrap_or_default();
                let reply = state.with(|inner| {
                    inner.commands.push(RecordedCommand {
                        name: "GET".to_string(),
                        args: vec![key.clone()],
                    });
                    *inner.get_calls.entry(key.clone()).or_insert(0) += 1;
                    if inner.fail_get.contains(&key) {
                        return error_reply("ERR simulated GET failure");
                    }
                    match inner.values.get(&key) {
                        Some(value) => bulk(value),
                        None => nil_bulk(),
                    }
                });
                (reply, true)
            }
            "SET" => {
                let key = arguments
                    .first()
                    .map(|part| text(part.as_slice()))
                    .unwrap_or_default();
                let value = arguments.get(1).cloned().unwrap_or_default();
                let tail: Vec<String> = arguments
                    .iter()
                    .skip(2)
                    .map(|part| text(part.as_slice()))
                    .collect();
                state.with(|inner| {
                    let mut args = vec![key.clone(), "<value>".to_string()];
                    args.extend(tail);
                    inner.commands.push(RecordedCommand {
                        name: "SET".to_string(),
                        args,
                    });
                    inner.values.insert(key, value);
                });
                (simple("OK"), false)
            }
            "DEL" => {
                let key = arguments
                    .first()
                    .map(|part| text(part.as_slice()))
                    .unwrap_or_default();
                let reply = state.with(|inner| {
                    inner.commands.push(RecordedCommand {
                        name: "DEL".to_string(),
                        args: vec![key.clone()],
                    });
                    if inner.fail_delete.contains(&key) {
                        return error_reply("ERR simulated DEL failure");
                    }
                    let removed = usize::from(inner.values.remove(&key).is_some())
                        + usize::from(inner.lists.remove(&key).is_some());
                    integer(i64::try_from(removed).unwrap_or(0))
                });
                (reply, false)
            }
            "SCAN" => {
                let cursor: u64 = arguments
                    .first()
                    .map(|part| text(part.as_slice()))
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let pattern = arguments
                    .get(2)
                    .map(|part| text(part.as_slice()))
                    .unwrap_or_default();
                let count: u16 = arguments
                    .get(4)
                    .map(|part| text(part.as_slice()))
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let reply = state.with(|inner| {
                    inner.commands.push(RecordedCommand {
                        name: "SCAN".to_string(),
                        args: vec![cursor.to_string(), pattern.clone(), count.to_string()],
                    });
                    inner.scan_calls.push((cursor, pattern.clone(), count));
                    if inner.fail_scan_cursor.contains(&cursor) {
                        return error_reply("ERR simulated SCAN failure");
                    }
                    let mut keys: Vec<String> = inner
                        .values
                        .keys()
                        .chain(inner.lists.keys())
                        .filter(|key| matches_pattern(key.as_str(), pattern.as_str()))
                        .cloned()
                        .collect();
                    keys.sort();
                    keys.dedup();
                    let start = usize::try_from(cursor).unwrap_or(0);
                    let end = start.saturating_add(inner.scan_page_size).min(keys.len());
                    let page: Vec<String> = keys.get(start..end).unwrap_or_default().to_vec();
                    let next = if end >= keys.len() {
                        0
                    } else {
                        u64::try_from(end).unwrap_or(0)
                    };
                    let mut reply = b"*2\r\n".to_vec();
                    reply.extend_from_slice(&bulk(next.to_string().as_bytes()));
                    reply.extend_from_slice(&string_array(&page));
                    reply
                });
                (reply, false)
            }
            other => (
                error_reply(&format!("ERR unsupported command '{other}'")),
                false,
            ),
        }
    }

    /// Emulate the two fixed semantic Lua scripts.
    fn evaluate(state: &FixtureState, token: &str, keys: &[String], args: &[String]) -> Vec<u8> {
        let source = state.with(|inner| inner.scripts.get(token).cloned());
        let Some(source) = source else {
            return error_reply("NOSCRIPT No matching script. Please use EVAL.");
        };
        let key = keys.first().cloned().unwrap_or_default();
        if source == SEMANTIC_INDEX_PUT {
            return state.with(|inner| {
                inner.commands.push(RecordedCommand {
                    name: "EVALSHA".to_string(),
                    args: vec!["index_put".to_string(), key.clone()],
                });
                inner.eval_calls.push(EvalCall {
                    script: "index_put".to_string(),
                    keys: keys.to_vec(),
                    args: args.to_vec(),
                });
                if inner.fail_eval.contains(&key) {
                    return error_reply("ERR simulated EVALSHA failure");
                }
                let member = args.first().cloned().unwrap_or_default();
                let maximum: usize = args
                    .get(1)
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                if maximum == 0 {
                    return string_array(&["invalid".to_string()]);
                }
                let list = inner.lists.entry(key).or_default();
                list.retain(|existing| existing != &member);
                list.insert(0, member);
                list.truncate(maximum);
                let length = list.len().to_string();
                string_array(&["ok".to_string(), length])
            });
        }
        if source == SEMANTIC_INDEX_READ {
            return state.with(|inner| {
                inner.commands.push(RecordedCommand {
                    name: "EVALSHA".to_string(),
                    args: vec!["index_read".to_string(), key.clone()],
                });
                inner.eval_calls.push(EvalCall {
                    script: "index_read".to_string(),
                    keys: keys.to_vec(),
                    args: args.to_vec(),
                });
                if inner.fail_eval.contains(&key) {
                    return error_reply("ERR simulated EVALSHA failure");
                }
                let maximum: usize = args
                    .first()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let members: Vec<String> = inner
                    .lists
                    .get(&key)
                    .map(|list| {
                        list.iter()
                            .take(maximum)
                            .filter(|member| super::parse_entry_digest(member).is_some())
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                string_array(&members)
            });
        }
        error_reply("ERR unexpected script source")
    }

    /// A local Tokio RESP server that speaks enough of the protocol to drive
    /// the real async Redis client.
    struct RespFixture {
        address: SocketAddr,
        state: Arc<FixtureState>,
    }

    impl RespFixture {
        async fn start() -> Self {
            let state = Arc::new(FixtureState::default());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let accept_state = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let connection_state = Arc::clone(&accept_state);
                    tokio::spawn(async move { serve_connection(connection_state, stream).await });
                }
            });
            Self { address, state }
        }

        fn store(&self) -> Arc<RedisSemanticCacheStore> {
            RedisSemanticCacheStore::from_async_store(AsyncRedisKVStore::new(
                AsyncRedisConfig::new(&format!("redis://{}/0", self.address)),
            ))
        }
    }

    async fn serve_connection(state: Arc<FixtureState>, stream: TcpStream) {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<Vec<Vec<u8>>>();
        let reader_state = Arc::clone(&state);
        // The reader runs ahead of the responder so a pipelined batch of
        // commands is observable as concurrent in-flight work.
        let reader_task = tokio::spawn(async move {
            while let Some(command) = read_command(&mut reader).await {
                let is_get = command
                    .first()
                    .map(|head| text(head).eq_ignore_ascii_case("GET"))
                    .unwrap_or(false);
                if is_get {
                    reader_state.enter_get();
                }
                if sender.send(command).is_err() {
                    return;
                }
            }
        });
        while let Some(command) = receiver.recv().await {
            let delay = state.with(|inner| inner.get_delay);
            let (reply, was_get) = respond(&state, &command);
            if was_get {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                state.leave_get();
            }
            if write_half.write_all(&reply).await.is_err() {
                break;
            }
        }
        reader_task.abort();
    }

    // --- constructor and validation -------------------------------------

    struct ValidatedL2Store {
        connection: ValidatedRedisConnection,
    }

    impl ValidatedL2Store {
        fn new(dsn: &str) -> Self {
            Self {
                connection: ValidatedRedisConnection::new(dsn, RedisTlsConfig::default()).unwrap(),
            }
        }
    }

    impl KVStore for ValidatedL2Store {
        fn validated_redis_connection(&self) -> Option<ValidatedRedisConnection> {
            Some(self.connection.clone())
        }

        fn get(&self, _key: &[u8]) -> anyhow::Result<Option<bytes::Bytes>> {
            anyhow::bail!("unused")
        }

        fn put(&self, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("unused")
        }

        fn delete(&self, _key: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("unused")
        }

        fn scan_prefix(&self, _prefix: &[u8]) -> anyhow::Result<Vec<(bytes::Bytes, bytes::Bytes)>> {
            anyhow::bail!("unused")
        }
    }

    #[test]
    fn redis_backend_requires_proxy_l2_cache_settings() {
        let error = expect_error(
            RedisSemanticCacheStore::from_l2_store(None),
            "redis backend without an l2 store must not construct",
        );

        let rendered = format!("{error:#}");
        assert!(rendered.contains("proxy.l2_cache_settings"), "{rendered}");
        assert!(
            rendered.contains("semantic_cache.backend redis"),
            "{rendered}"
        );
    }

    #[test]
    fn redis_backend_rejects_a_non_redis_l2_driver() {
        let memory = MemoryKVStore::new(0);

        let error = expect_error(
            RedisSemanticCacheStore::from_l2_store(Some(&memory)),
            "a non-redis l2 store must not construct a redis backend",
        );

        let rendered = format!("{error:#}");
        assert!(rendered.contains("proxy.l2_cache_settings"), "{rendered}");
    }

    #[tokio::test]
    async fn redis_backend_reuses_the_validated_connection_snapshot() {
        let fixture = RespFixture::start().await;
        let l2 = ValidatedL2Store::new(&format!(
            "redis://{SENTINEL_USER}:{SENTINEL_PASSWORD}@{}/0",
            fixture.address
        ));
        let store = RedisSemanticCacheStore::from_l2_store(Some(&l2)).unwrap();

        let health = store.health().await;

        assert_eq!(health.state, SemanticHealthState::Healthy);
        assert_eq!(health.backend, SemanticCacheBackend::Redis);
        let probed = fixture
            .state
            .with(|inner| inner.get_calls.contains_key(SEMANTIC_HEALTH_PROBE_KEY));
        assert!(
            probed,
            "health probe never reached the validated connection"
        );
    }

    #[tokio::test]
    async fn constructor_does_not_open_a_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let l2 = ValidatedL2Store::new(&format!("redis://{address}/0"));

        let store = RedisSemanticCacheStore::from_l2_store(Some(&l2)).unwrap();

        assert_eq!(store.backend(), SemanticCacheBackend::Redis);
        let accepted = tokio::time::timeout(Duration::from_millis(150), listener.accept()).await;
        assert!(
            accepted.is_err(),
            "constructing the Redis semantic store opened a connection"
        );
    }

    #[tokio::test]
    async fn redis_errors_never_render_the_dsn_username_password_host_or_key() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let dsn = format!("redis://{SENTINEL_USER}:{SENTINEL_PASSWORD}@127.0.0.1:{port}/0");
        let l2 = ValidatedL2Store::new(&dsn);
        let store = RedisSemanticCacheStore::from_l2_store(Some(&l2)).unwrap();
        let namespace = namespace();
        let digest = [3_u8; 32];
        let namespace_prefix = namespace.namespace_prefix();

        let lookup = store
            .lookup(&query_for(&namespace, digest, 2, 8))
            .await
            .unwrap_err();
        let put = store
            .put(&write_for(&namespace, digest, 2, 60, 8))
            .await
            .unwrap_err();
        let purge = store.purge(&SemanticPurgeScope::All).await.unwrap();
        let health = store.health().await;

        let rendered = format!(
            "{lookup} {lookup:?} {put} {put:?} {purge:?} {health:?} {:?}",
            store.stats()
        );
        for forbidden in [
            dsn.as_str(),
            SENTINEL_USER,
            SENTINEL_PASSWORD,
            "127.0.0.1",
            "redis://",
            SENTINEL_TENANT,
            SENTINEL_PROMPT,
            namespace_prefix.as_str(),
        ] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
        assert!(!purge.complete);
        assert_eq!(health.state, SemanticHealthState::Unavailable);
    }

    // --- deterministic RESP contracts -----------------------------------

    #[tokio::test]
    async fn redis_put_writes_payload_before_any_bucket_index() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();

        store
            .put(&write_for(&namespace, [5_u8; 32], 3, 60, 8))
            .await
            .unwrap();

        let names = fixture.state.command_names();
        let first_set = names
            .iter()
            .position(|name| name == "SET")
            .expect("payload was never written");
        let first_eval = names
            .iter()
            .position(|name| name == "EVALSHA")
            .expect("no index was written");
        assert!(
            first_set < first_eval,
            "payload must be written before any index: {names:?}"
        );
        assert_eq!(fixture.state.eval_calls("index_put").len(), 3);
        // The command capture holds no stored value, so a failing assertion
        // can never print a cached response.
        let set_args = fixture
            .state
            .with(|inner| {
                inner
                    .commands
                    .iter()
                    .find(|command| command.name == "SET")
                    .map(|command| command.args.clone())
            })
            .expect("payload command was not captured");
        assert!(set_args.contains(&"<value>".to_string()), "{set_args:?}");
        assert!(set_args.contains(&"EX".to_string()), "{set_args:?}");
    }

    #[tokio::test]
    async fn redis_index_put_uses_lrem_lpush_ltrim_and_expire() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();

        store
            .put(&write_for(&namespace, [6_u8; 32], 1, 60, 4))
            .await
            .unwrap();

        let source = fixture
            .state
            .with(|inner| {
                inner
                    .scripts
                    .values()
                    .find(|script| script.contains("index-put"))
                    .cloned()
            })
            .expect("index put script was never loaded");
        let lrem = source.find("LREM").expect("LREM missing");
        let lpush = source.find("LPUSH").expect("LPUSH missing");
        let ltrim = source.find("LTRIM").expect("LTRIM missing");
        let expire = source.find("EXPIRE").expect("EXPIRE missing");
        assert!(lrem < lpush && lpush < ltrim && ltrim < expire, "{source}");

        let mut calls = fixture.state.eval_calls("index_put");
        let call = calls.remove(0);
        let manifest = entry_keys(&namespace, &[6_u8; 32], 1).bucket_indexes[0]
            .manifest_key
            .clone();
        assert_eq!(call.keys, vec![manifest]);
        assert_eq!(call.args[0], hex::encode([6_u8; 32]));
        assert_eq!(call.args[1], "4");
        assert_eq!(call.args[2], "60");
    }

    #[tokio::test]
    async fn redis_candidate_read_never_requests_more_than_the_configured_bound() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let keys = entry_keys(&namespace, &[1_u8; 32], 2);
        let members: Vec<String> = (0..40_u8)
            .map(|seed| hex::encode([seed.wrapping_add(1); 32]))
            .collect();
        fixture.state.with(|inner| {
            for index in &keys.bucket_indexes {
                inner
                    .lists
                    .insert(index.manifest_key.clone(), members.clone());
            }
        });

        let lookup = store
            .lookup(&query_for(&namespace, [1_u8; 32], 2, 4))
            .await
            .unwrap();

        for call in fixture.state.eval_calls("index_read") {
            assert_eq!(call.args[0], "4", "manifest read exceeded the bound");
        }
        let fetched = fixture.state.with(|inner| inner.get_calls.len());
        assert!(
            fetched <= 2 * 4,
            "fetched {fetched} payloads above the bound"
        );
        assert!(lookup.truncated);
    }

    #[tokio::test]
    async fn redis_candidate_read_deduplicates_ids_across_tables() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let shared = hex::encode([9_u8; 32]);
        let keys = entry_keys(&namespace, &[1_u8; 32], 4);
        fixture.state.with(|inner| {
            for index in &keys.bucket_indexes {
                inner
                    .lists
                    .insert(index.manifest_key.clone(), vec![shared.clone()]);
            }
        });

        store
            .lookup(&query_for(&namespace, [1_u8; 32], 4, 8))
            .await
            .unwrap();

        let fetched = fixture.state.with(|inner| inner.get_calls.clone());
        assert_eq!(
            fetched.len(),
            1,
            "one id shared by four tables was fetched more than once"
        );
        assert_eq!(fetched.values().copied().next(), Some(1));
    }

    #[tokio::test]
    async fn redis_candidate_read_fetches_each_payload_at_most_once() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let keys = entry_keys(&namespace, &[1_u8; 32], 3);
        let members: Vec<String> = (0..6_u8)
            .map(|seed| hex::encode([seed.wrapping_add(20); 32]))
            .collect();
        fixture.state.with(|inner| {
            for index in &keys.bucket_indexes {
                inner
                    .lists
                    .insert(index.manifest_key.clone(), members.clone());
            }
        });

        store
            .lookup(&query_for(&namespace, [1_u8; 32], 3, 8))
            .await
            .unwrap();

        let fetched = fixture.state.with(|inner| inner.get_calls.clone());
        assert_eq!(fetched.len(), 6);
        for (key, count) in fetched {
            assert_eq!(count, 1, "{key} was fetched more than once");
        }
    }

    #[tokio::test]
    async fn redis_payload_fetch_concurrency_never_exceeds_eight() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let keys = entry_keys(&namespace, &[1_u8; 32], 1);
        let members: Vec<String> = (0..24_u8)
            .map(|seed| hex::encode([seed.wrapping_add(40); 32]))
            .collect();
        fixture.state.with(|inner| {
            inner.get_delay = Duration::from_millis(5);
            inner
                .lists
                .insert(keys.bucket_indexes[0].manifest_key.clone(), members);
        });

        store
            .lookup(&query_for(&namespace, [1_u8; 32], 1, 32))
            .await
            .unwrap();

        let observed = fixture.state.with(|inner| inner.max_in_flight_gets);
        assert!(
            observed <= 8,
            "payload fetch concurrency reached {observed}"
        );
        assert_eq!(fixture.state.with(|inner| inner.get_calls.len()), 24);
    }

    #[tokio::test]
    async fn redis_payload_error_discards_a_partial_exact_hit() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let hit_digest = [12_u8; 32];
        let broken_digest = [13_u8; 32];
        let keys = entry_keys(&namespace, &hit_digest, 1);
        let hit_key = semantic_entry_key(&namespace, &hit_digest);
        let broken_key = semantic_entry_key(&namespace, &broken_digest);
        let payload = encode_entry(&stored_entry(&namespace, hit_digest, 60)).unwrap();
        fixture.state.with(|inner| {
            inner.values.insert(hit_key, payload.to_vec());
            inner.fail_get.insert(broken_key);
            inner.lists.insert(
                keys.bucket_indexes[0].manifest_key.clone(),
                vec![hex::encode(hit_digest), hex::encode(broken_digest)],
            );
        });

        let error = store
            .lookup(&query_for(&namespace, hit_digest, 1, 8))
            .await
            .unwrap_err();

        assert_eq!(error, SemanticStoreError::Unavailable);
    }

    #[tokio::test]
    async fn dangling_index_member_is_a_safe_miss() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let keys = entry_keys(&namespace, &[1_u8; 32], 1);
        fixture.state.with(|inner| {
            inner.lists.insert(
                keys.bucket_indexes[0].manifest_key.clone(),
                vec![hex::encode([77_u8; 32])],
            );
        });

        let lookup = store
            .lookup(&query_for(&namespace, [1_u8; 32], 1, 8))
            .await
            .unwrap();

        assert!(lookup.exact_hit.is_none());
        assert_eq!(lookup.rejected, 1);
    }

    #[tokio::test]
    async fn payload_without_index_is_unreachable_and_safe() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let digest = [21_u8; 32];
        let entry_key = semantic_entry_key(&namespace, &digest);
        let payload = encode_entry(&stored_entry(&namespace, digest, 60)).unwrap();
        fixture.state.with(|inner| {
            inner.values.insert(entry_key, payload.to_vec());
        });

        let lookup = store
            .lookup(&query_for(&namespace, digest, 2, 8))
            .await
            .unwrap();

        assert!(lookup.exact_hit.is_none());
        assert_eq!(
            fixture.state.with(|inner| inner.get_calls.len()),
            0,
            "an unindexed payload must never be fetched"
        );
    }

    #[tokio::test]
    async fn partial_index_write_returns_an_error_but_cannot_create_a_false_hit() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        let digest = [31_u8; 32];
        let keys = entry_keys(&namespace, &digest, 3);
        fixture.state.with(|inner| {
            inner
                .fail_eval
                .insert(keys.bucket_indexes[2].manifest_key.clone());
        });

        let error = store
            .put(&write_for(&namespace, digest, 3, 60, 8))
            .await
            .unwrap_err();

        assert_eq!(error, SemanticStoreError::Unavailable);
        fixture.state.with(|inner| {
            let stored: BTreeSet<String> = inner.values.keys().cloned().collect();
            for (manifest, members) in &inner.lists {
                for member in members {
                    let referenced = semantic_entry_key(
                        &namespace,
                        &super::parse_entry_digest(member).expect("unsafe manifest member"),
                    );
                    assert!(
                        stored.contains(&referenced),
                        "{manifest} references a payload that was never stored"
                    );
                }
            }
        });
    }

    #[tokio::test]
    async fn redis_connection_failure_is_returned_without_sensitive_context() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let store = RedisSemanticCacheStore::from_async_store(AsyncRedisKVStore::new(
            AsyncRedisConfig::new(&format!("redis://127.0.0.1:{port}/0")),
        ));
        let namespace = namespace();

        let error = store
            .lookup(&query_for(&namespace, [4_u8; 32], 2, 8))
            .await
            .unwrap_err();

        assert_eq!(error, SemanticStoreError::Unavailable);
        assert_eq!(error.to_string(), "semantic cache backend unavailable");
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(&port.to_string()), "{rendered}");
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
    }

    #[tokio::test]
    async fn redis_health_reports_unavailable_after_a_sanitized_get_failure() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        fixture.state.with(|inner| {
            inner.fail_get.insert(SEMANTIC_HEALTH_PROBE_KEY.to_string());
        });

        let health = store.health().await;

        assert_eq!(health.state, SemanticHealthState::Unavailable);
        assert_eq!(health.reason, Some(SEMANTIC_HEALTH_PROBE_FAILED));
        let rendered = format!("{health:?}");
        assert!(
            !rendered.contains(&fixture.address.to_string()),
            "{rendered}"
        );
        assert!(!rendered.contains("redis://"), "{rendered}");
    }

    #[tokio::test]
    async fn redis_purge_reports_successful_deletes_before_a_later_failure() {
        let fixture = RespFixture::start().await;
        let store = fixture.store();
        let namespace = namespace();
        fixture.state.with(|inner| {
            inner.scan_page_size = 2;
            inner.fail_scan_cursor.insert(2);
            for seed in 0..5_u8 {
                let key = semantic_entry_key(&namespace, &[seed; 32]);
                inner.values.insert(key, vec![1, 2, 3]);
            }
        });

        let report = store.purge(&SemanticPurgeScope::All).await.unwrap();

        assert_eq!(report.removed, 2);
        assert_eq!(report.nodes_attempted, 1);
        assert_eq!(report.nodes_failed, 1);
        assert!(!report.complete);
        let scans = fixture.state.with(|inner| inner.scan_calls.clone());
        for (_, pattern, count) in &scans {
            assert_eq!(pattern.as_str(), "sbproxy:semcache:v2:*");
            assert_eq!(*count, 250);
        }
    }

    // --- shared store contract harness -----------------------------------

    /// Assertions every semantic store backend must satisfy.
    ///
    /// This harness stays private to `sbproxy-core` because dependency crates
    /// do not expose their `#[cfg(test)]` helpers. `await_expiry` lets each
    /// backend wait for its own TTL removal without an unbounded sleep.
    async fn assert_semantic_store_contract(
        store: Arc<dyn SemanticCacheStore>,
        await_expiry: AwaitExpiry,
    ) {
        let origin_a = namespace_for("a.test.sbproxy.dev", SENTINEL_TENANT);
        let origin_b = namespace_for("b.test.sbproxy.dev", SENTINEL_TENANT);
        let tenant_b = namespace_for("a.test.sbproxy.dev", SENTINEL_OTHER_TENANT);
        let first = [41_u8; 32];
        let second = [42_u8; 32];
        let expiring = [43_u8; 32];

        // empty store misses
        let miss = store
            .lookup(&query_for(&origin_a, first, 2, 8))
            .await
            .unwrap();
        assert!(miss.exact_hit.is_none());

        // put then load returns the stored entry
        store
            .put(&write_for(&origin_a, first, 2, 300, 8))
            .await
            .unwrap();
        let hit = store
            .lookup(&query_for(&origin_a, first, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .expect("stored entry was not returned");
        assert_eq!(hit.entry.prompt_digest, first);
        assert_eq!(hit.entry.response.status, 200);

        // namespace lookup cannot see another tenant scope
        store
            .put(&write_for(&tenant_b, second, 2, 300, 8))
            .await
            .unwrap();
        assert!(store
            .lookup(&query_for(&origin_a, second, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());

        // health is healthy after successful operations
        assert_eq!(store.health().await.state, SemanticHealthState::Healthy);

        // entry purge removes only one prompt
        store
            .put(&write_for(&origin_a, second, 2, 300, 8))
            .await
            .unwrap();
        let entry_purge = store
            .purge(&SemanticPurgeScope::Entry {
                namespace: origin_a.clone(),
                prompt_digest: first,
            })
            .await
            .unwrap();
        assert!(entry_purge.complete);
        assert!(store
            .lookup(&query_for(&origin_a, first, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());
        assert!(store
            .lookup(&query_for(&origin_a, second, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_some());

        // namespace purge removes only one namespace
        let namespace_purge = store
            .purge(&SemanticPurgeScope::Namespace {
                namespace: origin_a.clone(),
            })
            .await
            .unwrap();
        assert!(namespace_purge.complete);
        assert!(store
            .lookup(&query_for(&origin_a, second, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());
        assert!(store
            .lookup(&query_for(&tenant_b, second, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_some());

        // origin purge removes only one origin
        store
            .put(&write_for(&origin_b, first, 2, 300, 8))
            .await
            .unwrap();
        let origin_purge = store
            .purge(&SemanticPurgeScope::Origin {
                origin_digest: origin_a.origin_digest(),
            })
            .await
            .unwrap();
        assert!(origin_purge.complete);
        assert!(store
            .lookup(&query_for(&tenant_b, second, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());
        assert!(store
            .lookup(&query_for(&origin_b, first, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_some());

        // TTL expiry removes the entry
        store
            .put(&write_for(&origin_b, expiring, 2, 1, 8))
            .await
            .unwrap();
        await_expiry(Arc::clone(&store), query_for(&origin_b, expiring, 2, 8)).await;
        assert!(store
            .lookup(&query_for(&origin_b, expiring, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());

        // all purge removes every semantic key
        let all_purge = store.purge(&SemanticPurgeScope::All).await.unwrap();
        assert!(all_purge.complete);
        assert!(store
            .lookup(&query_for(&origin_b, first, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());

        // stats count reads, writes, and purges without raw labels
        let stats = store.stats();
        assert!(stats.candidate_reads >= 5, "{stats:?}");
        assert!(stats.writes >= 5, "{stats:?}");
        assert!(stats.purges >= 4, "{stats:?}");
        assert_eq!(stats.local_entries, None);
        let rendered = format!("{stats:?}");
        for forbidden in [SENTINEL_TENANT, SENTINEL_OTHER_TENANT, SENTINEL_PROMPT] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }

        // store errors have fixed Display text and carry no source detail
        assert_eq!(
            SemanticStoreError::Unavailable.to_string(),
            "semantic cache backend unavailable"
        );
        assert_eq!(
            SemanticStoreError::InvalidWrite.to_string(),
            "semantic cache write rejected"
        );
    }

    // --- disposable Redis -------------------------------------------------

    struct DisposableRedis {
        child: Option<Child>,
        port: u16,
        _directory: tempfile::TempDir,
    }

    impl DisposableRedis {
        fn start() -> std::io::Result<Self> {
            let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = reservation.local_addr()?.port();
            drop(reservation);
            let directory = tempfile::tempdir()?;
            let child = Command::new("redis-server")
                .arg("--port")
                .arg(port.to_string())
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--protected-mode")
                .arg("no")
                .arg("--save")
                .arg("")
                .arg("--appendonly")
                .arg("no")
                .arg("--daemonize")
                .arg("no")
                .arg("--dir")
                .arg(directory.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(Self {
                child: Some(child),
                port,
                _directory: directory,
            })
        }

        fn address(&self) -> String {
            format!("127.0.0.1:{}", self.port)
        }

        fn handle(&self) -> Arc<AsyncRedisKVStore> {
            AsyncRedisKVStore::new(AsyncRedisConfig::new(&format!(
                "redis://127.0.0.1:{}/0",
                self.port
            )))
        }

        async fn wait_until_ready(&self) {
            let redis = self.handle();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if AsyncKVStore::get(redis.as_ref(), b"semantic-probe")
                    .await
                    .is_ok()
                {
                    return;
                }
                assert!(Instant::now() < deadline, "disposable Redis did not start");
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    impl Drop for DisposableRedis {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    /// Send one raw RESP command to a live Redis and return its first reply
    /// line. Used only for administrative commands the async store seam does
    /// not expose, such as `SCRIPT FLUSH`.
    async fn send_raw_command(address: &str, parts: &[&str]) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut request = format!("*{}\r\n", parts.len()).into_bytes();
        for part in parts {
            request.extend_from_slice(format!("${}\r\n{part}\r\n", part.len()).as_bytes());
        }
        stream.write_all(&request).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        line.trim_end_matches(['\r', '\n']).to_string()
    }

    async fn live_keys(redis: &AsyncRedisKVStore, pattern: &str) -> Vec<String> {
        let mut cursor = 0_u64;
        let mut keys = Vec::new();
        loop {
            let page = redis.scan_page(cursor, pattern, 250).await.unwrap();
            keys.extend(page.keys);
            if page.next_cursor == 0 {
                keys.sort();
                keys.dedup();
                return keys;
            }
            cursor = page.next_cursor;
        }
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn live_redis_semantic_store_contract() {
        let server = DisposableRedis::start().unwrap();
        server.wait_until_ready().await;
        let store = RedisSemanticCacheStore::from_async_store(server.handle());

        assert_semantic_store_contract(
            store as Arc<dyn SemanticCacheStore>,
            Box::new(|store, query| -> BoxFuture<'static, ()> {
                Box::pin(async move {
                    // Bounded poll loop with an outer deadline, so the test can
                    // never sleep indefinitely on a stuck backend.
                    let deadline = Instant::now() + Duration::from_secs(15);
                    loop {
                        let lookup = store.lookup(&query).await.unwrap();
                        if lookup.exact_hit.is_none() {
                            return;
                        }
                        assert!(Instant::now() < deadline, "entry never expired");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                })
            }),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn live_redis_semantic_index_is_bounded_and_deduplicated() {
        let server = DisposableRedis::start().unwrap();
        server.wait_until_ready().await;
        let redis = server.handle();
        let store = RedisSemanticCacheStore::from_async_store(Arc::clone(&redis));
        let namespace = namespace();
        let bound = 4_usize;
        // Every write shares one forced-collision bucket, so all members land
        // in the same manifest.
        let manifest = entry_keys(&namespace, &[0_u8; 32], 1).bucket_indexes[0]
            .manifest_key
            .clone();

        for seed in 0..12_u8 {
            let digest = [seed; 32];
            store
                .put(&write_for(&namespace, digest, 1, 120, bound))
                .await
                .unwrap();
            // Write the same member twice to prove LREM removes the duplicate.
            store
                .put(&write_for(&namespace, digest, 1, 120, bound))
                .await
                .unwrap();
        }

        let members = redis
            .evalsha_with_reload(SEMANTIC_INDEX_READ, &[manifest], &["1000".to_string()])
            .await
            .unwrap();

        assert!(
            members.len() <= bound,
            "manifest returned {} members above the bound",
            members.len()
        );
        let unique: BTreeSet<&String> = members.iter().collect();
        assert_eq!(unique.len(), members.len(), "manifest kept a duplicate");
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn live_redis_semantic_payload_and_index_expire() {
        let server = DisposableRedis::start().unwrap();
        server.wait_until_ready().await;
        let redis = server.handle();
        let store = RedisSemanticCacheStore::from_async_store(Arc::clone(&redis));
        let namespace = namespace();
        let digest = [51_u8; 32];

        store
            .put(&write_for(&namespace, digest, 2, 1, 8))
            .await
            .unwrap();
        let pattern = format!("{}*", namespace.namespace_prefix());
        assert!(!live_keys(&redis, &pattern).await.is_empty());

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if live_keys(&redis, &pattern).await.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "payload and index keys never expired"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        assert!(store
            .lookup(&query_for(&namespace, digest, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn live_redis_semantic_script_recovers_after_script_flush() {
        let server = DisposableRedis::start().unwrap();
        server.wait_until_ready().await;
        let store = RedisSemanticCacheStore::from_async_store(server.handle());
        let namespace = namespace();
        let digest = [61_u8; 32];

        store
            .put(&write_for(&namespace, digest, 2, 120, 8))
            .await
            .unwrap();

        let flushed = send_raw_command(&server.address(), &["SCRIPT", "FLUSH"]).await;
        assert_eq!(flushed, "+OK");

        // The cached SHA is now unknown to Redis. evalsha_with_reload must
        // reload the source and retry rather than failing the write.
        store
            .put(&write_for(&namespace, digest, 2, 120, 8))
            .await
            .unwrap();

        assert!(store
            .lookup(&query_for(&namespace, digest, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_some());
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn live_redis_semantic_origin_purge_removes_payloads_and_indexes() {
        let server = DisposableRedis::start().unwrap();
        server.wait_until_ready().await;
        let redis = server.handle();
        let store = RedisSemanticCacheStore::from_async_store(Arc::clone(&redis));
        let origin_a = namespace_for("a.test.sbproxy.dev", SENTINEL_TENANT);
        let origin_b = namespace_for("b.test.sbproxy.dev", SENTINEL_TENANT);

        store
            .put(&write_for(&origin_a, [71_u8; 32], 2, 300, 8))
            .await
            .unwrap();
        store
            .put(&write_for(&origin_b, [72_u8; 32], 2, 300, 8))
            .await
            .unwrap();

        let report = store
            .purge(&SemanticPurgeScope::Origin {
                origin_digest: origin_a.origin_digest(),
            })
            .await
            .unwrap();

        assert!(report.complete);
        assert_eq!(report.nodes_attempted, 1);
        assert_eq!(report.nodes_failed, 0);
        assert!(report.removed >= 3, "payload and indexes were not removed");
        assert!(live_keys(&redis, &format!("{}*", origin_a.origin_prefix()))
            .await
            .is_empty());
        assert!(
            !live_keys(&redis, &format!("{}*", origin_b.origin_prefix()))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    #[ignore = "requires redis-server executable on PATH"]
    async fn live_redis_semantic_tenant_namespaces_do_not_cross() {
        let server = DisposableRedis::start().unwrap();
        server.wait_until_ready().await;
        let store = RedisSemanticCacheStore::from_async_store(server.handle());
        let tenant_a = namespace_for("a.test.sbproxy.dev", SENTINEL_TENANT);
        let tenant_b = namespace_for("a.test.sbproxy.dev", SENTINEL_OTHER_TENANT);
        let digest = [81_u8; 32];

        store
            .put(&write_for(&tenant_a, digest, 2, 300, 8))
            .await
            .unwrap();

        assert!(store
            .lookup(&query_for(&tenant_a, digest, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_some());
        assert!(store
            .lookup(&query_for(&tenant_b, digest, 2, 8))
            .await
            .unwrap()
            .exact_hit
            .is_none());
    }
}
