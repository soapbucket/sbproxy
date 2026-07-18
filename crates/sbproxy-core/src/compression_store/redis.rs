//! Strict lease-serialized Redis compression session store.

use async_trait::async_trait;
use base64::Engine;
use rand::RngCore;
use sbproxy_ai::compression::identity::normalize_origin;
use sbproxy_ai::compression::{
    CommitError, CompressionBackend, CompressionConsistency, CompressionRecordId,
    CompressionRecordMetadata, CompressionSessionRecord, CompressionSessionStore, DeleteResult,
    ListPage, ListRequest, PurgePage, PurgeRequest, StoreError, UpdatePermit,
    RECORD_SCHEMA_VERSION,
};
use sbproxy_platform::storage::{AsyncKVStore, AsyncRedisKVStore, RedisScanPage};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

const LUA_MAX_EXACT_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_ADMIN_PAGE_SIZE: u16 = 100;
const MAX_CURSOR_BYTES: usize = 64 * 1024;
const MAX_CURSOR_PENDING_KEYS: usize = 4_096;

const ACQUIRE_LUA: &str = r#"
-- sbproxy-compression:acquire:v1
local ownership = ARGV[1]
local lease_ttl_ms = ARGV[2]
local fence_ttl_ms = ARGV[3]
if redis.call('GET', KEYS[1]) then
  return {'contended'}
end
local fence = redis.call('INCR', KEYS[2])
redis.call('SET', KEYS[1], ownership .. ':' .. tostring(fence), 'PX', lease_ttl_ms)
redis.call('PEXPIRE', KEYS[2], fence_ttl_ms)
return {'acquired', tostring(fence)}
"#;

const COMMIT_LUA: &str = r#"
-- sbproxy-compression:commit:v1
local expected_logical_version = ARGV[1]
local new_logical_version = ARGV[2]
local ownership = ARGV[3]
local fence = ARGV[4]
local payload = ARGV[5]
local state_ttl_ms = ARGV[6]

if redis.call('GET', KEYS[2]) ~= ownership .. ':' .. fence then
  return {'lease_lost'}
end
if redis.call('GET', KEYS[3]) ~= fence then
  return {'fence_rejected'}
end

local current_payload = redis.call('GET', KEYS[1])
if expected_logical_version == '' then
  if current_payload then
    return {'stale_version'}
  end
else
  if not current_payload then
    return {'stale_version'}
  end
  local current_ok, current = pcall(cjson.decode, current_payload)
  if not current_ok or tostring(current['logical_version']) ~= expected_logical_version then
    return {'stale_version'}
  end
end

local candidate_ok, candidate = pcall(cjson.decode, payload)
if not candidate_ok or tostring(candidate['logical_version']) ~= new_logical_version then
  return {'serialization'}
end
redis.call('SET', KEYS[1], payload, 'PX', state_ttl_ms)
redis.call('PEXPIRE', KEYS[3], state_ttl_ms)
return {'committed'}
"#;

const RELEASE_LUA: &str = r#"
-- sbproxy-compression:release:v1
local ownership = ARGV[1] .. ':' .. ARGV[2]
if redis.call('GET', KEYS[1]) == ownership then
  redis.call('DEL', KEYS[1])
  return {'released'}
end
return {'not_owner'}
"#;

const DELETE_LUA: &str = r#"
-- sbproxy-compression:delete:v1
local existed = redis.call('EXISTS', KEYS[1])
redis.call('DEL', KEYS[1])
redis.call('DEL', KEYS[2])
local fence = redis.call('INCR', KEYS[3])
redis.call('PEXPIRE', KEYS[3], ARGV[1])
return {'deleted', tostring(existed), tostring(fence)}
"#;

/// Connection-independent Redis compression-store settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisCompressionStoreConfig {
    /// Domain-separated prefix placed before the shared Redis Cluster hash tag.
    pub key_prefix: String,
    /// Retention for delete fences that invalidate in-flight writers.
    pub deletion_fence_ttl: Duration,
    /// Redis `SCAN COUNT` work hint used by bounded admin listing.
    pub scan_count: u16,
    /// Maximum `SCAN` steps performed by one admin request.
    pub max_scan_rounds: u16,
}

impl Default for RedisCompressionStoreConfig {
    fn default() -> Self {
        Self {
            key_prefix: "sbproxy:compression:v1".to_string(),
            deletion_fence_ttl: Duration::from_secs(24 * 60 * 60),
            scan_count: 64,
            max_scan_rounds: 8,
        }
    }
}

#[async_trait]
trait RedisCompressionExecutor: Send + Sync {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;

    async fn eval(
        &self,
        source: &str,
        keys: &[String],
        args: &[String],
    ) -> anyhow::Result<Vec<String>>;

    async fn scan(&self, cursor: u64, pattern: &str, count: u16) -> anyhow::Result<RedisScanPage>;
}

#[async_trait]
impl RedisCompressionExecutor for AsyncRedisKVStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(AsyncKVStore::get(self, key.as_bytes())
            .await?
            .map(|value| value.to_vec()))
    }

    async fn eval(
        &self,
        source: &str,
        keys: &[String],
        args: &[String],
    ) -> anyhow::Result<Vec<String>> {
        self.evalsha_with_reload(source, keys, args).await
    }

    async fn scan(&self, cursor: u64, pattern: &str, count: u16) -> anyhow::Result<RedisScanPage> {
        self.scan_page(cursor, pattern, count).await
    }
}

/// Redis-backed strict compression session state.
#[derive(Clone)]
pub struct RedisCompressionStore {
    redis: Arc<dyn RedisCompressionExecutor>,
    config: RedisCompressionStoreConfig,
}

impl RedisCompressionStore {
    /// Build a strict adapter over the shared async Redis connection.
    pub fn new(
        redis: Arc<AsyncRedisKVStore>,
        config: RedisCompressionStoreConfig,
    ) -> Result<Self, StoreError> {
        Self::with_executor(redis, config)
    }

    fn with_executor(
        redis: Arc<dyn RedisCompressionExecutor>,
        config: RedisCompressionStoreConfig,
    ) -> Result<Self, StoreError> {
        validate_config(&config)?;
        Ok(Self { redis, config })
    }

    async fn load_record_key(
        &self,
        key: &str,
    ) -> Result<Option<CompressionSessionRecord>, StoreError> {
        let Some(encoded) = self
            .redis
            .get(key)
            .await
            .map_err(|_| StoreError::Unavailable)?
        else {
            return Ok(None);
        };
        let record = serde_json::from_slice::<CompressionSessionRecord>(&encoded)
            .map_err(|_| StoreError::CorruptRecord)?;
        if record.schema_version != RECORD_SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema);
        }
        Ok(Some(record))
    }

    async fn list_page(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
        validate_list_request(request)?;
        let mut cursor = match request.cursor.as_deref() {
            Some(cursor) => decode_cursor(cursor, &self.config)?,
            None => RedisListCursor::default(),
        };
        let wanted_origin = request.origin.as_deref().map(normalize_origin);
        let mut records = Vec::with_capacity(usize::from(request.limit));
        let mut scan_rounds = 0_u16;

        while records.len() < usize::from(request.limit) {
            while let Some(key) = cursor.pending.pop_front() {
                let Some(id) = record_id_from_key(&self.config, &key) else {
                    continue;
                };
                let Some(record) = self.load_record_key(&key).await? else {
                    continue;
                };
                if request
                    .tenant_id
                    .as_ref()
                    .is_some_and(|tenant_id| record.tenant_id != *tenant_id)
                    || wanted_origin
                        .as_ref()
                        .is_some_and(|origin| record.origin != *origin)
                    || request.expired.is_some_and(|expired| {
                        (record.expires_at_unix_ms <= request.expiration_cutoff_unix_ms) != expired
                    })
                    || request
                        .conflict
                        .is_some_and(|conflict| record.conflict_detected != conflict)
                {
                    continue;
                }
                records.push(CompressionRecordMetadata::from_record(
                    id,
                    CompressionBackend::Redis,
                    CompressionConsistency::Serialized,
                    &record,
                ));
                if records.len() == usize::from(request.limit) {
                    break;
                }
            }

            if records.len() == usize::from(request.limit)
                || cursor.finished
                || scan_rounds >= self.config.max_scan_rounds
            {
                break;
            }

            let page = self
                .redis
                .scan(
                    if cursor.started {
                        cursor.scan_cursor
                    } else {
                        0
                    },
                    &record_scan_pattern(&self.config),
                    self.config.scan_count,
                )
                .await
                .map_err(|_| StoreError::Unavailable)?;
            cursor.started = true;
            cursor.scan_cursor = page.next_cursor;
            cursor.finished = page.next_cursor == 0;
            for key in page.keys {
                if record_id_from_key(&self.config, &key).is_some() {
                    cursor.pending.push_back(key);
                }
            }
            if cursor.pending.len() > MAX_CURSOR_PENDING_KEYS {
                return Err(StoreError::Unavailable);
            }
            scan_rounds += 1;
        }

        let next_cursor = if cursor.pending.is_empty() && cursor.finished {
            None
        } else {
            Some(encode_cursor(&cursor)?)
        };
        Ok(ListPage {
            records,
            next_cursor,
        })
    }
}

#[async_trait]
impl CompressionSessionStore for RedisCompressionStore {
    fn backend(&self) -> CompressionBackend {
        CompressionBackend::Redis
    }

    fn consistency(&self) -> CompressionConsistency {
        CompressionConsistency::Serialized
    }

    async fn load(
        &self,
        id: &CompressionRecordId,
    ) -> Result<Option<CompressionSessionRecord>, StoreError> {
        self.load_record_key(&redis_keys(&self.config, *id).record)
            .await
    }

    async fn acquire_update(
        &self,
        id: &CompressionRecordId,
        lease_ttl: Duration,
    ) -> Result<Option<UpdatePermit>, StoreError> {
        let lease_ttl_ms = duration_millis(lease_ttl).ok_or(StoreError::InvalidRequest)?;
        let fence_ttl_ms = duration_millis(self.config.deletion_fence_ttl)
            .ok_or(StoreError::InvalidRequest)?
            .max(lease_ttl_ms);
        let mut owner_bytes = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut owner_bytes);
        let owner = hex::encode(owner_bytes);
        let keys = redis_keys(&self.config, *id);
        let response = self
            .redis
            .eval(
                ACQUIRE_LUA,
                &[keys.lease, keys.fence],
                &[
                    owner.clone(),
                    lease_ttl_ms.to_string(),
                    fence_ttl_ms.to_string(),
                ],
            )
            .await
            .map_err(|_| StoreError::Unavailable)?;
        match response.first().map(String::as_str) {
            Some("contended") => Ok(None),
            Some("acquired") => {
                let fence = response
                    .get(1)
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|fence| *fence > 0)
                    .ok_or(StoreError::CorruptRecord)?;
                Ok(Some(UpdatePermit::new(
                    *id,
                    CompressionBackend::Redis,
                    owner.into_bytes(),
                    fence,
                )))
            }
            _ => Err(StoreError::CorruptRecord),
        }
    }

    async fn commit(
        &self,
        permit: &UpdatePermit,
        expected_logical_version: Option<u64>,
        record: &CompressionSessionRecord,
        ttl: Duration,
    ) -> Result<(), CommitError> {
        if permit.backend() != CompressionBackend::Redis
            || record.schema_version != RECORD_SCHEMA_VERSION
            || record.logical_version
                != expected_logical_version
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(CommitError::Serialization)?
            || record.logical_version > LUA_MAX_EXACT_INTEGER
        {
            return Err(CommitError::Serialization);
        }
        let ttl_ms = duration_millis(ttl).ok_or(CommitError::Serialization)?;
        let owner = std::str::from_utf8(permit.ownership_token())
            .map_err(|_| CommitError::Serialization)?;
        let payload = serde_json::to_string(record).map_err(|_| CommitError::Serialization)?;
        let keys = redis_keys(&self.config, permit.record_id());
        let response = self
            .redis
            .eval(
                COMMIT_LUA,
                &[keys.record, keys.lease, keys.fence],
                &[
                    expected_logical_version
                        .map(|version| version.to_string())
                        .unwrap_or_default(),
                    record.logical_version.to_string(),
                    owner.to_string(),
                    permit.fence().to_string(),
                    payload,
                    ttl_ms.to_string(),
                ],
            )
            .await
            .map_err(|_| CommitError::Unavailable)?;
        match response.first().map(String::as_str) {
            Some("committed") => Ok(()),
            Some("lease_lost") => Err(CommitError::LeaseLost),
            Some("stale_version") => Err(CommitError::StaleVersion),
            Some("fence_rejected") => Err(CommitError::FenceRejected),
            Some("serialization") => Err(CommitError::Serialization),
            _ => Err(CommitError::Unavailable),
        }
    }

    async fn release(&self, permit: UpdatePermit) -> Result<(), StoreError> {
        if permit.backend() != CompressionBackend::Redis {
            return Err(StoreError::InvalidRequest);
        }
        let owner = std::str::from_utf8(permit.ownership_token())
            .map_err(|_| StoreError::InvalidRequest)?;
        let keys = redis_keys(&self.config, permit.record_id());
        let response = self
            .redis
            .eval(
                RELEASE_LUA,
                &[keys.lease],
                &[owner.to_string(), permit.fence().to_string()],
            )
            .await
            .map_err(|_| StoreError::Unavailable)?;
        match response.first().map(String::as_str) {
            Some("released" | "not_owner") => Ok(()),
            _ => Err(StoreError::Unavailable),
        }
    }

    async fn list(&self, request: &ListRequest) -> Result<ListPage, StoreError> {
        self.list_page(request).await
    }

    async fn delete(&self, id: &CompressionRecordId) -> Result<DeleteResult, StoreError> {
        let fence_ttl_ms =
            duration_millis(self.config.deletion_fence_ttl).ok_or(StoreError::InvalidRequest)?;
        let keys = redis_keys(&self.config, *id);
        let response = self
            .redis
            .eval(
                DELETE_LUA,
                &[keys.record, keys.lease, keys.fence],
                &[fence_ttl_ms.to_string()],
            )
            .await
            .map_err(|_| StoreError::Unavailable)?;
        if response.first().map(String::as_str) != Some("deleted") {
            return Err(StoreError::Unavailable);
        }
        let deleted = match response.get(1).map(String::as_str) {
            Some("0") => false,
            Some("1") => true,
            _ => return Err(StoreError::Unavailable),
        };
        Ok(DeleteResult {
            deleted,
            logical_version: None,
        })
    }

    async fn purge(&self, request: &PurgeRequest) -> Result<PurgePage, StoreError> {
        let page = self
            .list_page(&ListRequest {
                tenant_id: request.tenant_id.clone(),
                origin: request.origin.clone(),
                expired: request.expired_before_unix_ms.map(|_| true),
                expiration_cutoff_unix_ms: request.expired_before_unix_ms.unwrap_or(0),
                conflict: request.conflict,
                cursor: request.cursor.clone(),
                limit: request.limit,
            })
            .await?;
        let mut deleted = 0_u64;
        for record in page.records {
            if self.delete(&record.id).await?.deleted {
                deleted += 1;
            }
        }
        Ok(PurgePage {
            deleted,
            next_cursor: page.next_cursor,
        })
    }
}

#[derive(Debug)]
struct RedisKeys {
    record: String,
    lease: String,
    fence: String,
}

fn redis_keys(config: &RedisCompressionStoreConfig, id: CompressionRecordId) -> RedisKeys {
    let prefix = config.key_prefix.trim_end_matches(':');
    let id = id.to_string();
    RedisKeys {
        record: format!("{prefix}:{{compression}}:record:{id}"),
        lease: format!("{prefix}:{{compression}}:lease:{id}"),
        fence: format!("{prefix}:{{compression}}:fence:{id}"),
    }
}

fn record_key_prefix(config: &RedisCompressionStoreConfig) -> String {
    format!(
        "{}:{{compression}}:record:",
        config.key_prefix.trim_end_matches(':')
    )
}

fn record_scan_pattern(config: &RedisCompressionStoreConfig) -> String {
    format!("{}*", record_key_prefix(config))
}

fn record_id_from_key(
    config: &RedisCompressionStoreConfig,
    key: &str,
) -> Option<CompressionRecordId> {
    key.strip_prefix(&record_key_prefix(config))?.parse().ok()
}

fn validate_config(config: &RedisCompressionStoreConfig) -> Result<(), StoreError> {
    let prefix = config.key_prefix.trim_end_matches(':');
    if prefix.is_empty()
        || prefix.len() > 128
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":-_.".contains(&byte))
        || duration_millis(config.deletion_fence_ttl).is_none()
        || !(1..=1_000).contains(&config.scan_count)
        || config.max_scan_rounds == 0
    {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}

fn validate_list_request(request: &ListRequest) -> Result<(), StoreError> {
    if request
        .tenant_id
        .as_ref()
        .is_some_and(|tenant_id| tenant_id.trim().is_empty())
        || request
            .origin
            .as_ref()
            .is_some_and(|origin| origin.trim().is_empty())
        || (request.expired.is_some() && request.expiration_cutoff_unix_ms == 0)
        || !(1..=MAX_ADMIN_PAGE_SIZE).contains(&request.limit)
    {
        return Err(StoreError::InvalidRequest);
    }
    Ok(())
}

fn duration_millis(duration: Duration) -> Option<u64> {
    let millis = u64::try_from(duration.as_millis()).ok()?;
    (millis > 0 && millis <= LUA_MAX_EXACT_INTEGER).then_some(millis)
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedisListCursor {
    started: bool,
    finished: bool,
    scan_cursor: u64,
    pending: VecDeque<String>,
}

fn encode_cursor(cursor: &RedisListCursor) -> Result<String, StoreError> {
    let encoded = serde_json::to_vec(cursor).map_err(|_| StoreError::InvalidCursor)?;
    if encoded.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded))
}

fn decode_cursor(
    encoded: &str,
    config: &RedisCompressionStoreConfig,
) -> Result<RedisListCursor, StoreError> {
    if encoded.len() > MAX_CURSOR_BYTES.saturating_mul(2) {
        return Err(StoreError::InvalidCursor);
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StoreError::InvalidCursor)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(StoreError::InvalidCursor);
    }
    let cursor =
        serde_json::from_slice::<RedisListCursor>(&bytes).map_err(|_| StoreError::InvalidCursor)?;
    if (cursor.finished || !cursor.started) && cursor.scan_cursor != 0
        || cursor.pending.len() > MAX_CURSOR_PENDING_KEYS
        || cursor
            .pending
            .iter()
            .any(|key| record_id_from_key(config, key).is_none())
    {
        return Err(StoreError::InvalidCursor);
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::{
        redis_keys, RedisCompressionExecutor, RedisCompressionStore, RedisCompressionStoreConfig,
        ACQUIRE_LUA, COMMIT_LUA, DELETE_LUA, RELEASE_LUA,
    };
    use async_trait::async_trait;
    use sbproxy_ai::compression::{
        CommitError, CompressionRecordId, CompressionSessionRecord, CompressionSessionStore,
        ListRequest, MessageDigest, RecordKind, StoreError, RECORD_SCHEMA_VERSION,
    };
    use sbproxy_platform::storage::RedisScanPage;
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    struct EvalCall {
        source: String,
        keys: Vec<String>,
        args: Vec<String>,
    }

    #[derive(Default)]
    struct RecordingRedis {
        values: Mutex<HashMap<String, Vec<u8>>>,
        eval_calls: Mutex<Vec<EvalCall>>,
        eval_results: Mutex<VecDeque<anyhow::Result<Vec<String>>>>,
        scan_calls: Mutex<Vec<(u64, String, u16)>>,
        scan_results: Mutex<VecDeque<anyhow::Result<RedisScanPage>>>,
    }

    #[async_trait]
    impl RedisCompressionExecutor for RecordingRedis {
        async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }

        async fn eval(
            &self,
            source: &str,
            keys: &[String],
            args: &[String],
        ) -> anyhow::Result<Vec<String>> {
            self.eval_calls.lock().unwrap().push(EvalCall {
                source: source.to_string(),
                keys: keys.to_vec(),
                args: args.to_vec(),
            });
            self.eval_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("test must enqueue one eval response")
        }

        async fn scan(
            &self,
            cursor: u64,
            pattern: &str,
            count: u16,
        ) -> anyhow::Result<RedisScanPage> {
            self.scan_calls
                .lock()
                .unwrap()
                .push((cursor, pattern.to_string(), count));
            self.scan_results
                .lock()
                .unwrap()
                .pop_front()
                .expect("test must enqueue one scan response")
        }
    }

    fn config() -> RedisCompressionStoreConfig {
        RedisCompressionStoreConfig {
            key_prefix: "sbproxy:compression:v1".to_string(),
            deletion_fence_ttl: Duration::from_secs(60),
            scan_count: 16,
            max_scan_rounds: 4,
        }
    }

    fn id(seed: u8) -> CompressionRecordId {
        CompressionRecordId::derive("tenant-a", "api.example.com", [seed; 16])
    }

    fn record(version: u64, tenant: &str, origin: &str) -> CompressionSessionRecord {
        CompressionSessionRecord {
            schema_version: RECORD_SCHEMA_VERSION,
            logical_version: version,
            tenant_id: tenant.to_string(),
            origin: origin.to_string(),
            summary: "sensitive summary".to_string(),
            protected_prefix_count: 1,
            protected_prefix_digest: MessageDigest::for_messages(&[json!({
                "role": "system",
                "content": "protected"
            })]),
            covered_history_count: 2,
            covered_history_digest: MessageDigest::for_messages(&[json!({
                "role": "user",
                "content": "covered"
            })]),
            covered_input_tokens: 200,
            summary_tokens: 20,
            summarizer_provider: "provider-a".to_string(),
            summarizer_model: "model-a".to_string(),
            writer_node: "node-a".to_string(),
            parent_logical_version: version.checked_sub(1),
            conflict_detected: false,
            created_at_unix_ms: 1_000,
            updated_at_unix_ms: 2_000,
            expires_at_unix_ms: 60_000,
            kind: RecordKind::Live,
        }
    }

    fn store(redis: Arc<RecordingRedis>) -> RedisCompressionStore {
        RedisCompressionStore::with_executor(redis, config()).unwrap()
    }

    #[test]
    fn key_namespace_is_opaque_and_cluster_slot_stable() {
        let keys = redis_keys(&config(), id(7));
        assert!(keys
            .record
            .starts_with("sbproxy:compression:v1:{compression}:record:"));
        assert!(keys.lease.contains("{compression}"));
        assert!(keys.fence.contains("{compression}"));
        assert!(!keys.record.contains("tenant-a"));
        assert!(!keys.record.contains("api.example.com"));
        assert!(!keys.record.contains(&hex::encode([7; 16])));
    }

    #[tokio::test]
    async fn acquire_release_and_contention_use_owner_scoped_lua() {
        let redis = Arc::new(RecordingRedis::default());
        redis.eval_results.lock().unwrap().extend([
            Ok(vec!["acquired".into(), "7".into()]),
            Ok(vec!["contended".into()]),
        ]);
        let store = store(redis.clone());
        let record_id = id(1);

        let permit = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(permit.fence(), 7);
        assert!(store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .is_none());

        redis
            .eval_results
            .lock()
            .unwrap()
            .push_back(Ok(vec!["released".into()]));
        store.release(permit).await.unwrap();

        let calls = redis.eval_calls.lock().unwrap();
        assert!(calls[0].source.contains("sbproxy-compression:acquire:v1"));
        assert_eq!(calls[0].keys.len(), 2);
        assert_eq!(calls[0].args[1], "5000");
        assert!(calls[2].source.contains("sbproxy-compression:release:v1"));
        assert_eq!(calls[2].args[0], calls[0].args[0]);
        assert_eq!(calls[2].args[1], "7");
    }

    #[tokio::test]
    async fn commit_serializes_expected_version_and_maps_closed_rejections() {
        let redis = Arc::new(RecordingRedis::default());
        let store = store(redis.clone());
        let record_id = id(2);
        let permit = sbproxy_ai::compression::UpdatePermit::new(
            record_id,
            sbproxy_ai::compression::CompressionBackend::Redis,
            b"owner-a".to_vec(),
            9,
        );
        redis.eval_results.lock().unwrap().extend([
            Ok(vec!["committed".into()]),
            Ok(vec!["stale_version".into()]),
            Ok(vec!["lease_lost".into()]),
            Ok(vec!["fence_rejected".into()]),
        ]);

        store
            .commit(
                &permit,
                Some(1),
                &record(2, "tenant-a", "api.example.com"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .commit(
                    &permit,
                    Some(1),
                    &record(2, "tenant-a", "api.example.com"),
                    Duration::from_secs(60)
                )
                .await,
            Err(CommitError::StaleVersion)
        );
        assert_eq!(
            store
                .commit(
                    &permit,
                    Some(1),
                    &record(2, "tenant-a", "api.example.com"),
                    Duration::from_secs(60)
                )
                .await,
            Err(CommitError::LeaseLost)
        );
        assert_eq!(
            store
                .commit(
                    &permit,
                    Some(1),
                    &record(2, "tenant-a", "api.example.com"),
                    Duration::from_secs(60)
                )
                .await,
            Err(CommitError::FenceRejected)
        );

        let calls = redis.eval_calls.lock().unwrap();
        assert!(calls[0].source.contains("sbproxy-compression:commit:v1"));
        assert_eq!(calls[0].args[0], "1");
        assert_eq!(calls[0].args[1], "2");
        assert_eq!(calls[0].args[2], "owner-a");
        assert_eq!(calls[0].args[3], "9");
        assert_eq!(calls[0].args[5], "60000");
        assert!(calls[0].args[4].contains("sensitive summary"));
        assert!(!format!("{:?}", calls[0]).contains("redis://"));
    }

    #[tokio::test]
    async fn load_rejects_corrupt_and_unknown_schema_records() {
        let redis = Arc::new(RecordingRedis::default());
        let store = store(redis.clone());
        let keys = redis_keys(&config(), id(3));
        redis
            .values
            .lock()
            .unwrap()
            .insert(keys.record.clone(), b"not-json".to_vec());
        assert_eq!(store.load(&id(3)).await, Err(StoreError::CorruptRecord));

        let mut unknown = record(1, "tenant-a", "api.example.com");
        unknown.schema_version = RECORD_SCHEMA_VERSION + 1;
        redis
            .values
            .lock()
            .unwrap()
            .insert(keys.record, serde_json::to_vec(&unknown).unwrap());
        assert_eq!(store.load(&id(3)).await, Err(StoreError::UnsupportedSchema));
    }

    #[tokio::test]
    async fn metadata_listing_preserves_scan_overflow_in_opaque_cursor() {
        let redis = Arc::new(RecordingRedis::default());
        let first_id = id(4);
        let second_id = id(5);
        let first_keys = redis_keys(&config(), first_id);
        let second_keys = redis_keys(&config(), second_id);
        redis.values.lock().unwrap().extend([
            (
                first_keys.record.clone(),
                serde_json::to_vec(&record(1, "tenant-a", "api.example.com")).unwrap(),
            ),
            (
                second_keys.record.clone(),
                serde_json::to_vec(&record(2, "tenant-a", "api.example.com")).unwrap(),
            ),
        ]);
        redis
            .scan_results
            .lock()
            .unwrap()
            .push_back(Ok(RedisScanPage {
                next_cursor: 0,
                keys: vec![first_keys.record, second_keys.record],
            }));
        let store = store(redis.clone());
        let request = ListRequest {
            tenant_id: Some("tenant-a".to_string()),
            origin: Some("API.Example.COM.".to_string()),
            expired: None,
            expiration_cutoff_unix_ms: 0,
            conflict: None,
            cursor: None,
            limit: 1,
        };

        let first = store.list(&request).await.unwrap();
        assert_eq!(first.records.len(), 1);
        assert!(first.next_cursor.is_some());
        assert!(!first.next_cursor.as_deref().unwrap().contains("record"));
        let second = store
            .list(&ListRequest {
                cursor: first.next_cursor,
                ..request
            })
            .await
            .unwrap();
        assert_eq!(second.records.len(), 1);
        assert!(second.next_cursor.is_none());
        assert_eq!(redis.scan_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn metadata_listing_supports_unscoped_expiry_and_conflict_filters() {
        let redis = Arc::new(RecordingRedis::default());
        let expired_id = id(40);
        let active_id = id(41);
        let expired_key = redis_keys(&config(), expired_id).record;
        let active_key = redis_keys(&config(), active_id).record;
        let mut expired = record(1, "tenant-a", "api.example.com");
        expired.conflict_detected = true;
        expired.expires_at_unix_ms = 50_000;
        let mut active = record(1, "tenant-b", "other.example.com");
        active.conflict_detected = true;
        active.expires_at_unix_ms = 70_000;
        redis.values.lock().unwrap().extend([
            (expired_key.clone(), serde_json::to_vec(&expired).unwrap()),
            (active_key.clone(), serde_json::to_vec(&active).unwrap()),
        ]);
        redis
            .scan_results
            .lock()
            .unwrap()
            .push_back(Ok(RedisScanPage {
                next_cursor: 0,
                keys: vec![expired_key, active_key],
            }));

        let page = store(redis)
            .list(&ListRequest {
                tenant_id: None,
                origin: None,
                expired: Some(true),
                expiration_cutoff_unix_ms: 60_000,
                conflict: Some(true),
                cursor: None,
                limit: 10,
            })
            .await
            .unwrap();

        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].id, expired_id);
    }

    #[tokio::test]
    async fn invalid_cursor_and_backend_failures_are_not_empty_pages() {
        let redis = Arc::new(RecordingRedis::default());
        let store = store(redis.clone());
        let invalid = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: None,
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: Some("not-a-cursor".to_string()),
                limit: 10,
            })
            .await;
        assert_eq!(invalid, Err(StoreError::InvalidCursor));

        redis
            .scan_results
            .lock()
            .unwrap()
            .push_back(Err(anyhow::anyhow!("redis://user:secret@host")));
        let unavailable = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: None,
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: None,
                limit: 10,
            })
            .await;
        assert_eq!(unavailable, Err(StoreError::Unavailable));
    }

    #[test]
    fn lua_contract_uses_scan_externally_and_never_an_unbounded_keys_command() {
        for source in [ACQUIRE_LUA, COMMIT_LUA, RELEASE_LUA, DELETE_LUA] {
            assert!(!source.to_ascii_lowercase().contains("redis.call('keys'"));
        }
        assert!(ACQUIRE_LUA.contains("INCR"));
        assert!(COMMIT_LUA.contains("expected_logical_version"));
        assert!(RELEASE_LUA.contains("ownership"));
        assert!(DELETE_LUA.contains("INCR"));
    }

    struct RedisProcess {
        child: Child,
        _directory: tempfile::TempDir,
    }

    impl Drop for RedisProcess {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn spawn_redis() -> (RedisProcess, String) {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let directory = tempfile::tempdir().unwrap();
        let mut child = Command::new("redis-server")
            .args([
                "--bind",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                directory.path().to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("redis-server must be installed for this ignored test");
        let address = format!("127.0.0.1:{port}");
        for _ in 0..100 {
            if TcpStream::connect(&address).is_ok() {
                return (
                    RedisProcess {
                        child,
                        _directory: directory,
                    },
                    format!("redis://{address}"),
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("disposable redis-server did not become ready");
    }

    #[tokio::test]
    #[ignore = "requires the redis-server executable"]
    async fn live_redis_serializes_writers_fences_deletes_and_paginates() {
        let (_redis_process, url) = spawn_redis();
        let redis = sbproxy_platform::storage::AsyncRedisKVStore::new(
            sbproxy_platform::storage::AsyncRedisConfig::new(&url),
        );
        let store = RedisCompressionStore::new(redis, config()).unwrap();
        let record_id = id(20);

        let first = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert!(store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .is_none());
        store
            .commit(
                &first,
                None,
                &record(1, "tenant-a", "api.example.com"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .load(&record_id)
                .await
                .unwrap()
                .unwrap()
                .logical_version,
            1
        );

        let stale = sbproxy_ai::compression::UpdatePermit::new(
            first.record_id(),
            first.backend(),
            first.ownership_token().to_vec(),
            first.fence(),
        );
        store.release(first).await.unwrap();
        let second = store
            .acquire_update(&record_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert!(second.fence() > stale.fence());
        store.release(stale).await.unwrap();
        assert_eq!(
            store
                .commit(
                    &second,
                    None,
                    &record(1, "tenant-a", "api.example.com"),
                    Duration::from_secs(60),
                )
                .await,
            Err(CommitError::StaleVersion)
        );
        store
            .commit(
                &second,
                Some(1),
                &record(2, "tenant-a", "api.example.com"),
                Duration::from_secs(60),
            )
            .await
            .unwrap();

        assert!(store.delete(&record_id).await.unwrap().deleted);
        assert_eq!(
            store
                .commit(
                    &second,
                    Some(2),
                    &record(3, "tenant-a", "api.example.com"),
                    Duration::from_secs(60),
                )
                .await,
            Err(CommitError::LeaseLost)
        );
        assert!(!store.delete(&record_id).await.unwrap().deleted);

        let expiring_id = id(23);
        let expiring = store
            .acquire_update(&expiring_id, Duration::from_millis(20))
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let replacement = store
            .acquire_update(&expiring_id, Duration::from_secs(5))
            .await
            .unwrap()
            .unwrap();
        assert!(replacement.fence() > expiring.fence());
        assert_eq!(
            store
                .commit(
                    &expiring,
                    None,
                    &record(1, "tenant-a", "api.example.com"),
                    Duration::from_secs(60),
                )
                .await,
            Err(CommitError::LeaseLost)
        );
        store.release(replacement).await.unwrap();

        for seed in [21, 22] {
            let record_id = id(seed);
            let permit = store
                .acquire_update(&record_id, Duration::from_secs(5))
                .await
                .unwrap()
                .unwrap();
            store
                .commit(
                    &permit,
                    None,
                    &record(1, "tenant-a", "api.example.com"),
                    Duration::from_secs(60),
                )
                .await
                .unwrap();
            store.release(permit).await.unwrap();
        }
        let first_page = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: Some("api.example.com".to_string()),
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: None,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(first_page.records.len(), 1);
        let second_page = store
            .list(&ListRequest {
                tenant_id: Some("tenant-a".to_string()),
                origin: Some("api.example.com".to_string()),
                expired: None,
                expiration_cutoff_unix_ms: 0,
                conflict: None,
                cursor: first_page.next_cursor,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(second_page.records.len(), 1);
        assert_ne!(first_page.records[0].id, second_page.records[0].id);
    }
}
