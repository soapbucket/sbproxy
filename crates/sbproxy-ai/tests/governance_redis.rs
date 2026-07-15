//! Contract tests for strict Redis governance accounting.

#[path = "../src/governance.rs"]
mod governance;
#[path = "../src/governance_redis.rs"]
mod governance_redis;

use std::{sync::Arc, time::Duration};

use governance::{
    GovernanceDenial, GovernanceDimension, GovernanceError, GovernanceLimits, GovernanceStore,
    ReleaseRequest, ReserveRequest, SettleRequest, SnapshotKey,
};
use governance_redis::{redis_governance_key, RedisGovernanceConfig, RedisGovernanceStore};
use sbproxy_platform::storage::{AsyncKVStore, AsyncRedisConfig, AsyncRedisKVStore};

const COMMON_LUA: &str = include_str!("../src/governance_redis/common.lua");
const RESERVE_LUA: &str = include_str!("../src/governance_redis/reserve.lua");
const SETTLE_LUA: &str = include_str!("../src/governance_redis/settle.lua");
const RELEASE_LUA: &str = include_str!("../src/governance_redis/release.lua");
const SNAPSHOT_LUA: &str = include_str!("../src/governance_redis/snapshot.lua");

fn limits() -> GovernanceLimits {
    GovernanceLimits {
        requests_per_window: Some(1),
        tokens_per_window: Some(100),
        total_tokens: Some(100),
        total_micro_usd: Some(1_000),
        window_millis: 60_000,
    }
}

fn reserve_request(id: &str, key_id: &str) -> ReserveRequest {
    ReserveRequest {
        reservation_id: id.to_string(),
        key_id: key_id.to_string(),
        policy_revision: 9,
        limits: limits(),
        token_ceiling: 80,
        micro_usd_ceiling: 600,
    }
}

fn snapshot_key(key_id: &str) -> SnapshotKey {
    SnapshotKey {
        key_id: key_id.to_string(),
        policy_revision: 9,
        limits: limits(),
    }
}

fn unique_prefix(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "sbproxy:test:governance:{label}:{}:{nanos}",
        std::process::id()
    )
}

fn redis_config(prefix: String, ttl_millis: u64) -> RedisGovernanceConfig {
    RedisGovernanceConfig {
        key_prefix: prefix,
        reservation_ttl_millis: ttl_millis,
        terminal_retention_millis: ttl_millis.saturating_mul(2),
    }
}

#[test]
fn state_scripts_are_one_key_redis_time_contracts() {
    assert!(COMMON_LUA.contains("redis.call('TIME')"));
    assert!(COMMON_LUA.contains("local governance_key = KEYS[1]"));
    assert!(COMMON_LUA.contains("cleanup_expired"));
    assert!(COMMON_LUA.contains("terminal_retention_millis"));
    assert!(COMMON_LUA.contains("HGETALL"));
    assert!(COMMON_LUA.contains("HDEL"));

    for operation in [RESERVE_LUA, SETTLE_LUA, RELEASE_LUA, SNAPSHOT_LUA] {
        assert!(operation.contains("#KEYS ~= 1"));
        assert!(!operation.contains("KEYS[2]"));
        assert!(!operation.contains("redis.call('EVAL'"));
    }
    assert!(RESERVE_LUA.contains("cleanup_expired"));
    assert!(RESERVE_LUA.contains("denied"));
    assert!(SETTLE_LUA.contains("settled"));
    assert!(RELEASE_LUA.contains("released"));
    assert!(SNAPSHOT_LUA.contains("cleanup_expired"));
}

#[test]
fn redis_key_uses_only_a_secret_free_cluster_hash_tag() {
    let key_id = "immutable-key-id-not-a-bearer";
    let key = redis_governance_key("sbproxy:governance", key_id);
    let repeated = redis_governance_key("sbproxy:governance", key_id);
    let different = redis_governance_key("sbproxy:governance", "different-id");

    assert_eq!(key, repeated);
    assert_ne!(key, different);
    assert!(key.starts_with("sbproxy:governance:{"));
    assert!(key.ends_with('}'));
    assert!(!key.contains(key_id));
    let tag = key.split_once('{').unwrap().1.strip_suffix('}').unwrap();
    assert_eq!(tag.len(), 64);
    assert!(tag.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn two_stores_atomically_admit_only_one_concurrent_reservation() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("barrier");
    let key_id = format!("key-{}", std::process::id());
    let redis_a = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let redis_b = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let store_a =
        RedisGovernanceStore::new(redis_a.clone(), redis_config(prefix.clone(), 2_000)).unwrap();
    let store_b = RedisGovernanceStore::new(redis_b, redis_config(prefix.clone(), 2_000)).unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let gate_a = barrier.clone();
    let request_a = reserve_request("reservation-a", &key_id);
    let admit_a = async {
        gate_a.wait().await;
        store_a.reserve(request_a).await
    };
    let gate_b = barrier.clone();
    let request_b = reserve_request("reservation-b", &key_id);
    let admit_b = async {
        gate_b.wait().await;
        store_b.reserve(request_b).await
    };
    let open_gate = async { barrier.wait().await };
    let (result_a, result_b, _) = tokio::join!(admit_a, admit_b, open_gate);

    match (&result_a, &result_b) {
        (
            Ok(_),
            Err(GovernanceError::LimitExceeded(GovernanceDenial {
                dimension: GovernanceDimension::RequestsPerWindow,
                ..
            })),
        )
        | (
            Err(GovernanceError::LimitExceeded(GovernanceDenial {
                dimension: GovernanceDimension::RequestsPerWindow,
                ..
            })),
            Ok(_),
        ) => {}
        other => panic!("unexpected concurrent admissions: {other:?}"),
    }

    let snapshot_a = store_a.snapshot(snapshot_key(&key_id)).await.unwrap();
    let snapshot_b = store_b.snapshot(snapshot_key(&key_id)).await.unwrap();
    assert_eq!(
        snapshot_a.requests_per_window,
        snapshot_b.requests_per_window
    );
    assert_eq!(snapshot_a.tokens_per_window, snapshot_b.tokens_per_window);
    assert_eq!(snapshot_a.total_tokens, snapshot_b.total_tokens);
    assert_eq!(snapshot_a.total_micro_usd, snapshot_b.total_micro_usd);
    assert_eq!(snapshot_a.requests_per_window.reserved, 1);
    assert_eq!(snapshot_a.total_tokens.reserved, 80);

    if result_a.is_ok() {
        store_a
            .release(ReleaseRequest {
                reservation_id: "reservation-a".to_string(),
                key_id: key_id.clone(),
            })
            .await
            .unwrap();
    } else {
        store_b
            .release(ReleaseRequest {
                reservation_id: "reservation-b".to_string(),
                key_id: key_id.clone(),
            })
            .await
            .unwrap();
    }
    let key = redis_governance_key(&prefix, &key_id);
    redis_a.delete(key.as_bytes()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn another_store_repairs_an_expired_lease_before_admission() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("expiry");
    let key_id = format!("key-{}", std::process::id());
    let redis_a = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let redis_b = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let store_a = RedisGovernanceStore::new(redis_a, redis_config(prefix.clone(), 50)).unwrap();
    let store_b =
        RedisGovernanceStore::new(redis_b.clone(), redis_config(prefix.clone(), 50)).unwrap();

    store_a
        .reserve(reserve_request("expired-reservation", &key_id))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    store_b
        .reserve(reserve_request("replacement-reservation", &key_id))
        .await
        .unwrap();

    let snapshot = store_b.snapshot(snapshot_key(&key_id)).await.unwrap();
    assert_eq!(snapshot.requests_per_window.reserved, 1);
    assert_eq!(snapshot.tokens_per_window.reserved, 80);
    assert_eq!(snapshot.total_tokens.reserved, 80);
    store_b
        .release(ReleaseRequest {
            reservation_id: "replacement-reservation".to_string(),
            key_id: key_id.clone(),
        })
        .await
        .unwrap();
    let key = redis_governance_key(&prefix, &key_id);
    redis_b.delete(key.as_bytes()).await.unwrap();
}

#[tokio::test]
#[ignore = "requires REDIS_URL"]
async fn another_store_can_settle_and_release_without_local_reservation_state() {
    let url = std::env::var("REDIS_URL").expect("REDIS_URL must name a disposable Redis");
    let prefix = unique_prefix("cross-store-terminal");
    let settle_key_id = format!("settle-key-{}", std::process::id());
    let release_key_id = format!("release-key-{}", std::process::id());
    let redis_a = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let redis_b = AsyncRedisKVStore::new(AsyncRedisConfig::new(&url));
    let store_a =
        RedisGovernanceStore::new(redis_a.clone(), redis_config(prefix.clone(), 2_000)).unwrap();
    let store_b =
        RedisGovernanceStore::new(redis_b.clone(), redis_config(prefix.clone(), 2_000)).unwrap();

    store_a
        .reserve(reserve_request("cross-store-settle", &settle_key_id))
        .await
        .unwrap();
    let settlement = store_b
        .settle(SettleRequest {
            reservation_id: "cross-store-settle".to_string(),
            key_id: settle_key_id.clone(),
            actual_tokens: 55,
            actual_micro_usd: 400,
        })
        .await
        .unwrap();
    assert_eq!(settlement.actual.tokens, 55);
    assert_eq!(settlement.key_id, settle_key_id);

    store_a
        .reserve(reserve_request("cross-store-release", &release_key_id))
        .await
        .unwrap();
    let release = store_b
        .release(ReleaseRequest {
            reservation_id: "cross-store-release".to_string(),
            key_id: release_key_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(release.released.tokens, 80);
    assert_eq!(release.key_id, release_key_id);

    let settle_key = redis_governance_key(&prefix, &settle_key_id);
    let release_key = redis_governance_key(&prefix, &release_key_id);
    redis_a.delete(settle_key.as_bytes()).await.unwrap();
    redis_b.delete(release_key.as_bytes()).await.unwrap();
}
